// @ts-check

// The issuer core has two operations that the application calls at separate
// stages. `admit` structurally admits one request and returns it for the
// application to carry through preflight and cache lookup; `processMiss` takes
// that admitted request on a cache miss and turns it into one semantic result.
// A host cache hit is usable only if the current call's verified registration,
// context and policy decision would authorize the same result.
// This file handles no HTTP status, refusal wording, logging, authentication,
// or post-delivery work. A port decides how an error code crosses its transport
// boundary.

import { dcaError } from "../core-shared/errors.js";
import { checkVersion } from "./IssuerEngine.js";
import { utf8Encode } from "../core-shared/codec.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { periodGeometriesAgree } from "../core-shared/geometryBounds.js";
import { isAccessGroup, isContentName, isIssuerName } from "../core-shared/names.js";
import { own, setOwn } from "../core-shared/wire.js";
import { DcaRequest, parseDcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { DEFAULT_REQUEST_LIMITS, requestEntryCounts } from "../core-shared/requestLimits.js";

/**
 * @typedef {object} DcaSuccess
 * @property {'success'} kind
 * @property {object} document - the DCA response document
 * @property {any} policyData - opaque host data, never part of the document
 */

/**
 * @typedef {object} DcaFailure
 * @property {'failure'} kind
 * @property {string} code
 */

/** @typedef {DcaSuccess|DcaFailure} DcaResult */

/**
 * @typedef {object} DcaAdmitted
 * @property {'admitted'} kind
 * @property {DcaRequest} request - the structurally admitted request, carried
 *   unchanged through preflight, cache lookup, and miss processing
 */

/** @typedef {DcaAdmitted|DcaFailure} DcaAdmission */

/**
 * @typedef {object} IssuerInvocation
 * @property {DcaRequest} request - the request admission returned unchanged
 * @property {import('./IssuerEngine.js').PublisherRegistration} registration -
 *   selected by the host from the verified publisher key identifier
 * @property {import('./IssuerEngine.js').IssuerHostPolicyInput} [policyInput] -
 *   host-owned policy input, never read from the request
 * @property {number} [capturedAtMs] - finite host-captured epoch milliseconds
 * @property {import('./IssuerEngine.js').VerifiedClaims} [verification] - original signed-resource verification result; engine checks its provenance
 */

const OPTIONS = [
  "limits",
  "capabilityEncoders",
  "selectedExtensions",
  "periodKeyInput",
  "requestBounds",
  "extensionCoordinates",
];

/** Codes a request bound may refuse admission with. */
const BOUND_CODES = Object.freeze(["too_many_entries", "binding_failed"]);

/** Response members base writes; a section source may share only the geometry. */
const BASE_DOCUMENT_MEMBERS = Object.freeze(["keys", "errors", "notDelivered"]);

/**
 * The selected extensions whose request coordinates base reads itself, for a
 * deployment that names the extension and no coordinate of its own. Every
 * other selected extension states its coordinate through
 * `extensionCoordinates`.
 *
 * @type {Readonly<Record<string, (request: DcaRequest) => boolean>>}
 */
const BUILT_IN_EXTENSION_COORDINATES = Object.freeze({
  "chain-keys": (request) => Object.keys(request.sealedChainKeys ?? {}).length > 0,
});
const LIMITS = ["maxBodyBytes", "maxEntries", "maxEntriesPerGroup"];
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

// The structural admission limits this reference issuer applies when a
// deployment names none. An omitted member never means unbounded opening work:
// a deployment that names one member keeps these values for the others. These
// are reference deployment values rather than a wire maximum, so another
// implementation may pick different finite limits and refuse a well-formed
// request above them.
const DEFAULT_LIMITS = DEFAULT_REQUEST_LIMITS;

/**
 * @param {any} limits
 * @param {string} name
 * @returns {number}
 */
function cap(limits, name) {
  const value = limits[name];
  if (!Number.isFinite(value) || value <= 0) {
    throw dcaError("bad_config", `${name} is a positive number, got ${JSON.stringify(value)}`);
  }
  return value;
}

/** @param {any} value */
function nonemptyStringMap(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length > 0 &&
    Object.values(value).every((entry) => typeof entry === "string")
  );
}

/** @param {any} value */
function nonemptyPeriodKeyMap(value) {
  return (
    nonemptyStringMap(value) &&
    Object.values(value).every((entry) => binaryStringBytes(entry)?.length === 16)
  );
}

/** @param {any} value */
function isPeriodKeyResult(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([accessGroup, family]) =>
        isAccessGroup(accessGroup) &&
        nonemptyPeriodKeyMap(family) &&
        Object.keys(family).every(isPeriodKeyLabel),
    )
  );
}

/**
 * An uncomposed capability member is harmless only when it is an empty map.
 * A populated output would otherwise be silently omitted from a successful
 * typed answer instead of passing through the configured capability encoder.
 *
 * @param {any} result
 * @param {'periodCapabilities'|'chainKeys'} field
 */
function hasNonemptyUncomposedCapability(result, field) {
  if (!Object.hasOwn(result, field)) return false;
  const value = result[field];
  return (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length > 0
  );
}

const NOT_DELIVERED_REASONS = Object.freeze(["denied", "unavailable"]);

/**
 * Whether an engine's not-delivered report is one this processor can put in a
 * document: a map of admitted access-group names to a known reason and an
 * optional string message, where no named family also has a period key, a
 * chain key or a period-coordinate error in the same answer. Period keys Section 5.6
 * forbids that coexistence, and a client refuses the whole response for it,
 * so a report that breaks it is an engine fault rather than a delivery.
 *
 * @param {any} report
 * @param {any} result - the engine answer the report came with
 * @param {any[]} capabilities - the engine's represented period capabilities
 * @returns {boolean}
 */
function isNotDeliveredReport(report, result, capabilities) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) return false;
  for (const accessGroup of Object.keys(report)) {
    const entry = own(report, accessGroup);
    const message = own(entry, "message");
    if (
      !isAccessGroup(accessGroup) ||
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      !NOT_DELIVERED_REASONS.includes(own(entry, "reason")) ||
      (message !== undefined && typeof message !== "string") ||
      Object.hasOwn(result.periodKeys ?? {}, accessGroup) ||
      capabilities.some((capability) => capability?.accessGroup === accessGroup) ||
      Object.keys(result.errors).some((coordinate) => coordinate.startsWith(`${accessGroup}|`))
    ) {
      return false;
    }
  }
  return true;
}

/** @param {any} capability */
function isTypedCapability(capability) {
  return (
    capability !== null &&
    typeof capability === "object" &&
    !Array.isArray(capability) &&
    Object.hasOwn(capability, "kind") &&
    typeof capability.kind === "string" &&
    capability.kind.length > 0 &&
    Object.hasOwn(capability, "accessGroup") &&
    typeof capability.accessGroup === "string" &&
    capability.accessGroup.length > 0 &&
    Object.hasOwn(capability, "entries") &&
    nonemptyStringMap(capability.entries) &&
    Object.hasOwn(capability, "interpretation") &&
    capability.interpretation !== null &&
    typeof capability.interpretation === "object" &&
    !Array.isArray(capability.interpretation)
  );
}

export class IssuerProcessor {
  #engine;

  /** @type {Map<string, Function>} */
  #capabilityEncoders;

  /** @type {Set<string>} */
  #selectedExtensions;

  /** @type {boolean} */
  #periodKeyInput;

  /** @type {readonly ((request: DcaRequest) => void)[]} */
  #requestBounds;

  /** @type {Map<string, (request: DcaRequest) => boolean>} */
  #extensionCoordinates;

  /** @type {number} */
  #maxBodyBytes;

  /** @type {number} */
  #maxEntries;

  /** @type {number} */
  #maxEntriesPerGroup;

  /**
   * @param {{ checkVersion?: (request: DcaRequest) => void, checkOperatingIssuerName: (request: DcaRequest) => void, unlock: (request: DcaRequest, registration: any, policyInput?: any, invocation?: import('./IssuerEngine.js').IssuerUnlockInvocation) => Promise<{ contentKeys: Record<string, string>, periodKeys?: Record<string, Record<string, string>>, capabilities?: any[], errors: Record<string, object>, notDelivered?: Record<string, { reason: string, message?: string }>, policyData?: any, sections?: Record<string, any> }> }} issuerEngine
   *   Its optional checkVersion guard is synchronous pure and returns void;
   *   an unlock-only injected engine uses the baseline version guard.
   * @param {object} [options]
   * @param {{ maxBodyBytes?: number, maxEntries?: number, maxEntriesPerGroup?: number }} [options.limits] -
   *   the admission caps this deployment replaces; every member left out keeps
   *   its `DEFAULT_LIMITS` value. A present member must be a positive number,
   *   so a member written as `undefined` counts as supplied and is refused.
   * @param {Record<string, (record: any) => { section: string, accessGroup: string, entries: Record<string, string>, periodGeometry: { chainsPerDay: number, periodMinutes: number } }>} [options.capabilityEncoders] -
   *   the selected typed-capability projections for this issuer deployment
   * @param {string[]} [options.selectedExtensions] - the extensions this issuer
   *   deployment has selected, named the way the request members are. List an
   *   extension here whether or not it also returns a response section:
   *   selection decides which request members are recognized, and response
   *   encoding decides what goes back.
   * @param {boolean} [options.periodKeyInput] - whether trusted deployment
   *   configuration selects period-key request processing
   * @param {((request: DcaRequest) => void)[]} [options.requestBounds] - checks
   *   a selected extension runs on its own request members during admission,
   *   before any signature verification or private-key work. A bound refuses
   *   by throwing a DcaError coded `too_many_entries` or `binding_failed`;
   *   anything else it throws is a server fault and propagates.
   * @param {Record<string, (request: DcaRequest) => boolean>} [options.extensionCoordinates] -
   *   by selected extension name, whether a request presents a coordinate of
   *   that extension. A selected extension without one counts only through a
   *   built-in reading, which exists for `chain-keys`.
   */
  constructor(issuerEngine, options = {}) {
    if (!issuerEngine) throw dcaError("bad_config", "IssuerProcessor needs an engine");
    if (typeof issuerEngine.checkOperatingIssuerName !== "function") {
      throw dcaError("bad_config", "an engine checks its trusted operating issuer names");
    }
    if (issuerEngine.checkVersion !== undefined && typeof issuerEngine.checkVersion !== "function")
      throw dcaError("bad_config", "an engine version guard is a function");

    for (const name of Object.keys(options ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `IssuerProcessor has no ${name} yet, and will not pretend to`,
        );
      }
    }

    if (
      options.limits !== undefined &&
      (options.limits === null ||
        typeof options.limits !== "object" ||
        Array.isArray(options.limits))
    ) {
      throw dcaError("bad_config", "limits is an object of caps");
    }
    const configured = options.limits ?? {};
    for (const name of Object.keys(configured)) {
      if (!LIMITS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `IssuerProcessor caps nothing called ${name}, and will not pretend to`,
        );
      }
    }
    // Each named member replaces one default and goes through the same
    // strict check; the unnamed ones stay finite.
    const limits = { ...DEFAULT_LIMITS, ...configured };

    this.#engine = issuerEngine;
    if (
      options.capabilityEncoders !== undefined &&
      (options.capabilityEncoders === null ||
        typeof options.capabilityEncoders !== "object" ||
        Array.isArray(options.capabilityEncoders))
    ) {
      throw dcaError(
        "bad_config",
        "capabilityEncoders is an object keyed by supported capability kind",
      );
    }
    this.#capabilityEncoders = new Map();
    for (const [kind, encoder] of Object.entries(options.capabilityEncoders ?? {})) {
      if (typeof encoder !== "function") {
        throw dcaError("bad_config", `capability encoder ${JSON.stringify(kind)} is a function`);
      }
      this.#capabilityEncoders.set(kind, encoder);
    }
    if (
      options.selectedExtensions !== undefined &&
      (!Array.isArray(options.selectedExtensions) ||
        options.selectedExtensions.some((name) => typeof name !== "string" || name.length === 0))
    ) {
      throw dcaError("bad_config", "selectedExtensions is a list of selected extension names");
    }
    this.#selectedExtensions = new Set(options.selectedExtensions ?? []);
    if (options.periodKeyInput !== undefined && typeof options.periodKeyInput !== "boolean") {
      throw dcaError("bad_config", "periodKeyInput is boolean");
    }
    this.#periodKeyInput = options.periodKeyInput ?? false;
    const bounds = options.requestBounds ?? [];
    if (!Array.isArray(bounds) || bounds.some((bound) => typeof bound !== "function")) {
      throw dcaError("bad_config", "requestBounds is a list of functions over the request");
    }
    this.#requestBounds = Object.freeze([...bounds]);
    const coordinates = options.extensionCoordinates ?? {};
    if (coordinates === null || typeof coordinates !== "object" || Array.isArray(coordinates)) {
      throw dcaError("bad_config", "extensionCoordinates is an object keyed by extension name");
    }
    this.#extensionCoordinates = new Map();
    for (const [name, presents] of Object.entries(BUILT_IN_EXTENSION_COORDINATES)) {
      if (this.#selectedExtensions.has(name)) this.#extensionCoordinates.set(name, presents);
    }
    for (const [name, presents] of Object.entries(coordinates)) {
      if (!this.#selectedExtensions.has(name)) {
        throw dcaError(
          "bad_config",
          `extensionCoordinates names ${JSON.stringify(name)}, which is not selected`,
        );
      }
      if (typeof presents !== "function") {
        throw dcaError(
          "bad_config",
          `the coordinate reading of ${JSON.stringify(name)} is a function`,
        );
      }
      this.#extensionCoordinates.set(name, presents);
    }
    this.#maxBodyBytes = cap(limits, "maxBodyBytes");
    this.#maxEntries = cap(limits, "maxEntries");
    this.#maxEntriesPerGroup = cap(limits, "maxEntriesPerGroup");
  }

  /**
   * @param {string} code
   * @returns {DcaFailure}
   */
  #fail(code) {
    return { kind: "failure", code };
  }

  /**
   * Validate and project every represented capability before the response is
   * built, so a successful document cannot exist alongside an omitted,
   * malformed, or unconfigured representation.
   *
   * @param {any[]} capabilities
   * @returns {{ keys: Record<string, Record<string, string>>, contexts: Record<string, { chainsPerDay: number, periodMinutes: number }> }}
   */
  #encodeCapabilities(capabilities) {
    /** @type {Record<string, Record<string, string>>} */
    const encoded = {};
    /** @type {Record<string, { chainsPerDay: number, periodMinutes: number }>} */
    const contexts = {};
    for (const capability of capabilities) {
      if (!isTypedCapability(capability)) {
        throw dcaError(
          "bad_config",
          "an engine capability record has kind, access group, entries, and interpretation",
        );
      }
      const encoder = this.#capabilityEncoders.get(capability.kind);
      if (typeof encoder !== "function") {
        throw dcaError(
          "bad_config",
          `no capability encoder is configured for ${JSON.stringify(capability.kind)}`,
        );
      }
      const contribution = encoder(capability);
      if (
        contribution === null ||
        typeof contribution !== "object" ||
        contribution.section !== "chainKeys" ||
        typeof contribution.accessGroup !== "string" ||
        contribution.accessGroup.length === 0 ||
        !nonemptyStringMap(contribution.entries) ||
        contribution.periodGeometry === null ||
        typeof contribution.periodGeometry !== "object" ||
        Array.isArray(contribution.periodGeometry) ||
        !Number.isInteger(contribution.periodGeometry.chainsPerDay) ||
        !Number.isInteger(contribution.periodGeometry.periodMinutes) ||
        contribution.periodGeometry.chainsPerDay <= 0 ||
        contribution.periodGeometry.periodMinutes <= 0
      ) {
        throw dcaError(
          "bad_config",
          "a capability encoder returns one known nonempty section contribution with complete chain geometry",
        );
      }
      if (Object.hasOwn(encoded, contribution.accessGroup)) {
        throw dcaError(
          "bad_config",
          "capability encoders may not collide on one response section and access group",
        );
      }
      setOwn(encoded, contribution.accessGroup, contribution.entries);
      if (Object.keys(contexts).length > 0) {
        const first = Object.values(contexts)[0];
        if (
          first.chainsPerDay !== contribution.periodGeometry.chainsPerDay ||
          first.periodMinutes !== contribution.periodGeometry.periodMinutes
        )
          throw dcaError(
            "bad_config",
            "one period geometry applies to every response chain family",
          );
      }
      setOwn(contexts, contribution.accessGroup, {
        chainsPerDay: contribution.periodGeometry.chainsPerDay,
        periodMinutes: contribution.periodGeometry.periodMinutes,
      });
    }
    return { keys: encoded, contexts };
  }

  /**
   * @param {DcaRequest} request
   * @returns {boolean}
   */
  #overCap(request) {
    // Count before signature verification or private-key work. This count is
    // coarser than the engine's walk on purpose: the engine skips a section
    // or group that is not a map, while an array is counted here by its
    // indices. So this check can refuse a malformed request for size when the
    // engine would have answered it with nothing. An admission check should
    // err in that direction, and it is cheaper than deciding shape twice.

    // Read the raw container rather than the narrowed accessors; the comment
    // in #hasInvalidBaseCoordinate explains why.
    const counts = requestEntryCounts(request.sealed);
    return (
      counts.entries > this.#maxEntries ||
      [...counts.groups.values()].some((count) => count > this.#maxEntriesPerGroup)
    );
  }

  /**
   * Whether a base request names an identifier the format does not admit.
   * Structural admission runs before policy, BIND construction, or
   * opening-key work, and every rule here is decidable from the request as
   * it arrived.
   *
   * This method checks member names against the identifier grammar instead of
   * a separate delimiter check. The grammar is narrower than such a check and
   * refuses the BIND delimiter along with everything else it refuses, so a
   * name that cannot be sealed at, walked across runtimes, or represented in
   * an error coordinate is refused here and never reaches a policy decision.
   *
   * @param {DcaRequest} request
   * @returns {boolean}
   */
  #hasInvalidBaseCoordinate(request) {
    const sealed = request.sealed;
    if (sealed === null || typeof sealed !== "object" || Array.isArray(sealed)) return true;
    // Delivery blocks may omit this member, but the request container is
    // required even when only selected period coordinates are presented.
    if (own(sealed, "contentKeys") === undefined) return true;

    // Read the sections as they arrived. The accessors used below narrow any
    // value that is not a non-array object to `undefined`. A malformed named
    // map would then look the same as an absent one, and a well-formed sibling
    // section would carry the request on. A present named map that is not a
    // non-array object fails admission for the whole request, like every other
    // request map, so this loop reads it from the raw container.
    for (const name of ["contentKeys", ...(this.#periodKeyInput ? ["periodKeys"] : [])]) {
      const section = own(request.sealed, name);
      if (section === undefined) continue;
      if (section === null || typeof section !== "object" || Array.isArray(section)) return true;
    }

    for (const contentName of Object.keys(request.sealedContentKeys ?? {})) {
      if (!isContentName(contentName)) return true;
    }

    if (this.#periodKeyInput) {
      const supplied = own(request.sealed, "periodKeys");
      if (supplied !== undefined && Object.keys(request.sealedPeriodKeys ?? {}).length === 0) {
        return true;
      }
      for (const [accessGroup, periods] of Object.entries(request.sealedPeriodKeys ?? {})) {
        if (!isAccessGroup(accessGroup)) return true;
        if (periods === null || typeof periods !== "object" || Array.isArray(periods)) return true;
        if (Object.keys(periods).length === 0) return true;
        if (Object.keys(periods).some((t) => !isPeriodKeyLabel(t))) return true;
      }
    }

    // `issuerName` and `keyId` together address an opening key. `issuerName`
    // is a member-name identifier like the coordinates above. `keyId` is
    // opaque: a publisher names its issuer's key with whatever value that
    // deployment agreed on. The corpus uses "2025-10", which the name grammar
    // refuses, and the format's identifier rules cover the coordinates and
    // `issuerName` but not `keyId`. `spec--core-protocol.md` requires only that
    // `keyId` is a non-empty string. Both members are required request
    // structure, and an invalid one is refused here before policy or
    // opening-key lookup.
    const issuerName = request.issuerName;
    if (!isIssuerName(issuerName)) return true;

    const keyId = request.keyId;
    if (typeof keyId !== "string" || keyId.length === 0) return true;

    return false;
  }

  /**
   * Whether the request presents no coordinate at all. A request must carry
   * at least one base or selected-extension coordinate. A request with none
   * asks nothing an issuer could answer, so it is refused here instead of
   * going on to an opening key and getting an empty map back. A group name
   * counts as a coordinate on its own, as policy treats it, so a family with
   * no member under it can count only where that selected extension defines
   * the group itself as a coordinate. Period-key families are admitted as
   * non-empty before this check.
   *
   * @param {DcaRequest} request
   * @returns {boolean}
   */
  #hasNoCoordinate(request) {
    // A selected extension's coordinate counts once this issuer has selected
    // that extension. An issuer that relays chain families and answers with
    // period keys has selected chain keys and returns no chain section at
    // all, so a response encoder is the wrong signal to read here.
    const sections = [
      request.sealedContentKeys,
      ...(this.#periodKeyInput ? [request.sealedPeriodKeys] : []),
    ];
    if (sections.some((section) => Object.keys(section ?? {}).length > 0)) return false;
    for (const presents of this.#extensionCoordinates.values()) {
      if (presents(request) === true) return false;
    }
    return true;
  }

  /**
   * The selected extensions' own bounds, before any verification or key work.
   *
   * @param {DcaRequest} request
   * @returns {string|null} the refusal code, or null when every bound passed
   */
  #boundRefusal(request) {
    for (const bound of this.#requestBounds) {
      try {
        bound(request);
      } catch (cause) {
        const code = /** @type {any} */ (cause)?.code;
        if (BOUND_CODES.includes(code)) return code;
        throw cause;
      }
    }
    return null;
  }

  /**
   * Project optional period-key input out before core processing when this issuer
   * has not selected it. The admitted request itself stays unchanged for the
   * host's cache identity and request association.
   *
   * @param {DcaRequest} request
   * @returns {DcaRequest}
   */
  #selectedRequest(request) {
    if (this.#periodKeyInput || own(request.sealed, "periodKeys") === undefined) return request;

    /** @type {Record<string, unknown>} */
    const document = {};
    for (const [name, value] of Object.entries(request.toObject())) setOwn(document, name, value);

    /** @type {Record<string, unknown>} */
    const sealed = {};
    for (const [name, value] of Object.entries(request.sealed ?? {})) {
      if (name !== "periodKeys") setOwn(sealed, name, value);
    }
    setOwn(document, "sealed", sealed);
    return new DcaRequest(document);
  }

  /**
   * Structural admission, the first of the two operations. It applies this
   * processor's caps, verifies the engine's operating-name scope, and returns
   * the admitted request for preflight and cache lookup (stages 3-4). It does
   * not make an access-policy decision or build a response.
   *
   * A raw request document is checked against the byte cap before it is
   * parsed, and it is parsed exactly once into the request the whole protocol
   * path then uses. An already constructed `DcaRequest` came from a host that
   * owned its parse and measured its bytes with it, so the byte cap does not
   * re-measure one here; only the coordinate caps apply. In both cases admission never
   * runs again at stage 5: the request it returns is used unchanged for cache
   * identity and miss processing.
   *
   * @param {string|DcaRequest} requestOrDocument
   * @returns {DcaAdmission}
   */
  admit(requestOrDocument) {
    let request;
    if (requestOrDocument instanceof DcaRequest) {
      request = requestOrDocument;
    } else if (typeof requestOrDocument === "string") {
      // UTF-8 never uses fewer bytes than the string has code units, so a
      // string with more code units than the cap is already over it, and
      // encoding it to prove that would make the allocation the cap exists to
      // avoid. A string that passes that check is short enough to encode and
      // measure exactly. The second check is needed because the cap counts
      // bytes, and multi-byte text is over it at a length the first check lets
      // through.
      if (requestOrDocument.length > this.#maxBodyBytes) return this.#fail("body_too_large");
      if (utf8Encode(requestOrDocument).length > this.#maxBodyBytes)
        return this.#fail("body_too_large");
      try {
        request = parseDcaRequest(requestOrDocument);
      } catch (cause) {
        // As in processMiss, a `bad_config` thrown below this boundary means
        // this server is broken, so it is re-coded to `internal_error` and is
        // never returned as a code. `invalid_json`, the real parse refusal,
        // still passes through unchanged.
        const code = /** @type {any} */ (cause)?.code ?? "internal_error";
        return this.#fail(code === "bad_config" ? "internal_error" : code);
      }
    } else {
      throw dcaError("bad_config", "admit takes a DcaRequest or a raw request document");
    }

    const document = request.toObject();
    if (document === null || typeof document !== "object" || Array.isArray(document))
      return this.#fail("binding_failed");
    if (typeof request.version !== "string") return this.#fail("bad_version");
    // Carrier admission precedes this pure guard; version-dependent coordinate
    // grammar and all downstream publisher/caller work follow it.
    try {
      if (this.#engine.checkVersion) this.#engine.checkVersion(request);
      else checkVersion(request); // Unlock-only engines retain the baseline guard.
    } catch (cause) {
      if (/** @type {any} */ (cause)?.code === "bad_version") return this.#fail("bad_version");
      throw cause;
    }

    try {
      this.#engine.checkOperatingIssuerName(request);
    } catch (cause) {
      if (/** @type {any} */ (cause)?.code === "out_of_scope_issuer")
        return this.#fail("out_of_scope_issuer");
      throw cause;
    }

    if (this.#overCap(request)) return this.#fail("too_many_entries");
    const bounded = this.#boundRefusal(request);
    if (bounded !== null) return this.#fail(bounded);
    if (this.#hasInvalidBaseCoordinate(request)) return this.#fail("binding_failed");
    if (this.#hasNoCoordinate(request)) return this.#fail("binding_failed");
    return { kind: "admitted", request };
  }

  /**
   * Miss processing, the second operation (stage 5). Given the already
   * admitted request and its policy input, it calls the engine and constructs
   * one semantic result: granted key material, per-item errors, any
   * not-delivered family report and `policyData` on success, or a failure
   * code. It does not re-admit and does
   * not re-parse; admission already ran, and admission's caps are not checked
   * again here.
   *
   * @param {IssuerInvocation} invocation - the host-owned context for one
   *   already-admitted cache miss
   * @returns {Promise<DcaResult>}
   */
  async processMiss(invocation) {
    if (invocation === null || typeof invocation !== "object" || Array.isArray(invocation)) {
      throw dcaError("bad_config", "processMiss takes one invocation object");
    }
    const { request, registration, policyInput = {}, capturedAtMs, verification } = invocation;
    if (!(request instanceof DcaRequest)) {
      throw dcaError("bad_config", "processMiss takes a DcaRequest; parse or construct one first");
    }
    if (
      capturedAtMs !== undefined &&
      (typeof capturedAtMs !== "number" ||
        !Number.isFinite(capturedAtMs) ||
        Math.abs(capturedAtMs) > MAX_DATE_EPOCH_MS)
    ) {
      throw dcaError(
        "bad_config",
        "capturedAtMs is a finite host-captured epoch-millisecond number within Date range",
      );
    }
    // A host-captured instant goes into the source-facing canonical context.
    // When it is absent, the direct-library adapter path remains in effect for
    // a composition explicitly configured with a clock; period-key-only engines
    // ignore the instant.
    /** @type {import('./IssuerEngine.js').IssuerUnlockInvocation} */
    const engineInvocation = {};
    if (capturedAtMs !== undefined) engineInvocation.capturedAtMs = capturedAtMs;
    if (verification !== undefined) engineInvocation.verification = verification;

    let result;
    try {
      result = await this.#engine.unlock(
        this.#selectedRequest(request),
        registration,
        policyInput,
        capturedAtMs === undefined && verification === undefined ? undefined : engineInvocation,
      );
    } catch (cause) {
      // A config-class engine throw (a keyStore contradiction, say) means this
      // server is broken, not a caller's misconfiguration, so `bad_config` is
      // re-coded to `internal_error` at this request boundary. After this,
      // neither configuration code appears as a returned result.
      const code = /** @type {any} */ (cause)?.code ?? "internal_error";
      return this.#fail(
        ["bad_config", "unsupported_option"].includes(code) ? "internal_error" : code,
      );
    }

    // The engine answer is read here and nowhere else, so an engine that
    // returns something other than an UnlockResult is a server fault rather
    // than a delivery. Reading `result.errors` from a duck-typed engine that
    // omitted it would throw a raw TypeError out of a call that this port does
    // not wrap in a catch. This check, the same shape check the engine runs on
    // the policy decision, maps that case to a returned failure instead.
    // Period-key result representation is independent of period-key request
    // input. A selected chain-key source may project an authorized chain key to
    // period keys even when this processor intentionally ignores sealed.periodKeys.
    if (
      result === null ||
      typeof result !== "object" ||
      result.contentKeys === null ||
      typeof result.contentKeys !== "object" ||
      (result.periodKeys !== undefined && !isPeriodKeyResult(result.periodKeys)) ||
      result.errors === null ||
      typeof result.errors !== "object" ||
      (result.capabilities !== undefined && !Array.isArray(result.capabilities)) ||
      hasNonemptyUncomposedCapability(result, "periodCapabilities") ||
      hasNonemptyUncomposedCapability(result, "chainKeys") ||
      (result.notDelivered !== undefined &&
        !isNotDeliveredReport(result.notDelivered, result, result.capabilities ?? [])) ||
      (result.sections !== undefined &&
        (result.sections === null ||
          typeof result.sections !== "object" ||
          Array.isArray(result.sections)))
    ) {
      return this.#fail("internal_error");
    }

    /** @type {{ keys: Record<string, Record<string, string>>, contexts: Record<string, { chainsPerDay: number, periodMinutes: number }> }} */
    let encodedCapabilities;
    try {
      encodedCapabilities = this.#encodeCapabilities(result.capabilities ?? []);
    } catch {
      return this.#fail("internal_error");
    }

    /** @type {any} */
    const document = { keys: { contentKeys: result.contentKeys } };

    // The cached delivery path depends on which fields are present, so an
    // empty periodKeys object would mean something different from no field.
    if (result.periodKeys && Object.keys(result.periodKeys).length > 0) {
      document.keys.periodKeys = result.periodKeys;
    }
    if (Object.keys(encodedCapabilities.keys).length > 0) {
      document.keys.chainKeys = encodedCapabilities.keys;
    }

    // A success response can carry per-item failures alongside coordinates
    // that did open. The same response carries the relabel defense and the
    // ordinary stale-key answer.
    if (Object.keys(result.errors).length > 0) {
      document.errors = result.errors;
    }

    // An empty report is no member: period keys Section 5.6 requires a present
    // `notDelivered` to name at least one family.
    if (result.notDelivered !== undefined && Object.keys(result.notDelivered).length > 0) {
      document.notDelivered = result.notDelivered;
    }

    // Selected response sections follow every base member. Only the shared
    // period geometry may meet a base member, and then it must be equal.
    for (const [name, value] of Object.entries(result.sections ?? {})) {
      if (BASE_DOCUMENT_MEMBERS.includes(name)) return this.#fail("internal_error");
      if (Object.hasOwn(document, name)) {
        if (name !== "periodGeometry" || !periodGeometriesAgree(document[name], value))
          return this.#fail("internal_error");
        continue;
      }
      setOwn(document, name, value);
    }

    return {
      kind: "success",
      document,
      policyData: result.policyData,
    };
  }
}

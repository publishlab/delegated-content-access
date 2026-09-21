// @ts-check

// The issuer core has two operations that the application calls at separate
// stages. `admit` structurally admits one request and returns it for the
// application to carry through preflight and cache lookup; `processMiss` takes
// that admitted request on a cache miss and turns it into one semantic result.
// This file handles no HTTP status, refusal wording, logging, authentication,
// or post-delivery work. A port decides how an error code crosses its transport
// boundary.

import { dcaError } from "../core-shared/errors.js";
import { utf8Encode } from "../core-shared/codec.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { isExactPeriodLabel } from "../core-shared/periodLabels.js";
import { isAccessGroup, isContentName, isIssuerName } from "../core-shared/names.js";
import { own, setOwn } from "../core-shared/wire.js";
import { DcaRequest, parseDcaRequest } from "../core-shared--client-issuer/DcaRequest.js";

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
 */

const OPTIONS = ["limits", "capabilityEncoders", "selectedExtensions", "exactPeriodInput"];
const LIMITS = ["maxBodyBytes", "maxEntries", "maxEntriesPerGroup"];
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

// The structural admission limits this reference issuer applies when a
// deployment names none. An omitted member never means unbounded opening work:
// a deployment that names one member keeps these values for the others. These
// are reference deployment values rather than a wire maximum, so another
// implementation may pick different finite limits and refuse a well-formed
// request above them.
const DEFAULT_LIMITS = Object.freeze({
  maxBodyBytes: 64 * 1024,
  maxEntries: 16,
  maxEntriesPerGroup: 4,
});

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
function nonemptyExactKeyMap(value) {
  return (
    nonemptyStringMap(value) &&
    Object.values(value).every((entry) => binaryStringBytes(entry)?.length === 16)
  );
}

/** @param {any} value */
function exactPeriodResult(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([accessGroup, family]) =>
        isAccessGroup(accessGroup) &&
        nonemptyExactKeyMap(family) &&
        Object.keys(family).every(isExactPeriodLabel),
    )
  );
}

/**
 * A legacy member is harmless only when it is an empty map. A populated old
 * output would otherwise be silently omitted from a successful typed answer.
 *
 * @param {any} result
 * @param {'periodCapabilities'|'periodChainKeys'} field
 */
function hasNonemptyLegacyCapability(result, field) {
  if (!Object.hasOwn(result, field)) return false;
  const value = result[field];
  return (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length > 0
  );
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
  #exactPeriodInput;

  /** @type {number} */
  #maxBodyBytes;

  /** @type {number} */
  #maxEntries;

  /** @type {number} */
  #maxEntriesPerGroup;

  /**
   * @param {{ unlock: (request: DcaRequest, registration: any, policyInput?: any, invocation?: import('./IssuerEngine.js').IssuerInvocationContext) => Promise<{ contentKeys: Record<string, string>, periodKeys?: Record<string, Record<string, string>>, capabilities?: any[], errors: Record<string, object>, policyData?: any }> }} issuerEngine
   * @param {object} [options]
   * @param {{ maxBodyBytes?: number, maxEntries?: number, maxEntriesPerGroup?: number }} [options.limits] -
   *   the admission caps this deployment replaces; every member left out keeps
   *   its `DEFAULT_LIMITS` value. A present member must be a positive number,
   *   so a member written as `undefined` counts as supplied and is refused.
   * @param {Record<string, (record: any) => { section: string, accessGroup: string, entries: Record<string, string>, periodChain: { chainsPerDay: number, periodMinutes: number } }>} [options.capabilityEncoders] -
   *   the selected typed-capability projections for this issuer deployment
   * @param {string[]} [options.selectedExtensions] - the extensions this issuer
   *   deployment has selected, named the way the request members are. List an
   *   extension here whether or not it also returns a response section:
   *   selection decides which request members are recognized, and response
   *   encoding decides what goes back.
   * @param {boolean} [options.exactPeriodInput] - whether trusted deployment
   *   configuration selects exact-period request processing
   */
  constructor(issuerEngine, options = {}) {
    if (!issuerEngine) throw dcaError("bad_config", "IssuerProcessor needs an engine");

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
    if (options.exactPeriodInput !== undefined && typeof options.exactPeriodInput !== "boolean") {
      throw dcaError("bad_config", "exactPeriodInput is boolean");
    }
    this.#exactPeriodInput = options.exactPeriodInput ?? false;
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
        contribution.section !== "periodChainKeys" ||
        typeof contribution.accessGroup !== "string" ||
        contribution.accessGroup.length === 0 ||
        !nonemptyStringMap(contribution.entries) ||
        contribution.periodChain === null ||
        typeof contribution.periodChain !== "object" ||
        Array.isArray(contribution.periodChain) ||
        !Number.isInteger(contribution.periodChain.chainsPerDay) ||
        !Number.isInteger(contribution.periodChain.periodMinutes) ||
        contribution.periodChain.chainsPerDay <= 0 ||
        contribution.periodChain.periodMinutes <= 0
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
      setOwn(contexts, contribution.accessGroup, {
        chainsPerDay: contribution.periodChain.chainsPerDay,
        periodMinutes: contribution.periodChain.periodMinutes,
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
    const sealed = request.sealed;
    if (sealed === null || typeof sealed !== "object") return false;

    const contentKeys = own(sealed, "contentKeys");
    let entries =
      contentKeys !== null && typeof contentKeys === "object" ? Object.keys(contentKeys).length : 0;

    /** @type {Map<string, number>} */
    const entriesByGroup = new Map();
    for (const field of ["periodKeys", "periodChainKeys"]) {
      const periodKeys = own(sealed, field);
      if (periodKeys !== null && typeof periodKeys === "object") {
        for (const accessGroup of Object.keys(periodKeys)) {
          const periods = periodKeys[accessGroup];
          if (periods === null || typeof periods !== "object") continue;

          const count = Object.keys(periods).length;
          const groupCount = (entriesByGroup.get(accessGroup) ?? 0) + count;
          entriesByGroup.set(accessGroup, groupCount);
          if (groupCount > this.#maxEntriesPerGroup) return true;
          entries += count;
        }
      }
    }

    return entries > this.#maxEntries;
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
    // Read the sections as they arrived. The accessors used below narrow any
    // value that is not a non-array object to `undefined`. A malformed named
    // map would then look the same as an absent one, and a well-formed sibling
    // section would carry the request on. A present named map that is not a
    // non-array object fails admission for the whole request, like every other
    // request map, so this loop reads it from the raw container.
    for (const name of ["contentKeys", ...(this.#exactPeriodInput ? ["periodKeys"] : [])]) {
      const section = own(request.sealed, name);
      if (section === undefined) continue;
      if (section === null || typeof section !== "object" || Array.isArray(section)) return true;
    }

    for (const contentName of Object.keys(request.sealedContentKeys ?? {})) {
      if (!isContentName(contentName)) return true;
    }

    if (this.#exactPeriodInput) {
      const supplied = own(request.sealed, "periodKeys");
      if (supplied !== undefined && Object.keys(request.sealedPeriodKeys ?? {}).length === 0) {
        return true;
      }
      for (const [accessGroup, periods] of Object.entries(request.sealedPeriodKeys ?? {})) {
        if (!isAccessGroup(accessGroup)) return true;
        if (periods === null || typeof periods !== "object" || Array.isArray(periods)) return true;
        if (Object.keys(periods).length === 0) return true;
        if (Object.keys(periods).some((t) => !isExactPeriodLabel(t))) return true;
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
   * the group itself as a coordinate. Exact-period families are admitted as
   * non-empty before this check.
   *
   * @param {DcaRequest} request
   * @returns {boolean}
   */
  #hasNoCoordinate(request) {
    // The period-chain section counts as a coordinate once this issuer has
    // selected the extension. An issuer that relays chain families and answers
    // with exact leaves has selected it and returns no chain section at all, so
    // a response encoder is the wrong signal to read here.
    const sections = [
      request.sealedContentKeys,
      ...(this.#exactPeriodInput ? [request.sealedPeriodKeys] : []),
      ...(this.#selectedExtensions.has("period-chain") ? [request.sealedPeriodChainKeys] : []),
    ];
    return sections.every((section) => Object.keys(section ?? {}).length === 0);
  }

  /**
   * Project optional exact input out before core processing when this issuer
   * has not selected it. The admitted request itself stays unchanged for the
   * host's cache identity and request association.
   *
   * @param {DcaRequest} request
   * @returns {DcaRequest}
   */
  #selectedRequest(request) {
    if (this.#exactPeriodInput || own(request.sealed, "periodKeys") === undefined) return request;

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
   * processor's caps and returns the admitted request for the application to
   * carry through preflight and cache lookup (stages 3-4). It does not call
   * the engine and does not build a response.
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

    if (this.#overCap(request)) return this.#fail("too_many_entries");
    if (this.#hasInvalidBaseCoordinate(request)) return this.#fail("binding_failed");
    if (this.#hasNoCoordinate(request)) return this.#fail("binding_failed");
    return { kind: "admitted", request };
  }

  /**
   * Miss processing, the second operation (stage 5). Given the already
   * admitted request and its policy input, it calls the engine and constructs
   * one semantic result: granted key material, per-item errors, and
   * `policyData` on success, or a failure code. It does not re-admit and does
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
    const { request, registration, policyInput = {}, capturedAtMs } = invocation;
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
    // a composition explicitly configured with a clock; exact-only engines
    // ignore the instant.
    const sourceInvocation = capturedAtMs === undefined ? undefined : { capturedAtMs };

    let result;
    try {
      result = await this.#engine.unlock(
        this.#selectedRequest(request),
        registration,
        policyInput,
        sourceInvocation,
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
    // Exact result representation is independent of exact request input. A
    // selected period-chain source may project authorized chain state to exact
    // leaves even when this processor intentionally ignores sealed.periodKeys.
    if (
      result === null ||
      typeof result !== "object" ||
      result.contentKeys === null ||
      typeof result.contentKeys !== "object" ||
      (result.periodKeys !== undefined && !exactPeriodResult(result.periodKeys)) ||
      result.errors === null ||
      typeof result.errors !== "object" ||
      (result.capabilities !== undefined && !Array.isArray(result.capabilities)) ||
      hasNonemptyLegacyCapability(result, "periodCapabilities") ||
      hasNonemptyLegacyCapability(result, "periodChainKeys")
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
      document.keys.periodChainKeys = encodedCapabilities.keys;
      document.periodChain = { accessGroups: encodedCapabilities.contexts };
    }

    // A success response can carry per-item failures alongside coordinates
    // that did open. The same response carries the relabel defense and the
    // ordinary stale-key answer.
    if (Object.keys(result.errors).length > 0) {
      document.errors = result.errors;
    }

    return {
      kind: "success",
      document,
      policyData: result.policyData,
    };
  }
}

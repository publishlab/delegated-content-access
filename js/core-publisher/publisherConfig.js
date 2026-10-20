// @ts-check
//
// The publisher configuration checks that can run before a Sealer exists.
// Tooling may call this at edit or deploy time; Sealer calls the same function
// again at its runtime boundary. No operational dependency is invoked here.

import { seal as sealKey } from "../core-shared--publisher-issuer/keySealing.js";
import { validateIssuerName } from "../core-shared/names.js";
import { signableOrigin } from "../core-shared/publisherOrigin.js";
import { dcaError } from "../core-shared/errors.js";
import { checkedContentKeyWrap } from "./contentKeyWrap.js";
import { checkedIssuerSupplyPlanner } from "./issuerSupplyPlan.js";
import { chainMemberLimit } from "../core-shared/chainMemberLimit.js";
import { requestLimits } from "../core-shared/requestLimits.js";
import { settledPeriod } from "../core-shared--publisher-issuer/periodKeys.js";

const OPTIONS = [
  "origin",
  "developmentHttpOrigin",
  "clock",
  "random",
  "issuers",
  "signingKeys",
  "signingKid",
  "period",
  "periodKeySupply",
  "keySealing",
  "contentKeyWrapStrategy",
  "issuerSupplyPlanFor",
  "itemPreparations",
  "itemOptionMembers",
];

const CORE_KEY_SEALING = { seal: sealKey };

/** The options a supplied `period` may carry; each omitted one takes its default. */
const PERIOD_OPTIONS = ["length", "slots"];

/**
 * The members of one `issuers` entry that base reads, and the one definition
 * of them. A composed publisher admits these plus the members its selected
 * contributions declare; the plain Sealer stays open to any other member.
 * These are configuration members, not the members of an emitted issuer block.
 */
export const ISSUER_CONFIG_MEMBERS = Object.freeze([
  "issuerName",
  "keyId",
  "algorithm",
  "publicKey",
  "limits",
  "maxChainMembersPerMessage",
  "clientRequestExtraBytes",
  "envelope",
]);

/** Procedures the core key sealing seals itself; `envelope` never names one. */
const BASE_ENVELOPE_PROCEDURES = Object.freeze(["ecdh-p256", "rsa-oaep"]);

/**
 * Raw constructor input. Each member stays unknown until the existing runtime
 * admission checks and operations read it.
 *
 * @typedef {object} PublisherConfigInput
 * @property {unknown} [origin]
 * @property {unknown} [developmentHttpOrigin]
 * @property {unknown} [clock]
 * @property {unknown} [random]
 * @property {unknown} [issuers]
 * @property {unknown} [signingKeys]
 * @property {unknown} [signingKid]
 * @property {unknown} [period]
 * @property {unknown} [periodKeySupply]
 * @property {unknown} [keySealing]
 * @property {unknown} [contentKeyWrapStrategy]
 * @property {unknown} [issuerSupplyPlanFor]
 * @property {unknown} [itemPreparations] - set by publisher composition from
 *   the selected contributions
 * @property {unknown} [itemOptionMembers] - set by publisher composition from
 *   the selected contributions
 */

/**
 * Validate and snapshot the constructor-owned publisher configuration.
 * Callers that only need admission may ignore the returned runtime view.
 *
 * @param {PublisherConfigInput} config
 * @returns {any}
 */
export function validatePublisherConfig(config) {
  const {
    origin,
    developmentHttpOrigin,
    clock,
    random,
    issuers,
    signingKeys,
    signingKid,
    period,
    periodKeySupply,
    keySealing,
    contentKeyWrapStrategy,
    issuerSupplyPlanFor,
    itemPreparations,
    itemOptionMembers,
  } = config;

  // The issuer compares the observed Origin byte-for-byte. Production is
  // HTTPS; the explicit development profile admits only localhost HTTP.
  if (signableOrigin(origin, developmentHttpOrigin === true) !== origin) {
    throw dcaError("bad_config", "Sealer needs the canonical https publisher context origin");
  }
  if (!clock) throw dcaError("bad_config", "Sealer needs a clock");
  if (!random) throw dcaError("bad_config", "Sealer needs a random");
  const issuerList = /** @type {{ length?: unknown }|null} */ (issuers);
  if (!issuerList?.length) {
    throw dcaError("bad_config", "Sealer needs at least one issuer");
  }

  // The supply sources period keys. A periodSecret set to null still uses the
  // old shape; silently accepting it would drop the cached path.
  if ("periodSecret" in config) {
    throw dcaError("bad_config", "the Sealer takes no periodSecret; hand it a periodKeySupply");
  }
  // Keep the old-shape refusal above specific; only then report other names.
  for (const name of Object.keys(config ?? {})) {
    if (!OPTIONS.includes(name)) {
      throw dcaError("unsupported_option", `Sealer has no ${name} yet, and will not pretend to`);
    }
  }

  // A supplied but unusable seam must not silently fall back to the
  // content-key-only case. Arity catches the former derive(accessGroup, t,
  // periodSecret) API.
  if (
    periodKeySupply !== undefined &&
    typeof (/** @type {{ derive?: unknown }|null} */ (periodKeySupply)?.derive) !== "function"
  ) {
    throw dcaError("bad_config", "a periodKeySupply is an object with a derive(accessGroup, t)");
  }
  if (
    periodKeySupply !== undefined &&
    /** @type {{ derive: Function }} */ (periodKeySupply).derive.length > 2
  ) {
    throw dcaError(
      "bad_config",
      "a periodKeySupply derives with derive(accessGroup, t); a 3-arg supply is the old shape that took the periodSecret",
    );
  }
  if (
    /** @type {{ familyPlan?: unknown }|null} */ (periodKeySupply)?.familyPlan !== undefined &&
    typeof (/** @type {{ familyPlan?: unknown }|null} */ (periodKeySupply)?.familyPlan) !==
      "function"
  ) {
    throw dcaError(
      "bad_config",
      "periodKeySupply.familyPlan is a function when the supply plans per family",
    );
  }
  // The Sealer reads only these two members, so it refuses any other rather
  // than seal as if it had honored it.
  for (const name of Object.keys(/** @type {object} */ (periodKeySupply ?? {}))) {
    if (name !== "derive" && name !== "familyPlan") {
      throw dcaError(
        "unsupported_option",
        `periodKeySupply has no ${name} yet, and will not pretend to`,
      );
    }
  }
  // An explicit key-sealing substitution must at least provide the operation
  // the sealer calls. Falling back from a malformed substitution would silently
  // change the envelope implementation while leaving plausible wire data.
  if (
    keySealing !== undefined &&
    typeof (/** @type {{ seal?: unknown }|null} */ (keySealing)?.seal) !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "a keySealing is an object with a seal(keyBytes, publicKey, algorithm, options)",
    );
  }

  const kids = signingKeys ? Object.keys(/** @type {object} */ (signingKeys)) : [];
  if (kids.length === 0) {
    throw dcaError("bad_config", "Sealer needs a signingKeys map, keyed by kid");
  }
  const kid = signingKid ?? (kids.length === 1 ? kids[0] : undefined);
  if (kid === undefined) {
    throw dcaError("bad_config", "Sealer holds more than one signing key and needs a signingKid");
  }
  // Checked before the lookup: a number finds its key through property-key
  // coercion and would then sign a header whose kid every issuer refuses
  // (docs/spec--core-protocol.md, 4.1).
  if (typeof kid !== "string" || kid === "") {
    throw dcaError("bad_config", "the Sealer's signingKid is a nonempty string");
  }
  if (!Object.hasOwn(/** @type {object} */ (signingKeys), kid)) {
    throw dcaError("bad_config", `Sealer holds no signing key "${kid}"`);
  }
  // The lookup above admits a non-enumerable own entry, and a spread copies
  // only enumerable ones, so the selected key is copied by name as well.
  const signingKey = /** @type {Record<string, unknown>} */ (signingKeys)[kid];

  // Defaults apply to omitted options only. A period the Sealer cannot read
  // would otherwise select hourly periods, a wider key reach than chosen.
  /** @type {Record<string, unknown>} */
  const periodView = {};
  if (period !== undefined) {
    if (period === null || typeof period !== "object" || Array.isArray(period)) {
      throw dcaError("bad_config", "period is an options object with length and slots");
    }
    // Own names, enumerable or not: the check and the copy below must see the
    // same options, or a hidden `length` passes the check and a spread drops
    // it, and the render runs hourly.
    for (const name of Object.getOwnPropertyNames(period)) {
      if (!PERIOD_OPTIONS.includes(name)) {
        throw dcaError("unsupported_option", `period has no ${name} yet, and will not pretend to`);
      }
    }
    for (const name of PERIOD_OPTIONS) {
      if (Object.hasOwn(period, name)) {
        periodView[name] = /** @type {Record<string, unknown>} */ (period)[name];
      }
    }
    settledPeriod(
      /** @type {import('../core-shared--publisher-issuer/periodKeys.js').Period} */ (periodView),
    );
  }

  // issuerName becomes a map key on the wire: reject unsafe or duplicate
  // names here instead of overwriting one issuer during emission.
  const issuerNames = new Set();
  for (const issuer of /** @type {{ issuerName?: unknown, kdf?: unknown, keyId?: unknown, limits?: unknown, maxChainMembersPerMessage?: unknown, clientRequestExtraBytes?: unknown, envelope?: unknown }[]} */ (
    issuers
  )) {
    validateIssuerName(issuer?.issuerName);
    if (issuerNames.has(issuer.issuerName)) {
      throw dcaError(
        "bad_config",
        `issuerName "${issuer.issuerName}" is configured more than once`,
      );
    }
    issuerNames.add(issuer.issuerName);
    // An issuer record is copied wholesale below and the sealing operation is never handed a
    // `kdf`, so a deployment still naming one would seal raw-secret blobs
    // and get no error. keySealing refuses the same member on a call.
    if (issuer.kdf !== undefined) {
      throw dcaError(
        "unsupported_option",
        `issuer "${issuer.issuerName}" states kdf, and a sealed blob carries no derivation`,
      );
    }
    // Every issuer block identifies its opening key. Endpoints belong to
    // client configuration, not publisher configuration or delivery.
    for (const member of /** @type {const} */ (["keyId"])) {
      if (typeof issuer[member] !== "string") {
        throw dcaError("bad_config", `issuer "${issuer.issuerName}" needs a string ${member}`);
      }
    }
    // Each configured issuer is a usable route, and a usable route's keyId is
    // non-empty (docs/spec--core-protocol.md, section 9).
    if (issuer.keyId === "") {
      throw dcaError("bad_config", `issuer "${issuer.issuerName}" needs a nonempty keyId`);
    }
    requestLimits(issuer.limits);
    chainMemberLimit(issuer.maxChainMembersPerMessage);
    const extraBytes = issuer.clientRequestExtraBytes;
    if (
      extraBytes !== undefined &&
      (typeof extraBytes !== "number" || !Number.isSafeInteger(extraBytes) || extraBytes < 0)
    )
      throw dcaError("bad_config", "clientRequestExtraBytes is a nonnegative safe integer");
    // `envelope` selects an extension procedure for this issuer's seals. The
    // core key sealing has none, so the selection needs a key sealing that
    // implements it; the core one would ignore the name and write ordinary
    // blobs under it.
    if (Object.hasOwn(issuer, "envelope")) {
      const { envelope } = issuer;
      if (
        typeof envelope !== "string" ||
        envelope === "" ||
        BASE_ENVELOPE_PROCEDURES.includes(envelope)
      ) {
        throw dcaError(
          "bad_config",
          `issuer "${issuer.issuerName}" names an extension envelope procedure, or omits envelope`,
        );
      }
      if (keySealing === undefined || keySealing === CORE_KEY_SEALING) {
        throw dcaError(
          "bad_config",
          `issuer "${issuer.issuerName}" selects ${envelope}, which the core key sealing cannot seal`,
        );
      }
    }
  }

  const preparations = itemPreparations ?? [];
  if (
    !Array.isArray(preparations) ||
    preparations.some(
      (entry) =>
        entry === null ||
        typeof entry !== "object" ||
        typeof entry.name !== "string" ||
        entry.name === "" ||
        typeof entry.routes !== "function" ||
        typeof entry.prepare !== "function" ||
        (entry.requestRelay !== undefined && typeof entry.requestRelay !== "function") ||
        (entry.envelopes !== undefined &&
          (!Array.isArray(entry.envelopes) ||
            entry.envelopes.some((/** @type {unknown} */ name) => typeof name !== "string"))),
    )
  ) {
    throw dcaError(
      "bad_config",
      "itemPreparations is a list of named item preparations with routes and prepare",
    );
  }
  const optionMembers = itemOptionMembers ?? [];
  if (
    !Array.isArray(optionMembers) ||
    optionMembers.some((name) => typeof name !== "string" || name === "") ||
    new Set(optionMembers).size !== optionMembers.length
  ) {
    throw dcaError("bad_config", "itemOptionMembers is a list of distinct nonempty names");
  }

  return Object.freeze({
    origin,
    clock,
    random,
    signingKeys: { .../** @type {object} */ (signingKeys), [kid]: signingKey },
    signingKid: kid,
    period: periodView,
    periodKeySupply: periodKeySupply ?? null,
    keySealing: keySealing ?? CORE_KEY_SEALING,
    contentKeyWrap: checkedContentKeyWrap(contentKeyWrapStrategy),
    issuerSupplyPlanFor: checkedIssuerSupplyPlanner(issuerSupplyPlanFor),
    itemPreparations: Object.freeze([...preparations]),
    itemOptionMembers: Object.freeze([...optionMembers]),
    issuers: /** @type {{ issuerName?: unknown, kdf?: unknown, limits?: unknown }[]} */ (
      issuers
    ).map((issuer) => ({
      ...issuer,
      limits: requestLimits(issuer.limits),
    })),
  });
}

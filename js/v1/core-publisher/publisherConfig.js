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
];

const CORE_KEY_SEALING = { seal: sealKey };

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
  } = config;

  // The issuer compares the observed Origin byte-for-byte. Production is
  // HTTPS; the explicit development profile admits only localhost HTTP.
  if (signableOrigin(origin, developmentHttpOrigin === true) !== origin) {
    throw dcaError(
      "bad_config",
      "Sealer needs the canonical https origin its renders are delivered from",
    );
  }
  if (!clock) throw dcaError("bad_config", "Sealer needs a clock");
  if (!random) throw dcaError("bad_config", "Sealer needs a random");
  const issuerList = /** @type {{ length?: unknown }|null} */ (issuers);
  if (!issuerList?.length) {
    throw dcaError("bad_config", "Sealer needs at least one issuer");
  }

  // The supply sources exact keys. A periodSecret set to null still uses the
  // old shape; silently accepting it would drop the cached path.
  if ("periodSecret" in config) {
    throw dcaError(
      "bad_config",
      "the Sealer takes no periodSecret; hand it an exact periodKeySupply",
    );
  }
  // Keep the old-shape refusal above specific; only then report other names.
  for (const name of Object.keys(config ?? {})) {
    if (!OPTIONS.includes(name)) {
      throw dcaError("unsupported_option", `Sealer has no ${name} yet, and will not pretend to`);
    }
  }

  // A supplied but unusable seam must not silently fall back to the
  // direct-only case. Arity catches the former derive(accessGroup, t,
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
  if (periodKeySupply && Object.hasOwn(/** @type {object} */ (periodKeySupply), "exactProfile")) {
    throw dcaError("unsupported_option", "periodKeySupply has no width profile selector");
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
  if (!Object.hasOwn(/** @type {object} */ (signingKeys), /** @type {PropertyKey} */ (kid))) {
    throw dcaError("bad_config", `Sealer holds no signing key "${kid}"`);
  }

  // issuerName becomes a map key on the wire: reject unsafe or duplicate
  // names here instead of overwriting one issuer during emission.
  const issuerNames = new Set();
  for (const issuer of /** @type {{ issuerName?: unknown, kdf?: unknown }[]} */ (issuers)) {
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
  }

  return Object.freeze({
    origin,
    clock,
    random,
    signingKeys: { .../** @type {object} */ (signingKeys) },
    signingKid: kid,
    period: { .../** @type {object} */ (period ?? {}) },
    periodKeySupply: periodKeySupply ?? null,
    keySealing: keySealing ?? CORE_KEY_SEALING,
    contentKeyWrap: checkedContentKeyWrap(contentKeyWrapStrategy),
    issuerSupplyPlanFor: checkedIssuerSupplyPlanner(issuerSupplyPlanFor),
    issuers: /** @type {{ issuerName?: unknown, kdf?: unknown }[]} */ (issuers).map((issuer) => ({
      ...issuer,
    })),
  });
}

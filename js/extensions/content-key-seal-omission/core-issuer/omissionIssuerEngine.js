// @ts-check
//
// The issuer side with content-key seal omission selected: the ordinary engine,
// composed with this extension's content-key source.
//
// There is no second engine here. Base runs the unlock it always ran
// (version, registration by exact header kid, signature and renderId, one policy
// call, the complete-denial refusal, the registration-scoped opening-key state
// with its never-held and retired rules, BIND opening, per-item errors and
// `policyData`), and asks this extension for a granted content key its
// content-key seal did not answer. An issuer application may equally construct the base
// engine itself and pass the source; this function names that one line.

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { omissionContentKeySource } from "./omissionContentKeySource.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { dcaError } from "../../../core-shared/errors.js";

const OPTIONS = Object.freeze([
  "supportedVersions",
  "operatingIssuerNames",
  "accessPolicy",
  "developmentHttpOrigin",
  "periodKeyLookup",
]);

/**
 * @param {object} config
 * @param {string[]} [config.supportedVersions]
 * @param {string[]} config.operatingIssuerNames - trusted names this endpoint serves
 * @param {{ decide: Function }} config.accessPolicy - who may read what,
 *   required for base's reason: verification authenticates the publisher and
 *   grants the caller nothing.
 * @param {boolean} [config.developmentHttpOrigin]
 * @param {{ get: (registration: object) => (((accessGroup: string, t: string) => Promise<Uint8Array|null>)|undefined) }} [config.periodKeyLookup] -
 *   issuer application state answering `get(registration)` with the period-key
 *   view held for that authenticated publisher registration
 * @returns {IssuerEngine}
 */
export function omissionIssuerEngine(config = {}) {
  for (const name of Object.keys(config ?? {})) {
    if (!OPTIONS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `omissionIssuerEngine has no ${name} yet, and will not pretend to`,
      );
    }
  }

  const {
    supportedVersions,
    operatingIssuerNames,
    accessPolicy,
    developmentHttpOrigin = false,
    periodKeyLookup,
  } = config ?? {};
  if (periodKeyLookup !== undefined && typeof periodKeyLookup?.get !== "function") {
    throw dcaError(
      "bad_config",
      "a periodKeyLookup is application state answering get(registration) " +
        "with a period-key view taking (accessGroup, t)",
    );
  }
  return new IssuerEngine({
    supportedVersions,
    operatingIssuerNames,
    accessPolicy,
    developmentHttpOrigin,
    contentKeyScope: (registration) => periodKeyLookup?.get(registration),
    contentKeySource: omissionContentKeySource(),
  });
}

/** The name this composition answers for, so a deployment can be checked against it. */
export { EXTENSION_NAME };

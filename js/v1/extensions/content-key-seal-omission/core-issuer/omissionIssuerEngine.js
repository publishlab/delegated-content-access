// @ts-check
//
// The issuer side with content-key seal omission selected: the ordinary engine,
// composed with this extension's content-key source.
//
// There is no second engine here. Base runs the unlock it always ran
// (version, registration by exact header kid, signature and renderId, one policy
// call, the complete-denial refusal, the registration-scoped opening-key state
// with its never-held and retired rules, BIND opening, per-item errors and
// `policyData`), and asks this extension for a granted content key its direct
// seal did not answer. An issuer application may equally construct the base
// engine itself and pass the source; this function names that one line.

import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { omissionContentKeySource } from "./omissionContentKeySource.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { dcaError } from "../../../core-shared/errors.js";

const OPTIONS = Object.freeze([
  "supportedVersions",
  "accessPolicy",
  "developmentHttpOrigin",
  "exactPeriodLeaves",
]);

/**
 * @param {object} config
 * @param {string[]} [config.supportedVersions]
 * @param {{ decide: Function }} config.accessPolicy - who may read what,
 *   required for base's reason: verification authenticates the publisher and
 *   grants the caller nothing.
 * @param {boolean} [config.developmentHttpOrigin]
 * @param {{ get: (registration: object) => (((accessGroup: string, t: string) => Promise<Uint8Array|null>)|undefined) }} [config.exactPeriodLeaves] -
 *   issuer application state answering `get(registration)` with the exact leaf
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
    accessPolicy,
    developmentHttpOrigin = false,
    exactPeriodLeaves,
  } = config ?? {};
  if (exactPeriodLeaves !== undefined && typeof exactPeriodLeaves?.get !== "function") {
    throw dcaError(
      "bad_config",
      "an exactPeriodLeaves is application state answering get(registration) " +
        "with a leaf view taking (accessGroup, t)",
    );
  }
  return new IssuerEngine({
    supportedVersions,
    accessPolicy,
    developmentHttpOrigin,
    contentKeyScope: (registration) => exactPeriodLeaves?.get(registration),
    contentKeySource: omissionContentKeySource(),
  });
}

/** The name this composition answers for, so a deployment can be checked against it. */
export { EXTENSION_NAME };

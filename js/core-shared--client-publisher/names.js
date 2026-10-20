// @ts-check
//
// This module defines the `|` delimiter and the one validation rule for
// `resourceId`.
//
// The identifier grammar the three member-name kinds share moved to
// `core-shared/names`, because the issuer admits names on the request path and
// a module belongs with every role that extracts it. The content AAD lives in
// `contentAad.js` beside this module; it length-prefixes its fields and
// neither joins on `|` nor reads `resourceId`.
//
// `resourceId` is a value and never a member name, so none of the member-name
// rules apply to it. The spec's own example, `123456`, starts with a digit and
// would fail that grammar. Core Section 4.1 asks only for a non-empty Unicode
// scalar string, `|` included: no transcript or BIND grammar joins a
// resourceId.
//
// The wire field names (`contentData`, `sealedContent`, `issuerData` and the
// rest) appear literally at their use sites. At every one of those sites the
// internal name and the wire name are the same string, so the
// `field(internalName)` indirection would map each name to itself today. It
// gets added for the first field whose two names differ.

import { isResourceId } from "../core-shared/names.js";
import { dcaError } from "../core-shared/errors.js";

/**
 * The character the optional period-key constructions join on. No field that
 * enters one of those joins may contain it, so each join is unambiguous.
 */
export const AAD_DELIMITER = "|";

/**
 * @param {unknown} resourceId
 * @returns {string}
 */
export function validateResourceId(resourceId) {
  if (isResourceId(resourceId)) return /** @type {string} */ (resourceId);
  throw dcaError(
    "bad_name",
    `resourceId ${JSON.stringify(resourceId)} is not a non-empty Unicode scalar string`,
  );
}

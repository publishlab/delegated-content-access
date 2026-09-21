// @ts-check
//
// This module defines the aad delimiter and the one validation rule for
// `resourceId`.
//
// The identifier grammar the three member-name kinds share moved to
// `core-shared/names`, because the issuer admits names on the request path and
// a module belongs with every role that extracts it. This module keeps what
// only a publisher writing an aad and a client carrying one into AEAD need.
// The client uses the record's carried aad; it does not rebuild one from this
// resourceId or another local page value.
//
// `resourceId` is a value and never a member name, so none of the member-name
// rules apply to it. The spec's own example, `123456`, starts with a digit and
// would fail that grammar. Because `resourceId` goes into the content aad, it
// has exactly one rule: it must be a non-empty string with no `|` in it.
//
// The wire field names (`contentData`, `sealedContent`, `issuerData` and the
// rest) appear literally at their use sites. At every one of those sites the
// internal name and the wire name are the same string, so the
// `field(internalName)` indirection would map each name to itself today. It
// gets added for the first field whose two names differ.

import { dcaError } from "../core-shared/errors.js";

/**
 * The character the content aad and optional period-key constructions join on.
 * No field that enters one of those joins may contain it, so each join is
 * unambiguous.
 */
export const AAD_DELIMITER = "|";

/**
 * A resourceId is a value on the wire and never a member name, so it keeps the
 * publisher's own identifier scheme - digits, slashes, a non-ASCII slug. The
 * one thing it may not do is carry the character the aad joins on.
 *
 * @param {unknown} resourceId
 * @returns {boolean}
 */
export function isResourceId(resourceId) {
  return (
    typeof resourceId === "string" && resourceId.length > 0 && !resourceId.includes(AAD_DELIMITER)
  );
}

/**
 * @param {unknown} resourceId
 * @returns {string}
 */
export function validateResourceId(resourceId) {
  if (isResourceId(resourceId)) return /** @type {string} */ (resourceId);
  throw dcaError(
    "bad_name",
    `resourceId ${JSON.stringify(resourceId)} is not a non-empty string without "${AAD_DELIMITER}"`,
  );
}

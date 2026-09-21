// @ts-check
//
// This module seals like a publisher that never ran the delimiter ban. It
// writes core's bound bodies, with the value built by `unbannedBindValue`
// below: core's own fields, joined on core's own delimiter, with one of them
// carrying a delimiter inside it.
//
// The vector set needs it because the shipped sealer makes every blob in the
// corpus and refuses these coordinates, so a body cut from an honest render
// cannot carry a blob that was sealed with the delimiter inside a bound field.
// Without such a blob the two implementations the corpus exists to tell apart
// write the same bytes: an issuer that enforces the ban builds no value and
// answers with an error, an issuer that joins whatever it was handed builds a
// value nothing was sealed under, the tag fails, and it answers with the same
// error. Put a blob into the body that was sealed at such a coordinate, and the
// two come apart. The issuer that joins blindly rebuilds the exact string the
// blob was sealed under, the tag verifies, and it hands back a key at a
// coordinate the vector does not list.
//
// No code on the protocol path reaches this.
// `core-shared--publisher-issuer/keySealing.js` builds its value directly from
// `bindFields`, the same string that `bindValue` returns, and carries no seam
// to swap it. The sealer, issuer and client therefore use one grammar, and
// nothing can hand them this one. This module lives in `tools/` as a second
// sealing, imported by `make-vectors.js`, by the replay that checks what it
// wrote, and by nothing a deployment runs.
// The alternative would be a flag on the real sealer, which puts the hostile
// path one argument away from every call site that seals.
//
// Core validates a coordinate before it returns binding fields, so this
// deliberate bypass cannot call that helper. `unbannedBindValue` repeats only
// the content and exact-period layouts used by the hostile vectors. It refuses
// period-chain coordinates rather than silently constructing the wrong layout.

import { BIND_DELIMITER, BIND_VERSION } from "../../core-shared--publisher-issuer/bind.js";
import { sealingWith } from "./keySealingWith.js";

/**
 * @typedef {import('../../core-shared--publisher-issuer/bind.js').Binding} Binding
 */

/**
 * Where the value would carry the delimiter, the join gets this character
 * instead. NUL sits outside every name grammar in the format and outside
 * base64url, so no field a render carries can hold one, and the restore below
 * puts back only what this put in.
 */
const PLACEHOLDER = "\u0000";

/**
 * Returns the caller's coordinate with every delimiter hidden. This helper
 * passes `renderId` through untouched because its callers use a recorded,
 * admitted render identifier and vary only a content or access-group name.
 *
 * @param {Binding} binding
 * @returns {Binding}
 */
function placeheld({ renderId, contentName, accessGroup, t }) {
  /**
   * @param {string|undefined} value
   * @returns {string|undefined}
   */
  const hide = (value) => {
    if (value === undefined) return undefined;
    if (value.includes(PLACEHOLDER)) {
      throw new Error("a field carrying NUL would come back carrying a delimiter it never had");
    }
    return value.replaceAll(BIND_DELIMITER, PLACEHOLDER);
  };

  return {
    renderId,
    ...(contentName === undefined ? {} : { contentName: hide(contentName) }),
    ...(accessGroup === undefined ? {} : { accessGroup: hide(accessGroup) }),
    ...(t === undefined ? {} : { t: hide(t) }),
  };
}

/**
 * Returns the value core would build for this coordinate if `bindable` did not
 * refuse it, which is also the value an issuer that joins the fields blindly
 * arrives at from the coordinate in a request.
 *
 * @param {Binding} binding
 * @returns {string}
 */
export function unbannedBindValue(binding) {
  if (/** @type {any} */ (binding).periodChain === true) {
    throw new Error("delimiter-bypass fixture supports content and exact-period coordinates only");
  }
  const fields = placeheld(binding);
  const value =
    fields.contentName === undefined
      ? [BIND_VERSION, "p", fields.renderId, fields.accessGroup, fields.t]
      : [BIND_VERSION, "c", fields.renderId, fields.contentName];
  return value.join(BIND_DELIMITER).replaceAll(PLACEHOLDER, BIND_DELIMITER);
}

/**
 * `make-vectors.js` calls `seal`, and the replay calls `unseal` to show what a
 * blind join hands over. Both use core's carriers, and they differ from
 * `core-shared--publisher-issuer/keySealing.js` only in the string ahead of the
 * key.
 */
export const { seal, unseal } = sealingWith(unbannedBindValue);

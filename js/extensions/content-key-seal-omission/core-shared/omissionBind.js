// @ts-check
//
// The inner binding this extension wraps a contentKey under, and the one thing
// its publisher, client and issuer all have to agree on byte for byte.
//
// One grammar, four coordinates:
//
//     dca-bind-seal-omission | renderId | contentName | accessGroup | t
//
// It is extension-owned and provisional. `dca-bind-key-envelope` is the outer BIND's
// constant and stays there: two grammars under one token would leave a reader
// unable to say which one produced a value. `bindFields` in
// `core-shared--publisher-issuer/bind.js` refuses a vector naming a contentName
// and an accessGroup at once, by design, so this value cannot be built there
// and is built here instead.
//
// Copied from `core-shared--publisher-issuer/bind.js`:
//
//   - `bindable`, unchanged. It is module-private there.
//   - `validateRenderId`, unchanged in behavior. It is exported
//     there, but `bind.js` sits in the publisher/issuer pairwise slice and the
//     client role may not import that slice - and the client rebuilds this same
//     binding locally. One binding builder every role can reach has to sit in
//     this extension's universal `core-shared/`, so the two checks come with
//     it. The issuer still runs the base `validateRenderId` before it gets
//     here, through `checkEnvelopes`.
//
// The delimiter and its ban are the base rules, reused rather than reinvented:
// contentName, accessGroup and t already exclude the pipe byte at their own
// entry points, so no field can carry it and no length prefix is needed.

import { utf8Encode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";

/** The extension name, as the wire marker and the request support signal carry it. */
export const EXTENSION_NAME = "content-key-seal-omission";

/** Domain separation and identity of this grammar. Distinct from `dca-bind-key-envelope`. */
export const OMISSION_BIND_IDENTIFIER = "dca-bind-seal-omission";

/** The field boundary, banned inside every field it separates. */
export const OMISSION_BIND_DELIMITER = "|";

/** The exact width of a bound renderId before base64url encoding. */
export const RENDER_ID_BYTES = 16;

/**
 * One bound contentData wrap's coordinate. All four fields, always: this
 * grammar has one shape, so there is no arity to read a kind off.
 *
 * @typedef {object} OmissionBinding
 * @property {string} renderId - as the wire carries it, base64url
 * @property {string} contentName
 * @property {string} accessGroup
 * @property {string} t
 */

/**
 * @param {unknown} value
 * @param {string} field - for the message
 * @returns {string}
 */
function bindable(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw dcaError("binding_failed", `${field} is not a string a binding can carry`);
  }
  if (value.includes(OMISSION_BIND_DELIMITER)) {
    throw dcaError(
      "binding_failed",
      `${field} ${JSON.stringify(value)} carries the delimiter, which would make it two fields`,
    );
  }
  return value;
}

/**
 * The renderId this binding is anchored to, checked for the entropy it rests
 * on. Bound as the wire string; the decode only measures it.
 *
 * @param {unknown} renderId
 * @returns {string}
 */
export function validateOmissionRenderId(renderId) {
  const value = bindable(renderId, "renderId");

  const bytes = binaryStringBytes(value);
  if (bytes === null) {
    throw dcaError(
      "binding_failed",
      "renderId is canonical base64url on the wire and this one is not",
    );
  }
  if (bytes.length !== RENDER_ID_BYTES) {
    throw dcaError(
      "binding_failed",
      `renderId must be exactly ${RENDER_ID_BYTES} bytes in canonical unpadded base64url`,
    );
  }

  return value;
}

/**
 * The fields of one inner binding, in the order the grammar joins them. Split
 * out for the same reason base splits `bindFields`: a caller demonstrating
 * another encoding joins the same fields another way.
 *
 * @param {OmissionBinding} binding
 * @returns {string[]}
 */
export function omissionBindFields(binding) {
  if (binding === null || typeof binding !== "object") {
    throw dcaError("binding_failed", "a binding is an object naming one coordinate");
  }
  return [
    OMISSION_BIND_IDENTIFIER,
    validateOmissionRenderId(binding.renderId),
    bindable(binding.contentName, "contentName"),
    bindable(binding.accessGroup, "accessGroup"),
    bindable(binding.t, "t"),
  ];
}

/**
 * @param {OmissionBinding} binding
 * @returns {string}
 */
export function omissionBindValue(binding) {
  return omissionBindFields(binding).join(OMISSION_BIND_DELIMITER);
}

/**
 * The same value as AES-GCM `additionalData`. `core-shared/aead.js` already
 * takes an aad argument that the base contentData wrap does not pass, so the
 * bound wrap costs no new primitive.
 *
 * @param {OmissionBinding} binding
 * @returns {Uint8Array}
 */
export function omissionBindAad(binding) {
  return utf8Encode(omissionBindValue(binding));
}

/**
 * Whether one `contentData[name].keys[group][]` entry is a bound wrap. The
 * marker keeps the two representations apart: a base reader sees an entry it
 * can describe but cannot open, and this extension refuses an entry
 * that does not carry it rather than trying it unbound.
 *
 * @param {any} entry
 * @returns {boolean}
 */
export function isBoundEntry(entry) {
  return (
    entry !== null &&
    typeof entry === "object" &&
    Object.hasOwn(entry, "bind") &&
    entry.bind === OMISSION_BIND_IDENTIFIER
  );
}

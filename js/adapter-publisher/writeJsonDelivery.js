// @ts-check
//
// This module emits the baseline delivery form: one serialized JSON document,
// per spec--data-format.md Section 6, object delivery. The document holds the
// `dca-data` members in one enclosing object and adds the optional
// `sealedContent` records of Section 5 beside them. `adapter-client/JsonDeliveryReader.js`
// reads it back. The markup form in `writeMarkupDelivery.js` carries the same
// two values in two script elements; that form belongs to the
// `dca-profile-html-carrier` profile.
//
// The writer returns bytes, not a string or an object. The serialized UTF-8
// document is what crosses between a publisher and a client, so the writer
// hands its caller the octets that cross, and a port produces the same kind of
// value. A language-native object is not the interchange form.
//
// This module holds no state. It takes one render's values, checks them, and
// returns new bytes on every call. It uses no DOM and no demo code.
//
// The document's text is `JSON.stringify` output, the same spelling the markup
// writer puts in its data block, so one render reads alike in either form. A
// value `JSON.stringify` cannot serialize at all, a bigint or a cycle, is
// refused as configuration rather than escaping as a TypeError.

import { dcaError } from "../core-shared/errors.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { utf8Encode } from "../core-shared/codec.js";
import { validateContentName } from "../core-shared/names.js";

/** The members a render hands this writer; any other member is refused. */
const RENDER_MEMBERS = ["dcaData", "sealedContent"];

/** The document member that carries the sealed-content records. */
const SEALED_MEMBER = "sealedContent";

/**
 * Whether `value` is a non-array object.
 *
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Canonical base64url from the sealer carries no other spelling. A value
 * outside that alphabet, or one with nonzero unused trailing bits, did not come
 * from the sealer, and the writer refuses it with the code the markup writer
 * uses for the same value.
 *
 * @param {string} contentName - which item's ciphertext, for the message
 * @param {unknown} ciphertext
 * @returns {string}
 */
function validateCiphertext(contentName, ciphertext) {
  if (typeof ciphertext !== "string" || binaryStringBytes(ciphertext) === null) {
    throw dcaError(
      "bad_name",
      `the sealed ciphertext for ${JSON.stringify(contentName)} is not base64url`,
    );
  }
  return ciphertext;
}

/**
 * Emit one render's baseline delivery document. The function takes the
 * render's values, returns new bytes, and holds nothing across calls.
 *
 * The document is one JSON object: every own enumerable member of `dcaData`, in
 * its order, and then `sealedContent`. The bytes are UTF-8 with no byte order
 * mark. The writer always writes `sealedContent`, as `[]` when the render
 * carries no ciphertext, so the document says the publisher delivered no
 * ciphertext rather than leaving the reader to infer it.
 *
 * Refusals:
 * - `bad_config` for a render that is not a non-array object, a missing or
 *   non-object `dcaData`, a missing or non-object `sealedContent`, a `dcaData`
 *   with its own `sealedContent` member, and a value `JSON.stringify` cannot
 *   serialize, such as a bigint or a cycle
 * - `unsupported_option` for a render member other than `dcaData` and
 *   `sealedContent`
 * - `bad_name` for a `sealedContent` member name outside the contentName
 *   grammar and a ciphertext that is not canonical base64url
 *
 * @param {object} render - the pair `Sealer.seal()` returns
 * @param {object} render.dcaData - what the publisher signed and shipped,
 *   without a `sealedContent` member
 * @param {Record<string, string>} render.sealedContent - contentName to
 *   base64url ciphertext; `{}` when no item ciphertext is delivered
 * @returns {Uint8Array} the UTF-8 octets of the document
 */
export function writeJsonDelivery(render) {
  if (!isRecord(render)) {
    throw dcaError("bad_config", "the JSON writer takes one render record");
  }
  for (const name of Object.keys(render)) {
    if (!RENDER_MEMBERS.includes(name)) {
      throw dcaError("unsupported_option", `the JSON writer takes no ${name} member`);
    }
  }
  const { dcaData, sealedContent } = render;
  if (!isRecord(dcaData)) {
    throw dcaError("bad_config", "the JSON writer emits one render's dcaData object");
  }
  if (!isRecord(sealedContent)) {
    throw dcaError(
      "bad_config",
      "the JSON writer needs the sealedContent object beside the dcaData, even if it is empty",
    );
  }
  // The writer puts the ciphertext records in one place. A dcaData that brings
  // its own would put a second member in the document, and one of the two
  // would silently replace the other.
  if (Object.hasOwn(dcaData, SEALED_MEMBER)) {
    throw dcaError("bad_config", "the dcaData already carries a sealedContent member");
  }

  // The render holds ciphertext by name; the document carries one
  // `{contentName, content}` record per item, in the render's item order.
  /** @type {{ contentName: string, content: string }[]} */
  const carrier = [];
  for (const [contentName, ciphertext] of Object.entries(sealedContent)) {
    carrier.push({
      contentName: validateContentName(contentName),
      content: validateCiphertext(contentName, ciphertext),
    });
  }

  // The spread defines each member as an own data property, so a member named
  // `__proto__` that arrived as an own member stays an own member.
  const document = { ...dcaData, [SEALED_MEMBER]: carrier };
  /** @type {string|undefined} */
  let json;
  try {
    json = JSON.stringify(document);
  } catch {
    // A bigint or a cycle; refused below.
  }
  if (typeof json !== "string") {
    throw dcaError("bad_config", "the dcaData holds a value JSON cannot represent");
  }
  return utf8Encode(json);
}

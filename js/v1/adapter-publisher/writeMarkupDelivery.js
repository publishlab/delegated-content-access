// @ts-check
//
// This module emits the markup delivery form: the two inert elements a
// publisher puts in the body, per spec--data-format.md Section 3, markup
// delivery, and Section 5, the sealed-content carrier. The data block goes in a
// `.dca-data` script element and the ciphertext goes in a second script
// element, `.dca-sealed-content`, which carries one JSON object keyed by
// contentName. `adapter-client/MarkupDeliveryReader.js` reads it back. Both
// files take the block placement from `core-shared/markupPlacement.js`, so the
// placement of each block is stated once and both sides use it.
//
// The emitter writes two blocks. The ciphertext stays out of dca-data so a page
// of large opaque payloads does not bury the metadata a client reads first, and
// so a deferred item can be left out of the carrier without changing the item
// inventory dca-data declares.
//
// This module holds no state. It receives one render's dca-data and its
// per-item sealed ciphertext as plain values, and it returns the placement as a
// string that the publisher application puts in its page. It uses no DOM, no
// document, and no demo code. It emits text, so a runtime with no document
// object can still produce it.
//
// The emitter keeps the data block inert. `resource.data` is whatever the CMS
// put there and it reaches this JSON verbatim, so the two sequences that end a
// script block early do arrive: `</script` ends it outright, and
// `<!--` opens the escaped states where a later `<script` makes the element's
// own closing tag stop ending it. Both are rewritten to JSON's own escape for
// `<`, so `JSON.parse` on the far side hands back the string that went in and no
// reader has to know an escape happened.
//
// The emitter keeps the sealed block inert by limiting what enters it. Its JSON
// is built from checked values only: a member name the contentName grammar
// admits and a value the sealer's base64url alphabet admits, and neither
// alphabet carries `<`. So nothing that could end the block can be in it. The
// same rewrite runs over it anyway, because keeping one emission rule for both
// inert blocks costs less than arguing about which one needed it.

import { dcaError } from "../core-shared/errors.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { validateContentName } from "../core-shared/names.js";
import { DATA_CLASS, SEALED_CLASS } from "../core-shared/markupPlacement.js";

/**
 * Rewrites the two sequences that end a script data block early so that they
 * cannot. Inside `<script type="application/json">` the HTML tokenizer is still
 * running: it ends the element at the first `</script`, whatever the JSON
 * grammar around it says, and `<!--` opens the escaped states where a later
 * `<script` makes the element's own closing tag stop ending it.
 *
 * The rewrite replaces the `<` in each sequence with its JSON escape, so
 * `JSON.parse` hands back the string that went in. A blanket pass is safe because `<` occurs nowhere in
 * `JSON.stringify` output but inside a string literal, where it cannot be
 * structure.
 *
 * @param {string} json
 * @returns {string}
 */
function inertInAScriptBlock(json) {
  return json
    .replace(/<\/script/gi, (match) => `\\u003c${match.slice(1)}`)
    .replace(/<!--/g, "\\u003c!--");
}

/**
 * The ciphertext goes into the carrier as a JSON string, next to a name that
 * was checked for the same reason. Canonical base64url from the sealer
 * carries nothing that could end the script block. If a value steps outside
 * that alphabet (for example, a `<` that could start a terminator) or carries
 * nonzero unused trailing bits, a caller handed it to this writer and the
 * sealer did not produce it. Such a value is refused at emission and is not
 * written into the markup.
 *
 * @param {string} contentName - which item's ciphertext, for the message
 * @param {unknown} ciphertext
 * @returns {string}
 */
function validateCiphertext(contentName, ciphertext) {
  if (typeof ciphertext !== "string") {
    throw dcaError(
      "bad_name",
      `the sealed ciphertext for ${JSON.stringify(contentName)} is not base64url`,
    );
  }
  if (binaryStringBytes(ciphertext) === null) {
    throw dcaError(
      "bad_name",
      `the sealed ciphertext for ${JSON.stringify(contentName)} is not base64url`,
    );
  }
  return ciphertext;
}

/**
 * Emit one render's markup placement. The function takes the render's values,
 * returns the string, and holds nothing across calls.
 *
 * The writer puts the ciphertext in the sealed-content block and nowhere else.
 * The object delivery form differs from this form only there: it has a single
 * enclosing object and carries the same map under its `sealedContent` member.
 *
 * @param {object} render
 * @param {object} render.dcaData - what the publisher signed and shipped,
 *   without the `sealedContent` member the object form carries
 * @param {Record<string, string>} render.sealedContent - contentName to
 *   base64url ciphertext
 * @returns {string}
 */
export function writeMarkupDelivery(render) {
  const { dcaData, sealedContent } = render ?? {};
  if (!dcaData || typeof dcaData !== "object" || Array.isArray(dcaData)) {
    throw dcaError("bad_config", "the markup writer emits one render's dcaData");
  }
  if (!sealedContent || typeof sealedContent !== "object") {
    throw dcaError(
      "bad_config",
      "the markup writer needs the sealedContent beside the dcaData, even if it is empty",
    );
  }

  /** @type {Record<string, string>} */
  const carrier = {};
  for (const [contentName, ciphertext] of Object.entries(sealedContent)) {
    carrier[validateContentName(contentName)] = validateCiphertext(contentName, ciphertext);
  }

  return [
    `<script type="application/json" class="${DATA_CLASS}">${inertInAScriptBlock(JSON.stringify(dcaData))}</script>`,
    `<script type="application/json" class="${SEALED_CLASS}">`,
    inertInAScriptBlock(JSON.stringify(carrier)),
    "</script>",
  ].join("\n");
}

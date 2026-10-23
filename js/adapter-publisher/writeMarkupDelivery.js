// @ts-check
//
// This module emits the markup delivery form: the two inert elements a
// publisher puts in the body, per spec--data-format.md Section 3, markup
// delivery, and Section 5, the sealed-content carrier. The data block goes in a
// `.dca-data` script element and the ciphertext goes in a second script
// element, `.dca-sealed-content`, which carries one JSON array of
// `{contentName, content}` records. `adapter-client/MarkupDeliveryReader.js` reads it back. Both
// files take the block placement from `core-shared/markupPlacement.js`, so the
// placement of each block is stated once and both sides use it.
//
// The emitter writes two blocks. The ciphertext stays out of dca-data so a page
// of large opaque payloads does not bury the metadata a client reads first, and
// so a deferred item can be left out of the carrier without changing the item
// inventory dca-data declares.
//
// Native writers preserve decoded JSON values and inert carrier behavior, not
// JSON.stringify number spelling or object member order; see js/PORTING.md,
// Markup writer values. Signed token and ciphertext strings remain exact.
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
//
// An optional carrier that an extension defines is not written here. The
// extension composes this writer's two blocks with its own block from
// `inertJsonScript`, which applies the same inert rule and refuses the two base
// tokens, so no caller writes a second base carrier around the checks above.

import { dcaError } from "../core-shared/errors.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { validateContentName } from "../core-shared/names.js";
import { DATA_CLASS, SEALED_CLASS } from "../core-shared/markupPlacement.js";

/** The members a render hands this writer; any other member is refused. */
const RENDER_MEMBERS = ["dcaData", "sealedContent"];

/** A class token that needs no quoting or escaping inside the attribute value. */
const CLASS_TOKEN = /^-?[A-Za-z_][A-Za-z0-9_-]*$/;

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
 * One inert `<script type="application/json">` element carrying `value` as
 * JSON, with the same rewrite as the base carriers. An extension writes its own
 * carrier through this, beside the blocks `writeMarkupDelivery` emits.
 *
 * The class is one token of the selector `ident` grammar, so it cannot end the
 * attribute or the tag. The two base tokens are refused: their blocks carry
 * checked names and ciphertext, and only `writeMarkupDelivery` writes them.
 *
 * @param {string} className - the one class token of the element
 * @param {unknown} value - a value `JSON.stringify` serializes
 * @returns {string}
 */
export function inertJsonScript(className, value) {
  if (typeof className !== "string" || !CLASS_TOKEN.test(className)) {
    throw dcaError("bad_config", "an inert JSON block takes one class token");
  }
  if (className === DATA_CLASS || className === SEALED_CLASS) {
    throw dcaError("bad_config", `the ${className} block is written by writeMarkupDelivery`);
  }
  return scriptBlock(className, serializedJson(value));
}

/** @param {unknown} value @returns {string} */
function serializedJson(value) {
  /** @type {string|undefined} */
  let json;
  try {
    json = JSON.stringify(value);
  } catch {
    // A BigInt or a cycle; refused below with the other unrepresentable values.
  }
  if (typeof json !== "string") {
    throw dcaError("bad_config", "an inert JSON block carries a value JSON can represent");
  }
  return json;
}

/**
 * @param {string} className - already checked
 * @param {string} json
 * @returns {string}
 */
function scriptBlock(className, json) {
  return `<script type="application/json" class="${className}">${inertInAScriptBlock(json)}</script>`;
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
 * enclosing object and carries the same records under its `sealedContent`
 * member.
 *
 * @param {object} render
 * @param {object} render.dcaData - what the publisher signed and shipped,
 *   without the `sealedContent` member the object form carries
 * @param {Record<string, string>} render.sealedContent - contentName to
 *   base64url ciphertext
 * @returns {string}
 */
export function writeMarkupDelivery(render) {
  if (render === null || typeof render !== "object" || Array.isArray(render)) {
    throw dcaError("bad_config", "the markup writer takes one render record");
  }
  const { dcaData, sealedContent } = render;
  for (const name of Object.keys(render)) {
    if (!RENDER_MEMBERS.includes(name)) {
      throw dcaError("unsupported_option", `the markup writer takes no ${name} member`);
    }
  }
  if (!dcaData || typeof dcaData !== "object" || Array.isArray(dcaData)) {
    throw dcaError("bad_config", "the markup writer emits one render's dcaData");
  }
  if (!sealedContent || typeof sealedContent !== "object" || Array.isArray(sealedContent)) {
    throw dcaError(
      "bad_config",
      "the markup writer needs the sealedContent beside the dcaData, even if it is empty",
    );
  }

  // The render holds ciphertext by name; the block carries one
  // `{contentName, content}` record per item, in the render's item order.
  /** @type {{ contentName: string, content: string }[]} */
  const carrier = [];
  for (const [contentName, ciphertext] of Object.entries(sealedContent)) {
    carrier.push({
      contentName: validateContentName(contentName),
      content: validateCiphertext(contentName, ciphertext),
    });
  }

  return [
    scriptBlock(DATA_CLASS, serializedJson(dcaData)),
    `<script type="application/json" class="${SEALED_CLASS}">`,
    inertInAScriptBlock(JSON.stringify(carrier)),
    "</script>",
  ].join("\n");
}

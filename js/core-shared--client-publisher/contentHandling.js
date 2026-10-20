// @ts-check
// Handling metadata stays admitted even though content AAD binds only the
// render and item name. These are local resource bounds, not wire limits.
import { utf8Encode } from "../core-shared/codec.js";
import { isUnicodeScalarString } from "../core-shared/names.js";

/** @param {unknown} value @returns {boolean} */
function scalarValue(value) {
  return (
    typeof value === "string" &&
    value.length <= 64 * 1024 &&
    isUnicodeScalarString(value) &&
    utf8Encode(value).length <= 64 * 1024
  );
}

/**
 * Accept a captured list, empty for absent encodings.
 * @param {unknown} contentType
 * @param {readonly string[]} contentEncodings
 * @returns {boolean}
 */
export function contentHandlingIsValid(contentType, contentEncodings) {
  if (!scalarValue(contentType) || contentEncodings.length > 64) return false;
  for (let index = 0; index < contentEncodings.length; index += 1) {
    if (
      !Object.hasOwn(contentEncodings, index) ||
      contentEncodings[index] === "" ||
      !scalarValue(contentEncodings[index])
    )
      return false;
  }
  return true;
}

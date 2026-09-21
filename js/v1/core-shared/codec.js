// @ts-check
//
// The published base64url pair, plus the UTF-8 pair.
// Canonical source: spec--data-format.md section 2.2.
//
// Two departures from the code the public reference ships, both measured:
//
//   base64urlEncode: the reference spreads the whole buffer into
//   String.fromCharCode. That throws a RangeError somewhere around 125k bytes,
//   and a long article reaches that size, so this code uses the chunked loop
//   that the reference mentions in a comment.
//
//   base64urlDecode: the reference builds the result with
//   Uint8Array.from(atob(s), c => c.charCodeAt(0)). That calls a callback once
//   per byte and runs about 16x slower than writing into a preallocated array.

/** TextEncoder and TextDecoder hold no state; one of each is enough. */
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** How many bytes go into one String.fromCharCode call. */
const CHUNK = 0x8000;

/**
 * Bytes to base64url, no padding (RFC 4648 section 5).
 *
 * @param {Uint8Array|ArrayBuffer} buf
 * @returns {string}
 */
export function base64urlEncode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);

  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, /** @type {any} */ (bytes.subarray(i, i + CHUNK)));
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * base64url to bytes. Padding is optional, and standard base64 also decodes.
 * The two replacements do nothing when the input has no `-` or `_`, so PEM key
 * material goes through the same call.
 *
 * @param {string} s
 * @returns {Uint8Array}
 */
export function base64urlDecode(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (s.length % 4)) % 4);
  const binary = atob(padded);

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/**
 * @param {string} str
 * @returns {Uint8Array}
 */
export function utf8Encode(str) {
  return encoder.encode(str);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function utf8Decode(bytes) {
  return decoder.decode(bytes);
}

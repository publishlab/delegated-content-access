// @ts-check

// Compact JWT structure decoding only. This module authenticates nothing: an
// issuer uses it solely to locate the one verification key for the same token,
// and client code may read non-authorizing page coordinates from it.

import { base64urlDecode, utf8Decode } from "./codec.js";
import { dcaError } from "./errors.js";

/** @param {string} segment @param {string} what @returns {any} */
function decodeSegment(segment, what) {
  let value;
  try {
    value = JSON.parse(utf8Decode(base64urlDecode(segment)));
  } catch {
    throw dcaError("bad_jwt", `the ${what} segment is not base64url JSON`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw dcaError("bad_jwt", `the ${what} segment is not a JSON object`);
  }
  return value;
}

/**
 * @param {unknown} token
 * @returns {{ header: any, payload: any, parts: [string, string, string] }}
 */
export function decodeCompactJwt(token) {
  if (typeof token !== "string" || token.length === 0) throw dcaError("bad_jwt", "no token");
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0].length === 0 || parts[1].length === 0) {
    throw dcaError("bad_jwt", "a JWS compact token is a header, a payload and a signature");
  }
  return {
    header: decodeSegment(parts[0], "header"),
    payload: decodeSegment(parts[1], "payload"),
    parts: /** @type {[string, string, string]} */ (parts),
  };
}

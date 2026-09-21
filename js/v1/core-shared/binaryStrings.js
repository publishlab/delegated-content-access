// @ts-check
//
// This module holds the single admission rule for a binary member received
// off the wire.
// Canonical source: spec--data-format.md section 2.2.
//
// Section 2.2 admits canonical unpadded base64url and refuses padding,
// standard-base64 characters, undecodable input and a spelling with nonzero
// unused trailing bits. `codec.js` decodes all but the last of those on
// purpose: PEM key material goes through the same call, and the encoding
// reference documents that leniency. So this module implements the strict rule
// under its own name, and builds it on the generic pair instead of replacing it.
//
// Before this module existed, three receive boundaries implemented the same
// rule by hand, each with its own alphabet screen and re-encode comparison: the
// two renderId validators and the client-bound JWK coordinates. They call this
// module instead, and keep their own failure codes and width checks.
//
// This module returns null for a refusal instead of throwing. A caller that
// treats one unreadable leaf as a candidate miss must handle the refusal where
// it arrived: `contentKeyWrapAttempt` admits one named DOMException and
// rethrows everything else. A new error type from a decoder would therefore
// abort the whole wrap attempt instead of dropping one candidate, and
// spec--data-format.md section 2.2 limits a failure to dropping one candidate.

import { base64urlDecode, base64urlEncode } from "./codec.js";

/** Matches only characters of the canonical alphabet. The empty string matches and carries zero bytes. */
const CANONICAL = /^[A-Za-z0-9_-]*$/;

/**
 * The bytes of one canonical unpadded base64url member, or null for every other
 * spelling.
 *
 * No runtime decoder applies the re-encode comparison by itself. Every decoder
 * accepts a value whose last character carries nonzero unused bits without
 * complaint, so the only way to detect it is to encode the bytes back and
 * compare.
 *
 * @param {unknown} value - a member as it arrived, of any type
 * @returns {Uint8Array|null} the bytes, or null where the spelling is refused
 */
export function binaryStringBytes(value) {
  if (typeof value !== "string") return null;
  if (!CANONICAL.test(value)) return null;
  if (value.length % 4 === 1) return null;

  let bytes;
  try {
    bytes = base64urlDecode(value);
  } catch {
    return null;
  }

  return base64urlEncode(bytes) === value ? bytes : null;
}

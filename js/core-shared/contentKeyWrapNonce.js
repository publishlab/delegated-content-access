// @ts-check
//
// The nonce of one period-key wrap. No entry carries it: the publisher and every
// reader of the wrap rebuild it from the coordinate the wrap sits at.
//
//   LP(bytes) = U32BE(byteLength(bytes)) || bytes
//   context   = UTF8("dca-derivation-content-key-wrap-nonce") || 0x00 ||
//               renderIdBytes(16) || LP(UTF8(contentName)) || LP(UTF8(accessGroup)) ||
//               LP(UTF8(t)) || LP(selectedWrapAAD)
//   nonce     = first12(SHA-256(context))
//
// Within one render the item name tells apart the content keys one period key
// wraps; across renders the fresh random render ID does. `selectedWrapAAD` is
// empty for an ordinary wrap and the exact AAD an alternative wrap encrypts
// under, so two wrap procedures at one coordinate never share a transcript.
//
// The publisher, the client and the omission issuer all derive this value, so
// it lives in the slice every role ships.
//
// Names and labels use the grammar the format admits, which is ASCII. A value
// outside it is refused here rather than framed: a reader that hashed a spelling
// no producer can write would only ever produce a wrong nonce.

import { binaryStringBytes } from "./binaryStrings.js";
import { sha256Digest } from "./cryptoProvider.js";
import { utf8Encode } from "./codec.js";
import { NONCE_BYTES } from "./aead.js";
import { isAccessGroup, isContentName } from "./names.js";
import { isPeriodKeyLabel } from "./periodLabels.js";

const LABEL = utf8Encode("dca-derivation-content-key-wrap-nonce");

/** The decoded width of a render ID, as the format fixes it. */
const RENDER_ID_OCTETS = 16;

/**
 * @typedef {object} ContentKeyWrapNonceFields
 * @property {string} renderId - canonical unpadded base64url of 16 octets, as the wire carries it
 * @property {string} contentName
 * @property {string} accessGroup - the group the entry is authored under, never a cache label
 * @property {string} t - the entry's own `t`
 * @property {Uint8Array} [aad] - the selected wrap AAD; absent means empty
 */

/**
 * The 12-byte nonce of the wrap at one coordinate, or null when an input is not
 * an admitted spelling. Every input is read and copied before the digest is
 * awaited, so a caller may change its own objects while the call is pending.
 *
 * @param {ContentKeyWrapNonceFields} fields
 * @returns {Promise<Uint8Array|null>}
 */
export async function contentKeyWrapNonce(fields) {
  const context = wrapNonceContext(fields);
  if (context === null) return null;
  return new Uint8Array(await sha256Digest(context), 0, NONCE_BYTES);
}

/**
 * @param {unknown} fields
 * @returns {Uint8Array|null}
 */
function wrapNonceContext(fields) {
  if (fields === null || typeof fields !== "object" || Array.isArray(fields)) return null;
  const read = (/** @type {string} */ member) =>
    Object.hasOwn(fields, member) ? /** @type {any} */ (fields)[member] : undefined;
  const renderId = read("renderId");
  const contentName = read("contentName");
  const accessGroup = read("accessGroup");
  const t = read("t");
  const aad = read("aad");

  const renderIdBytes = binaryStringBytes(renderId);
  if (renderIdBytes === null || renderIdBytes.length !== RENDER_ID_OCTETS) return null;
  if (!isContentName(contentName) || !isAccessGroup(accessGroup) || !isPeriodKeyLabel(t)) {
    return null;
  }
  if (aad !== undefined && !(aad instanceof Uint8Array)) return null;

  const prefixed = [
    utf8Encode(contentName),
    utf8Encode(accessGroup),
    utf8Encode(t),
    aad ?? new Uint8Array(0),
  ];
  const length = prefixed.reduce(
    (sum, value) => sum + 4 + value.length,
    LABEL.length + 1 + RENDER_ID_OCTETS,
  );
  const context = new Uint8Array(length);
  const view = new DataView(context.buffer);
  context.set(LABEL, 0);
  // The zero octet after the label stays as allocated.
  let offset = LABEL.length + 1;
  context.set(renderIdBytes, offset);
  offset += RENDER_ID_OCTETS;
  for (const value of prefixed) {
    view.setUint32(offset, value.length);
    context.set(value, offset + 4);
    offset += 4 + value.length;
  }
  return context;
}

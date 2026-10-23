// @ts-check
// Independent spelling of the period-key wrap nonce:
// first12(SHA-256("dca-derivation-content-key-wrap-nonce" || 0x00 || renderIdBytes ||
// LP(contentName) || LP(accessGroup) || LP(t) || LP(selectedWrapAAD))), with U32BE
// lengths. This helper uses node:crypto and Buffer and shares no transcript code
// with the implementation, so a framing bug there cannot pass here too.
import { createHash } from "node:crypto";

/** @param {Uint8Array} bytes */
function lp(bytes) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
}

/**
 * @param {{ renderId: string, contentName: string, accessGroup: string, t: string, aad?: Uint8Array }} coordinate
 * @returns {Uint8Array} the 12 nonce octets
 */
export function contentKeyWrapNonceOctets({ renderId, contentName, accessGroup, t, aad }) {
  const context = Buffer.concat([
    Buffer.from("dca-derivation-content-key-wrap-nonce", "utf8"),
    Buffer.from([0]),
    Buffer.from(renderId, "base64url"),
    lp(Buffer.from(contentName, "utf8")),
    lp(Buffer.from(accessGroup, "utf8")),
    lp(Buffer.from(t, "utf8")),
    lp(aad ?? new Uint8Array(0)),
  ]);
  return new Uint8Array(createHash("sha256").update(context).digest().subarray(0, 12));
}

/**
 * The render ID a delivery's resourceJWT names, read without verification.
 *
 * @param {any} dcaData
 * @returns {string}
 */
export function renderIdOf(dcaData) {
  const payload = String(dcaData.resourceJWT).split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).renderId;
}

/**
 * The nonce of the ordinary wrap at one coordinate of a delivery.
 *
 * @param {any} dcaData @param {string} contentName @param {string} accessGroup @param {string} t
 * @returns {Uint8Array}
 */
export function wrapNonceOf(dcaData, contentName, accessGroup, t) {
  return contentKeyWrapNonceOctets({ renderId: renderIdOf(dcaData), contentName, accessGroup, t });
}

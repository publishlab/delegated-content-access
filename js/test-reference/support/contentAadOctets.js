// @ts-check
// Independent spelling of LP(renderId) || LP(contentName), with U32BE UTF-8
// lengths. This helper shares no transcript code with the implementation.
const encoder = new TextEncoder();
/** @param {string} value */
function lp(value) {
  const bytes = encoder.encode(value);
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, bytes.length);
  return [...prefix, ...bytes];
}
/** @param {any} dcaData @param {string} contentName */
export function contentAadOctets(dcaData, contentName) {
  const payload = String(dcaData.resourceJWT).split(".")[1];
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  return Uint8Array.from([...lp(claims.renderId), ...lp(contentName)]);
}

// @ts-check
// Content AAD is LP(renderId) || LP(contentName). LP is the unsigned
// four-octet big-endian UTF-8 octet length followed by those octets.
// Both roles compute these bytes; no item carries AAD on the wire.

import { utf8Encode } from "../core-shared/codec.js";
import { isUnicodeScalarString } from "../core-shared/names.js";

/** Local per-field resource bound, not a wire limit. */
export const CONTENT_AAD_LIMITS = Object.freeze({ maxValueBytes: 64 * 1024 });

/**
 * @param {{ renderId: string, contentName: string }} fields
 * @returns {Uint8Array|null} null when either field is malformed or exceeds the local limit
 */
export function contentAad(fields) {
  if (fields === null || typeof fields !== "object") return null;
  const values = [];
  for (const member of ["renderId", "contentName"]) {
    const value = Object.hasOwn(fields, member) ? /** @type {any} */ (fields)[member] : undefined;
    if (typeof value !== "string" || value.length > CONTENT_AAD_LIMITS.maxValueBytes) return null;
    if (!isUnicodeScalarString(value)) return null;
    const octets = utf8Encode(value);
    if (octets.length > CONTENT_AAD_LIMITS.maxValueBytes) return null;
    values.push(octets);
  }
  const transcript = new Uint8Array(values.reduce((length, value) => length + 4 + value.length, 0));
  const view = new DataView(transcript.buffer);
  let offset = 0;
  for (const octets of values) {
    view.setUint32(offset, octets.length);
    transcript.set(octets, offset + 4);
    offset += 4 + octets.length;
  }
  return transcript;
}

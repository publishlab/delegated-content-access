// @ts-check
// Historical full-token and signing-input comparators, plus the current
// render/name transcript used to open authentic production renders.
import { contentAad } from "../../../core-shared--client-publisher/contentAad.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";

const encoder = new TextEncoder();
const FULL_TOKEN_DOMAIN = encoder.encode("dca-bind-content-representation-v1\0");
const MAX_BYTES = 1024 * 1024; // Local experiment resource limit, not a wire limit.

/** @param {unknown} value */
function encodedString(value) {
  if (
    typeof value !== "string" ||
    /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
  ) {
    throw new TypeError("transcript field must be a Unicode scalar-value string");
  }
  if (value.length > MAX_BYTES) throw new RangeError("transcript field exceeds local limit");
  return encoder.encode(value);
}

/** @param {number} value */
function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError("transcript length is out of range");
  }
  return Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
}

/** @param {Uint8Array} value */
function lp(value) {
  return [u32(value.length), value];
}

/**
 * Earlier full-compact-token candidate from captured delivery values.
 * It does not decode or verify the JWT and makes no provenance claim.
 * @param {object} delivery
 * @param {string} contentName
 * @returns {Uint8Array}
 */
export function tokenRepresentationAad(delivery, contentName) {
  return representationAad(delivery, contentName, FULL_TOKEN_DOMAIN, (token) => token);
}

/** Historical signing-input construction, independent of current production.
 * @param {object} delivery @param {string} contentName @returns {Uint8Array}
 */
export function signingInputRepresentationAad(delivery, contentName) {
  return representationAad(delivery, contentName, encoder.encode("dca-bind-content\0"), (token) => {
    const match = /^([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+$/.exec(token);
    if (match === null) throw new TypeError("resourceJWT must be a compact JWS");
    return match[1];
  });
}

/** Current production render/name transcript.
 * @param {object} delivery @param {string} contentName @returns {Uint8Array}
 */
export function adoptedContentAad(delivery, contentName) {
  selectedRecord(delivery, contentName);
  const renderId = decodeCompactJwt(/** @type {any} */ (delivery).resourceJWT).payload.renderId;
  const aad = contentAad({ renderId, contentName });
  if (aad === null) throw new TypeError("the selected item forms no content AAD");
  return aad;
}

/**
 * @param {object} delivery
 * @param {string} contentName
 * @returns {any}
 */
function selectedRecord(delivery, contentName) {
  const contentData =
    Object.hasOwn(delivery, "contentData") && /** @type {any} */ (delivery).contentData;
  if (
    contentData === null ||
    typeof contentData !== "object" ||
    Array.isArray(contentData) ||
    !Object.hasOwn(contentData, contentName)
  ) {
    throw new TypeError("selected item is absent");
  }
  const record = contentData[contentName];
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new TypeError("selected item is malformed");
  }
  return record;
}

/**
 * @param {object} delivery
 * @param {string} contentName
 * @param {Uint8Array} domain
 * @param {(token: string) => string} tokenInput
 * @returns {Uint8Array}
 */
function representationAad(delivery, contentName, domain, tokenInput) {
  const record = selectedRecord(delivery, contentName);
  const rawToken = Object.hasOwn(delivery, "resourceJWT") && delivery.resourceJWT;
  if (typeof rawToken !== "string") throw new TypeError("resourceJWT must be a string");
  const token = encodedString(tokenInput(rawToken));
  const name = encodedString(contentName);
  const type = encodedString(Object.hasOwn(record, "contentType") && record.contentType);
  const encodings = Object.hasOwn(record, "contentEncodings") ? record.contentEncodings : [];
  if (
    !Array.isArray(encodings) ||
    (Object.hasOwn(record, "contentEncodings") && encodings.length === 0)
  ) {
    throw new TypeError("contentEncodings must be a nonempty array when present");
  }
  if (encodings.length > MAX_BYTES / 4) throw new RangeError("too many encoding layers");
  const parts = [domain, ...lp(token), ...lp(name), ...lp(type), u32(encodings.length)];
  let length = parts.reduce((sum, part) => sum + part.length, 0);
  for (let i = 0; i < encodings.length; i++) {
    if (!Object.hasOwn(encodings, i) || encodings[i] === "") {
      throw new TypeError("contentEncodings must be dense nonempty strings");
    }
    const field = lp(encodedString(encodings[i]));
    length += field[0].length + field[1].length;
    if (length > MAX_BYTES) throw new RangeError("transcript exceeds local limit");
    parts.push(...field);
  }
  if (length > MAX_BYTES) throw new RangeError("transcript exceeds local limit");
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

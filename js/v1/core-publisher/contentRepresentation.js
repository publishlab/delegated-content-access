// @ts-check

// This module sits on the publisher side, between caller values and the bytes
// Sealer encrypts. Bare values follow the original API: this module encodes a
// string as UTF-8 and copies a byte array. A caller who passes an explicit
// descriptor declares that its bytes already carry the listed encoding layers,
// so base records those layers and applies no codec itself.

import { utf8Encode } from "../core-shared/codec.js";
import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

const DESCRIPTOR_MEMBERS = ["bytes", "contentType", "contentEncodings"];

/** @param {unknown} value */
function isEncodingList(value) {
  if (!Array.isArray(value)) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (
      !Object.hasOwn(value, index) ||
      typeof value[index] !== "string" ||
      value[index].length === 0
    )
      return false;
  }
  return true;
}

/**
 * Whether a value selects the explicit descriptor overload. Uint8Array stays
 * a bare legacy value even though it is an object.
 *
 * @param {unknown} value
 * @returns {value is object}
 */
export function isContentRepresentation(value) {
  return value !== null && typeof value === "object" && !(value instanceof Uint8Array);
}

/**
 * Snapshot one caller value into the representation Sealer retains.
 *
 * This function reads `legacyContentType` only for a bare string or
 * Uint8Array. An explicit descriptor must carry the current contentType
 * member itself. The function checks and copies contentEncodings without
 * consulting that member.
 *
 * @param {unknown} value
 * @param {unknown} [legacyContentType]
 * @returns {Readonly<{
 *   bytes: Uint8Array,
 *   contentType: string,
 *   contentEncodings: readonly string[],
 * }>}
 */
export function normalizeContentRepresentation(value, legacyContentType) {
  if (!isContentRepresentation(value)) {
    if (typeof value !== "string" && !(value instanceof Uint8Array)) {
      throw dcaError("bad_config", "content is a string, Uint8Array or representation descriptor");
    }
    if (typeof legacyContentType !== "string") {
      throw dcaError(
        "bad_config",
        "a content representation carries the current string contentType",
      );
    }
    return Object.freeze({
      bytes: value instanceof Uint8Array ? Uint8Array.from(value) : utf8Encode(value),
      contentType: legacyContentType,
      contentEncodings: Object.freeze([]),
    });
  }

  for (const name of Object.keys(value)) {
    if (!DESCRIPTOR_MEMBERS.includes(name)) {
      throw dcaError("unsupported_option", `a content representation has no ${name}`);
    }
  }

  const bytes = own(value, "bytes");
  if (!(bytes instanceof Uint8Array)) {
    throw dcaError("bad_config", "a content representation carries Uint8Array bytes");
  }

  const contentEncodings = own(value, "contentEncodings");
  if (!isEncodingList(contentEncodings)) {
    throw dcaError(
      "bad_config",
      "a content representation carries a list of nonempty contentEncodings",
    );
  }

  const contentType = own(value, "contentType");
  if (typeof contentType !== "string") {
    throw dcaError("bad_config", "a content representation carries the current string contentType");
  }

  return Object.freeze({
    bytes: Uint8Array.from(bytes),
    contentType,
    contentEncodings: Object.freeze([...contentEncodings]),
  });
}

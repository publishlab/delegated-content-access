// @ts-check

// Decrypt one item and then reverse the representation layers its record
// names. Codecs stay in the caller-owned registry; neither this module nor the
// actors that compose it know any codec name.

import { openContent } from "./openContent.js";
import { contentEncodingsFrom } from "./contentEncodings.js";
import { DcaError, dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

export class ContentRepresentationOpener {
  /** @type {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} */
  #decoders;

  /**
   * The constructor copies only the registry's own enumerable properties.
   * It ignores names on the registry's prototype, so they never decode a
   * wire value.
   *
   * @param {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [decoders]
   */
  constructor(decoders = {}) {
    if (decoders === null || typeof decoders !== "object" || Array.isArray(decoders)) {
      throw dcaError("bad_config", "content decoders are an object registry");
    }

    this.#decoders = Object.create(null);
    for (const name of Object.keys(decoders)) {
      const decoder = own(decoders, name);
      if (typeof decoder !== "function") {
        throw dcaError(
          "bad_config",
          `the content decoder for ${JSON.stringify(name)} is a function`,
        );
      }
      this.#decoders[name] = decoder;
    }
    Object.freeze(this.#decoders);
  }

  /**
   * @param {object} call
   * @param {unknown} call.record - one contentData record
   * @param {string} call.contentName - for typed item failures
   * @param {string} call.ciphertext - base64url ciphertext
   * @param {unknown} call.aad - the composition's content AAD
   * @param {() => Promise<Uint8Array|CryptoKey|null|undefined>} call.resolveKey
   * @returns {Promise<Uint8Array>}
   */
  async open({ record, contentName, ciphertext, aad, resolveKey }) {
    const contentEncodings = contentEncodingsFrom(record, contentName);
    /** @type {((bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array)[]} */
    const decoders = [];
    for (const name of contentEncodings) {
      const decoder = own(this.#decoders, name);
      if (typeof decoder !== "function") {
        throw dcaError(
          "unsupported_encoding",
          `"${contentName}" uses unsupported content encoding ${JSON.stringify(name)}`,
        );
      }
      decoders.push(decoder);
    }

    if (typeof aad !== "string") {
      throw dcaError("bad_page", `the contentData record for "${contentName}" carries no aad`);
    }

    const contentKey = await resolveKey();
    if (!contentKey) throw dcaError("no_key", `no key opens "${contentName}"`);

    let bytes = await openContent(contentKey, contentName, own(record, "nonce"), ciphertext, aad);
    for (let index = decoders.length - 1; index >= 0; index -= 1) {
      try {
        const decoded = await decoders[index](bytes);
        if (!(decoded instanceof Uint8Array)) {
          throw dcaError(
            "bad_encoding",
            `a content decoder returned no bytes for "${contentName}"`,
          );
        }
        bytes = Uint8Array.from(decoded);
      } catch (cause) {
        if (cause instanceof DcaError) throw cause;
        throw dcaError("bad_encoding", `a content decoder refused the bytes of "${contentName}"`);
      }
    }
    return bytes;
  }
}

// @ts-check

// Decrypt one item and then reverse the representation layers its captured
// view names. Codecs stay in the caller-owned registry; neither this module nor
// the actors that compose it know any codec name. The opener reads only the
// view `DcaData#contentItemFor` captured, never the live record, so the
// AAD and the decoder selection come from one captured read.

import { openContent } from "./openContent.js";
import { capturedContentEncodings, contentEncodingLimits } from "./contentEncodings.js";
import { DcaError, dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

/**
 * A representation decoder receives the remaining output allowance for this layer.
 * @typedef {(bytes: Uint8Array, budget: { maxOutputBytes: number }) => Promise<Uint8Array>|Uint8Array} ContentDecoder
 */

export class ContentRepresentationOpener {
  /** @type {Record<string, ContentDecoder>} */
  #decoders;
  #limits;

  /**
   * The constructor copies only the registry's own enumerable properties.
   * It ignores names on the registry's prototype, so they never decode a
   * wire value.
   *
   * @param {Record<string, ContentDecoder>} [decoders]
   * @param {{ limits?: Partial<typeof import('./contentEncodings.js').DEFAULT_CONTENT_ENCODING_LIMITS> }} [options]
   */
  constructor(decoders = {}, { limits } = {}) {
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
    this.#limits = contentEncodingLimits(limits);
  }

  /**
   * Admit the item's representation before a caller authenticates its sealed
   * bytes. This checks the same captured decoder registry as `open` without
   * invoking any decoder.
   *
   * @param {{ item: import('./DcaData.js').ContentItemView }} call
   * @returns {void}
   */
  preflight({ item }) {
    this.#decodersFor(item.contentEncodings, item.contentName);
  }

  /** @param {readonly string[]} captured @param {string} contentName */
  #decodersFor(captured, contentName) {
    const contentEncodings = capturedContentEncodings(captured, contentName, this.#limits);
    /** @type {ContentDecoder[]} */
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
    return decoders;
  }

  /**
   * Open one captured item. Every value the open uses is read from the view
   * before `resolveKey` is awaited; the caller hands off the view's
   * `contentType` with the returned bytes.
   *
   * `resolveKey` receives a predicate that answers whether a candidate key
   * opens this item. Its second argument names the candidate's origin, as
   * `ContentKeyResolver` reports it (`held-content-key`, `cached-period-key`,
   * `recovered-content-key`, ...). A resolver holding rival candidates tries them with it,
   * so a wrong newest candidate cannot hide a working older one. The opener
   * keeps the bytes the returned key opened in that trial and decodes those.
   * A caller that ignores the predicate gets the single-key open as before.
   *
   * @param {object} call
   * @param {import('./DcaData.js').ContentItemView} call.item - from `DcaData#contentItemFor`
   * @param {string} call.ciphertext - base64url ciphertext, captured with the item
   * @param {(authenticate: (candidate: Uint8Array|CryptoKey, origin?: { kind?: string }) => Promise<boolean>) => Uint8Array|CryptoKey|null|undefined|Promise<Uint8Array|CryptoKey|null|undefined>} call.resolveKey
   * @returns {Promise<Uint8Array>}
   */
  async open({ item, ciphertext, resolveKey }) {
    const contentName = item.contentName;
    if (!(item.contentAad instanceof Uint8Array)) {
      throw dcaError("bad_config", `the content AAD for "${contentName}" is not bytes`);
    }
    // The view is frozen but its bytes are not; this open keeps its own copy.
    const contentAad = Uint8Array.from(item.contentAad);
    const decoders = this.#decodersFor(item.contentEncodings, contentName);

    /** @type {{ key: Uint8Array|CryptoKey, bytes: Uint8Array } | null} */
    let trial = null;
    /** @type {DcaError | null} */
    let rejected = null;
    /**
     * @param {Uint8Array|CryptoKey} candidate
     * @param {{ kind?: string }} [origin] - where the resolver found the candidate
     */
    const authenticate = async (candidate, origin) => {
      try {
        trial = {
          key: candidate,
          bytes: await openContent(candidate, contentName, ciphertext, contentAad),
        };
        return true;
      } catch (cause) {
        // Only a tag failure means "not this key". A malformed page or a key
        // configuration fault stays the refusal it is.
        if (cause instanceof DcaError && cause.code === "decrypt_failed") {
          // A delivered, unwrapped or already held candidate is treated as
          // a known key; held material can include an earlier recovered key.
          // A recovery source's current guess, or a candidate
          // passed without an origin argument, that does not open is only a
          // miss. Any supplied origin other than recovered-content-key,
          // including {}, marks a failed known candidate.
          if (origin !== undefined && origin.kind !== "recovered-content-key") rejected = cause;
          return false;
        }
        throw cause;
      }
    };
    const contentKey = await resolveKey(authenticate);
    // A resolver that tried candidates and found none that opens answers
    // null. A failed delivered or unwrapped key fails the item the way a
    // single wrong key does; failed recovered guesses leave it a miss.
    if (!contentKey) throw rejected ?? dcaError("no_key", `no key opens "${contentName}"`);

    const opened = /** @type {{ key: Uint8Array|CryptoKey, bytes: Uint8Array } | null} */ (trial);
    let bytes =
      opened !== null && opened.key === contentKey
        ? opened.bytes
        : await openContent(contentKey, contentName, ciphertext, contentAad);
    let totalInputBytes = 0;
    let totalOutputBytes = 0;
    for (let index = decoders.length - 1; index >= 0; index -= 1) {
      try {
        if (
          bytes.length > this.#limits.maxInputBytes ||
          bytes.length > this.#limits.maxTotalInputBytes - totalInputBytes
        ) {
          throw dcaError(
            "bad_encoding",
            `encoded content for "${contentName}" exceeds the input limit`,
          );
        }
        totalInputBytes += bytes.length;
        const decoded = await decoders[index](bytes, {
          maxOutputBytes: Math.min(
            this.#limits.maxOutputBytes,
            this.#limits.maxTotalOutputBytes - totalOutputBytes,
          ),
        });
        if (!(decoded instanceof Uint8Array)) {
          throw dcaError(
            "bad_encoding",
            `a content decoder returned no bytes for "${contentName}"`,
          );
        }
        if (
          decoded.length > this.#limits.maxOutputBytes ||
          decoded.length > this.#limits.maxTotalOutputBytes - totalOutputBytes
        ) {
          throw dcaError(
            "bad_encoding",
            `decoded content for "${contentName}" exceeds the output limit`,
          );
        }
        totalOutputBytes += decoded.length;
        bytes = Uint8Array.from(decoded);
      } catch (cause) {
        if (cause instanceof DcaError) throw cause;
        throw dcaError("bad_encoding", `a content decoder refused the bytes of "${contentName}"`);
      }
    }
    return bytes;
  }
}

// @ts-check
//
// Old-format control: a client that opens under the carried `aad` string, as
// every client did before the derived content AAD was adopted on 2026-10-15.
//
// Current core no longer has this path. `DcaData#contentItemFor` builds the
// adopted transcript and ignores a carried `aad`, and the reference `Client`
// opens only through it. This class keeps the reference composition's key
// delivery, cache, request and response, and replaces only the open step: it
// reads the record through the same `DcaData` admission, takes its AAD from
// `aadFor`, and uses independent historical nonce/ciphertext guards. A subclass
// that rebuilds the old string instead of reading it overrides `aadFor`.

import { Client } from "../../../../test-lib/harnesses/client.js";
import { DcaData } from "../../../../core-client/DcaData.js";
import { decrypt } from "../../../../core-shared/aead.js";
import { binaryStringBytes } from "../../../../core-shared/binaryStrings.js";
import { utf8Encode } from "../../../../core-shared/codec.js";
import { dcaError } from "../../../../core-shared/errors.js";
import { isUnicodeScalarString } from "../../../../core-shared/names.js";
import { normalizePublisherOrigin } from "../../../../core-shared/publisherOrigin.js";
import { own } from "../../../../core-shared/wire.js";

export class CarriedAadClient extends Client {
  #publisherOrigin;

  /** @param {ConstructorParameters<typeof Client>[0]} config */
  constructor(config) {
    super(config);
    this.#publisherOrigin = normalizePublisherOrigin(config.publisherOrigin);
  }

  /**
   * Where the old-format AAD comes from: the carried member.
   *
   * @param {object} _dcaData
   * @param {string} _contentName
   * @param {any} record
   * @returns {unknown}
   */
  aadFor(_dcaData, _contentName, record) {
    return own(record, "aad");
  }

  /**
   * The pre-adoption open path, in its order: record, AAD, key, AEAD.
   *
   * @param {object} dcaData
   * @param {string} contentName
   * @param {string|null} ciphertext
   * @returns {Promise<Uint8Array>}
   */
  async decrypt(dcaData, contentName, ciphertext) {
    const record = new DcaData(dcaData, { publisherOrigin: this.#publisherOrigin }).contentDataFor(
      contentName,
    );
    if (!record) {
      throw dcaError("unknown_content", `the page declares no content item "${contentName}"`);
    }
    if (typeof ciphertext !== "string") {
      throw dcaError("unknown_content", `no ciphertext for "${contentName}"`);
    }
    const aad = this.aadFor(dcaData, contentName, record);
    if (typeof aad !== "string" || !isUnicodeScalarString(aad)) {
      throw dcaError("bad_page", `the contentData record for "${contentName}" carries no aad`);
    }
    const contentKey = await this.contentKeyFor(dcaData, contentName);
    if (!contentKey) throw dcaError("no_key", `no key opens "${contentName}"`);
    const nonce = binaryStringBytes(own(record, "nonce"));
    const sealed = binaryStringBytes(ciphertext);
    if (nonce === null || nonce.length !== 12 || sealed === null || sealed.length < 16) {
      throw dcaError(
        "bad_page",
        `the historical nonce or ciphertext for "${contentName}" is malformed`,
      );
    }
    try {
      return await decrypt(contentKey, nonce, sealed, utf8Encode(aad));
    } catch {
      throw dcaError("decrypt_failed", `historical content tag mismatch for "${contentName}"`);
    }
  }
}

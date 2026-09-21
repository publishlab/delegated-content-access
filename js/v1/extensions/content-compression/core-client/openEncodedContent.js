// @ts-check
//
// Compatibility convenience for callers of the extension's earlier generic
// opener. Generic layer
// traversal now belongs to base; this extension contributes only gzip's
// decoder registry entry.

import { ContentRepresentationOpener } from "../../../core-client/ContentRepresentationOpener.js";
import { own } from "../../../core-shared/wire.js";
import { ENCODING, webStreamsGzip } from "../core-shared--client-publisher/gzipCodec.js";

/**
 * Open one content item with gzip installed in base's decoder registry.
 *
 * @param {object} call
 * @param {any} call.record - the `contentData` record, as `contentDataFor` returns it
 * @param {string} call.contentName - for the messages
 * @param {string} call.ciphertext - base64url, as the delivery carries it
 * @param {() => Promise<Uint8Array|CryptoKey|null|undefined>} call.resolveKey - the
 *   content key for this item, asked for only once the item is one this client
 *   can read
 * @param {import('../core-shared--client-publisher/gzipCodec.js').Gzip|null} [call.gzip] - the
 *   gzip implementation. The Web Streams one by default; a runtime without
 *   `DecompressionStream` passes its own, and a client that reads no gzipped
 *   item at all passes `null`.
 * @returns {Promise<Uint8Array>} the item's bytes, decompressed
 */
export async function openEncodedContent({
  record,
  contentName,
  ciphertext,
  resolveKey,
  gzip = webStreamsGzip,
}) {
  const opener = new ContentRepresentationOpener(
    gzip === null
      ? {}
      : {
          [ENCODING]: (bytes) => /** @type {any} */ (gzip).decode(bytes),
        },
  );
  return opener.open({
    record,
    contentName,
    ciphertext,
    aad: own(record, "aad"),
    resolveKey,
  });
}

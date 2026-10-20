// @ts-check
//
// Compatibility convenience for callers of the extension's earlier generic
// opener. Generic layer
// traversal now belongs to base; this extension contributes only gzip's
// decoder registry entry. The item arrives as the view
// `DcaData#contentItemFor` captured, so the content AAD, the decoders and the
// caller's handoff all come from one read of the delivery.

import { ContentRepresentationOpener } from "../../../core-client/ContentRepresentationOpener.js";
import { ENCODING, encode, decode } from "../core-shared--client-publisher/gzipCodec.js";

/**
 * Open one content item with gzip installed in base's decoder registry.
 *
 * @param {object} call
 * @param {import('../../../core-client/DcaData.js').ContentItemView} call.item - the
 *   captured view, as `DcaData#contentItemFor` returns it
 * @param {string} call.ciphertext - base64url, as the delivery carries it
 * @param {() => Promise<Uint8Array|CryptoKey|null|undefined>} call.resolveKey - the
 *   content key for this item, asked for only once the item is one this client
 *   can read
 * @param {import('../core-shared--client-publisher/gzipCodec.js').Gzip|null} [call.gzip] - the
 *   gzip implementation. The strict single-member decoder is the default;
 *   a client that reads no gzipped item at all passes `null`.
 * @returns {Promise<Uint8Array>} the item's bytes, decompressed; hand them off
 *   with `item.contentType`
 */
export async function openEncodedContent({
  item,
  ciphertext,
  resolveKey,
  gzip = { encode, decode },
}) {
  const opener = new ContentRepresentationOpener(
    gzip === null
      ? {}
      : {
          [ENCODING]: (bytes, budget) => /** @type {any} */ (gzip).decode(bytes, budget),
        },
  );
  return opener.open({ item, ciphertext, resolveKey });
}

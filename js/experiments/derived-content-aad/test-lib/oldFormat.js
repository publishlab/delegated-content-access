// @ts-check
//
// The pre-adoption content AAD, rebuilt here as an explicit old-format control.
//
// Until 2026-10-15 the publisher sealed every item under the string
// `resourceId|1|contentName` and carried it as `contentData[name].aad`; the
// client opened under whatever that member held. Current core does neither: the
// publisher seals under LP(renderId) || LP(contentName), using a fixed zero
// nonce and omitting both members; the client ignores carried nonce or AAD. So no current publisher writes
// an old-format page, and this file makes one from a current render instead.
//
// `resealOldFormat` takes an authentic current render and the item keys a real
// issuer grant delivered for it. It opens each item under the adopted
// transcript, then seals the same plaintext under the old carried string with
// the same key and a fresh nonce, and writes `aad`. The resourceJWT, issuer
// envelopes and key wraps stay the publisher's, so the real issuer still grants
// the same keys for the page. Only the content sealing is old-format.

import { adoptedContentAad } from "../implementation/tokenRepresentationAad.js";
import { decrypt, encrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";

/**
 * The carried AAD string of the pre-adoption format.
 *
 * @param {string} resourceId
 * @param {string} contentName
 * @returns {string}
 */
export function oldCarriedAad(resourceId, contentName) {
  return `${resourceId}|1|${contentName}`;
}

/**
 * The same render with every item sealed in the old carried format.
 *
 * @param {any} page - an authentic current render, in object delivery form
 * @param {Record<string, Uint8Array|CryptoKey>} contentKeys - every item's key
 * @param {string} resourceId - the resourceId the publisher signed
 * @returns {Promise<any>} a copy; the caller's page is unchanged
 */
export async function resealOldFormat(page, contentKeys, resourceId) {
  const old = structuredClone(page);
  for (const contentName of Object.keys(page.contentData)) {
    const record = old.contentData[contentName];
    const key = contentKeys[contentName];
    if (key === undefined) throw new TypeError(`no key for "${contentName}"`);
    const plaintext = await decrypt(
      key,
      new Uint8Array(NONCE_BYTES),
      base64urlDecode(page.sealedContent[contentName]),
      adoptedContentAad(page, contentName),
    );
    // A fresh nonce: the key already sealed this plaintext once under the
    // adopted transcript.
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const aad = oldCarriedAad(resourceId, contentName);
    record.nonce = base64urlEncode(nonce);
    record.aad = aad;
    old.sealedContent[contentName] = base64urlEncode(
      await encrypt(key, nonce, plaintext, utf8Encode(aad)),
    );
  }
  return old;
}

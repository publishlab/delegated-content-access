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
// the same key and zero nonce, and writes `aad`. This local resealing comparison
// deliberately holds the nonce constant to isolate AAD, and is not a production
// sealing recipe. The resourceJWT, issuer
// envelopes stay the publisher's, so the real issuer still grants the same keys.
// Most controls retain current wraps. The explicit whole-record controls also
// supply real granted period keys to build historical carried-nonce wraps.

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
 * @param {{accessGroup: string, period: string, key: string}[]} [periodKeys] - real issuer grant for historical wrap controls
 * @returns {Promise<any>} a copy; the caller's page is unchanged
 */
export async function resealOldFormat(page, contentKeys, resourceId, periodKeys) {
  const old = structuredClone(page);
  for (const record of old.contentData) {
    const { contentName } = record;
    const key = contentKeys[contentName];
    if (key === undefined) throw new TypeError(`no key for "${contentName}"`);
    // Only the explicit whole-record controls select historical wraps. Other
    // controls retain current key delivery to isolate content AAD alone.
    if (periodKeys) {
      for (const entry of record.keys ?? []) {
        const periodKey = periodKeys.find(
          (candidate) =>
            candidate.accessGroup === entry.accessGroup && candidate.period === entry.period,
        )?.key;
        if (!periodKey)
          throw new TypeError(`no granted period key for ${entry.accessGroup}/${entry.period}`);
        const wrapNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
        entry.nonce = base64urlEncode(wrapNonce);
        entry.key = base64urlEncode(await encrypt(base64urlDecode(periodKey), wrapNonce, key));
      }
    }
    const plaintext = await decrypt(
      key,
      new Uint8Array(NONCE_BYTES),
      base64urlDecode(page.sealedContent[contentName]),
      adoptedContentAad(page, contentName),
    );
    // Hold the content nonce fixed so a format mismatch tests AAD alone.
    const nonce = new Uint8Array(NONCE_BYTES);
    const aad = oldCarriedAad(resourceId, contentName);
    record.nonce = base64urlEncode(nonce);
    record.aad = aad;
    old.sealedContent[contentName] = base64urlEncode(
      await encrypt(key, nonce, plaintext, utf8Encode(aad)),
    );
  }
  return old;
}

/**
 * Historical AEAD control using actual issuer-granted period bytes. This is
 * deliberately not a current client: current clients never read carried wrap
 * nonces. The test names the granted coordinate rather than inventing access.
 * @param {any} page
 * @param {string} contentName
 * @param {{accessGroup: string, period: string, key: string}[]} periodKeys
 * @returns {Promise<{key: Uint8Array, plaintext: Uint8Array}>}
 */
export async function openOldPeriodRecord(page, contentName, periodKeys) {
  const record = page.contentData.findLast((candidate) => candidate.contentName === contentName);
  for (const entry of record.keys ?? []) {
    const periodKey = periodKeys.find(
      (candidate) =>
        candidate.accessGroup === entry.accessGroup && candidate.period === entry.period,
    )?.key;
    if (!periodKey) continue;
    const key = await decrypt(
      base64urlDecode(periodKey),
      base64urlDecode(entry.nonce),
      base64urlDecode(entry.key),
    );
    const plaintext = await decrypt(
      key,
      base64urlDecode(record.nonce),
      base64urlDecode(page.sealedContent[contentName]),
      utf8Encode(record.aad),
    );
    return { key, plaintext };
  }
  throw new TypeError("the historical control needs a granted period coordinate");
}

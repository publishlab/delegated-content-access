// @ts-check
//
// What dropping the carried item `aad` saves on one representative delivery: three
// items under period keys, one of them gzip-encoded, written by the stock JSON
// writer. The old form is the same delivery with each record's retired
// `resourceId|1|contentName` member put back where the old publisher wrote it
// (after `nonce`) and each item resealed under that string with the same key and
// nonce, so it is a delivery an old reader would open.
//
// Two differences are kept apart. AES-GCM output is as long as its input plus the
// tag whatever the AAD, so resealing changes ciphertext bytes and no lengths; the
// byte saving is the removed members alone. The test asserts both, measures raw
// and gzip sizes, and prints them as diagnostics. Raw sizes are fixed by the
// inputs; gzip sizes move by a few bytes between runs because signatures and
// envelopes are random.

import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { decrypt, encrypt } from "../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { exchangeWorld } from "./support/derivedContentAadExchanges.js";

const RESOURCE_ID = "article-42";

const ITEMS = [
  {
    name: "bodytext",
    contentType: "text/html",
    value: Array.from(
      { length: 12 },
      (_, i) =>
        `<p>Paragraph ${i + 1}: the council voted 7-2 to rezone the harbour, and the ferry ` +
        `timetable changes on Monday for the winter season.</p>`,
    ).join(""),
  },
  { name: "locked-data", contentType: "application/json", value: '{"score":[3,1],"final":true}' },
  { name: "teaser", contentType: "text/html", value: "<p>Read the full report.</p>" },
];

/** @param {Uint8Array} bytes */
const gzipLength = (bytes) => gzipSync(bytes).length;

test("removing the item aad saves its member bytes on one delivery; ciphertext length is unchanged", async (t) => {
  const w = await exchangeWorld({ route: "period", transport: "direct", resourceId: RESOURCE_ID });
  const rendered = JSON.parse(JSON.stringify(await w.render({ items: ITEMS, gzip: ["bodytext"] })));
  assert.deepEqual(rendered.dcaData.contentData.bodytext.contentEncodings, ["gzip"]);

  // The measured delivery is a working one: the public client opens every item,
  // and the period grant it takes yields each raw content key.
  const client = w.clientFor(rendered, "json", await w.readerState());
  /** @type {Record<string, Uint8Array>} */
  const keys = {};
  for (const item of ITEMS) {
    assert.equal(new TextDecoder().decode((await client.open(item.name)).bytes), item.value);
    const key = await client.resolver.contentKeyFor(client.dcaData, item.name);
    assert.ok(key instanceof Uint8Array);
    keys[item.name] = key;
  }

  /** @type {Record<string, any>} */
  const oldContentData = {};
  /** @type {Record<string, any>} */
  const carriedOnly = {};
  /** @type {Record<string, string>} */
  const oldSealed = {};
  let memberBytes = 0;
  for (const item of ITEMS) {
    const record = rendered.dcaData.contentData[item.name];
    const aad = `${RESOURCE_ID}|1|${item.name}`;
    const nonce = new Uint8Array(12);
    const encoded = await decrypt(
      keys[item.name],
      nonce,
      base64urlDecode(rendered.sealedContent[item.name]),
      contentAadOctets(rendered.dcaData, item.name),
    );
    const resealed = base64urlEncode(
      await encrypt(keys[item.name], nonce, encoded, utf8Encode(aad)),
    );
    assert.equal(
      resealed.length,
      rendered.sealedContent[item.name].length,
      `${item.name}: same length`,
    );
    assert.notEqual(resealed, rendered.sealedContent[item.name]);
    oldSealed[item.name] = resealed;

    // The old publisher's member order: contentType, nonce, aad, then the rest.
    const { contentType, nonce: n, ...rest } = record;
    oldContentData[item.name] = { contentType, nonce: n, aad, ...rest };
    carriedOnly[item.name] = oldContentData[item.name];
    memberBytes += utf8Encode(`,"aad":${JSON.stringify(aad)}`).length;
  }

  const current = writeJsonDelivery(rendered);
  const withMembers = writeJsonDelivery({
    dcaData: { ...rendered.dcaData, contentData: carriedOnly },
    sealedContent: rendered.sealedContent,
  });
  const old = writeJsonDelivery({
    dcaData: { ...rendered.dcaData, contentData: oldContentData },
    sealedContent: oldSealed,
  });

  // 7 bytes of `,"aad":` per item plus the quoted value: "article-42|1|bodytext"
  // (23), "article-42|1|locked-data" (26), "article-42|1|teaser" (21).
  assert.equal(memberBytes, 91);
  assert.equal(withMembers.length - current.length, memberBytes, "the members alone");
  assert.equal(old.length - withMembers.length, 0, "resealing under the old AAD adds no bytes");

  const sizes = {
    items: ITEMS.length,
    rawNew: current.length,
    rawOld: old.length,
    rawSaved: old.length - current.length,
    gzipNew: gzipLength(current),
    gzipOld: gzipLength(old),
    gzipSaved: gzipLength(old) - gzipLength(current),
  };
  t.diagnostic(`derived content AAD wire size: ${JSON.stringify(sizes)}`);
  assert.equal(sizes.rawSaved, 91);
  assert.ok(sizes.gzipSaved > 0, "the old form compresses larger too");
});

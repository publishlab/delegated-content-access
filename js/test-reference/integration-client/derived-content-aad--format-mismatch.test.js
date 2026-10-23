// @ts-check
//
// Old and new readers do not interoperate, and nothing on the wire chooses
// between them (docs/spec--content-protection.md Section 3.2; js/PORTING.md
// "Derived content AAD"). An item sealed under the retired
// `resourceId|1|contentName` string fails under the stock client whatever the
// record carries; a carried `aad` of any type changes no outcome on either
// format. Changing only the issuer endpoint a client is configured with leaves
// the AAD, and so the opening, unchanged.

import test from "node:test";
import assert from "node:assert/strict";
import { decrypt, encrypt } from "../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { contentRecordOf } from "../../test-lib/helpers/inspect.js";
import {
  BODY,
  GROUP,
  LOCKED,
  OTHER_UNLOCK_URL,
  RESOURCE_ID,
  UNLOCK_URL,
  periodKeysAnswered,
  putItemRecord,
  text,
  world,
} from "./derived-content-aad--support.js";

const OLD_AAD = `${RESOURCE_ID}|1|${BODY.name}`;

/**
 * A render, a reader holding its period grant, and the same render with BODY
 * resealed with only the AAD changed: the key the grant recovers, the same zero nonce, the retired
 * string as AAD and carried in the record. LOCKED stays in the new format.
 */
async function withOldItem() {
  const w = await world({ route: "period" });
  const delivered = await w.render();
  const grantee = w.client(delivered);
  assert.equal(text((await grantee.open(BODY.name)).bytes), BODY.value);
  const key = await grantee.resolver.contentKeyFor(grantee.dcaData, BODY.name);
  assert.ok(key instanceof Uint8Array);
  const nonce = new Uint8Array(12);
  const old = structuredClone(delivered);
  putItemRecord(old.dcaData, BODY.name, {
    ...contentRecordOf(old.dcaData, BODY.name),
    nonce: base64urlEncode(nonce),
    aad: OLD_AAD,
  });
  old.sealedContent[BODY.name] = base64urlEncode(
    await encrypt(key, nonce, utf8Encode(BODY.value), utf8Encode(OLD_AAD)),
  );
  return { w, delivered, old, key, cache: grantee.cache };
}

/**
 * What one retained-grant open yields, as a comparable value.
 *
 * @param {Awaited<ReturnType<typeof world>>} w
 * @param {any} delivered
 * @param {any} cache
 * @param {string} contentName
 */
async function outcome(w, delivered, cache, contentName) {
  try {
    const opened = await w.retained(delivered, cache).openLocal(contentName);
    return { contentType: opened.contentType, text: text(opened.bytes) };
  } catch (error) {
    return { code: /** @type {any} */ (error).code };
  }
}

test("an old-format item fails under the stock client, through a retained grant and a fresh unlock", async () => {
  const { w, old, key, cache } = await withOldItem();
  // The resealed item is a sound old-format item: the retired string opens it.
  const record = contentRecordOf(old.dcaData, BODY.name);
  assert.equal(
    text(
      await decrypt(
        key,
        base64urlDecode(record.nonce),
        base64urlDecode(old.sealedContent[BODY.name]),
        utf8Encode(record.aad),
      ),
    ),
    BODY.value,
  );

  assert.deepEqual(await outcome(w, old, cache, BODY.name), { code: "decrypt_failed" });
  assert.deepEqual(
    await outcome(w, old, cache, LOCKED.name),
    { contentType: LOCKED.contentType, text: LOCKED.value },
    "the new-format sibling in the same delivery opens",
  );

  const before = w.exchanges.length;
  await assert.rejects(w.client(old).open(BODY.name), { code: "decrypt_failed" });
  assert.equal(w.exchanges.length, before + 1, "one unlock and no retry under another AAD");
  assert.ok(periodKeysAnswered(w.exchanges[before].body, GROUP).length > 0);
});

test("a carried aad of any type selects no transcript: every outcome equals the outcome without it", async () => {
  const { w, delivered, old, cache } = await withOldItem();
  const adopted = contentAadOctets(delivered.dcaData, BODY.name);
  const carried = [
    OLD_AAD,
    `${RESOURCE_ID}|1|${LOCKED.name}`,
    "",
    "%%% not base64url %%%",
    base64urlEncode(adopted),
    base64urlEncode(utf8Encode(OLD_AAD)),
    0,
    17,
    -1.5,
    true,
    false,
    null,
    {},
    { aad: OLD_AAD },
    [],
    [OLD_AAD],
  ];

  /** @type {[string, any, object][]} */
  const formats = [
    ["new format", delivered, { contentType: BODY.contentType, text: BODY.value }],
    ["old format", old, { code: "decrypt_failed" }],
  ];
  for (const [format, page, expected] of formats) {
    const without = structuredClone(page);
    delete contentRecordOf(without.dcaData, BODY.name).aad;
    assert.deepEqual(await outcome(w, without, cache, BODY.name), expected, `${format}, no aad`);
    for (const value of carried) {
      const copy = structuredClone(page);
      contentRecordOf(copy.dcaData, BODY.name).aad = value;
      assert.deepEqual(
        await outcome(w, copy, cache, BODY.name),
        expected,
        `${format}, carried aad ${JSON.stringify(value)}`,
      );
    }
  }
});

test("a route-only configuration change opens the same delivery under the same AAD", async () => {
  const w = await world({ route: "period" });
  const delivered = await w.render();
  const before = JSON.stringify(delivered);
  const first = w.client(delivered, { unlockUrl: UNLOCK_URL });
  const second = w.client(delivered, { unlockUrl: OTHER_UNLOCK_URL });
  assert.equal(text((await first.open(BODY.name)).bytes), BODY.value);
  assert.equal(text((await second.open(LOCKED.name)).bytes), LOCKED.value);
  assert.deepEqual(
    w.exchanges.map((exchange) => [exchange.url, exchange.status]),
    [
      [UNLOCK_URL, 200],
      [OTHER_UNLOCK_URL, 200],
    ],
  );
  assert.equal(
    JSON.stringify(delivered),
    before,
    "the delivery the AAD is built from is unchanged",
  );
});

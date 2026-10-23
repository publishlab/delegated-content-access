// @ts-check
//
// Derived content AAD under a real reusable grant (docs/spec--content-protection.md
// Sections 3.2 and 5.4). The issuer receives only period-key envelopes, so every
// content key a reader holds came through one period grant that also reaches the
// sibling item and any later render of the same resource in the same period. That
// grant is what makes a moved or edited record worth testing.
//
// A moved record meets two independent refusals. The period-wrap nonce derives
// from the render ID and the item name (Section 4.1), so the retained grant
// recovers no key for a record moved to another slot or render. And the key the
// record's own slot recovers does not open the moved ciphertext under the new
// slot's content AAD. Each move below checks both, and no plaintext is released.
// No case falls back to a carried `aad`.

import test from "node:test";
import assert from "node:assert/strict";
import { decrypt, encrypt } from "../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { contentRecordOf, periodsOn } from "../../test-lib/helpers/inspect.js";
import {
  BODY,
  DECODERS,
  ENCODED,
  GROUP,
  LOCKED,
  RESOURCE_ID,
  encodedItem,
  periodKeysAnswered,
  putItemRecord,
  segment,
  text,
  world,
} from "./derived-content-aad--support.js";

/**
 * One render and a reader that holds a period grant for it. The grant came from
 * opening one item; the issuer returned period keys and no item key.
 */
async function granted() {
  const w = await world({ route: "period" });
  const delivered = await w.render({ items: [BODY, LOCKED, encodedItem()] });
  const grantee = w.client(delivered);
  assert.equal(text((await grantee.open(BODY.name)).bytes), BODY.value);
  assert.equal(w.exchanges.length, 1);
  assert.deepEqual(w.exchanges[0].body.keys.contentKeys, [], "no item key was delivered");
  assert.ok(periodKeysAnswered(w.exchanges[0].body, GROUP).length > 0);
  return { w, delivered, cache: grantee.cache, grantee };
}

/**
 * @param {Awaited<ReturnType<typeof world>>} w
 * @param {any} delivered
 * @param {any} cache
 * @param {string} contentName
 * @param {string} why
 * @param {Uint8Array} sourceKey - the key the moved record's own slot recovers
 */
async function refusedUnderRetainedKey(w, delivered, cache, contentName, why, sourceKey) {
  const reader = w.retained(delivered, cache);
  assert.equal(
    await reader.resolver.contentKeyFor(reader.dcaData, contentName),
    null,
    `${why}: the moved wrap recovers no key at its new slot`,
  );
  let opened = null;
  await assert.rejects(
    (async () => {
      opened = await reader.openLocal(contentName);
    })(),
    { code: "no_key" },
    why,
  );
  assert.equal(opened, null, `${why}: no plaintext is released`);
  await assert.rejects(
    decrypt(
      sourceKey,
      new Uint8Array(12),
      base64urlDecode(delivered.sealedContent[contentName]),
      contentAadOctets(delivered.dcaData, contentName),
    ),
    `${why}: the record's own key fails the new slot's content AAD`,
  );
}

/**
 * The content key one item's own slot recovers under the reader's grant.
 *
 * @param {any} reader @param {string} contentName
 * @returns {Promise<Uint8Array>}
 */
async function slotKey(reader, contentName) {
  const key = await reader.resolver.contentKeyFor(reader.dcaData, contentName);
  assert.ok(key instanceof Uint8Array);
  return key;
}

test("a retained period grant opens every item of the render it came from", async () => {
  const { w, delivered, cache } = await granted();
  const reader = w.retained(delivered, cache);
  assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value);
  assert.equal(text((await reader.openLocal(LOCKED.name)).bytes), LOCKED.value);
  const encoded = await reader.openLocal(ENCODED.name);
  assert.equal(text(encoded.bytes), ENCODED.plaintext);
  assert.equal(encoded.contentType, ENCODED.contentType);
  for (const name of [BODY.name, LOCKED.name, ENCODED.name]) {
    assert.equal(Object.hasOwn(contentRecordOf(delivered.dcaData, name), "aad"), false);
  }
});

test("name changes fail while claims and handling metadata retain authentication", async () => {
  const { w, delivered, cache, grantee } = await granted();
  const bodyKey = await slotKey(grantee, BODY.name);
  const [header, payload] = delivered.dcaData.resourceJWT.split(".");
  const claims = JSON.parse(new TextDecoder().decode(base64urlDecode(payload)));
  const headerClaims = JSON.parse(new TextDecoder().decode(base64urlDecode(header)));

  /** @type {[string, string, (copy: any) => Promise<void>|void][]} */
  const cases = [
    [
      "signing-input header: the same members in another order, validly signed",
      BODY.name,
      async (copy) => {
        const reordered = Object.fromEntries(Object.entries(headerClaims).reverse());
        copy.dcaData.resourceJWT = await w.signSegments(segment(reordered), payload);
      },
    ],
    [
      "signing-input payload: the same claims in another order, validly signed",
      BODY.name,
      async (copy) => {
        const reordered = Object.fromEntries(Object.entries(claims).reverse());
        copy.dcaData.resourceJWT = await w.signSegments(header, segment(reordered));
      },
    ],
    [
      "signing-input payload: one changed claim, validly signed",
      BODY.name,
      async (copy) => {
        const changed = { ...claims, data: { section: "sports" } };
        copy.dcaData.resourceJWT = await w.signSegments(header, segment(changed));
      },
    ],
    [
      "contentName slot: the record and its ciphertext under another name",
      "bodytext-copy",
      (copy) => {
        putItemRecord(copy.dcaData, "bodytext-copy", contentRecordOf(copy.dcaData, BODY.name));
        copy.sealedContent["bodytext-copy"] = copy.sealedContent[BODY.name];
      },
    ],
    [
      "contentType: another type",
      BODY.name,
      (copy) => {
        contentRecordOf(copy.dcaData, BODY.name).contentType = "text/plain";
      },
    ],
    [
      "contentType: the same type in another case",
      BODY.name,
      (copy) => {
        contentRecordOf(copy.dcaData, BODY.name).contentType = "TEXT/HTML";
      },
    ],
    [
      "contentType: an added parameter",
      BODY.name,
      (copy) => {
        contentRecordOf(copy.dcaData, BODY.name).contentType = "text/html; charset=utf-8";
      },
    ],
    [
      "encodings added to an item that had none",
      BODY.name,
      (copy) => {
        contentRecordOf(copy.dcaData, BODY.name).contentEncodings = ["x-identity"];
      },
    ],
    [
      "encodings: one layer removed",
      ENCODED.name,
      (copy) => {
        contentRecordOf(copy.dcaData, ENCODED.name).contentEncodings = ["x-reverse"];
      },
    ],
    [
      "encodings: the whole list removed",
      ENCODED.name,
      (copy) => {
        delete contentRecordOf(copy.dcaData, ENCODED.name).contentEncodings;
      },
    ],
    [
      // Undoing the two layers in either order gives the same plaintext, so
      // only the AAD can tell the orders apart.
      "encodings: the same layers reordered",
      ENCODED.name,
      (copy) => {
        contentRecordOf(copy.dcaData, ENCODED.name).contentEncodings = ["x-identity", "x-reverse"];
      },
    ],
    [
      "encodings: a repeated layer added",
      ENCODED.name,
      (copy) => {
        contentRecordOf(copy.dcaData, ENCODED.name).contentEncodings = [
          "x-reverse",
          "x-identity",
          "x-identity",
        ];
      },
    ],
  ];

  for (const [why, contentName, mutate] of cases) {
    const copy = structuredClone(delivered);
    await mutate(copy);
    const source = contentName === "bodytext-copy" ? BODY.name : contentName;
    const changedAad = contentAadOctets(copy.dcaData, contentName);
    const originalAad = contentAadOctets(delivered.dcaData, source);
    if (contentName === "bodytext-copy") {
      assert.notDeepEqual(changedAad, originalAad, why);
      await refusedUnderRetainedKey(w, copy, cache, contentName, why, bodyKey);
    } else {
      assert.deepEqual(changedAad, originalAad, `${why}: metadata leaves the tag unchanged`);
      const opened = await w.retained(copy, cache).openLocal(contentName);
      let expected = utf8Encode(contentName === ENCODED.name ? ENCODED.plaintext : BODY.value);
      if (contentName === ENCODED.name) expected.reverse();
      for (const encoding of [
        ...(contentRecordOf(copy.dcaData, contentName).contentEncodings ?? []),
      ].reverse()) {
        expected = DECODERS[encoding](expected);
      }
      assert.deepEqual(opened.bytes, expected, `${why}: selected processing applies`);
      assert.equal(opened.contentType, contentRecordOf(copy.dcaData, contentName).contentType, why);
    }
  }

  // The unchanged delivery still opens under the same grant, so the refusals
  // above are the edits and not a lost grant.
  const reader = w.retained(delivered, cache);
  assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value);
  assert.equal(text((await reader.openLocal(ENCODED.name)).bytes), ENCODED.plaintext);
});

/**
 * Move ciphertext and its whole item record (nonce, contentType, wraps) between
 * two slots of one delivery. Each record takes the name of the slot it lands in.
 *
 * @param {any} delivered
 */
function swapSlots(delivered) {
  const moved = structuredClone(delivered);
  putItemRecord(moved.dcaData, BODY.name, contentRecordOf(delivered.dcaData, LOCKED.name));
  putItemRecord(moved.dcaData, LOCKED.name, contentRecordOf(delivered.dcaData, BODY.name));
  moved.sealedContent[BODY.name] = delivered.sealedContent[LOCKED.name];
  moved.sealedContent[LOCKED.name] = delivered.sealedContent[BODY.name];
  return moved;
}

test("a complete record moved to another slot fails, and its carried old AAD does not reopen it", async () => {
  const { w, delivered, cache, grantee } = await granted();
  const lockedKey = await slotKey(grantee, LOCKED.name);
  const bodyKey = await slotKey(grantee, BODY.name);

  const moved = swapSlots(delivered);
  await refusedUnderRetainedKey(
    w,
    moved,
    cache,
    BODY.name,
    "LOCKED's record in BODY's slot",
    lockedKey,
  );
  await refusedUnderRetainedKey(
    w,
    moved,
    cache,
    LOCKED.name,
    "BODY's record in LOCKED's slot",
    bodyKey,
  );

  // The record itself is intact: under its own slot's transcript, spelled by
  // hand, the moved ciphertext opens.
  assert.equal(
    text(
      await decrypt(
        lockedKey,
        new Uint8Array(12),
        base64urlDecode(delivered.sealedContent[LOCKED.name]),
        contentAadOctets(delivered.dcaData, LOCKED.name),
      ),
    ),
    LOCKED.value,
  );

  // Carried members of every kind change nothing, including the old-format
  // string that names the source slot.
  for (const aad of [`${RESOURCE_ID}|1|${LOCKED.name}`, `${RESOURCE_ID}|1|${BODY.name}`, 7, {}]) {
    const carried = structuredClone(moved);
    contentRecordOf(carried.dcaData, BODY.name).aad = aad;
    await refusedUnderRetainedKey(
      w,
      carried,
      cache,
      BODY.name,
      `carried aad ${JSON.stringify(aad)}`,
      lockedKey,
    );
  }
});

test("old-format contrast: the same move opens when the AAD travels with the record", async () => {
  // Copied in shape from js/experiments/derived-content-aad/test/comparison.test.js,
  // test "a real period grant opens a moved complete record only under the old
  // carried AAD"; its sibling "a period grant opens another render's same-slot
  // record only under the old carried AAD" is the same contrast across renders.
  // Only what the contrast needs is kept: both items are resealed under the
  // retired `resourceId|1|contentName` string with the keys the period grant
  // recovered, the records are swapped, and a reader that trusts the carried string
  // and holds LOCKED's key opens LOCKED's plaintext in BODY's slot. The stock client
  // refuses the same page: the moved wrap opens no key there, and the content AAD
  // refuses LOCKED's key. A wrap without the derived nonce's slot binding handed
  // the moved record's key to that reader; here it is taken from LOCKED's own slot.
  const { w, delivered, cache, grantee } = await granted();
  const old = structuredClone(delivered);
  for (const item of [BODY, LOCKED]) {
    const key = await grantee.resolver.contentKeyFor(grantee.dcaData, item.name);
    assert.ok(key instanceof Uint8Array);
    const nonce = new Uint8Array(12);
    const aad = `${RESOURCE_ID}|1|${item.name}`;
    const ciphertext = await encrypt(key, nonce, utf8Encode(item.value), utf8Encode(aad));
    putItemRecord(old.dcaData, item.name, {
      ...contentRecordOf(old.dcaData, item.name),
      nonce: base64urlEncode(nonce),
      aad,
    });
    old.sealedContent[item.name] = base64urlEncode(ciphertext);
  }
  const moved = swapSlots(old);

  const lockedKey = await slotKey(grantee, LOCKED.name);
  const record = contentRecordOf(moved.dcaData, BODY.name);
  assert.equal(
    text(
      await decrypt(
        lockedKey,
        base64urlDecode(record.nonce),
        base64urlDecode(moved.sealedContent[BODY.name]),
        utf8Encode(record.aad),
      ),
    ),
    LOCKED.value,
    "a carried-AAD reader fills BODY's slot with LOCKED's plaintext",
  );
  await refusedUnderRetainedKey(
    w,
    moved,
    cache,
    BODY.name,
    "the stock client on the old page",
    lockedKey,
  );
});

test("a complete record moved into a fresh render of the same resourceId and period fails", async () => {
  const { w, delivered: prior, cache, grantee } = await granted();
  const priorBodyKey = await slotKey(grantee, BODY.name);
  const current = await w.render({ items: [BODY, LOCKED, encodedItem()] });
  assert.notEqual(prior.dcaData.resourceJWT, current.dcaData.resourceJWT);
  assert.equal(current.dcaData.resource.resourceId, prior.dcaData.resource.resourceId);
  assert.deepEqual(
    periodsOn(current.dcaData, BODY.name, GROUP),
    periodsOn(prior.dcaData, BODY.name, GROUP),
    "both renders wrap under the same period coordinates",
  );

  // The one grant opens both renders as published.
  for (const delivered of [prior, current]) {
    const reader = w.retained(delivered, cache);
    assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value);
  }

  for (const [name, carry] of [
    ["the prior record alone", undefined],
    ["the prior record with its old-format string", `${RESOURCE_ID}|1|${BODY.name}`],
  ]) {
    const mixed = structuredClone(current);
    putItemRecord(
      mixed.dcaData,
      BODY.name,
      structuredClone(contentRecordOf(prior.dcaData, BODY.name)),
    );
    mixed.sealedContent[BODY.name] = prior.sealedContent[BODY.name];
    if (carry !== undefined) contentRecordOf(mixed.dcaData, BODY.name).aad = carry;
    await refusedUnderRetainedKey(w, mixed, cache, BODY.name, String(name), priorBodyKey);
  }
});

test("NFC and NFD resource identifiers keep distinct authentic signing input and content AAD", async () => {
  const w = await world({ route: "period" });
  const resourceIds = ["caf\u00e9", "cafe\u0301"];
  assert.notEqual(resourceIds[0], resourceIds[1]);
  assert.equal(resourceIds[0].normalize("NFD"), resourceIds[1]);
  const deliveries = await Promise.all(
    resourceIds.map((resourceId) => w.render({ resourceId, items: [BODY] })),
  );
  const expectedAads = [];
  const readers = [];
  /** @type {Uint8Array[]} */
  const keys = [];
  for (const [index, delivered] of deliveries.entries()) {
    const reader = w.client(delivered);
    assert.equal(text((await reader.open(BODY.name)).bytes), BODY.value);
    const [, payload] = delivered.dcaData.resourceJWT.split(".");
    const signedResource = JSON.parse(text(base64urlDecode(payload)));
    assert.equal(signedResource.resourceId, resourceIds[index]);
    const exchange = w.exchanges[index];
    assert.equal(exchange.status, 200, "the issuer admitted the authentic signature");
    assert.equal(exchange.request.resourceJWT, delivered.dcaData.resourceJWT);

    const expected = contentAadOctets(delivered.dcaData, BODY.name);
    const renderBytes = utf8Encode(signedResource.renderId);
    assert.equal(new DataView(expected.buffer).getUint32(0), renderBytes.length);
    assert.deepEqual(expected.subarray(4, 4 + renderBytes.length), renderBytes);
    const key = await reader.resolver.contentKeyFor(reader.dcaData, BODY.name);
    assert.equal(
      text(
        await decrypt(
          key,
          new Uint8Array(12),
          base64urlDecode(delivered.sealedContent[BODY.name]),
          expected,
        ),
      ),
      BODY.value,
      "the authentic item opens under independently laid-out AAD bytes",
    );
    expectedAads.push(expected);
    readers.push(reader);
    keys.push(/** @type {Uint8Array} */ (key));
  }
  assert.equal(w.exchanges.length, 2);
  assert.notDeepEqual(expectedAads[0], expectedAads[1]);
  for (const index of [0, 1]) {
    const crossed = JSON.parse(JSON.stringify(deliveries[index]));
    crossed.dcaData.resourceJWT = deliveries[1 - index].dcaData.resourceJWT;
    await refusedUnderRetainedKey(
      w,
      crossed,
      readers[index].cache,
      BODY.name,
      "the other authentic Unicode signing input cannot open this ciphertext",
      keys[index],
    );
  }
});

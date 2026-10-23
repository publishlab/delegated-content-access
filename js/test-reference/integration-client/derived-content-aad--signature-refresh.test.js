// @ts-check
//
// Content AAD binds the renderId and content name. Re-signing, reordering
// claims, or changing claims other than renderId leaves content authentication
// intact; issuer admission continues to verify the complete signed token.

import test from "node:test";
import assert from "node:assert/strict";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { contentRecordOf } from "../../test-lib/helpers/inspect.js";
import {
  BODY,
  GROUP,
  LOCKED,
  encodedItem,
  ENCODED,
  periodKeysAnswered,
  putItemRecord,
  segment,
  text,
  world,
} from "./derived-content-aad--support.js";

async function granted() {
  const w = await world({ route: "period" });
  const delivered = await w.render({ items: [BODY, LOCKED, encodedItem()] });
  const grantee = w.client(delivered);
  assert.equal(text((await grantee.open(BODY.name)).bytes), BODY.value);
  assert.deepEqual(w.exchanges[0].body.keys.contentKeys, []);
  assert.ok(periodKeysAnswered(w.exchanges[0].body, GROUP).length > 0);
  return { w, delivered, cache: grantee.cache };
}

/** @param {any} delivered @param {string} token */
function withToken(delivered, token) {
  const copy = structuredClone(delivered);
  copy.dcaData.resourceJWT = token;
  return copy;
}

/** @param {string} token */
function signingInput(token) {
  return token.slice(0, token.lastIndexOf("."));
}

test("a signature-only refresh keeps the AAD: the retained key opens and the issuer admits the token", async () => {
  const { w, delivered, cache } = await granted();
  const original = delivered.dcaData.resourceJWT;
  const [header, payload] = original.split(".");
  const token = await w.signSegments(header, payload);
  assert.notEqual(token, original, "ES256 gives a new signature over the same input");
  assert.equal(signingInput(token), signingInput(original));
  const refreshed = withToken(delivered, token);
  for (const name of [BODY.name, LOCKED.name, ENCODED.name]) {
    assert.deepEqual(
      contentAadOctets(refreshed.dcaData, name),
      contentAadOctets(delivered.dcaData, name),
    );
  }

  const reader = w.retained(refreshed, cache);
  assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value);
  assert.equal(text((await reader.openLocal(ENCODED.name)).bytes), ENCODED.plaintext);

  // A reader with nothing retained unlocks the refreshed copy afresh.
  const fresh = w.client(refreshed);
  assert.equal(text((await fresh.open(LOCKED.name)).bytes), LOCKED.value);
  const last = w.exchanges.at(-1);
  assert.equal(last?.status, 200);
  assert.equal(last?.request.resourceJWT, token);
});

test("changed signed claims retain content authentication when renderId is unchanged", async () => {
  const { w, delivered, cache } = await granted();
  const [header, payload] = delivered.dcaData.resourceJWT.split(".");
  const headerClaims = JSON.parse(new TextDecoder().decode(Buffer.from(header, "base64url")));
  const claims = JSON.parse(new TextDecoder().decode(Buffer.from(payload, "base64url")));
  const changed = {
    "header: the same members reordered": await w.signSegments(
      segment(Object.fromEntries(Object.entries(headerClaims).reverse())),
      payload,
    ),
    "payload: the same claims reordered": await w.signSegments(
      header,
      segment(Object.fromEntries(Object.entries(claims).reverse())),
    ),
    "payload: one changed claim": await w.signSegments(
      header,
      segment({ ...claims, data: { section: "sports" } }),
    ),
  };
  for (const [why, token] of Object.entries(changed)) {
    const copy = withToken(delivered, token);
    const reader = w.retained(copy, cache);
    assert.ok(
      (await reader.resolver.contentKeyFor(reader.dcaData, BODY.name)) instanceof Uint8Array,
      `${why}: the retained grant still recovers the key`,
    );
    assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value, why);

    // The issuer verifies the changed token and grants again; its unchanged
    // renderId keeps the existing content usable.
    const before = w.exchanges.length;
    const fresh = w.client(copy);
    assert.equal(text((await fresh.open(LOCKED.name)).bytes), LOCKED.value, why);
    assert.equal(w.exchanges.length, before + 1, `${why}: one unlock, no retry`);
    assert.equal(w.exchanges[before].status, 200, `${why}: the issuer admitted the token`);
  }
});

test("a period key retained from a newer render opens an older render of the same period", async () => {
  const w = await world({ route: "period" });
  const older = await w.render({ items: [BODY, LOCKED] });
  const newer = await w.render({ items: [BODY, LOCKED] });
  assert.notEqual(older.dcaData.resource.renderId, newer.dcaData.resource.renderId);
  const grantee = w.client(newer);
  assert.equal(text((await grantee.open(BODY.name)).bytes), BODY.value);
  const reader = w.retained(older, grantee.cache);
  assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value);
  assert.equal(text((await reader.openLocal(LOCKED.name)).bytes), LOCKED.value);
});

test("deferred ciphertext delivered later opens only with its original render's inputs", async () => {
  const { w, delivered, cache } = await granted();
  const ciphertext = delivered.sealedContent[LOCKED.name];
  const deferred = structuredClone(delivered);
  delete deferred.sealedContent[LOCKED.name];

  // Deferred: the item is locked, its sibling opens.
  const early = w.retained(deferred, cache);
  await assert.rejects(early.openLocal(LOCKED.name), { code: "bad_page" });
  assert.equal(text((await early.openLocal(BODY.name)).bytes), BODY.value);

  // Later, the exact ciphertext arrives beside the original render's inputs,
  // or beside a signature-only refresh of them: it opens.
  const [header, payload] = delivered.dcaData.resourceJWT.split(".");
  for (const dcaData of [
    deferred.dcaData,
    withToken(deferred, await w.signSegments(header, payload)).dcaData,
  ]) {
    const later = w.retained({ dcaData, sealedContent: { [LOCKED.name]: ciphertext } }, cache);
    assert.equal(text((await later.openLocal(LOCKED.name)).bytes), LOCKED.value);
  }

  // Beside a fresh render of the same resource and period it does not. With
  // that render's own record, the fresh wrap opens a key that fails the content
  // AAD. With the original record under the fresh token, the original wrap opens
  // nothing: its nonce derives from the original render ID.
  const next = await w.render({ items: [BODY, LOCKED, encodedItem()] });
  const originalRecord = {
    ...next.dcaData,
    contentData: structuredClone(next.dcaData.contentData),
  };
  putItemRecord(
    originalRecord,
    LOCKED.name,
    structuredClone(contentRecordOf(delivered.dcaData, LOCKED.name)),
  );
  for (const [why, dcaData, code] of [
    ["the fresh render's own record", next.dcaData, "decrypt_failed"],
    ["the original record under the fresh render's token", originalRecord, "no_key"],
  ]) {
    const later = w.retained({ dcaData, sealedContent: { [LOCKED.name]: ciphertext } }, cache);
    await assert.rejects(later.openLocal(LOCKED.name), { code }, String(why));
  }
});

test("a malformed signature of valid compact shape keeps the AAD; a new issuer unlock refuses the token", async () => {
  const { w, delivered, cache } = await granted();
  const [header, payload, signature] = delivered.dcaData.resourceJWT.split(".");
  const flipped = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  for (const bad of [flipped, "AAAA"]) {
    const token = `${header}.${payload}.${bad}`;
    const copy = withToken(delivered, token);
    assert.deepEqual(
      contentAadOctets(copy.dcaData, BODY.name),
      contentAadOctets(delivered.dcaData, BODY.name),
    );

    const reader = w.retained(copy, cache);
    assert.equal(text((await reader.openLocal(BODY.name)).bytes), BODY.value, bad);

    const before = w.exchanges.length;
    const fresh = w.client(copy);
    await assert.rejects(fresh.open(BODY.name), { code: "no_key" }, bad);
    assert.equal(w.exchanges.length, before + 1);
    const refusal = w.exchanges[before];
    assert.notEqual(refusal.status, 200, `${bad}: the issuer refuses the token`);
    assert.equal(Object.hasOwn(refusal.body, "keys"), false, `${bad}: no key leaves the issuer`);
  }
});

test("a base64url-shaped but non-canonical signature forms the AAD and still opens nothing", async () => {
  // A noncanonical compact segment is rejected during item capture before
  // the client tries to resolve a key. The independent helper still spells
  // the same coordinate bytes, demonstrating the refusal is token admission.
  const { w, delivered, cache } = await granted();
  const [header, payload] = delivered.dcaData.resourceJWT.split(".");
  const copy = withToken(delivered, `${header}.${payload}.x`);
  assert.deepEqual(
    contentAadOctets(copy.dcaData, BODY.name),
    contentAadOctets(delivered.dcaData, BODY.name),
  );
  const reader = w.retained(copy, cache);
  /** @type {unknown} */
  let opened = null;
  await assert.rejects(
    (async () => {
      opened = await reader.openLocal(BODY.name);
    })(),
    { code: "bad_page" },
  );
  assert.equal(opened, null);
});

// @ts-check
//
// The client-bound EC handle chain, end to end, watched at each handle's usages.
// A companion to `client-bound.test.js`: that file proves the mode works and
// reads what crossed the wire; this one reads the least-privilege claim off the
// live handles the chain produces.
//
// The claim. Under client-bound transport nothing here holds key bytes: the
// periodKey and the contentKey are both non-extractable `CryptoKey` handles,
// and each carries only the one capability its role needs. A periodKey only
// unwraps the next hop (`['unwrapKey']`); the contentKey it opens only decrypts
// content (`['decrypt']`). Neither is handed both, and that over-grant is what
// `aead.decryptToKey`'s threaded usages exist to stop.
//
// Both handles come out of the chain itself. A shared `PeriodKeyCache` takes
// article A's unlock response, so the cached periodKey is the handle the
// resolver filed, not one made in the test. Article B is a second render of the
// same access group and period, so its contentKey is recovered the cached way:
// the periodKey unwraps B's sealed cEK with no second unlock. The counters at
// the end are how "no second unlock" is asserted: one post crossed the
// network, one grant left the server, and B's key came out of the cache.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import * as ecdhProfile from "../ecdhP256.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";
import {
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
} from "../../../demo/scenarios/fixtures.js";

const { subtle } = globalThis.crypto;
const PUBLISHER_ORIGIN = "https://www.news-site.example";

/**
 * One client's transport pair in the shape a client-bound `Client` holds it: a
 * private half whose bytes JavaScript cannot read, and the public half exported
 * once, when the pair is made, because the request it goes into is synchronous.
 * Local, the way `client-bound.test.js` keeps its own: these are a client's
 * keys, not the issuer's static seal key.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: JsonWebKey }>}
 */
async function clientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

describe("Client-bound EC: the handle chain carries least-privilege usages", () => {
  test("the cached periodKey only unwraps, the contentKey it opens only decrypts, and B needs no second unlock", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });

    // One cache, shared across the two renders: the periodKey A's unlock
    // files is the one B is later opened from. One client, holding the EC
    // keypair, so its requests ask client-bound and its resolver opens the
    // wrapped answer to handles.
    const cache = /** @type {any} */ (new PeriodKeyCache());
    const client = new Client({
      publisherOrigin: PUBLISHER_ORIGIN,
      cache,
      clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
    });

    // Article A. Build the request this client really sends, post it once,
    // and apply the client-bound answer into the shared cache.
    const pageA = (await stage.render("A")).asJson();
    const dcaDataA = client.parse(pageA);
    const request = client.buildRequest(dcaDataA, PRIMARY, [CONTENT_NAME]);
    assert.equal(request.clientPublicKey.kty, "EC", "the client asked client-bound");

    const { status, body } = await stage.network.post(PRIMARY_UNLOCK, request, {
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(status, 200);
    assert.equal(body.transport.mode, "client-bound", "and the answer wrapped its keys");

    await client.applyResponse(dcaDataA, PRIMARY, body);

    // The cached periodKeys. Every one A filed is a non-extractable handle,
    // not bytes, whose only capability is to unwrap the next hop, never
    // decrypt.
    const entries = await cache.entries();
    assert.ok(entries.length >= 1, "A delivered at least one periodKey");
    for (const { key: periodKey } of entries) {
      assert.ok(periodKey instanceof globalThis.CryptoKey, "a handle, not bytes");
      assert.equal(periodKey instanceof Uint8Array, false);
      assert.equal(periodKey.extractable, false);
      assert.deepEqual([...periodKey.usages].sort(), ["unwrapKey"], "a periodKey only unwraps");
      await assert.rejects(
        () => subtle.exportKey("raw", periodKey),
        "its bytes stay out of JavaScript",
      );
    }

    // Article B. A second render of the same access group and period. No
    // response is applied for it: its content key can only come from the
    // cached periodKey unwrapping B's sealed cEK.
    const pageB = (await stage.render("B")).asJson();
    const dcaDataB = client.parse(pageB);

    const contentKey = await client.contentKeyFor(dcaDataB, CONTENT_NAME);

    // The recovered contentKey. Also a non-extractable handle, and its only
    // capability is to decrypt content, never unwrap.
    assert.ok(contentKey instanceof globalThis.CryptoKey, "a handle, not bytes");
    assert.equal(contentKey instanceof Uint8Array, false);
    assert.equal(/** @type {any} */ (contentKey).extractable, false);
    assert.deepEqual(
      [.../** @type {any} */ (contentKey).usages].sort(),
      ["decrypt"],
      "a contentKey only decrypts",
    );
    await assert.rejects(
      () => subtle.exportKey("raw", /** @type {any} */ (contentKey)),
      "its bytes stay out too",
    );

    // And the handle chain actually opens B's body.
    const plaintext = await client.decrypt(
      dcaDataB,
      CONTENT_NAME,
      client.extract(pageB, CONTENT_NAME),
    );
    assert.equal(
      utf8Decode(plaintext),
      ARTICLES.B,
      "B opened through two handles the client never read",
    );

    // The client never unlocks a second time. One post crossed the network and
    // one grant left the server; B was answered entirely from the cached
    // periodKey.
    assert.equal(
      stage.network.stats()[PRIMARY_UNLOCK].attempts,
      1,
      "A unlocked once, B not at all",
    );
    assert.equal(stage.servers.primary.stats().grants, 1, "and the server granted once");
  });
});

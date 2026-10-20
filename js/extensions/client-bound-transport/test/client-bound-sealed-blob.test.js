// @ts-check
//
// The sealed-blob cache form, end to end, watched at what the cache holds. A
// companion to `client-bound-ec.test.js`: that file drives the client-bound
// chain through `PeriodKeyCache`, which keeps the opened handle; this one drives
// the same chain through `sealedBlobCache`, which keeps no key at all, only the
// pre-open delivery the resolver rides along in `context.delivery`, and re-opens
// it on every read.
//
// The claim. The resolver's store seam does not depend on the cache form: it
// hands `put` the opened key and the delivery, and a cache is free to keep
// either. So a second article of the same period opens with no second unlock
// whether the cache held a handle or re-unwrapped the retained blob, and the
// resolver's trial unwrap cannot tell which it read from. The sealed-blob cache
// holds only wire values: a client-bound entry holds the `{ key, nonce? }` value
// plus the response's transport (the transport public key sits beside the blob
// under ECDH), a direct entry holds the base64url string. Never a `CryptoKey`,
// never key bytes.
//
// Each test runs for every method. Both client-bound profiles (ECDH and
// RSA-OAEP) go through the one seam, and a direct world goes through the same
// cache to show its meaning is unchanged for bytes.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../../../test-lib/harnesses/client.js";
import { sealedBlobCache } from "./_lib/sealedBlobCache.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";
import * as ecdhProfile from "../ecdhP256.js";
import * as rsaProfile from "../rsaOaep.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import {
  ARTICLES,
  CONTENT_NAME,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
} from "../../../demo/scenarios/fixtures.js";

const { subtle } = globalThis.crypto;
const PUBLISHER_ORIGIN = "https://www.news-site.example";

/**
 * One client's EC transport pair, in the shape a client-bound `Client` holds it:
 * a private half whose bytes JavaScript cannot read, and the public half
 * exported once when the pair is made.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: JsonWebKey }>}
 */
async function ecClientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

/**
 * The same, RSA-OAEP: the method that wraps each key straight under the client
 * key with no agreed transport.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: JsonWebKey }>}
 */
async function rsaClientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,
      ["unwrapKey"],
    )
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

const PROFILES = [
  {
    name: "ECDH-P256",
    method: ecdhProfile.METHOD,
    profile: ecdhProfile,
    keys: ecClientKeys,
    carriesTransportKey: true,
  },
  {
    name: "RSA-OAEP",
    method: rsaProfile.METHOD,
    profile: rsaProfile,
    keys: rsaClientKeys,
    carriesTransportKey: false,
  },
];

/**
 * Asserts one held entry keeps no opened key: not a `CryptoKey`, not bytes, and
 * its wrapped blob is a string.
 *
 * @param {any} delivery
 */
function assertNoKeyHeld(delivery) {
  assert.equal(delivery.value instanceof globalThis.CryptoKey, false, "no handle in the cache");
  assert.equal(delivery.value instanceof Uint8Array, false, "no key bytes in the cache");
  assert.equal(typeof delivery.value, "object", "a client-bound value is the wrapped-key object");
  assert.equal(typeof delivery.value.key, "string", "and the blob it holds is a wire string");
}

describe("Client-bound sealed-blob cache: wrapped entries hold no key material", () => {
  for (const { name, method, profile, keys, carriesTransportKey } of PROFILES) {
    test(`${name}: A unlocks into sealed blobs, and B opens from the re-unwrapped cache with no second unlock`, async () => {
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: method === rsaProfile.METHOD ? rsaProfile : ecdhProfile,
      });

      // One capability, shared: it builds the sealed-blob cache (which
      // re-opens through it) and, via the same keypair, the client's own
      // opener. One cache across the two renders.
      const clientKeys = await keys();
      const capability = clientBoundKeyCapability(clientKeys, profile);
      const cache = sealedBlobCache(capability);
      const client = new Client({
        publisherOrigin: PUBLISHER_ORIGIN,
        cache,
        clientBoundKeyCapability: capability,
      });

      // Article A. Build the request this client really sends, post it
      // once, and apply the client-bound answer into the sealed-blob cache.
      const pageA = (await stage.render("A")).asJson();
      const dcaDataA = client.parse(pageA);
      const request = client.buildRequest(dcaDataA, PRIMARY, [CONTENT_NAME]);
      assert.equal(
        request.clientPublicKey.kty,
        carriesTransportKey ? "EC" : "RSA",
        "the client asked client-bound",
      );

      const { status, body } = await stage.network.post(PRIMARY_UNLOCK, request, {
        origin: PUBLISHER_ORIGIN,
      });
      assert.equal(status, 200);
      assert.equal(Object.hasOwn(body.transport, "mode"), false, "and the answer wrapped its keys");
      assert.equal(body.transport.method, method);

      await client.applyResponse(dcaDataA, PRIMARY, body);

      // The cache holds only wire values: no handle, no key bytes. Under
      // ECDH the transport public key sits beside the blob, the retained
      // delivery context; RSA agrees no transport, so none does.
      const entries = cache.entries();
      assert.ok(entries.length >= 1, "A delivered at least one periodKey");
      for (const { delivery } of entries) {
        assertNoKeyHeld(delivery);
        assert.equal(delivery.value.key instanceof globalThis.CryptoKey, false);
        if (carriesTransportKey) {
          assert.ok(
            delivery.transport && typeof delivery.transport.publicKey === "object",
            "the transport public key is kept beside the blob under ECDH",
          );
          assert.equal(
            delivery.value.nonce !== undefined,
            true,
            "and each ECDH value carries its nonce",
          );
        } else {
          assert.equal(delivery.transport.publicKey, undefined, "RSA keeps no transport key");
          assert.equal(delivery.value.nonce, undefined, "and no nonce");
        }
      }

      // Article B. A second render of the same access group and period. No
      // response is applied: its content key can only come from the held
      // delivery being re-unwrapped on the cached read.
      const pageB = (await stage.render("B")).asJson();
      const dcaDataB = client.parse(pageB);
      const contentKey = await client.contentKeyFor(dcaDataB, CONTENT_NAME);

      // The re-opened chain still yields a non-extractable handle the
      // client never read, and it opens B's body.
      assert.ok(contentKey instanceof globalThis.CryptoKey, "a handle, not bytes");
      assert.equal(/** @type {any} */ (contentKey).extractable, false);
      await assert.rejects(
        () => subtle.exportKey("raw", /** @type {any} */ (contentKey)),
        "its bytes stay out",
      );

      const plaintext = await client.decrypt(
        dcaDataB,
        CONTENT_NAME,
        client.extract(pageB, CONTENT_NAME),
      );
      assert.equal(utf8Decode(plaintext), ARTICLES.B, "B opened from the re-unwrapped sealed blob");

      // The client never unlocks a second time. One post crossed the network
      // and one grant left the server; B was answered entirely from the
      // re-opened cache.
      assert.equal(
        stage.network.stats()[PRIMARY_UNLOCK].attempts,
        1,
        "A unlocked once, B not at all",
      );
      assert.equal(stage.servers.primary.stats().grants, 1, "and the server granted once");
    });

    test(`${name}: a direct world through the same sealed-blob cache opens B from bytes`, async () => {
      // The store is unchanged in meaning for direct: it keeps the base64url
      // string, and the cached read decodes it to bytes.
      // The capability is only there to build the cache; the direct client
      // holds no keypair and never reaches it.
      const stage = await actorWorld({});
      const capability = clientBoundKeyCapability(await keys(), profile);
      const cache = sealedBlobCache(capability);
      const client = new Client({ publisherOrigin: PUBLISHER_ORIGIN, cache });

      const pageA = (await stage.render("A")).asJson();
      const dcaDataA = client.parse(pageA);
      const request = client.buildRequest(dcaDataA, PRIMARY, [CONTENT_NAME]);
      assert.equal(request.clientPublicKey, undefined, "a direct client sends no client key");

      const { status, body } = await stage.network.post(PRIMARY_UNLOCK, request, {
        origin: PUBLISHER_ORIGIN,
      });
      assert.equal(status, 200);
      assert.equal(body.transport, undefined, "a direct answer carries no transport");

      await client.applyResponse(dcaDataA, PRIMARY, body);

      const entries = cache.entries();
      assert.ok(entries.length >= 1, "A delivered at least one periodKey");
      for (const { delivery } of entries) {
        assert.equal(typeof delivery.value, "string", "a direct entry is the wire string");
        assert.equal(delivery.transport, undefined, "and no transport");
      }

      const pageB = (await stage.render("B")).asJson();
      const dcaDataB = client.parse(pageB);
      const plaintext = await client.decrypt(
        dcaDataB,
        CONTENT_NAME,
        client.extract(pageB, CONTENT_NAME),
      );
      assert.equal(utf8Decode(plaintext), ARTICLES.B, "B opened from the decoded bytes");

      assert.equal(
        stage.network.stats()[PRIMARY_UNLOCK].attempts,
        1,
        "A unlocked once, B not at all",
      );
    });
  }
});

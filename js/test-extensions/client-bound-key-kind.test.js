// @ts-check

// Client-bound key-kind binding across one real response. The issuer wraps a
// content key, a period key and two chain keys through KeyDelivery;
// the client admits every coordinate before it opens anything. The kind a
// key entry opens as comes from the admitted section the client reads
// (docs/spec--response-binding.md section 6), so a key entry moved into another
// admitted section of the same response, under the same method and recipient,
// must fail as one malformed key entry. Its siblings still open, and the client
// makes one open attempt per key entry: no retry as another kind or with an empty
// context.
//
// The chain composition lives here rather than in either extension, so neither
// package imports its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { chainKeyRequestBuilderFactory } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { keyDerivationSecret } from "../demo/scenarios/fixtures.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { base64urlEncode } from "../core-shared/codec.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import * as rsaProfile from "../extensions/client-bound-transport/rsaOaep.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import { ACCESS_GROUP, CONTENT_NAME, ISSUER_NAME as PRIMARY } from "../demo/scenarios/fixtures.js";

const { subtle } = globalThis.crypto;
const PUBLISHER_ORIGIN = "https://www.news-site.example";
const CHAIN_CUTOFF = "251023T1400";
const CHAIN_SIBLING = "251023T1100";
const CHAIN_GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

function chainPeriodKeySupply() {
  return periodFamilySupply({
    families: {
      [ACCESS_GROUP]: periodFamilyGeneration({
        keyDerivationSecret: keyDerivationSecret(7),
        geometry: CHAIN_GEOMETRY,
      }),
    },
    chainWindows: 2,
  });
}

/** @param {any} profile */
async function clientKeysFor(profile) {
  const pair = /** @type {CryptoKeyPair} */ (
    profile === ecdhProfile
      ? await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
      : await subtle.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          },
          false,
          ["unwrapKey", "decrypt"],
        )
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

/**
 * Records the input octets of every AES-GCM and RSA-OAEP opening primitive
 * the client spends while it applies one response: the ciphertext of
 * `decrypt` and the wrapped key of `unwrapKey`. A retry of one key entry under
 * another kind or an empty context would show its ciphertext twice.
 *
 * @template T
 * @param {() => Promise<T>} run
 * @returns {Promise<{ result: T, inputs: string[] }>}
 */
async function metered(run) {
  const originals = { decrypt: subtle.decrypt, unwrapKey: subtle.unwrapKey };
  /** @type {string[]} */
  const inputs = [];
  for (const name of /** @type {const} */ (["decrypt", "unwrapKey"])) {
    const original = /** @type {Function} */ (originals[name]);
    const dataAt = name === "decrypt" ? 2 : 1;
    /** @type {any} */ (subtle)[name] = function (/** @type {any[]} */ ...args) {
      inputs.push(base64urlEncode(new Uint8Array(args[dataAt])));
      return original.apply(subtle, args);
    };
  }
  try {
    return { result: await run(), inputs };
  } finally {
    subtle.decrypt = originals.decrypt;
    subtle.unwrapKey = originals.unwrapKey;
  }
}

/** @param {string[]} inputs @param {string} ciphertext */
function attemptsOn(inputs, ciphertext) {
  return inputs.filter((input) => input === ciphertext).length;
}

/**
 * One client-bound response for one request, wrapped by the issuer's own
 * KeyDelivery, with one content key, one period key and two chain keys,
 * each a different 16-byte value.
 *
 * @param {any} profile
 */
async function kindFixture(profile) {
  const stage = await actorWorld({
    period: { length: 15, slots: 1 },
    periodKeySupply: chainPeriodKeySupply(),
  });
  const capability = clientBoundKeyCapability(await clientKeysFor(profile), profile);
  const calls = { opens: 0 };
  const client = new Client({
    publisherOrigin: PUBLISHER_ORIGIN,
    cache: new PeriodKeyCache(),
    chainCache: new ChainKeyCache(),
    chainKeyProfile: referenceChainKeyProfile,
    requestBuilderFactory: chainKeyRequestBuilderFactory,
    clientBoundKeyCapability: {
      publicKey: capability.publicKey,
      assertCanOpenChainKeys: () => capability.assertCanOpenChainKeys(),
      async openDeliveredKeys(/** @type {unknown} */ transport) {
        const opener = await capability.openDeliveredKeys(transport);
        return {
          async open(/** @type {any[]} */ ...args) {
            calls.opens++;
            return /** @type {any} */ (opener.open)(...args);
          },
        };
      },
    },
  });
  const rawPage = (await stage.render("A")).asJson();
  rawPage.issuerData[PRIMARY].sealed.chainKeys = {
    [ACCESS_GROUP]: {
      "251023T1145": "AQ",
      "251023T2345": "Ag",
    },
  };
  rawPage.periodGeometry = { chainsPerDay: 2, periodMinutes: 15 };
  const page = client.parse(rawPage);
  const request = client.buildRequest(page, PRIMARY, [CONTENT_NAME]);
  const [periodT] = Object.keys(request.sealed.periodKeys[ACCESS_GROUP]);
  assert.ok(periodT, "the request presents a period-key coordinate");

  const delivery = new KeyDelivery({
    profile,
    random: { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) },
  });
  const view = await delivery.preflight("client-bound", new DcaRequest(request));
  const response = await delivery.prepare(
    {
      keys: {
        contentKeys: { [CONTENT_NAME]: base64urlEncode(new Uint8Array(16).fill(1)) },
        periodKeys: { [ACCESS_GROUP]: { [periodT]: base64urlEncode(new Uint8Array(16).fill(2)) } },
        chainKeys: {
          [ACCESS_GROUP]: {
            [CHAIN_SIBLING]: base64urlEncode(new Uint8Array(16).fill(3)),
            [CHAIN_CUTOFF]: base64urlEncode(new Uint8Array(16).fill(4)),
          },
        },
      },
      periodGeometry: rawPage.periodGeometry,
    },
    view,
  );

  /** @type {Record<'contentKey'|'periodKey'|'chainKey', { section: string, path: string[] }>} */
  const slots = {
    contentKey: { section: "contentKeys", path: ["contentKeys", CONTENT_NAME] },
    periodKey: { section: "periodKeys", path: ["periodKeys", ACCESS_GROUP, periodT] },
    chainKey: { section: "chainKeys", path: ["chainKeys", ACCESS_GROUP, CHAIN_CUTOFF] },
  };
  return { client, page, request, response, calls, slots };
}

/** @param {any} keys @param {string[]} path */
function keyEntryAt(keys, path) {
  return path.reduce((node, name) => node[name], keys);
}

/** @param {any} keys @param {string[]} path @param {any} value */
function setKeyEntry(keys, path, value) {
  keyEntryAt(keys, path.slice(0, -1))[/** @type {string} */ (path.at(-1))] = value;
}

const DELIVERED_KEYS = 4;
const KIND_PAIRS = /** @type {const} */ ([
  ["contentKey", "periodKey"],
  ["periodKey", "contentKey"],
  ["contentKey", "chainKey"],
  ["chainKey", "contentKey"],
  ["periodKey", "chainKey"],
  ["chainKey", "periodKey"],
]);

for (const profile of [ecdhProfile, rsaProfile]) {
  test(`${profile.METHOD} opens each same-kind key entry of one issuer response once`, async () => {
    const { client, page, request, response, calls } = await kindFixture(profile);
    const { result, inputs } = await metered(() =>
      client.applyResponse(page, PRIMARY, response, request),
    );
    assert.deepEqual(result.issues, []);
    assert.equal(
      result.accepted,
      DELIVERED_KEYS,
      "content-key, period-key and both chain-key entries open",
    );
    assert.equal(calls.opens, DELIVERED_KEYS, "one opener call per key entry");
    assert.equal(inputs.length, DELIVERED_KEYS, "one opening primitive per key entry");
  });

  test(`${profile.METHOD} refuses a key entry moved into another admitted key section`, async () => {
    for (const [from, to] of KIND_PAIRS) {
      const fixture = await kindFixture(profile);
      const { client, page, request, calls, slots } = fixture;
      const moved = structuredClone(fixture.response);
      // Same method, same recipient, same transport: only the section differs.
      const keyEntry = keyEntryAt(moved.keys, slots[from].path);
      setKeyEntry(moved.keys, slots[to].path, structuredClone(keyEntry));
      const label = `${from} entry in ${slots[to].section}`;

      const { result, inputs } = await metered(() =>
        client.applyResponse(page, PRIMARY, moved, request),
      );

      assert.deepEqual(
        result.issues,
        [{ section: slots[to].section, code: "malformed_key" }],
        `${label} is one malformed key entry`,
      );
      assert.equal(result.accepted, DELIVERED_KEYS - 1, `${label}: every sibling still opens`);
      assert.equal(calls.opens, DELIVERED_KEYS, `${label}: no second opener call`);
      assert.equal(
        attemptsOn(inputs, keyEntry.key),
        2,
        `${label}: one attempt in its own section and one in the other, no retry as another kind or empty context`,
      );
    }
  });
}

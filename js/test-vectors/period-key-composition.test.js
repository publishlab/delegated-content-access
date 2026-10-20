// @ts-check
//
// Replays the recorded period-key composition in
// verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition/
// through the real issuer and client. The publisher does not run: each step
// loads the recorded markup, and the issuer and client are built from
// `inputs.json` alone. This file does not import the recorder, so a broken
// recorder cannot hide a broken replay.
//
// The story: render A offers two periods and the issuer grants one, render B
// opens from the kept period key with no issuer call, and render C an hour
// later is refused with nothing cached or opened. Each step compares the live
// request, response, opened text and cache with the recording, and also
// asserts the story's rules directly, so a recording of the wrong story
// cannot pass by being self-consistent.
//
// A second test checks the recorded bytes with stock WebCrypto, apart from the
// reference: the renders are signed by the registered key, the granted period
// key opens B's wrap to the key that opens B, and it opens neither of the next
// period's wraps.
//
// The recorder's `--check` covers membership, checksums and regeneration; the
// package test below repeats membership and checksums only so the replay never
// runs on bytes the manifest disowns.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { domOver } from "../test-lib/helpers/domOver.js";
import { DATA_SELECTOR, SEALED_SELECTOR } from "../core-shared/markupPlacement.js";
import { Clock } from "../demo/actors/Clock.js";
import { Network } from "../demo/actors/Network.js";
import { Storage } from "../demo/actors/Storage.js";
import { Browser } from "../demo/actors/Browser.js";
import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { IssuerKeyStore } from "../demo/support/IssuerKeyStore.js";
import { openingKeysOver } from "../demo/support/PublisherRegistrations.js";
import { publisherRegistrationsOver } from "../demo/support/provisioning.js";
import { utf8Decode } from "../core-shared/codec.js";
import { ARTICLES, T_NEXT, T_NOW } from "../demo/scenarios/fixtures.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";

const DIR = fileURLToPath(
  new URL(
    "../../verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition/",
    import.meta.url,
  ),
);
const THIS_FILE = "js/test-vectors/period-key-composition.test.js";
const FORMAT = "period-key-composition/v1";
const T_AFTER_NEXT = "251023T1600";
const ACCESS_GROUP = "premium";

const { subtle } = globalThis.crypto;
const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/** @param {string} name @returns {any} */
const member = (name) => JSON.parse(readFileSync(DIR + name, "utf8"));
const manifest = member("manifest.json");
const inputs = member("inputs.json");
const renders = member("renders.json").steps;
const exchanges = member("exchange.json").exchanges;
const expected = member("expected.json").steps;

/** @param {string} text */
const fromBase64url = (text) => new Uint8Array(Buffer.from(text, "base64url"));

/** @param {Uint8Array} bytes */
const sha256Hex = async (bytes) =>
  Buffer.from(await subtle.digest("SHA-256", bytes)).toString("hex");

/** @param {unknown} value */
const hasChainGeometry = (value) => JSON.stringify(value).includes('"chainsPerDay"');

/**
 * The two carriers of one recorded render, read off its markup the way the
 * client's reader finds them.
 *
 * @param {any} render
 * @returns {{ root: any, dcaData: any, sealedContent: Record<string, string> }}
 */
function delivered(render) {
  const root = domOver(render.markup, { publisherOrigin: render.publisherOrigin });
  return {
    root,
    dcaData: JSON.parse(root.querySelector(DATA_SELECTOR).textContent),
    sealedContent: JSON.parse(root.querySelector(SEALED_SELECTOR).textContent),
  };
}

/**
 * AES-128-GCM open with stock WebCrypto.
 *
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} sealed
 * @param {Uint8Array} [aad]
 */
async function openGcm(key, nonce, sealed, aad) {
  const handle = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  const params =
    aad === undefined
      ? { name: "AES-GCM", iv: nonce }
      : { name: "AES-GCM", iv: nonce, additionalData: aad };
  return new Uint8Array(await subtle.decrypt(params, handle, sealed));
}

test("the package declares its members, and each one carries the bytes the manifest names", async () => {
  assert.equal(manifest.schema, "dca-fixture-package-manifest/v1");
  assert.equal(manifest.stability, "draft");
  assert.equal(manifest.profile, "dca-profile-period-keys");
  assert.equal(manifest.format, FORMAT);
  const consumer = (/** @type {string} */ role) =>
    manifest.consumers.find((/** @type {any} */ entry) => entry.role === role);
  assert.equal(consumer("replay").path, THIS_FILE);
  assert.equal(
    consumer("recorder self-test").path,
    "js/test-tools/record-period-key-composition.test.js",
  );
  assert.equal(
    consumer("package check").command,
    "node js/tools/record-period-key-composition.js --check",
  );

  const declared = manifest.members.map((/** @type {any} */ entry) => entry.path);
  const payloads = readdirSync(DIR)
    .filter((name) => name.endsWith(".json") && name !== "manifest.json")
    .sort();
  assert.deepEqual(declared, payloads, "every payload is declared once and replayed");
  assert.ok(existsSync(`${DIR}README.md`));

  const sums = new Map(
    readFileSync(`${DIR}SHA256SUMS`, "utf8")
      .trim()
      .split("\n")
      .map((line) => /** @type {[string, string]} */ (line.split("  ").reverse())),
  );
  for (const { path, sha256 } of manifest.members) {
    const actual = await sha256Hex(readFileSync(DIR + path));
    assert.equal(sha256, actual, `${path}: manifest sha256`);
    assert.equal(sums.get(path), actual, `${path}: SHA256SUMS`);
    assert.equal(member(path).format, FORMAT, `${path}: payload format`);
  }
});

test(
  "the recorded composition replays: a partial grant, the kept period key reused, the ungranted period refused",
  {
    tags: [
      "dca-profile-period-keys/issuer/period-key-result",
      "dca-profile-period-keys/client/period-key-admission",
    ],
  },
  async () => {
    const issuerPrivateKey = await subtle.importKey(
      "jwk",
      inputs.issuer.privateKeyJwk,
      ECDH_P256,
      false,
      ["deriveBits"],
    );
    const issuerPublicKey = await subtle.importKey(
      "jwk",
      inputs.issuer.publicKeyJwk,
      ECDH_P256,
      true,
      [],
    );
    const signingPublicKey = await subtle.importKey(
      "jwk",
      inputs.publisherRegistration.publicKeyJwk,
      ECDSA_P256,
      true,
      ["verify"],
    );
    const { issuerName, keyId, algorithm, unlockUrl } = inputs.issuer;

    const clock = new Clock(inputs.clock.start);
    const network = new Network({ clock });
    const keyStore = new IssuerKeyStore([
      { issuerName, keyId, algorithm, privateKey: issuerPrivateKey, publicKey: issuerPublicKey },
    ]);
    /** @type {any[]} */
    const presented = [];
    const server = new IssuerServer({
      clock,
      network,
      issuerName,
      unlockUrl,
      keyStore,
      publisherRegistrations: publisherRegistrationsOver(
        {
          [inputs.publisherRegistration.domain]: {
            [inputs.publisherRegistration.kid]: signingPublicKey,
          },
        },
        openingKeysOver(keyStore, [{ issuerName, keyId }]),
      ),
      accessPolicy: {
        decide(/** @type {unknown} */ _claims, /** @type {any} */ asked) {
          presented.push(JSON.parse(JSON.stringify(asked)));
          return structuredClone(inputs.issuerDecisions[presented.length - 1]);
        },
      },
      periodKeyInput: true,
      role: "primary",
    });

    /** @type {any[]} */
    const live = [];
    let step = 0;
    const browser = new Browser({
      clock,
      storage: new Storage(),
      issuers: [{ issuerName, unlockUrl }],
      relayPeriodKeys: inputs.client.relayPeriodKeys,
      network: {
        async post(/** @type {string} */ url, /** @type {any} */ request, /** @type {any} */ opts) {
          const answer = await network.post(url, request, opts);
          live.push({
            step,
            url,
            origin: opts?.origin ?? null,
            request: JSON.parse(JSON.stringify(request)),
            status: answer.status,
            body: JSON.parse(JSON.stringify(answer.body)),
          });
          return answer;
        },
      },
    });

    const grantedKey = inputs.periodKeys[ACCESS_GROUP][T_NOW];
    const names = inputs.client.contentNames;
    assert.equal(renders.length, 3);

    for (const [index, render] of renders.entries()) {
      step = index + 1;
      clock.advance(inputs.clock.steps[index].advanceMs);
      assert.equal(render.clockIso, clock.now().toISOString(), `step ${step}: recorded instant`);
      const { root, dcaData } = delivered(render);
      assert.equal(dcaData.resourceJWT, render.resourceJWT);
      // Period keys only: no sealed content key a client could open with instead.
      const block = dcaData.issuerData[issuerName];
      assert.equal(Object.hasOwn(block.sealed, "contentKeys"), false);
      assert.deepEqual(Object.keys(block.sealed.periodKeys), [ACCESS_GROUP]);
      assert.equal(hasChainGeometry(dcaData), false);

      const decisionsBefore = presented.length;
      const load = browser.load(root);
      const { missing } = await load.resolve(names);
      const unlock = missing.length === 0 ? null : await load.unlock();
      /** @type {Record<string, string|null>} */
      const texts = {};
      /** @type {Record<string, string|null>} */
      const errors = {};
      for (const name of names) {
        const opened = await load.open(name);
        texts[name] = opened.bytes === null ? null : utf8Decode(opened.bytes);
        errors[name] = opened.error;
      }
      const cache = (await browser.cache.entries()).map(({ familyName, t, key }) => ({
        familyName,
        t,
        key: Buffer.from(/** @type {Uint8Array} */ (key)).toString("base64url"),
      }));
      const issuer = server.stats();
      const want = expected[index];

      assert.deepEqual(
        live.filter((exchange) => exchange.step === step),
        exchanges.filter((/** @type {any} */ exchange) => exchange.step === step),
        `step ${step}: the live request and the issuer's answer are the recorded ones`,
      );
      assert.deepEqual(texts, want.texts, `step ${step}: opened text`);
      assert.deepEqual(errors, want.errors, `step ${step}: item errors`);
      assert.deepEqual(unlock, want.unlock, `step ${step}: unlock result`);
      assert.deepEqual(
        presented.slice(decisionsBefore),
        want.presented,
        `step ${step}: policy input`,
      );
      assert.deepEqual(cache, want.cache, `step ${step}: cached period keys`);
      assert.equal(browser.stats().unlocks, want.browserUnlocks);
      assert.deepEqual(
        { requests: issuer.requests, grants: issuer.grants, denials: issuer.denials },
        want.issuer,
      );
      for (const exchange of live) assert.equal(hasChainGeometry(exchange), false);
    }

    // The story's rules, asserted directly rather than read off the recording.
    const [first, third] = live;
    assert.equal(live.length, 2, "render B makes no issuer call");
    assert.deepEqual(renders[0].coordinates, { [ACCESS_GROUP]: [T_NOW, T_NEXT] });
    assert.deepEqual(renders[2].coordinates, { [ACCESS_GROUP]: [T_NEXT, T_AFTER_NEXT] });

    assert.equal(first.step, 1);
    assert.deepEqual(first.request.sealed.contentKeys, {});
    assert.deepEqual(Object.keys(first.request.sealed.periodKeys[ACCESS_GROUP]), [T_NOW, T_NEXT]);
    assert.equal(first.status, 200);
    assert.deepEqual(first.body, {
      keys: { contentKeys: {}, periodKeys: { [ACCESS_GROUP]: { [T_NOW]: grantedKey } } },
    });
    assert.equal(fromBase64url(grantedKey).length, 16);
    assert.deepEqual(expected[0].presented, [
      {
        contentNames: [],
        accessGroups: [ACCESS_GROUP],
        periodCoordinates: { [ACCESS_GROUP]: [T_NOW, T_NEXT] },
      },
    ]);
    assert.equal(expected[0].texts.bodytext, ARTICLES.A);

    assert.equal(expected[1].unlock, null);
    assert.equal(expected[1].texts.bodytext, ARTICLES.B);
    assert.equal(expected[1].browserUnlocks, 1, "the kept period key opened B");

    assert.equal(third.step, 3);
    assert.deepEqual(Object.keys(third.request.sealed.periodKeys[ACCESS_GROUP]), [
      T_NEXT,
      T_AFTER_NEXT,
    ]);
    assert.equal(third.status, 401);
    assert.deepEqual(third.body, { error: "denied" });
    assert.equal(expected[2].texts.bodytext, null);
    assert.equal(expected[2].errors.bodytext, "no_key");
    assert.equal(expected[2].issuer.grants, 1, "the refusal granted nothing");

    for (const observed of expected) {
      assert.deepEqual(
        observed.cache.map((/** @type {any} */ entry) => [entry.t, entry.key]),
        [[T_NOW, grantedKey]],
        `step ${observed.step}: only the granted period key is ever cached`,
      );
    }
  },
);

test("stock WebCrypto confirms the recorded renders and what the granted period key reaches", async () => {
  // No role code runs here, so this test carries no duty tag: it checks the
  // recorded bytes the replay above consumes.
  const signingKey = await subtle.importKey(
    "jwk",
    inputs.publisherRegistration.publicKeyJwk,
    ECDSA_P256,
    false,
    ["verify"],
  );
  for (const render of renders) {
    const [header, payload, signature] = render.resourceJWT.split(".");
    assert.equal(
      await subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        signingKey,
        fromBase64url(signature),
        new TextEncoder().encode(`${header}.${payload}`),
      ),
      true,
      `render ${render.label}: the registered key signed it`,
    );
  }

  const grantedKey = fromBase64url(exchanges[0].body.keys.periodKeys[ACCESS_GROUP][T_NOW]);
  const nextKey = fromBase64url(inputs.periodKeys[ACCESS_GROUP][T_NEXT]);

  /** @param {any} render */
  const itemOf = (render) => {
    const { dcaData, sealedContent } = delivered(render);
    const item = dcaData.contentData.bodytext;
    assert.equal(Object.hasOwn(item, "aad"), false, "the item record carries no aad");
    // The hand-built transcript over this render's token and item, not the reference module.
    const aad = contentAadOctets(dcaData, "bodytext");
    /** @param {string} t */
    const wrapAt = (t) => item.keys[ACCESS_GROUP].find((/** @type {any} */ wrap) => wrap.t === t);
    return { item, aad, wrapAt, ciphertext: fromBase64url(sealedContent.bodytext) };
  };
  /** @param {Uint8Array} key @param {any} wrap */
  const unwrap = (key, wrap) => openGcm(key, fromBase64url(wrap.nonce), fromBase64url(wrap.key));

  // Existing-key reach: the key granted for A opens B's wrap, and that content key opens B.
  const b = itemOf(renders[1]);
  const contentKey = await unwrap(grantedKey, b.wrapAt(T_NOW));
  assert.equal(contentKey.length, 16);
  const plaintext = await openGcm(contentKey, new Uint8Array(12), b.ciphertext, b.aad);
  assert.equal(utf8Decode(plaintext), ARTICLES.B);

  // The granted key opens no next-period wrap, in B or in the refused C.
  const c = itemOf(renders[2]);
  for (const wrap of [b.wrapAt(T_NEXT), c.wrapAt(T_NEXT)]) {
    await assert.rejects(
      unwrap(grantedKey, wrap),
      "the current period key opens no next-period wrap",
    );
  }
  // C was sealed correctly: the withheld next-period key would have opened it.
  const withheld = await unwrap(nextKey, c.wrapAt(T_NEXT));
  const opened = await openGcm(withheld, new Uint8Array(12), c.ciphertext, c.aad);
  assert.equal(utf8Decode(opened), ARTICLES.C);
});

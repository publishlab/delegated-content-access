//
// The other transport. An issuer that wraps every key it hands over to one
// client's public key, beside an issuer that hands the bytes over as they are,
// in one process at one moment.
//
// Client-bound transport runs like this here. The client generates a
// non-extractable ECDH keypair and sends the public half with the unlock
// request. The issuer agrees a transport key against it with an ephemeral pair
// of its own, wraps each key under that, and sends its ephemeral public key
// back beside the wrapped values. The client unwraps into `CryptoKey` handles
// whose bytes it cannot read either.
// None of that is the DCA wire format - the format says the issuer decides how
// keys travel - so the shapes below are this demo's frozen choice and are
// asserted as such.
//
// This file follows two lines. Direct and client-bound both live at once and
// a client that asked client-bound takes a direct answer, which is the fallback
// path.
//
// The client here is a `Browser` holding a keypair: one pair per client,
// beside its key cache and the issuer list, handed down to each load's client. So
// this file runs the client the rest of the suite runs, with the one knob this
// file is about turned on, and a mode nothing in the client asks for or is told.
//
// The tests read what crossed off the wire. A load reports what its walk did
// rather than what it was answered with, and the claims here are about the body
// itself: which shape the keys arrived in, whose public key they were wrapped
// under, whether two clients were handed the same one. `wiretap` is that
// reading, and nothing about the client changes to allow it.
//
// Pinned: one issuer, up and fast, no fallback, and the clock stands still.
// That is `demo/scenarios/world.js`'s actor family, and every test turns on
// the one thing it is about: transport mode or fallback behavior.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { Storage } from "../../../demo/actors/Storage.js";
import { IssuerServer } from "../../../demo/actors/IssuerServer.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { KeyDelivery } from "../../../adapter-issuer/KeyDelivery.js";
import * as ecdhProfile from "../ecdhP256.js";
import * as rsaProfile from "../rsaOaep.js";
import { clientBoundKeyCapability } from "../core-client/clientBoundKeyCapability.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { deliveredKeys } from "../../../core-shared--client-issuer/responseKeys.js";
import { formatT } from "../../../core-shared--publisher-issuer/periodKeys.js";
import { actorWorld, readArticle } from "../../../demo/scenarios/world.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { refuses } from "../../../test-lib/helpers/refuses.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  DOMAIN,
  FALLBACK_ISSUER_NAME as FALLBACK,
  HEALTH_URL as PRIMARY_HEALTH,
  ISSUER_NAME as PRIMARY,
  UNLOCK_URL as PRIMARY_UNLOCK,
  T_NOW,
} from "../../../demo/scenarios/fixtures.js";
import { keyAt, periodKeyMap } from "../../../test-reference/support/namedRecords.js";

const { subtle } = globalThis.crypto;

const SECOND = 1000;
const PUBLISHER_ORIGIN = `https://${DOMAIN}`;

/**
 * Counts the resource verifications and ECDH key derivations the issuer spends
 * on a request. An unreadable client key costs the one admission verification
 * and no derivation. The render and client keypair are made outside the
 * meter; only the issuer's work for the request belongs in these counts.
 *
 * @returns {{ counts: { verify: number, deriveKey: number }, stop: () => void }}
 */
function cryptoMeter() {
  const counts = { verify: 0, deriveKey: 0 };
  const originals = { verify: subtle.verify, deriveKey: subtle.deriveKey };
  for (const name of Object.keys(originals)) {
    const original = /** @type {Function} */ (
      originals[/** @type {'verify'|'deriveKey'} */ (name)]
    );
    /** @param {...any} args */
    /** @type {any} */ (subtle)[name] = function (...args) {
      counts[/** @type {'verify'|'deriveKey'} */ (name)]++;
      return original.apply(subtle, args);
    };
  }
  return {
    counts,
    stop() {
      subtle.verify = originals.verify;
      subtle.deriveKey = originals.deriveKey;
    },
  };
}

/**
 * A second issuer that hands the bytes over as they are. It differs from the
 * fixtures' fallback: it stands beside the primary rather than behind it, and
 * both answer the same page at the same moment.
 */
const SECOND_ISSUER = "paywall_reader_service";
const SECOND_UNLOCK = "https://reader.example.com/unlock";

/**
 * One client's pair, in the shape a `Browser` holds it: a private half whose
 * bytes JavaScript cannot read, and the public half exported once, when the
 * pair is made, because the request it goes into is built synchronously.
 *
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: JsonWebKey }>}
 */
async function clientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

/**
 * The RSA-OAEP client's pair, in the same shape. The private half keeps only
 * `unwrapKey`, which is all the last hop asks of it - it opens each wrapped key
 * to a handle and never decrypts anything itself.
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

/**
 * A client that can do client-bound: one of this world's browsers with a
 * keypair of its own, over the in-memory cache. The world's own `Storage` is
 * left off because a store of strings cannot hold a handle, which is a case of
 * its own further down rather than a thing every test here trips over.
 *
 * Two of these are two machines: two keypairs, two caches, one network.
 *
 * @param {any} stage
 * @param {object} [overrides] - anything else the `Browser` takes
 * @returns {Promise<any>}
 */
async function boundBrowser(stage, overrides = {}) {
  const { clientKeys: suppliedKeys, ...browserOverrides } = overrides;
  const keys = suppliedKeys ?? (await clientKeys());
  const profile = keys?.publicKey?.kty === "RSA" ? rsaProfile : ecdhProfile;
  return stage.makeBrowser({
    storage: undefined,
    issuers: stage.routes.map(({ issuerName, unlockUrl }) => ({
      issuerName,
      unlockUrl,
      acceptDirectResponse: issuerName === FALLBACK || issuerName === SECOND_ISSUER,
    })),
    clientBoundKeyCapability: clientBoundKeyCapability(keys, profile),
    // This helper composes the world so the direct fallback shows, including
    // reuse of its period key. Client-bound-only consumers are constructed
    // explicitly in the response tests.
    acceptDirectFallback: true,
    persistRawPeriodKeys: true,
    ...browserOverrides,
  });
}

/**
 * A network that keeps what crossed it, standing in for the world's own on one
 * client. `posted` is that client's unlocks in order: the request as it went
 * out, and the status and body of the ones that were answered.
 *
 * The record is made before the call, so a request that reached nobody is still
 * a request this client sent.
 *
 * @param {any} network
 * @returns {any}
 */
function wiretap(network) {
  /** @type {any[]} */
  const posted = [];
  return {
    posted,
    /**
     * @param {string} url
     * @param {any} request
     * @param {any} [options]
     * @returns {Promise<{ status: number, body: any }>}
     */
    post: async (url, request, options) => {
      const record = { url, request };
      posted.push(record);

      const answer = await network.post(url, request, options);
      Object.assign(record, answer);
      return answer;
    },
  };
}

describe("Client-bound, end to end", () => {
  test(
    "a client-bound unlock hands over handles, and the article opens",
    { tags: ["dca-profile-client-bound-ecdh-p256/issuer/wrapped-result"] },
    async () => {
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: ecdhProfile,
      });
      const wire = wiretap(stage.network);
      const browser = await boundBrowser(stage, { network: wire });

      const read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);

      assert.equal(read.errors[CONTENT_NAME], null);
      assert.equal(
        read.texts[CONTENT_NAME],
        ARTICLES.A,
        "the chain ran without the client ever seeing a byte of key",
      );
      assert.equal(read.unlock.status, 200);
      assert.equal(
        read.unlock.transportMode,
        "client-bound",
        "read off the answer, not off what was asked for",
      );

      const [{ request, body }] = wire.posted;

      // The request carries the client's public half, in its wire form. It
      // crossed the `Network`, so it is already known to be JSON-safe.
      assert.equal(request.clientPublicKey.kty, "EC");
      assert.equal(request.clientPublicKey.crv, "P-256");
      assert.equal(request.clientPublicKey.d, undefined, "the public half, and only that");

      // The answer says how it travelled by carrying the issuer's ephemeral
      // public key, and every key in it is wrapped under a nonce of its own.
      assert.equal(Object.hasOwn(body.transport, "mode"), false);
      assert.equal(body.transport.publicKey.kty, "EC");
      const values = [...deliveredKeys(body.keys)];
      assert.ok(values.length >= 2, "a contentKey and at least one periodKey");
      for (const value of values) {
        assert.equal(typeof value, "object", "no bare key bytes anywhere in a client-bound body");
        assert.equal(typeof value.key, "string");
        assert.equal(typeof value.nonce, "string");
      }
      assert.equal(
        new Set(values.map((/** @type {any} */ v) => v.nonce)).size,
        values.length,
        "one nonce per key",
      );

      // What client-bound adds: the cached periodKey is a handle, and the bytes
      // behind it are not reachable from JavaScript.
      const [held] = await browser.cache.entries();
      assert.ok(!(held.key instanceof Uint8Array), "not bytes");
      assert.equal(held.key.extractable, false);
      assert.equal(held.key.algorithm.name, "AES-GCM");
      await assert.rejects(
        () => subtle.exportKey("raw", held.key),
        "exportKey is what non-extractable refuses",
      );

      assert.equal(stage.servers.primary.stats().transportMode, "client-bound");
      assert.equal(stage.servers.primary.stats().grants, 1);
    },
  );

  test("ECDH client-bound delivery derives the transport key without exposing shared bits", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });
    const browser = await boundBrowser(stage);
    const meter = cryptoMeter();
    let read;
    try {
      read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
    } finally {
      meter.stop();
    }

    assert.equal(read.errors[CONTENT_NAME], null, "the same ECDH transport body still opens");
    assert.ok(
      meter.counts.deriveKey >= 2,
      "issuer and client derive their non-extractable HKDF bases",
    );
    assert.equal(
      /subtle\.deriveBits\(/.test(
        await readFile(
          new URL("../core-shared--client-issuer/ecdhP256.js", import.meta.url),
          "utf8",
        ),
      ),
      false,
      "the client-bound profile never asks WebCrypto to return an ECDH shared secret",
    );
  });

  test(
    "the RSA-OAEP method wraps under the client key alone, and the article opens",
    { tags: ["dca-profile-client-bound-rsa-oaep/issuer/wrapped-result"] },
    async () => {
      // The issuer's other method: it wraps each key straight under the
      // client's RSA public key, so the body carries no ephemeral public key
      // and each value is the wrapped key alone. `clientBoundProfile` is the
      // issuer's; the client pairs its RSA keypair with the RSA profile off the
      // key's kty, and nothing else about the flow changes.
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: rsaProfile,
      });
      const wire = wiretap(stage.network);
      const browser = await boundBrowser(stage, {
        network: wire,
        clientKeys: await rsaClientKeys(),
      });

      const read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);

      assert.equal(read.errors[CONTENT_NAME], null);
      assert.equal(
        read.texts[CONTENT_NAME],
        ARTICLES.A,
        "the chain ran without the client ever seeing a byte of key",
      );
      assert.equal(read.unlock.status, 200);
      assert.equal(read.unlock.transportMode, "client-bound");

      const [{ request, body }] = wire.posted;
      assert.equal(
        request.clientPublicKey.kty,
        "RSA",
        "the request carries the client's RSA public half",
      );
      assert.equal(request.clientPublicKey.d, undefined, "the public half, and only that");

      // The answer names its method and carries no ephemeral public key: RSA
      // agrees no transport, so the values are the wrapped keys alone.
      assert.equal(Object.hasOwn(body.transport, "mode"), false);
      assert.equal(body.transport.method, "RSA-OAEP");
      assert.equal(
        body.transport.publicKey,
        undefined,
        "RSA wraps under the client key, so it carries none back",
      );
      const values = [...deliveredKeys(body.keys)];
      assert.ok(values.length >= 2, "a contentKey and at least one periodKey");
      for (const value of values) {
        assert.equal(typeof value, "object", "no bare key bytes anywhere in a client-bound body");
        assert.equal(typeof value.key, "string");
        assert.equal(value.nonce, undefined, "RSA carries no wrapping nonce");
      }

      // The cached periodKey is a non-extractable handle, as under ECDH: the
      // method changed, the shape the cache holds did not.
      const [held] = await browser.cache.entries();
      assert.ok(!(held.key instanceof Uint8Array), "not bytes");
      assert.equal(held.key.extractable, false);
      assert.equal(held.key.algorithm.name, "AES-GCM");
      await assert.rejects(
        () => subtle.exportKey("raw", held.key),
        "exportKey is what non-extractable refuses",
      );

      assert.equal(stage.servers.primary.stats().transportMode, "client-bound");
      assert.equal(stage.servers.primary.stats().grants, 1);
    },
  );

  test(
    "a required RSA-OAEP issuer refuses a missing or malformed offer before opening a publisher key",
    { tags: ["dca-profile-client-bound-rsa-oaep/issuer/wrapped-result"] },
    async () => {
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: rsaProfile,
      });
      const wire = wiretap(stage.network);
      const browser = await boundBrowser(stage, {
        network: wire,
        clientKeys: await rsaClientKeys(),
      });

      stage.network.offline(PRIMARY_UNLOCK);
      await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
      stage.network.online(PRIMARY_UNLOCK);
      const { request } = wire.posted[0];
      const { clientPublicKey: offeredKey, ...requestWithoutOffer } = request;
      assert.equal(offeredKey.kty, "RSA");

      const meter = cryptoMeter();
      try {
        for (const [clientPublicKey, error] of [
          [undefined, "client_key_required"],
          [{}, "bad_client_key"],
        ]) {
          const answer = await stage.network.post(
            PRIMARY_UNLOCK,
            {
              ...requestWithoutOffer,
              ...(clientPublicKey === undefined ? {} : { clientPublicKey }),
            },
            { from: browser, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
          );
          assert.equal(answer.status, 400);
          assert.equal(answer.body.error, error);
          assert.equal(answer.body.keys, undefined, "no key in direct representation is released");
        }
      } finally {
        meter.stop();
      }

      // Browser admission verifies the resource and compares origins before it
      // reads the offer, so each request costs one verification. A second one
      // would mean the refused request reached the engine.
      assert.equal(stage.servers.primary.stats().grants, 0);
      assert.equal(stage.keyStores.primary.reachCount, 0, "no publisher opening key is reached");
      assert.equal(meter.counts.verify, 2, "one admission verification per refused offer");
    },
  );

  test("a second article of the same period opens from the handle in the cache, with no unlock", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });
    const browser = await boundBrowser(stage);

    await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
    const second = await readArticle(browser, await stage.render("B"), [CONTENT_NAME]);

    assert.equal(second.texts[CONTENT_NAME], ARTICLES.B);
    assert.equal(second.unlock, null, "nothing was missing, so nothing was asked");
    assert.equal(stage.network.stats()[PRIMARY_UNLOCK].attempts, 1);
  });

  test(
    "two clients get bodies wrapped to their own keys",
    { tags: ["dca-profile-client-bound-ecdh-p256/issuer/wrapped-result"] },
    async () => {
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: ecdhProfile,
      });
      const page = await stage.render("A");

      const oneWire = wiretap(stage.network);
      const otherWire = wiretap(stage.network);
      const one = await boundBrowser(stage, { network: oneWire });
      const other = await boundBrowser(stage, { network: otherWire });

      const first = await readArticle(one, page, [CONTENT_NAME]);
      const second = await readArticle(other, page, [CONTENT_NAME]);

      assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
      assert.equal(second.texts[CONTENT_NAME], ARTICLES.A, "both read the same article");
      assert.notDeepEqual(
        otherWire.posted[0].body,
        oneWire.posted[0].body,
        "and each got a body of its own",
      );
      assert.notEqual(
        oneWire.posted[0].body.transport.publicKey.x,
        otherWire.posted[0].body.transport.publicKey.x,
        "an ephemeral transport key per response",
      );

      // The proof that the two are not interchangeable: one client's body
      // applied by a third accepts none of its entries, because each was
      // wrapped to a key that client does not hold. A client composition of
      // its own, because taking somebody else's answer is not a step a page
      // load has.
      const stranger = new Client({
        publisherOrigin: PUBLISHER_ORIGIN,
        cache: /** @type {any} */ (new PeriodKeyCache()),
        clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
      });
      const report = await stranger.applyResponse(
        first.load.dcaData,
        PRIMARY,
        oneWire.posted[0].body,
        oneWire.posted[0].request,
      );
      assert.equal(report.accepted, 0);
      assert.equal(report.issues.length, [...deliveredKeys(oneWire.posted[0].body.keys)].length);
      assert.ok(report.issues.every((issue) => issue.code === "malformed_key"));
    },
  );
});

describe("Both modes at once, and the fallback path", () => {
  test("an unsupported response transport ends this walk; an independent direct issuer still answers", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });
    await stage.standUp(SECOND_ISSUER, SECOND_UNLOCK);

    const network = {
      post: async (url, request, options) => {
        const answer = await stage.network.post(url, request, options);
        if (url !== PRIMARY_UNLOCK || answer.status !== 200) return answer;
        return {
          ...answer,
          body: {
            ...answer.body,
            transport: { ...answer.body.transport, method: "not-this-client" },
          },
        };
      },
    };
    const browser = await boundBrowser(stage, { network });
    const page = await stage.render("A");
    const read = await readArticle(browser, page, [CONTENT_NAME]);

    assert.equal(read.texts[CONTENT_NAME], null);
    assert.equal(read.errors[CONTENT_NAME], "no_key");
    assert.equal(read.unlock.issuerName, PRIMARY);
    assert.deepEqual(
      read.unlock.attempts.map((attempt) => ({
        issuerName: attempt.issuerName,
        outcome: attempt.outcome,
      })),
      [{ issuerName: PRIMARY, outcome: "invalid_transport" }],
    );

    const independent = await readArticle(browser, page, [CONTENT_NAME], {
      issuerName: SECOND_ISSUER,
    });
    assert.equal(independent.texts[CONTENT_NAME], ARTICLES.A);
    assert.deepEqual(
      independent.unlock.attempts.map(({ issuerName, outcome }) => ({ issuerName, outcome })),
      [{ issuerName: SECOND_ISSUER, outcome: "answered" }],
    );
  });

  test("one unsolicited ECDH-wrapped entry does not suppress its valid siblings", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });
    const keys = await clientKeys();
    const wire = wiretap(stage.network);
    const browser = await boundBrowser(stage, { network: wire, clientKeys: keys });
    const read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
    const body = structuredClone(wire.posted[0].body);
    const good = keyAt(body.keys.contentKeys, { contentName: CONTENT_NAME });
    body.keys.contentKeys.push({
      contentName: "malformedSibling",
      key: { ...good, key: `${good.key[0] === "A" ? "B" : "A"}${good.key.slice(1)}` },
    });
    const consumer = new Client({
      publisherOrigin: PUBLISHER_ORIGIN,
      cache: /** @type {any} */ (new PeriodKeyCache()),
      clientBoundKeyCapability: clientBoundKeyCapability(keys, ecdhProfile),
    });

    const report = await consumer.applyResponse(
      read.load.dcaData,
      PRIMARY,
      body,
      wire.posted[0].request,
    );

    assert.equal(report.accepted, [...deliveredKeys(wire.posted[0].body.keys)].length);
    assert.deepEqual(report.issues, [{ section: "contentKeys", code: "unsolicited_coordinate" }]);
    assert.ok(
      await consumer.contentKeyFor(read.load.dcaData, CONTENT_NAME),
      "the valid content sibling was retained",
    );
    assert.equal(await consumer.contentKeyFor(read.load.dcaData, "malformedSibling"), null);
  });

  test("direct and client-bound live at once, and a client that asked client-bound takes a direct answer", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
      fallback: true,
    });

    // Two issuers, two modes, one process and one moment.
    assert.equal(stage.servers.primary.stats().transportMode, "client-bound");
    assert.equal(stage.servers.fallback.stats().transportMode, "direct");

    const wire = wiretap(stage.network);
    const browser = await boundBrowser(stage, { network: wire });

    const first = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
    assert.equal(first.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(first.unlock.issuerName, PRIMARY);
    assert.equal(first.unlock.transportMode, "client-bound");
    assert.equal(Object.hasOwn(wire.posted[0].body.transport, "mode"), false);

    // The outage, two periods later - far enough that the handles this client
    // is holding open nothing, so it has to ask somebody.
    stage.network.offline(PRIMARY_UNLOCK);
    stage.network.offline(PRIMARY_HEALTH);
    stage.clock.advance(2 * 60 * 60 * SECOND);

    // The same client, the same request shape - it still carries a
    // clientPublicKey, because that is what this client is - and the answer
    // comes back as readable bytes.
    const second = await readArticle(browser, await stage.render("B"), [CONTENT_NAME]);
    assert.deepEqual(
      second.unlock.attempts.map((/** @type {any} */ a) => ({
        issuerName: a.issuerName,
        outcome: a.outcome,
      })),
      [
        { issuerName: PRIMARY, outcome: "offline" },
        { issuerName: FALLBACK, outcome: "answered" },
      ],
    );

    const answered = wire.posted.at(-1);
    assert.equal(
      answered.request.clientPublicKey.kty,
      "EC",
      "the client asked for client-bound all the same",
    );
    assert.equal(
      answered.body.transport,
      undefined,
      "and a direct answer says nothing about transport",
    );
    for (const value of deliveredKeys(answered.body.keys)) {
      assert.equal(typeof value, "string", "direct is the bytes, base64url");
    }
    assert.equal(second.unlock.transportMode, "direct");
    assert.equal(
      second.texts[CONTENT_NAME],
      ARTICLES.B,
      "the client read the response by what is in it, not by what it asked for",
    );

    // The cache now holds one of each, and it holds both the same way.
    const held = await browser.cache.entries();
    assert.ok(
      held.some((/** @type {any} */ e) => e.key instanceof Uint8Array),
      "the fallback bytes",
    );
    assert.ok(
      held.some((/** @type {any} */ e) => !(e.key instanceof Uint8Array)),
      "the primary handle",
    );
  });

  test("an RSA-OAEP client rides the failover: direct in the outage, then RSA-OAEP again when the primary is back", async () => {
    // The same arc as the EC failover, on an RSA-OAEP primary and an RSA
    // keypair the client carries from the first article to the last. RSA
    // wraps under the client key alone, so the healthy and resumed bodies
    // name their method and carry no ephemeral key; the fallback answers
    // direct and never reads the offered key at all.
    const stage = await actorWorld({
      transportMode: "client-bound",
      fallback: true,
      breaker: { threshold: 1 },
      clientBoundProfile: rsaProfile,
    });
    assert.equal(stage.servers.primary.stats().transportMode, "client-bound");
    assert.equal(stage.servers.fallback.stats().transportMode, "direct");

    const wire = wiretap(stage.network);
    const browser = await boundBrowser(stage, { network: wire, clientKeys: await rsaClientKeys() });

    // Healthy: the primary answers client-bound, and it says RSA-OAEP - the
    // wrapped keys are the values alone, with no ephemeral key and no nonce.
    const healthy = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
    assert.equal(healthy.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(healthy.unlock.issuerName, PRIMARY);
    assert.equal(healthy.unlock.transportMode, "client-bound");
    const healthyPost = wire.posted[0];
    assert.equal(
      healthyPost.request.clientPublicKey.kty,
      "RSA",
      "the client offered its RSA public half",
    );
    assert.equal(Object.hasOwn(healthyPost.body.transport, "mode"), false);
    assert.equal(healthyPost.body.transport.method, "RSA-OAEP");
    assert.equal(
      healthyPost.body.transport.publicKey,
      undefined,
      "RSA wraps under the client key, so none comes back",
    );
    for (const value of deliveredKeys(healthyPost.body.keys)) {
      assert.equal(typeof value.key, "string");
      assert.equal(value.nonce, undefined, "RSA carries no wrapping nonce");
    }
    const healthyCache = await browser.cache.entries();
    assert.ok(
      healthyCache.every((/** @type {any} */ e) => !(e.key instanceof Uint8Array)),
      "every entry a handle",
    );

    // The outage, two periods later - far enough that the handles this client
    // holds open nothing, so it has to ask somebody.
    stage.network.offline(PRIMARY_UNLOCK);
    stage.network.offline(PRIMARY_HEALTH);
    stage.clock.advance(2 * 60 * 60 * SECOND);

    // The fallback answers direct. The request still carries the RSA public
    // half, because that is what this client is, and the fallback ignored it.
    const outage = await readArticle(browser, await stage.render("B"), [CONTENT_NAME]);
    assert.equal(outage.texts[CONTENT_NAME], ARTICLES.B);
    assert.deepEqual(
      outage.unlock.attempts.map((/** @type {any} */ a) => ({
        issuerName: a.issuerName,
        outcome: a.outcome,
      })),
      [
        { issuerName: PRIMARY, outcome: "offline" },
        { issuerName: FALLBACK, outcome: "answered" },
      ],
    );
    assert.equal(outage.unlock.transportMode, "direct");
    const answered = wire.posted.at(-1);
    assert.equal(
      answered.request.clientPublicKey.kty,
      "RSA",
      "the client asked client-bound all the same",
    );
    assert.equal(
      answered.body.transport,
      undefined,
      "a direct answer says nothing about transport",
    );
    for (const value of deliveredKeys(answered.body.keys)) {
      assert.equal(typeof value, "string", "direct is the bytes, base64url");
    }
    const mixed = await browser.cache.entries();
    assert.ok(
      mixed.some((/** @type {any} */ e) => e.key instanceof Uint8Array),
      "the fallback bytes",
    );
    assert.ok(
      mixed.some((/** @type {any} */ e) => !(e.key instanceof Uint8Array)),
      "the primary handles",
    );

    // The tail: the primary is back, but this article is still inside the
    // period the fallback granted, so it opens against the cached key the
    // direct fallback delivered, at no unlock - the outage grant reaches until
    // its period rolls.
    stage.network.online(PRIMARY_UNLOCK);
    stage.network.online(PRIMARY_HEALTH);
    const tail = await readArticle(browser, await stage.render("C"), [CONTENT_NAME]);
    assert.equal(tail.texts[CONTENT_NAME], ARTICLES.C);
    assert.equal(
      tail.unlock,
      null,
      "the cached key from the direct fallback opened it, so nobody was asked",
    );

    // Past that period and past the breaker's window: the client asks again,
    // the breaker half-opens, and the trial call is the unlock. The primary
    // that is back answers RSA-OAEP on the same keypair, and re-wraps for the
    // same capability the client has carried all along.
    stage.clock.advance(41 * 60 * SECOND);
    const resumed = await readArticle(browser, await stage.render("D"), [CONTENT_NAME]);
    assert.equal(resumed.texts[CONTENT_NAME], ARTICLES.D);
    assert.equal(resumed.unlock.issuerName, PRIMARY);
    assert.equal(
      resumed.unlock.transportMode,
      "client-bound",
      "the primary answers in the mode it always had",
    );
    assert.deepEqual(
      resumed.unlock.attempts.map((/** @type {any} */ a) => a.outcome),
      ["answered"],
      "the breaker half-opened, and the trial call was the unlock",
    );
    const resumedPost = wire.posted.at(-1);
    assert.equal(
      resumedPost.request.clientPublicKey.kty,
      "RSA",
      "the same RSA keypair, first article to last",
    );
    assert.equal(
      resumedPost.body.transport.method,
      "RSA-OAEP",
      "re-wrapped under RSA-OAEP for the same capability",
    );
    assert.equal(resumedPost.body.transport.publicKey, undefined);
    const afterResume = await browser.cache.entries();
    assert.ok(
      afterResume.some((/** @type {any} */ e) => !(e.key instanceof Uint8Array)),
      "a handle again",
    );
  });

  test(
    "a client-bound method the first issuer cannot speak ends the walk, and no later issuer is tried",
    { tags: ["dca-profile-client-bound-ecdh-p256/issuer/wrapped-result"] },
    async () => {
      // Two issuers standing, the first client-bound on ECDH. The client
      // carries an RSA-OAEP keypair, so the method it offers is one the first
      // issuer cannot agree: it refuses the key at preflight as bad_client_key
      // and answers 400. A non-200 ends the walk, so the second issuer, which
      // would have answered, is never asked.
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: ecdhProfile,
      });
      const { server: second } = await stage.standUp(SECOND_ISSUER, SECOND_UNLOCK);

      const wire = wiretap(stage.network);
      const browser = await boundBrowser(stage, {
        network: wire,
        clientKeys: await rsaClientKeys(),
      });

      const read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);

      assert.equal(read.unlock.ok, false, "the mismatch is fatal, not a downgrade");
      assert.equal(read.unlock.status, 400);
      assert.deepEqual(
        read.unlock.attempts.map((/** @type {any} */ a) => ({
          issuerName: a.issuerName,
          outcome: a.outcome,
        })),
        [{ issuerName: PRIMARY, outcome: "rejected" }],
        "one attempt, rejected at the first issuer, and the walk stops there",
      );
      assert.ok(
        !read.unlock.attempts.some((/** @type {any} */ a) => a.outcome === "answered"),
        "no issuer answered",
      );
      assert.equal(wire.posted.at(-1).body.error, "bad_client_key");
      assert.equal(read.texts[CONTENT_NAME], null);
      assert.equal(read.errors[CONTENT_NAME], "no_key");

      // The second issuer, which hands bytes over and would have answered, was
      // never reached: the walk did not shop past the refusal.
      assert.equal(second.stats().requests, 0, "the later issuer never heard from this client");
      assert.equal(stage.servers.primary.stats().grants, 0, "and the first opened nothing");
    },
  );

  test(
    "a server pinned to client-bound refuses a request that brings no client key",
    { tags: ["dca-profile-client-bound-ecdh-p256/issuer/wrapped-result"] },
    async () => {
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: ecdhProfile,
      });
      const wire = wiretap(stage.network);

      // A browser with no keypair: it offers nothing, and asks for direct by
      // saying nothing about a mode at all.
      const plain = stage.makeBrowser({ network: wire });
      const page = await stage.render("A");

      const meter = cryptoMeter();
      /** @type {any} */
      let read;
      try {
        read = await readArticle(plain, page, [CONTENT_NAME]);
      } finally {
        meter.stop();
      }

      // The downgrade is not the issuer's to make quietly: answering direct here
      // would hand raw bytes to anyone who left the client key out.
      assert.equal(read.unlock.status, 400);
      assert.equal(wire.posted[0].request.clientPublicKey, undefined);
      assert.equal(wire.posted[0].body.error, "client_key_required");
      assert.equal(read.texts[CONTENT_NAME], null);
      assert.equal(read.errors[CONTENT_NAME], "no_key");
      assert.equal(stage.servers.primary.stats().grants, 0);
      assert.equal(
        stage.servers.primary.stats().refusals,
        1,
        "and the refusal is on the record as one",
      );
      assert.equal(
        meter.counts.verify,
        1,
        "the missing key is refused after admission verifies the resource, once",
      );
      assert.equal(meter.counts.deriveKey, 0, "and before an ECDH transport agreement");
      assert.equal(
        stage.keyStores.primary.reachCount,
        0,
        "and before the issuer reaches a private key",
      );
    },
  );

  test(
    "a client key the issuer cannot read is refused before anything is unsealed",
    { tags: ["dca-profile-client-bound-ecdh-p256/issuer/wrapped-result"] },
    async () => {
      const stage = await actorWorld({
        transportMode: "client-bound",
        clientBoundProfile: ecdhProfile,
      });
      const wire = wiretap(stage.network);
      const browser = await boundBrowser(stage, { network: wire });

      // The request a load really builds, taken off the wire on its way out
      // rather than written here - one written by hand could drift from what
      // this client sends. The issuer is unreachable for it, so the counters
      // below carry nothing but the five refusals.
      stage.network.offline(PRIMARY_UNLOCK);
      await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
      stage.network.online(PRIMARY_UNLOCK);

      const { request } = wire.posted[0];
      const good = request.clientPublicKey;

      const meter = cryptoMeter();
      try {
        for (const clientPublicKey of [
          {},
          "not a key",
          { ...good, crv: "P-384" },
          { ...good, x: "not-a-coordinate" },
          { ...good, d: "a-private-scalar" },
        ]) {
          const answer = await stage.network.post(
            PRIMARY_UNLOCK,
            { ...request, clientPublicKey },
            { from: browser, timeout: 2 * SECOND, origin: PUBLISHER_ORIGIN },
          );
          assert.equal(answer.status, 400, JSON.stringify(clientPublicKey));
          assert.equal(answer.body.error, "bad_client_key");
        }
      } finally {
        meter.stop();
      }

      // Nothing was opened for any of them: a request there is no way to answer
      // is not a request worth taking a key out of a sealed blob for.
      assert.equal(stage.servers.primary.stats().grants, 0);
      assert.equal(stage.servers.primary.stats().requests, 5);
      assert.equal(
        stage.servers.primary.stats().refusals,
        5,
        "every one of them turned away, and counted",
      );
      assert.equal(
        meter.counts.verify,
        5,
        "each bad key is refused after admission verifies the resource, once",
      );
      assert.equal(meter.counts.deriveKey, 0, "and before any ECDH agreement");
      assert.equal(
        stage.keyStores.primary.reachCount,
        0,
        "and before the issuer reaches a private key",
      );
    },
  );
});

describe("Issuer delivery admission", () => {
  test("issuer preflights before delivery preparation and trims fallback responses", async () => {
    // Record the concrete delivery collaborators. Preflight must happen
    // before response preparation, and fallback trimming must happen before
    // the trimmed body reaches preparation.
    /** @type {string[]} */
    const calls = [];
    /** @type {any[]} */
    const prepared = [];
    const originalPreflight = KeyDelivery.prototype.preflight;
    const originalPrepare = KeyDelivery.prototype.prepare;

    KeyDelivery.prototype.preflight = async function (...args) {
      calls.push("preflight");
      return originalPreflight.apply(this, /** @type {any} */ (args));
    };
    KeyDelivery.prototype.prepare = async function (...args) {
      calls.push("prepare");
      prepared.push(structuredClone(args[0]));
      return originalPrepare.apply(this, /** @type {any} */ (args));
    };
    try {
      const ordinary = await actorWorld();
      const page = await ordinary.render("A");
      await readArticle(ordinary.makeBrowser(), page, [CONTENT_NAME]);
      await readArticle(ordinary.makeBrowser(), page, [CONTENT_NAME]);

      assert.deepEqual(calls, ["preflight", "prepare", "preflight", "prepare"]);

      calls.length = 0;
      prepared.length = 0;

      const failedOver = await actorWorld({ fallback: true });
      failedOver.network.offline(PRIMARY_UNLOCK);
      failedOver.network.offline(PRIMARY_HEALTH);
      await readArticle(failedOver.makeBrowser(), await failedOver.render("A"), [CONTENT_NAME]);

      assert.deepEqual(
        calls,
        ["preflight", "prepare"],
        "the fallback preflights before preparing its response",
      );
      assert.deepEqual(
        Object.keys(periodKeyMap(prepared[0].keys.periodKeys)[ACCESS_GROUP]),
        [T_NOW],
        "prepare receives the fallback-trimmed body, never the future period",
      );
    } finally {
      KeyDelivery.prototype.preflight = originalPreflight;
      KeyDelivery.prototype.prepare = originalPrepare;
    }
  });
});

describe("What refuses itself", () => {
  test("the transport knobs refuse what they do not do", async () => {
    const { clock, network, random, publisherRegistrations } = await actorWorld();
    let urls = 0;
    /**
     * @param {object} extra
     */
    const stand = (extra) =>
      new IssuerServer({
        clock,
        network,
        issuerName: PRIMARY,
        unlockUrl: `https://issuer-${++urls}.example.com/unlock`,
        keyStore: { get: () => undefined },
        publisherRegistrations,
        accessPolicy: new AllowAllPolicy(),
        ...extra,
      });

    // A mode this server does not have, a pinned mode beside a policy that
    // would decide one, and client-bound with nothing to draw a nonce from.
    assert.throws(
      () => stand({ transportMode: "sealed-envelope" }),
      (/** @type {any} */ e) => e.code === "unsupported_option",
    );
    assert.throws(
      () =>
        stand({ transportMode: "direct", transportPolicy: { modeFor: () => "direct" }, random }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => stand({ transportPolicy: { decide: () => "direct" }, random }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => stand({ transportMode: "client-bound" }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => stand({ transportPolicy: { modeFor: () => "direct" } }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => stand({ transportMode: "client-bound", clientBoundProfile: ecdhProfile }),
      (/** @type {any} */ e) =>
        e.code === "bad_config" && /needs an injected Random$/.test(e.message),
      "ECDH declares its Random requirement at construction",
    );
    assert.doesNotThrow(
      () => stand({ transportMode: "client-bound", clientBoundProfile: rsaProfile }),
      "RSA-OAEP needs no injected Random",
    );
    for (const RANDOM_REQUIRED of [undefined, "yes"]) {
      assert.throws(
        () =>
          stand({
            transportMode: "client-bound",
            clientBoundProfile: {
              METHOD: "malformed-random-declaration",
              RANDOM_REQUIRED,
              seal: async () => ({}),
            },
          }),
        (/** @type {any} */ e) =>
          e.code === "bad_config" && /boolean RANDOM_REQUIRED/.test(e.message),
      );
    }

    // And a policy that answers with something that is not a mode is a server
    // fault, not a quiet direct.
    const other = await actorWorld({
      transportPolicy: { modeFor: () => "whatever" },
      clientBoundProfile: ecdhProfile,
    });
    const wire = wiretap(other.network);
    const reader = await boundBrowser(other, { network: wire });
    const read = await readArticle(reader, await other.render("A"), [CONTENT_NAME]);
    assert.equal(read.unlock.status, 500);
    assert.deepEqual(wire.posted[0].body, {
      error: "bad_transport_policy",
      issuerName: PRIMARY,
    });
  });

  test("the client refuses a keypair it cannot use, and a body it cannot unwrap", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });

    // Every refusal is bad_config, so what tells them apart is what each one
    // says. The private half is read first, so reaching a word about the public
    // half at all takes a private key that is one.
    //
    // The public half goes on the wire, so it is handed over in its wire form -
    // exported once, when the pair was made. A `CryptoKey` here would have to be
    // exported inside `buildRequest`, which is synchronous and stays that way.
    const pair = /** @type {CryptoKeyPair} */ (
      await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
    );
    const keyRefusals = /** @type {[any, RegExp][]} */ ([
      [null, /exported JWK$/],
      ["x", /exported JWK$/],
      [{}, /this privateKey is not a private key$/],
      [{ privateKey: 1 }, /this privateKey is not a private key$/],
      [
        { privateKey: pair.privateKey, publicKey: pair.publicKey },
        /buildRequest cannot await one$/,
      ],
      [{ privateKey: pair.privateKey, publicKey: {} }, /this publicKey is not a JWK$/],
      [{ privateKey: pair.privateKey, publicKey: "x" }, /this publicKey is not a JWK$/],
    ]);
    for (const [keys, says] of keyRefusals) {
      await refuses(
        () => clientBoundKeyCapability(keys, ecdhProfile),
        { code: "bad_config", message: says },
        `clientKeys refused with ${says}`,
      );
    }

    const wire = wiretap(stage.network);
    const browser = await boundBrowser(stage, { network: wire });
    const read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);
    const { body } = wire.posted[0];

    // A client with no keypair cannot read a client-bound body, and says so
    // rather than filing something unusable in its cache. Both of these take
    // a client of their own: an answer arriving at a client it was not
    // wrapped for is not a step a page load has.
    const plain = new Client({
      publisherOrigin: PUBLISHER_ORIGIN,
      cache: /** @type {any} */ (new PeriodKeyCache()),
    });
    await refuses(
      () => plain.applyResponse(read.load.dcaData, PRIMARY, body, wire.posted[0].request),
      "bad_response",
      "a wrapped body on a client with no keypair",
    );

    // A client-bound body with no transport key to agree against is a local
    // response miss: a PageLoad can continue to another issuer, while the
    // low-level capability still keeps its typed refusal.
    const bound = new Client({
      publisherOrigin: PUBLISHER_ORIGIN,
      cache: /** @type {any} */ (new PeriodKeyCache()),
      clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
    });
    assert.deepEqual(
      await bound.applyResponse(
        read.load.dcaData,
        PRIMARY,
        { keys: body.keys },
        wire.posted[0].request,
      ),
      { accepted: 0, errors: [], issues: [{ section: "response", code: "invalid_transport" }] },
    );

    // Transport describes this endpoint's agreed representation even when
    // policy delivers no key entry. The family report remains authoritative.
    assert.deepEqual(
      await bound.applyResponse(
        read.load.dcaData,
        PRIMARY,
        {
          transport: body.transport,
          keys: {},
          notDelivered: [{ accessGroup: "premium", reason: "denied" }],
        },
        wire.posted[0].request,
      ),
      {
        accepted: 0,
        errors: [],
        issues: [],
        notDelivered: [{ accessGroup: "premium", reason: "denied" }],
      },
    );
  });

  test("a storage-backed cache uses an opaque handle for first use without persisting it", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });

    // A string store cannot persist a CryptoKey. The response-private lease
    // still lets this obtaining operation open the current article without
    // exporting the handle or pretending it was filed for later reads.
    const storage = new Storage();
    const browser = stage.makeBrowser({
      storage,
      clientBoundKeyCapability: clientBoundKeyCapability(await clientKeys(), ecdhProfile),
    });
    const page = await stage.render("A");

    const read = await readArticle(browser, page, [CONTENT_NAME]);
    assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(read.errors[CONTENT_NAME], null);
    assert.equal(storage.stats().sets, 0, "the opaque capability was not persisted as a string");
  });

  test("the current period is what a fallback trims to, whatever the primary was doing", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
      fallback: true,
    });

    stage.network.offline(PRIMARY_UNLOCK);
    stage.network.offline(PRIMARY_HEALTH);

    const wire = wiretap(stage.network);
    const browser = await boundBrowser(stage, { network: wire });
    const read = await readArticle(browser, await stage.render("A"), [CONTENT_NAME]);

    assert.equal(read.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(read.unlock.issuerName, FALLBACK);
    assert.deepEqual(
      Object.keys(periodKeyMap(wire.posted.at(-1).body.keys.periodKeys)[ACCESS_GROUP]).sort(),
      [formatT(stage.clock.now())],
    );
    assert.equal(stage.servers.fallback.stats().transportMode, "direct");
  });

  test("two issuers on two modes answer the same page, and the client keeps both kinds", async () => {
    const stage = await actorWorld({
      transportMode: "client-bound",
      clientBoundProfile: ecdhProfile,
    });
    await stage.standUp(SECOND_ISSUER, SECOND_UNLOCK);

    const page = await stage.render("A");

    const boundWire = wiretap(stage.network);
    const directWire = wiretap(stage.network);
    const bound = await boundBrowser(stage, { network: boundWire });
    // A client with no keypair is configured to ask the issuer that hands bytes
    // over; the client-bound one has nothing it could answer it with.
    const direct = stage.makeBrowser({
      network: directWire,
      issuers: [{ issuerName: SECOND_ISSUER, unlockUrl: SECOND_UNLOCK }],
    });

    const boundRead = await readArticle(bound, page, [CONTENT_NAME]);
    const directRead = await readArticle(direct, page, [CONTENT_NAME]);

    assert.equal(boundRead.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(directRead.texts[CONTENT_NAME], ARTICLES.A);
    assert.equal(Object.hasOwn(boundWire.posted[0].body.transport, "mode"), false);
    assert.equal(directWire.posted[0].body.transport, undefined);

    const [held] = await bound.cache.entries();
    const [plain] = await direct.cache.entries();
    assert.ok(!(held.key instanceof Uint8Array));
    assert.ok(plain.key instanceof Uint8Array);
    assert.equal(held.t, plain.t, "the same period, two ways of holding it");
  });
});

describe("The view-isolation seam, from the reject side", () => {
  // KeyDelivery keeps the agreed wrapping key in a per-instance WeakMap keyed
  // by the view it handed out, so only the view it handed out reaches that
  // view's transport. These drive the delivery directly, at the seam, because
  // the reject side is the thing an end-to-end run does not walk.

  // A random that satisfies the constructor and is never drawn from: the bodies
  // below carry no key to wrap, so the guard and the lookup are what is proven,
  // not the wrap. `new Uint8Array(n)` so a draw, were one to happen, is legal.
  const okRandom = { bytes: (/** @type {number} */ n) => new Uint8Array(n) };

  /**
   * A request carrying a real P-256 client public key, the shape `preflight`
   * agrees a client-bound transport against.
   *
   * @returns {Promise<DcaRequest>}
   */
  async function boundRequest() {
    const { publicKey } = await clientKeys();
    return DcaRequest.fromParts({
      version: "0.10",
      issuerName: PRIMARY,
      resource: { domain: "issuer.example.com" },
      contentKeys: [],
      clientPublicKey: publicKey,
    });
  }

  test("a view this KeyDelivery did not agree is refused, not silently wrapped", async () => {
    const request = await boundRequest();

    // Two deliveries, each with its own WeakMap. The view mine agreed is a
    // genuine view: it prepares against mine and comes back client-bound.
    const mine = new KeyDelivery({ random: okRandom, profile: ecdhProfile });
    const theirs = new KeyDelivery({ random: okRandom, profile: ecdhProfile });
    const view = await mine.preflight("client-bound", request);

    const wrapped = await mine.prepare({ keys: {} }, view);
    assert.equal(
      Object.hasOwn(wrapped.transport, "mode"),
      false,
      "the view is a real one, agreed by mine",
    );

    // The same real view handed to the other delivery: its map has no entry
    // for it, so it refuses rather than reaching for a transport it never
    // agreed. That is what the WeakMap isolates, seen from where a body-forging
    // browser would come at it.
    await refuses(
      () => theirs.prepare({ keys: {} }, view),
      { code: "bad_config", message: /was not agreed by this KeyDelivery$/ },
      "a view agreed by another KeyDelivery, on this one",
    );
  });

  test("a client-bound view object this KeyDelivery never made is refused", async () => {
    const delivery = new KeyDelivery({ random: okRandom, profile: ecdhProfile });

    // A forged view: a plain object wearing the mode, not the RequestView the
    // seam hands out (the class is not exported, so this is all a caller can
    // hold). The instanceof gate turns it away before any transport lookup.
    await refuses(
      () => delivery.prepare({ keys: {} }, { mode: "client-bound", isDirect: () => false }),
      { code: "bad_config", message: /takes the view preflight returned$/ },
      "a hand-made object standing in for a view",
    );

    // And a missing view is the same refusal, not a pass-through.
    await refuses(
      () => delivery.prepare({ keys: {} }, undefined),
      { code: "bad_config", message: /takes the view preflight returned$/ },
      "no view at all",
    );
  });

  test("the client-bound path refuses a KeyDelivery given no usable Random", async () => {
    // The constructor turns away a random that is not one, before any request
    // reaches it: a client-bound delivery with no way to draw a nonce is a
    // misconfiguration, named at construction.
    for (const random of [{}, "x", { bytes: 42 }, { bytes: null }]) {
      await refuses(
        () => new KeyDelivery({ random: /** @type {any} */ (random), profile: ecdhProfile }),
        { code: "bad_config", message: /bytes\(n\)$/ },
        `random ${JSON.stringify(random)}`,
      );
    }

    // And a delivery built with no random at all refuses at preflight on the
    // client-bound path: the sealer draws its nonces from the Random, so it
    // is refused before a view is even agreed, and it never hands the bytes
    // over unwrapped.
    const noRandom = new KeyDelivery({ profile: ecdhProfile });
    const request = await boundRequest();
    await refuses(
      () => noRandom.preflight("client-bound", request),
      { code: "bad_config", message: /needs a Random$/ },
      "a client-bound preflight with no Random to draw nonces from",
    );
  });
});

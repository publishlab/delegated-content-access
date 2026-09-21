//
// What a rotation does to markup an edge cache is still serving. Three keys
// rotate on three independent schedules - the issuer's keypair, the
// publisher's signing key and the publisher's exact period-key supply - and
// none of them is coordinated with the moment a page falls out of a CDN.
//
// The whole axis is one claim: a rotation is an operational event and never an
// integrity one. The keyId on a request has three answers, and they live here
// together. A keyId the issuer holds is opened with the key filed at it, and a
// key that turns out to open nothing is a per-item unseal failure beside a 200.
// A keyId it has let go is 200 with a per-item `key_retired` on every
// coordinate the request carried, because the envelope verifies and the only
// thing wrong is that the private key is gone. A keyId this issuer never held
// is the third answer - a request routed somewhere it does not belong - and is
// answered with a whole-request 400, nothing reported per item.
//
// This settles the choice for an unknown or retired keyId: 200-with-errors
// versus whole-request refusal. seal-unseal-decrypt.test.js and
// transport.test.js read as disagreeing, but they
// were answering different questions - an unknown keyId against a wrong key at
// a known one - and both of their keyId tests now sit below. Retirement is
// something an issuer says out loud, `IssuerServer.retireKey`, rather than a
// keyId going quiet, which is what keeps the retired case and the never-held
// case apart at the store.
//
// The publisher's signing key belongs to jwt-proof.test.js ('markup signed
// before a signing-key rotation still verifies, selected by kid'), and so
// does the unsupported version; neither is repeated here. What is here is the
// crossing: all three rotating at once, over one render that predates them.
//
// Pinned: one issuer, direct transport, no access policy, one accessGroup, one
// content item, ECDH P-256.

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { IssuerKeyStore } from "../demo/support/IssuerKeyStore.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";
import { open } from "../core-shared--publisher-issuer/keySealing.js";
import { exactPeriodKeySupply } from "../demo/support/exactPeriodKeySupply.js";
import { decodeHeader } from "../core-shared--publisher-issuer/jwt.js";
import { utf8Decode } from "../core-shared/codec.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  ARTICLES,
  CONTENT_NAME,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
  article,
} from "../demo/scenarios/fixtures.js";
import { actorWorld, readArticle } from "../demo/scenarios/world.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { held, issuerPeriodsOn } from "../test-lib/helpers/inspect.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { issuerKeypair } from "../test-reference/support/keys.js";
import { refuses } from "../test-lib/helpers/refuses.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";

/**
 * The other side of each rotation. `fixtures` names one coordinate per axis
 * because one is what a story that does not rotate needs; a rotation is two, and
 * the second one is this file's subject rather than the suite's.
 */
const KEY_NEW = "2025-11";
const KID_NEW = "sign-2025-11";

/** A keyId this issuer has never held - a request that came to the wrong door. */
const KEY_NEVER = "2019-01";

const PUBLISHER_ORIGIN = `https://${DOMAIN}`;

/**
 * A client that reads one page and hands the wire answer back beside the
 * plaintext, so a test can assert the status an article came through rather than
 * only whether it opened.
 *
 * `demo/scenarios/readArticle` is the shared form and does not reach this far: it
 * reads through a `Browser`, which has no way to swap the keyId on an outgoing
 * request and hands back the client's own view rather than the issuer's answer
 * body, so a 400 or a named per-item error is out of its reach. Tests that need
 * either of those read through here; the one that needs neither reads through
 * `readArticle` like the rest of the suite.
 *
 * @param {any} network
 * @returns {(unsealer: Client, page: any, tamper?: { keyId?: string })
 *   => Promise<{ missing: string[], answer: any, text: string|null }>}
 */
function readerOn(network) {
  return async (unsealer, page, tamper = {}) => {
    const dcaData = unsealer.parse(page);
    const { missing } = await unsealer.resolve(dcaData, [CONTENT_NAME]);

    let answer = null;
    if (missing.length > 0) {
      const request = unsealer.buildRequest(dcaData, ISSUER_NAME, missing);
      // Nothing signs the keyId and nothing proves it, which is what makes
      // a swapped one a misrouted request rather than a forgery.
      if (tamper.keyId !== undefined) request.keyId = tamper.keyId;
      answer = await network.post(UNLOCK_URL, request, { origin: PUBLISHER_ORIGIN });
      if (answer.status === 200) await unsealer.applyResponse(dcaData, ISSUER_NAME, answer.body);
    }

    let text = null;
    try {
      text = utf8Decode(
        await unsealer.decrypt(dcaData, CONTENT_NAME, unsealer.extract(page, CONTENT_NAME)),
      );
    } catch {
      text = null;
    }

    return { missing, answer, text };
  };
}

describe("the issuer's own keypair", () => {
  test("an issuer holds both keyIds through the rollover, and either markup opens", async () => {
    const { network, publisher, servers, keyStores } = await actorWorld();
    const read = readerOn(network);
    const rotated = await issuerKeypair();

    // Sealed for the key the publisher had at the time, and still on a CDN
    // when the issuer rotates. The new keypair arrives beside the old one
    // rather than over it: an issuer that dropped the old private key at the
    // moment it generated a new one would break every page already out there.
    const cached = (await publisher.render(article("A"))).asJson();
    servers.primary.rotateKey(KEY_NEW, {
      algorithm: ALGORITHM,
      privateKey: rotated.privateKey,
    });
    publisher.rotateIssuerKey(ISSUER_NAME, KEY_NEW, rotated.publicKey);
    const fresh = (await publisher.render(article("B"))).asJson();

    assert.equal(cached.issuerData[ISSUER_NAME].keyId, KEY_ID);
    assert.equal(fresh.issuerData[ISSUER_NAME].keyId, KEY_NEW);

    // The fresh page first, so nothing about the pass below can be the old
    // key simply being the only one anybody reached for.
    const afterRotation = await read(new Client({ publisherOrigin: PUBLISHER_ORIGIN }), fresh);
    assert.equal(afterRotation.answer.status, 200);
    assert.equal(afterRotation.text, ARTICLES.B);

    const beforeRotation = await read(new Client({ publisherOrigin: PUBLISHER_ORIGIN }), cached);
    assert.equal(beforeRotation.answer.status, 200);
    assert.equal(
      beforeRotation.answer.body.errors,
      undefined,
      "the rollover is not an error for anyone",
    );
    assert.equal(beforeRotation.text, ARTICLES.A);

    // Both keyIds now have one owner, so both reads reach the same store.
    assert.equal(
      keyStores.primary.reachCount,
      2,
      "the store answered both the old and newly rotated keyIds",
    );
    assert.equal(servers.primary.stats().grants, 2);
    assert.equal(servers.primary.stats().unsealFailures, 0);

    // Two real keypairs, so neither pass above was one key answering for
    // both: the old private key makes nothing of a blob sealed to the new
    // public one.
    const oldPrivateKey = keyStores.primary.privateKeyOf(ISSUER_NAME, KEY_ID);
    const freshBlob = fresh.issuerData[ISSUER_NAME].sealed.contentKeys[CONTENT_NAME];
    await refuses(
      () =>
        open(freshBlob, oldPrivateKey, ALGORITHM, {
          binding: { renderId: fresh.resource.renderId, contentName: CONTENT_NAME },
        }),
      "unseal_failed",
      "the old private key opens nothing sealed to the new public one",
    );
  });

  test("a key rotated through the server is resolved by its store, and a wrong one is 200-with-errors", async () => {
    const { browser, servers, render } = await actorWorld();
    const other = await globalThis.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );

    // The rotation lands on the keyId the page names, so the request arrives
    // verified and whole and the blobs will not open under it. That is an
    // operational failure, not an integrity one: 200 with per-item errors, and
    // the client is told nothing about the issuer's key management.
    servers.primary.rotateKey(KEY_ID, { algorithm: ALGORITHM, privateKey: other.privateKey });

    const locked = await readArticle(browser, await render("A"), [CONTENT_NAME]);
    assert.equal(locked.unlock.status, 200);
    assert.equal(locked.texts[CONTENT_NAME], null);
    assert.equal(locked.errors[CONTENT_NAME], "no_key");
    assert.ok(servers.primary.stats().unsealFailures > 0);
    assert.equal(servers.primary.stats().grants, 0, "nothing was handed over");

    assert.throws(
      () => servers.primary.rotateKey(KEY_ID, /** @type {any} */ ({})),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
  });

  test("a retired keyId is 200-with-errors", async () => {
    const { network, publisher, servers } = await actorWorld();
    const read = readerOn(network);
    const cached = (await publisher.render(article("A"))).asJson();

    // The cached markup outlived the private key. Everything about the
    // request is intact - the envelope verifies and every blob is bound to
    // the render it arrived with - and the one thing the issuer cannot do is
    // open it. That is an operational failure, so it is per-item and the
    // request as a whole succeeded.
    servers.primary.retireKey(KEY_ID);

    const retired = await read(new Client({ publisherOrigin: PUBLISHER_ORIGIN }), cached);
    assert.equal(retired.answer.status, 200);
    assert.equal(retired.answer.body.error, undefined, "not a whole-request refusal");
    assert.deepEqual(retired.answer.body.keys.contentKeys, {});
    assert.equal(retired.answer.body.keys.periodKeys, undefined);
    assert.equal(retired.text, null);

    // Every coordinate the request carried is reported, contentKeys by name
    // and periodKeys under the `accessGroup|t` pair the engine already
    // reports an unseal failure at.
    assert.deepEqual(
      Object.keys(retired.answer.body.errors).sort(),
      [CONTENT_NAME, ...issuerPeriodsOn(cached).map((t) => `${ACCESS_GROUP}|${t}`)].sort(),
    );
    for (const entry of Object.values(retired.answer.body.errors)) {
      assert.equal(/** @type {any} */ (entry).error, "key_retired");
    }

    assert.equal(servers.primary.stats().grants, 0, "nothing was handed over");
    assert.equal(
      servers.primary.stats().unsealFailures,
      Object.keys(retired.answer.body.errors).length,
    );
  });

  test("an unknown keyId is a whole-request refusal, not a per-item error", async () => {
    const { network, publisher, publisherRegistration, servers } = await actorWorld();
    const read = readerOn(network);
    const cached = (await publisher.render(article("A"))).asJson();

    // The other case, and the reason it is not the answer above: a keyId
    // this issuer has never held is a request that arrived at the wrong
    // door. There is nothing to report per item, because no key of this
    // issuer's was ever meant to open these blobs.
    const stranger = await read(new Client({ publisherOrigin: PUBLISHER_ORIGIN }), cached, {
      keyId: KEY_NEVER,
    });
    assert.equal(stranger.answer.status, 400);
    assert.equal(stranger.answer.body.error, "unknown_key");
    assert.equal(stranger.answer.body.keys, undefined);
    assert.equal(servers.primary.stats().grants, 0, "nothing was handed over");

    // The same answer arrived at from the other side: the keyId the page
    // names, unchanged, against an issuer whose store holds nothing at all.
    // What the store says is `undefined` either way, and `undefined` is the
    // whole of what the refusal reads.
    const emptyProcessor = new IssuerProcessor(
      new IssuerEngine({ accessPolicy: new AllowAllPolicy() }),
    );
    const empty = new UnlockEndpoint(emptyProcessor);
    const { status, body } = await unlockThroughAdmission(
      emptyProcessor,
      empty,
      requestFor(cached),
      {
        ...publisherRegistration,
        openingKeys: new IssuerKeyStore(),
      },
    );

    assert.equal(status, 400);
    assert.equal(body.error, "unknown_key");

    // Retiring is something the issuer says about a key it holds. A keyId it
    // cannot resolve is a wiring mistake, refused where it is made.
    assert.throws(
      () => servers.primary.retireKey(KEY_NEVER),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
  });

  test("serving can use a read-only key store, but key lifecycle changes cannot", async () => {
    const readOnly = { get: () => undefined };
    const { servers } = await actorWorld({ primary: { keyStore: readOnly } });
    const pair = await issuerKeypair();

    assert.throws(
      () =>
        servers.primary.rotateKey(KEY_NEW, { algorithm: ALGORITHM, privateKey: pair.privateKey }),
      (/** @type {any} */ err) => err.code === "bad_config" && err.message.includes("rotate"),
    );
    assert.throws(
      () => servers.primary.retireKey(KEY_ID),
      (/** @type {any} */ err) => err.code === "bad_config" && err.message.includes("retire"),
    );
  });

  test("a store entry that is neither a key nor a retirement is a server fault", async () => {
    const { publisher, publisherRegistration } = await actorWorld();
    const page = (await publisher.render(article("A"))).asJson();
    const request = requestFor(page);

    // A verified request, so the store is genuinely reached. An entry
    // claiming both at once, or neither, has not said which of the three
    // things it means, and reading it as either would let a misconfigured
    // deployment pass for a rollover.
    //
    // Store-less on purpose: `IssuerKeyStore` refuses both of these shapes
    // where they are written, so the engine's own refusal is only reachable
    // through a plain object with a `get`.
    const cases = [
      [{ algorithm: ALGORITHM }, "an entry with no privateKey and no retirement"],
      [{ algorithm: ALGORITHM, retired: true, privateKey: {} }, "an entry both held and retired"],
    ];

    for (const [entry, what] of cases) {
      const endpointProcessor = new IssuerProcessor(
        new IssuerEngine({ accessPolicy: new AllowAllPolicy() }),
      );
      const endpoint = new UnlockEndpoint(endpointProcessor);
      const { status, body } = await unlockThroughAdmission(endpointProcessor, endpoint, request, {
        ...publisherRegistration,
        openingKeys: { get: () => entry },
      });

      // A config-class engine throw is re-coded to `internal_error` at the
      // request boundary, so `bad_config` never crosses back as a returned
      // result. It is still a 500: the STATUS map has no `internal_error`
      // and falls closed to a server fault.
      assert.equal(status, 500, what);
      assert.equal(body.error, "internal_error", what);
      assert.equal(body.keys, undefined, what);
    }

    // And the boundary the rule sits on: the claim lives in the field rather
    // than in the value behind it. A store that says it holds a key and hands
    // over one that opens nothing has answered and been wrong, which is the per-item
    // unseal failure and not a fault of the deployment's shape.
    //
    // A real store rather than a literal, because the two readings produce
    // the same wire: the engine absorbs an unseal failure into a per-item
    // error beside a 200, so an empty `contentKeys` says nothing about
    // whether anything was consulted. The reach count is what says it.
    const opensNothing = new IssuerKeyStore([
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        privateKey: /** @type {any} */ (null),
      },
    ]);
    const wrongProcessor = new IssuerProcessor(
      new IssuerEngine({ accessPolicy: new AllowAllPolicy() }),
    );
    const wrong = new UnlockEndpoint(wrongProcessor);
    const { status, body } = await unlockThroughAdmission(wrongProcessor, wrong, request, {
      ...publisherRegistration,
      openingKeys: opensNothing,
    });

    assert.equal(status, 200);
    assert.deepEqual(body.keys.contentKeys, {});
    assert.equal(body.errors[CONTENT_NAME].error, "unseal_failed");
    assert.equal(opensNothing.reachCount, 1, "the store answered rather than went unreached");
  });
});

describe("the publisher's exact period-key supply", () => {
  test("an exact period-key supply rotation is a trial-unwrap miss for the new render, and the old render stays open beside it", async () => {
    const { network, publisher, servers } = await actorWorld();
    const read = readerOn(network);

    const cache = new PeriodKeyCache();
    const unsealer = new Client({ cache, publisherOrigin: PUBLISHER_ORIGIN });

    // One article, one unlock, and the client keeps the period family.
    const before = (await publisher.render(article("A"))).asJson();
    const first = await read(unsealer, before);
    assert.equal(first.text, ARTICLES.A);
    assert.deepEqual(first.missing, [CONTENT_NAME]);
    assert.equal((await held(cache)).length, 2, "the current period and the forward overlap");

    // The publisher rotates its exact-key supply inside the same period.
    // Nothing about the wire changes - the same coordinates, the same
    // shape, the same labels - and only the bytes behind them do.
    publisher.rotatePeriodKeySupply(exactPeriodKeySupply());
    const after = (await publisher.render(article("B"))).asJson();
    assert.deepEqual(
      issuerPeriodsOn(after),
      issuerPeriodsOn(before),
      "the same periods, relabelled by nothing",
    );
    assert.notDeepEqual(
      after.issuerData[ISSUER_NAME].sealed.periodKeys[ACCESS_GROUP],
      before.issuerData[ISSUER_NAME].sealed.periodKeys[ACCESS_GROUP],
    );

    const attempts = network.stats()[UNLOCK_URL].attempts;
    const second = await read(unsealer, after);

    // The held keys no longer open anything, and that is the entire visible
    // effect: a miss, one more unlock, no error at either end.
    assert.deepEqual(second.missing, [CONTENT_NAME], "the trial unwrap missed");
    assert.equal(
      network.stats()[UNLOCK_URL].attempts,
      attempts + 1,
      "and the miss re-entered unlock",
    );
    assert.equal(second.answer.status, 200);
    assert.equal(second.answer.body.errors, undefined);
    assert.equal(second.text, ARTICLES.B);
    assert.equal(servers.primary.stats().unsealFailures, 0);

    // The rotated keys landed on the coordinates the old ones held, and
    // coexist there rather than overwriting: each of the two periods now
    // holds both its old key and its new one, two candidates to a coordinate.
    assert.equal(
      (await held(cache)).length,
      4,
      "the old and the new key at each of the two periods",
    );
    assert.deepEqual(
      [...new Set(await held(cache))].reverse(),
      issuerPeriodsOn(after),
      "the same two periods, each holding a key from before the rotation and one from after",
    );

    // And the payoff of coexistence, stated rather than implied: the article
    // from before the rotation still opens out of the cache. Its key was not
    // thrown away to make room for the new family, so a fresh load of it costs
    // no unlock - only the render sealed under the new key had to ask.
    const attemptsAfter = network.stats()[UNLOCK_URL].attempts;
    const rereader = new Client({ cache, publisherOrigin: PUBLISHER_ORIGIN });
    assert.deepEqual(
      (await rereader.resolve(rereader.parse(before), [CONTENT_NAME])).missing,
      [],
      "the pre-rotation article still opens from the cache",
    );
    const reread = await read(rereader, before);
    assert.equal(reread.text, ARTICLES.A, "and it opens without a second unlock");
    assert.equal(
      network.stats()[UNLOCK_URL].attempts,
      attemptsAfter,
      "the coexisting old key cost no round trip",
    );
  });
});

describe("all three at once", () => {
  test("the three rotation axes are independent, and one render predating all of them opens", async () => {
    // Both kids on the publisher's domain, each with a keypair of its own:
    // the publisher holds both private halves and the issuer resolves both
    // public ones, which is what markup signed either side of the rotation
    // needs of it.
    const { network, publisher, servers } = await actorWorld({
      signingKids: { [DOMAIN]: [SIGNING_KID, KID_NEW] },
    });
    const read = readerOn(network);

    // Rendered under every old key there is, then all three rotate: the
    // issuer's keypair, the publisher's signing key, and the exact period-key supply.
    const cached = (await publisher.render(article("A"))).asJson();

    const rotatedIssuer = await issuerKeypair();
    servers.primary.rotateKey(KEY_NEW, {
      algorithm: ALGORITHM,
      privateKey: rotatedIssuer.privateKey,
    });
    publisher.rotateIssuerKey(ISSUER_NAME, KEY_NEW, rotatedIssuer.publicKey);
    publisher.rotateSigningKey(KID_NEW);
    publisher.rotatePeriodKeySupply(exactPeriodKeySupply());
    const fresh = (await publisher.render(article("B"))).asJson();

    // Nothing about the three is bundled: the fresh page names the new key
    // on the two axes a page carries in the open, and the cached one names
    // the old.
    //
    // Sealing is randomised, so two renders never carry the same blob bytes
    // and comparing them would say nothing about the exact period-key
    // supply. Each axis is pinned where it is actually visible instead: the keyId on the wire,
    // the `kid` in the header the issuer selects the signing key by, and -
    // below - the exact period-key supply in the only place it shows at all,
    // a client holding one render's period keys and finding they do not open the
    // other's.
    assert.equal(cached.issuerData[ISSUER_NAME].keyId, KEY_ID);
    assert.equal(fresh.issuerData[ISSUER_NAME].keyId, KEY_NEW);
    assert.equal(decodeHeader(cached.resourceJWT).kid, SIGNING_KID);
    assert.equal(decodeHeader(fresh.resourceJWT).kid, KID_NEW);

    // One cache across both reads. Two real signing keys and two real
    // keypairs mean a 200 here is the issuer selecting by `kid` and by keyId
    // rather than holding one of each; the second miss is the exact
    // period-key supply.
    const cache = new PeriodKeyCache();

    for (const [page, text] of [
      [cached, ARTICLES.A],
      [fresh, ARTICLES.B],
    ]) {
      const answer = await read(new Client({ cache, publisherOrigin: PUBLISHER_ORIGIN }), page);
      assert.deepEqual(
        answer.missing,
        [CONTENT_NAME],
        `${text} - the held period keys do not open it`,
      );
      assert.equal(answer.answer.status, 200, text);
      assert.equal(answer.answer.body.errors, undefined, text);
      assert.equal(answer.text, text);
    }

    assert.equal(servers.primary.stats().grants, 2);
    assert.equal(servers.primary.stats().denials, 0);
    assert.equal(servers.primary.stats().unsealFailures, 0);
  });
});

/**
 * The interleaving seam, the same shape `storage-concurrency.test.js` uses to
 * stop one actor mid-operation while another runs to completion. Nothing here is
 * timed: `arrive` is what the suspended unlock awaits, `reached` resolves once it
 * has actually reached the gate, and `release` is what lets it go on. A
 * `setTimeout` in any of the three would make the order a guess.
 *
 * @returns {{ arrive: () => Promise<void>, reached: () => Promise<void>, release: () => void }}
 */
function decideGate() {
  /** @type {null|(() => void)} */
  let release = null;
  /** @type {null|(() => void)} */
  let announce = null;

  return {
    arrive() {
      return new Promise((resolve) => {
        release = resolve;
        announce?.();
      });
    },
    reached() {
      return new Promise((resolve) => {
        announce = () => resolve();
      });
    },
    release() {
      release?.();
      release = null;
    },
  };
}

/**
 * An access policy that grants exactly what `AllowAllPolicy` does, and suspends
 * at the gate on its way there. `IssuerEngine` awaits the access decision after
 * it has verified the envelope and before it reads the private key, so a policy
 * that waits here holds the whole request in flight at the one point a rotation
 * can still change what the store answers.
 *
 * @param {{ arrive: () => Promise<void> }} gate
 * @returns {{ decide: (claims: any, requested: any, input: any) => Promise<any> }}
 */
function gateOnDecide(gate) {
  const inner = new AllowAllPolicy();
  return {
    async decide(claims, requested, input) {
      await gate.arrive();
      return inner.decide(claims, requested, input);
    },
  };
}

describe("a rotation that lands while a request is in flight", () => {
  test("a keyId retired mid-flight is the retired answer, read at unseal time and not at admission", async () => {
    const gate = decideGate();
    const { servers, keyStores, publisher, publisherRegistration } = await actorWorld({
      primary: { accessPolicy: gateOnDecide(gate) },
    });

    // Rendered and structurally admitted while the issuer still holds the
    // key. Admission is the request accepted for processing; it touches no
    // private key, which is the reachCount below.
    const cached = (await publisher.render(article("A"))).asJson();
    const admission = servers.primary.processor.admit(new DcaRequest(requestFor(cached)));
    assert.equal(admission.kind, "admitted", "admitted under the held key");
    assert.equal(keyStores.primary.reachCount, 0, "admission read no private key");

    // The unlock runs into the access-decision await and suspends there:
    // past the envelope verification, before the private key is read.
    const reached = gate.reached();
    const pending = servers.primary.endpoint.handleRequest({
      request: admission.request,
      registration: publisherRegistration,
    });
    await reached;
    assert.equal(keyStores.primary.reachCount, 0, "the private key has not been read yet");

    // The rotation lands while the request is suspended in flight. The store
    // the still-pending unlock will read is the store this retirement leaves.
    servers.primary.retireKey(KEY_ID);

    gate.release();
    const { status, body } = (await pending).response;

    // The store is read after the retirement, so the request admitted under
    // a held key is answered the one way a retired key is ever answered: 200,
    // the private key gone, every coordinate the request carried reported as
    // a typed `key_retired`. A request that admitted clean never becomes an
    // untyped failure because a rotation crossed it. This is the same wire
    // the sequential retired case above asserts, reached here by a rotation
    // that landed after admission rather than before the request was built.
    assert.equal(status, 200, "a rollover is operational, not a whole-request refusal");
    assert.equal(body.error, undefined, "not a whole-request refusal");
    assert.deepEqual(body.keys.contentKeys, {});
    assert.equal(body.keys.periodKeys, undefined);
    assert.deepEqual(
      Object.keys(body.errors).sort(),
      [CONTENT_NAME, ...issuerPeriodsOn(cached).map((t) => `${ACCESS_GROUP}|${t}`)].sort(),
    );
    for (const entry of Object.values(body.errors)) {
      assert.equal(/** @type {any} */ (entry).error, "key_retired");
    }
    assert.equal(keyStores.primary.reachCount, 1, "the store answered once, after the rotation");
  });

  test("an additive keypair rotation mid-flight leaves the admitted request opening under its own key", async () => {
    const gate = decideGate();
    const { servers, keyStores, publisher, publisherRegistration } = await actorWorld({
      primary: { accessPolicy: gateOnDecide(gate) },
    });
    const rotated = await issuerKeypair();

    const cached = (await publisher.render(article("A"))).asJson();
    const admission = servers.primary.processor.admit(new DcaRequest(requestFor(cached)));
    assert.equal(admission.kind, "admitted");

    const reached = gate.reached();
    const pending = servers.primary.endpoint.handleRequest({
      request: admission.request,
      registration: publisherRegistration,
    });
    await reached;

    // A new keypair arrives beside the old one, the rollover the issuer's-own-
    // keypair story is about, while the request sits suspended in flight. The
    // rotation adds a coordinate and takes none away, so the keyId the request
    // named is still held when the unseal finally reaches for it.
    servers.primary.rotateKey(KEY_NEW, {
      algorithm: ALGORITHM,
      privateKey: rotated.privateKey,
    });

    gate.release();
    const { status, body } = (await pending).response;

    // The request is answered under the key it was admitted with: 200, no
    // per-item error, the content key delivered. An additive rotation
    // crossing a request in flight is invisible to it.
    assert.equal(status, 200);
    assert.equal(body.errors, undefined, "the coexisting new key is not an error for this request");
    assert.ok(body.keys.contentKeys[CONTENT_NAME], "the admitted key opened its own content");
    assert.equal(keyStores.primary.reachCount, 1, "one read, of the still-held old key");
  });
});

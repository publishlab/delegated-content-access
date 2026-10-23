// @ts-check
//
// Replays the recorded chain-key prefix composition in
// verification/fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix/
// through the real issuer and client. The publisher does not run: each read
// loads recorded markup, and the issuer and client are built from
// `inputs.json` alone. This file does not import the recorder, so a broken
// recorder cannot hide a broken replay.
//
// The story: the issuer returns one chain key at the 14:15 cutoff, every item
// from the 12:00 window start through the cutoff opens from that one key, and
// the items at 14:30, 11:45 and the next day's 00:00 open nothing without a
// new unlock. Each read compares the live request, response, opened text and
// retained keys with the recording, and also asserts the facts in
// `expected.json` directly, so a recording of the wrong story cannot pass by
// being self-consistent. Those facts take the cutoff key and prefix period keys
// from the frozen construction vectors, not from the code under test.
//
// A second test checks the recorded bytes with stock WebCrypto, apart from the
// reference: it builds the Leaf and Step contexts from the specification's
// octet layout, checks one against the frozen witness, walks the recorded
// cutoff key back to the window start, and opens every prefix item to its
// known text. No prefix period key opens an out-of-reach wrap, while the period
// key each of those items was wrapped under does.
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
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { wrapNonceOf } from "../test-reference/support/contentKeyWrapNonceOctets.js";

const DIR = fileURLToPath(
  new URL(
    "../../verification/fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix/",
    import.meta.url,
  ),
);
const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const THIS_FILE = "js/test-vectors/chain-keys-prefix.test.js";
const FORMAT = "chain-keys-prefix/v1";
const ACCESS_GROUP = "premium";

const { subtle } = globalThis.crypto;
const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/** @param {string} name @returns {any} */
const member = (name) => JSON.parse(readFileSync(DIR + name, "utf8"));
const manifest = member("manifest.json");
const inputs = member("inputs.json");
const renders = member("renders.json").renders;
const exchanges = member("exchange.json").exchanges;
const expected = member("expected.json");

/** @param {string} text */
const fromBase64url = (text) => new Uint8Array(Buffer.from(text, "base64url"));

/** @param {Uint8Array} bytes */
const toBase64url = (bytes) => Buffer.from(bytes).toString("base64url");

/** @param {Uint8Array} bytes */
const sha256Hex = async (bytes) =>
  Buffer.from(await subtle.digest("SHA-256", bytes)).toString("hex");

/**
 * The one record of a named collection whose `member` is `name`.
 *
 * @param {any[]} records
 * @param {string} member
 * @param {string} name
 * @returns {any}
 */
function recordNamed(records, member, name) {
  const found = records.filter((record) => record[member] === name);
  assert.equal(found.length, 1, `one record with ${member} ${name}`);
  return found[0];
}

/**
 * The records of one accessGroup in a key collection, in record order.
 *
 * @param {any[]} records
 * @param {string} accessGroup
 * @returns {any[]}
 */
const ofGroup = (records, accessGroup) =>
  records.filter((record) => record.accessGroup === accessGroup);

/** @param {string} t @returns {any} */
const renderAt = (t) => renders.find((/** @type {any} */ render) => render.t === t);

/**
 * The two carriers of one recorded render, read off its markup the way the
 * client's reader finds them.
 *
 * @param {any} render
 * @returns {{ root: any, dcaData: any, sealedContent: { contentName: string, content: string }[] }}
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

/**
 * One Root, Step or Leaf context, laid out as docs/spec-profile--chain-keys.md
 * §6.4 states it: a domain octet, then u16-length-prefixed construction
 * identifier and access group, u16 chainsPerDay and periodMinutes, u32
 * windowStart and u16 position, all big-endian.
 *
 * @param {number} domain - 0x02 Step, 0x03 Leaf
 * @param {number} position
 */
function context(domain, position) {
  const { accessGroup, chainsPerDay, periodMinutes, windowStart } = expected.witness;
  const construction = new TextEncoder().encode("dca-construction-chain-keys");
  const group = new TextEncoder().encode(accessGroup);
  const bytes = new Uint8Array(1 + 2 + construction.length + 2 + group.length + 2 + 2 + 4 + 2);
  const view = new DataView(bytes.buffer);
  let at = 0;
  view.setUint8(at, domain);
  at += 1;
  for (const field of [construction, group]) {
    view.setUint16(at, field.length);
    bytes.set(field, at + 2);
    at += 2 + field.length;
  }
  view.setUint16(at, chainsPerDay);
  view.setUint16(at + 2, periodMinutes);
  view.setUint32(at + 4, windowStart);
  view.setUint16(at + 8, position);
  return bytes;
}

/**
 * HKDF-SHA-256 with an empty salt and a 16-octet output, the one primitive
 * call of §6.3.
 *
 * @param {Uint8Array} ikm
 * @param {Uint8Array} info
 */
async function hkdf16(ikm, info) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    key,
    128,
  );
  return new Uint8Array(bits);
}

/**
 * What the client holds, by coordinate and kind, in the recorder's shape.
 *
 * @param {any} browser
 * @param {any} chainCache
 */
async function retainedBy(browser, chainCache) {
  return {
    chain: chainCache.entries().map((/** @type {any} */ { t, kind }) => ({ t, kind })),
    periodKeys: (await browser.cache.entries()).map((/** @type {any} */ { t }) => ({ t })),
  };
}

test("the package declares its members, and each one carries the bytes the manifest names", async () => {
  assert.equal(manifest.schema, "dca-fixture-package-manifest/v1");
  assert.equal(manifest.stability, "draft");
  assert.equal(manifest.profile, "dca-profile-chain-keys");
  assert.equal(manifest.format, FORMAT);
  const consumer = (/** @type {string} */ role) =>
    manifest.consumers.find((/** @type {any} */ entry) => entry.role === role);
  assert.equal(consumer("replay").path, THIS_FILE);
  assert.equal(
    consumer("recorder self-test").path,
    "js/test-tools/record-chain-keys-prefix.test.js",
  );
  assert.equal(
    consumer("package check").command,
    "node js/tools/record-chain-keys-prefix.js --check",
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
  "the recorded prefix replays: one cutoff key opens the window start through the cutoff and nothing beyond",
  {
    tags: [
      "dca-profile-chain-keys/client/chain-relay",
      "dca-profile-chain-keys/issuer/chain-input",
      "dca-profile-chain-keys/issuer/chain-output",
      "dca-profile-chain-keys/client/chain-derivation",
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
    assert.deepEqual([inputs.issuer.input, inputs.issuer.output], ["chain-keys", "chain-keys"]);
    assert.deepEqual([inputs.client.relay, inputs.client.response], ["chain-keys", "chain-keys"]);

    // One clock for the issuer and the client, which never moves: no read can
    // meet a later grant than the first one.
    const clock = new Clock(inputs.clock.issuerAndClient);
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
          const decision = inputs.issuerDecisions[presented.length - 1];
          // Replay the separately recorded horizon and authorized coordinates.
          return {
            contentNames: [...decision.contentNames],
            periodGrants: decision.periodGrants.map(
              ({ accessGroup, futurePeriodCount, authorizedPeriods }) => ({
                accessGroup,
                futurePeriodCount,
                authorizePeriod: (t) => authorizedPeriods.includes(t),
              }),
            ),
          };
        },
      },
      periodKeyInput: false,
      periodGrantKind: "chain-keys",
      chainKeyProfile: referenceChainKeyProfile,
      role: "primary",
    });

    /** @type {any[]} */
    const live = [];
    let step = 0;
    const chainCache = new ChainKeyCache({ strategy: inputs.client.chainRetention });
    const browser = new Browser({
      clock,
      storage: new Storage(),
      issuers: [{ issuerName, unlockUrl }],
      relayPeriodKeys: false,
      chainKeyProfile: referenceChainKeyProfile,
      chainKeyCacheFactory: () => chainCache,
      chainKeyStrategy: inputs.client.chainRetention,
      requestBuilderFactory: (/** @type {object} */ opts) => new ChainKeyRequestBuilder(opts),
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
    const { periodMinutes, chainsPerDay } = expected.witness;
    /** @param {string} t */
    const derivedAt = async (t) =>
      (
        await chainCache.candidates(ACCESS_GROUP, t, {
          publisher: inputs.publisherOrigin,
          chainsPerDay,
          periodMinutes,
        })
      ).map(toBase64url);

    const [name] = inputs.client.contentNames;
    /** @type {any} */
    let settled;
    for (const [index, read] of inputs.reads.entries()) {
      step = index + 1;
      const render = renderAt(read.t);
      const { root, dcaData } = delivered(render);
      assert.equal(dcaData.resourceJWT, render.resourceJWT);
      // Chain keys only, one wrap at the render's own coordinate.
      const block = recordNamed(dcaData.issuerData, "issuerName", issuerName);
      assert.equal(
        Object.hasOwn(block.sealed, "contentKeys"),
        false,
        `${read.t}: no sealed content key`,
      );
      assert.equal(
        Object.hasOwn(block.sealed, "periodKeys"),
        false,
        `${read.t}: no period-key member`,
      );
      assert.deepEqual(
        ofGroup(block.sealed.chainKeys, ACCESS_GROUP).map(({ cutoff }) => cutoff),
        render.suppliedChain,
      );
      assert.deepEqual(
        ofGroup(recordNamed(dcaData.contentData, "contentName", name).keys, ACCESS_GROUP).map(
          ({ period }) => period,
        ),
        [read.t],
      );

      const decisionsBefore = presented.length;
      const load = browser.load(root);
      const { missing } = await load.resolve([name]);
      const unlock =
        read.unlock === "when-missing" && missing.length > 0 ? await load.unlock() : null;
      const opened = await load.open(name);
      const issuer = server.stats();
      const observed = {
        step,
        t: read.t,
        missing,
        texts: { [name]: opened.bytes === null ? null : utf8Decode(opened.bytes) },
        errors: { [name]: opened.error },
        unlock,
        presented: presented.slice(decisionsBefore),
        retained: await retainedBy(browser, chainCache),
        browserUnlocks: browser.stats().unlocks,
        issuer: { requests: issuer.requests, grants: issuer.grants, denials: issuer.denials },
      };
      assert.deepEqual(
        live.filter((exchange) => exchange.step === step),
        exchanges.filter((/** @type {any} */ exchange) => exchange.step === step),
        `step ${step}: the live request and the issuer's answer are the recorded ones`,
      );
      assert.deepEqual(observed, expected.steps[index], `step ${step}: ${read.t} as recorded`);
      // What the client holds once the last prefix item has opened.
      if (expected.prefix.some((/** @type {any} */ fact) => fact.t === read.t)) {
        settled = observed.retained;
      }
    }

    // The facts, asserted directly rather than read off the recorded steps.
    assert.equal(live.length, expected.retainedReuse.issuerExchanges, "one issuer exchange");
    const [{ step: unlockedStep, request, status, body }] = live;
    assert.deepEqual([inputs.reads[unlockedStep - 1].t], expected.retainedReuse.unlockedReads);

    // Relay: the render's chain member and geometry, unchanged; nothing else to answer from.
    const { dcaData: unlocked } = delivered(renderAt(expected.witness.cutoff));
    assert.deepEqual(request.sealed.contentKeys, []);
    assert.equal(Object.hasOwn(request.sealed, "periodKeys"), false);
    assert.deepEqual(
      request.sealed.chainKeys,
      recordNamed(unlocked.issuerData, "issuerName", issuerName).sealed.chainKeys,
    );
    assert.deepEqual(request.periodGeometry, unlocked.periodGeometry);

    // Result form: a chain result at the witness cutoff, under the request geometry.
    assert.equal(status, expected.response.status);
    assert.deepEqual(body.keys.contentKeys, expected.response.contentKeys);
    assert.equal(expected.response.periodKeys, "absent");
    assert.equal(Object.hasOwn(body.keys, "periodKeys"), false);
    assert.deepEqual(body.keys.chainKeys, expected.response.chainKeys);
    assert.deepEqual(expected.response.chainKeys, [
      {
        accessGroup: ACCESS_GROUP,
        cutoff: expected.witness.cutoff,
        key: expected.witness.cutoffChainKey,
      },
    ]);
    assert.equal(Object.hasOwn(body, "periodGeometry"), false);
    const { accessGroups, ...documentWide } = request.periodGeometry;
    assert.deepEqual(
      accessGroups?.[ACCESS_GROUP] ?? documentWide,
      expected.response.geometry[ACCESS_GROUP],
    );

    // There is no optional future horizon; the article target independently
    // selects the cutoff key, whose inherent reach is ten coordinates.
    assert.deepEqual(inputs.issuerDecisions[0].periodGrants, [
      {
        accessGroup: ACCESS_GROUP,
        futurePeriodCount: expected.policyHorizon.futurePeriodCount,
        authorizedPeriods: expected.prefix.map(({ t }) => t),
      },
    ]);
    assert.deepEqual(expected.policyHorizon.coordinates, []);
    assert.equal(expected.prefix.length, expected.witness.position + 1);

    // Reach: every prefix item opened to its known text, from the period key
    // the frozen vectors name for its position.
    for (const fact of expected.prefix) {
      const observed = expected.steps.find((/** @type {any} */ entry) => entry.t === fact.t);
      assert.equal(observed.texts[name], fact.plaintext, `${fact.t}: opened`);
      assert.equal(observed.unlock === null, fact.t !== expected.witness.cutoff, fact.t);
      assert.ok(
        (await derivedAt(fact.t)).includes(fact.periodKey),
        `${fact.t}: the witness period key`,
      );
    }

    // Absence of reach: the retained key derives nothing here, the item stays
    // missing and unopened, and what the client holds does not change.
    assert.ok(
      settled.chain.some(
        (/** @type {any} */ entry) =>
          entry.kind === "chain-key" && entry.t === expected.witness.cutoff,
      ),
      "the cutoff key is still held",
    );
    for (const fact of expected.outOfReach) {
      const observed = expected.steps.find((/** @type {any} */ entry) => entry.t === fact.t);
      assert.match(fact.kind, /^absence of reach/);
      assert.deepEqual(observed.missing, fact.missing, fact.t);
      assert.equal(observed.texts[name], fact.plaintext, fact.t);
      assert.equal(observed.errors[name], fact.error, fact.t);
      assert.equal(observed.unlock, null, `${fact.t}: no unlock was asked`);
      assert.equal(fact.retainedUnchanged, true);
      assert.deepEqual(observed.retained, settled, `${fact.t}: nothing retained changed`);
      assert.deepEqual(await derivedAt(fact.t), [], `${fact.t}: no period key derives`);
    }
  },
);

test("stock WebCrypto confirms the witness, the recorded prefix period keys and what they open", async () => {
  // No role code runs here, so this test carries no duty tag: it checks the
  // recorded bytes the replay above consumes.
  const vectors = JSON.parse(readFileSync(REPO_ROOT + expected.witness.source, "utf8"));
  const witness = vectors.cases.find(
    (/** @type {any} */ entry) => entry.id === expected.witness.case,
  );
  assert.equal(expected.witness.cutoffChainKey, witness.cutoffChainKeys[expected.witness.cutoff]);
  assert.equal(expected.witness.leafInfoHex, witness.leafInfoHex);
  assert.equal(expected.witness.windowStart, witness.windowStart);
  assert.equal(expected.witness.position, witness.position);
  for (const fact of expected.prefix)
    assert.equal(fact.periodKey, witness.expansion[fact.position]);

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
      `render ${render.t}: the registered key signed it`,
    );
  }

  // The Leaf context this test lays out is the one the frozen vectors record:
  // 49 octets for the seven-octet `premium`, as §6.4 counts them.
  const cutoffInfo = context(0x03, expected.witness.position);
  assert.equal(cutoffInfo.length, 49);
  assert.equal(Buffer.from(cutoffInfo).toString("hex"), expected.witness.leafInfoHex);

  /** @param {any} render */
  const itemOf = (render) => {
    const { dcaData, sealedContent } = delivered(render);
    const item = recordNamed(dcaData.contentData, "contentName", "bodytext");
    assert.equal(Object.hasOwn(item, "aad"), false, "the item record carries no aad");
    // The hand-built transcript over this render's token and item, not the reference module.
    const aad = contentAadOctets(dcaData, "bodytext");
    const [wrap] = ofGroup(item.keys, ACCESS_GROUP);
    // The wrap nonce is not on the wire: it derives from this render's coordinate.
    const iv = wrapNonceOf(dcaData, "bodytext", ACCESS_GROUP, wrap.period);
    const { content } = recordNamed(sealedContent, "contentName", "bodytext");
    return { item, aad, wrap, iv, ciphertext: fromBase64url(content) };
  };
  /** @param {Uint8Array} periodKey @param {any} render */
  const openWith = async (periodKey, render) => {
    const { aad, wrap, iv, ciphertext } = itemOf(render);
    // Content-key wraps under a period key use the empty AAD.
    const contentKey = await openGcm(periodKey, iv, fromBase64url(wrap.key));
    const plaintext = await openGcm(contentKey, new Uint8Array(12), ciphertext, aad);
    return utf8Decode(plaintext);
  };

  // Walk the cutoff key the issuer returned back to the window start: Leaf at
  // each position, then Step to the one below, as §6.5 and §6.6 state them.
  const returned = ofGroup(exchanges[0].body.keys.chainKeys, ACCESS_GROUP).filter(
    ({ cutoff }) => cutoff === expected.witness.cutoff,
  );
  assert.equal(returned.length, 1, "one returned chain key at the witness cutoff");
  let chainKey = fromBase64url(returned[0].key);
  /** @type {Uint8Array[]} */
  const prefixPeriodKeys = [];
  for (let position = expected.witness.position; position >= 0; position--) {
    const periodKey = await hkdf16(chainKey, context(0x03, position));
    const fact = expected.prefix[position];
    assert.equal(
      toBase64url(periodKey),
      fact.periodKey,
      `${fact.t}: the stock period key is the witness period key`,
    );
    assert.equal(await openWith(periodKey, renderAt(fact.t)), fact.plaintext, `${fact.t}: opens`);
    prefixPeriodKeys.push(periodKey);
    if (position > 0) chainKey = await hkdf16(chainKey, context(0x02, position - 1));
  }

  // No granted period key opens an out-of-reach wrap; the period key the item
  // was wrapped under does, so each refusal above is about reach and not a
  // broken render.
  for (const fact of expected.outOfReach) {
    const render = renderAt(fact.t);
    for (const periodKey of prefixPeriodKeys) {
      await assert.rejects(openWith(periodKey, render), `${fact.t}: no prefix period key opens it`);
    }
    assert.equal(
      await openWith(fromBase64url(fact.withheldPeriodKey), render),
      fact.sealedPlaintext,
    );
  }
  const later = expected.outOfReach.find((/** @type {any} */ fact) => fact.t === "251023T1430");
  assert.equal(later.withheldPeriodKey, witness.expansion[expected.witness.position + 1]);
});

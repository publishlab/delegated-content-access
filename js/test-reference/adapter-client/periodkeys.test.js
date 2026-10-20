// @ts-check
//
// The cached path. The publisher takes a periodKey per (accessGroup, t),
// wraps each contentKey under it, and seals the
// periodKeys to the issuer. The client unlocks once, caches what came back,
// and opens the next article of the same period without asking anyone.
//
// Pinned: one issuer, direct transport, grant-all policy, one period family
// per accessGroup, the clock still. Rollover, eviction, storage, the breaker
// and access policy are each a file of their own.

import { test, portableTest } from "../support/portable-test.js";
import assert from "node:assert/strict";

import { currentT, formatT, periodsFor } from "../../core-shared--publisher-issuer/periodKeys.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { PeriodKeyCache, keyByIssuer } from "../../adapter-client/PeriodKeyCache.js";
import { periodKeyCandidateSource } from "../../core-client/periodKeyCandidateSource.js";
import { attemptContentKeyWrap } from "../../core-client/contentKeyWrapAttempt.js";
import { evictAfterSixHours } from "../../adapter-client/periodKeyEviction.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { sealerForRender } from "../../core-publisher/testing/sealerFactory.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { Random } from "../../demo/actors/Random.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Storage } from "../../demo/actors/Storage.js";
import { base64urlEncode, utf8Decode } from "../../core-shared/codec.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { openEcdhEnvelope } from "../support/ecdhEnvelope.js";
import { issuerKeypair, signingKeypair, TEST_ISSUER_PRIVATE_KEY_PKCS8 } from "../support/keys.js";
import { sealerPeriodKeysRender, sealerPeriodKeysSetup } from "../support/sealerCases.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const DOMAIN = "www.news-site.example";
const AT = "2025-10-23T14:20:00Z";

/** The publisher these renders name, folded the way the resolver folds it before
 * the cache files a key - the coordinate a direct put/read shares with the page. */
const PUB = `https://${DOMAIN}`;

/** Somewhere else the same render is served from, so two coordinates exist. */
const COPY_ORIGIN = "https://copy.example";

const ARTICLE_A = "<p>The council voted 7-2 to rezone the harbour.</p>";
const ARTICLE_B = "<p>The harbour plan goes to a second reading.</p>";

/**
 * A publisher and an issuer that share nothing but the issuer's public key.
 * Every render below comes out of this one world, so two articles carry the
 * same periodKey family.
 *
 * @returns {Promise<{ issuerKeys: CryptoKeyPair, keyStore: object, render: (resourceId: string, value: string) => Promise<any> }>}
 */
async function world({
  periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed: 7 }) }),
} = {}) {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();

  let seed = 1;

  /**
   * @param {string} resourceId
   * @param {string} value
   */
  async function render(resourceId, value, at = AT) {
    const sealer = new Sealer({
      origin: PUB,
      clock: new Clock(at),
      random: new Random({ seed: seed++ }),
      signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,
        },
      ],
    });

    sealer.resource(resourceId, { section: "politics" });
    sealer.content("bodytext", value, "text/html", { accessGroups: ["premium"] });

    const rendered = await sealer.seal();
    return JSON.parse(
      JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
    );
  }

  const keyStore = {
    /**
     * @param {string} issuerName
     * @param {string} keyId
     */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };

  const publisherRegistration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);

  return { issuerKeys, keyStore, publisherRegistration, render };
}

/** An endpoint that counts what crossed it, so "zero calls" is an assertion. */
function countingEndpoint(publisherRegistration, engineConfig = {}) {
  const processor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: new AllowAllPolicy(),
      ...engineConfig,
    }),
    { periodKeyInput: true },
  );
  const endpoint = new UnlockEndpoint(processor);
  const calls = { count: 0 };
  return {
    calls,
    /** @param {any} body */
    async unlock(body) {
      calls.count++;
      return unlockThroughAdmission(processor, endpoint, body, publisherRegistration);
    },
  };
}
const portableCoreTest = portableTest("portable-core");
const portableCoreDynamicTest = portableTest("portable-core-dynamic");
const portableSealerPeriodKeysTest = portableTest("portable-sealer-period-keys");

/**
 * Dates formatT refuses, each a value the bridge carries. None is a Date,
 * which formatT declares, so their twin runs under portable-core-dynamic.
 */
const NOT_PERIOD_DATES = [null, "2025-10-23T14:20:00Z", {}];

/** Period lengths formatT refuses, each a value the bridge carries. */
const NOT_PERIOD_LENGTHS = [0, -1, 0.5, 9007199254740992];

/** Period lengths periodsFor refuses, each a value the bridge carries. */
const NOT_PERIODSFOR_LENGTHS = [0, -1, -60, 0.5];

test("a Sealer given no supply seals no periodKeys - the content-key-only case", async () => {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 1 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  // A named group would need a supply to wrap under, so content() refuses it
  // rather than sealing the item without its wraps. The item goes in ungrouped.
  assert.throws(
    () => sealer.content("bodytext", ARTICLE_A, "text/html", { accessGroups: ["premium"] }),
    {
      code: "bad_config",
      message: /names accessGroups, and this publisher holds no periodKeySupply/,
    },
  );
  sealer.content("bodytext", ARTICLE_A, "text/html", { accessGroups: [] });

  const { dcaData } = await sealer.seal();
  assert.equal(
    Object.hasOwn(dcaData.contentData.bodytext, "keys"),
    false,
    "no supply, no cached path, so no wrapped contentKeys on the wire",
  );
  assert.equal(
    dcaData.issuerData[ISSUER_NAME].sealed.periodKeys,
    undefined,
    "and the issuer is handed contentKeys only, no sealed periodKeys",
  );
});

portableCoreTest("t always includes minutes while preserving the selected period start", () => {
  const at = new Date("2025-10-23T14:20:00Z");

  assert.equal(formatT(at), "251023T1400");
  assert.equal(formatT(at, 60), "251023T1400");
  assert.equal(formatT(at, 15), "251023T1415", "a quarter-hour period needs the minutes");
  assert.equal(formatT(new Date("2026-02-28T09:05:00Z"), 60), "260228T0900");
});

test("period labels admit only safe UTC producer coordinates in the supported century", () => {
  const bad = (value, length) =>
    assert.throws(
      () => formatT(/** @type {any} */ (value), /** @type {any} */ (length)),
      (error) => error && error.code === "bad_config",
    );
  const overridden = new Date("2025-10-23T14:20:00Z");
  overridden.getTime = () => Date.UTC(2026, 0, 1);

  for (const value of [new Date("not a date"), ...NOT_PERIOD_DATES]) bad(value, 60);
  assert.equal(
    formatT(overridden, 60),
    "251023T1400",
    "own getTime cannot choose the producer coordinate",
  );
  for (const length of [...NOT_PERIOD_LENGTHS, NaN, Infinity])
    bad(new Date("2025-10-23T14:20:00Z"), length);

  assert.equal(formatT(new Date("2000-01-01T00:00:00Z"), 60), "000101T0000");
  assert.equal(formatT(new Date("2099-12-31T23:59:00Z"), 60), "991231T2300");
  bad(new Date("1999-12-31T23:59:00Z"), 60);
  bad(new Date("2100-01-01T00:00:00Z"), 60);
});

/**
 * Asserts that formatT refuses `value` at `length` with bad_config.
 *
 * @param {unknown} value
 * @param {unknown} length
 */
function badPeriodInput(value, length) {
  assert.throws(
    () => formatT(/** @type {any} */ (value), /** @type {any} */ (length)),
    (/** @type {any} */ error) => error && error.code === "bad_config",
    `${JSON.stringify(value)} at ${JSON.stringify(length)}`,
  );
}

// The portable twins of the case above. An invalid Date, NaN and Infinity are
// not bridge values, and an own getTime is not part of the Date the bridge
// carries, so those halves run only in the direct case. The dates that are
// not a Date run in the dynamic twin below.
portableCoreTest(
  "period labels admit only safe UTC producer coordinates in the supported century, from a Date",
  () => {
    for (const length of NOT_PERIOD_LENGTHS)
      badPeriodInput(new Date("2025-10-23T14:20:00Z"), length);

    assert.equal(formatT(new Date("2000-01-01T00:00:00Z"), 60), "000101T0000");
    assert.equal(formatT(new Date("2099-12-31T23:59:00Z"), 60), "991231T2300");
    badPeriodInput(new Date("1999-12-31T23:59:00Z"), 60);
    badPeriodInput(new Date("2100-01-01T00:00:00Z"), 60);
  },
);

portableCoreDynamicTest("formatT refuses a date that is not a Date", () => {
  for (const value of NOT_PERIOD_DATES) badPeriodInput(value, 60);
});

portableCoreTest("periodsFor refuses a forward slot beyond the supported century", () => {
  assert.throws(
    () => periodsFor(new Date("2099-12-31T23:20:00Z"), { length: 60, slots: 2 }),
    (error) => error && error.code === "bad_config",
  );
});

test("periodsFor refuses a period length that is not a positive whole number of minutes", () => {
  const now = new Date("2025-10-23T14:20:00Z");
  for (const length of [...NOT_PERIODSFOR_LENGTHS, NaN]) {
    assert.throws(
      () => periodsFor(now, { length, slots: 2 }),
      (/** @type {any} */ error) =>
        error?.code === "bad_config" && /period length/.test(error.message),
      String(length),
    );
  }
});

// The portable twin of the case above, without NaN, which is not a bridge value.
portableCoreTest(
  "periodsFor refuses a period length that is not a positive whole number of minutes, NaN aside",
  () => {
    const now = new Date("2025-10-23T14:20:00Z");
    for (const length of NOT_PERIODSFOR_LENGTHS) {
      assert.throws(
        () => periodsFor(now, { length, slots: 2 }),
        (/** @type {any} */ error) =>
          error?.code === "bad_config" && /period length/.test(error.message),
        String(length),
      );
    }
  },
);

portableCoreTest(
  "currentT picks the greatest started label whatever order the labels arrive in",
  () => {
    const now = new Date("2025-10-23T14:30:00Z");
    for (const labels of [
      ["251023T1200", "251023T1300", "251023T1400", "251023T1500"],
      ["251023T1500", "251023T1400", "251023T1300", "251023T1200"],
      ["251023T1300", "251023T1500", "251023T1200", "251023T1400"],
    ]) {
      assert.equal(currentT(now, labels), "251023T1400", labels.join(","));
    }
  },
);

test("currentT selects actual canonical supply without an hourly alias or inferred source", () => {
  const now = new Date("2025-10-23T14:30:59Z");
  assert.equal(
    currentT(now, ["251023T14", "251023T1415", "251023T1430", "251023T1445"]),
    "251023T1430",
  );
  assert.equal(currentT(now, ["251023T1200", "251023T1500"]), "251023T1200");
  assert.equal(currentT(now, ["251023T1500"]), null);
  assert.equal(currentT(now, ["251023T14"]), null);
  assert.equal(currentT(now, []), null);
});

// Every label list here holds a value that is not a string, where currentT
// declares string[], so the case runs under portable-core-dynamic.
portableCoreDynamicTest("currentT skips a label that is not a string", () => {
  const now = new Date("2025-10-23T14:30:00Z");
  for (const odd of [["251023T1400"], 251023, null]) {
    assert.equal(
      currentT(now, /** @type {any} */ (["251023T1300", odd])),
      "251023T1300",
      JSON.stringify(odd),
    );
  }
});

portableCoreTest(
  "periodsFor ships the current period and forward overlap, never a past one",
  () => {
    const now = new Date("2025-10-23T14:20:00Z");

    assert.deepEqual(
      periodsFor(now),
      ["251023T1400", "251023T1500"],
      "hourly, two slots is the default",
    );
    assert.deepEqual(periodsFor(now, { length: 60, slots: 3 }), [
      "251023T1400",
      "251023T1500",
      "251023T1600",
    ]);
    assert.deepEqual(periodsFor(now, { length: 15, slots: 2 }), ["251023T1415", "251023T1430"]);

    for (const t of periodsFor(now, { length: 60, slots: 4 })) {
      assert.ok(t >= "251023T1400", `${t} is not behind the current period`);
    }
  },
);

portableCoreTest(
  "periodsFor at the day's last period rolls the overlap into the next UTC day",
  () => {
    // The forward slot leaves the render's own date behind. An implementation that wrapped
    // the label inside the render's own day would ship 251023T0000 here - a label sorting below
    // the current one, which is the past label this module refuses to ship.
    const lastHour = new Date("2025-10-23T23:20:00Z");

    assert.deepEqual(
      periodsFor(lastHour),
      ["251023T2300", "251024T0000"],
      "hourly, the overlap is tomorrow",
    );
    assert.deepEqual(periodsFor(lastHour, { length: 60, slots: 3 }), [
      "251023T2300",
      "251024T0000",
      "251024T0100",
    ]);

    // Sub-hour geometry, where the day's last period does not start on the 23:00 hour.
    assert.deepEqual(periodsFor(new Date("2025-10-23T23:52:00Z"), { length: 15, slots: 2 }), [
      "251023T2345",
      "251024T0000",
    ]);
    assert.deepEqual(periodsFor(new Date("2025-10-23T23:41:00Z"), { length: 30, slots: 3 }), [
      "251023T2330",
      "251024T0000",
      "251024T0030",
    ]);

    // The month rolls with the day.
    assert.deepEqual(periodsFor(new Date("2025-10-31T23:05:00Z")), ["251031T2300", "251101T0000"]);

    for (const t of periodsFor(lastHour, { length: 60, slots: 4 })) {
      assert.ok(t >= "251023T2300", `${t} is not behind the current period`);
    }
  },
);

test("the wire carries the wrapped contentKeys and the sealed periodKeys", async () => {
  const { render } = await world();
  const page = await render("123456", ARTICLE_A);

  const entries = page.contentData.bodytext.keys.premium;
  assert.ok(
    Array.isArray(entries),
    "the accessGroup value is the format's array of { t, nonce, key }",
  );
  assert.deepEqual(
    entries.map((/** @type {any} */ e) => e.t),
    ["251023T1400", "251023T1500"],
  );
  for (const entry of entries) {
    assert.deepEqual(Object.keys(entry).sort(), ["key", "nonce", "t"]);
    assert.equal(entry.key.length, 43, "a 16-byte key plus a 16-byte tag, base64url");
    assert.match(entry.nonce, /^[A-Za-z0-9_-]+$/);
  }

  const sealed = page.issuerData[ISSUER_NAME].sealed;
  assert.deepEqual(Object.keys(sealed).sort(), ["contentKeys", "periodKeys"]);
  assert.deepEqual(Object.keys(sealed.periodKeys.premium), ["251023T1400", "251023T1500"]);
  assert.equal(typeof sealed.periodKeys.premium["251023T1400"], "string");

  // The client-facing entries and the issuer-facing map name the same periods.
  assert.deepEqual(
    entries.map((/** @type {any} */ e) => e.t),
    Object.keys(sealed.periodKeys.premium),
  );

  assert.ok(!JSON.stringify(page).includes("periodSecret"));
});

portableSealerPeriodKeysTest(
  "through the Sealer factory, the wire carries every drawn value at its offset in the random stream",
  async () => {
    // One render through the factory, on plain setup a port builds its own
    // Sealer from: a fixed instant, one random stream, a fixed key for each of
    // the two periods and the known test keys. The reference reads the stream in
    // this order: render id, content key, the wrap nonce of each
    // period, the nonce that seals the content key to the issuer, and the nonce
    // that seals each period key.
    const setup = sealerPeriodKeysSetup();
    const stream = setup.randomStream;
    const periodKeys = setup.fixedPeriodKeys.premium;
    const sealer = await sealerForRender(setup);
    const { resource, content } = sealerPeriodKeysRender();
    sealer.resource(resource.resourceId, resource.data);
    for (const item of content) {
      sealer.content(item.name, item.value, item.contentType, { accessGroups: item.accessGroups });
    }
    const rendered = await sealer.seal();
    const page = JSON.parse(
      JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
    );

    const entries = page.contentData.bodytext.keys.premium;
    assert.ok(
      Array.isArray(entries),
      "the accessGroup value is the format's array of { t, nonce, key }",
    );
    assert.deepEqual(
      entries.map((/** @type {any} */ e) => e.t),
      ["251023T1400", "251023T1500"],
    );
    for (const entry of entries) {
      assert.deepEqual(Object.keys(entry).sort(), ["key", "nonce", "t"]);
      assert.equal(entry.key.length, 43, "a 16-byte key plus a 16-byte tag, base64url");
      assert.match(entry.nonce, /^[A-Za-z0-9_-]+$/);
    }

    const sealed = page.issuerData[ISSUER_NAME].sealed;
    assert.deepEqual(Object.keys(sealed).sort(), ["contentKeys", "periodKeys"]);
    assert.deepEqual(Object.keys(sealed.periodKeys.premium), ["251023T1400", "251023T1500"]);
    assert.equal(typeof sealed.periodKeys.premium["251023T1400"], "string");

    // The client-facing entries and the issuer-facing map name the same periods.
    assert.deepEqual(
      entries.map((/** @type {any} */ e) => e.t),
      Object.keys(sealed.periodKeys.premium),
    );

    assert.ok(!JSON.stringify(page).includes("periodSecret"));

    // Every value the render drew is on the wire at its offset in the stream,
    // up to the last byte, so a port that reuses a nonce, skips a read or reads
    // out of order moves a value the test names. The expected values come from
    // Node's Buffer and WebCrypto, so no call here reaches the test target.
    /** @param {number} from @param {number} to */
    const drawn = (from, to) => Buffer.from(stream.subarray(from, to)).toString("base64url");
    /** @param {string} text */
    const bytesOf = (text) => new Uint8Array(Buffer.from(text, "base64url"));
    assert.equal(page.resource.renderId, drawn(0, 16));
    assert.equal(Object.hasOwn(page.contentData.bodytext, "nonce"), false);
    assert.deepEqual(
      entries.map((/** @type {any} */ e) => e.nonce),
      [drawn(32, 44), drawn(44, 56)],
    );
    for (const entry of entries) {
      const periodKey = await crypto.subtle.importKey(
        "raw",
        periodKeys[/** @type {"251023T1400" | "251023T1500"} */ (entry.t)],
        { name: "AES-GCM" },
        false,
        ["decrypt"],
      );
      const contentKey = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytesOf(entry.nonce) },
        periodKey,
        bytesOf(entry.key),
      );
      assert.equal(
        Buffer.from(contentKey).toString("base64url"),
        drawn(16, 32),
        `the ${entry.t} wrap opens to the content key`,
      );
    }
    // An ECDH envelope carries its nonce after the 65-byte ephemeral point.
    /** @param {string} envelope */
    const envelopeNonce = (envelope) =>
      Buffer.from(bytesOf(envelope).subarray(65, 77)).toString("base64url");
    assert.equal(envelopeNonce(sealed.contentKeys.bodytext), drawn(56, 68));
    assert.deepEqual(
      Object.values(sealed.periodKeys.premium).map((envelope) =>
        envelopeNonce(/** @type {string} */ (envelope)),
      ),
      [drawn(68, 80), drawn(80, 92)],
    );
    // The issuer opens each envelope at its coordinate: the content-key one to the
    // drawn content key, and each period-key one to that period's fixed key.
    const renderId = page.resource.renderId;
    const openedContentKey = await openEcdhEnvelope(
      sealed.contentKeys.bodytext,
      `dca-bind-key-envelope|c|${renderId}|bodytext`,
      TEST_ISSUER_PRIVATE_KEY_PKCS8,
    );
    assert.equal(Buffer.from(openedContentKey).toString("base64url"), drawn(16, 32));
    for (const [t, envelope] of Object.entries(sealed.periodKeys.premium)) {
      const opened = await openEcdhEnvelope(
        /** @type {string} */ (envelope),
        `dca-bind-key-envelope|p|${renderId}|premium|${t}`,
        TEST_ISSUER_PRIVATE_KEY_PKCS8,
      );
      assert.equal(
        Buffer.from(opened).toString("hex"),
        Buffer.from(periodKeys[/** @type {"251023T1400" | "251023T1500"} */ (t)]).toString("hex"),
        `the ${t} envelope opens to that period's fixed key`,
      );
    }
  },
);

test("the reference eviction policy removes malformed period-key coordinates", async () => {
  const clock = new Clock("2025-10-23T14:20:00Z");
  const cache = new PeriodKeyCache({ clock, evictionPolicy: evictAfterSixHours });
  await cache.put("premium", "not-a-period", new Uint8Array(16).fill(1), { publisher: PUB });
  assert.deepEqual(
    await cache.entries(),
    [],
    "malformed labels cannot bypass a time-bounded reference cache",
  );
});

test("unlock once, cache the periodKeys, unwrap and decrypt", async () => {
  const { publisherRegistration, render } = await world();
  const page = await render("123456", ARTICLE_A);

  const cache = new PeriodKeyCache();
  const unsealer = new Client({ publisherOrigin: PUB, cache });
  const endpoint = countingEndpoint(publisherRegistration);

  const dcaData = unsealer.parse(page);

  const { missing } = await unsealer.resolve(dcaData, ["bodytext"]);
  assert.deepEqual(missing, ["bodytext"], "an empty cache covers nothing");

  const request = unsealer.buildRequest(dcaData, ISSUER_NAME, missing);
  assert.deepEqual(Object.keys(request.sealed.periodKeys.premium), ["251023T1400", "251023T1500"]);

  const { status, body } = await endpoint.unlock(JSON.stringify(request));
  assert.equal(status, 200);
  assert.deepEqual(Object.keys(body.keys.periodKeys.premium), ["251023T1400", "251023T1500"]);
  assert.equal(body.errors, undefined);

  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
  assert.equal((await cache.entries()).length, 2, "both periods cached");

  const plaintext = await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"));
  assert.equal(utf8Decode(plaintext), ARTICLE_A);
  assert.equal(endpoint.calls.count, 1);
});

test("a held content-key grant answers before cached period material, and the cache is never consulted", async () => {
  // Both a held content-key grant and a cached period key open this item -
  // both paths recover the same key. The target precedence is held-grant-first,
  // so the resolver answers from this render's own grant and never reaches the
  // cache. A spy on `candidates` shows the order: held-first leaves it at
  // zero, the old cache-first order calls it and hands back the cached key
  // instead. The held grant carries distinct bytes so which one answered is
  // visible in what comes out.
  const { publisherRegistration, render } = await world();
  const page = await render("123456", ARTICLE_A);

  const real = new PeriodKeyCache();
  let candidateCalls = 0;
  const cache = {
    /** @param {any[]} args */
    put: (...args) => real.put(...args),
    /** @param {any[]} args */
    candidatesAt: (...args) => {
      candidateCalls++;
      return real.candidatesAt(...args);
    },
    attempted: (...args) => real.attempted(...args),
  };

  const unsealer = new Client({ publisherOrigin: PUB, cache });
  const endpoint = countingEndpoint(publisherRegistration);
  const dcaData = unsealer.parse(page);

  // The cached period material that also opens bodytext is put in place first.
  const { body } = await endpoint.unlock(unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]));
  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
  assert.equal((await real.entries()).length, 2, "the cached period material is in place");

  // And a distinct content-key grant is held for the same item on this render.
  const heldGrant = new Uint8Array(16).fill(200);
  unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
  await unsealer.applyResponse(dcaData, ISSUER_NAME, {
    keys: { contentKeys: { bodytext: base64urlEncode(heldGrant) } },
  });

  candidateCalls = 0;
  const answered = await unsealer.contentKeyFor(dcaData, "bodytext");
  assert.deepEqual(answered, heldGrant, "the held grant answered, not the cached period material");
  assert.equal(
    candidateCalls,
    0,
    "and the cache was never consulted - held-grant-first short-circuits",
  );
});

test("the second article of the period costs no unlock call", async () => {
  const { publisherRegistration, render } = await world();
  const cache = new PeriodKeyCache();
  const unsealer = new Client({ publisherOrigin: PUB, cache });
  const endpoint = countingEndpoint(publisherRegistration);

  const first = unsealer.parse(await render("123456", ARTICLE_A));
  const firstRequest = unsealer.buildRequest(first, ISSUER_NAME, ["bodytext"]);
  await unsealer.applyResponse(first, ISSUER_NAME, (await endpoint.unlock(firstRequest)).body);
  assert.equal(endpoint.calls.count, 1);

  const secondPage = await render("123457", ARTICLE_B);
  const second = unsealer.parse(secondPage);

  const { covered, missing } = await unsealer.resolve(second, ["bodytext"]);
  assert.deepEqual(covered, ["bodytext"]);
  assert.deepEqual(missing, [], "the cached periodKey already opens it");

  const plaintext = await unsealer.decrypt(
    second,
    "bodytext",
    unsealer.extract(secondPage, "bodytext"),
  );
  assert.equal(utf8Decode(plaintext), ARTICLE_B);
  assert.equal(endpoint.calls.count, 1, "no second unlock");
});

test("the same render delivered from another origin is another cache coordinate", async () => {
  // The control above reads the second article through the origin the first
  // one was delivered from. Here the same render arrives from somewhere else
  // - a copy of the page on another site - and the cache that opens it at the
  // publisher's own origin holds nothing for that one: the publisher is the
  // outermost segment of every coordinate the resolver files under.
  const { publisherRegistration, render } = await world();
  const cache = new PeriodKeyCache();
  const atPublisher = new Client({ publisherOrigin: PUB, cache });
  const endpoint = countingEndpoint(publisherRegistration);

  const first = atPublisher.parse(await render("123456", ARTICLE_A));
  await atPublisher.applyResponse(
    first,
    ISSUER_NAME,
    (await endpoint.unlock(atPublisher.buildRequest(first, ISSUER_NAME, ["bodytext"]))).body,
  );
  assert.equal(
    (await cache.entries()).length,
    2,
    "the periods of this render are cached under the publisher",
  );

  const secondPage = await render("123457", ARTICLE_B);
  const atCopy = new Client({ publisherOrigin: COPY_ORIGIN, cache });
  assert.deepEqual(
    (await atCopy.resolve(atCopy.parse(secondPage), ["bodytext"])).missing,
    ["bodytext"],
    "another delivery origin reaches none of the keys cached under the publisher",
  );

  // And the same page at the publisher's own origin still opens from the
  // cache, so what the copy site missed is the coordinate and not the key.
  assert.deepEqual(
    (await atPublisher.resolve(atPublisher.parse(secondPage), ["bodytext"])).covered,
    ["bodytext"],
  );
  assert.equal(endpoint.calls.count, 1);
});

test("the cached path is closed to a client that names no delivery origin", () => {
  // No implicit coordinate: a client built without one cannot read a page at
  // all, so nothing above can be reached through an origin nobody named.
  for (const config of [undefined, {}, { cache: new PeriodKeyCache() }]) {
    assert.throws(
      () => new Client(/** @type {any} */ (config)),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  }
});

test("a repeated article in one period adds no cache entries", async () => {
  const { publisherRegistration, render } = await world();
  const cache = new PeriodKeyCache();
  const unsealer = new Client({ publisherOrigin: PUB, cache });
  const endpoint = countingEndpoint(publisherRegistration);

  for (const [resourceId, value] of [
    ["123456", ARTICLE_A],
    ["123457", ARTICLE_B],
    ["123458", ARTICLE_A],
  ]) {
    const dcaData = unsealer.parse(await render(resourceId, value));
    // Every article unlocked, deliberately - the dedup is the cache's, not
    // the caller's.
    const { body } = await endpoint.unlock(
      unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]),
    );
    await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
  }

  assert.equal(endpoint.calls.count, 3);
  assert.equal(
    (await cache.entries()).length,
    2,
    "one entry per (accessGroup, t), whatever the article count",
  );
});

test("a contentKey delivery never populates the cache, a periodKey delivery does", async () => {
  const { render } = await world();
  const dcaData = new Client({ publisherOrigin: PUB }).parse(await render("123456", ARTICLE_A));

  const cache = new PeriodKeyCache();
  const unsealer = new Client({ publisherOrigin: PUB, cache });

  unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
  await unsealer.applyResponse(dcaData, ISSUER_NAME, {
    keys: { contentKeys: { bodytext: base64urlEncode(new Uint8Array(16).fill(1)) } },
  });
  assert.deepEqual(
    await cache.entries(),
    [],
    "a contentKey is good for one render, and is not cache material",
  );

  unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
  await unsealer.applyResponse(dcaData, ISSUER_NAME, {
    keys: {
      periodKeys: { premium: { "251023T1400": base64urlEncode(new Uint8Array(16).fill(2)) } },
    },
  });
  assert.equal((await cache.entries()).length, 1);
});

test("a failed trial moves to the next candidate and keeps the one that missed", async () => {
  const { publisherRegistration, render } = await world();
  const page = await render("123456", ARTICLE_A);

  const cache = new PeriodKeyCache();
  // Lexicographically newest, so it is tried first, and it opens nothing.
  await cache.put("premium", "251023T9900", new Uint8Array(16).fill(3), { publisher: PUB });

  const unsealer = new Client({ publisherOrigin: PUB, cache });
  const endpoint = countingEndpoint(publisherRegistration);
  const dcaData = unsealer.parse(page);

  const { body } = await endpoint.unlock(unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]));
  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
  assert.equal((await cache.entries()).length, 3);

  const plaintext = await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"));
  assert.equal(utf8Decode(plaintext), ARTICLE_A);

  assert.equal(
    (await cache.entries()).length,
    3,
    "the key that missed is still held - another period may need it",
  );
});

test("the cache hands back only an exact coordinate and its coexisting rivals", async () => {
  const cache = new PeriodKeyCache();

  await cache.put("premium", "251023T1400", new Uint8Array(16).fill(1), { publisher: PUB });
  await cache.put("premium", "251023T1600", new Uint8Array(16).fill(3), { publisher: PUB });
  await cache.put("premium", "251023T1500", new Uint8Array(16).fill(2), { publisher: PUB });
  await cache.put("locked-data", "251023T1400", new Uint8Array(16).fill(9), { publisher: PUB });

  const candidates = await cache.candidatesAt("premium", "251023T1500", { publisher: PUB });
  assert.deepEqual(
    candidates.map((/** @type {any} */ k) => k[0]),
    [2],
    "other family coordinates are not scanned",
  );
  assert.deepEqual(
    (await cache.candidatesAt("locked-data", "251023T1400", { publisher: PUB })).length,
    1,
    "families do not mix",
  );
  assert.deepEqual(
    await cache.candidatesAt("subscriber", "251023T1400", { publisher: PUB }),
    [],
    "an unknown family is empty, not a throw",
  );

  // After a period-key rotation the same coordinate carries other bytes, and
  // the new key coexists with the old rather than replacing it: T16 now holds
  // two candidates, so the family reports one more entry and the trial has both
  // to try at that period. The rotation's key was filed second, so it is the one
  // the trial reaches first.
  await cache.put("premium", "251023T1600", new Uint8Array(16).fill(4), { publisher: PUB });
  assert.equal((await cache.entries()).length, 5);
  assert.deepEqual(
    (await cache.candidatesAt("premium", "251023T1600", { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [4, 3],
  );
});

test("rival keys at one coordinate are handed back newest filed first", async () => {
  // Nothing on a period key says which generation it belongs to, so the only
  // fact available about two rivals at one coordinate is which of them arrived
  // later. The spec asks for the newest first, and the list a coordinate holds
  // is already insertion ordered.
  //
  // The bytes here are chosen to disagree with that: the key filed second
  // sorts after the key filed first under any comparison of their bytes, so a
  // cache ordering candidates by their base64url hands back the key a rotation
  // has already replaced and the trial unwrap starts on the wrong one.
  const first = new Uint8Array(16).fill(1);
  const second = new Uint8Array(16).fill(2);
  assert.ok(
    base64urlEncode(first) < base64urlEncode(second),
    "the key filed second sorts after the first",
  );

  const inMemory = new PeriodKeyCache();
  await inMemory.put("premium", "251023T1400", first, { publisher: PUB });
  await inMemory.put("premium", "251023T1400", second, { publisher: PUB });
  assert.deepEqual(
    (await inMemory.candidatesAt("premium", "251023T1400", { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [2, 1],
    "the key filed second is tried first",
  );

  // And the filing order is what the store carries, so the next page load
  // reads the same order back rather than whatever the bytes sort to.
  const storage = new Storage();
  const filing = new PeriodKeyCache({ storage });
  await filing.put("premium", "251023T1400", first, { publisher: PUB });
  await filing.put("premium", "251023T1400", second, { publisher: PUB });

  const reopened = new PeriodKeyCache({ storage });
  assert.deepEqual(
    (await reopened.candidatesAt("premium", "251023T1400", { publisher: PUB })).map(
      (/** @type {any} */ k) => k[0],
    ),
    [2, 1],
    "a cache built over the same store reads the filing order back",
  );
  assert.deepEqual(
    (await reopened.entries()).map((/** @type {any} */ e) => e.key[0]),
    [2, 1],
    "and reports it the same way",
  );
});

test("the newest eligible rival leads across issuer families before the trial limit", async () => {
  for (const storage of [undefined, new Storage()]) {
    const cache = new PeriodKeyCache(
      storage ? { keyBy: keyByIssuer, storage } : { keyBy: keyByIssuer },
    );
    const t = "260926T0900";
    for (let value = 1; value <= 4; value++) {
      await cache.put("premium", t, new Uint8Array(16).fill(value), {
        publisher: PUB,
        issuerName: "alpha",
      });
    }
    const newest = new Uint8Array(16).fill(9);
    await cache.put("premium", t, newest, { publisher: PUB, issuerName: "beta" });
    await cache.put("other-group", t, new Uint8Array(16).fill(10), {
      publisher: PUB,
      issuerName: "beta",
    });
    await cache.put("premium", t, new Uint8Array(16).fill(11), {
      publisher: PUB,
      issuerName: "gamma",
    });
    await cache.put("premium", t, new Uint8Array(16).fill(9), {
      publisher: PUB,
      issuerName: "beta",
    });

    const reading = storage ? new PeriodKeyCache({ keyBy: keyByIssuer, storage }) : cache;
    const issuerNames = ["alpha", "beta"];
    assert.deepEqual(
      (await reading.candidatesAt("premium", t, { publisher: PUB, issuerNames })).map(
        (key) => key[0],
      ),
      [9, 4, 3, 2, 1],
      "only eligible keys at this group and period compete, even after reopening storage",
    );

    const source = periodKeyCandidateSource({
      candidatesAt: reading.candidatesAt.bind(reading),
      attempted: () => {},
    });
    const nonce = new Uint8Array(12).fill(7);
    const contentKey = new Uint8Array(16).fill(42);
    const wrappingKey = await crypto.subtle.importKey("raw", newest, "AES-GCM", false, ["encrypt"]);
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, wrappingKey, contentKey),
    );
    const entry = { t, nonce: base64urlEncode(nonce), key: base64urlEncode(wrapped) };
    assert.equal(
      await attemptContentKeyWrap(entry, new Uint8Array(16).fill(4)),
      null,
      "the old generation does not authenticate the new wrap",
    );
    const attempts = [];
    let opened = null;
    for await (const candidate of source.attempts({
      accessGroup: "premium",
      entries: [entry],
      publisher: PUB,
      issuerNames,
    })) {
      attempts.push(candidate.periodKey[0]);
      opened ??= await attemptContentKeyWrap(entry, candidate.periodKey);
    }
    assert.deepEqual(attempts, [9, 4, 3, 2], "the four-attempt slice includes the newest key");
    assert.deepEqual(opened, contentKey, "the retained newest key opens the wrap");
  }
});

test("independent cache instances order simultaneous issuer filings in one realm", async () => {
  let releaseSets = () => {};
  const setGate = new Promise((resolve) => {
    releaseSets = resolve;
  });
  let allSetsReached = () => {};
  const allSets = new Promise((resolve) => {
    allSetsReached = resolve;
  });
  let waitingSets = 0;
  const storage = new Storage({
    gate({ op }) {
      if (op !== "set") return;
      if (++waitingSets === 5) allSetsReached();
      return setGate;
    },
  });

  const t = "260926T0900";
  const issuerNames = ["alpha", "bravo", "charlie", "delta", "echo"];
  const filings = issuerNames.map((issuerName, i) =>
    new PeriodKeyCache({ storage, keyBy: keyByIssuer }).put(
      "premium",
      t,
      new Uint8Array(16).fill(i + 1),
      { publisher: PUB, issuerName },
    ),
  );
  await allSets;
  releaseSets();
  await Promise.all(filings);

  const reopened = new PeriodKeyCache({ storage, keyBy: keyByIssuer });
  assert.deepEqual(
    (await reopened.candidatesAt("premium", t, { publisher: PUB, issuerNames })).map(
      (key) => key[0],
    ),
    [5, 4, 3, 2, 1],
    "five separate instances retain the order in which they filed after the same store read",
  );
  const source = periodKeyCandidateSource({
    candidatesAt: reopened.candidatesAt.bind(reopened),
    attempted: () => {},
  });
  const attempted = [];
  for await (const candidate of source.attempts({
    accessGroup: "premium",
    entries: [{ t }],
    publisher: PUB,
    issuerNames,
  })) {
    attempted.push(candidate.periodKey[0]);
  }
  assert.deepEqual(attempted, [5, 4, 3, 2], "the newest key survives the four-trial bound");
});

test("the reference cache has finite default storage and period-key rival limits", async () => {
  for (const storage of [undefined, new Storage()]) {
    const cache = new PeriodKeyCache(storage === undefined ? {} : { storage });
    for (let i = 0; i < 13; i++) {
      await cache.put(
        "premium",
        `251023T${String(i).padStart(2, "0")}00`,
        new Uint8Array(16).fill(i),
        {
          publisher: PUB,
        },
      );
    }
    assert.equal((await cache.entries()).length, 12, "the default retains twelve candidates");

    for (let i = 0; i < 5; i++) {
      await cache.put("rivals", "251024T1400", new Uint8Array(16).fill(i), { publisher: PUB });
    }
    assert.deepEqual(
      (await cache.candidatesAt("rivals", "251024T1400", { publisher: PUB })).map((key) => key[0]),
      [4, 3, 2, 1],
      "a fifth rival displaces the oldest candidate at one exact coordinate",
    );
  }
});

test("response-private keys survive the immediate attempt while ordinary retention stays independently usable", async () => {
  const key = new Uint8Array(16).fill(7);
  const retained = new PeriodKeyCache();
  const retainedLease = {};
  await retained.put("premium", "251023T1400", key, { publisher: PUB, lease: retainedLease });
  assert.deepEqual(
    await retained.candidatesAt("premium", "251023T1400", { publisher: PUB }),
    [key],
    "an ordinary later resolve sees the bounded filing without reusing the application report",
  );
  await retained.attempted({ lease: retainedLease });
  assert.deepEqual(
    await retained.candidatesAt("premium", "251023T1400", { publisher: PUB }),
    [key],
    "finishing the first-use operation discards only its private copy",
  );

  const lease = {};
  const forward = new PeriodKeyCache({
    clock: { now: () => new Date("2025-10-26T14:00:00Z") },
    evictionPolicy: evictAfterSixHours,
  });
  await forward.put("premium", "251023T1400", key, { publisher: PUB, lease });
  assert.deepEqual(
    await forward.candidatesAt("premium", "251023T1400", { publisher: PUB }),
    [],
    "a different operation cannot observe response-private material",
  );
  assert.deepEqual(
    await forward.candidatesAt("premium", "251023T1400", { publisher: PUB, lease }),
    [key],
    "the obtaining operation still tries it under a far-forward clock",
  );
  await forward.attempted({ lease });
  assert.deepEqual(
    await forward.entries(),
    [],
    "the later retained-cache policy may evict it normally",
  );

  const invalid = new PeriodKeyCache({
    clock: { now: () => new Date("not a date") },
    evictionPolicy: evictAfterSixHours,
  });
  const invalidLease = {};
  await invalid.put("premium", "251023T1400", key, { publisher: PUB, lease: invalidLease });
  assert.deepEqual(
    await invalid.candidatesAt("premium", "251023T1400", { publisher: PUB, lease: invalidLease }),
    [key],
  );
  await invalid.attempted({ lease: invalidLease });
  assert.deepEqual(
    await invalid.candidatesAt("premium", "251023T1400", { publisher: PUB }),
    [key],
    "an invalid host clock does not prevent immediate use or ordinary promotion",
  );
});

test("a cache store requires its publisher while a read without one remains a miss", async () => {
  const cache = new PeriodKeyCache();

  await assert.rejects(
    () => cache.put("premium", "251023T1400", new Uint8Array(16).fill(1)),
    (/** @type {any} */ err) => err.code === "bad_key",
  );
  assert.deepEqual(
    await cache.candidatesAt("premium", "251023T1400"),
    [],
    "a publisherless read takes the ordinary miss",
  );
  assert.deepEqual(await cache.entries(), [], "the refused key was not filed under a bare family");
});

test("an inherited accessGroup is not a cached family", async () => {
  const cache = new PeriodKeyCache();
  const key = new Uint8Array(16).fill(1);
  await cache.put("premium", "251023T1400", key, { publisher: PUB });

  assert.deepEqual(
    await cache.candidatesAt("premium", "251023T1400", { publisher: PUB }),
    [key],
    "the control reaches the coordinate the inherited names are tested against",
  );

  for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
    assert.deepEqual(
      await cache.candidatesAt(name, "251023T1400", { publisher: PUB }),
      [],
      `candidates('${name}') must not resolve`,
    );
  }
});

test("the cache accepts an eviction clock and callback, and refuses unknown options", () => {
  // `maxEntries` and `storage` are implemented now, and
  // test-reference/adapter-client/storage-concurrency.test.js covers what they do under two tabs.
  // `keyBy` arrived with the two issuers that give it a meaning, in
  // test/multi-issuer.test.js.
  assert.throws(
    () => new PeriodKeyCache({ clock: {} }),
    (/** @type {any} */ err) => err.code === "bad_config",
  );
  assert.throws(
    () => new PeriodKeyCache({ clock: new Clock(AT) }),
    (/** @type {any} */ err) => err.code === "bad_config",
  );
  assert.throws(
    () => new PeriodKeyCache({ evictionPolicy: /** @type {any} */ ({}) }),
    (/** @type {any} */ err) => err.code === "bad_config",
  );
  assert.throws(
    () => new PeriodKeyCache({ evictionPolicy: () => false }),
    (/** @type {any} */ err) => err.code === "bad_config",
  );
  for (const options of [{ ttl: 60 }]) {
    assert.throws(
      () => new PeriodKeyCache(options),
      (/** @type {any} */ err) => err.code === "unsupported_option",
      `${Object.keys(options)[0]} is not implemented, and is not pretended`,
    );
  }
});

test("leased opaque rivals in byte storage keep newest-first trials across issuers", async () => {
  const cache = new PeriodKeyCache({ storage: new Storage(), keyBy: keyByIssuer });
  const lease = {};
  const t = "260926T0900";
  const handles = [];
  for (let value = 1; value <= 5; value++) {
    const handle = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(value),
      "AES-GCM",
      false,
      ["unwrapKey"],
    );
    handles.push(handle);
    await cache.put("premium", t, handle, {
      publisher: PUB,
      issuerName: value === 5 ? "beta" : "alpha",
      lease,
    });
  }
  // Re-filing the same handle does not make it a newly acquired rival.
  await cache.put("premium", t, handles[0], { publisher: PUB, issuerName: "alpha", lease });
  const trials = [];
  for await (const trial of periodKeyCandidateSource(cache).attempts({
    accessGroup: "premium",
    entries: [{ t }],
    publisher: PUB,
    issuerNames: ["alpha", "beta"],
    lease,
  }))
    trials.push(trial.periodKey);
  assert.deepEqual(
    trials,
    handles.slice(1).reverse(),
    "the latest grant enters the four-rival trial bound first",
  );
  await cache.attempted({ lease });
  assert.deepEqual(
    await cache.candidatesAt("premium", t, { publisher: PUB, issuerNames: ["alpha", "beta"] }),
    [],
  );
});

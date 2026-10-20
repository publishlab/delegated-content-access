// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { decrypt } from "../../../core-shared/aead.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { base64urlDecode, utf8Decode } from "../../../core-shared/codec.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { periodKeysFromChainKey } from "../core-shared/chainKeyConstruction.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;
const AT = new Date("2025-10-23T14:20:00Z");
// Ten minutes into the second-to-last position of the 12:00-24:00 stationary window.
const NEAR_WINDOW_END = new Date("2025-10-23T23:40:00Z");
const ORIGIN = "https://www.news-site.example";

function watchedGeneration(generation, accessGroup, events) {
  return Object.freeze({
    geometry: generation.geometry,
    // Pass the wrapped generation's profile through: a planning supply reads
    // its widths off it.
    constructionProfile: generation.constructionProfile,
    coordinateFor: (t) => generation.coordinateFor(t),
    async periodKey(group, t) {
      assert.equal(group, accessGroup);
      events.push(`period-key:${group}:${t}`);
      return generation.periodKey(group, t);
    },
    async chainCapability(group, t) {
      assert.equal(group, accessGroup);
      events.push(`chain-key:${group}:${t}`);
      return generation.chainCapability(group, t);
    },
  });
}

async function publisherConfig({
  supply,
  planFor,
  events = [],
  at = AT,
  period = { length: 60, slots: 2 },
}) {
  const signing = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  let draw = 0;
  const seals = [];
  return {
    seals,
    config: {
      origin: ORIGIN,
      clock: { now: () => new Date(at.getTime()) },
      random: {
        bytes(n) {
          events.push(`random:${n}`);
          draw += 1;
          return new Uint8Array(n).fill(draw);
        },
      },
      signingKeys: { signing: signing.privateKey },
      period,
      periodKeySupply: supply,
      // Each case's plan chooses representations; the scope stays the whole render.
      issuerSupplyPlanFor: (issuer, render) => {
        const planned = planFor(issuer, render);
        return planned !== null && typeof planned === "object"
          ? { ...wholeRenderIssuerSupplyPlan(issuer, render), ...planned }
          : planned;
      },
      issuers: ["A", "B"].map((id) => ({
        issuerName: `issuer-${id.toLowerCase()}`,
        keyId: "key-1",
        algorithm: "rsa-oaep",
        publicKey: { id },
      })),
      keySealing: {
        async seal(key, publicKey, algorithm, options) {
          events.push(`seal:${options.binding.accessGroup ?? options.binding.contentName}`);
          seals.push({
            key: Uint8Array.from(key),
            publicKey,
            algorithm,
            binding: { ...options.binding },
          });
          return `sealed-${seals.length}`;
        },
      },
    },
  };
}

function addContent(sealer) {
  sealer.resource("article-1", { section: "news" });
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
  sealer.content("locked-data", '{"answer":42}', "application/json", { accessGroups: ["locked"] });
  return sealer;
}

test("one render plans each family once and supplies period keys, chain keys, or their explicit union per issuer", async () => {
  const events = [];
  const premiumGeneration = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const lockedGeneration = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(9),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({
    families: {
      premium: watchedGeneration(premiumGeneration, "premium", events),
      locked: watchedGeneration(lockedGeneration, "locked", events),
    },
    chainWindows: 2,
    chainItemSlots: 2,
  });
  const { config, seals } = await publisherConfig({
    supply,
    events,
    planFor: (issuer) =>
      issuer.issuerName === "issuer-a"
        ? { periodKeyDelivery: { premium: ["period-keys"], locked: ["chain-keys"] } }
        : {
            periodKeyDelivery: { premium: ["period-keys", "chain-keys"], locked: ["period-keys"] },
          },
  });

  const render = await addContent(new Sealer(config)).seal();
  const { dcaData } = render;

  assert.deepEqual(
    dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    ["251023T1415", "251023T1430"],
  );
  assert.deepEqual(
    dcaData.contentData["locked-data"].keys.locked.map(({ t }) => t),
    ["251023T1415", "251023T1430"],
  );
  assert.deepEqual(dcaData.periodGeometry, { chainsPerDay: 2, periodMinutes: 15 });

  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.periodKeys), ["premium"]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.chainKeys), ["locked"]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.periodKeys), [
    "premium",
    "locked",
  ]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.chainKeys), ["premium"]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.chainKeys.premium), [
    "251023T2345",
    "251024T1145",
  ]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.chainKeys.locked), [
    "251023T2345",
    "251024T1145",
  ]);

  assert.equal(
    events.filter((event) => event.startsWith("period-key:")).length,
    4,
    "one period-key acquisition per family coordinate",
  );
  assert.equal(
    events.filter((event) => event.startsWith("chain-key:")).length,
    4,
    "one chain-key acquisition per supplied family window",
  );
  assert.ok(
    events
      .slice(0, 8)
      .every((event) => event.startsWith("period-key:") || event.startsWith("chain-key:")),
    "all supplier acquisition finishes before the first entropy draw",
  );

  const periodKeySeal = seals.find(
    ({ publicKey, binding }) =>
      publicKey.id === "B" &&
      binding.accessGroup === "premium" &&
      binding.t === "251023T1415" &&
      binding.chainKey !== true,
  );
  const chainSeal = seals.find(
    ({ publicKey, binding }) =>
      publicKey.id === "B" &&
      binding.accessGroup === "premium" &&
      binding.suppliedT === "251023T2345" &&
      binding.chainKey === true,
  );
  assert.ok(periodKeySeal && chainSeal);
  assert.deepEqual(chainSeal.binding, {
    renderId: dcaData.resource.renderId,
    accessGroup: "premium",
    suppliedT: "251023T2345",
    chainKey: true,
    chainsPerDay: 2,
    periodMinutes: 15,
  });
  assert.deepEqual(
    chainSeal.key,
    (await premiumGeneration.chainCapability("premium", "251023T2345")).key,
    "the chain envelope carries the canonical positioned chain key",
  );
  const expanded = await premiumGeneration.expansion("premium", "251023T2345");
  assert.deepEqual(
    periodKeySeal.key,
    expanded.find(({ t }) => t === "251023T1415").key,
    "the period-key envelope carries the canonical period key the chain envelope reaches",
  );

  const wrap = dcaData.contentData.bodytext.keys.premium[0];
  const contentKey = await decrypt(
    periodKeySeal.key,
    base64urlDecode(wrap.nonce),
    base64urlDecode(wrap.key),
  );
  const plaintext = await decrypt(
    contentKey,
    new Uint8Array(12),
    base64urlDecode(render.sealedContent.bodytext),
    contentAadOctets(dcaData, "bodytext"),
  );
  assert.equal(
    utf8Decode(plaintext),
    "<p>Body</p>",
    "the same period key opens the shared content-side wrap",
  );
});

test("a chain-bearing render takes every wrap and both issuer routes of one family from its one selected generation", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({
    families: { premium: generation },
    chainWindows: 2,
    chainItemSlots: 2,
  });
  const { config, seals } = await publisherConfig({
    supply,
    planFor: (issuer) =>
      issuer.issuerName === "issuer-a"
        ? { periodKeyDelivery: { premium: ["period-keys"] } }
        : { periodKeyDelivery: { premium: ["chain-keys"] } },
  });
  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  const plaintexts = { bodytext: "<p>Body</p>", summary: "<p>Summary</p>" };
  for (const [name, text] of Object.entries(plaintexts)) {
    sealer.content(name, text, "text/html", { accessGroups: ["premium"] });
  }

  const render = await sealer.seal();
  const { dcaData } = render;
  // The recording keySealing returns `sealed-<n>` for its nth seal.
  const sealOf = (/** @type {string} */ sealed) =>
    seals[Number(sealed.slice("sealed-".length)) - 1];

  const periodKeyIssuer = dcaData.issuerData["issuer-a"].sealed;
  const chainIssuer = dcaData.issuerData["issuer-b"].sealed;
  assert.deepEqual(Object.keys(periodKeyIssuer.periodKeys), ["premium"]);
  assert.equal(Object.hasOwn(periodKeyIssuer, "chainKeys"), false);
  assert.deepEqual(Object.keys(chainIssuer.chainKeys), ["premium"]);
  assert.equal(Object.hasOwn(chainIssuer.periodKeys ?? {}, "premium"), false);

  /** @type {Map<string, Uint8Array>} */
  const periodKeyAt = new Map();
  for (const [t, sealed] of Object.entries(periodKeyIssuer.periodKeys.premium)) {
    const { publicKey, binding, key } = sealOf(sealed);
    assert.equal(publicKey.id, "A");
    assert.equal(binding.accessGroup, "premium");
    assert.equal(binding.t, t);
    periodKeyAt.set(t, key);
  }

  /** @type {Map<string, Uint8Array>} */
  const derivedPeriodKeyAt = new Map();
  const geometry = dcaData.periodGeometry;
  for (const [suppliedT, sealed] of Object.entries(chainIssuer.chainKeys.premium)) {
    const { publicKey, binding, key } = sealOf(sealed);
    assert.equal(publicKey.id, "B");
    assert.equal(binding.suppliedT, suppliedT);
    // Every sealed member, the next window's too, comes from the render's generation.
    assert.deepEqual(key, (await generation.chainCapability("premium", suppliedT)).key);
    for (const derived of await periodKeysFromChainKey({
      chainKey: key,
      accessGroup: "premium",
      suppliedT,
      cutoffT: suppliedT,
      geometry,
    })) {
      derivedPeriodKeyAt.set(derived.t, derived.key);
    }
  }

  assert.deepEqual([...periodKeyAt.keys()], ["251023T1415", "251023T1430"]);
  for (const [t, key] of periodKeyAt) {
    assert.deepEqual(
      derivedPeriodKeyAt.get(t),
      key,
      `${t}: the chain issuer's material derives the period key the period-key-only issuer holds`,
    );
    assert.deepEqual(key, await generation.periodKey("premium", t));
  }

  for (const [name, text] of Object.entries(plaintexts)) {
    const record = dcaData.contentData[name];
    assert.deepEqual(Object.keys(record.keys), ["premium"]);
    /** @type {Uint8Array[]} */
    const contentKeys = [];
    for (const [index, wrap] of record.keys.premium.entries()) {
      const where = `${name} premium wrap ${index} at ${wrap.t}`;
      const periodKey = periodKeyAt.get(wrap.t) ?? derivedPeriodKeyAt.get(wrap.t);
      assert.ok(periodKey, `${where}: the render's own issuer routes supply a period key there`);
      // A wrap under another generation's period key fails authentication here.
      const contentKey = await decrypt(
        periodKey,
        base64urlDecode(wrap.nonce),
        base64urlDecode(wrap.key),
      ).catch(() => null);
      assert.ok(contentKey, `${where}: opens under the render's own generation`);
      contentKeys.push(contentKey);
    }
    assert.ok(contentKeys.length > 0);
    for (const contentKey of contentKeys) assert.deepEqual(contentKey, contentKeys[0]);
    const plaintext = await decrypt(
      contentKeys[0],
      new Uint8Array(12),
      base64urlDecode(render.sealedContent[name]),
      contentAadOctets(dcaData, name),
    );
    assert.equal(utf8Decode(plaintext), text);
  }
});

test("a period-key-only family crosses a chain-window edge without supplying a chain", async () => {
  const events = [];
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ families: { premium: generation }, chainWindows: 1 });
  const { config, seals } = await publisherConfig({
    supply,
    planFor: () => ({ periodKeyDelivery: { premium: ["period-keys"] } }),
    at: NEAR_WINDOW_END,
    period: { length: 60, slots: 3 },
    events,
  });
  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });

  const { dcaData } = await sealer.seal();
  const periods = ["251023T2330", "251023T2345", "251024T0000"];
  assert.deepEqual(
    dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    periods,
  );
  for (const issuerName of ["issuer-a", "issuer-b"]) {
    assert.deepEqual(
      Object.keys(dcaData.issuerData[issuerName].sealed.periodKeys.premium),
      periods,
    );
    assert.equal(Object.hasOwn(dcaData.issuerData[issuerName].sealed, "chainKeys"), false);
  }
  assert.deepEqual(dcaData.periodGeometry, { chainsPerDay: 2, periodMinutes: 15 });
  assert.equal(events.filter((event) => event.startsWith("chain-key:")).length, 0);
  const periodKeySeal = seals.find(
    ({ publicKey, binding }) =>
      publicKey.id === "A" && binding.accessGroup === "premium" && binding.t === periods[2],
  );
  assert.deepEqual(periodKeySeal.key, await generation.periodKey("premium", periods[2]));
});

test("dual supply uses one current-window chain and only the selected next-window period-key source", async () => {
  const events = [];
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const stockSupply = periodFamilySupply({
    families: { premium: watchedGeneration(generation, "premium", events) },
    chainWindows: 1,
    chainItemSlots: 3,
  });
  const seenModes = [];
  const supply = {
    derive: stockSupply.derive,
    familyPlan(...args) {
      seenModes.push(args.slice(3));
      return stockSupply.familyPlan(...args);
    },
  };
  const { config, seals } = await publisherConfig({
    supply,
    events,
    at: NEAR_WINDOW_END,
    period: { length: 60, slots: 3 },
    planFor: (issuer, render) => {
      assert.equal(render.now.toISOString(), NEAR_WINDOW_END.toISOString());
      render.now.setUTCFullYear(2030); // A planner cannot change the captured render instant.
      return issuer.issuerName === "issuer-a"
        ? {
            contentKeyNames: [],
            periodKeyDelivery: { premium: ["period-keys", "chain-keys"] },
            periodKeySourceTs: { premium: ["251024T0000"] },
          }
        : { contentKeyNames: [], periodKeyDelivery: { premium: ["period-keys"] } };
    },
  });
  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
  const { dcaData } = await sealer.seal();
  assert.equal(dcaData.resource.issuedAt, NEAR_WINDOW_END.toISOString());
  assert.deepEqual(
    dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    ["251023T2330", "251023T2345", "251024T0000"],
  );
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.periodKeys.premium), [
    "251024T0000",
  ]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.chainKeys.premium), [
    "251023T2345",
  ]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.periodKeys.premium), [
    "251023T2330",
    "251023T2345",
    "251024T0000",
  ]);
  assert.equal(Object.hasOwn(dcaData.issuerData["issuer-b"].sealed, "chainKeys"), false);
  assert.equal(events.filter((event) => event.startsWith("chain-key:")).length, 1);
  assert.deepEqual(
    seenModes,
    [[true]],
    "a dual route still tells its provider that chain supply was selected",
  );
  const chain = seals.find(
    ({ publicKey, binding }) => publicKey.id === "A" && binding.chainKey === true,
  );
  const next = seals.find(
    ({ publicKey, binding }) => publicKey.id === "A" && binding.t === "251024T0000",
  );
  assert.deepEqual(chain.key, (await generation.chainCapability("premium", "251023T2345")).key);
  assert.deepEqual(next.key, await generation.periodKey("premium", "251024T0000"));
});

test("the ordinary T1 key remains identical when current at noon or midnight, without a second chain source", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const unrelated = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(8),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  for (const { at, nextAt, current, terminal, t1 } of [
    {
      at: "2025-10-23T11:40:00Z",
      nextAt: "2025-10-23T12:05:00Z",
      current: "251023T1130",
      terminal: "251023T1145",
      t1: "251023T1200",
    },
    {
      at: "2025-10-23T23:40:00Z",
      nextAt: "2025-10-24T00:05:00Z",
      current: "251023T2330",
      terminal: "251023T2345",
      t1: "251024T0000",
    },
  ]) {
    const supply = periodFamilySupply({
      families: { premium: generation },
      chainWindows: 1,
      chainItemSlots: 3,
    });
    const first = await publisherConfig({
      supply,
      at: new Date(at),
      period: { length: 60, slots: 3 },
      planFor: () => ({
        contentKeyNames: [],
        periodKeyDelivery: { premium: ["period-keys", "chain-keys"] },
        periodKeySourceTs: { premium: [t1] },
      }),
    });
    const firstSealer = new Sealer(first.config);
    firstSealer.resource("before-edge", {});
    firstSealer.content("bodytext", "before", "text/html", { accessGroups: ["premium"] });
    const before = await firstSealer.seal();
    const firstSealed = before.dcaData.issuerData["issuer-a"].sealed;
    assert.deepEqual(Object.keys(firstSealed.periodKeys.premium), [t1]);
    assert.deepEqual(Object.keys(firstSealed.chainKeys.premium), [terminal]);
    assert.deepEqual(
      before.dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
      [current, terminal, t1],
    );

    const second = await publisherConfig({
      supply: periodFamilySupply({ families: { premium: generation }, chainWindows: 1 }),
      at: new Date(nextAt),
      period: { length: 60, slots: 1 },
      planFor: () => ({
        contentKeyNames: [],
        periodKeyDelivery: { premium: ["period-keys", "chain-keys"] },
        periodKeySourceTs: { premium: [] },
      }),
    });
    const secondSealer = new Sealer(second.config);
    secondSealer.resource("after-edge", {});
    secondSealer.content("bodytext", "after", "text/html", { accessGroups: ["premium"] });
    const after = await secondSealer.seal();
    assert.equal(Object.hasOwn(after.dcaData.issuerData["issuer-a"].sealed, "periodKeys"), false);
    assert.deepEqual(
      after.dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
      [t1],
    );
    const key = first.seals.find(
      ({ publicKey, binding }) => publicKey.id === "A" && binding.t === t1,
    ).key;
    assert.deepEqual(key, await generation.periodKey("premium", t1));
    const opened = await decrypt(
      key,
      base64urlDecode(after.dcaData.contentData.bodytext.keys.premium[0].nonce),
      base64urlDecode(after.dcaData.contentData.bodytext.keys.premium[0].key),
    );
    const plaintext = await decrypt(
      opened,
      new Uint8Array(12),
      base64urlDecode(after.sealedContent.bodytext),
      contentAadOctets(after.dcaData, "bodytext"),
    );
    assert.equal(
      utf8Decode(plaintext),
      "after",
      `${t1}: prior T1 key opens a later current-period article`,
    );
    const unrelatedKey = await unrelated.periodKey("locked", t1);
    await assert.rejects(
      () =>
        decrypt(
          unrelatedKey,
          base64urlDecode(after.dcaData.contentData.bodytext.keys.premium[0].nonce),
          base64urlDecode(after.dcaData.contentData.bodytext.keys.premium[0].key),
        ),
      `${t1}: another group cannot open this wrap`,
    );
  }
});

test("source selectors and explicit promised reach refuse before any acquisition", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ families: { premium: generation }, chainWindows: 1 });
  const cases = [
    {
      name: "promised item with no matching source",
      plan: { periodKeySourceTs: { premium: [] }, reachableContentNames: ["bodytext"] },
      message: /must reach "bodytext" through a selected period source/,
    },
    {
      name: "unplanned source",
      plan: { periodKeySourceTs: { premium: ["251024T0015"] } },
      message: /unplanned period-key source/,
    },
    {
      name: "malformed source",
      plan: { periodKeySourceTs: { premium: ["not-a-period"] } },
      message: /unique YYMMDDTHHMM labels/,
    },
    {
      name: "duplicate source",
      plan: { periodKeySourceTs: { premium: ["251024T0000", "251024T0000"] } },
      message: /unique YYMMDDTHHMM labels/,
    },
    {
      name: "selector without ordinary mode",
      plan: { periodKeyDelivery: { premium: ["chain-keys"] }, periodKeySourceTs: { premium: [] } },
      message: /without period-key delivery/,
    },
    {
      name: "unsupplied group",
      plan: { periodKeySourceTs: { other: [] } },
      message: /unsupplied accessGroup/,
    },
  ];
  for (const { name, plan, message } of cases) {
    const events = [];
    const { config, seals } = await publisherConfig({
      supply,
      events,
      at: NEAR_WINDOW_END,
      period: { length: 60, slots: 3 },
      planFor: (issuer) =>
        issuer.issuerName === "issuer-a"
          ? { contentKeyNames: [], ...plan }
          : { contentKeyNames: [], periodKeyDelivery: { premium: ["period-keys"] } },
    });
    const sealer = new Sealer(config);
    sealer.resource("article-1", {});
    sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
    await assert.rejects(
      () => sealer.seal(),
      (error) => {
        assert.equal(error.code, "bad_config", name);
        assert.match(error.message, message, name);
        return true;
      },
    );
    assert.deepEqual(events, [], `${name}: no acquisition or entropy`);
    assert.deepEqual(seals, [], `${name}: no seal`);
  }
});

test("an item with no content-key seal and no source-reachable wrap is refused before acquisition", async () => {
  const events = [];
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ families: { premium: generation }, chainWindows: 1 });
  const { config, seals } = await publisherConfig({
    supply,
    events,
    planFor: () => ({
      contentKeyNames: [],
      periodKeyDelivery: { premium: ["period-keys"] },
      periodKeySourceTs: { premium: [] },
    }),
  });
  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
  await assert.rejects(
    () => sealer.seal(),
    /no complete issuer route for protected content "bodytext"/,
  );
  assert.deepEqual(events, []);
  assert.deepEqual(seals, []);
});

test("an empty ordinary-source selection does not emit a source-free issuer block", async () => {
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({ families: { premium: generation }, chainWindows: 1 });
  const { config } = await publisherConfig({
    supply,
    planFor: (issuer) =>
      issuer.issuerName === "issuer-a"
        ? { contentKeyNames: [], periodKeySourceTs: { premium: [] } }
        : { contentKeyNames: [], periodKeyDelivery: { premium: ["period-keys"] } },
  });
  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });

  const { dcaData } = await sealer.seal();
  assert.equal(Object.hasOwn(dcaData.issuerData, "issuer-a"), false);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.periodKeys.premium), [
    "251023T1415",
    "251023T1430",
  ]);
});

test("invalid delivery, missing chain route, and bad supplier output all refuse before entropy or sealing", async () => {
  const periodKeySupply = { derive: async () => new Uint8Array(32).fill(3) };
  const cases = [
    {
      name: "invalid delivery mode",
      supply: periodKeySupply,
      planFor: () => ({ periodKeyDelivery: { premium: ["future"] } }),
      code: "bad_config",
    },
    {
      name: "chain selection without a chain family route",
      supply: periodFamilySupply({ periodKeySupply, families: {}, chainWindows: 2 }),
      planFor: () => ({ periodKeyDelivery: { premium: ["chain-keys"] } }),
      code: "bad_config",
    },
    {
      name: "binding-unsafe planned label",
      supply: {
        derive: async () => new Uint8Array(32),
        familyPlan: () => ({
          periods: ["invalid|label"],
          periodKeyAt: async () => new Uint8Array(32),
        }),
      },
      planFor: () => ({}),
      code: "bad_config",
    },
    {
      name: "chain geometry past the shared position ceiling",
      supply: {
        derive: async () => new Uint8Array(32),
        familyPlan: () => ({
          periods: ["251023T1415"],
          periodKeyAt: async () => new Uint8Array(32),
          chain: {
            geometry: { chainsPerDay: 4, periodMinutes: 1 },
            suppliedTs: ["251023T1759"],
            capabilityAt: async () => new Uint8Array(32),
          },
        }),
      },
      planFor: () => ({ periodKeyDelivery: { premium: ["chain-keys"] } }),
      code: "bad_config",
      message: /carries valid complete geometry/,
    },
    {
      name: "wrong-width period-key supplier output",
      supply: {
        derive: async () => new Uint8Array(31),
        familyPlan: () => ({
          periods: ["251023T1415"],
          periodKeyAt: async () => new Uint8Array(31),
        }),
      },
      planFor: () => ({}),
      code: "bad_key",
    },
    {
      name: "supplier failure",
      supply: {
        derive: async () => {
          throw new Error("key service unavailable");
        },
        familyPlan: () => ({
          periods: ["251023T1415"],
          periodKeyAt: async () => {
            throw new Error("key service unavailable");
          },
        }),
      },
      planFor: () => ({}),
      message: /key service unavailable/,
    },
  ];

  for (const scenario of cases) {
    const events = [];
    const { config, seals } = await publisherConfig({
      supply: scenario.supply,
      planFor: scenario.planFor,
      period: { length: 15, slots: 2 },
      events,
    });
    const sealer = new Sealer(config);
    sealer.resource("article-1", {});
    sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
    await assert.rejects(
      () => sealer.seal(),
      (error) => {
        if (scenario.code) assert.equal(error.code, scenario.code, scenario.name);
        if (scenario.message) assert.match(error.message, scenario.message, scenario.name);
        return true;
      },
    );
    assert.deepEqual(
      events.filter((event) => event.startsWith("random:")),
      [],
      `${scenario.name}: no entropy`,
    );
    assert.deepEqual(seals, [], `${scenario.name}: no issuer seal`);
  }
});

test("the render instant is copied before asynchronous supplier work", async () => {
  const clockValue = new Date(AT.getTime());
  const supply = {
    derive: async () => new Uint8Array(16).fill(3),
    familyPlan: () => ({
      periods: ["251023T1415"],
      periodKeyAt: async () => {
        clockValue.setUTCHours(16);
        return new Uint8Array(16).fill(3);
      },
    }),
  };
  const { config } = await publisherConfig({
    supply,
    planFor: () => ({}),
    period: { length: 15, slots: 2 },
  });
  config.clock = { now: () => clockValue };

  const render = await addContent(new Sealer(config)).seal();
  assert.equal(render.dcaData.resource.issuedAt, AT.toISOString());
  assert.deepEqual(
    render.dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    ["251023T1415"],
  );
});

test("a chain-only source may leave T1 cached-only when a content-key route completes the item", async () => {
  const events = [];
  const seenModes = [];
  const premiumGeneration = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const stockSupply = periodFamilySupply({
    families: { premium: watchedGeneration(premiumGeneration, "premium", events) },
    chainWindows: 1,
    chainItemSlots: 4,
  });
  const supply = {
    derive: stockSupply.derive,
    familyPlan(...args) {
      seenModes.push(args.slice(3));
      return stockSupply.familyPlan(...args);
    },
  };
  const { config, seals } = await publisherConfig({
    supply,
    events,
    planFor: () => ({ periodKeyDelivery: { premium: ["chain-keys"] } }),
  });
  // Four 15-minute slots from 23:30 leave the window whose terminal supplies
  // this issuer's one capability.
  config.clock = { now: () => new Date(NEAR_WINDOW_END.getTime()) };
  config.period = { length: 60, slots: 4 };

  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });

  const render = await sealer.seal();
  assert.deepEqual(
    render.dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    ["251023T2330", "251023T2345", "251024T0000", "251024T0015"],
  );
  for (const issuerName of ["issuer-a", "issuer-b"]) {
    const sealed = render.dcaData.issuerData[issuerName].sealed;
    assert.deepEqual(Object.keys(sealed.chainKeys.premium), ["251023T2345"]);
    assert.deepEqual(Object.keys(sealed.contentKeys), ["bodytext"]);
    assert.equal(Object.hasOwn(sealed, "periodKeys"), false);
  }
  assert.deepEqual(seenModes, [[true]]);
  assert.ok(events.length > 0);
  assert.ok(seals.length > 0);
});

test("publisher rejects an off-grid ordinary family label before key acquisition", async () => {
  let acquisitions = 0;
  const supply = {
    derive: async () => {
      acquisitions++;
      return new Uint8Array(16);
    },
    familyPlan: () => ({
      periods: ["251023T1405"],
      periodMinutes: 15,
      periodKeyAt: async () => {
        acquisitions++;
        return new Uint8Array(16);
      },
    }),
  };
  const { config } = await publisherConfig({
    supply,
    period: { length: 15, slots: 2 },
    planFor: () => ({ periodKeyDelivery: { premium: ["period-keys"] } }),
  });
  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });
  await assert.rejects(
    sealer.seal(),
    (error) => error.code === "bad_config" && /align/.test(error.message),
  );
  assert.equal(acquisitions, 0);
});

test("publisher rejects different chain geometries before any family key acquisition", async () => {
  const events = [];
  const premium = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const locked = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(9),
    geometry: { chainsPerDay: 4, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({
    families: {
      premium: watchedGeneration(premium, "premium", events),
      locked: watchedGeneration(locked, "locked", events),
    },
    chainWindows: 2,
  });
  const { config } = await publisherConfig({
    supply,
    period: { length: 15, slots: 2 },
    planFor: () => ({ periodKeyDelivery: { premium: ["chain-keys"], locked: ["chain-keys"] } }),
  });
  await assert.rejects(
    addContent(new Sealer(config)).seal(),
    (error) => error.code === "bad_config" && /one period geometry/.test(error.message),
  );
  assert.deepEqual(events, []);
});

test("publisher chain reach requires the wrap's window and a supplied position at or above it", async () => {
  const geometry = { chainsPerDay: 2, periodMinutes: 15 };
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry,
  });
  const target = "251023T1430";
  for (const [source, reachable] of [
    [target, true],
    ["251024T1145", false],
    ["251023T1415", false],
  ]) {
    const events = [];
    const supply = {
      derive: async () => {
        throw new Error("not the selected family path");
      },
      familyPlan: () => ({
        periods: [target],
        periodKeyAt: async (t) => {
          events.push("period");
          return generation.periodKey("premium", t);
        },
        chain: {
          geometry,
          suppliedTs: [source],
          capabilityAt: async (t) => {
            events.push("chain");
            return (await generation.chainCapability("premium", t)).key;
          },
        },
      }),
    };
    const { config, seals } = await publisherConfig({
      supply,
      events,
      planFor: () => ({
        contentKeyNames: [],
        reachableContentNames: ["bodytext"],
        periodKeyDelivery: { premium: ["chain-keys"] },
      }),
    });
    const sealer = new Sealer(config);
    sealer.resource("chain-reach", {});
    sealer.content("bodytext", "reachable", "text/plain", { accessGroups: ["premium"] });
    if (reachable) {
      const rendered = await sealer.seal();
      assert.ok(rendered.dcaData.issuerData["issuer-a"].sealed.chainKeys.premium[source]);
      assert.ok(events.includes("period"));
    } else {
      await assert.rejects(
        sealer.seal(),
        (error) => error.code === "bad_config" && /must reach/.test(error.message),
      );
      assert.deepEqual(events, [], `${source}: refusal precedes acquisition and entropy`);
      assert.deepEqual(seals, []);
    }
  }
});

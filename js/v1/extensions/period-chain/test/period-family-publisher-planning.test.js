// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode, utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";

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
      events.push(`exact:${group}:${t}`);
      return generation.periodKey(group, t);
    },
    async chainCapability(group, t) {
      assert.equal(group, accessGroup);
      events.push(`chain:${group}:${t}`);
      return generation.chainCapability(group, t);
    },
  });
}

async function publisherConfig({ supply, planFor, events = [] }) {
  const signing = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  let draw = 0;
  const seals = [];
  return {
    seals,
    config: {
      origin: ORIGIN,
      clock: { now: () => new Date(AT.getTime()) },
      random: {
        bytes(n) {
          events.push(`random:${n}`);
          draw += 1;
          return new Uint8Array(n).fill(draw);
        },
      },
      signingKeys: { signing: signing.privateKey },
      period: { length: 60, slots: 2 },
      periodKeySupply: supply,
      issuerSupplyPlanFor: planFor,
      issuers: ["A", "B"].map((id) => ({
        issuerName: `issuer-${id.toLowerCase()}`,
        keyId: "key-1",
        algorithm: "RSA-OAEP",
        publicKey: { id },
        unlockUrl: `https://issuer-${id.toLowerCase()}.example/unlock`,
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

test("one render plans each family once and supplies exact, chain, or their explicit union per issuer", async () => {
  const events = [];
  const premiumGeneration = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const lockedGeneration = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(9),
    geometry: { chainsPerDay: 4, periodMinutes: 5 },
  });
  const supply = periodFamilySupply({
    families: {
      premium: watchedGeneration(premiumGeneration, "premium", events),
      locked: watchedGeneration(lockedGeneration, "locked", events),
    },
    chainWindows: 2,
  });
  const { config, seals } = await publisherConfig({
    supply,
    events,
    planFor: (issuer) =>
      issuer.issuerName === "issuer-a"
        ? { periodKeyDelivery: { premium: ["exact"], locked: ["chain"] } }
        : { periodKeyDelivery: { premium: ["exact", "chain"], locked: ["exact"] } },
  });

  const render = await addContent(new Sealer(config)).seal();
  const { dcaData } = render;

  assert.deepEqual(
    dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    ["251023T1415", "251023T1430"],
  );
  assert.deepEqual(
    dcaData.contentData["locked-data"].keys.locked.map(({ t }) => t),
    ["251023T1420", "251023T1425"],
  );
  assert.deepEqual(dcaData.periodChain, {
    accessGroups: {
      premium: { chainsPerDay: 2, periodMinutes: 15 },
      locked: { chainsPerDay: 4, periodMinutes: 5 },
    },
  });

  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.periodKeys), ["premium"]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.periodChainKeys), ["locked"]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.periodKeys), [
    "premium",
    "locked",
  ]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.periodChainKeys), ["premium"]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-b"].sealed.periodChainKeys.premium), [
    "251023T2345",
    "251024T1145",
  ]);
  assert.deepEqual(Object.keys(dcaData.issuerData["issuer-a"].sealed.periodChainKeys.locked), [
    "251023T1755",
    "251023T2355",
  ]);

  assert.equal(
    events.filter((event) => event.startsWith("exact:")).length,
    4,
    "one exact acquisition per family coordinate",
  );
  assert.equal(
    events.filter((event) => event.startsWith("chain:")).length,
    4,
    "one chain acquisition per supplied family window",
  );
  assert.ok(
    events.slice(0, 8).every((event) => event.startsWith("exact:") || event.startsWith("chain:")),
    "all supplier acquisition finishes before the first entropy draw",
  );

  const exactSeal = seals.find(
    ({ publicKey, binding }) =>
      publicKey.id === "B" &&
      binding.accessGroup === "premium" &&
      binding.t === "251023T1415" &&
      binding.periodChain !== true,
  );
  const chainSeal = seals.find(
    ({ publicKey, binding }) =>
      publicKey.id === "B" &&
      binding.accessGroup === "premium" &&
      binding.suppliedT === "251023T2345" &&
      binding.periodChain === true,
  );
  assert.ok(exactSeal && chainSeal);
  assert.deepEqual(chainSeal.binding, {
    renderId: dcaData.resource.renderId,
    accessGroup: "premium",
    suppliedT: "251023T2345",
    periodChain: true,
    chainsPerDay: 2,
    periodMinutes: 15,
  });
  assert.deepEqual(
    chainSeal.key,
    (await premiumGeneration.chainCapability("premium", "251023T2345")).key,
    "the chain envelope carries the canonical positioned state",
  );
  const expanded = await premiumGeneration.expansion("premium", "251023T2345");
  assert.deepEqual(
    exactSeal.key,
    expanded.find(({ t }) => t === "251023T1415").key,
    "the exact envelope carries the canonical leaf reached by the chain envelope",
  );

  const wrap = dcaData.contentData.bodytext.keys.premium[0];
  const contentKey = await decrypt(
    exactSeal.key,
    base64urlDecode(wrap.nonce),
    base64urlDecode(wrap.key),
  );
  const plaintext = await decrypt(
    contentKey,
    base64urlDecode(dcaData.contentData.bodytext.nonce),
    base64urlDecode(render.sealedContent.bodytext),
    utf8Encode(dcaData.contentData.bodytext.aad),
  );
  assert.equal(
    utf8Decode(plaintext),
    "<p>Body</p>",
    "the same exact leaf opens the shared content-side wrap",
  );
});

test("invalid delivery, missing chain route, and bad supplier output all refuse before entropy or sealing", async () => {
  const exactSupply = { derive: async () => new Uint8Array(32).fill(3) };
  const cases = [
    {
      name: "invalid delivery mode",
      supply: exactSupply,
      planFor: () => ({ periodKeyDelivery: { premium: ["future"] } }),
      code: "bad_config",
    },
    {
      name: "chain selection without a chain family route",
      supply: periodFamilySupply({ exactSupply, families: {}, chainWindows: 2 }),
      planFor: () => ({ periodKeyDelivery: { premium: ["chain"] } }),
      code: "bad_config",
    },
    {
      name: "binding-unsafe planned label",
      supply: {
        derive: async () => new Uint8Array(32),
        familyPlan: () => ({ periods: ["invalid|label"], exactAt: async () => new Uint8Array(32) }),
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
          exactAt: async () => new Uint8Array(32),
          chain: {
            geometry: { chainsPerDay: 4, periodMinutes: 1 },
            suppliedTs: ["251023T1759"],
            capabilityAt: async () => new Uint8Array(32),
          },
        }),
      },
      planFor: () => ({ periodKeyDelivery: { premium: ["chain"] } }),
      code: "bad_config",
      message: /carries valid complete geometry/,
    },
    {
      name: "wrong-width exact supplier output",
      supply: {
        derive: async () => new Uint8Array(31),
        familyPlan: () => ({ periods: ["251023T1415"], exactAt: async () => new Uint8Array(31) }),
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
          exactAt: async () => {
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
      exactAt: async () => {
        clockValue.setUTCHours(16);
        return new Uint8Array(16).fill(3);
      },
    }),
  };
  const { config } = await publisherConfig({ supply, planFor: () => ({}) });
  config.clock = { now: () => clockValue };

  const render = await addContent(new Sealer(config)).seal();
  assert.equal(render.dcaData.resource.issuedAt, AT.toISOString());
  assert.deepEqual(
    render.dcaData.contentData.bodytext.keys.premium.map(({ t }) => t),
    ["251023T1415"],
  );
});

test("a chain family reaching past its supplied windows refuses before any supplier call, entropy or seal", async () => {
  const events = [];
  const premiumGeneration = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: { chainsPerDay: 2, periodMinutes: 15 },
  });
  const supply = periodFamilySupply({
    families: { premium: watchedGeneration(premiumGeneration, "premium", events) },
    chainWindows: 1,
  });
  const { config, seals } = await publisherConfig({
    supply,
    events,
    planFor: () => ({ periodKeyDelivery: { premium: ["chain"] } }),
  });
  // Four 15-minute slots from 23:30 leave the window whose terminal supplies
  // this issuer's one capability.
  config.clock = { now: () => new Date(NEAR_WINDOW_END.getTime()) };
  config.period = { length: 60, slots: 4 };

  const sealer = new Sealer(config);
  sealer.resource("article-1", {});
  sealer.content("bodytext", "<p>Body</p>", "text/html", { accessGroups: ["premium"] });

  await assert.rejects(
    () => sealer.seal(),
    (error) => {
      assert.equal(error.code, "bad_config");
      assert.match(error.message, /no supplied period-chain capability reaches/);
      return true;
    },
  );
  assert.deepEqual(events, [], "no exact or chain supplier call, no entropy draw and no seal");
  assert.deepEqual(seals, []);
});

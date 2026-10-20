// @ts-check
// Enum-slot access is a scenario using existing independent access-group chains.
// These tests exercise ordinary chain composition, not common-root tree crypto.

import test from "node:test";
import assert from "node:assert/strict";
import { hkdfSync } from "node:crypto";
import { readFileSync } from "node:fs";

import { actorWorld, readArticle } from "../../../demo/scenarios/world.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { ISSUER_NAME } from "../../../demo/scenarios/fixtures.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { attemptContentKeyWrap } from "../../../core-client/contentKeyWrapAttempt.js";
import { decrypt } from "../../../core-shared/aead.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { base64urlDecode, utf8Decode } from "../../../core-shared/codec.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { ChainKeyRequest } from "../core-shared--client-issuer/ChainKeyRequest.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { referenceChainKeyProfile } from "../referenceProfile.js";
import { exchangesPosted } from "./world.js";

const GEOMETRY = Object.freeze({ chainsPerDay: 1, periodMinutes: 60 });
const DAY = "2026-10-07";
const BODY = "bodytext";
const SLOT = "slot8";
const SLOTS = Object.freeze(Array.from({ length: 10 }, (_, index) => `slot${index + 1}`));
const SECTION_TO_SLOT = Object.freeze({ sports: SLOT, politics: "slot7" });
const WINDOW = Date.parse(`${DAY}T00:00:00Z`) / 60_000;
const SELECTED = Object.freeze([label(0), label(2), label(4)]);
const jsonBytes = (value) => Buffer.byteLength(JSON.stringify(value), "utf8");

/** @param {number} position @param {string} [day] */
function label(position, day = DAY) {
  return `${day.slice(2).replaceAll("-", "")}T${String(position).padStart(2, "0")}00`;
}
/** @param {number} position @param {string} [day] */
function instant(position, day = DAY) {
  return `${day}T${String(position).padStart(2, "0")}:00:00Z`;
}
/** @param {string} slot */
function secretFor(slot) {
  assert.ok(SLOTS.includes(slot));
  // One publisher-scoped secret across all slots makes omitted family context
  // observable; slot isolation must come from the canonical transcript.
  return new Uint8Array(32).fill(7);
}

// Independent transcript encoder: §6.4 of docs/spec-profile--chain-keys.md. Expected
// bytes come from Node's stock HKDF, without a production context builder.
/** @param {number} domain @param {string} group @param {any} geometry @param {number} windowStart @param {number} position */
function info(domain, group, geometry, windowStart, position) {
  const construction = Buffer.from("dca-construction-chain-keys", "utf8");
  const name = Buffer.from(group, "utf8");
  const bytes = Buffer.alloc(1 + 2 + construction.length + 2 + name.length + 2 + 2 + 4 + 2);
  let at = 0;
  bytes.writeUInt8(domain, at++);
  bytes.writeUInt16BE(construction.length, at);
  at += 2;
  construction.copy(bytes, at);
  at += construction.length;
  bytes.writeUInt16BE(name.length, at);
  at += 2;
  name.copy(bytes, at);
  at += name.length;
  bytes.writeUInt16BE(geometry.chainsPerDay, at);
  at += 2;
  bytes.writeUInt16BE(geometry.periodMinutes, at);
  at += 2;
  bytes.writeUInt32BE(windowStart, at);
  at += 4;
  bytes.writeUInt16BE(position, at);
  return bytes;
}
/** @param {Uint8Array} input @param {Uint8Array} context */
function hkdf(input, context) {
  return new Uint8Array(hkdfSync("sha256", input, new Uint8Array(), context, 16));
}
/** @param {string} slot @param {number} position @param {number} [windowStart] */
function expectedChain(slot, position, windowStart = WINDOW) {
  let key = hkdf(secretFor(slot), info(1, slot, GEOMETRY, windowStart, 23));
  for (let index = 22; index >= position; index--)
    key = hkdf(key, info(2, slot, GEOMETRY, windowStart, index));
  return key;
}
/** @param {string} slot @param {number} position @param {number} [windowStart] */
function expectedPeriod(slot, position, windowStart = WINDOW) {
  return hkdf(
    expectedChain(slot, position, windowStart),
    info(3, slot, GEOMETRY, windowStart, position),
  );
}

/**
 * A local supply configuration of the existing public familyPlan seam. Stock
 * planning supplies C23; this adapter supplies C12 from the same 24-position
 * generation, preserving the item-wrap plan and the terminal Root at C23.
 * @param {Record<string, any>} families @param {number} suppliedPosition
 */
function positionedSupply(families, suppliedPosition) {
  const ordinary = periodFamilySupply({ families, chainWindows: 1 });
  return Object.freeze({
    derive: ordinary.derive,
    familyPlan(group, now, period, chainRequested) {
      const plan = /** @type {any} */ (ordinary.familyPlan(group, now, period, chainRequested));
      const suppliedT = label(suppliedPosition, now.toISOString().slice(0, 10));
      return Object.freeze({
        ...plan,
        chain: Object.freeze({
          geometry: plan.chain.geometry,
          suppliedTs: Object.freeze([suppliedT]),
          async capabilityAt(t) {
            assert.equal(t, suppliedT);
            return (await families[group].chainCapability(group, t)).key;
          },
        }),
      });
    },
  });
}

/** @param {{ representation?: 'chain-keys'|'period-keys', suppliedPosition?: number, permits?: (t: string) => boolean, futurePeriodCount?: number, requestedPeriods?: readonly string[] }} [options] */
async function setup({
  representation = "chain-keys",
  suppliedPosition = 12,
  permits = (t) => t >= label(0) && t <= label(4),
  futurePeriodCount = 5,
  requestedPeriods,
} = {}) {
  const families = Object.fromEntries(
    SLOTS.map((slot) => [
      slot,
      periodFamilyGeneration({
        keyDerivationSecret: secretFor(slot),
        geometry: GEOMETRY,
      }),
    ]),
  );
  const policyClaims = [];
  const world = await actorWorld({
    at: instant(0),
    period: { length: 60, slots: 1 },
    periodKeySupply: positionedSupply(families, suppliedPosition),
    issuerSupplyPlanFor: (_issuer, render) => ({
      contentKeyNames: [],
      suppliedAccessGroups: render.accessGroups,
      reachableContentNames: render.contentNames,
      periodKeyDelivery: Object.fromEntries(
        render.accessGroups.map((group) => [group, ["chain-keys"]]),
      ),
    }),
    chainKeyProfile:
      representation === "chain-keys"
        ? referenceChainKeyProfile
        : {
            ...referenceChainKeyProfile,
            issuerEngineFor: referenceChainKeyProfile.explicitIssuerEngineFor,
          },
    chainKeyCacheFactory: (options) => new ChainKeyCache(options),
    primary: { periodGrantKind: "chain-keys" },
    accessPolicy: {
      decide(claims, requested) {
        policyClaims.push(claims);
        // Membership comes from verified publisher metadata and issuer-held
        // configuration. Unsigned requested group names select no entitlement.
        const slot = SECTION_TO_SLOT[claims.resource.data.section];
        assert.equal(claims.resource.data.slot, slot);
        return {
          contentNames: [],
          periodGrants: requested.accessGroups.map((group) => ({
            accessGroup: group,
            futurePeriodCount,
            authorizePeriod: (t) => group === SLOT && slot === SLOT && permits(t),
          })),
        };
      },
    },
  });
  const chainCache = new ChainKeyCache();
  const periodCache = new PeriodKeyCache();
  const browser = world.makeBrowser({
    chainKeyStrategy: "retain",
    chainKeyCacheFactory: () => chainCache,
    cacheFactory: () => periodCache,
    requestBuilderFactory: (options) => {
      const builder = new ChainKeyRequestBuilder(options);
      if (requestedPeriods === undefined) return builder;
      // Explicit synthetic issuer-selection input; the ordinary A relay still
      // has only A's coordinate. Return a real request so admission, response
      // association and the network recorder all see the same selected hints.
      return {
        build(page, issuerName, needed) {
          const request = builder.build(page, issuerName, needed);
          return new ChainKeyRequest({
            ...request.toObject(),
            requestedPeriodKeys: { [SLOT]: [...requestedPeriods] },
          });
        },
      };
    },
  });
  return { world, families, browser, chainCache, periodCache, policyClaims };
}

/** @param {any} world @param {string} id @param {number} position @param {string} [slot] @param {string} [day] */
async function render(world, id, position, slot = SLOT, day = DAY) {
  world.clock.set(instant(position, day));
  const section = slot === SLOT ? "sports" : "politics";
  const text = `Article ${id}: ${section} at ${label(position, day)}.`;
  const page = await world.publisher.render({
    resourceId: `article-${id}`,
    data: { section, slot },
    items: [{ name: BODY, value: text, contentType: "text/plain", accessGroups: [slot] }],
  });
  return { page, text, position, slot, day };
}
/** @param {any} fixture */
function wrapOf(fixture) {
  return fixture.page.asJson().contentData[BODY].keys[fixture.slot][0];
}
/** @param {any} fixture @param {Uint8Array} periodKey */
async function openWrap(fixture, periodKey) {
  // The ordinary v1 content-key wrap uses no AAD. Item encryption has its own
  // content AAD, derived from the token and the item; do not invent a
  // coordinate wrap AAD.
  return attemptContentKeyWrap(wrapOf(fixture), periodKey);
}
/** @param {any} fixture */
async function positiveControl(fixture) {
  const windowStart = Date.parse(`${fixture.day}T00:00:00Z`) / 60_000;
  const cK = await openWrap(fixture, expectedPeriod(fixture.slot, fixture.position, windowStart));
  assert.ok(cK instanceof Uint8Array);
  assert.equal(cK.length, 16);
  const doc = fixture.page.asJson();
  const body = await decrypt(
    cK,
    new Uint8Array(12),
    base64urlDecode(doc.sealedContent[BODY]),
    contentAadOctets(doc, BODY),
  );
  assert.equal(utf8Decode(body), fixture.text);
  return cK;
}
/** @param {any} browser @param {any} fixture @param {boolean} opens */
async function cachedOpening(browser, fixture, opens) {
  const load = browser.load(rootFromPage(fixture.page));
  const { missing } = await load.resolve([BODY]);
  assert.deepEqual(missing, opens ? [] : [BODY]);
  const opened = await load.open(BODY);
  assert.equal(opened.error, opens ? null : "no_key");
  assert.equal(
    opened.bytes === null ? null : utf8Decode(opened.bytes),
    opens ? fixture.text : null,
  );
}
/** @param {any} world @param {string} group @param {string} t */
function cacheContext(world, group, t) {
  void group;
  void t;
  return { publisher: world.publisher.origin, ...GEOMETRY };
}
/** @param {any} fixture @param {any} response */
function ledger(fixture, response) {
  const doc = fixture.page.asJson();
  const entry = wrapOf(fixture);
  const source = doc.issuerData[ISSUER_NAME].sealed.chainKeys;
  const rawResponse = Object.values(response.keys.chainKeys ?? response.keys.periodKeys)
    .flatMap((family) => Object.values(family))
    .reduce((sum, value) => sum + base64urlDecode(value).length, 0);
  return {
    serialization:
      "Buffer.byteLength(JSON.stringify(value), 'utf8'); compact object serialization, not HTTP bytes",
    itemKeyMapJson: jsonBytes(doc.contentData[BODY].keys),
    sourceMapJson: jsonBytes(source),
    deliveryJson: jsonBytes(doc),
    responseJson: jsonBytes(response),
    itemWrapPayload: base64urlDecode(entry.nonce).length + base64urlDecode(entry.key).length,
    sourcePayload: base64urlDecode(source[SLOT][label(12)]).length,
    responsePayload: rawResponse,
  };
}

test("independent enum-slot HKDF oracle reproduces recorded Root, Step and Leaf bytes", () => {
  const vectors = JSON.parse(
    readFileSync(
      new URL("./fixtures/dca-profile-chain-keys.vectors.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(vectors.status, "canonical-16");
  const row = vectors.cases[0];
  const geometry = { chainsPerDay: row.chainsPerDay, periodMinutes: row.periodMinutes };
  for (const [domain, position, recorded] of [
    [1, row.N - 1, row.rootInfoHex],
    [2, row.N - 2, row.stepInfoHex],
    [3, row.position, row.leafInfoHex],
  ])
    assert.equal(
      info(domain, row.accessGroup, geometry, row.windowStart, position).toString("hex"),
      recorded,
    );
  let chain = hkdf(Buffer.from(row.secretHex, "hex"), Buffer.from(row.rootInfoHex, "hex"));
  assert.equal(Buffer.from(chain).toString("base64url"), row.rootChainKey);
  chain = hkdf(chain, Buffer.from(row.stepInfoHex, "hex"));
  assert.equal(Buffer.from(chain).toString("base64url"), row.chainKeyAfterOneStep);
  for (let position = row.N - 3; position >= row.position; position--)
    chain = hkdf(chain, info(2, row.accessGroup, geometry, row.windowStart, position));
  assert.equal(
    Buffer.from(hkdf(chain, Buffer.from(row.leafInfoHex, "hex"))).toString("base64url"),
    row.periodKey,
  );
});

test("slot8 C12 supply returns future C4, opens fresh prefix articles and preserves slot/window limits", async (t) => {
  const { world, families, browser, chainCache, policyClaims } = await setup();
  assert.equal(SLOTS.length, 10);
  for (const position of [0, 4, 12, 23]) {
    const coordinate = families[SLOT].coordinateFor(label(position));
    assert.equal(coordinate.position, position);
    assert.equal(coordinate.windowStart, WINDOW);
    assert.deepEqual(
      (await families[SLOT].chainCapability(SLOT, label(position))).key,
      expectedChain(SLOT, position),
    );
  }
  const a = await render(world, "A", 0);
  const doc = a.page.asJson();
  assert.deepEqual(Object.keys(doc.contentData[BODY].keys), [SLOT]);
  assert.deepEqual(
    doc.contentData[BODY].keys[SLOT].map((entry) => entry.t),
    [label(0)],
  );
  assert.equal(base64urlDecode(wrapOf(a).nonce).length, 12);
  assert.equal(base64urlDecode(wrapOf(a).key).length, 32);
  const sealed = doc.issuerData[ISSUER_NAME].sealed;
  assert.deepEqual(Object.keys(sealed.chainKeys), [SLOT]);
  assert.deepEqual(Object.keys(sealed.chainKeys[SLOT]), [label(12)]);
  assert.equal(base64urlDecode(sealed.chainKeys[SLOT][label(12)]).length, 109);
  assert.deepEqual(Object.keys(sealed.contentKeys ?? {}), []);
  assert.equal(sealed.periodKeys, undefined);
  const { result, exchanges } = await exchangesPosted(world.network, () =>
    readArticle(browser, a.page, [BODY]),
  );
  assert.equal(result.unlock.ok, true, JSON.stringify(exchanges));
  assert.equal(result.texts[BODY], a.text);
  assert.equal(exchanges.length, 1);
  assert.equal(exchanges[0].status, 200);
  assert.deepEqual(exchanges[0].request.requestedPeriodKeys, { [SLOT]: [label(0)] });
  assert.deepEqual(exchanges[0].request.sealed.chainKeys, sealed.chainKeys);
  assert.deepEqual(policyClaims[0].resource.data, { section: "sports", slot: SLOT });
  const response = exchanges[0].body;
  assert.deepEqual(Object.keys(response.keys.chainKeys), [SLOT]);
  assert.deepEqual(Object.keys(response.keys.chainKeys[SLOT]), [label(4)]);
  const c4 = base64urlDecode(response.keys.chainKeys[SLOT][label(4)]);
  assert.equal(c4.length, 16);
  assert.deepEqual(c4, expectedChain(SLOT, 4));
  assert.equal(response.keys.periodKeys, undefined);
  assert.deepEqual(Object.keys(response.keys.contentKeys ?? {}), []);
  assert.equal(Object.hasOwn(response, "periodGeometry"), false);
  assert.deepEqual(exchanges[0].request.periodGeometry, GEOMETRY);
  assert.deepEqual(
    await chainCache.candidates(SLOT, label(0), cacheContext(world, SLOT, label(0))),
    [expectedPeriod(SLOT, 0)],
  );
  assert.equal(await openWrap(a, c4), null, "a chain key is not an AES item-wrap period key");
  const b = await render(world, "B", 3);
  const aKey = await positiveControl(a);
  const bKey = await positiveControl(b);
  assert.notDeepEqual(aKey, bKey, "fresh independently encrypted article has a fresh cK");
  const cached = await exchangesPosted(world.network, () => readArticle(browser, b.page, [BODY]));
  assert.equal(cached.result.unlock, null);
  assert.equal(cached.result.texts[BODY], b.text);
  assert.equal(cached.exchanges.length, 0);
  assert.deepEqual(
    await chainCache.candidates(SLOT, label(3), cacheContext(world, SLOT, label(3))),
    [expectedPeriod(SLOT, 3)],
  );
  for (const row of [
    { name: "cutoff4 included", position: 4, slot: SLOT, day: DAY, opens: true },
    { name: "slot7 isolated", position: 0, slot: "slot7", day: DAY, opens: false },
    { name: "position5 excluded", position: 5, slot: SLOT, day: DAY, opens: false },
    {
      name: "next daily window isolated",
      position: 0,
      slot: SLOT,
      day: "2026-10-08",
      opens: false,
    },
  ]) {
    await t.test(row.name, async () => {
      const page = await render(
        world,
        row.name.replaceAll(" ", "-"),
        row.position,
        row.slot,
        row.day,
      );
      await positiveControl(page);
      const checked = await exchangesPosted(world.network, () =>
        cachedOpening(browser, page, row.opens),
      );
      assert.equal(checked.exchanges.length, 0);
      if (!row.opens) {
        assert.deepEqual(
          await chainCache.candidates(
            row.slot,
            label(row.position, row.day),
            cacheContext(world, row.slot, label(row.position, row.day)),
          ),
          [],
        );
        for (let index = 0; index <= 4; index++)
          assert.equal(
            await openWrap(page, expectedPeriod(SLOT, index)),
            null,
            `held P${index} fails authentication`,
          );
      }
    });
  }
  // One P4 is independently usable at4 and supplies no chain for earlier A.
  const onlyP4 = new PeriodKeyCache();
  await onlyP4.put(SLOT, label(4), expectedPeriod(SLOT, 4), { publisher: world.publisher.origin });
  const periodBrowser = world.makeBrowser({
    cacheFactory: () => onlyP4,
    chainKeyCacheFactory: () => new ChainKeyCache(),
    requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
  });
  world.clock.set(instant(4));
  const at4 = await render(world, "P4-control", 4);
  const control = await exchangesPosted(world.network, async () => {
    await cachedOpening(periodBrowser, at4, true);
    await cachedOpening(periodBrowser, a, false);
  });
  assert.equal(control.exchanges.length, 0);
  assert.equal(await openWrap(a, expectedPeriod(SLOT, 4)), null);
  const sizes = ledger(a, response);
  assert.equal(sizes.itemWrapPayload, 44);
  assert.equal(sizes.sourcePayload, 109);
  assert.equal(sizes.responsePayload, 16);
  t.diagnostic(`chain response byte ledger: ${JSON.stringify(sizes)}`);
});

test("sparse selected period output returns only canonical0,2,4 and caches those coordinates", async (t) => {
  const { world, browser, periodCache, chainCache } = await setup({
    representation: "period-keys",
    futurePeriodCount: 0,
    requestedPeriods: SELECTED,
    permits: (coordinate) => SELECTED.includes(coordinate),
  });
  const a = await render(world, "A", 0);
  // Extra hints are issuer-selection test input, not the stock one-article
  // client's relay behavior. Policy authorizes each coordinate independently.
  const { result, exchanges } = await exchangesPosted(world.network, () =>
    readArticle(browser, a.page, [BODY]),
  );
  assert.equal(result.unlock.ok, true, JSON.stringify(exchanges));
  assert.equal(result.texts[BODY], a.text);
  assert.equal(exchanges.length, 1);
  assert.deepEqual(exchanges[0].request.requestedPeriodKeys, { [SLOT]: [...SELECTED] });
  const response = exchanges[0].body;
  assert.equal(response.keys.chainKeys, undefined);
  assert.deepEqual(Object.keys(response.keys.periodKeys), [SLOT]);
  assert.deepEqual(Object.keys(response.keys.periodKeys[SLOT]), SELECTED);
  assert.deepEqual(Object.keys(response.keys.contentKeys ?? {}), []);
  assert.equal(
    chainCache.entries().some((entry) => entry.kind === "chain-key"),
    false,
  );
  for (const position of [0, 2, 4]) {
    const key = base64urlDecode(response.keys.periodKeys[SLOT][label(position)]);
    assert.deepEqual(key, expectedPeriod(SLOT, position));
    assert.deepEqual(
      await periodCache.candidatesAt(SLOT, label(position), { publisher: world.publisher.origin }),
      [key],
    );
  }
  for (const position of [0, 1, 2, 3, 4]) {
    await t.test(`cached position${position}`, async () => {
      const fixture = await render(world, `selected-${position}`, position);
      await positiveControl(fixture);
      const opens = [0, 2, 4].includes(position);
      const checked = await exchangesPosted(world.network, () =>
        cachedOpening(browser, fixture, opens),
      );
      assert.equal(checked.exchanges.length, 0);
      if (!opens)
        for (const granted of [0, 2, 4])
          assert.equal(await openWrap(fixture, expectedPeriod(SLOT, granted)), null);
    });
  }
  // Keep A's entry unchanged and demonstrate its two legitimate opening inputs.
  const original = JSON.stringify(wrapOf(a));
  const individual = base64urlDecode(response.keys.periodKeys[SLOT][label(0)]);
  const chain = new ChainKeyCache();
  await chain.put(SLOT, label(4), expectedChain(SLOT, 4), cacheContext(world, SLOT, label(4)));
  const [derived] = await chain.candidates(SLOT, label(0), cacheContext(world, SLOT, label(0)));
  assert.deepEqual(await openWrap(a, individual), await openWrap(a, derived));
  assert.equal(JSON.stringify(wrapOf(a)), original);
  const sizes = ledger(a, response);
  assert.equal(sizes.responsePayload, 48);
  t.diagnostic(`selected-period response byte ledger: ${JSON.stringify(sizes)}`);
});

test("fresh acquisition cannot exceed absent or earlier supply, or a denied prefix member", async (t) => {
  for (const row of [
    {
      name: "absent supply",
      suppliedPosition: 12,
      omit: true,
      permits: (t) => t >= label(0) && t <= label(4),
      cutoff: null,
    },
    {
      name: "earlier authentic C3",
      suppliedPosition: 3,
      omit: false,
      permits: (t) => t >= label(0) && t <= label(4),
      cutoff: 3,
    },
    {
      name: "denied prefix position2",
      requestedPeriods: [label(0), label(4)],
      suppliedPosition: 12,
      omit: false,
      permits: (t) => t >= label(0) && t <= label(4) && t !== label(2),
      cutoff: 1,
    },
  ]) {
    await t.test(row.name, async () => {
      const { world, browser, families } = await setup(row);
      const a = await render(world, "A", 0);
      if (row.omit) {
        const post = world.network.post.bind(world.network);
        world.network.post = (url, request, options) => {
          const input = structuredClone(request);
          delete input.sealed.chainKeys;
          return post(url, input, options);
        };
      }
      const checked = await exchangesPosted(world.network, () =>
        readArticle(browser, a.page, [BODY]),
      );
      assert.equal(checked.exchanges.length, 1);
      if (row.requestedPeriods !== undefined)
        assert.deepEqual(checked.exchanges[0].request.requestedPeriodKeys, {
          [SLOT]: row.requestedPeriods,
        });
      const returned = checked.exchanges[0].body.keys?.chainKeys?.[SLOT] ?? {};
      assert.deepEqual(Object.keys(returned), row.cutoff === null ? [] : [label(row.cutoff)]);
      assert.equal(Object.hasOwn(returned, label(4)), false);
      if (row.cutoff !== null)
        assert.deepEqual(
          base64urlDecode(returned[label(row.cutoff)]),
          expectedChain(SLOT, row.cutoff),
        );
      assert.equal(checked.result.texts[BODY], row.cutoff === null ? null : a.text);
      // The publisher cannot promise a chain-only route for a new position 4
      // while sealing only C3. Publish that control with a complete C12 source;
      // the client's previously granted C3 still cannot reach its wrap.
      if (row.suppliedPosition === 3)
        world.publisher.rotatePeriodKeySupply(positionedSupply(families, 12));
      const at4 = await render(world, "unavailable-4", 4);
      await positiveControl(at4);
      const noMore = await exchangesPosted(world.network, () => cachedOpening(browser, at4, false));
      assert.equal(noMore.exchanges.length, 0);
    });
  }
});

test("equal prefix authority can return C4 or five canonical period keys", async (t) => {
  const { world, browser } = await setup({ representation: "period-keys" });
  const a = await render(world, "A", 0);
  const { result, exchanges } = await exchangesPosted(world.network, () =>
    readArticle(browser, a.page, [BODY]),
  );
  assert.equal(result.unlock.ok, true);
  assert.equal(result.texts[BODY], a.text);
  assert.equal(exchanges.length, 1);
  assert.deepEqual(exchanges[0].request.requestedPeriodKeys, { [SLOT]: [label(0)] });
  const response = exchanges[0].body;
  assert.equal(response.keys.chainKeys, undefined);
  assert.deepEqual(Object.keys(response.keys.periodKeys), [SLOT]);
  assert.deepEqual(
    Object.keys(response.keys.periodKeys[SLOT]),
    Array.from({ length: 5 }, (_, index) => label(index)),
  );
  // The same authority as the C4 response above: all period keys in prefix0..4.
  const chain = new ChainKeyCache();
  await chain.put(SLOT, label(4), expectedChain(SLOT, 4), cacheContext(world, SLOT, label(4)));
  for (let position = 0; position <= 4; position++) {
    const period = base64urlDecode(response.keys.periodKeys[SLOT][label(position)]);
    assert.deepEqual(period, expectedPeriod(SLOT, position));
    assert.deepEqual(
      await chain.candidates(SLOT, label(position), cacheContext(world, SLOT, label(position))),
      [period],
    );
  }
  const sizes = ledger(a, response);
  assert.equal(sizes.responsePayload, 80);
  t.diagnostic(`equal-prefix period response byte ledger: ${JSON.stringify(sizes)}`);
});

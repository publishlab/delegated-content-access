// Content groups over the stock chain-key construction, through the production
// roles: `createPublisher` with the publisher contribution, `createIssuerCore`
// with the issuer contribution and `createDeliveryClient` with the client
// bundle, over the real period-key and chain-key caches. These are the access
// and binding checks that need the stock Root/Step/Leaf derivation, which the
// extension's own tests may not import.
//
// Each test that replaces an assertion of the retired form says which: that
// form carried a root `contentGroups` array, connector arrays with `null`
// placeholders, a publisher-wide window seed and the response member
// `contentGroupChains`. This form carries one `{group, connector}` record per
// item route, a `{contentName, windowStart, key}` seed record under
// `contentWindowSeeds`, and the response member `contentGroupKeys` as named
// records. Record order on the wire means nothing, so lists compare sorted.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { base64urlEncode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { sign } from "../../../core-shared--publisher-issuer/jwt.js";
import { openContent } from "../../../core-client/openContent.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import {
  chainKeyFromChainKey,
  chainKeyLeafPrimitive,
  chainKeyStepPrimitive,
} from "../../chain-keys/core-shared/chainKeyConstruction.js";
import { periodFamilyGeneration } from "../../chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { seedHandle } from "../core-shared--publisher-issuer/seedHandle.js";
import {
  CONTRACT,
  contentNameSeed,
  contentNameSeedAad,
  frame,
  itemPad,
  publisherNamespace,
  settleLimits,
  xor16,
} from "../core-shared/construction.js";
import { openSeed } from "../core-shared/seed-envelope.js";
import {
  CHAIN,
  GEOMETRY,
  NEXT,
  PUBLISHER,
  SECRET,
  T12,
  T18,
  T19,
  chainPolicy,
  claimsOf,
  copy,
  item,
  names,
  world,
} from "./_lib/world.js";
import {
  connectorOf,
  connectorsOf,
  cutoffRecords,
  find,
  findAll,
  groupRecords,
  issuerBlock,
  item as pageItem,
  seedOf,
} from "./_lib/records.js";

const T13 = "261014T1300";
const T14 = "261014T1400";
const T15 = "261014T1500";
const NOON2 = "261015T1200";

function text(bytes) {
  return bytes === null ? null : new TextDecoder().decode(bytes);
}
function renderIdOf(published) {
  return claimsOf(published.page.resourceJWT).renderId;
}
/**
 * One exchange for every item of the page through a new or given reader. The
 * route walk asks nothing for an item the caches already open; `attempt`
 * sends the request anyway, so a reader can accept a second answer.
 */
async function exchanged(w, published, options = {}) {
  const issuer = options.issuer ?? w.issuer();
  const reader = options.reader ?? w.reader();
  const client = reader.client(published, issuer, options);
  const contentNames =
    options.names ?? published.page.contentData.map(({ contentName }) => contentName);
  const walk = await (options.attempt ? client.attempt : client.unlock)(contentNames);
  return { client, walk, reader, issuer, request: client.sent[0] };
}
/** Open an item with one candidate content key; null when its body tag fails. */
async function openWith({ page, sealedContent }, name, key) {
  try {
    return text(await openContent(key, name, sealedContent[name], contentAadOctets(page, name)));
  } catch (error) {
    if (error?.code === "decrypt_failed") return null;
    throw error;
  }
}
/** The content key a period key recovers through one named connector. */
async function recovered(published, name, group, periodKey) {
  const pad = await itemPad(periodKey, { renderId: renderIdOf(published), contentName: name });
  return xor16(binaryStringBytes(connectorOf(published.page, name, group)), pad);
}
/** Point one item's connector record for `group` at another value. */
function setConnector(page, name, group, connector) {
  find(connectorsOf(page, name), { group }).connector = connector;
}
/** The group names an item's connector records carry, sorted: record order means nothing. */
const groupsOn = (page, name) =>
  connectorsOf(page, name)
    .map(({ group }) => group)
    .sort();
async function handleOf(name, window, { secret = SECRET, origin = PUBLISHER } = {}) {
  const seed = await contentNameSeed(secret, origin, GEOMETRY, name, window, CHAIN);
  return seedHandle(seed, GEOMETRY, window, CHAIN);
}
const chainKeysOf = (answer) => answer.body.contentGroupKeys.chainKeys;
/** The groups of one content name's chain-key records, sorted, one per record. */
const chainGroups = (records, contentName) =>
  findAll(records, { contentName })
    .map(({ group }) => group)
    .sort();
/** The cutoffs of one content name and group's chain-key records, sorted, one per record. */
const chainCutoffs = (records, contentName, group) =>
  findAll(records, { contentName, group })
    .map(({ cutoff }) => cutoff)
    .sort();
/** One chain-key record's key, or undefined. */
const chainKeyAt = (records, contentName, group, cutoff) =>
  find(records, { contentName, group, cutoff })?.key;
/** One recovered item key of an answer body, or undefined. */
const contentKeyOf = (body, contentName) =>
  find(body.contentGroupKeys.contentKeys, { contentName })?.key;
/** The windows of one content name's seed records in a request, sorted. */
const requestWindows = (request, contentName) =>
  findAll(request.sealed.contentWindowSeeds, { contentName })
    .map(({ windowStart }) => windowStart)
    .sort();

// Replaces the frozen broad-seed vector and the `SEED_ID`, `CONNECTOR_ID` and
// `CONSTRUCTION` literals: root's content-name seed anchor, the contract's
// names, and the stock derivation the seed handle hands that seed to.
test("frozen vectors: root's seed anchor feeds the stock derivation unchanged", async () => {
  // Root computed these anchors with Python hashlib/hmac, outside both implementations.
  assert.equal(
    await publisherNamespace(PUBLISHER),
    "2d0a016473ff75fd2afa3cc1dac401896235215a4a61e06d11129ff3442837a7",
  );
  const seed = await contentNameSeed(SECRET, PUBLISHER, GEOMETRY, "bodytext", T12, CHAIN);
  assert.equal(
    Buffer.from(seed).toString("hex"),
    "d9b1274900e75c2ddcf90b8015ffc87d4bd60eb8b84298d5ec9d57e26223a8f3",
  );
  assert.equal(CONTRACT.construction, "dca-construction-content-groups");
  assert.equal(CONTRACT.seedSalt, "dca-construction-content-name-seeds");
  assert.equal(CONTRACT.itemPadSalt, "dca-construction-content-connectors");
  // The seed is the stock family's key-derivation secret, nothing more.
  const handle = seedHandle(seed, GEOMETRY, T12, CHAIN);
  const stock = periodFamilyGeneration({ keyDerivationSecret: seed, geometry: GEOMETRY });
  assert.deepEqual(await handle.periodKey("politics", T15), await stock.periodKey("politics", T15));
  assert.deepEqual(
    (await handle.chainKey("politics", T18)).key,
    (await stock.chainCapability("politics", T18)).key,
  );
  // Expected bytes from Python's standard-library RFC 5869 HMAC extract/expand.
  const pad = await itemPad(
    Uint8Array.from({ length: 16 }, (_, i) => i),
    { renderId: "AAECAwQFBgcICQoLDA0ODw", contentName: "bodytext" },
  );
  assert.equal(Buffer.from(pad).toString("hex"), "a542731601b70098974ed71b45171cba");
  const ckey = Uint8Array.from({ length: 16 }, (_, i) => 0xf0 + i);
  assert.equal(Buffer.from(xor16(ckey, pad)).toString("hex"), "55b381e5f542f66f6fb72de0b9eae245");
});

// Replaces the root `contentGroups` array and `contentGroupChains.chainKeys`
// group counts and the absent `chainWindowSeeds` member.
async function groupsCrossAllRoles(counts) {
  for (const count of counts) {
    const w = await world();
    const groups = names(count);
    const published = await w.publish({ items: [item("bodytext", groups)] });
    const { page } = published;
    assert.equal(Object.hasOwn(page, "contentGroups"), false, "no root dictionary");
    assert.deepEqual(groupsOn(page, "bodytext"), groups);
    assert.equal(Object.hasOwn(pageItem(page, "bodytext"), "aad"), false, "the record omits aad");
    const envelope = seedOf(page, "issuer", "bodytext", T12);
    assert.equal(binaryStringBytes(envelope).length, 113);
    const { client, request, issuer } = await exchanged(w, published);
    assert.deepEqual(request.requested.contentGroups, groupRecords({ bodytext: groups }));
    const [answer] = issuer.calls.answers;
    assert.deepEqual(chainGroups(chainKeysOf(answer), "bodytext"), groups);
    assert.equal(JSON.stringify(answer.body).includes(CONTRACT.wire.sealedSeeds), false);
    const seed = await contentNameSeed(SECRET, PUBLISHER, GEOMETRY, "bodytext", T12, CHAIN);
    assert.equal(JSON.stringify(answer.body).includes(base64urlEncode(seed)), false);
    assert.equal(await client.open("bodytext"), "content:bodytext", `${count} groups`);
  }
}
test("1, 2 and 10 groups cross all three roles as named maps; the answer carries no seed", () =>
  groupsCrossAllRoles([1, 2, 10]));
test("100 groups cross all three roles as named maps", () => groupsCrossAllRoles([100]));

test("the client rebuilds the content AAD: a carried aad is ignored and a changed type preserves authentication", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { reader, issuer } = await exchanged(w, published);
  const variant = (change) => {
    const changed = copy(published);
    change(pageItem(changed.page, "bodytext"));
    return reader.client(changed, issuer);
  };
  assert.equal(
    await variant((record) => (record.aad = "story1|1|bodytext")).open("bodytext"),
    "content:bodytext",
  );
  assert.equal(
    await variant((record) => (record.contentType = "text/html")).open("bodytext"),
    "content:bodytext",
  );
  assert.equal(
    await variant((record) => (record.contentEncodings = ["gzip"])).open("bodytext"),
    null,
  );
});

// Replaces the `null` connector positions under the root dictionary: each
// item's records name only the groups it has a route for.
test("named connector maps: sparse routes, exact denial, pooled grants and a later cached render", async () => {
  const w = await world();
  const items = [item("bodytext", ["sports", "politics"]), item("headline", ["politics"])];
  const published = await w.publish({ items });
  assert.deepEqual(groupsOn(published.page, "headline"), ["politics"]);
  assert.equal(JSON.stringify(published.page.contentData).includes("null"), false);
  const sports = await exchanged(w, published, {
    narrowing: { requestedContentGroups: { bodytext: ["sports"] } },
  });
  assert.deepEqual(sports.request.requested.contentGroups, groupRecords({ bodytext: ["sports"] }));
  const politics = await exchanged(w, published, {
    narrowing: { requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] } },
  });
  assert.equal(await sports.client.open("bodytext"), "content:bodytext");
  assert.equal(await sports.client.open("headline"), null);
  assert.equal(await politics.client.open("headline"), "content:headline");
  assert.equal(await politics.client.open("bodytext"), "content:bodytext");

  const later = await w.publish({
    at: T15,
    items: [
      item("bodytext", ["sports", "politics"], "later"),
      item("headline", ["politics"], "later headline"),
    ],
  });
  assert.notEqual(renderIdOf(later), renderIdOf(published));
  const sportsLater = sports.reader.client(later, sports.issuer);
  assert.equal(await sportsLater.open("bodytext"), "later");
  assert.equal(await sportsLater.open("headline"), null);
  assert.equal(
    await politics.reader.client(later, politics.issuer).open("headline"),
    "later headline",
  );

  // One reader pools what two exchanges granted.
  const pooled = w.reader();
  await exchanged(w, published, {
    reader: pooled,
    narrowing: { requestedContentGroups: { bodytext: ["sports"] } },
  });
  assert.equal(await pooled.client(later, sports.issuer).open("headline"), null);
  await exchanged(w, published, {
    reader: pooled,
    names: ["headline"],
    narrowing: { requestedContentGroups: { headline: ["politics"] } },
  });
  assert.equal(await pooled.client(later, sports.issuer).open("headline"), "later headline");
});

// The requested.contentGroups collection names groups per content name.
test("the issuer verifies the JWT and independently authorizes requested names, groups and windows", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { request } = await exchanged(w, published);
  assert.equal(request.version, "1");
  assert.equal(request.keyId, "issuer-k1");
  assert.deepEqual(request.requested.contentGroups, groupRecords({ bodytext: ["sports"] }));
  assert.deepEqual(requestWindows(request, "bodytext"), [T12, NEXT]);
  for (const field of ["contentData", "requestedContentItems", "contentGroups"])
    assert.equal(Object.hasOwn(request, field), false, field);
  assert.deepEqual(
    findAll(request.requested.contentKeys, { contentName: "bodytext" }).map(({ group }) => group),
    ["sports"],
  );
  assert.equal(request.renderPeriod, T12);
  assert.deepEqual(request.periodGeometry, GEOMETRY);
  const answer = (changed, options) => w.issuer(options).answer(changed);
  // Keep these authorization checks about group routes. The default request
  // also offers the item's connectors, which remain independent alternatives.
  const groupOnly = copy(request);
  groupOnly.requested.contentKeys = [];

  const badSig = copy(request);
  badSig.resourceJWT = `${badSig.resourceJWT.slice(0, -2)}aa`;
  assert.notEqual((await answer(badSig)).status, 200);
  // A group name on the page is presentation, not entitlement: policy decides.
  const unknown = copy(groupOnly);
  unknown.requested.contentGroups = groupRecords({ bodytext: ["premium"] });
  assert.deepEqual(chainGroups(chainKeysOf(await answer(unknown)), "bodytext"), ["premium"]);
  const refuseAll = chainPolicy({ authorize: () => false });
  assert.equal((await answer(unknown, { policy: refuseAll })).code, "bad_policy");
  for (const deniedLabel of [T12, T15, T18]) {
    const denied = chainPolicy({ authorize: (_name, _group, t) => t !== deniedLabel });
    assert.equal((await answer(groupOnly, { policy: denied })).code, "bad_policy", deniedLabel);
  }
  const narrow = copy(request);
  narrow.requestedChainCutoffs = cutoffRecords({ [T12]: T14 });
  assert.deepEqual(chainCutoffs(chainKeysOf(await answer(narrow)), "bodytext", "sports"), [T14]);
  const broaden = copy(request);
  broaden.requestedChainCutoffs = cutoffRecords({ [T12]: T19 });
  assert.deepEqual(chainCutoffs(chainKeysOf(await answer(broaden)), "bodytext", "sports"), [T18]);
  // An explicit empty group list refuses; so does a request that asks nothing.
  const emptyList = copy(groupOnly);
  emptyList.requested.contentGroups = groupRecords({ bodytext: [] });
  assert.equal((await answer(emptyList)).code, "binding_failed");
  const asksNothing = copy(groupOnly);
  delete asksNothing.requested.contentGroups;
  assert.notEqual((await answer(asksNothing)).status, 200);
  // No selected window leaves the policy nothing to grant.
  const noWindows = copy(groupOnly);
  noWindows.requestedChainCutoffs = [];
  assert.equal((await answer(noWindows)).code, "denied");
  const local = await exchanged(w, published, {
    narrowing: { requestedContentItems: ["bodytext"] },
  });
  assert.equal(Object.hasOwn(local.request, "requestedContentItems"), false);
  assert.deepEqual(local.request.requested.contentGroups, groupRecords({ bodytext: ["sports"] }));
});

// Replaces the pending-association checks on `contentGroupChains`, the
// foreign-window check and the above-cutoff check: the client admits the
// `contentGroupKeys` answer against its request, all or nothing, before any cache.
test("the pending request bounds the answer's names, groups, windows, positions and ceilings before any cache", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports", "politics"])] });
  const narrowing = {
    requestedContentGroups: { bodytext: ["sports"] },
    requestedChainCutoffs: { [T12]: T14 },
  };
  const wide = (await exchanged(w, published)).issuer.calls.answers[0].body;
  const sportsKey = chainKeyAt(wide.contentGroupKeys.chainKeys, "bodytext", "sports", T18);
  const sportsRecords = (body) =>
    findAll(body.contentGroupKeys.chainKeys, { contentName: "bodytext", group: "sports" });
  /** Replace the bodytext sports records with one record at `cutoff`. */
  const sportsOnlyAt = (body, cutoff) => {
    body.contentGroupKeys.chainKeys = body.contentGroupKeys.chainKeys
      .filter((record) => !sportsRecords(body).includes(record))
      .concat([{ contentName: "bodytext", group: "sports", cutoff, key: sportsKey }]);
  };
  for (const [label, rewrite] of [
    [
      "foreign group",
      (body) =>
        body.contentGroupKeys.chainKeys.push(
          ...sportsRecords(body).map((record) => ({ ...record, group: "politics" })),
        ),
    ],
    [
      "foreign name",
      (body) =>
        body.contentGroupKeys.chainKeys.push(
          ...findAll(body.contentGroupKeys.chainKeys, { contentName: "bodytext" }).map(
            (record) => ({
              ...record,
              contentName: "headline",
            }),
          ),
        ),
    ],
    [
      "redundant wrapper",
      (body) => {
        const record = find(body.contentGroupKeys.chainKeys, {
          contentName: "bodytext",
          group: "sports",
          cutoff: T14,
        });
        record.key = { position: 1, key: record.key };
      },
    ],
    ["above the ceiling", (body) => sportsOnlyAt(body, T18)],
    ["foreign window", (body) => sportsOnlyAt(body, NEXT)],
  ]) {
    const reader = w.reader();
    const { client } = await exchanged(w, published, {
      reader,
      narrowing,
      answered: (body) => {
        rewrite(body);
        return body;
      },
    });
    assert.equal(await client.open("bodytext"), null, label);
    assert.deepEqual(await reader.chainKeyCache().entries(), [], label);
  }
  const { client } = await exchanged(w, published, { narrowing });
  assert.equal(await client.open("bodytext"), "content:bodytext");
});

test("a corrupted first chain route is skipped and a valid later group opens", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports", "politics"])] });
  const { client } = await exchanged(w, published, {
    answered: (body) => {
      const record = find(body.contentGroupKeys.chainKeys, {
        contentName: "bodytext",
        group: "sports",
        cutoff: T18,
      });
      const bytes = binaryStringBytes(record.key);
      bytes[0] ^= 1;
      record.key = base64urlEncode(bytes);
      return body;
    },
  });
  assert.equal(await client.open("bodytext"), "content:bodytext");
});

// Replaces the root-dictionary budget: `maxGroups` bounds one content name's
// connector map; retired limit names refuse.
test("a trusted maxGroups admits 1025 groups while the default refuses; retired limit names refuse", async () => {
  for (const retired of ["maxScopes", "maxPeriodKeysPerGroup"])
    assert.throws(() => settleLimits({ [retired]: 1 }), /unknown content-groups limit/);
  for (const bad of [0, -1, 1.2, Infinity]) assert.throws(() => settleLimits({ maxGroups: bad }));
  const w = await world();
  const groups = names(1025);
  await assert.rejects(
    w.publish({ items: [item("bodytext", groups)] }),
    /names its content groups as a bounded list/,
  );
  const limits = { maxGroups: 1025 };
  const published = await w.publish({ items: [item("bodytext", groups)], limits });
  const first = () => ({
    grants: [
      { kind: "chain", contentName: "bodytext", group: groups[0], windowStart: T12, cutoffT: T18 },
    ],
    authorizePeriod: () => true,
  });
  const { client, issuer, request } = await exchanged(w, published, {
    issuer: w.issuer({ limits, policy: first }),
    reader: w.reader({ limits }),
  });
  assert.equal(
    find(request.requested.contentGroups, { contentName: "bodytext" }).groups.length,
    1025,
  );
  assert.equal(issuer.calls.decide[0].contentGroups.bodytext.groups.length, 1025);
  assert.deepEqual(chainGroups(chainKeysOf(issuer.calls.answers[0]), "bodytext"), [groups[0]]);
  assert.equal(await client.open("bodytext"), "content:bodytext");
});

// Replaces the raw `chainWindowSeeds` count and the response group bound.
test("raw request and answer bounds refuse surplus entries before verification, derivation or cache", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { request } = await exchanged(w, published);
  const reads = w.verifierReads();
  const surplusSeeds = copy(request);
  surplusSeeds.sealed.contentWindowSeeds.push({
    contentName: "bodytext",
    windowStart: NOON2,
    key: "not an envelope",
  });
  assert.equal((await w.issuer().answer(surplusSeeds)).code, "too_many_entries");
  const surplusNames = copy(request);
  surplusNames.requested.contentGroups = groupRecords(
    Object.fromEntries(names(65).map((name) => [name, ["sports"]])),
  );
  assert.equal((await w.issuer().answer(surplusNames)).code, "too_many_entries");
  assert.equal(w.verifierReads(), reads, "no bound reached the signature verifier");

  const reader = w.reader();
  const { client } = await exchanged(w, published, {
    reader,
    answered: (body) => {
      const records = body.contentGroupKeys.chainKeys;
      const key = chainKeyAt(records, "bodytext", "sports", T18);
      for (const group of names(2048))
        records.push({ contentName: "bodytext", group, cutoff: T18, key });
      return body;
    },
  });
  assert.equal(await client.open("bodytext"), null);
  assert.deepEqual(await reader.chainKeyCache().entries(), []);
});

test("publication snapshots item groups, plaintext and the retained secret before asynchronous work", async () => {
  const w = await world();
  const secret = Uint8Array.from(SECRET);
  const publisher = w.publisher({ retainedSecret: secret, connectorNames: ["bodytext"] });
  secret.fill(0);
  const items = [item("bodytext", ["sports"], "original")];
  const pending = publisher.publish({ items });
  items[0].contentGroups[0] = "politics";
  items[0].value = "changed";
  const published = await pending;
  assert.deepEqual(groupsOn(published.page, "bodytext"), ["sports"]);
  const handle = await handleOf("bodytext", T12);
  const key = await recovered(
    published,
    "bodytext",
    "sports",
    await handle.periodKey("sports", T12),
  );
  assert.equal(await openWith(published, "bodytext", key), "original");
});

test("one cached T18 chain opens every T12..T18 render, but not T19 or the next window", async () => {
  const w = await world();
  const issuer = w.issuer();
  const first = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { reader } = await exchanged(w, first, { issuer });
  for (let hour = 12; hour <= 18; hour++) {
    const period = `261014T${String(hour).padStart(2, "0")}00`;
    const page = await w.publish({ at: period, items: [item("bodytext", ["sports"], period)] });
    assert.equal(page.page.renderPeriod, period);
    assert.equal(await reader.client(page, issuer).open("bodytext"), period);
  }
  for (const period of [T19, NEXT]) {
    const page = await w.publish({ at: period, items: [item("bodytext", ["sports"], period)] });
    assert.equal(await reader.client(page, issuer).open("bodytext"), null, period);
  }
  const midnight = await w.publish({ at: NEXT, items: [item("bodytext", ["sports"], "midnight")] });
  const { client } = await exchanged(w, midnight, {
    reader,
    issuer: w.issuer({ policy: chainPolicy({ windowStart: NEXT, cutoffT: NEXT }) }),
    narrowing: { requestedChainCutoffs: { [NEXT]: NEXT } },
  });
  assert.equal(await client.open("bodytext"), "midnight");
});

test("raw future and wrong-window Step and Leaf probes fail body GCM, while planted controls open", async () => {
  const w = await world();
  const source = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { issuer } = await exchanged(w, source);
  const held = binaryStringBytes(
    chainKeyAt(chainKeysOf(issuer.calls.answers[0]), "bodytext", "sports", T18),
  );
  const future = await w.publish({ at: T19, items: [item("bodytext", ["sports"], "future")] });
  await assert.rejects(
    chainKeyFromChainKey({
      chainKey: held,
      accessGroup: "sports",
      suppliedT: T18,
      targetT: T19,
      geometry: GEOMETRY,
    }),
  );
  const at19 = CHAIN.coordinate(T19, GEOMETRY);
  const rawFuture = await chainKeyLeafPrimitive({
    chainKey: held,
    accessGroup: "sports",
    ...GEOMETRY,
    windowStart: at19.windowStart,
    position: at19.position,
  });
  assert.equal(
    await openWith(future, "bodytext", await recovered(future, "bodytext", "sports", rawFuture)),
    null,
  );
  // Planted control: a connector made for the probed key opens, so the
  // refusal above is the key's, not the harness's.
  const correct = await (await handleOf("bodytext", T12)).periodKey("sports", T19);
  const ckey = await recovered(future, "bodytext", "sports", correct);
  assert.equal(await openWith(future, "bodytext", ckey), "future");
  const planted = copy(future);
  const wrongPad = await itemPad(rawFuture, {
    renderId: renderIdOf(future),
    contentName: "bodytext",
  });
  setConnector(planted.page, "bodytext", "sports", base64urlEncode(xor16(ckey, wrongPad)));
  assert.equal(
    await openWith(planted, "bodytext", await recovered(planted, "bodytext", "sports", rawFuture)),
    "future",
  );

  const nextAt = CHAIN.coordinate(NEXT, GEOMETRY);
  const forgedStep = await chainKeyStepPrimitive({
    chainKey: held,
    accessGroup: "sports",
    ...GEOMETRY,
    windowStart: nextAt.windowStart,
    position: 0,
  });
  const wrongWindow = await chainKeyLeafPrimitive({
    chainKey: forgedStep,
    accessGroup: "sports",
    ...GEOMETRY,
    windowStart: nextAt.windowStart,
    position: 0,
  });
  const midnight = await w.publish({ at: NEXT, items: [item("bodytext", ["sports"], "midnight")] });
  assert.equal(
    await openWith(
      midnight,
      "bodytext",
      await recovered(midnight, "bodytext", "sports", wrongWindow),
    ),
    null,
  );
  const midnightKey = await recovered(
    midnight,
    "bodytext",
    "sports",
    await (await handleOf("bodytext", NEXT)).periodKey("sports", NEXT),
  );
  const plantedMidnight = copy(midnight);
  setConnector(
    plantedMidnight.page,
    "bodytext",
    "sports",
    base64urlEncode(
      xor16(
        midnightKey,
        await itemPad(wrongWindow, { renderId: renderIdOf(midnight), contentName: "bodytext" }),
      ),
    ),
  );
  assert.equal(
    await openWith(
      plantedMidnight,
      "bodytext",
      await recovered(plantedMidnight, "bodytext", "sports", wrongWindow),
    ),
    "midnight",
  );
});

// Replaces the broad publisher's own route refusals. The base Sealer now owns
// ordinary envelopes, so the retired `keys` input and the ordinary sealing
// ports have no counterpart here.
test("a connector-only item carries no ordinary key; an item with no route refuses before sealing", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  assert.equal(Object.hasOwn(pageItem(published.page, "bodytext"), "keys"), false);
  assert.equal(Object.hasOwn(issuerBlock(published.page, "issuer").sealed, "contentKeys"), false);
  // An empty group list is ordinary only, and no ordinary route is supplied.
  await assert.rejects(w.publish({ items: [item("bodytext", [])] }), /route/);
  // The only seed is for the next window, so the render window has no route.
  await assert.rejects(
    w.publish({
      items: [item("bodytext", ["sports"])],
      seedWindows: { issuer: { bodytext: [NEXT] } },
    }),
    /route/,
  );
});

// Replaces the broad `seedAAD` vector and `openWindowSeed` binding checks and
// the root `contentGroups` connector indexing.
test("a seed envelope binds publisher, render, issuer, content name, window and geometry", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("bodytext", ["sports"]), item("headline", ["sports"])],
  });
  const binding = {
    publisher: PUBLISHER,
    renderId: renderIdOf(published),
    issuerName: "issuer",
    contentName: "bodytext",
    windowStartLabel: T12,
    periodGeometry: GEOMETRY,
  };
  // The transcript written out from the contract, hashed by node:crypto.
  const namespace = createHash("sha256").update(PUBLISHER).digest("hex");
  assert.equal(
    new TextDecoder().decode(await contentNameSeedAad(binding, CHAIN)),
    `["dca-bind-content-name-seed","${namespace}","${binding.renderId}","issuer","bodytext","261014T1200",2,60]`,
  );
  const seedAt = (contentName, windowStart) =>
    seedOf(published.page, "issuer", contentName, windowStart);
  const privateKey = w.opening.issuer.privateKey;
  const open = async (envelope, change) =>
    openSeed(envelope, privateKey, await contentNameSeedAad({ ...binding, ...change }, CHAIN));
  assert.deepEqual(
    await open(seedAt("bodytext", T12), {}),
    await contentNameSeed(SECRET, PUBLISHER, GEOMETRY, "bodytext", T12, CHAIN),
  );
  for (const change of [
    { publisher: "https://other.example" },
    { renderId: "AAECAwQFBgcICQoLDA0ODw" },
    { issuerName: "other" },
    { contentName: "headline" },
    { windowStartLabel: NEXT },
    { periodGeometry: { chainsPerDay: 4, periodMinutes: 60 } },
  ])
    await assert.rejects(
      open(seedAt("bodytext", T12), change),
      { name: "OperationError" },
      JSON.stringify(change),
    );
  await assert.rejects(open(seedAt("bodytext", NEXT), {}), { name: "OperationError" });
  await assert.rejects(open(seedAt("headline", T12), {}), { name: "OperationError" });
  // An envelope replayed into a later render's request does not open there.
  const later = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { request } = await exchanged(w, later);
  const replayed = copy(request);
  find(replayed.sealed.contentWindowSeeds, { contentName: "bodytext", windowStart: T12 }).key =
    seedAt("bodytext", T12);
  assert.equal((await w.issuer().answer(replayed)).code, "binding_failed");
  // The signed resource carries no commitment or content-group route.
  const claims = claimsOf(published.page.resourceJWT);
  assert.equal(Object.hasOwn(claims, "contentKeyCommitments"), false);
  for (const field of [
    "contentGroups",
    "connectors",
    "renderPeriod",
    "periodGeometry",
    "contentWindowSeeds",
  ])
    assert.equal(Object.hasOwn(claims, field), false, field);
});

// Replaces the root-dictionary reorder, duplicate and array-length checks:
// a connector map is read by member name, never by position.
test("a connector map is read by group name: member order is free, a relabeled or retired map opens nothing", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports", "politics"])] });
  const { reader, issuer } = await exchanged(w, published);
  const variant = (change) => {
    const changed = copy(published);
    change(changed.page);
    return reader.client(changed, issuer);
  };
  const reorder = (page) => pageItem(page, "bodytext").connectors.reverse();
  assert.equal(await variant(reorder).open("bodytext"), "content:bodytext");
  const relabel = (page) => {
    const sports = connectorOf(page, "bodytext", "sports");
    const politics = connectorOf(page, "bodytext", "politics");
    setConnector(page, "bodytext", "sports", politics);
    setConnector(page, "bodytext", "politics", sports);
  };
  assert.equal(await variant(relabel).open("bodytext"), null);
  for (const [label, change] of [
    ["empty map", (page) => (pageItem(page, "bodytext").connectors = [])],
    // Bare connector values without their group names.
    [
      "array",
      (page) =>
        (pageItem(page, "bodytext").connectors = connectorsOf(page, "bodytext").map(
          ({ connector }) => connector,
        )),
    ],
    ["root dictionary", (page) => (page.contentGroups = ["sports", "politics"])],
  ]) {
    const fresh = w.reader();
    const changed = copy(published);
    change(changed.page);
    const client = fresh.client(changed, issuer);
    await client.unlock(["bodytext"]);
    assert.equal(
      client.sent.some((sent) => Object.hasOwn(sent.requested ?? {}, "contentGroups")),
      false,
      `${label}: no content-group member is relayed`,
    );
    assert.equal(await client.open("bodytext"), null, label);
  }
  assert.throws(() => reader.client(published, issuer, { narrowing: { resourceJWT: "forged" } }), {
    code: "bad_config",
  });
});

test("prototype-looking group names stay own members; a known content key recovers no other item", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("bodytext", ["constructor", "toString"]), item("headline", ["toString"])],
  });
  const { client } = await exchanged(w, published);
  assert.equal(await client.open("bodytext"), "content:bodytext");
  assert.equal(await client.open("headline"), "content:headline");
  const handle = await handleOf("bodytext", T12);
  await assert.rejects(handle.chainKey("sports", NEXT), /outside seed window/);
  await assert.rejects(handle.periodKey("sports", NEXT), /outside seed window/);
  const pkey = await handle.periodKey("toString", T12);
  const bodyKey = await recovered(published, "bodytext", "toString", pkey);
  assert.equal(await openWith(published, "bodytext", bodyKey), "content:bodytext");
  // bodytext's pad applied to headline's connector recovers no headline key,
  // and headline's own seed is another content name's.
  const misapplied = await recovered(published, "headline", "toString", pkey);
  assert.notDeepEqual(misapplied, bodyKey);
  assert.equal(await openWith(published, "headline", misapplied), null);
});

test("standard access reveals the item's premium pad but cannot open premium-only items", async () => {
  const w = await world();
  const shared = await w.publish({
    items: [item("bodytext", ["standard", "premium"], "shared article")],
  });
  const issuer = w.issuer({
    policy: (input) => {
      const decision = chainPolicy()(input);
      return { ...decision, grants: decision.grants.filter((grant) => grant.group === "standard") };
    },
  });
  const { reader, client } = await exchanged(w, shared, { issuer });
  assert.equal(await client.open("bodytext"), "shared article");
  const delivered = chainKeysOf(issuer.calls.answers[0]);
  assert.deepEqual(chainGroups(delivered, "bodytext"), ["standard"]);

  // The reader computes the item key from its delivered standard chain.
  const chainKey = await chainKeyFromChainKey({
    chainKey: binaryStringBytes(chainKeyAt(delivered, "bodytext", "standard", T18)),
    accessGroup: "standard",
    suppliedT: T18,
    targetT: T12,
    geometry: GEOMETRY,
  });
  const at = CHAIN.coordinate(T12, GEOMETRY);
  const standardPeriodKey = await chainKeyLeafPrimitive({
    chainKey,
    accessGroup: "standard",
    ...GEOMETRY,
    windowStart: at.windowStart,
    position: at.position,
  });
  const sharedCkey = await recovered(shared, "bodytext", "standard", standardPeriodKey);
  assert.equal(await openWith(shared, "bodytext", sharedCkey), "shared article");
  const exposedPremiumPad = xor16(
    sharedCkey,
    binaryStringBytes(connectorOf(shared.page, "bodytext", "premium")),
  );
  // Publisher-side oracle confirms what leaked; it is not reader material.
  const publisherHandle = await handleOf("bodytext", T12);
  const premiumPeriodKey = await publisherHandle.periodKey("premium", T12);
  assert.deepEqual(
    exposedPremiumPad,
    await itemPad(premiumPeriodKey, { renderId: renderIdOf(shared), contentName: "bodytext" }),
  );

  for (const period of [T12, T15, NEXT]) {
    const target = await w.publish({
      at: period,
      items: [item("bodytext", ["premium"], `premium-only ${period}`)],
    });
    assert.notEqual(renderIdOf(target), renderIdOf(shared));
    assert.deepEqual(groupsOn(target.page, "bodytext"), ["premium"]);
    assert.equal(await reader.client(target, issuer).open("bodytext"), null);
    // Raw attempts bypass client lookup and coordinate validation. The body
    // must reject them, including when both articles use the same period key.
    const connector = binaryStringBytes(connectorOf(target.page, "bodytext", "premium"));
    for (const candidate of [
      sharedCkey,
      xor16(connector, exposedPremiumPad),
      await recovered(target, "bodytext", "premium", exposedPremiumPad),
      await recovered(target, "bodytext", "premium", standardPeriodKey),
    ]) {
      assert.equal(await openWith(target, "bodytext", candidate), null, period);
    }

    // Positive control: the target really opens with its premium period key.
    const window = period === NEXT ? NEXT : T12;
    const correct = await (await handleOf("bodytext", window)).periodKey("premium", period);
    if (period === T12) assert.deepEqual(correct, premiumPeriodKey);
    assert.equal(
      await openWith(target, "bodytext", await recovered(target, "bodytext", "premium", correct)),
      `premium-only ${period}`,
    );
  }
});

test("a zero-connector item grant exposes only that item's pad, not another name or render", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("bodytext", ["sports"]), item("headline", ["sports"])],
  });
  const issuer = w.issuer({
    policy: (input) => ({
      grants: input.items.includes("bodytext") ? [{ kind: "item", contentName: "bodytext" }] : [],
      authorizePeriod: () => true,
    }),
  });
  const { request } = await exchanged(w, published, {
    issuer,
    names: ["bodytext"],
    narrowing: { requestedContentGroups: {}, requestedContentKeys: { bodytext: "sports" } },
  });
  const genuine = issuer.calls.answers.at(-1);
  assert.equal(genuine.status, 200);
  assert.equal(
    await openWith(
      published,
      "bodytext",
      binaryStringBytes(contentKeyOf(genuine.body, "bodytext")),
    ),
    "content:bodytext",
  );
  const changed = copy(request);
  for (const route of findAll(changed.requested.contentKeys, { contentName: "bodytext" }))
    route.connector = base64urlEncode(new Uint8Array(16));
  const answer = await issuer.answer(changed);
  assert.equal(answer.status, 200);
  assert.deepEqual(Object.keys(answer.body.contentGroupKeys), ["contentKeys"]);
  assert.deepEqual(
    answer.body.contentGroupKeys.contentKeys.map(({ contentName }) => contentName),
    ["bodytext"],
  );
  const exposedPad = binaryStringBytes(contentKeyOf(answer.body, "bodytext"));
  const pkey = await (await handleOf("bodytext", T12)).periodKey("sports", T12);
  assert.deepEqual(
    exposedPad,
    await itemPad(pkey, { renderId: renderIdOf(published), contentName: "bodytext" }),
  );
  assert.equal(await openWith(published, "bodytext", exposedPad), null);

  const later = await w.publish({ items: [item("bodytext", ["sports"])] });
  assert.notEqual(renderIdOf(later), renderIdOf(published));
  assert.equal(later.page.renderPeriod, published.page.renderPeriod);
  assert.equal(
    (
      await w
        .issuer({ policy: () => ({ grants: [], authorizePeriod: () => true }) })
        .answer(changed)
    ).code,
    "denied",
  );
  for (const [target, name] of [
    [published, "headline"],
    [later, "bodytext"],
  ]) {
    const connector = binaryStringBytes(connectorOf(target.page, name, "sports"));
    for (const candidate of [
      exposedPad,
      xor16(connector, exposedPad),
      await recovered(target, name, "sports", exposedPad),
    ])
      assert.equal(await openWith(target, name, candidate), null, name);
    const ownKey = await (await handleOf(name, T12)).periodKey("sports", T12);
    assert.equal(
      await openWith(target, name, await recovered(target, name, "sports", ownKey)),
      `content:${name}`,
      "the genuine target remains openable",
    );
  }
});

test("deliberately reused item-pad context exposes the XOR of two different content keys", async () => {
  const pad = await itemPad(
    Uint8Array.from({ length: 16 }, (_, i) => i),
    { renderId: "AAECAwQFBgcICQoLDA0ODw", contentName: "bodytext" },
  );
  const a = Uint8Array.from({ length: 16 }, (_, i) => i + 16);
  const b = Uint8Array.from({ length: 16 }, (_, i) => i + 32);
  const connectorA = xor16(a, pad);
  const connectorB = xor16(b, pad);
  assert.deepEqual(xor16(connectorA, connectorB), xor16(a, b));
  // Knowing the first ckey then recovers the second when the pad is reused.
  const exposedPad = xor16(a, connectorA);
  assert.deepEqual(xor16(connectorB, exposedPad), b);
});

// Replaces the broad `windowSeed` with the content-name seed.
test("origin hashes separate sites without a separate site name or slug collisions", async () => {
  const first = "https://news-site.example";
  const second = "https://newssite.example";
  assert.notEqual(await publisherNamespace(first), await publisherNamespace(second));
  const a = await handleOf("bodytext", T12, { origin: first });
  const b = await handleOf("bodytext", T12, { origin: second });
  assert.notDeepEqual(await a.periodKey("sports", T12), await b.periodKey("sports", T12));
});

test("origin validation rejects malformed UTF-16 and noncanonical origins before hashing", async () => {
  for (const origin of [
    "a\ud800",
    "a�",
    "https://news.example/",
    "https://NEWS.example",
    "https://news.example:443",
    "https://news.example/path",
    "https://é.example",
    "http://news.example",
    "https://news.example?x=1",
    "https://user@news.example",
  ])
    await assert.rejects(publisherNamespace(origin), /canonical ASCII HTTPS origin/);
});

test("geometry member order is free on the delivery, the request and the answer", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const reordered = copy(published);
  reordered.page.periodGeometry = { periodMinutes: 60, chainsPerDay: 2 };
  const { client, request } = await exchanged(w, reordered, {
    answered: (body) => {
      body.periodGeometry = { periodMinutes: 60, chainsPerDay: 2 };
      return body;
    },
  });
  assert.deepEqual(Object.keys(request.periodGeometry), ["periodMinutes", "chainsPerDay"]);
  assert.equal(await client.open("bodytext"), "content:bodytext");
});

const FOUR_A_DAY = Object.freeze({ chainsPerDay: 4, periodMinutes: 60 });
/**
 * A policy that survives a geometry rollover: it finds the window of the
 * verified render time under the request's geometry and grants a chain to that
 * window's last period. The request geometry grants nothing by itself; a
 * geometry outside `supported` is denied.
 */
function rolloverPolicy(supported = [GEOMETRY, FOUR_A_DAY]) {
  return (input) => {
    const geometry = input.request.periodGeometry;
    const known = supported.some(
      (g) => g.chainsPerDay === geometry.chainsPerDay && g.periodMinutes === geometry.periodMinutes,
    );
    if (!known) return { grants: [], authorizePeriod: () => false };
    const windowMinutes = 1440 / geometry.chainsPerDay;
    const minutes = Math.floor(Date.parse(input.claims.issuedAt) / 60_000);
    const start = minutes - (minutes % windowMinutes);
    const windowStart = CHAIN.labelAt(start);
    const cutoffT = CHAIN.labelAt(start + windowMinutes - geometry.periodMinutes);
    return {
      grants: Object.entries(input.contentGroups).flatMap(([contentName, { groups, windows }]) =>
        windows.includes(windowStart)
          ? groups.map((group) => ({ kind: "chain", contentName, group, windowStart, cutoffT }))
          : [],
      ),
      authorizePeriod: () => true,
    };
  };
}

test("a policy reading the request geometry serves a rollover; a relayed other geometry fails at seed opening", async () => {
  const w = await world();
  const before = await w.publish({ items: [item("bodytext", ["sports"])] });
  const after = await w.publish({
    items: [item("bodytext", ["sports"])],
    periodGeometry: FOUR_A_DAY,
    resourceId: "story2",
  });
  const issuer = w.issuer({ policy: rolloverPolicy() });
  const reader = w.reader();
  for (const published of [before, after]) {
    const { client } = await exchanged(w, published, { issuer, reader });
    assert.equal(issuer.calls.answers.at(-1).status, 200);
    assert.equal(await client.open("bodytext"), "content:bodytext");
  }
  assert.deepEqual(chainCutoffs(chainKeysOf(issuer.calls.answers.at(-1)), "bodytext", "sports"), [
    "261014T1700",
  ]);

  // A 2/60 page relayed as 4/60: the policy grants within 4/60's T12 window,
  // and the seed sealed under 2/60 refuses at opening. Nothing opens.
  const relayed = copy(before);
  relayed.page.periodGeometry = FOUR_A_DAY;
  const forged = await exchanged(w, relayed, { issuer });
  assert.equal(issuer.calls.decide.at(-1).request.periodGeometry.chainsPerDay, 4);
  assert.equal(issuer.calls.answers.at(-1).status, 400);
  assert.equal(issuer.calls.answers.at(-1).code, "binding_failed");
  assert.equal(await forged.client.open("bodytext"), null);
  // A geometry the policy does not serve is denied, not answered.
  const halfHours = copy(before);
  halfHours.page.periodGeometry = { chainsPerDay: 2, periodMinutes: 30 };
  await exchanged(w, halfHours, { issuer });
  assert.equal(issuer.calls.answers.at(-1).code, "denied");
  // A policy fixed to T18 answers a grant outside 4/60's window: that stays
  // its own fault, bad_policy, and is not relabelled as the caller's.
  const fixed = w.issuer({ policy: chainPolicy() });
  await exchanged(w, relayed, { issuer: fixed });
  assert.equal(fixed.calls.answers.at(-1).code, "bad_policy");
});

test("an altered renderPeriod returns a wrong item candidate and leaves a chain grant unchanged", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { request } = await exchanged(w, published);
  const answer = (changed) => w.issuer().answer(changed);
  const asItem = copy(request);
  delete asItem.requested.contentGroups;
  asItem.requested.contentKeys = [
    {
      contentName: "bodytext",
      group: "sports",
      connector: connectorOf(published.page, "bodytext", "sports"),
    },
  ];
  const genuine = await answer(asItem);
  assert.equal(genuine.status, 200);
  assert.ok(contentKeyOf(genuine.body, "bodytext"));
  // Same window and the next window: both seeds open, the pad differs, and
  // the recovered candidate cannot authenticate the genuine body.
  for (const period of [T13, "261015T0100"]) {
    const moved = copy(asItem);
    moved.renderPeriod = period;
    const result = await answer(moved);
    assert.equal(result.status, 200, period);
    assert.equal(
      await openWith(
        published,
        "bodytext",
        binaryStringBytes(contentKeyOf(result.body, "bodytext")),
      ),
      null,
      period,
    );
  }
  const chainMoved = copy(request);
  chainMoved.renderPeriod = T15;
  assert.deepEqual(chainKeysOf(await answer(chainMoved)), chainKeysOf(await answer(request)));
});

test("the widest cached chain key survives T18, then T12, then T13 and stays in its own family", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("bodytext", ["sports"]), item("headline", ["sports"])],
  });
  const reader = w.reader();
  for (const cutoffT of [T18, T12, T13]) {
    const { client } = await exchanged(w, published, {
      reader,
      names: ["bodytext"],
      attempt: true,
      issuer: w.issuer({ policy: chainPolicy({ cutoffT }) }),
    });
    assert.equal(client.sent.length, 1, cutoffT);
  }
  const issuer = w.issuer();
  const later = await w.publish({
    at: T15,
    items: [item("bodytext", ["sports"], "still open"), item("headline", ["sports"])],
  });
  assert.equal(await reader.client(later, issuer).open("bodytext"), "still open");
  assert.equal(await reader.client(later, issuer).open("headline"), null, "another content name");
  for (const override of [
    { retainedSecret: new Uint8Array(32).fill(9) },
    { origin: "https://other.example" },
    { periodGeometry: { chainsPerDay: 4, periodMinutes: 60 } },
  ]) {
    const foreign = await w.publish({ ...override, items: [item("bodytext", ["sports"])] });
    assert.equal(
      await reader.client(foreign, issuer).open("bodytext"),
      null,
      JSON.stringify(override),
    );
  }
});

test("fresh item keys across item names and renders; another group's key fails real body GCM", async () => {
  const w = await world();
  const pages = [];
  for (let i = 0; i < 2; i++)
    pages.push(
      await w.publish({ items: [item("bodytext", ["sports"]), item("headline", ["politics"])] }),
    );
  const keys = [];
  for (const published of pages)
    for (const [name, group] of [
      ["bodytext", "sports"],
      ["headline", "politics"],
    ]) {
      const handle = await handleOf(name, T12);
      const key = await recovered(published, name, group, await handle.periodKey(group, T12));
      keys.push(Buffer.from(key).toString("hex"));
      assert.equal(await openWith(published, name, key), `content:${name}`);
    }
  assert.equal(new Set(keys).size, 4);
  const [published] = pages;
  const wrong = await (await handleOf("headline", T12)).periodKey("sports", T12);
  assert.equal(
    await openWith(
      published,
      "headline",
      await recovered(published, "headline", "politics", wrong),
    ),
    null,
  );
});

// Replaces the `contentGroupChains` carrier shape: the answer is the
// `contentGroupKeys` section beside base `keys`.
test("the answer is a chain-key carrier without seed bytes; policy output cannot broaden the request", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports", "politics"])] });
  const { request, issuer } = await exchanged(w, published, {
    narrowing: {
      requestedContentGroups: { bodytext: ["sports"] },
      requestedChainCutoffs: { [T12]: T18 },
      seedWindows: [T12],
    },
  });
  const { body } = issuer.calls.answers[0];
  assert.deepEqual(Object.keys(body), ["keys", "contentGroupKeys"]);
  assert.equal(Object.hasOwn(body, "periodGeometry"), false);
  assert.deepEqual(Object.keys(body.contentGroupKeys), ["chainKeys"]);
  const entry = chainKeyAt(body.contentGroupKeys.chainKeys, "bodytext", "sports", T18);
  assert.equal(typeof entry, "string");
  assert.equal(binaryStringBytes(entry).length, 16);
  // Defense in depth: a grant outside the request is the policy's fault.
  for (const grant of [
    { kind: "chain", contentName: "bodytext", group: "politics", windowStart: T12, cutoffT: T18 },
    { kind: "chain", contentName: "bodytext", group: "sports", windowStart: NEXT, cutoffT: NEXT },
    { kind: "chain", contentName: "headline", group: "sports", windowStart: T12, cutoffT: T18 },
    { kind: "item", contentName: "bodytext" },
  ]) {
    const policy = () => ({ grants: [grant], authorizePeriod: () => true });
    assert.equal(
      (await w.issuer({ policy }).answer(request)).code,
      "bad_policy",
      JSON.stringify(grant),
    );
  }
});

test("request identity and verified claims precede policy; a narrowed or reordered seed map needs no signed mirror", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { request } = await exchanged(w, published);
  const issuer = w.issuer();
  for (const change of [{ version: "2" }, { issuerName: "other" }])
    assert.notEqual(
      (await issuer.answer({ ...request, ...change })).status,
      200,
      JSON.stringify(change),
    );
  const claims = claimsOf(published.page.resourceJWT);
  for (const change of [{ issuedAt: "not-a-date" }, { data: [] }, { renderId: "short" }]) {
    const resourceJWT = await sign({ ...claims, ...change }, w.signing.privateKey, { kid: "p1" });
    assert.notEqual(
      (await issuer.answer({ ...request, resourceJWT })).status,
      200,
      JSON.stringify(change),
    );
  }
  assert.equal(issuer.calls.decide.length, 0, "policy saw none of them");
  // A well-formed authorized request reaches policy before an unknown
  // registration key is resolved; the policy still runs only once.
  assert.equal((await issuer.answer({ ...request, keyId: "other-key" })).code, "unknown_key");
  assert.equal(issuer.calls.decide.length, 1);
  const subset = await exchanged(w, published, { narrowing: { seedWindows: [T12] } });
  assert.deepEqual(requestWindows(subset.request, "bodytext"), [T12]);
  assert.equal(await subset.client.open("bodytext"), "content:bodytext");
  const reversed = copy(request);
  reversed.sealed.contentWindowSeeds.reverse();
  assert.deepEqual(chainCutoffs(chainKeysOf(await issuer.answer(reversed)), "bodytext", "sports"), [
    T18,
  ]);
});

test("the finite transcript uses exact literal ASCII and integer octets, without serializer-dependent escapes", () => {
  assert.equal(new TextDecoder().decode(frame(["slash/value", 0, 60])), '["slash/value",0,60]');
  for (const part of [
    'quote"',
    "back\\slash",
    "line\nfeed",
    "ø",
    -1,
    0.5,
    Number.MAX_SAFE_INTEGER + 1,
  ])
    assert.throws(() => frame([part]), /ASCII|integers/);
});

// Replaces the broad client's `cacheSize()` window bound with the dedicated
// chain-key cache's `maxWindowsPerGroup` family bound.
test("retained windows are bounded per content name and group, with acceptance recency", async () => {
  const w = await world();
  const starts = [T12, NEXT, NOON2];
  const pages = [];
  for (const window of starts)
    pages.push(
      await w.publish({
        at: window,
        items: [item("bodytext", ["sports"])],
        seedWindows: { issuer: { bodytext: [window] } },
      }),
    );
  const grant = (window, cutoffT = window) =>
    w.issuer({ policy: chainPolicy({ windowStart: window, cutoffT }) });
  const issuer = w.issuer();
  for (const capacity of [2, 3]) {
    const reader = w.reader({ limits: { maxWindowsPerGroup: capacity } });
    for (let i = 0; i < pages.length; i++)
      await exchanged(w, pages[i], { reader, issuer: grant(starts[i]) });
    assert.equal((await reader.chainKeyCache().entries()).length, capacity);
    assert.equal(
      await reader.client(pages[0], issuer).open("bodytext"),
      capacity === 2 ? null : "content:bodytext",
    );
    assert.equal(await reader.client(pages[1], issuer).open("bodytext"), "content:bodytext");
    assert.equal(await reader.client(pages[2], issuer).open("bodytext"), "content:bodytext");
  }
  const reader = w.reader({ limits: { maxWindowsPerGroup: 2 } });
  await exchanged(w, pages[0], { reader, issuer: grant(T12, T18) });
  await exchanged(w, pages[1], { reader, issuer: grant(NEXT) });
  // A narrower acceptance in the first window refreshes it and keeps its widest key.
  await exchanged(w, pages[0], { reader, issuer: grant(T12, T12), attempt: true });
  await exchanged(w, pages[2], { reader, issuer: grant(NOON2) });
  assert.equal(await reader.client(pages[0], issuer).open("bodytext"), "content:bodytext");
  assert.equal(await reader.client(pages[1], issuer).open("bodytext"), null);
  assert.equal(await reader.client(pages[2], issuer).open("bodytext"), "content:bodytext");
  const later = await w.publish({ at: T18, items: [item("bodytext", ["sports"])] });
  assert.equal(await reader.client(later, issuer).open("bodytext"), "content:bodytext");
});

// Replaces the object API's inherited-member checks: on the wire a member can
// only be an own JSON member, so the hazard is an own `__proto__` member.
test("protocol entries are own JSON members: a __proto__ member is a name like any other", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const issuer = w.issuer();
  const page = copy(published);
  const index = page.page.contentData.indexOf(pageItem(page.page, "bodytext"));
  page.page.contentData[index] = JSON.parse(
    JSON.stringify(page.page.contentData[index]).replace('"sports"', '"__proto__"'),
  );
  const fresh = w.reader();
  const client = fresh.client(page, issuer);
  await client.unlock(["bodytext"]);
  assert.equal(
    client.sent.some((sent) => Object.hasOwn(sent.requested ?? {}, "contentGroups")),
    false,
  );
  assert.equal(await client.open("bodytext"), null);
  const reader = w.reader();
  const answered = await exchanged(w, published, {
    reader,
    answered: (body) =>
      JSON.parse(JSON.stringify(body).replace('"group":"sports"', '"group":"__proto__"')),
  });
  assert.equal(await answered.client.open("bodytext"), null);
  assert.deepEqual(await reader.chainKeyCache().entries(), []);
  const control = await exchanged(w, published);
  assert.equal(await control.client.open("bodytext"), "content:bodytext");
});

// Extensible request records ignore unknown own fields. Response key records
// remain closed. JSON.parse creates an own __proto__ field in either case,
// never a prototype; neither reading changes any prototype.
test("own __proto__ is ignored in extensible requests and refused in closed responses", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const prototypeMembers = Object.getOwnPropertyNames(Object.prototype);
  /** The JSON value with an own `__proto__` member opened right after `anchor`. */
  const smuggled = (/** @type {any} */ value, /** @type {string} */ anchor) => {
    const json = JSON.stringify(value);
    assert.ok(json.includes(anchor), `the document holds ${anchor}`);
    return JSON.parse(json.replace(anchor, `${anchor}"__proto__":{"polluted":"yes"},`));
  };

  // The same exchange opens the item without the extra member.
  const control = await exchanged(w, published);
  assert.equal(await control.client.open("bodytext"), "content:bodytext");

  // Request side: this unknown field does not change the successful grant.
  const request = smuggled(control.request, '"contentGroups":[{');
  assert.ok(Object.hasOwn(request.requested.contentGroups[0], "__proto__"));
  const issuer = w.issuer();
  const accepted = await issuer.answer(request);
  assert.equal(accepted.status, 200);
  assert.equal(issuer.calls.decide.length, 1);

  // Answer side: the client refuses the section and files no chain key.
  const reader = w.reader();
  const answered = await exchanged(w, published, {
    reader,
    answered: (body) => {
      const tampered = smuggled(body, '"chainKeys":[{');
      assert.ok(Object.hasOwn(tampered.contentGroupKeys.chainKeys[0], "__proto__"));
      return tampered;
    },
  });
  assert.equal(await answered.client.open("bodytext"), null);
  assert.deepEqual(await reader.chainKeyCache().entries(), []);

  assert.deepEqual(Object.getOwnPropertyNames(Object.prototype), prototypeMembers);
  assert.equal(/** @type {any} */ ({}).polluted, undefined);
});

test("rotated retained secrets keep rival chain keys usable in one window, in either order and at any cutoff", async () => {
  const w = await world();
  const issuer = w.issuer();
  const reader = w.reader();
  const pages = [];
  for (let i = 0; i < 3; i++) {
    const published = await w.publish({
      retainedSecret: new Uint8Array(32).fill(i + 1),
      items: [item("bodytext", ["sports"], `rotation${i}`)],
    });
    await exchanged(w, published, { reader, issuer });
    pages.push(published);
  }
  for (let i = 0; i < pages.length; i++)
    assert.equal(await reader.client(pages[i], issuer).open("bodytext"), `rotation${i}`);

  for (const order of [
    [1, 2],
    [2, 1],
  ])
    for (const cutoffs of [
      [T18, T18],
      [T18, T12],
      [T12, T18],
    ]) {
      const rotating = w.reader();
      const opened = [];
      for (let i = 0; i < order.length; i++) {
        const published = await w.publish({
          retainedSecret: new Uint8Array(32).fill(order[i]),
          items: [item("bodytext", ["sports"], `secret${order[i]}`)],
        });
        await exchanged(w, published, {
          reader: rotating,
          issuer: w.issuer({ policy: chainPolicy({ cutoffT: cutoffs[i] }) }),
        });
        opened.push([published, `secret${order[i]}`]);
      }
      for (const [published, expected] of opened)
        assert.equal(await rotating.client(published, issuer).open("bodytext"), expected);
    }
});

test("policy refusal and empty grants precede opening even a valid-width corrupted seed", async () => {
  const w = await world();
  const published = await w.publish({ items: [item("bodytext", ["sports"])] });
  const { request } = await exchanged(w, published);
  const corrupted = copy(request);
  const record = find(corrupted.sealed.contentWindowSeeds, {
    contentName: "bodytext",
    windowStart: T12,
  });
  const seed = binaryStringBytes(record.key);
  seed[seed.length - 1] ^= 1;
  record.key = base64urlEncode(seed);
  const refusing = w.issuer({ policy: chainPolicy({ authorize: () => false }) });
  assert.equal((await refusing.answer(corrupted)).code, "bad_policy");
  const empty = w.issuer({ policy: () => ({ grants: [], authorizePeriod: () => true }) });
  assert.equal((await empty.answer(corrupted)).code, "denied");
  assert.equal((await w.issuer().answer(corrupted)).code, "binding_failed");
});

// Replaces the broad client's receipt token: the delivery client that opened
// an item holds its key, whatever the shared cache later evicts.
test("a narrower grant cannot hide a wider cached key, and an opened item survives capacity eviction", async () => {
  const w = await world();
  const reader = w.reader({ limits: { maxCachedWindows: 1 } });
  const issuer = w.issuer();
  const early = await w.publish({ items: [item("bodytext", ["sports"])] });
  await exchanged(w, early, {
    reader,
    issuer: w.issuer({ policy: chainPolicy({ cutoffT: T18 }) }),
  });
  const { client: earlyClient } = await exchanged(w, early, {
    reader,
    attempt: true,
    issuer: w.issuer({ policy: chainPolicy({ cutoffT: T12 }) }),
  });
  assert.equal(earlyClient.sent.length, 1);
  assert.equal(await earlyClient.open("bodytext"), "content:bodytext");
  const middle = await w.publish({ at: T15, items: [item("bodytext", ["sports"])] });
  assert.equal(await reader.client(middle, issuer).open("bodytext"), "content:bodytext");
  const other = await w.publish({ items: [item("bodytext", ["politics"])] });
  await exchanged(w, other, { reader, issuer });
  assert.equal((await reader.chainKeyCache().entries()).length, 1);
  assert.equal(await earlyClient.open("bodytext"), "content:bodytext");
  assert.equal(await reader.client(middle, issuer).open("bodytext"), null);
});

test("concurrent rival admission retains both independent secrets", async () => {
  const w = await world();
  const reader = w.reader();
  const issuer = w.issuer();
  const pages = [];
  for (let i = 0; i < 3; i++)
    pages.push(
      await w.publish({
        retainedSecret: new Uint8Array(32).fill(i + 1),
        items: [item("bodytext", ["sports"], `secret${i}`)],
      }),
    );
  await exchanged(w, pages[0], { reader, issuer });
  await Promise.all(pages.slice(1).map((published) => exchanged(w, published, { reader, issuer })));
  for (let i = 0; i < 3; i++)
    assert.equal(await reader.client(pages[i], issuer).open("bodytext"), `secret${i}`);
});

test("a thousand distinct groups obey a finite total chain-key cache", async () => {
  const w = await world();
  const groups = names(1000);
  const published = await w.publish({ items: [item("bodytext", groups)] });
  const reader = w.reader({ limits: { maxCachedWindows: 8 } });
  const sixteen = () => ({
    grants: groups.slice(0, 16).map((group) => ({
      kind: "chain",
      contentName: "bodytext",
      group,
      windowStart: T12,
      cutoffT: T18,
    })),
    authorizePeriod: () => true,
  });
  const { client } = await exchanged(w, published, {
    reader,
    issuer: w.issuer({ policy: sixteen }),
  });
  assert.equal(await client.open("bodytext"), "content:bodytext");
  assert.ok((await reader.chainKeyCache().entries()).length <= 8);
});

test("an equivalent narrower receipt and a wider cached rival count as one trial", async () => {
  const w = await world();
  const reader = w.reader({ limits: { maxTrialsPerItem: 2 } });
  const issuer = w.issuer();
  const correct = await w.publish({ items: [item("bodytext", ["sports"])] });
  const rotated = await w.publish({
    retainedSecret: new Uint8Array(32).fill(9),
    items: [item("bodytext", ["sports"])],
  });
  await exchanged(w, correct, { reader, issuer });
  for (const cutoffT of [T18, T12]) {
    const cut = w.issuer({ policy: chainPolicy({ cutoffT }) });
    const wrong = (await exchanged(w, rotated, { issuer: cut })).issuer.calls.answers[0].body;
    await exchanged(w, correct, {
      reader,
      issuer: cut,
      attempt: true,
      answered: (body) => {
        const sports = { contentName: "bodytext", group: "sports" };
        const held = findAll(body.contentGroupKeys.chainKeys, sports);
        body.contentGroupKeys.chainKeys = body.contentGroupKeys.chainKeys
          .filter((record) => !held.includes(record))
          .concat(findAll(wrong.contentGroupKeys.chainKeys, sports));
        return body;
      },
    });
  }
  assert.equal(await reader.client(correct, issuer).open("bodytext"), "content:bodytext");
});

test("rival capacity eviction keeps the newly opened item for its own delivery client", async () => {
  const w = await world();
  const reader = w.reader({ limits: { maxRivalsPerWindow: 2 } });
  const issuer = w.issuer();
  const opened = [];
  for (let secret = 1; secret <= 3; secret++) {
    const published = await w.publish({
      retainedSecret: new Uint8Array(32).fill(secret),
      items: [item("bodytext", ["sports"], `secret${secret}`)],
    });
    const { client } = await exchanged(w, published, { reader, issuer });
    assert.equal(await client.open("bodytext"), `secret${secret}`);
    opened.push([published, client]);
  }
  assert.equal((await reader.chainKeyCache().entries()).length, 2, "two rivals in one window");
  assert.equal(await reader.client(opened[0][0], issuer).open("bodytext"), null);
  assert.equal(await opened[0][1].open("bodytext"), "secret1");
  for (let i = 1; i < 3; i++)
    assert.equal(await reader.client(opened[i][0], issuer).open("bodytext"), `secret${i + 1}`);
});

// Replaces the relabeled root dictionary: a connector moved under another
// group name derives nothing that opens.
test("page group names are derivation inputs while verified claims and issuer policy grant reach", async () => {
  const w = await world();
  const published = await w.publish({
    data: { sections: ["weather"] },
    items: [item("bodytext", ["sports"])],
  });
  const policy = (input) => ({
    grants: Object.entries(input.contentGroups).flatMap(([contentName, { groups }]) =>
      input.claims.data.sections.includes("weather") && groups.includes("sports")
        ? [{ kind: "chain", contentName, group: "sports", windowStart: T12, cutoffT: T18 }]
        : [],
    ),
    authorizePeriod: (_contentName, group) => group === "sports",
  });
  const { client } = await exchanged(w, published, { issuer: w.issuer({ policy }) });
  assert.equal(await client.open("bodytext"), "content:bodytext");

  const relabeled = copy(published);
  pageItem(relabeled.page, "bodytext").connectors = [
    { group: "politics", connector: connectorOf(relabeled.page, "bodytext", "sports") },
  ];
  const { client: other, issuer } = await exchanged(w, relabeled);
  assert.deepEqual(chainGroups(chainKeysOf(issuer.calls.answers[0]), "bodytext"), ["politics"]);
  assert.equal(await other.open("bodytext"), null);
});

// @ts-check
//
// Response admission against the one captured exchange. The consumer reads
// `association.request` with the shared request reader, admits only
// `chainKeys`, `periodKeys` and `contentKeys` members inside the pending
// content names, groups, windows and requested ceiling, and refuses the whole
// member on any fault, before it opens or files anything. The kind each key
// opens under comes from its section, never from the value.

import test from "node:test";
import assert from "node:assert/strict";

import {
  admitContentGroupResponse,
  contentGroupResponseInput,
} from "../core-client/contentGroupResponseInput.js";
import { ContentGroupRequestBuilder } from "../core-client/ContentGroupRequestBuilder.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { CHAIN } from "./_lib/chainPort.js";

const PUB = "https://news.example";
const ISSUER = "issuer";
const W1 = "261014T1200";
const W2 = "261015T0000";
const GEOMETRY = { chainsPerDay: 2, periodMinutes: 60 };
/** @param {number} n */
const b64 = (n, size = 16) => base64urlEncode(new Uint8Array(size).fill(n));
/** @param {any} value */
const json = (value) => base64urlEncode(utf8Encode(JSON.stringify(value)));
const JWT = `${json({ alg: "ES256", kid: "k1" })}.${json({ origin: PUB, renderId: b64(9) })}.c2ln`;

function page() {
  return {
    version: "1",
    resourceJWT: JWT,
    renderPeriod: "261014T1500",
    periodGeometry: GEOMETRY,
    contentData: [
      {
        contentName: "bodytext",
        contentType: "text/plain",
        connectors: [
          { group: "politics", connector: b64(1) },
          { group: "sports", connector: b64(2) },
        ],
      },
      {
        contentName: "headline",
        contentType: "text/plain",
        connectors: [{ group: "politics", connector: b64(3) }],
      },
    ],
    issuerData: [
      {
        issuerName: ISSUER,
        keyId: "kid",
        sealed: {
          contentKeys: [],
          contentWindowSeeds: [
            { contentName: "bodytext", windowStart: W1, key: b64(11, 113) },
            { contentName: "bodytext", windowStart: W2, key: b64(12, 113) },
            { contentName: "headline", windowStart: W1, key: b64(13, 113) },
          ],
        },
      },
    ],
  };
}

const dcaData = new DcaData(page(), { publisherOrigin: PUB });
/** @param {Record<string, unknown>} narrowing */
function exchange(narrowing) {
  const request = new ContentGroupRequestBuilder({ narrowing })
    .build(dcaData, ISSUER, ["bodytext", "headline"])
    .toObject();
  return new ResponseAssociation(dcaData, ISSUER, request);
}
const CUTOFF = { requestedChainCutoffs: { [W1]: "261014T1800" } };
const association = exchange({ ...CUTOFF, requestedContentKeys: { headline: "politics" } });

/** @returns {any} */
function good() {
  return {
    chainKeys: [
      { contentName: "bodytext", group: "politics", cutoff: "261014T1800", key: b64(31) },
    ],
    periodKeys: [
      { contentName: "bodytext", group: "sports", period: "261014T1500", key: b64(32) },
      { contentName: "bodytext", group: "sports", period: "261014T1600", key: b64(34) },
    ],
    contentKeys: [{ contentName: "headline", key: b64(33) }],
  };
}
/** @param {string} contentName @param {string} group @param {string} period @param {unknown} key */
const periodRecord = (contentName, group, period, key) => ({ contentName, group, period, key });
/** @param {string} contentName @param {string} group @param {string} cutoff @param {unknown} key */
const chainRecord = (contentName, group, cutoff, key) => ({ contentName, group, cutoff, key });

/** @param {any} section @param {any} [assoc] @param {Record<string, number>} [limits] */
const admit = (section, assoc = association, limits) =>
  admitContentGroupResponse(section, assoc.request, { chain: CHAIN, limits });

test("a bare chain value derives its position from the captured request and cutoff", () => {
  const staged = admit(good());
  assert.equal(staged.chains[0].value, b64(31));
  assert.equal(staged.chains[0].position, 6);
  assert.equal(staged.chains[0].windowStart, W1);
  assert.equal(staged.chains[0].keyKind, "contentGroupChainKey");
});

test("an answer inside the exchange is staged with its section's kind", () => {
  const staged = admit(good());
  assert.deepEqual(
    staged.chains.map(({ contentName, group, windowStart, cutoffT, position, keyKind }) => ({
      contentName,
      group,
      windowStart,
      cutoffT,
      position,
      keyKind,
    })),
    [
      {
        contentName: "bodytext",
        group: "politics",
        windowStart: W1,
        cutoffT: "261014T1800",
        position: 6,
        keyKind: "contentGroupChainKey",
      },
    ],
  );
  assert.deepEqual(
    staged.periods.map(({ t, keyKind }) => [t, keyKind]),
    [
      ["261014T1500", "contentGroupPeriodKey"],
      ["261014T1600", "contentGroupPeriodKey"],
    ],
  );
  assert.deepEqual(
    staged.contentKeys.map(({ contentName, group, keyKind }) => [contentName, group, keyKind]),
    [["headline", "politics", "contentKey"]],
  );
});

/** @param {(section: any) => void} mutate */
const variant = (mutate) => {
  const section = good();
  mutate(section);
  return section;
};

test("denied-period reach: a period key beyond the requested ceiling refuses the answer", () => {
  assert.throws(
    () =>
      admit(
        variant((s) =>
          s.periodKeys.push(periodRecord("bodytext", "sports", "261014T1900", b64(40))),
        ),
      ),
    /exceeds the requested cutoff/,
    "denied-period reach: a key above the requested ceiling was admitted",
  );
  assert.throws(
    () =>
      admit(
        variant(
          (s) => (s.chainKeys = [chainRecord("bodytext", "politics", "261014T1900", b64(41))]),
        ),
      ),
    /exceeds the requested cutoff/,
    "denied-period reach: a key above the requested ceiling was admitted",
  );
  // Without a requested ceiling the whole supplied window is in reach.
  const open = exchange({});
  assert.equal(
    admit(
      variant((s) => {
        s.periodKeys.push(periodRecord("bodytext", "sports", "261014T1900", b64(40)));
        delete s.contentKeys;
      }),
      open,
    ).periods.length,
    3,
  );
});

test("every member must sit inside the pending names, groups and windows", () => {
  const cases = [
    [
      (/** @type {any} */ s) =>
        s.periodKeys.push(periodRecord("purchase", "politics", "261014T1500", b64(1))),
      /pending content names and groups/,
    ],
    [
      (/** @type {any} */ s) =>
        s.periodKeys.push(periodRecord("bodytext", "opinions", "261014T1500", b64(1))),
      /pending content names and groups/,
    ],
    [
      (/** @type {any} */ s) =>
        s.chainKeys.push(chainRecord("headline", "sports", "261014T1800", b64(1))),
      /pending content names and groups/,
    ],
    [
      (/** @type {any} */ s) =>
        (s.periodKeys = [periodRecord("bodytext", "sports", "261015T0100", b64(1))]),
      /outside the pending windows/,
    ],
    [
      (/** @type {any} */ s) =>
        (s.periodKeys = [periodRecord("bodytext", "sports", "261016T0100", b64(1))]),
      /outside the pending windows/,
    ],
    [
      (/** @type {any} */ s) => s.contentKeys.push({ contentName: "bodytext", key: b64(1) }),
      /outside the requested items/,
    ],
    [(/** @type {any} */ s) => (s.extra = {}), /unknown content-group response member/],
    [
      (/** @type {any} */ s) => (s.periodKeys = { bodytext: { sports: {} } }),
      /is an array of records/,
    ],
    [(/** @type {any} */ s) => (s.contentKeys = [{ contentName: "headline" }]), /holds records/],
    [(/** @type {any} */ s) => (s.contentKeys[0].group = "politics"), /holds records/],
    [(/** @type {any} */ s) => (s.periodKeys[0] = [s.periodKeys[0]]), /holds records/],
    [(/** @type {any} */ s) => (s.chainKeys[0].period = s.chainKeys[0].cutoff), /holds records/],
  ];
  for (const [mutate, message] of cases)
    assert.throws(
      () => admit(variant(/** @type {any} */ (mutate))),
      /** @type {RegExp} */ (message),
    );
});

test("a chain record preserves its key value and its window has one selected cutoff", () => {
  const wrapped = { key: b64(1), nonce: b64(2, 12) };
  const staged = admit(variant((s) => (s.chainKeys[0].key = wrapped)));
  assert.equal(
    staged.chains[0].value,
    wrapped,
    "the selected transport opens the bare method object",
  );
  assert.equal(staged.chains[0].position, 6, "the label fixes the internal position");
  // Several candidates at the selected cutoff are staged, in either order.
  const rival = chainRecord("bodytext", "politics", "261014T1800", b64(41));
  for (const order of [
    (/** @type {any[]} */ list) => list.push(rival),
    (/** @type {any[]} */ list) => list.unshift(rival),
  ]) {
    const both = admit(variant((s) => order(s.chainKeys)));
    assert.deepEqual(both.chains.map((c) => c.value).sort(), [b64(31), b64(41)].sort());
    assert.ok(both.chains.every((c) => c.cutoffT === "261014T1800" && c.position === 6));
  }
  // A record at another cutoff of the same window conflicts, in either order.
  const other = chainRecord("bodytext", "politics", "261014T1700", b64(1));
  for (const order of [
    (/** @type {any[]} */ list) => list.push(other),
    (/** @type {any[]} */ list) => list.unshift(other),
  ])
    assert.throws(
      () => admit(variant((s) => order(s.chainKeys))),
      /different cutoffs of one window/,
    );
});

test("several key records at one period or item are candidates; record order is immaterial", () => {
  const section = variant((s) => {
    s.periodKeys.push(periodRecord("bodytext", "sports", "261014T1500", b64(42)));
    s.contentKeys.push({ contentName: "headline", key: b64(43) });
  });
  const forward = admit(JSON.parse(JSON.stringify(section)));
  assert.equal(forward.periods.length, 3);
  assert.deepEqual(
    forward.contentKeys.map((c) => c.value),
    [b64(33), b64(43)],
  );
  const reversed = /** @type {any} */ (structuredClone(section));
  for (const name of ["chainKeys", "periodKeys", "contentKeys"]) reversed[name].reverse();
  const backward = admit(JSON.parse(JSON.stringify(reversed)));
  /** @param {any} staged */
  const sorted = (staged) =>
    ["chains", "periods", "contentKeys"].map((name) =>
      staged[name].map((/** @type {any} */ e) => JSON.stringify(e)).sort(),
    );
  assert.deepEqual(sorted(backward), sorted(forward));
  // Raw candidates count toward maxPeriodKeysPerContentGroup.
  assert.throws(
    () => admit(section, association, { maxPeriodKeysPerContentGroup: 2 }),
    /period keys/,
  );
});

test("labels are canonical grid labels", () => {
  for (const label of ["261014T1530", "261014T15000", "2610141500", "261014t1500"])
    assert.throws(
      () =>
        admit(variant((s) => (s.periodKeys = [periodRecord("bodytext", "sports", label, b64(1))]))),
      /label/,
      label,
    );
});

test("raw entries count against maxResponseMembers before any member admission", () => {
  assert.throws(
    () =>
      admit(
        variant((s) =>
          s.periodKeys.push(periodRecord("purchase", "politics", "261014T1500", b64(1))),
        ),
        association,
        { maxResponseMembers: 4 },
      ),
    /raw response bound/,
  );
  assert.equal(admit(good(), association, { maxResponseMembers: 4 }).periods.length, 2);
  assert.throws(
    () => admit(good(), association, { maxPeriodKeysPerContentGroup: 1 }),
    /period keys/,
  );
});

test("a missing captured request pair and a plain exchange admit nothing", () => {
  assert.throws(
    () =>
      admitContentGroupResponse(
        good(),
        { ...association.request, periodGeometry: { periodMinutes: 60 } },
        { chain: CHAIN },
      ),
    /periodGeometry/,
  );
  const plain = new ResponseAssociation(
    dcaData,
    ISSUER,
    new DcaRequestBuilder().build(dcaData, ISSUER, ["bodytext"]),
  );
  assert.throws(() => admit(good(), plain), /no pending content-group exchange/);
});

/** A resolver context double: openKey decodes direct values and records each use. */
function context({ fail = /** @type {string|null} */ (null), retired = false } = {}) {
  /** @type {any[]} */
  const uses = [];
  /** @type {any[]} */
  const held = [];
  return {
    uses,
    held,
    value: {
      dcaData,
      issuerName: ISSUER,
      publisher: PUB,
      response: { periodGeometry: GEOMETRY, contentGroupKeys: good() },
      association,
      lease: {},
      check() {
        if (retired) throw new Error("reader retired");
      },
      /** @param {unknown} value @param {any} use */
      async openKey(value, use) {
        uses.push({ value, ...use });
        if (fail !== null && value === fail) return { key: null, issue: "malformed_key" };
        return { key: Uint8Array.from(Buffer.from(String(value), "base64url")), issue: null };
      },
      /** @param {string} contentName @param {unknown} key */
      holdContentKey(contentName, key) {
        if (retired) throw new Error("reader retired");
        held.push([contentName, key]);
      },
    },
  };
}

test("the consumer opens each key under its section's kind and files the whole answer", async () => {
  /** @type {any[]} */
  const filed = [];
  const consumer = contentGroupResponseInput({
    chain: CHAIN,
    retain: async (admitted) => {
      filed.push(admitted);
    },
  });
  assert.equal(consumer.name, "contentGroupKeys");
  assert.deepEqual(consumer.keyValues(good()).sort(), [b64(31), b64(32), b64(33), b64(34)].sort());
  const ctx = context();
  const result = await consumer.admit(good(), /** @type {any} */ (ctx.value));
  assert.deepEqual(result, { accepted: 4, issues: [] });
  assert.deepEqual(
    ctx.uses.map(({ keyKind, raw, usages }) => [keyKind, raw === true, usages ?? null]),
    [
      ["contentGroupChainKey", true, null],
      ["contentGroupPeriodKey", true, null],
      ["contentGroupPeriodKey", true, null],
      ["contentKey", false, ["decrypt"]],
    ],
  );
  assert.equal(filed.length, 1);
  assert.equal(filed[0].publisher, PUB);
  assert.deepEqual(filed[0].periodGeometry, GEOMETRY);
  assert.deepEqual(filed[0].chains[0].key, new Uint8Array(16).fill(31));
  assert.deepEqual(
    ctx.held,
    [["headline", new Uint8Array(16).fill(33)]],
    "a recovered item key is held for the plain key path, after the answer was filed",
  );
});

test("one unopenable key, a refused member or a retired reader files nothing", async () => {
  /** @type {any[]} */
  const filed = [];
  const consumer = contentGroupResponseInput({
    chain: CHAIN,
    retain: async (admitted) => {
      filed.push(admitted);
    },
  });
  assert.deepEqual(
    await consumer.admit(good(), /** @type {any} */ (context({ fail: b64(32) }).value)),
    {
      accepted: 0,
      issues: [{ code: "malformed_key" }],
    },
  );
  const refused = variant((s) =>
    s.periodKeys.push(periodRecord("bodytext", "sports", "261014T1900", b64(40))),
  );
  const ctx = context();
  assert.deepEqual(await consumer.admit(refused, /** @type {any} */ (ctx.value)), {
    accepted: 0,
    issues: [{ code: "malformed_response" }],
  });
  assert.equal(ctx.uses.length, 0, "a refused member opens nothing");
  assert.deepEqual(ctx.held, [], "a refused member holds nothing");
  await assert.rejects(
    consumer.admit(good(), /** @type {any} */ (context({ retired: true }).value)),
    /reader retired/,
  );
  assert.equal(filed.length, 0);
});

test("the request is read once per captured exchange", async () => {
  let reads = 0;
  const request = association.request;
  const watched = new Proxy(request, {
    get(target, name, receiver) {
      if (name === "requestedContentGroups") reads++;
      return Reflect.get(target, name, receiver);
    },
  });
  const consumer = contentGroupResponseInput({ chain: CHAIN, retain: async () => {} });
  const ctx = context();
  const assoc = { request: watched, matches: () => true };
  for (let i = 0; i < 3; i++)
    await consumer.admit(good(), /** @type {any} */ ({ ...ctx.value, association: assoc }));
  assert.equal(reads, 1);
});

const RETIRED = Object.freeze({ error: "key_retired" });
/** good() plus one retirement in each family section, at coordinates no key holds. */
function withErrors() {
  return {
    ...good(),
    errors: {
      chainKeys: [{ contentName: "bodytext", group: "sports", cutoff: "261014T1700", ...RETIRED }],
      periodKeys: [
        { contentName: "bodytext", group: "politics", period: "261014T1500", ...RETIRED },
      ],
    },
  };
}
const ITEM_RETIRED = Object.freeze({ contentName: "headline", ...RETIRED });
const itemAssociation = exchange({ ...CUTOFF, requestedContentKeys: { headline: "politics" } });
// No cutoffs: both supplied windows of bodytext are pending.
const twoWindows = exchange({ requestedContentKeys: { headline: "politics" } });

test("key_retired errors inside the exchange are staged beside the keys and open nothing", () => {
  const staged = admit(withErrors());
  assert.equal(staged.chains.length + staged.periods.length + staged.contentKeys.length, 4);
  assert.deepEqual(staged.errors, [
    {
      section: "chainKeys",
      contentName: "bodytext",
      group: "sports",
      windowStart: W1,
      t: "261014T1700",
      error: "key_retired",
    },
    {
      section: "periodKeys",
      contentName: "bodytext",
      group: "politics",
      windowStart: W1,
      t: "261014T1500",
      error: "key_retired",
    },
  ]);
  const item = admit({ errors: { contentKeys: [{ ...ITEM_RETIRED }] } }, itemAssociation);
  assert.deepEqual(item.errors, [
    { section: "contentKeys", contentName: "headline", group: "politics", error: "key_retired" },
  ]);
  assert.equal(admit(good()).errors.length, 0);
});

test("an error outside the exchange, of another shape or at a key's coordinate refuses the member", () => {
  /** @type {[string, (s: any) => void, any?][]} */
  /** @param {string} group @param {string} period */
  const periodError = (group, period, name = "bodytext") => ({
    contentName: name,
    group,
    period,
    ...RETIRED,
  });
  const cases = [
    ["errors is an object of record sections", (s) => (s.errors = [RETIRED])],
    ["an unknown error section", (s) => (s.errors.seeds = [{ ...ITEM_RETIRED }])],
    ["a map of errors", (s) => (s.errors.contentKeys = { headline: RETIRED })],
    [
      "a record with a message",
      (s) => (s.errors.contentKeys = [{ ...ITEM_RETIRED, message: "m" }]),
    ],
    [
      "another error code",
      (s) => (s.errors.contentKeys = [{ contentName: "headline", error: "unseal_failed" }]),
    ],
    ["a record carrying a key", (s) => (s.errors.contentKeys = [{ ...ITEM_RETIRED, key: b64(5) }])],
    ["a string record", (s) => (s.errors.contentKeys = ["key_retired"])],
    [
      "a record without its label",
      (s) => (s.errors.periodKeys = [{ contentName: "bodytext", group: "politics", ...RETIRED }]),
    ],
    [
      "an unrequested item",
      (s) => (s.errors.contentKeys = [{ contentName: "bodytext", ...RETIRED }]),
    ],
    [
      "an unrequested group",
      (s) => s.errors.periodKeys.push(periodError("sports", "261014T1500", "headline")),
    ],
    [
      "an unrequested name",
      (s) => s.errors.periodKeys.push(periodError("politics", "261014T1500", "purchase")),
    ],
    [
      "an unselected window",
      (s) => (s.errors.periodKeys = [periodError("politics", "261015T0100")]),
    ],
    [
      "a label above the ceiling",
      (s) => (s.errors.periodKeys = [periodError("politics", "261014T1900")]),
    ],
    [
      "a noncanonical label",
      (s) => (s.errors.periodKeys = [periodError("politics", "261014T1530")]),
    ],
    ["an item key and its error", (s) => (s.errors.contentKeys = [{ ...ITEM_RETIRED }])],
    [
      "a period key and its error",
      (s) => (s.errors.periodKeys = [periodError("sports", "261014T1600")]),
    ],
    [
      "a chain key and an error in its window",
      (s) =>
        (s.errors.chainKeys = [
          { contentName: "bodytext", group: "politics", cutoff: "261014T1800", ...RETIRED },
        ]),
    ],
    [
      "chain errors at different cutoffs of one window",
      (s) =>
        s.errors.chainKeys.push({
          contentName: "bodytext",
          group: "sports",
          cutoff: "261014T1600",
          ...RETIRED,
        }),
    ],
  ];
  for (const [label, mutate] of cases) {
    const section = /** @type {any} */ (withErrors());
    mutate(section);
    assert.throws(
      () => admit(section),
      (/** @type {any} */ error) =>
        error.code === "bad_response" && !/response member errors$/.test(error.message),
      label,
    );
  }
});

test("error entries count toward the response bounds with the keys", () => {
  // Four keys and two errors.
  assert.throws(
    () => admit(withErrors(), association, { maxResponseMembers: 5 }),
    /raw response bound/,
  );
  assert.equal(admit(withErrors(), association, { maxResponseMembers: 6 }).errors.length, 2);
  const periods = /** @type {any} */ (good());
  periods.errors = {
    periodKeys: [{ contentName: "bodytext", group: "sports", period: "261014T1700", ...RETIRED }],
  };
  assert.throws(
    () => admit(periods, association, { maxPeriodKeysPerContentGroup: 2 }),
    /period keys/,
  );
  const chains = /** @type {any} */ (good());
  chains.errors = {
    chainKeys: [{ contentName: "bodytext", group: "politics", cutoff: "261015T0300", ...RETIRED }],
  };
  assert.equal(admit(chains, twoWindows).errors.length, 1);
  assert.throws(() => admit(chains, twoWindows, { maxWindowsPerGroup: 1 }), /maxWindowsPerGroup/);
  // Candidates at one cutoff share their window: they count once toward
  // maxWindowsPerGroup and every one toward maxResponseMembers.
  const rivals = /** @type {any} */ (good());
  rivals.chainKeys.push(chainRecord("bodytext", "politics", "261014T1800", b64(41)));
  assert.equal(admit(rivals, association, { maxWindowsPerGroup: 1 }).chains.length, 2);
  assert.throws(() => admit(rivals, association, { maxResponseMembers: 4 }), /raw response bound/);
});

test("an admitted error delivers no key, files nothing and holds nothing", async () => {
  /** @type {any[]} */
  const filed = [];
  const consumer = contentGroupResponseInput({
    chain: CHAIN,
    retain: async (admitted) => {
      filed.push(admitted);
    },
  });
  // Error records are not key values for the response-wide rules.
  assert.deepEqual(
    consumer.keyValues(withErrors()).sort(),
    [b64(31), b64(32), b64(33), b64(34)].sort(),
  );
  const only = { errors: { contentKeys: [{ ...ITEM_RETIRED }] } };
  const ctx = context();
  const value = { ...ctx.value, association: itemAssociation };
  assert.deepEqual(await consumer.admit(only, /** @type {any} */ (value)), {
    accepted: 0,
    issues: [],
    errors: [
      { section: "contentKeys", contentName: "headline", group: "politics", error: "key_retired" },
    ],
  });
  assert.equal(ctx.uses.length, 0);
  assert.deepEqual(ctx.held, []);
  assert.equal(filed.length, 0, "an errors-only answer reaches no retention");
  // Beside keys, the keys are filed and the errors are not.
  const mixed = context();
  assert.deepEqual(await consumer.admit(withErrors(), /** @type {any} */ (mixed.value)), {
    accepted: 4,
    issues: [],
    errors: admit(withErrors()).errors,
  });
  assert.equal(mixed.uses.length, 4);
  assert.equal(filed.length, 1);
  assert.deepEqual(
    [filed[0].chains.length, filed[0].periods.length, filed[0].contentKeys.length],
    [1, 2, 1],
  );
});

test("response geometry is unnecessary and mutation during opening cannot change retention", async () => {
  const filed = [];
  const consumer = contentGroupResponseInput({
    chain: CHAIN,
    retain: async (entry) => {
      filed.push(entry);
    },
  });
  const ctx = context();
  delete ctx.value.response.periodGeometry;
  const open = ctx.value.openKey;
  ctx.value.openKey = async (value, use) => {
    ctx.value.response.periodGeometry = { chainsPerDay: 4, periodMinutes: 30 };
    return open(value, use);
  };
  assert.deepEqual(await consumer.admit(good(), ctx.value), { accepted: 4, issues: [] });
  assert.deepEqual(filed[0].periodGeometry, GEOMETRY);
});

test("the frozen associated request survives source request and delivery geometry mutation", async () => {
  const data = new DcaData(page(), { publisherOrigin: PUB });
  const request = new ContentGroupRequestBuilder({
    narrowing: { ...CUTOFF, requestedContentKeys: { headline: "politics" } },
  })
    .build(data, ISSUER, ["bodytext", "headline"])
    .toObject();
  const captured = new ResponseAssociation(data, ISSUER, request);
  request.periodGeometry.chainsPerDay = 4;
  data.toObject().periodGeometry = { chainsPerDay: 4, periodMinutes: 30 };
  assert.deepEqual(captured.request.periodGeometry, GEOMETRY);
  assert.ok(Object.isFrozen(captured.request.periodGeometry));
  const filed = [];
  const consumer = contentGroupResponseInput({
    chain: CHAIN,
    retain: async (entry) => {
      filed.push(entry);
    },
  });
  const ctx = context();
  ctx.value.association = captured;
  ctx.value.dcaData = data;
  ctx.value.response.periodGeometry = { chainsPerDay: 8, periodMinutes: 15 };
  assert.equal((await consumer.admit(good(), ctx.value)).accepted, 4);
  assert.deepEqual(filed[0].periodGeometry, GEOMETRY);
});

test("missing, partial and conflicting captured request geometry refuses before key opening", async () => {
  for (const geometry of [
    undefined,
    { periodMinutes: 60 },
    { chainsPerDay: 4, periodMinutes: 60 },
  ]) {
    const request = new ContentGroupRequestBuilder({
      narrowing: { ...CUTOFF, requestedContentKeys: { headline: "politics" } },
    })
      .build(dcaData, ISSUER, ["bodytext", "headline"])
      .toObject();
    request.periodGeometry = geometry;
    const ctx = context();
    ctx.value.association = new ResponseAssociation(dcaData, ISSUER, request);
    let writes = 0;
    const consumer = contentGroupResponseInput({
      chain: CHAIN,
      retain: async () => {
        writes++;
      },
    });
    const result = await consumer.admit(good(), ctx.value);
    assert.deepEqual(result, { accepted: 0, issues: [{ code: "malformed_response" }] });
    assert.deepEqual(ctx.uses, []);
    assert.equal(writes, 0);
  }
});

test("a repeated error record at one coordinate is one report: the last whole record stands", () => {
  const section = /** @type {any} */ (withErrors());
  section.errors.periodKeys.push({ ...section.errors.periodKeys[0] });
  const staged = admit(section);
  assert.equal(staged.errors.filter((e) => e.section === "periodKeys").length, 1);
  // The raw copy still counts toward the bounds.
  assert.throws(() => admit(section, association, { maxResponseMembers: 6 }), /raw response bound/);
});

for (const [kind, coordinate] of Object.entries({
  chainKeys: { contentName: "bodytext", group: "sports", cutoff: "261014T1700" },
  periodKeys: { contentName: "bodytext", group: "politics", period: "261014T1500" },
  contentKeys: { contentName: "headline" },
})) {
  test(`${kind} error replacement validates only the last whole payload and keeps raw bounds`, () => {
    const valid = { ...coordinate, error: "key_retired" };
    const section = (/** @type {unknown[]} */ errors) => ({ errors: { [kind]: errors } });
    for (const invalid of [
      { ...coordinate, error: "invented-error" },
      { ...coordinate },
      { ...coordinate, error: "key_retired", extra: true },
    ]) {
      const staged = admit(section([invalid, valid]));
      assert.equal(staged.errors.length, 1);
      assert.equal(staged.errors[0].error, "key_retired");
      assert.throws(() => admit(section([valid, invalid])), { code: "bad_response" });
      assert.throws(
        () => admit(section([invalid, valid]), association, { maxResponseMembers: 1 }),
        /raw response bound/,
      );
    }
    // Replacement never repairs a bad identity or a key/error conflict.
    assert.throws(() => admit(section([{ ...valid, contentName: null }, valid])), {
      code: "bad_response",
    });
    const conflict = good();
    const occupied = conflict[kind][0];
    const { key: _key, ...occupiedCoordinate } = occupied;
    assert.throws(
      () =>
        admit({
          ...conflict,
          errors: { [kind]: [{ ...occupiedCoordinate, error: "key_retired" }] },
        }),
      { code: "bad_response" },
    );
    if (kind === "periodKeys")
      assert.throws(
        () => admit(section([valid, valid]), association, { maxPeriodKeysPerContentGroup: 1 }),
        /period keys over/,
      );
  });
}

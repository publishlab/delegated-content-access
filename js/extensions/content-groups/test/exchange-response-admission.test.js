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
    contentData: {
      bodytext: {
        contentType: "text/plain",
        nonce: b64(0, 12),
        connectors: { politics: b64(1), sports: b64(2) },
      },
      headline: { contentType: "text/plain", nonce: b64(0, 12), connectors: { politics: b64(3) } },
    },
    issuerData: {
      [ISSUER]: {
        keyId: "kid",
        sealed: {
          contentKeys: {},
          contentWindowSeeds: {
            bodytext: { [W1]: b64(11, 125), [W2]: b64(12, 125) },
            headline: { [W1]: b64(13, 125) },
          },
        },
      },
    },
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

function good() {
  return {
    chainKeys: { bodytext: { politics: { "261014T1800": b64(31) } } },
    periodKeys: { bodytext: { sports: { "261014T1500": b64(32), "261014T1600": b64(34) } } },
    contentKeys: { headline: b64(33) },
  };
}

/** @param {any} section @param {any} [assoc] @param {Record<string, number>} [limits] */
const admit = (section, assoc = association, limits) =>
  admitContentGroupResponse(section, assoc.request, { chain: CHAIN, limits });

test("a bare chain value derives its position from the captured request and cutoff", () => {
  const section = /** @type {any} */ (good());
  section.chainKeys.bodytext.politics["261014T1800"] = b64(31);
  const staged = admit(section);
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
    () => admit(variant((s) => (s.periodKeys.bodytext.sports["261014T1900"] = b64(40)))),
    /exceeds the requested cutoff/,
    "denied-period reach: a key above the requested ceiling was admitted",
  );
  assert.throws(
    () => admit(variant((s) => (s.chainKeys.bodytext.politics = { "261014T1900": b64(41) }))),
    /exceeds the requested cutoff/,
    "denied-period reach: a key above the requested ceiling was admitted",
  );
  // Without a requested ceiling the whole supplied window is in reach.
  const open = exchange({});
  assert.equal(
    admit(
      variant((s) => {
        s.periodKeys.bodytext.sports["261014T1900"] = b64(40);
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
      (/** @type {any} */ s) => (s.periodKeys.purchase = { politics: {} }),
      /pending content names and groups/,
    ],
    [
      (/** @type {any} */ s) => (s.periodKeys.bodytext.opinions = {}),
      /pending content names and groups/,
    ],
    [
      (/** @type {any} */ s) => (s.chainKeys.headline = { sports: {} }),
      /pending content names and groups/,
    ],
    [
      (/** @type {any} */ s) => (s.periodKeys.bodytext.sports = { "261015T0100": b64(1) }),
      /outside the pending windows/,
    ],
    [
      (/** @type {any} */ s) => (s.periodKeys.bodytext.sports = { "261016T0100": b64(1) }),
      /outside the pending windows/,
    ],
    [(/** @type {any} */ s) => (s.contentKeys.bodytext = b64(1)), /outside the requested items/],
    [(/** @type {any} */ s) => (s.extra = {}), /unknown content-group response member/],
    [(/** @type {any} */ s) => (s.periodKeys = []), /is a map/],
  ];
  for (const [mutate, message] of cases)
    assert.throws(
      () => admit(variant(/** @type {any} */ (mutate))),
      /** @type {RegExp} */ (message),
    );
});

test("a chain member preserves its key value and occupies one place per window", () => {
  const wrapped = { key: b64(1), nonce: b64(2, 12) };
  const staged = admit(variant((s) => (s.chainKeys.bodytext.politics["261014T1800"] = wrapped)));
  assert.equal(
    staged.chains[0].value,
    wrapped,
    "the selected transport opens the bare method object",
  );
  assert.equal(staged.chains[0].position, 6, "the label fixes the internal position");
  assert.throws(
    () => admit(variant((s) => (s.chainKeys.bodytext.politics["261014T1700"] = b64(1)))),
    /one chain key per window/,
  );
});

test("labels are canonical grid labels", () => {
  for (const label of ["261014T1530", "261014T15000", "2610141500", "261014t1500"])
    assert.throws(
      () => admit(variant((s) => (s.periodKeys.bodytext.sports = { [label]: b64(1) }))),
      /label/,
      label,
    );
});

test("raw entries count against maxResponseMembers before any member admission", () => {
  assert.throws(
    () =>
      admit(
        variant((s) => (s.periodKeys.purchase = { politics: { "261014T1500": b64(1) } })),
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
      response: { periodGeometry: GEOMETRY, contentGroups: good() },
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
  assert.equal(consumer.name, "contentGroups");
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
  const refused = variant((s) => (s.periodKeys.bodytext.sports["261014T1900"] = b64(40)));
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
      chainKeys: { bodytext: { sports: { "261014T1700": { ...RETIRED } } } },
      periodKeys: { bodytext: { politics: { "261014T1500": { ...RETIRED } } } },
    },
  };
}
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
  const item = admit({ errors: { contentKeys: { headline: { ...RETIRED } } } }, itemAssociation);
  assert.deepEqual(item.errors, [
    { section: "contentKeys", contentName: "headline", group: "politics", error: "key_retired" },
  ]);
  assert.equal(admit(good()).errors.length, 0);
});

test("an error outside the exchange, of another shape or at a key's coordinate refuses the member", () => {
  /** @type {[string, (s: any) => void, any?][]} */
  const cases = [
    ["errors is a map", (s) => (s.errors = [RETIRED])],
    ["an unknown error map", (s) => (s.errors.seeds = { bodytext: RETIRED })],
    [
      "a leaf with a message",
      (s) => (s.errors.contentKeys = { headline: { ...RETIRED, message: "m" } }),
    ],
    [
      "another error code",
      (s) => (s.errors.contentKeys = { headline: { error: "unseal_failed" } }),
    ],
    [
      "a leaf carrying a key",
      (s) => (s.errors.contentKeys = { headline: { ...RETIRED, key: b64(5) } }),
    ],
    ["a string leaf", (s) => (s.errors.contentKeys = { headline: "key_retired" })],
    ["a leaf above its depth", (s) => (s.errors.periodKeys.bodytext.politics = RETIRED)],
    ["an unrequested item", (s) => (s.errors.contentKeys = { bodytext: RETIRED })],
    [
      "an unrequested group",
      (s) => (s.errors.periodKeys.headline = { sports: { "261014T1500": RETIRED } }),
    ],
    [
      "an unrequested name",
      (s) => (s.errors.periodKeys.purchase = { politics: { "261014T1500": RETIRED } }),
    ],
    [
      "an unselected window",
      (s) => (s.errors.periodKeys.bodytext.politics = { "261015T0100": RETIRED }),
    ],
    [
      "a label above the ceiling",
      (s) => (s.errors.periodKeys.bodytext.politics = { "261014T1900": RETIRED }),
    ],
    [
      "a noncanonical label",
      (s) => (s.errors.periodKeys.bodytext.politics = { "261014T1530": RETIRED }),
    ],
    ["an item key and its error", (s) => (s.errors.contentKeys = { headline: RETIRED })],
    [
      "a period key and its error",
      (s) => (s.errors.periodKeys.bodytext.sports = { "261014T1600": RETIRED }),
    ],
    [
      "a chain key and an error in its window",
      (s) => (s.errors.chainKeys.bodytext.politics = { "261014T1700": RETIRED }),
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
  periods.errors = { periodKeys: { bodytext: { sports: { "261014T1700": RETIRED } } } };
  assert.throws(
    () => admit(periods, association, { maxPeriodKeysPerContentGroup: 2 }),
    /period keys/,
  );
  const chains = /** @type {any} */ (good());
  chains.errors = { chainKeys: { bodytext: { politics: { "261015T0300": RETIRED } } } };
  assert.equal(admit(chains, twoWindows).errors.length, 1);
  assert.throws(() => admit(chains, twoWindows, { maxWindowsPerGroup: 1 }), /maxWindowsPerGroup/);
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
  const only = { errors: { contentKeys: { headline: { ...RETIRED } } } };
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

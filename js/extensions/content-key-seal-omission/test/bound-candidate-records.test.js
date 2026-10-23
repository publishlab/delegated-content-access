// @ts-check
//
// `boundCandidates` on the named-record wire: one record per bound wrap entry,
// `{contentName, accessGroup, period, key, bind}`. Array position means
// nothing, so the client, the publisher and the issuer read the same records
// in any order. A sealed period record at a coordinate is a candidate like any
// other: every distinct one gets its own trial.

import test from "node:test";
import assert from "node:assert/strict";

import { base64urlEncode } from "../../../core-shared/codec.js";
import { omissionBoundCandidates } from "../core-shared--client-publisher/omissionCandidates.js";
import { omissionPresentedContentNames } from "../core-client/OmissionRequestBuilder.js";
import { candidatesFor, presentedCoordinates } from "../core-issuer/omissionCandidates.js";
import { OMISSION_BIND_IDENTIFIER, omissionBindAad } from "../core-shared/omissionBind.js";
import { omissionContentKeySource } from "../core-issuer/omissionContentKeySource.js";
import { encrypt } from "../../../core-shared/aead.js";
import { contentKeyWrapNonce } from "../../../core-shared/contentKeyWrapNonce.js";

const BIND = OMISSION_BIND_IDENTIFIER;
const P1 = "251023T2200";
const P2 = "251023T2300";
/** A canonical v1 wrap: 16 key bytes and the 16-byte tag. @param {number} n */
const wrap = (n) => base64urlEncode(new Uint8Array(32).fill(n));
/** @param {number} n */
const blob = (n) => base64urlEncode(new Uint8Array(60).fill(n));

/** @param {any} document */
function request(document) {
  return { toObject: () => document, sealedPeriodKeys: document.sealed?.periodKeys };
}

const GRANT = { sourceGrants: [{ accessGroup: "premium", periods: [P1, P2] }] };

test("the client writes one record per bound wrap entry, its period named `period`", () => {
  const records = omissionBoundCandidates(["bodytext", "note"], (name) =>
    name === "bodytext"
      ? [
          [
            "premium",
            [
              { t: P1, key: wrap(1), bind: BIND, nonce: "x" },
              { t: P2, key: wrap(2) },
            ],
          ],
          ["basic", [{ t: P2, key: wrap(3), bind: BIND }]],
        ]
      : [],
  );
  assert.deepEqual(records, [
    { contentName: "bodytext", accessGroup: "premium", period: P1, key: wrap(1), bind: BIND },
    { contentName: "bodytext", accessGroup: "basic", period: P2, key: wrap(3), bind: BIND },
  ]);
});

test("the presented content names are the distinct names the records carry", () => {
  const boundCandidates = [
    { contentName: "note", accessGroup: "premium", period: P1, key: wrap(1), bind: BIND },
    { contentName: "bodytext", accessGroup: "premium", period: P1, key: wrap(2), bind: BIND },
    { contentName: "note", accessGroup: "premium", period: P2, key: wrap(3), bind: BIND },
  ];
  assert.deepEqual(omissionPresentedContentNames({ boundCandidates }), ["note", "bodytext"]);
  assert.deepEqual(
    omissionPresentedContentNames({ boundCandidates: { bodytext: boundCandidates } }),
    [],
  );
});

test("the issuer presents admitted names, groups and source-only period labels", () => {
  const document = {
    sealed: {},
    boundCandidates: [
      { contentName: "bodytext", accessGroup: "premium", period: P1, key: wrap(1), bind: BIND },
      { contentName: "note", accessGroup: "basic", period: P2, key: wrap(2), bind: BIND },
      { contentName: "note", accessGroup: "basic", period: P2, key: wrap(4), bind: BIND },
    ],
  };
  const presented = presentedCoordinates(request(document));
  assert.deepEqual(presented.contentNames, ["bodytext", "note"]);
  assert.deepEqual(presented.accessGroups.sort(), ["basic", "premium"]);
  assert.deepEqual(presented.sourcePeriodCoordinates, { premium: [P1], basic: [P2] });

  const mapped = { sealed: {}, boundCandidates: { bodytext: document.boundCandidates } };
  assert.throws(() => presentedCoordinates(request(mapped)), { code: "binding_failed" });
});

test("a record that names `t` instead of required period refuses the request", () => {
  const document = {
    sealed: { periodKeys: [{ accessGroup: "premium", period: P1, key: blob(9) }] },
    boundCandidates: [
      { contentName: "bodytext", accessGroup: "premium", t: P1, key: wrap(1), bind: BIND },
      { contentName: "bodytext", accessGroup: "premium", period: P1, key: wrap(2), bind: BIND },
    ],
  };
  assert.throws(
    () => candidatesFor({ request: request(document), decision: GRANT, periodKeyFor: null }),
    { code: "binding_failed" },
  );
});

test("every distinct sealed period record at a coordinate is its own trial", () => {
  const document = {
    sealed: {
      periodKeys: [
        { accessGroup: "premium", period: P1, key: blob(7) },
        { accessGroup: "premium", period: P1, key: blob(8) },
        { accessGroup: "premium", period: P1, key: blob(7) },
      ],
    },
    boundCandidates: [
      { contentName: "bodytext", accessGroup: "premium", period: P1, key: wrap(1), bind: BIND },
    ],
  };
  const held = async () => null;
  const tries = candidatesFor({ request: request(document), decision: GRANT, periodKeyFor: held });
  const listed = tries.get("bodytext") ?? [];
  assert.deepEqual(
    listed.map((entry) => (entry.periodKey ? "held" : entry.sealed)),
    ["held", blob(7), blob(8)],
  );
});

test("a sealed period record alone presents its label to the grant clamp", () => {
  // P2 is granted, and only a sealed period record presents it.
  const document = {
    sealed: { periodKeys: [{ accessGroup: "premium", period: P2, key: blob(5) }] },
    boundCandidates: [
      { contentName: "bodytext", accessGroup: "premium", period: P2, key: wrap(1), bind: BIND },
    ],
  };
  const tries = candidatesFor({
    request: request(document),
    decision: { sourceGrants: [{ accessGroup: "premium", periods: [P2] }] },
    periodKeyFor: null,
  });
  assert.equal(tries.get("bodytext")?.length, 1);
});

test("record order across a JSON boundary changes no trial", () => {
  const document = {
    sealed: {
      periodKeys: [
        { accessGroup: "premium", period: P1, key: blob(7) },
        { accessGroup: "premium", period: P2, key: blob(8) },
      ],
    },
    boundCandidates: [
      { contentName: "bodytext", accessGroup: "premium", period: P1, key: wrap(1), bind: BIND },
      { contentName: "note", accessGroup: "premium", period: P2, key: wrap(2), bind: BIND },
      { contentName: "bodytext", accessGroup: "premium", period: P2, key: wrap(3), bind: BIND },
    ],
  };
  const reversed = JSON.parse(JSON.stringify(document));
  reversed.sealed.periodKeys.reverse();
  reversed.boundCandidates.reverse();
  /** @param {any} doc */
  const summary = (doc) =>
    Object.fromEntries(
      [...candidatesFor({ request: request(doc), decision: GRANT, periodKeyFor: null })]
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([name, list]) => [
          name,
          list.map(({ coordinate, sealed }) => JSON.stringify({ coordinate, sealed })).sort(),
        ]),
    );
  assert.deepEqual(summary(reversed), summary(document));
});

test("the source opens each rival sealed blob at one coordinate, whichever comes first", async () => {
  const renderId = "AAECAwQFBgcICQoLDA0ODw";
  const periodKey = new Uint8Array(16).fill(4);
  const contentKey = new Uint8Array(16).fill(6);
  const binding = { renderId, contentName: "bodytext", accessGroup: "premium", t: P1 };
  const aad = omissionBindAad(binding);
  const nonce = /** @type {Uint8Array} */ (await contentKeyWrapNonce({ ...binding, aad }));
  const wrapped = base64urlEncode(await encrypt(periodKey, nonce, contentKey, aad));
  const candidate = {
    contentName: "bodytext",
    accessGroup: "premium",
    period: P1,
    key: wrapped,
    bind: BIND,
  };
  // Only blob 8 opens to the period key; blob 7 is admissible but wrong.
  /** @param {unknown} sealed */
  const open = async (sealed) =>
    sealed === blob(8)
      ? { bytes: periodKey }
      : { error: { error: "unseal_failed", message: "no" } };

  for (const order of [
    [blob(7), blob(8)],
    [blob(8), blob(7)],
  ]) {
    const document = {
      sealed: {
        periodKeys: order.map((key) => ({ accessGroup: "premium", period: P1, key })),
      },
      boundCandidates: [candidate],
    };
    const lookup = omissionContentKeySource().contentKeys({
      request: /** @type {any} */ (request(document)),
      decision: { sourceGrants: [{ accessGroup: "premium", periods: [P1] }] },
      scope: undefined,
      renderId,
      open,
    });
    assert.deepEqual(await lookup("bodytext"), { bytes: contentKey }, order.join(","));
  }
});

test("a held Buffer snapshot cannot change between items after its host storage mutates", async () => {
  const renderId = "AAECAwQFBgcICQoLDA0ODw";
  const held = Buffer.alloc(16, 4);
  const contentKey = new Uint8Array(16).fill(6);
  const records = [];
  for (const contentName of ["bodytext", "note"]) {
    const binding = { renderId, contentName, accessGroup: "premium", t: P1 };
    const aad = omissionBindAad(binding);
    const nonce = /** @type {Uint8Array} */ (await contentKeyWrapNonce({ ...binding, aad }));
    records.push({
      contentName,
      accessGroup: "premium",
      period: P1,
      key: base64urlEncode(await encrypt(held, nonce, contentKey, aad)),
      bind: BIND,
    });
  }
  let calls = 0;
  const lookup = omissionContentKeySource().contentKeys({
    request: /** @type {any} */ (request({ sealed: {}, boundCandidates: records })),
    decision: { sourceGrants: [{ accessGroup: "premium", periods: [P1] }] },
    scope: async () => {
      calls++;
      return [held];
    },
    renderId,
    open: async () => {
      throw new Error("must use held keys");
    },
  });
  assert.deepEqual(await lookup("bodytext"), { bytes: contentKey });
  held.fill(0);
  assert.deepEqual(await lookup("note"), { bytes: contentKey });
  assert.equal(calls, 1);
});

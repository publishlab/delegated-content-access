// @ts-check
//
// The relay counts the selected issuer's received chain carrier before it
// projects the needed families
// (docs/spec-profile--chain-keys.md Section 22.1, docs/spec--data-format.md Section
// 4.3). A family with more than two raw members is omitted from the request; a
// collection with more than 16 raw members across all its families sends no
// chain member at all. Projection must not turn an over-limit input into an
// accepted subset. Another issuer block in the same delivery is a separate
// collection and never adds to the selected issuer's count.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";

const ISSUER_A = "issuer-a";
const ISSUER_B = "issuer-b";
const MALFORMED = "not-base64!";

/** Window terminals of the 2/15 geometry, one per window, in label order. */
const TERMINALS = [
  "251023T2345",
  "251024T1145",
  "251024T2345",
  "251025T1145",
  "251025T2345",
  "251026T1145",
];

/**
 * One family of `count` raw member records with canonical inert values, except
 * the members named in `malformedAt`, which carry a value no reader admits.
 *
 * @param {string} accessGroup
 * @param {number} count
 * @param {number[]} [malformedAt]
 * @returns {{ accessGroup: string, cutoff: string, key: string }[]}
 */
function family(accessGroup, count, malformedAt = []) {
  return Array.from({ length: count }, (_, index) => ({
    accessGroup,
    cutoff: TERMINALS[index],
    key: malformedAt.includes(index) ? MALFORMED : base64urlEncode(Uint8Array.of(16 + index)),
  }));
}

/**
 * The access groups a relayed chain collection names, each once, sorted.
 *
 * @param {any[]} records
 */
function groupsOf(records) {
  return [...new Set(records.map((record) => record.accessGroup))].sort();
}

/**
 * `bodytext` is wrapped under `premium` and `vault`; every other chain family
 * the issuer block carries is one this request does not need.
 *
 * @param {unknown[]} chainKeysA - issuer A's whole chain collection
 * @param {unknown[]} [chainKeysB] - issuer B's, a separate block
 */
function pageData(chainKeysA, chainKeysB = family("premium", 2)) {
  return {
    version: "1",
    resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "raw-render" })))}.c2lnbmF0dXJl`,
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
    contentData: [
      {
        contentName: "bodytext",
        contentType: "text/html",
        nonce: "n",
        keys: [
          { accessGroup: "premium", period: "251023T1400", nonce: "pn", key: "pk" },
          { accessGroup: "vault", period: "251023T1415", nonce: "vn", key: "vk" },
        ],
      },
    ],
    issuerData: [
      {
        issuerName: ISSUER_A,
        keyId: "a-key",
        unlockUrl: "https://a.example/unlock",
        sealed: {
          contentKeys: [{ contentName: "bodytext", key: "AQ" }],
          periodKeys: [{ accessGroup: "premium", period: "251023T1400", key: "Ag" }],
          chainKeys: chainKeysA,
        },
      },
      {
        issuerName: ISSUER_B,
        keyId: "b-key",
        unlockUrl: "https://b.example/unlock",
        sealed: { contentKeys: [{ contentName: "bodytext", key: "CA" }], chainKeys: chainKeysB },
      },
    ],
  };
}

/** @param {any} data */
function relay(data) {
  const page = new DcaData(data);
  const before = JSON.stringify(data);
  const relayed = new ChainKeyRequestBuilder({ relayPeriodKeys: true })
    .build(page, ISSUER_A, ["bodytext"])
    .toObject();
  assert.equal(JSON.stringify(data), before, "counting reads the page without changing it");
  const base = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(page, ISSUER_A, ["bodytext"])
    .toObject();
  return { relayed, base };
}

/**
 * Unneeded families of two raw members each, `count` of them, one malformed
 * value in each so filtering would shrink them.
 *
 * @param {number} count
 */
function unneeded(count) {
  return Array.from({ length: count }, (_, index) => family(`unused${index}`, 2, [1])).flat();
}

test("a needed family relays at two raw members and is omitted at three", () => {
  const { relayed: two } = relay(pageData([...family("premium", 2), ...family("vault", 1)]));
  assert.deepEqual(groupsOf(two.sealed.chainKeys), ["premium", "vault"]);

  for (const premium of [
    family("premium", 3),
    family("premium", 3, [2]),
    family("premium", 3, [0, 2]),
  ]) {
    const { relayed, base } = relay(pageData([...premium, ...family("vault", 1)]));
    assert.deepEqual(
      relayed.sealed.chainKeys,
      family("vault", 1),
      "the over-limit family goes, even when some values cannot be decoded",
    );
    assert.deepEqual(
      relayed.periodGeometry,
      { chainsPerDay: 2, periodMinutes: 15 },
      "the root geometry applies to the relayed sibling",
    );
    assert.deepEqual(relayed.requestedPeriodKeys, [
      { accessGroup: "vault", periods: ["251023T1415"] },
    ]);
    assert.deepEqual(relayed.sealed.contentKeys, base.sealed.contentKeys);
    assert.deepEqual(relayed.sealed.periodKeys, base.sealed.periodKeys);
  }
});

test("exactly two raw members relay both values unchanged, including malformed", () => {
  const { relayed } = relay(pageData([...family("premium", 2, [1]), ...family("vault", 1)]));
  assert.deepEqual(
    relayed.sealed.chainKeys.filter(
      (/** @type {any} */ record) => record.accessGroup === "premium",
    ),
    family("premium", 2, [1]),
  );
  assert.deepEqual(relayed.requestedPeriodKeys[0], {
    accessGroup: "premium",
    periods: ["251023T1400"],
  });
});

test("the selected collection relays at 16 raw members and sends no chain member at 17", () => {
  // Six unneeded families of two, each with a malformed value, plus the two
  // needed families of two: 16 raw members, 10 of them admissible.
  const sixteen = [...family("premium", 2), ...family("vault", 2), ...unneeded(6)];
  const { relayed: atLimit } = relay(pageData(sixteen));
  assert.deepEqual(groupsOf(atLimit.sealed.chainKeys), ["premium", "vault"]);

  for (const extra of [family("spare", 1), family("spare", 1, [0])]) {
    const { relayed, base } = relay(pageData([...sixteen, ...extra]));
    assert.equal(Object.hasOwn(relayed.sealed, "chainKeys"), false);
    assert.equal(Object.hasOwn(relayed, "periodGeometry"), false);
    assert.equal(Object.hasOwn(relayed, "requestedPeriodKeys"), false);
    assert.deepEqual(relayed, base, "the base request reaches the issuer unchanged");
  }
});

test("another issuer block never counts toward the selected collection", () => {
  const sixteen = [...family("premium", 2), ...family("vault", 2), ...unneeded(6)];
  const crowdedB = [...family("premium", 2), ...family("vault", 2), ...unneeded(7)];
  const { relayed } = relay(pageData(sixteen, crowdedB));
  assert.deepEqual(groupsOf(relayed.sealed.chainKeys), ["premium", "vault"]);
  assert.equal(JSON.stringify(relayed).includes("unused6"), false);
});

test("with no chain family left the request carries no chain member and keeps its base", () => {
  const { relayed, base } = relay(pageData([...family("premium", 3), ...family("vault", 3, [1])]));
  assert.equal(Object.hasOwn(relayed.sealed, "chainKeys"), false);
  assert.equal(Object.hasOwn(relayed, "periodGeometry"), false);
  assert.equal(Object.hasOwn(relayed, "requestedPeriodKeys"), false);
  assert.deepEqual(relayed, base);
  assert.deepEqual(relayed.sealed.periodKeys, [
    { accessGroup: "premium", period: "251023T1400", key: "Ag" },
  ]);
});

test("a record whose fields are only inherited names no family and rejects the collection", () => {
  // A reader of inherited fields would count two more premium members, omit
  // premium as over its bound and relay vault. Read by own fields, these
  // records carry no accessGroup, and a delivery collection with a record
  // missing its identity supplies no chain member at all
  // (docs/spec--data-format.md Section 2.1).
  const inherited = [2, 3].map((index) =>
    Object.create({ accessGroup: "premium", cutoff: TERMINALS[index], key: "AQ" }),
  );
  const { relayed, base } = relay(
    pageData([...family("premium", 2), ...inherited, ...family("vault", 1)]),
  );
  assert.equal(Object.hasOwn(relayed.sealed, "chainKeys"), false);
  assert.equal(Object.hasOwn(relayed, "requestedPeriodKeys"), false);
  assert.deepEqual(relayed, base);
});

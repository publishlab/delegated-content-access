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
 * One family of `count` raw members with canonical inert values, except the
 * members named in `malformedAt`, which carry a value no reader admits.
 *
 * @param {number} count
 * @param {number[]} [malformedAt]
 * @returns {Record<string, string>}
 */
function family(count, malformedAt = []) {
  /** @type {Record<string, string>} */
  const members = {};
  for (let index = 0; index < count; index++) {
    members[TERMINALS[index]] = malformedAt.includes(index)
      ? MALFORMED
      : base64urlEncode(Uint8Array.of(16 + index));
  }
  return members;
}

/**
 * `bodytext` is wrapped under `premium` and `vault`; every other chain family
 * the issuer block carries is one this request does not need.
 *
 * @param {Record<string, unknown>} chainKeysA - issuer A's whole chain collection
 * @param {Record<string, unknown>} [chainKeysB] - issuer B's, a separate block
 */
function pageData(chainKeysA, chainKeysB = { premium: family(2) }) {
  return {
    version: "1",
    resourceJWT: `e30.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "raw-render" })))}.c2lnbmF0dXJl`,
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        keys: {
          premium: [{ t: "251023T1400", nonce: "pn", key: "pk" }],
          vault: [{ t: "251023T1415", nonce: "vn", key: "vk" }],
        },
      },
    },
    issuerData: {
      [ISSUER_A]: {
        keyId: "a-key",
        unlockUrl: "https://a.example/unlock",
        sealed: {
          contentKeys: { bodytext: "AQ" },
          periodKeys: { premium: { "251023T1400": "Ag" } },
          chainKeys: chainKeysA,
        },
      },
      [ISSUER_B]: {
        keyId: "b-key",
        unlockUrl: "https://b.example/unlock",
        sealed: { contentKeys: { bodytext: "CA" }, chainKeys: chainKeysB },
      },
    },
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
  return Object.fromEntries(
    Array.from({ length: count }, (_, index) => [`unused${index}`, family(2, [1])]),
  );
}

test("a needed family relays at two raw members and is omitted at three", () => {
  const { relayed: two } = relay(pageData({ premium: family(2), vault: family(1) }));
  assert.deepEqual(Object.keys(two.sealed.chainKeys).sort(), ["premium", "vault"]);

  for (const premium of [family(3), family(3, [2]), family(3, [0, 2])]) {
    const { relayed, base } = relay(pageData({ premium, vault: family(1) }));
    assert.deepEqual(
      relayed.sealed.chainKeys,
      { vault: family(1) },
      "the over-limit family goes, even when some values cannot be decoded",
    );
    assert.deepEqual(
      relayed.periodGeometry,
      { chainsPerDay: 2, periodMinutes: 15 },
      "the root geometry applies to the relayed sibling",
    );
    assert.deepEqual(relayed.requestedPeriodKeys, { vault: ["251023T1415"] });
    assert.deepEqual(relayed.sealed.contentKeys, base.sealed.contentKeys);
    assert.deepEqual(relayed.sealed.periodKeys, base.sealed.periodKeys);
  }
});

test("exactly two raw members relay both values unchanged, including malformed", () => {
  const { relayed } = relay(pageData({ premium: family(2, [1]), vault: family(1) }));
  assert.deepEqual(relayed.sealed.chainKeys.premium, family(2, [1]));
  assert.deepEqual(relayed.requestedPeriodKeys.premium, ["251023T1400"]);
});

test("the selected collection relays at 16 raw members and sends no chain member at 17", () => {
  // Six unneeded families of two, each with a malformed value, plus the two
  // needed families of two: 16 raw members, 10 of them admissible.
  const sixteen = { premium: family(2), vault: family(2), ...unneeded(6) };
  const { relayed: atLimit } = relay(pageData(sixteen));
  assert.deepEqual(Object.keys(atLimit.sealed.chainKeys).sort(), ["premium", "vault"]);

  for (const extra of [{ spare: family(1) }, { spare: family(1, [0]) }]) {
    const { relayed, base } = relay(pageData({ ...sixteen, ...extra }));
    assert.equal(Object.hasOwn(relayed.sealed, "chainKeys"), false);
    assert.equal(Object.hasOwn(relayed, "periodGeometry"), false);
    assert.equal(Object.hasOwn(relayed, "requestedPeriodKeys"), false);
    assert.deepEqual(relayed, base, "the base request reaches the issuer unchanged");
  }
});

test("another issuer block never counts toward the selected collection", () => {
  const sixteen = { premium: family(2), vault: family(2), ...unneeded(6) };
  const crowdedB = { premium: family(2), vault: family(2), ...unneeded(7) };
  const { relayed } = relay(pageData(sixteen, crowdedB));
  assert.deepEqual(Object.keys(relayed.sealed.chainKeys).sort(), ["premium", "vault"]);
  assert.equal(JSON.stringify(relayed).includes("unused6"), false);
});

test("with no chain family left the request carries no chain member and keeps its base", () => {
  const { relayed, base } = relay(pageData({ premium: family(3), vault: family(3, [1]) }));
  assert.equal(Object.hasOwn(relayed.sealed, "chainKeys"), false);
  assert.equal(Object.hasOwn(relayed, "periodGeometry"), false);
  assert.equal(Object.hasOwn(relayed, "requestedPeriodKeys"), false);
  assert.deepEqual(relayed, base);
  assert.deepEqual(relayed.sealed.periodKeys, { premium: { "251023T1400": "Ag" } });
});

test("inherited members are not raw carrier members", () => {
  const premium = Object.assign(
    Object.create({ [TERMINALS[2]]: "AQ", [TERMINALS[3]]: "AQ" }),
    family(2),
  );
  const { relayed } = relay(pageData({ premium, vault: family(1) }));
  assert.deepEqual(relayed.sealed.chainKeys.premium, family(2));
});

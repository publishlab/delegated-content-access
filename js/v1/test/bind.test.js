//
// core-shared/bind and core-shared/keySealing - the renderId-anchored binding,
// attacked. These cases record its construction and normative layout.
//
// `core-shared/keySealing` seals every key to the coordinate the publisher put
// it at, and that binding is the only thing standing between a reader's browser
// and a relabeled blob: nothing on the wire says where a blob came from, and no
// signature is checked over one. So a relabel is stopped inside the unseal,
// after the private key has been used, or it is not stopped at all. This file
// is where that is run.
//
// Every refusal here is worth what its control is worth, and the controls are a
// file away: the seal before the binding, the delimiter-less join and an issuer
// that reads the slot off the request all run in
// `experiments/bind-on-renderId-and-slot/test/comparison.test.js`, each one
// letting through what is refused here.
//
// The test harness supplies two pieces. `sealedSection` is the issuer walk these
// attacks are driven through, and `selfTest` is the fixture check; both are
// beside the variant because core carries no section walk of its own and the
// engine offers neither the whole-request refusal nor the switchable slot the
// controls probe. Where core is the subject on its own - the grammar, one blob
// at one coordinate - `core-shared/bind` and `core-shared/keySealing` are called directly.
// `sealedSection` therefore reports a moved blob as whole-request
// `binding_failed`; the reference engine reports that coordinate per item as
// `unseal_failed` beside 200 in `jwt-proof.test.js`.
//
// Both carriers hold one value. `BIND` is the same string on both; only what
// carries it differs - AES-GCM `additionalData` for ECDH, the OAEP plaintext
// prefix for RSA. So every attack runs twice, once per carrier, from one body.
// Neither carrier widens the wire; the width against an unbound seal is pinned
// in the controls file.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import {
  BIND_DELIMITER,
  BIND_VERSION,
  RENDER_ID_BYTES,
  bindValue,
} from "../core-shared--publisher-issuer/bind.js";
import * as boundSealing from "../core-shared--publisher-issuer/keySealing.js";
import { sealSection, unsealSection } from "../test-lib/harnesses/sealedSection.js";
import { bindSelfTest, bindFailureClass } from "../test-lib/harnesses/bindSelfTest.js";
import { encrypt, decrypt, NONCE_BYTES } from "../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode, utf8Decode } from "../core-shared/codec.js";
import { DcaError } from "../core-shared/errors.js";
import { ACCESS_GROUP, ARTICLES, ISSUER_NAME } from "../demo/scenarios/fixtures.js";
import { asWire, issuerKeypair, seededRandom } from "../test-reference/support/keys.js";
import { makeRenderId } from "../test-lib/fixtures/renderId.js";
import { refuses } from "../test-lib/helpers/refuses.js";

const { subtle } = globalThis.crypto;

/** @param {string} base64url */
function pinnedNonce(base64url) {
  const nonce = base64urlDecode(base64url);
  return { bytes: () => nonce };
}

/** A renderId to bind on; the value is incidental, distinct per fill byte. */
const RENDER_A = makeRenderId(0xa1);
const RENDER_B = makeRenderId(0xb2);

/** What `core-publisher/Sealer` drew while the manifest was the binder: 12 bytes. */
const SHORT_RENDER = base64urlEncode(new Uint8Array(12).fill(0xc3));

const T = "251023T1300";

/** The two items of one render: the free one and the one worth stealing. */
const CONTENT_KEYS = {
  bodytext: new Uint8Array(16).fill(0x11),
  premiumtext: new Uint8Array(16).fill(0x22),
};

const PERIOD_KEYS = { [ACCESS_GROUP]: { [T]: new Uint8Array(16).fill(0x33) } };

/** The two carriers of one binding value. */
const CARRIERS = [
  { label: "ECDH P-256", algorithm: "ECDH-P256" },
  { label: "RSA-OAEP", algorithm: "RSA-OAEP" },
];

/**
 * A publisher and an issuer for one carrier, and the sealed section of one
 * render between them. `sealed` has the shape `issuerData[issuer].sealed` and
 * `request.sealed` both carry, which is what makes a relabel a matter of moving
 * one member.
 *
 * @param {{ algorithm: string }} carrier
 * @param {object} [options]
 * @param {string} [options.renderId]
 * @param {CryptoKeyPair} [options.keys] - the issuer's, so two renders can be
 *   sealed for one issuer and the renderId is the only thing between them
 */
async function world(carrier, { renderId = RENDER_A, keys } = {}) {
  const { publicKey, privateKey } = keys ?? (await issuerKeypair(carrier.algorithm));
  const random = seededRandom(20251023);

  const sealed = await sealSection({
    renderId,
    contentKeys: CONTENT_KEYS,
    periodKeys: PERIOD_KEYS,
    publicKey,
    algorithm: carrier.algorithm,
    random,
  });

  /**
   * The issuer's side: what it would return for the coordinates it granted.
   *
   * @param {any} presented - the `sealed` section as the request carries it
   * @param {object} [open]
   * @param {{ contentNames?: string[], accessGroups?: string[] }} [open.granted]
   * @param {string} [open.renderId] - the verified renderId of *this* request
   */
  const unlock = (presented, open = {}) =>
    unsealSection({
      sealed: presented,
      renderId: open.renderId ?? renderId,
      privateKey,
      algorithm: carrier.algorithm,
      granted: open.granted,
    });

  return { renderId, publicKey, privateKey, random, sealed, unlock };
}

describe("The grammar", () => {
  // No key material anywhere in this section - BIND is a string.

  test("the two BIND grammars include every bound coordinate", () => {
    assert.equal(
      bindValue({ renderId: RENDER_A, contentName: "premiumtext" }),
      `${BIND_VERSION}|c|${RENDER_A}|premiumtext`,
    );
    assert.equal(
      bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T }),
      `${BIND_VERSION}|p|${RENDER_A}|${ACCESS_GROUP}|${T}`,
    );
    assert.equal(
      bindValue({
        renderId: RENDER_A,
        accessGroup: ACCESS_GROUP,
        suppliedT: T,
        periodChain: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      }),
      `${BIND_VERSION}|pc|${RENDER_A}|${ACCESS_GROUP}|${T}|2|15`,
    );
    assert.throws(
      () =>
        bindValue({
          renderId: RENDER_A,
          accessGroup: ACCESS_GROUP,
          suppliedT: T,
          periodChain: true,
        }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "a chain envelope carries its geometry, and there is no shorter pc value",
    );
    assert.equal(BIND_DELIMITER, "|");
    assert.equal(BIND_VERSION, "dca-bind-v1");
  });

  test("BIND admits only canonical identifier names and valid chain coordinates", () => {
    for (const binding of [
      { renderId: RENDER_A, contentName: "9premium" },
      { renderId: RENDER_A, contentName: "x".repeat(65) },
      { renderId: RENDER_A, accessGroup: "premium|archive", t: T },
      {
        renderId: RENDER_A,
        accessGroup: ACCESS_GROUP,
        suppliedT: "251023T1411",
        periodChain: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      },
      {
        renderId: RENDER_A,
        accessGroup: ACCESS_GROUP,
        suppliedT: "251023T13",
        periodChain: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      },
      {
        renderId: RENDER_A,
        accessGroup: ACCESS_GROUP,
        suppliedT: T,
        periodChain: true,
        chainsPerDay: 7,
        periodMinutes: 15,
      },
    ]) {
      assert.throws(
        () => bindValue(binding),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `invalid binding coordinate ${JSON.stringify(binding)} is refused before it becomes BIND`,
      );
    }
  });

  test("a chain coordinate is on the grid when its minute of day is a multiple of periodMinutes", () => {
    // docs/spec--period-key-chains.md §7.3: a 90-minute family has a period at
    // 01:30, and a 120-minute family has none at 01:00.
    const chain = (periodMinutes, suppliedT) => ({
      renderId: RENDER_A,
      accessGroup: ACCESS_GROUP,
      suppliedT,
      periodChain: true,
      chainsPerDay: 1,
      periodMinutes,
    });
    for (const [periodMinutes, suppliedT] of [
      [90, "251023T0130"],
      [90, "251023T0300"],
      [120, "251023T0200"],
    ]) {
      assert.equal(
        bindValue(chain(periodMinutes, suppliedT)),
        `${BIND_VERSION}|pc|${RENDER_A}|${ACCESS_GROUP}|${suppliedT}|1|${periodMinutes}`,
      );
    }
    for (const [periodMinutes, suppliedT] of [
      [120, "251023T0100"],
      [90, "251023T0100"],
    ]) {
      assert.throws(
        () => bindValue(chain(periodMinutes, suppliedT)),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${suppliedT} is off the ${periodMinutes}-minute grid`,
      );
    }
  });

  test("a chain coordinate names a moment the calendar has", () => {
    const chain = (suppliedT) => ({
      renderId: RENDER_A,
      accessGroup: ACCESS_GROUP,
      suppliedT,
      periodChain: true,
      chainsPerDay: 2,
      periodMinutes: 30,
    });
    // 2024 is a leap year, and 23:30 is the last 30-minute period of its 29 February.
    assert.equal(
      bindValue(chain("240229T2330")),
      `${BIND_VERSION}|pc|${RENDER_A}|${ACCESS_GROUP}|240229T2330|2|30`,
    );
    for (const suppliedT of ["251331T1400", "250229T1400"]) {
      assert.throws(
        () => bindValue(chain(suppliedT)),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${suppliedT} has the label's shape and names no real date`,
      );
    }
  });

  test("a binding names one kind, and the kind is in the value it produces", () => {
    const content = bindValue({ renderId: RENDER_A, contentName: ACCESS_GROUP });
    const period = bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T });
    const chain = bindValue({
      renderId: RENDER_A,
      accessGroup: ACCESS_GROUP,
      suppliedT: T,
      periodChain: true,
      chainsPerDay: 2,
      periodMinutes: 15,
    });

    // The same name in the two positions, which is the confusion the kind char
    // and the field count both refuse.
    assert.notEqual(content, period);
    assert.notEqual(period, chain);
    assert.equal(content.split(BIND_DELIMITER)[1], "c");
    assert.equal(period.split(BIND_DELIMITER)[1], "p");
    assert.equal(content.split(BIND_DELIMITER).length, 4);
    assert.equal(period.split(BIND_DELIMITER).length, 5);
    assert.equal(chain.split(BIND_DELIMITER)[1], "pc");
    assert.equal(chain.split(BIND_DELIMITER).length, 7);

    assert.throws(
      () =>
        bindValue({ renderId: RENDER_A, contentName: "bodytext", accessGroup: ACCESS_GROUP, t: T }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "a binding that is both kinds at once has not said which",
    );
    assert.throws(
      () => bindValue({ renderId: RENDER_A }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "and one that is neither has nothing to bind to",
    );
    assert.throws(
      () => bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "a periodKey coordinate is the pair, and t is half of it",
    );
  });

  test("a contentKey binding names its contentName and no period or chain field", () => {
    for (const extra of [
      { accessGroup: ACCESS_GROUP },
      { t: T },
      { suppliedT: T },
      { chainsPerDay: 2 },
      { periodMinutes: 15 },
    ]) {
      assert.throws(
        () => bindValue({ renderId: RENDER_A, contentName: "bodytext", ...extra }),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `a contentName beside ${JSON.stringify(extra)} does not say which key the blob holds`,
      );
    }
  });

  test("periodChain is an optional boolean, never a truthy kind selector", () => {
    const exact = `${BIND_VERSION}|p|${RENDER_A}|${ACCESS_GROUP}|${T}`;
    assert.equal(bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T }), exact);
    assert.equal(
      bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T, periodChain: false }),
      exact,
    );

    for (const periodChain of [1, "true", null, {}, []]) {
      assert.throws(
        () => bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T, periodChain }),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${JSON.stringify(periodChain)} must not silently downgrade a chain coordinate to an exact one`,
      );
    }
  });

  test("a chain binding names its position as suppliedT, and t is the exact-period label", () => {
    // The same bytes the chain grammar has always joined, under the name the
    // specs use for the field. `t` stays the exact-period label, and a
    // binding that spells one of them where the other belongs is refused
    // rather than silently read as the other kind of coordinate.
    assert.equal(
      bindValue({
        renderId: RENDER_A,
        accessGroup: ACCESS_GROUP,
        suppliedT: T,
        periodChain: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      }),
      `${BIND_VERSION}|pc|${RENDER_A}|${ACCESS_GROUP}|${T}|2|15`,
      "the rename moves no BIND byte",
    );

    assert.throws(
      () =>
        bindValue({
          renderId: RENDER_A,
          accessGroup: ACCESS_GROUP,
          t: T,
          periodChain: true,
          chainsPerDay: 2,
          periodMinutes: 15,
        }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "a chain binding spelling its position t has named the exact-period field",
    );
    assert.throws(
      () => bindValue({ renderId: RENDER_A, accessGroup: ACCESS_GROUP, suppliedT: T }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "and an exact binding spelling its label suppliedT has named the chain field",
    );
  });

  test("a period binding that names both t and suppliedT is refused, whichever kind it is", () => {
    const both = { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T, suppliedT: T };
    for (const binding of [
      both,
      { ...both, periodChain: false },
      { ...both, periodChain: true, chainsPerDay: 2, periodMinutes: 15 },
    ]) {
      assert.throws(
        () => bindValue(binding),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${JSON.stringify(binding)} names two positions and does not say which one its blob is bound at`,
      );
    }
  });

  test("chain geometry is the [1-9][0-9]* production, so no integer joins in exponent form", () => {
    /** @param {object} geometry */
    const chain = (geometry) =>
      bindValue({
        renderId: RENDER_A,
        accessGroup: ACCESS_GROUP,
        suppliedT: T,
        periodChain: true,
        ...geometry,
      });

    assert.equal(
      chain({ chainsPerDay: 2, periodMinutes: 15 }),
      `${BIND_VERSION}|pc|${RENDER_A}|${ACCESS_GROUP}|${T}|2|15`,
      "the ordinary pair still joins as its decimal digits",
    );

    // `Number.isInteger` holds for both of these and `String` renders them in
    // exponent form, so the value that used to join carried `.`, `e` and `+`
    // into a bound field and ran past the width the pc ceiling is computed
    // from. The ECDH carrier has no capacity check to catch it afterwards.
    for (const geometry of [
      { chainsPerDay: 1e21, periodMinutes: 15 },
      { chainsPerDay: 2, periodMinutes: 1e21 },
      { chainsPerDay: Number.MAX_VALUE, periodMinutes: 15 },
    ]) {
      assert.throws(
        () => chain(geometry),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${JSON.stringify(geometry)} is outside the decimal production the grammar states`,
      );
    }
  });

  test("the delimiter is banned in every bound field", () => {
    for (const binding of [
      { renderId: `${RENDER_A}|x`, contentName: "premiumtext" },
      { renderId: RENDER_A, contentName: "premium|text" },
      { renderId: RENDER_A, accessGroup: "premium|1", t: T },
      { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: "251023T13|" },
    ]) {
      assert.throws(
        () => bindValue(binding),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${JSON.stringify(binding)} would join to a value another pair of fields could also produce`,
      );
    }
  });

  test("a bound field is a non-empty string", () => {
    for (const binding of [
      { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: "" },
      { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: 251023 },
      { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: null },
      { renderId: "", contentName: "premiumtext" },
      { renderId: 42, contentName: "premiumtext" },
    ]) {
      assert.throws(
        () => bindValue(/** @type {any} */ (binding)),
        (error) => /** @type {DcaError} */ (error).code === "binding_failed",
        `${JSON.stringify(binding)} has a field that is empty or not a string`,
      );
    }
  });

  test("a renderId is exactly 16 bytes in canonical unpadded base64url", () => {
    assert.equal(base64urlDecode(SHORT_RENDER).length, 12, "the width a render used to carry");

    assert.throws(
      () => bindValue({ renderId: SHORT_RENDER, contentName: "premiumtext" }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "a short identifier is outside the one v1 width",
    );
    assert.equal(RENDER_ID_BYTES, 16);
    assert.ok(bindValue({ renderId: RENDER_A, contentName: "premiumtext" }));
    const long = base64urlEncode(new Uint8Array(RENDER_ID_BYTES + 1).fill(0xb2));
    assert.throws(
      () => bindValue({ renderId: long, contentName: "premiumtext" }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "a long identifier is outside the one v1 width",
    );
    assert.throws(
      () => bindValue({ renderId: `${RENDER_A}=`, contentName: "premiumtext" }),
      (error) => /** @type {DcaError} */ (error).code === "binding_failed",
      "padding is not canonical base64url",
    );
  });
});

describe("The carriers", () => {
  // One body, run for each - the binding value is the same string on both,
  // and only what carries it differs.

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("a bound section opens at every coordinate it was sealed at", async () => {
        const { sealed, unlock } = await world(carrier);

        const opened = await unlock(sealed);

        assert.equal(opened.contentKeys.bodytext, asWire(CONTENT_KEYS.bodytext));
        assert.equal(opened.contentKeys.premiumtext, asWire(CONTENT_KEYS.premiumtext));
        assert.equal(opened.periodKeys[ACCESS_GROUP][T], asWire(PERIOD_KEYS[ACCESS_GROUP][T]));
      });

      test("a same-render slot swap dies in the unseal", async () => {
        const { sealed, unlock } = await world(carrier);

        // The attack: entitled to bodytext, the premium blob moved into the
        // bodytext slot. Both blobs came off the same page, both are the
        // publisher's, and nothing about either is malformed - the only thing
        // wrong is which slot it is sitting in.
        const relabeled = {
          contentKeys: { bodytext: sealed.contentKeys.premiumtext },
        };

        // Where it is caught: the issuer has already agreed the key and spent
        // it before it learns anything. There is no check ahead of the private
        // key, and the design is that there does not need to be.
        await refuses(
          () => unlock(relabeled, { granted: { contentNames: ["bodytext"] } }),
          "binding_failed",
          "the blob was sealed for premiumtext and the issuer rebuilt the value for bodytext",
        );

        // And the honest request through the same walk still works, so the
        // refusal above is the attack and not a harness that says no.
        const honest = await unlock(
          { contentKeys: { bodytext: sealed.contentKeys.bodytext } },
          { granted: { contentNames: ["bodytext"] } },
        );
        assert.equal(honest.contentKeys.bodytext, asWire(CONTENT_KEYS.bodytext));
      });

      test("a blob from another render fails on the renderId component", async () => {
        const a = await world(carrier);
        // One issuer, two renders. The keypair is shared deliberately: a second
        // issuer's blob would fail for having been sealed to another key, which
        // would prove nothing about the binding.
        const b = await world(carrier, {
          renderId: RENDER_B,
          keys: { publicKey: a.publicKey, privateKey: a.privateKey },
        });

        // Render B's own request opens render B's blobs, so the key is right
        // and the renderId is the only thing between the two cases.
        const own = await b.unlock(b.sealed);
        assert.equal(own.contentKeys.premiumtext, asWire(CONTENT_KEYS.premiumtext));

        await refuses(
          () => a.unlock({ contentKeys: { premiumtext: b.sealed.contentKeys.premiumtext } }),
          "binding_failed",
          "render B's blob presented under render A's verified renderId",
        );

        await refuses(
          () =>
            a.unlock({
              periodKeys: { [ACCESS_GROUP]: { [T]: b.sealed.periodKeys[ACCESS_GROUP][T] } },
            }),
          "binding_failed",
          "and the periodKey coordinate is bound to its render too",
        );
      });

      test("a content blob in a period slot fails, and the reverse", async () => {
        // One name in both positions, so the kind is the only thing separating
        // them - `c` against `p`, and the field count behind it.
        const { publicKey, privateKey } = await issuerKeypair(carrier.algorithm);
        const random = seededRandom(7);
        const keyBytes = new Uint8Array(16).fill(0x44);
        const options = { random };

        const asContent = await boundSealing.seal(keyBytes, publicKey, carrier.algorithm, {
          ...options,
          binding: { renderId: RENDER_A, contentName: ACCESS_GROUP },
        });
        const asPeriod = await boundSealing.seal(keyBytes, publicKey, carrier.algorithm, {
          ...options,
          binding: { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T },
        });

        const open = (/** @type {string} */ blob, /** @type {any} */ binding) =>
          boundSealing.open(
            blob,
            privateKey,
            carrier.algorithm,
            carrier.algorithm === "RSA-OAEP" ? { binding } : { binding },
          );

        assert.deepEqual(
          await open(asContent, { renderId: RENDER_A, contentName: ACCESS_GROUP }),
          keyBytes,
        );
        assert.deepEqual(
          await open(asPeriod, { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T }),
          keyBytes,
        );

        await refuses(
          () => open(asContent, { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T }),
          "unseal_failed",
          "a contentKey blob presented as the periodKey of a family with the same name",
        );
        await refuses(
          () => open(asPeriod, { renderId: RENDER_A, contentName: ACCESS_GROUP }),
          "unseal_failed",
          "and the other way round",
        );
      });

      test("an exact period blob and a chain blob are different kinds, and a chain terminal is bound", async () => {
        const { publicKey, privateKey } = await issuerKeypair(carrier.algorithm);
        const random = seededRandom(8);
        const keyBytes = new Uint8Array(16).fill(0x45);
        const options = { random };
        const exact = { renderId: RENDER_A, accessGroup: ACCESS_GROUP, t: T };
        const { t: exactLabel, ...atGroup } = exact;
        const chain = {
          ...atGroup,
          suppliedT: exactLabel,
          periodChain: true,
          chainsPerDay: 2,
          periodMinutes: 15,
        };

        const asExact = await boundSealing.seal(keyBytes, publicKey, carrier.algorithm, {
          ...options,
          binding: exact,
        });
        const asChain = await boundSealing.seal(keyBytes, publicKey, carrier.algorithm, {
          ...options,
          binding: chain,
        });
        const open = (/** @type {string} */ blob, /** @type {any} */ binding) =>
          boundSealing.open(
            blob,
            privateKey,
            carrier.algorithm,
            carrier.algorithm === "RSA-OAEP" ? { binding } : { binding },
          );

        assert.deepEqual(await open(asExact, exact), keyBytes);
        assert.deepEqual(await open(asChain, chain), keyBytes);
        await refuses(
          () => open(asExact, chain),
          "unseal_failed",
          "an exact pK cannot be returned as a chain capability",
        );
        await refuses(
          () => open(asChain, exact),
          "unseal_failed",
          "a chain capability cannot be returned as one exact pK",
        );
        await refuses(
          () => open(asChain, { ...chain, suppliedT: "251023T1330" }),
          "unseal_failed",
          "a chain key moved to another terminal label cannot widen its cutoff",
        );
      });

      test("a chain blob does not open under another chain geometry", async () => {
        // The two geometry integers are bound (`bind.js` :175-189) so a chain
        // state cannot be relabeled into a different geometry and derive under
        // it. One state, one coordinate, and the geometry is the only thing
        // that moves between the three opens below.
        const { publicKey, privateKey } = await issuerKeypair(carrier.algorithm);
        const random = seededRandom(9);
        const stateBytes = new Uint8Array(16).fill(0x46);
        const options = { random };
        const sealedAt = {
          renderId: RENDER_A,
          accessGroup: ACCESS_GROUP,
          suppliedT: T,
          periodChain: true,
          chainsPerDay: 2,
          periodMinutes: 15,
        };

        const asChain = await boundSealing.seal(stateBytes, publicKey, carrier.algorithm, {
          ...options,
          binding: sealedAt,
        });
        const open = (/** @type {string} */ blob, /** @type {any} */ binding) =>
          boundSealing.open(
            blob,
            privateKey,
            carrier.algorithm,
            carrier.algorithm === "RSA-OAEP" ? { binding } : { binding },
          );

        // The coordinate it was sealed at, so the two refusals below are the
        // geometry and not the state or the key.
        assert.deepEqual(await open(asChain, sealedAt), stateBytes);

        await refuses(
          () => open(asChain, { ...sealedAt, chainsPerDay: 4 }),
          "unseal_failed",
          "the same label means another position under another chainsPerDay, and the tag says so",
        );
        await refuses(
          () => open(asChain, { ...sealedAt, periodMinutes: 30 }),
          "unseal_failed",
          "and a period width the state was not built at cannot be read onto it either",
        );
      });

      test("a name that is a prefix of another does not open under it", async () => {
        // The other end of the boundary question. The `|` delimiter settles
        // where one bound field stops and the next starts; this is where the
        // whole value stops and the key starts, which only the RSA carrier has
        // to answer - GCM commits the AAD length in its tag, and an OAEP
        // plaintext is a run of bytes with the boundary implied. A prefix
        // compare would hand `premiumtext`'s key back under a `premium` grant,
        // with the four extra characters in front of it.
        const { publicKey, privateKey } = await issuerKeypair(carrier.algorithm);
        const named = {
          premium: new Uint8Array(16).fill(0x66),
          premiumtext: new Uint8Array(16).fill(0x77),
        };

        const sealed = await sealSection({
          renderId: RENDER_A,
          contentKeys: named,
          periodKeys: { [ACCESS_GROUP]: { "251023T13": new Uint8Array(16).fill(0x88) } },
          publicKey,
          algorithm: carrier.algorithm,
          random: seededRandom(13),
        });

        const unlock = (/** @type {any} */ presented, /** @type {any} */ granted) =>
          unsealSection({
            sealed: presented,
            renderId: RENDER_A,
            privateKey,
            algorithm: carrier.algorithm,
            granted,
          });

        await refuses(
          () =>
            unlock(
              { contentKeys: { premium: sealed.contentKeys.premiumtext } },
              { contentNames: ["premium"] },
            ),
          "binding_failed",
          "premiumtext is premium with four more characters, and the value it was sealed under is not this one",
        );

        // And the same boundary between the two halves of a periodKey
        // coordinate, where a truncated `t` is the shorter value.
        await refuses(
          () =>
            unlock({
              periodKeys: {
                [ACCESS_GROUP]: { "251023T1": sealed.periodKeys[ACCESS_GROUP]["251023T13"] },
              },
            }),
          "binding_failed",
          "a t the issuer never parses, one character short of the one the blob was sealed for",
        );

        // The grant that is honestly held still opens, so the two refusals are
        // the boundary and not the name.
        const honest = await unlock(
          { contentKeys: { premium: sealed.contentKeys.premium } },
          { contentNames: ["premium"] },
        );
        assert.equal(honest.contentKeys.premium, asWire(named.premium));
      });

      test("a renderId of the wrong width is refused at seal", async () => {
        const { publicKey } = await issuerKeypair(carrier.algorithm);

        await refuses(
          () =>
            sealSection({
              renderId: SHORT_RENDER,
              contentKeys: CONTENT_KEYS,
              publicKey,
              algorithm: carrier.algorithm,
              random: seededRandom(3),
            }),
          "binding_failed",
          "the publisher emitted a renderId outside the one width, so it is refused here",
        );
      });
    });
  }
});

const RESOURCE_ID = "123456";
const RESOURCE_VERSION = "1";

/** What the two contentKeys of this render actually encrypt. */
const TEXT = {
  bodytext: ARTICLES.A,
  // No fixture twin: the second item is the one worth stealing, and every
  // attack below reads better when its text says which one that is.
  premiumtext: "<p>The rezoning covers the two berths the port sold in June.</p>",
};

/**
 * The client's own binding, a value apart from BIND: shipped in the markup,
 * rebuilt at the decrypt, and the only check the client makes.
 *
 * @param {string} contentName
 * @returns {string}
 */
function contentAad(contentName) {
  return `${RESOURCE_ID}|${RESOURCE_VERSION}|${contentName}`;
}

/**
 * The content layer of one render: each item under its own contentKey, with the
 * aad of the slot it sits in. Stage 1's first line, and what stands between a
 * key the issuer handed over and the text.
 *
 * @param {{ bytes: (n: number) => Uint8Array }} random
 * @returns {Promise<Record<string, { nonce: Uint8Array, ciphertext: Uint8Array }>>}
 */
async function contentLayer(random) {
  /** @type {Record<string, { nonce: Uint8Array, ciphertext: Uint8Array }>} */
  const items = {};
  for (const [contentName, keyBytes] of Object.entries(CONTENT_KEYS)) {
    const nonce = random.bytes(NONCE_BYTES);
    items[contentName] = {
      nonce,
      ciphertext: await encrypt(
        keyBytes,
        nonce,
        utf8Encode(TEXT[/** @type {'bodytext'|'premiumtext'} */ (contentName)]),
        utf8Encode(contentAad(contentName)),
      ),
    };
  }
  return items;
}

/**
 * The client, entire: a key out of the unlock response, a ciphertext out of the
 * markup, and the aad it rebuilds for the slot. Nothing here knows what a BIND
 * is, which is the point of the two tests that call it.
 *
 * @param {{ nonce: Uint8Array, ciphertext: Uint8Array }} item
 * @param {Uint8Array} keyBytes
 * @param {string} aad
 * @returns {Promise<string>}
 */
async function readContent(item, keyBytes, aad) {
  return utf8Decode(await decrypt(keyBytes, item.nonce, item.ciphertext, utf8Encode(aad)));
}

/**
 * Deliberately not `refuses()`. The refusal has to come from the AES-GCM tag
 * over the content, so a `DcaError` here would mean some binding code caught it
 * first and the claim would be the wrong one. The tag refusal is WebCrypto's
 * own `OperationError`, and requiring that name is what keeps a harness
 * `TypeError` from reading as a refused tag.
 *
 * @param {() => Promise<unknown>} run
 * @param {string} why
 * @returns {Promise<void>}
 */
async function failsAtContentDecrypt(run, why) {
  await assert.rejects(run, (error) => {
    assert.ok(
      !(error instanceof DcaError),
      `${why}: this has to be the content tag, not a binding check`,
    );
    assert.equal(
      /** @type {any} */ (error).name,
      "OperationError",
      `${why}: an AES-GCM tag refusal is an OperationError, and this is ${/** @type {any} */ (error)?.name}: ${/** @type {any} */ (error)?.message}`,
    );
    return true;
  });
}

/**
 * One carrier's seal options: ECDH carries a nonce, RSA-OAEP randomises itself
 * and refuses a Random rather than ignoring it.
 *
 * @param {{ algorithm: string }} carrier
 * @param {{ bytes: (n: number) => Uint8Array }} random
 * @returns {any}
 */
function sealOptionsFor(carrier, random) {
  return carrier.algorithm === "RSA-OAEP" ? {} : { random };
}

describe("The layer under the binding", () => {
  // Two of the attacks land here rather than in the unseal, and both are one
  // fact seen from two sides: BIND is the issuer's binding over the key seal,
  // `resourceId|version|contentName` is the client's over the content, and
  // neither covers the other. Two independent AADs on different layers, each
  // checked by a different party.

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("a granted user's own key, sealed under a valid BIND, comes back and opens nothing", async () => {
        // Forgery #5. The attacker is a paying reader with a bodytext grant,
        // and nothing they send is malformed: this is exactly the blob an
        // honest publisher produces for that slot, over a key they drew
        // themselves.
        const { sealed, unlock, publicKey } = await world(carrier);
        const content = await contentLayer(seededRandom(61));

        const forgedKey = new Uint8Array(16).fill(0x99);
        const forged = await boundSealing.seal(forgedKey, publicKey, carrier.algorithm, {
          ...sealOptionsFor(carrier, seededRandom(62)),
          binding: { renderId: RENDER_A, contentName: "bodytext" },
        });

        // The issuer cannot tell, and the design never asks it to: the binding
        // is valid for a slot this user holds, so the unlock succeeds and hands
        // back exactly the bytes that went in. That is the whole of what the
        // oracle question buys - an authenticated user making the issuer do
        // asymmetric work to return their own key.
        const opened = await unlock(
          { contentKeys: { bodytext: forged } },
          { granted: { contentNames: ["bodytext"] } },
        );
        assert.equal(
          opened.contentKeys.bodytext,
          asWire(forgedKey),
          "their own key, round-tripped",
        );

        // Where it dies. The ciphertext is under the publisher's contentKey and
        // the tag over it is what the forged key fails, so nothing of the
        // article comes out - the gap between stage 2's output and stage 3's
        // check, which is where the "garbage key" result is visible.
        await failsAtContentDecrypt(
          () =>
            readContent(
              content.bodytext,
              base64urlDecode(opened.contentKeys.bodytext),
              contentAad("bodytext"),
            ),
          "the forged key against the real ciphertext",
        );

        // And it is not a lever on the slot they were denied either: the blob
        // is bound to bodytext, so presenting it as premiumtext refuses.
        await refuses(
          () =>
            unlock(
              { contentKeys: { premiumtext: forged } },
              { granted: { contentNames: ["premiumtext"] } },
            ),
          "binding_failed",
          "a forged blob is bound like any other, so it opens at one coordinate only",
        );

        // The control: the publisher's own blob, through the same unlock, opens
        // the same ciphertext - so the failure above is the forged key and not
        // the harness.
        const honest = await unlock(
          { contentKeys: { bodytext: sealed.contentKeys.bodytext } },
          { granted: { contentNames: ["bodytext"] } },
        );
        assert.equal(
          await readContent(
            content.bodytext,
            base64urlDecode(honest.contentKeys.bodytext),
            contentAad("bodytext"),
          ),
          TEXT.bodytext,
        );
      });

      test("a correctly bound blob with the wrong ciphertext still dies at the content decrypt", async () => {
        // The client reconstructs no BIND - it has no
        // renderId in hand at the decrypt and no code path that would use one -
        // so a blob the issuer was happy with buys an attacker nothing once the
        // ciphertext beside it has been moved.
        const { sealed, unlock } = await world(carrier);
        const content = await contentLayer(seededRandom(71));

        // The issuer's side here is entirely correct: the blob presented at
        // bodytext is the blob sealed for bodytext, so the binding matches and
        // the genuine contentKey comes back.
        const opened = await unlock(
          { contentKeys: { bodytext: sealed.contentKeys.bodytext } },
          { granted: { contentNames: ["bodytext"] } },
        );
        const contentKey = base64urlDecode(opened.contentKeys.bodytext);
        assert.deepEqual(
          contentKey,
          CONTENT_KEYS.bodytext,
          "the binding held, so this is the publisher key",
        );

        // What the client is handed: that key, with the premium item's
        // ciphertext moved into the bodytext slot of the markup. Its only
        // protection is the content tag, and the content tag is enough.
        await failsAtContentDecrypt(
          () => readContent(content.premiumtext, contentKey, contentAad("bodytext")),
          "the right key, the wrong ciphertext",
        );

        // The same ciphertext under the aad of the slot it was sealed at fails
        // too, which says the first refusal was not the aad on its own: the key
        // is wrong for this ciphertext either way.
        await failsAtContentDecrypt(
          () => readContent(content.premiumtext, contentKey, contentAad("premiumtext")),
          "the aad of the ciphertext, with a key that does not belong to it",
        );

        // The control: key, ciphertext and aad from one slot is the only
        // combination that opens.
        assert.equal(
          await readContent(content.bodytext, contentKey, contentAad("bodytext")),
          TEXT.bodytext,
        );
      });
    });
  }
});

// A second name over the story issuer's keypair: one trust domain, two labels.
// The fixtures' `FALLBACK_ISSUER_NAME` is a failover deployment, a different
// arrangement, so the name for this one is kept here.
const ISSUER_B = "white_label_partner";

describe("What BIND does not name", () => {
  // `issuerName` is not an input to seal or to unseal anywhere below, and the
  // shared-keypair case is the argument for leaving it out: naming the issuer
  // would forbid the one dedup a shared keypair allows and buy nothing,
  // because a shared keypair is one trust domain.

  test("ECDH: two issuerNames behind one keypair seal one render to byte-identical blobs", async () => {
    const keys = await issuerKeypair("ECDH-P256");

    // Pinned so the two seals are comparable at all: WebCrypto draws a fresh
    // ephemeral and a fresh nonce per seal, and either would make two blobs
    // differ for reasons that have nothing to do with what is bound.
    const ephemeral = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ]);
    const binding = { renderId: RENDER_A, contentName: "premiumtext" };
    const options = {
      random: pinnedNonce(base64urlEncode(new Uint8Array(NONCE_BYTES).fill(0x5e))),
      ephemeralKeyPair: ephemeral,
      binding,
    };

    // The name is handed to the seal in both calls, and there is nowhere for it
    // to enter: no parameter reads it and the grammar has no field for it.
    const forIssuerA = await boundSealing.seal(
      CONTENT_KEYS.premiumtext,
      keys.publicKey,
      "ECDH-P256",
      {
        ...options,
        issuerName: ISSUER_NAME,
      },
    );
    const forIssuerB = await boundSealing.seal(
      CONTENT_KEYS.premiumtext,
      keys.publicKey,
      "ECDH-P256",
      {
        ...options,
        issuerName: ISSUER_B,
      },
    );

    assert.equal(
      forIssuerA,
      forIssuerB,
      "one keypair, one render, one blob - the `sealedAs` alias is routing, not crypto",
    );

    const value = bindValue(binding);
    assert.ok(
      !value.includes(ISSUER_NAME) && !value.includes(ISSUER_B),
      "and no issuer name reaches the value",
    );
    assert.equal(
      value.split(BIND_DELIMITER).length,
      4,
      "version, kind, renderId, contentName - there is no fifth field",
    );

    // What the shared blob means on the other side: it opens for whoever holds
    // the private key, under either name, with no name in the options.
    const opened = await boundSealing.open(forIssuerB, keys.privateKey, "ECDH-P256", { binding });
    assert.deepEqual(opened, CONTENT_KEYS.premiumtext);
  });

  test("RSA-OAEP: identical inputs seal to two different blobs, and the one keypair opens both", async () => {
    // The ECDH claim above needs the ephemeral pinned; this carrier has nothing
    // to pin - OAEP draws its padding seed inside WebCrypto - so identical
    // inputs give different ciphertexts and the dedup saving is ECDH's alone.
    // What carries over is the part this section is about: neither blob names
    // an issuer, and both open for whoever holds the private key.
    const keys = await issuerKeypair("RSA-OAEP");
    const binding = { renderId: RENDER_A, contentName: "premiumtext" };

    const first = await boundSealing.seal(CONTENT_KEYS.premiumtext, keys.publicKey, "RSA-OAEP", {
      binding,
      issuerName: ISSUER_NAME,
    });
    const second = await boundSealing.seal(CONTENT_KEYS.premiumtext, keys.publicKey, "RSA-OAEP", {
      binding,
      issuerName: ISSUER_B,
    });

    assert.notEqual(first, second, "OAEP randomises itself, so two seals of one key never repeat");
    for (const blob of [first, second]) {
      assert.deepEqual(
        await boundSealing.open(blob, keys.privateKey, "RSA-OAEP", { binding }),
        CONTENT_KEYS.premiumtext,
        "and the name it was sealed under is not an input to opening it",
      );
    }
  });

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("two keypairs over identical inputs do not dedupe, and neither opens the other's blob", async () => {
        // The other half of that argument: the lever exists only when the keypair
        // is shared. Two issuers with keypairs of their own produce different
        // ciphertext for the same key at the same coordinate, and there is
        // nothing to share.
        const first = await issuerKeypair(carrier.algorithm);
        const second = await issuerKeypair(carrier.algorithm);
        const binding = { renderId: RENDER_A, contentName: "premiumtext" };

        // Everything an attacker or a de-duplicator could hold constant is held
        // constant here, including the ECDH ephemeral, so the recipient key is
        // the only difference between the two blobs.
        const options =
          carrier.algorithm === "RSA-OAEP"
            ? { binding }
            : {
                random: pinnedNonce(base64urlEncode(new Uint8Array(NONCE_BYTES).fill(0x6f))),
                ephemeralKeyPair: await subtle.generateKey(
                  { name: "ECDH", namedCurve: "P-256" },
                  true,
                  ["deriveBits"],
                ),
                binding,
              };

        const forFirst = await boundSealing.seal(
          CONTENT_KEYS.premiumtext,
          first.publicKey,
          carrier.algorithm,
          options,
        );
        const forSecond = await boundSealing.seal(
          CONTENT_KEYS.premiumtext,
          second.publicKey,
          carrier.algorithm,
          options,
        );

        assert.notEqual(
          forFirst,
          forSecond,
          "one blob per issuer keypair, which is what `issuerData.*.sealed` costs",
        );

        // Each opens its own - the control that makes the refusals the keypair
        // and not the binding.
        assert.deepEqual(
          await boundSealing.open(forFirst, first.privateKey, carrier.algorithm, { binding }),
          CONTENT_KEYS.premiumtext,
        );
        await refuses(
          () => boundSealing.open(forFirst, second.privateKey, carrier.algorithm, { binding }),
          "unseal_failed",
          "the second issuer's key against the first issuer's blob, at the coordinate both agree on",
        );
      });
    });
  }
});

/**
 * Build the issuer's private self-test fixture in memory. It exercises the
 * same binding path as a recorded fixture without making the base suite read
 * the vector corpus.
 *
 * @param {CryptoKey} publicKey
 */
async function selfTestFixture(publicKey) {
  const key = CONTENT_KEYS.bodytext;
  return {
    renderId: RENDER_A,
    contentName: "bodytext",
    blob: await boundSealing.seal(key, publicKey, "ECDH-P256", {
      random: pinnedNonce(base64urlEncode(new Uint8Array(NONCE_BYTES).fill(0x44))),
      binding: { renderId: RENDER_A, contentName: "bodytext" },
    }),
    keyBase64url: base64urlEncode(key),
  };
}

const miswiredSealing = {
  unseal: async () => {
    throw new Error("the configured binding does not match the publisher");
  },
};

/**
 * The per-blob picture the telemetry counts. `unsealSection` refuses the whole
 * request at the first failure - the 7.2 rule - so the outcomes are gathered one
 * coordinate per call, which is what an issuer that wants the count has to do
 * as well.
 *
 * @param {any} section - the `sealed` section as presented
 * @param {(presented: any, open: any) => Promise<any>} open
 * @returns {Promise<{ coordinate: string, ok: boolean }[]>}
 */
async function blobOutcomes(section, open) {
  const outcomes = [];
  for (const [contentName, blob] of Object.entries(section.contentKeys ?? {})) {
    try {
      await open(
        { contentKeys: { [contentName]: blob } },
        { granted: { contentNames: [contentName] } },
      );
      outcomes.push({ coordinate: `contentKeys.${contentName}`, ok: true });
    } catch {
      outcomes.push({ coordinate: `contentKeys.${contentName}`, ok: false });
    }
  }
  return outcomes;
}

describe("The binding self-test fixture", () => {
  // Section 7.2: any binding failure is suspected tampering, which
  // leaves an issuer whose own wiring is wrong sending tampering alarms for
  // every blob it is handed. The fixture is what tells the two apart, and
  // `test-lib/harnesses/bindSelfTest.js` is that fixture run
  // through the same modules a request takes.

  test("the self-test opens the fixture for a correctly wired keyId, and its request is the ok class", async () => {
    const issuer = await issuerKeypair("ECDH-P256");
    const fixture = await selfTestFixture(issuer.publicKey);

    const selfTest = await bindSelfTest({
      fixture,
      privateKey: issuer.privateKey,
      algorithm: "ECDH-P256",
    });
    assert.equal(selfTest.ok, true, selfTest.reason);

    const { sealed, unlock } = await world(CARRIERS[0], { keys: issuer });
    const outcomes = await blobOutcomes(sealed, unlock);
    assert.deepEqual(
      outcomes,
      [
        { coordinate: "contentKeys.bodytext", ok: true },
        { coordinate: "contentKeys.premiumtext", ok: true },
      ],
      "a correctly wired keyId opens what an honest publisher sends",
    );

    const report = bindFailureClass(selfTest, outcomes);
    assert.equal(report.class, "ok");
    assert.deepEqual(report.coordinates, []);
  });

  test("a keyId whose binding is wired wrong fails the fixture, and that is the all-blobs-fail class", async () => {
    // Two wirings, one class. The naive join is the encoding mismatch the
    // delimiter was written against; the unbound unseal is the same mistake made in the carrier
    // instead of the value. Neither is an attack and neither is distinguishable
    // from one by looking at a request - only the fixture separates them.
    const issuer = await issuerKeypair("ECDH-P256");
    const fixture = await selfTestFixture(issuer.publicKey);
    const { sealed } = await world(CARRIERS[0], { keys: issuer });

    /** @type {{ label: string, config: any }[]} */
    const misconfigured = [
      { label: "a binding mismatch", config: { keySealing: miswiredSealing } },
    ];

    for (const { label, config } of misconfigured) {
      const selfTest = await bindSelfTest({
        fixture,
        privateKey: issuer.privateKey,
        algorithm: "ECDH-P256",
        ...config,
      });
      assert.equal(
        selfTest.ok,
        false,
        `${label}: the fixture never left the issuer, and it did not open`,
      );

      const unlock = (/** @type {any} */ presented, /** @type {any} */ open = {}) =>
        unsealSection({
          sealed: presented,
          renderId: RENDER_A,
          privateKey: issuer.privateKey,
          algorithm: "ECDH-P256",
          granted: open.granted,
          ...config,
        });

      const outcomes = await blobOutcomes(sealed, unlock);
      assert.deepEqual(
        outcomes,
        [
          { coordinate: "contentKeys.bodytext", ok: false },
          { coordinate: "contentKeys.premiumtext", ok: false },
        ],
        `${label}: every blob from an honest publisher fails`,
      );

      const report = bindFailureClass(selfTest, outcomes);
      assert.equal(
        report.class,
        "all-blobs-fail",
        `${label}: the operator is told the wiring is wrong`,
      );
      assert.deepEqual(report.coordinates, ["contentKeys.bodytext", "contentKeys.premiumtext"]);
      assert.match(report.reason, /binding configuration is wrong/);
    }
  });

  test("a passing self-test with one blob failing is the single-blob-fail class, and it names that blob", async () => {
    const issuer = await issuerKeypair("ECDH-P256");
    const fixture = await selfTestFixture(issuer.publicKey);
    const { sealed, unlock } = await world(CARRIERS[0], { keys: issuer });

    const selfTest = await bindSelfTest({
      fixture,
      privateKey: issuer.privateKey,
      algorithm: "ECDH-P256",
    });
    assert.equal(selfTest.ok, true, selfTest.reason);

    // One relabel in an otherwise honest request: the premium blob presented at
    // bodytext as well as at its own coordinate.
    const presented = {
      contentKeys: {
        bodytext: sealed.contentKeys.premiumtext,
        premiumtext: sealed.contentKeys.premiumtext,
      },
    };

    const report = bindFailureClass(selfTest, await blobOutcomes(presented, unlock));
    assert.equal(
      report.class,
      "single-blob-fail",
      "the fixture opened, so the wiring is not what failed",
    );
    assert.deepEqual(
      report.coordinates,
      ["contentKeys.bodytext"],
      "and the moved blob is the one named",
    );

    // The classification only changes what the log says; the request is still
    // refused whole, which is the 7.2 rule the telemetry sits beside rather
    // than replaces.
    await refuses(
      () => unlock(presented, { granted: { contentNames: ["bodytext", "premiumtext"] } }),
      "binding_failed",
      "one failed coordinate rejects the unlock, however it was classified",
    );
  });

  test("every blob of one render failing is still per-blob tampering while the fixture opens", async () => {
    // The case that separates the two classifiers, and the reason `selfTest.ok`
    // is what `bindFailureClass` branches on. Counting failures would call this
    // request all-blobs-fail - every coordinate it carries failed - and send the
    // operator hunting a wiring error that is not there. The fixture never left
    // the issuer, it opened, so the wiring is right and what arrived is a render
    // whose blobs were all moved: one attacker, one request, per-blob tampering.
    const issuer = await issuerKeypair("ECDH-P256");
    const fixture = await selfTestFixture(issuer.publicKey);
    const { sealed, unlock } = await world(CARRIERS[0], { keys: issuer });

    const selfTest = await bindSelfTest({
      fixture,
      privateKey: issuer.privateKey,
      algorithm: "ECDH-P256",
    });
    assert.equal(selfTest.ok, true, selfTest.reason);

    // The two blobs of this render, swapped into each other's slots. Nothing is
    // malformed and nothing is unbound - each is bound to the coordinate it is
    // not sitting at.
    const swapped = {
      contentKeys: {
        bodytext: sealed.contentKeys.premiumtext,
        premiumtext: sealed.contentKeys.bodytext,
      },
    };

    const outcomes = await blobOutcomes(swapped, unlock);
    assert.deepEqual(
      outcomes,
      [
        { coordinate: "contentKeys.bodytext", ok: false },
        { coordinate: "contentKeys.premiumtext", ok: false },
      ],
      "every coordinate this request carries failed",
    );

    const report = bindFailureClass(selfTest, outcomes);
    assert.equal(
      report.class,
      "single-blob-fail",
      "a count-based classifier reads this as all-blobs-fail; the fixture says the wiring is fine",
    );
    assert.deepEqual(report.coordinates, ["contentKeys.bodytext", "contentKeys.premiumtext"]);

    // And the mirror of it, on the same helper: a keyId wired wrong is
    // all-blobs-fail even when the request that exposed it carried nothing that
    // could fail - the class is a statement about the issuer, not about a count.
    const brokenWiring = await bindSelfTest({
      fixture,
      privateKey: issuer.privateKey,
      algorithm: "ECDH-P256",
      keySealing: miswiredSealing,
    });
    assert.equal(
      brokenWiring.ok,
      false,
      "the configured binding does not open the publisher fixture",
    );

    const empty = bindFailureClass(brokenWiring, []);
    assert.equal(
      empty.class,
      "all-blobs-fail",
      "zero failed blobs, and the keyId is still misconfigured",
    );
    assert.deepEqual(empty.coordinates, []);
  });

  test("a failed self-test names the wiring and not the field that failed", async () => {
    // The fixture answers one question: is this keyId's binding wired the
    // way the publisher's is. Which field of the coordinate disagreed is
    // not part of that answer, and carrying the unseal's own words into the
    // line makes the wiring report read like the per-blob relabel report it
    // exists to be told apart from.
    const issuer = await issuerKeypair("ECDH-P256");
    const fixture = await selfTestFixture(issuer.publicKey);

    // A wiring error in the fixture's own coordinate: the blob is
    // bodytext's and the issuer states premiumtext. Nothing here came off a
    // wire, so the outcome is a statement about this issuer.
    const selfTest = await bindSelfTest({
      fixture: { ...fixture, contentName: "premiumtext" },
      privateKey: issuer.privateKey,
      algorithm: "ECDH-P256",
    });
    assert.equal(
      selfTest.ok,
      false,
      "the fixture did not open under the coordinate the issuer stated",
    );

    const report = bindFailureClass(selfTest, [{ coordinate: "contentKeys.bodytext", ok: false }]);
    assert.equal(report.class, "all-blobs-fail");
    for (const line of [selfTest.reason, report.reason]) {
      assert.doesNotMatch(line, /premiumtext|bodytext/, "no coordinate of the fixture");
      assert.doesNotMatch(
        line,
        /contentName|accessGroup|renderId|suppliedT/,
        "no field of the grammar",
      );
      assert.doesNotMatch(
        line,
        /unseal failed|not bound to this coordinate/,
        "and not the unseal's words",
      );
    }
    assert.match(report.reason, /binding configuration is wrong/, "what it does say is the wiring");
  });

  test("the RSA-OAEP carrier runs a pc fixture, and a substituted geometry is still only the wiring", async () => {
    // The other carrier and the third coordinate shape, which the fixture
    // takes in the member names `bind.js` gives them: a chain position is
    // `suppliedT` with the complete geometry beside it.
    const issuer = await issuerKeypair("RSA-OAEP");
    const geometry = { chainsPerDay: 2, periodMinutes: 15 };
    const coordinate = {
      renderId: RENDER_A,
      accessGroup: ACCESS_GROUP,
      suppliedT: T,
      periodChain: true,
      ...geometry,
    };
    const state = new Uint8Array(16).fill(0x55);
    const fixture = {
      ...coordinate,
      blob: await boundSealing.seal(state, issuer.publicKey, "RSA-OAEP", { binding: coordinate }),
      keyBase64url: base64urlEncode(state),
    };

    const selfTest = await bindSelfTest({
      fixture,
      privateKey: issuer.privateKey,
      algorithm: "RSA-OAEP",
    });
    assert.equal(selfTest.ok, true, selfTest.reason);

    // One geometry value away from the coordinate the state was sealed at,
    // which is a resolved geometry configured wrong rather than a blob that
    // moved.
    const wrongGeometry = await bindSelfTest({
      fixture: { ...fixture, periodMinutes: 30 },
      privateKey: issuer.privateKey,
      algorithm: "RSA-OAEP",
    });
    assert.equal(wrongGeometry.ok, false, "the pc fixture does not open under another geometry");
    assert.doesNotMatch(
      wrongGeometry.reason,
      /periodMinutes|30|15/,
      "and the line names no field or value",
    );
    assert.doesNotMatch(wrongGeometry.reason, /not bound to this coordinate/);
  });
});

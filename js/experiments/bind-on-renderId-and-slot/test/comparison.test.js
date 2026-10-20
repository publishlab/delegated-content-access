//
// The controls the renderid-anchored binding is measured against. What core
// refuses is run in bind.test.js; each test here takes one piece of the binding
// away and shows what comes through. The construction, attacks, and layout are
// recorded directly by these cases and their vector.
//
// Local controls under implementation/, plus a shared test-only walk:
//
//   unboundSealing.js  the seal before the binding, which lets the relabel
//                      through; the control every claim in bind.test.js is
//                      measured against
//   bind.js            a delimiter-less join with a collision at malformed
//                      period labels that current request admission rejects
//   test-lib/harnesses/sealedSection.js (under js/): a walk that refuses the whole request where the
//                      engine answers per item, with `slotFrom` making the
//                      soundness condition switchable, so an issuer reading
//                      the slot off a wrapper field hands over the premium key
//                      it just denied
//
// The attacks run through `unsealSection` rather than through `IssuerEngine`
// because they probe the whole-request refusal and the wrapper slot, and the
// engine offers neither.
//
// Both carriers carry one value. `BIND` is the same string on both; only what
// carries it differs: AES-GCM `additionalData` for ECDH, the OAEP plaintext
// prefix for RSA. So every control runs twice, once per carrier, from one body.
// For these 16-byte keys and the tested issuer key sizes, neither carrier
// widens the wire; both widths are asserted against the unbound seal.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { bindValue } from "../../../core-shared--publisher-issuer/bind.js";
import * as boundSealing from "../../../core-shared--publisher-issuer/keySealing.js";
import { naiveBindValue } from "../implementation/bind.js";
import * as naiveSealing from "../implementation/naiveSealing.js";
import * as unboundSealing from "../implementation/unboundSealing.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { sealSection, unsealSection } from "../../../test-lib/harnesses/sealedSection.js";
import { decrypt, encrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import { base64urlDecode, utf8Encode, utf8Decode } from "../../../core-shared/codec.js";
import { ACCESS_GROUP } from "../../../demo/scenarios/fixtures.js";
import { asWire, issuerKeypair, seededRandom } from "../../../test-reference/support/keys.js";
import { makeRenderId } from "../../../test-lib/fixtures/renderId.js";
import { refuses } from "../../../test-lib/helpers/refuses.js";

/** A renderId to bind on; the value is incidental. */
const RENDER_A = makeRenderId(0xa1);

const T = "251023T1300";

/** The two items of one render: the free one and the one worth stealing. */
const CONTENT_KEYS = {
  bodytext: new Uint8Array(16).fill(0x11),
  premiumtext: new Uint8Array(16).fill(0x22),
};

const PERIOD_KEYS = { [ACCESS_GROUP]: { [T]: new Uint8Array(16).fill(0x33) } };

/** The two carriers of one binding value, and the blob width each produces. */
const CARRIERS = [
  { label: "ECDH P-256", algorithm: "ecdh-p256", blobBytes: 109 },
  { label: "rsa-oaep", algorithm: "rsa-oaep", blobBytes: 256 },
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
 * @param {any} [options.keySealing] - `unboundSealing` for the control
 */
async function world(carrier, { renderId = RENDER_A, keys, keySealing } = {}) {
  const { publicKey, privateKey } = keys ?? (await issuerKeypair(carrier.algorithm));
  const random = seededRandom(20251023);

  const sealed = await sealSection({
    renderId,
    contentKeys: CONTENT_KEYS,
    periodKeys: PERIOD_KEYS,
    publicKey,
    algorithm: carrier.algorithm,
    random,
    keySealing,
  });

  /**
   * The issuer's side: what it would return for the coordinates it granted.
   *
   * @param {any} presented - the `sealed` section as the request carries it
   * @param {object} [open]
   * @param {{ contentNames?: string[], accessGroups?: string[] }} [open.granted]
   * @param {string} [open.renderId] - the verified renderId of *this* request
   * @param {'key'|'wrapper'} [open.slotFrom]
   */
  const unlock = (presented, open = {}) =>
    unsealSection({
      sealed: presented,
      renderId: open.renderId ?? renderId,
      privateKey,
      algorithm: carrier.algorithm,
      granted: open.granted,
      slotFrom: open.slotFrom,
      keySealing,
    });

  return { renderId, publicKey, privateKey, random, sealed, unlock };
}

describe("The grammar", () => {
  // No key material anywhere in this section: BIND is a string.

  test("the naive concatenation collides on historical malformed period labels", () => {
    // Direct BIND construction treats period labels as opaque. Both labels
    // here fail current request admission; this is a serialization stress
    // case, not an attack demonstrated through the current issuer path.
    assert.equal(
      naiveBindValue({ renderId: RENDER_A, accessGroup: "premium1", t: "251023T13" }),
      naiveBindValue({ renderId: RENDER_A, accessGroup: "premium", t: "1251023T13" }),
    );
    assert.notEqual(
      bindValue({ renderId: RENDER_A, accessGroup: "premium1", t: "251023T13" }),
      bindValue({ renderId: RENDER_A, accessGroup: "premium", t: "1251023T13" }),
    );
  });

  test("current period-key admission rejects both collision labels before engine work", () => {
    const processor = new IssuerProcessor(
      {
        checkOperatingIssuerName() {},
        async unlock() {
          throw new Error("admission must not invoke the engine");
        },
      },
      { periodKeyInput: true },
    );
    const admit = (accessGroup, t) =>
      processor.admit(
        JSON.stringify({
          version: "1",
          issuerName: "paywall",
          keyId: "2025-10",
          resourceJWT: "opaque-admission-only",
          sealed: { contentKeys: {}, periodKeys: { [accessGroup]: { [t]: "opaque" } } },
        }),
      );
    assert.equal(admit("premium1", T).kind, "admitted", "valid coordinate control");
    for (const [group, t] of [
      ["premium1", "251023T13"],
      ["premium", "1251023T13"],
    ]) {
      assert.deepEqual(admit(group, t), { kind: "failure", code: "binding_failed" });
    }
  });
});

describe("The carriers", () => {
  // One body, run for each. The binding value is the same string on both,
  // and only what carries it differs.

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("binding preserves envelope width for the fixture's 16-byte keys", async () => {
        const { sealed } = await world(carrier);
        const unbound = await world(carrier, { keySealing: unboundSealing });

        for (const [contentName, blob] of Object.entries(sealed.contentKeys)) {
          assert.equal(
            base64urlDecode(blob).length,
            carrier.blobBytes,
            `${contentName} is the width the format budgets`,
          );
          assert.equal(blob.length, unbound.sealed.contentKeys[contentName].length);
        }
        assert.equal(base64urlDecode(sealed.periodKeys[ACCESS_GROUP][T]).length, carrier.blobBytes);
      });

      test("unbound, the same relabel succeeds and hands over the premium key", async () => {
        // The control, and the reason the binding is in core. Same walk, same
        // keypair, same moved blob; only the seal commits to nothing, and the
        // premium contentKey comes back under the bodytext label the issuer
        // granted.
        const { sealed, unlock } = await world(carrier, { keySealing: unboundSealing });

        const opened = await unlock(
          { contentKeys: { bodytext: sealed.contentKeys.premiumtext } },
          { granted: { contentNames: ["bodytext"] } },
        );

        assert.equal(
          opened.contentKeys.bodytext,
          asWire(CONTENT_KEYS.premiumtext),
          "the genuine premium contentKey, returned for a bodytext grant",
        );
      });

      test("the direct envelope harness exposes a naive collision outside admitted period grammar", async () => {
        // Bypass request admission deliberately: a caller moves the boundary
        // between fields. The admission control above rejects these labels.
        const groups = { premium1: { "251023T13": new Uint8Array(16).fill(0x55) } };
        const { publicKey, privateKey } = await issuerKeypair(carrier.algorithm);

        const bound = await sealSection({
          renderId: RENDER_A,
          periodKeys: groups,
          publicKey,
          algorithm: carrier.algorithm,
          random: seededRandom(11),
        });

        const moved = {
          periodKeys: { [ACCESS_GROUP]: { "1251023T13": bound.periodKeys.premium1["251023T13"] } },
        };

        await refuses(
          () =>
            unsealSection({
              sealed: moved,
              renderId: RENDER_A,
              privateKey,
              algorithm: carrier.algorithm,
            }),
          "binding_failed",
          "the delimiter makes premium1|251023T13 and premium|1251023T13 two strings",
        );

        // The control: the same two coordinates joined without a boundary are
        // one value, so the direct walk opens the other group's key.
        const naive = await sealSection({
          renderId: RENDER_A,
          periodKeys: groups,
          publicKey,
          algorithm: carrier.algorithm,
          random: seededRandom(11),
          keySealing: naiveSealing,
        });

        const collided = await unsealSection({
          sealed: {
            periodKeys: {
              [ACCESS_GROUP]: { "1251023T13": naive.periodKeys.premium1["251023T13"] },
            },
          },
          renderId: RENDER_A,
          privateKey,
          algorithm: carrier.algorithm,
          keySealing: naiveSealing,
        });

        assert.equal(
          collided.periodKeys[ACCESS_GROUP]["1251023T13"],
          asWire(groups.premium1["251023T13"]),
          "premium1's periodKey, opened under a premium grant",
        );
      });

      test("an issuer reading the slot off a wrapper field reopens the attack", async () => {
        // The section 3 soundness condition, taken away. The access decision is
        // keyed by the request member name either way; only where the binding
        // value's slot comes from differs.
        const { sealed, unlock } = await world(carrier);

        const presented = {
          contentKeys: {
            bodytext: { blob: sealed.contentKeys.premiumtext, contentName: "premiumtext" },
          },
        };
        const granted = { contentNames: ["bodytext"] };

        await refuses(
          () => unlock(presented, { granted }),
          "binding_failed",
          "the sound issuer binds to the name it decided on and ignores what the request labels it",
        );

        const unsound = await unlock(presented, { granted, slotFrom: "wrapper" });
        assert.equal(
          unsound.contentKeys.bodytext,
          asWire(CONTENT_KEYS.premiumtext),
          "the premium key, handed over on a bodytext grant, because the two labels came from different places",
        );
      });
    });
  }
});

describe("The AAD an issuer forgets to supply", () => {
  // Nothing on the wire says a blob is bound, so the question is what an
  // issuer that omits `additionalData` does: fail open on the relabel, or
  // fail closed on everything.

  test("ECDH: an issuer unsealing unbound fails every bound blob, honest and relabeled alike", async () => {
    const carrier = CARRIERS[0];
    const { sealed, unlock, privateKey } = await world(carrier);

    // `unboundSealing` is the omission itself rather than a stand-in for it: it
    // supplies no additionalData anywhere, which is what an implementation that
    // adopted BIND and missed the carrier would ship.
    const withoutAad = (/** @type {any} */ presented, /** @type {any} */ granted) =>
      unsealSection({
        sealed: presented,
        renderId: RENDER_A,
        privateKey,
        algorithm: carrier.algorithm,
        granted,
        keySealing: unboundSealing,
      });

    await refuses(
      () =>
        withoutAad(
          { contentKeys: { bodytext: sealed.contentKeys.bodytext } },
          { contentNames: ["bodytext"] },
        ),
      "binding_failed",
      "the honest presentation is what fails first: the tag commits an AAD this unseal supplies none of",
    );
    await refuses(
      () =>
        withoutAad(
          { periodKeys: { [ACCESS_GROUP]: { [T]: sealed.periodKeys[ACCESS_GROUP][T] } } },
          undefined,
        ),
      "binding_failed",
      "and the period coordinate with it - nothing this issuer is asked to open opens",
    );

    // The claim: the relabel the omission was feared to let through fails
    // the same way the honest request does. The mistake is total and
    // immediately visible, never a silent downgrade.
    await refuses(
      () =>
        withoutAad(
          { contentKeys: { bodytext: sealed.contentKeys.premiumtext } },
          { contentNames: ["bodytext"] },
        ),
      "binding_failed",
      "the relabel gets no more out of a missing AAD than the honest request does",
    );

    // The control: the same blobs, the same key, the same walk, with the AAD
    // supplied, so what failed above is the omission and nothing else.
    const opened = await unlock(sealed);
    assert.equal(opened.contentKeys.bodytext, asWire(CONTENT_KEYS.bodytext));
    assert.equal(opened.periodKeys[ACCESS_GROUP][T], asWire(PERIOD_KEYS[ACCESS_GROUP][T]));
  });
});

/**
 * A decoder that falls back: core's bound unseal first, the unbound one when it
 * throws. It is the accommodating thing a migration reaches for ("keep opening
 * the old blobs while the publishers catch up"), written as a keySealing module
 * so `unsealSection` drives it the way it drives any other.
 *
 * @returns {any}
 */
function fallbackSealing() {
  return {
    seal: boundSealing.seal,
    /**
     * @param {string} blob
     * @param {CryptoKey} privateKey
     * @param {string} algorithm
     * @param {any} options
     */
    unseal: async (blob, privateKey, algorithm, options) => {
      try {
        return await boundSealing.open(blob, privateKey, algorithm, options);
      } catch {
        return await unboundSealing.unseal(blob, privateKey, algorithm, {});
      }
    },
  };
}

describe("Bound and unbound decoder configurations", () => {
  // These tests select decoder modules directly with the same issuer keypair.
  // They do not exercise keyId registration or disjoint opening-key custody.

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("bound decoding rejects unbound blobs; unbound RSA decoding releases bound key bytes", async () => {
        // Share one keypair so the decoder is the only difference.
        const keys = await issuerKeypair(carrier.algorithm);
        const legacy = await world(carrier, { keys, keySealing: unboundSealing });
        const bound = await world(carrier, { keys });

        // Each opens its own, so the rest of this shows decoding rather
        // than a broken keypair.
        assert.equal(
          (await legacy.unlock(legacy.sealed)).contentKeys.bodytext,
          asWire(CONTENT_KEYS.bodytext),
        );
        assert.equal(
          (await bound.unlock(bound.sealed)).contentKeys.bodytext,
          asWire(CONTENT_KEYS.bodytext),
        );

        await refuses(
          () =>
            bound.unlock(
              { contentKeys: { bodytext: legacy.sealed.contentKeys.bodytext } },
              { granted: { contentNames: ["bodytext"] } },
            ),
          "binding_failed",
          "the bound decoder refuses: ECDH tag mismatch or RSA's 16-byte key missing the BIND prefix",
        );

        if (carrier.algorithm === "ecdh-p256") {
          await refuses(
            () =>
              legacy.unlock(
                { contentKeys: { bodytext: bound.sealed.contentKeys.bodytext } },
                { granted: { contentNames: ["bodytext"] } },
              ),
            "binding_failed",
            "the unbound ECDH decoder supplies none of the AAD committed by the tag",
          );
        } else {
          const plaintext = utf8Encode("premium content denied to this reader");
          const nonce = new Uint8Array(NONCE_BYTES);
          const ciphertext = await encrypt(CONTENT_KEYS.premiumtext, nonce, plaintext);
          // The RSA asymmetry. An unbound unseal recovers whatever OAEP hands
          // it and measures no width, so a relabeled bound blob comes back as
          // BIND then the premium key. Releasing that plaintext discloses the
          // key: a reader can extract the final 16 bytes regardless of whether
          // a stock AES consumer rejects the whole oversized value.
          const presented = { contentKeys: { bodytext: bound.sealed.contentKeys.premiumtext } };
          const granted = { contentNames: ["bodytext"] };
          await refuses(() => bound.unlock(presented, { granted }), "binding_failed");
          const opened = await legacy.unlock(presented, { granted });
          const recovered = base64urlDecode(opened.contentKeys.bodytext);

          assert.notEqual(opened.contentKeys.bodytext, asWire(CONTENT_KEYS.bodytext));
          assert.equal(
            utf8Decode(recovered.subarray(0, recovered.length - 16)),
            bindValue({ renderId: RENDER_A, contentName: "premiumtext" }),
            "the binding, in front of the key, with nobody on this path checking it",
          );
          await assert.rejects(
            () => encrypt(recovered, new Uint8Array(NONCE_BYTES), utf8Encode("x")),
            /16-byte key/,
            "rejecting the whole oversized value does not remove the disclosed suffix",
          );
          const stolenKey = recovered.subarray(recovered.length - 16);
          assert.deepEqual(stolenKey, CONTENT_KEYS.premiumtext);
          assert.deepEqual(await decrypt(stolenKey, nonce, ciphertext), plaintext);
        }
      });

      test("a decoder that falls back to unbound unsealing releases the relabeled premium key", async () => {
        const keys = await issuerKeypair(carrier.algorithm);
        const legacy = await world(carrier, { keys, keySealing: unboundSealing });
        const bound = await world(carrier, { keys });

        const unlock = (/** @type {any} */ presented, /** @type {any} */ granted) =>
          unsealSection({
            sealed: presented,
            renderId: RENDER_A,
            privateKey: keys.privateKey,
            algorithm: carrier.algorithm,
            granted,
            keySealing: fallbackSealing(),
          });

        // It looks like the helpful thing to do during a migration, and it
        // opens both shapes of blob with one private key.
        assert.equal(
          (await unlock(bound.sealed, undefined)).contentKeys.premiumtext,
          asWire(CONTENT_KEYS.premiumtext),
        );
        assert.equal(
          (await unlock(legacy.sealed, undefined)).contentKeys.premiumtext,
          asWire(CONTENT_KEYS.premiumtext),
        );

        // The downgrade. A reader granted bodytext presents the legacy premium
        // blob at that coordinate. The bound unseal refuses it, correctly, and
        // the fallback then opens it anyway, because the legacy seal commits to
        // nothing. Every publisher still on the old sealer is a relabel surface
        // for as long as one decoder accepts both.
        const opened = await unlock(
          { contentKeys: { bodytext: legacy.sealed.contentKeys.premiumtext } },
          { contentNames: ["bodytext"] },
        );
        assert.equal(
          opened.contentKeys.bodytext,
          asWire(CONTENT_KEYS.premiumtext),
          "the premium contentKey, handed over on a bodytext grant",
        );

        // The same relabel under the decoder pinned to bound sealing, the
        // arrangement the claim asks for and the one the fallback gives up.
        await refuses(
          () =>
            bound.unlock(
              { contentKeys: { bodytext: legacy.sealed.contentKeys.premiumtext } },
              { granted: { contentNames: ["bodytext"] } },
            ),
          "binding_failed",
          "bound decoding refuses the relabel before releasing any plaintext",
        );
      });
    });
  }
});

// @ts-check
// Base placement: js/v1/test-lib/suites/retained-render.js
//
// One old article render and one current article render share one exact period
// key. A reader retains the old public ciphertext, sealed content key,
// period-key blob, and matching coordinate. The issuer private key stays
// in the harness, out of the attacker's hands.
//
// The test first proves the complete old render still opens at its honest old
// coordinate. It then presents the old period-key blob at the current render.
// Two renders are enough: more saved copies repeat the same BIND decision.

import { before, describe, test } from "node:test";
import assert from "node:assert/strict";

import { decrypt, encrypt, NONCE_BYTES } from "../../../../core-shared/aead.js";
import { utf8Decode, utf8Encode } from "../../../../core-shared/codec.js";
import { issuerKeypair, seededRandom } from "../../../../test-reference/support/keys.js";
import { makeRenderId } from "../../../../test-lib/fixtures/renderId.js";

const OLD_RENDER = makeRenderId(0x31);
const CURRENT_RENDER = makeRenderId(0x41);
const PUBLISHER = "publisher.example";
const ACCESS_GROUP = "premium";
const T = "251023T14";
const PERIOD_KEY = new Uint8Array(16).fill(0x71);

const CARRIERS = [
  { id: "ecdh", label: "ECDH P-256", algorithm: "ECDH-P256" },
  { id: "rsa", label: "RSA-OAEP", algorithm: "RSA-OAEP" },
];

/**
 * @typedef {object} SemanticBinding
 * @property {string} publisher
 * @property {string} renderId
 * @property {string} accessGroup
 * @property {string} t
 */

/**
 * @typedef {object} Target
 * @property {(key: Uint8Array, publicKey: CryptoKey, algorithm: string, options: any) => Promise<string>} seal
 * @property {(blob: string, privateKey: CryptoKey, algorithm: string, options: any) => Promise<Uint8Array>} open
 * @property {(binding: SemanticBinding) => any} binding
 */

/** @param {string} renderId */
function semantic(renderId) {
  return { publisher: PUBLISHER, renderId, accessGroup: ACCESS_GROUP, t: T };
}

async function oldArticle() {
  const contentKey = new Uint8Array(16).fill(0x72);
  const keyNonce = new Uint8Array(NONCE_BYTES).fill(0x73);
  const keyAad = utf8Encode(
    `${PUBLISHER}|article-old|${OLD_RENDER}|premiumtext|${ACCESS_GROUP}|${T}`,
  );
  const contentNonce = new Uint8Array(NONCE_BYTES).fill(0x74);
  const contentAad = utf8Encode(`${PUBLISHER}|article-old|${OLD_RENDER}|premiumtext`);
  const plaintext = "content retained with the old article render";

  return {
    keyNonce,
    keyAad,
    sealedContentKey: await encrypt(PERIOD_KEY, keyNonce, contentKey, keyAad),
    contentNonce,
    contentAad,
    ciphertext: await encrypt(contentKey, contentNonce, utf8Encode(plaintext), contentAad),
    plaintext,
  };
}

/** @param {Uint8Array} periodKey @param {Awaited<ReturnType<typeof oldArticle>>} retained */
async function assertOpensOldArticle(periodKey, retained) {
  const contentKey = await decrypt(
    periodKey,
    retained.keyNonce,
    retained.sealedContentKey,
    retained.keyAad,
  );
  const opened = await decrypt(
    contentKey,
    retained.contentNonce,
    retained.ciphertext,
    retained.contentAad,
  );
  assert.equal(
    utf8Decode(opened),
    retained.plaintext,
    "the returned period key opens content retained with the old render",
  );
}

/** @param {unknown} error */
function isUnsealFailure(error) {
  return /** @type {any} */ (error)?.code === "unseal_failed";
}

/**
 * @param {{ target: Target, targetLabel: string, movedValueOutcome?: 'accepted'|'refused' }} config
 */
export function registerRetainedRenderSuite({
  target,
  targetLabel,
  movedValueOutcome = "accepted",
}) {
  /** @type {Map<string, 'accepted'|'refused'>} */
  const outcomes = new Map();

  describe(`Reader retaining an old render: ${targetLabel}`, () => {
    for (const [index, carrier] of CARRIERS.entries()) {
      describe(carrier.label, () => {
        /** @type {CryptoKeyPair} */
        let issuer;
        before(async () => {
          issuer = await issuerKeypair(carrier.algorithm);
        });

        /** @param {string} blob @param {SemanticBinding} binding */
        const open = (blob, binding) =>
          target.open(blob, issuer.privateKey, carrier.algorithm, {
            binding: target.binding(binding),
          });

        test(`${movedValueOutcome.toUpperCase()}: old render's sealed period value presented at current render`, async (t) => {
          const oldCoordinate = semantic(OLD_RENDER);
          const currentCoordinate = semantic(CURRENT_RENDER);
          const retained = await oldArticle();
          const sealOptions = (binding, seed) =>
            carrier.algorithm === "RSA-OAEP"
              ? { binding: target.binding(binding) }
              : { binding: target.binding(binding), random: seededRandom(seed) };
          const oldBlob = await target.seal(
            PERIOD_KEY,
            issuer.publicKey,
            carrier.algorithm,
            sealOptions(oldCoordinate, 101 + index),
          );
          const currentBlob = await target.seal(
            PERIOD_KEY,
            issuer.publicKey,
            carrier.algorithm,
            sealOptions(currentCoordinate, 201 + index),
          );

          const openedOld = await open(oldBlob, oldCoordinate);
          assert.deepEqual(openedOld, PERIOD_KEY, "the complete old render still opens honestly");
          await assertOpensOldArticle(openedOld, retained);
          assert.deepEqual(
            await open(currentBlob, currentCoordinate),
            PERIOD_KEY,
            "the same exact period authority opens in the current render",
          );

          let moved;
          try {
            moved = await open(oldBlob, currentCoordinate);
          } catch (error) {
            outcomes.set(carrier.id, "refused");
            if (!isUnsealFailure(error)) throw error;
            t.diagnostic(
              "the moved blob was refused, but its matching retained old render opened above",
            );
            assert.equal(
              movedValueOutcome,
              "refused",
              "the comparison expected this moved sealed value to be refused",
            );
            return;
          }

          outcomes.set(carrier.id, "accepted");
          assert.ok(moved instanceof Uint8Array, "an accepted issuer seal returns key bytes");
          assert.deepEqual(moved, PERIOD_KEY, "the issuer returned the exact retained period key");
          await assertOpensOldArticle(moved, retained);
          assert.equal(
            movedValueOutcome,
            "accepted",
            "the comparison expected this moved sealed value to be accepted",
          );
        });
      });
    }

    test("the classified outcomes remain exact", () => {
      const expected = new Map(CARRIERS.map(({ id }) => [id, movedValueOutcome]));
      assert.deepEqual(outcomes, expected);
    });
  });
}

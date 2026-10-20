// @ts-check
// Base placement: js/test-lib/suites/period-binding-authority.js
//
// One period-authority comparison, run unchanged against the shipped BIND and
// the authority candidate. The target adapter says only how semantic fields map
// to that implementation's binding object. Classified outcomes are explicit
// passing observations, not TODO-shaped failures.

import { before, describe, test } from "node:test";
import assert from "node:assert/strict";

import { issuerKeypair, seededRandom } from "../../../../test-reference/support/keys.js";
import { makeRenderId } from "../../../../test-lib/fixtures/renderId.js";

const RENDER_A = makeRenderId(0xa1);
const RENDER_B = makeRenderId(0xb2);
const PERIOD_KEY = new Uint8Array(16).fill(0x4a);

const CARRIERS = [
  { id: "ecdh", label: "ECDH P-256", algorithm: "ecdh-p256" },
  { id: "rsa", label: "rsa-oaep", algorithm: "rsa-oaep" },
];

const KINDS = [
  { id: "period-key", chainKey: false },
  { id: "chain-key", chainKey: true },
];

const CASE_IDS = [
  ...KINDS.flatMap(({ id }) => [
    `${id}/cross-render`,
    `${id}/publisher`,
    `${id}/accessGroup`,
    `${id}/t`,
  ]),
  "kind/period-key-as-chain-key",
  "kind/chain-key-as-period-key",
];

/**
 * @typedef {object} SemanticBinding
 * @property {string} publisher
 * @property {string} renderId
 * @property {string} accessGroup
 * @property {string} t
 * @property {boolean} chainKey
 */

/**
 * @typedef {object} Target
 * @property {(key: Uint8Array, publicKey: CryptoKey, algorithm: string, options: any) => Promise<string>} seal
 * @property {(blob: string, privateKey: CryptoKey, algorithm: string, options: any) => Promise<Uint8Array>} open
 * @property {(binding: SemanticBinding) => any} binding
 */

const BASE = {
  publisher: "publisher-a.example",
  renderId: RENDER_A,
  accessGroup: "premium",
  t: "251023T1400",
  chainKey: false,
};

/** @param {any} error */
function isUnsealFailure(error) {
  return error?.code === "unseal_failed";
}

/**
 * @param {{
 *   target: Target,
 *   targetLabel: string,
 *   classifiedOutcomes: Record<string, 'accepted'|'refused'>,
 * }} config
 */
export function registerPeriodBindingAuthoritySuite({ target, targetLabel, classifiedOutcomes }) {
  for (const id of Object.keys(classifiedOutcomes)) {
    if (!CASE_IDS.includes(id)) throw new Error(`unknown period-authority case ${id}`);
  }
  for (const id of CASE_IDS) {
    if (!Object.hasOwn(classifiedOutcomes, id)) {
      throw new Error(`missing period-authority outcome ${id}`);
    }
  }

  /** @param {string} id */
  const expectedFor = (id) => classifiedOutcomes[id];

  /** @param {string} id @param {string} subject */
  const caseLabel = (id, subject) => `${expectedFor(id).toUpperCase()}: ${subject}`;

  /** @type {Map<string, string>} */
  const outcomes = new Map();

  describe(`Period BIND authority: ${targetLabel}`, () => {
    for (const carrier of CARRIERS) {
      describe(carrier.label, () => {
        /** @type {CryptoKeyPair} */
        let issuer;
        before(async () => {
          issuer = await issuerKeypair(carrier.algorithm);
        });

        /** @param {SemanticBinding} binding */
        const seal = (binding) =>
          target.seal(
            PERIOD_KEY,
            issuer.publicKey,
            carrier.algorithm,
            carrier.algorithm === "rsa-oaep"
              ? { binding: target.binding(binding), random: seededRandom(31) }
              : { binding: target.binding(binding), random: seededRandom(31) },
          );

        /** @param {string} blob @param {SemanticBinding} binding */
        const open = (blob, binding) =>
          target.open(
            blob,
            issuer.privateKey,
            carrier.algorithm,
            carrier.algorithm === "rsa-oaep"
              ? { binding: target.binding(binding) }
              : { binding: target.binding(binding) },
          );

        for (const kind of KINDS) {
          const source = { ...BASE, chainKey: kind.chainKey };

          const crossRenderId = `${kind.id}/cross-render`;
          test(
            caseLabel(crossRenderId, `${kind.id} sealed value presented at another render`),
            async () => {
              const sourceAtRenderB = { ...source, renderId: RENDER_B };
              const blob = await seal(sourceAtRenderB);
              assert.deepEqual(
                await open(blob, sourceAtRenderB),
                PERIOD_KEY,
                "honest source render opens",
              );
              let outcome;
              try {
                assert.deepEqual(await open(blob, source), PERIOD_KEY);
                outcome = "accepted";
              } catch (error) {
                if (!isUnsealFailure(error)) throw error;
                outcome = "refused";
              }
              outcomes.set(`${carrier.id}/${crossRenderId}`, outcome);
              assert.equal(outcome, expectedFor(crossRenderId));
            },
          );

          for (const changed of [
            ["publisher", "publisher-b.example"],
            ["accessGroup", "free"],
            ["t", "251023T1500"],
          ]) {
            const [field, value] = changed;
            const id = `${kind.id}/${field}`;
            const detail =
              field === "publisher"
                ? "changed publisher in a same-keyset, colliding-renderId primitive probe"
                : `changed ${field}`;
            test(caseLabel(id, `${kind.id} ${detail}`), async () => {
              const blob = await seal(source);
              assert.deepEqual(await open(blob, source), PERIOD_KEY, "honest coordinate opens");
              let outcome;
              try {
                await open(blob, { ...source, [field]: value });
                outcome = "accepted";
              } catch (error) {
                if (!isUnsealFailure(error)) throw error;
                outcome = "refused";
              }
              outcomes.set(`${carrier.id}/${id}`, outcome);
              assert.equal(outcome, expectedFor(id));
            });
          }
        }

        for (const confusion of [
          { id: "kind/period-key-as-chain-key", source: false, destination: true },
          { id: "kind/chain-key-as-period-key", source: true, destination: false },
        ]) {
          test(caseLabel(confusion.id, confusion.id.replace("/", ": ")), async () => {
            const source = { ...BASE, chainKey: confusion.source };
            const blob = await seal(source);
            assert.deepEqual(await open(blob, source), PERIOD_KEY, "honest kind opens");
            let outcome;
            try {
              await open(blob, { ...source, chainKey: confusion.destination });
              outcome = "accepted";
            } catch (error) {
              if (!isUnsealFailure(error)) throw error;
              outcome = "refused";
            }
            outcomes.set(`${carrier.id}/${confusion.id}`, outcome);
            assert.equal(outcome, expectedFor(confusion.id));
          });
        }
      });
    }

    test("the classified outcomes remain exact", () => {
      const expected = CARRIERS.flatMap(({ id: carrier }) =>
        CASE_IDS.map((id) => [`${carrier}/${id}`, expectedFor(id)]),
      ).sort(([a], [b]) => a.localeCompare(b));
      const observed = [...outcomes].sort(([a], [b]) => a.localeCompare(b));
      assert.deepEqual(observed, expected);
    });
  });
}

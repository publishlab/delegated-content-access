// @ts-check
//
// The five relabel cases shared by the shipped BIND invariant and the
// accessGroup-only comparison.  The binding is injected: this file holds the
// fixture, coordinates, carrier matrix, readable refusal diagnosis, hostile
// client consequence, suite registration and completeness accounting, while a
// variant's implementation stays outside it.
// An entry point supplies the implementation, its display name, and the case
// IDs it expects to fail the same invariant under a rejected construction.

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { decrypt, encrypt, NONCE_BYTES } from "../../core-shared/aead.js";
import { base64urlDecode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { asWire, issuerKeypair, seededRandom } from "../../test-reference/support/keys.js";
import { makeRenderId } from "../fixtures/renderId.js";

const CARRIERS = [
  { id: "ecdh-p256", label: "ECDH P-256", algorithm: "ecdh-p256" },
  { id: "rsa-oaep", label: "RSA-OAEP", algorithm: "rsa-oaep" },
];

const CASES = [
  {
    id: "cross-accessGroup",
    label: "cross-accessGroup control: premiumtext → bodytext (premium → free)",
    action: "premium contentKey moved to the free bodytext field",
    source: "contentKeys.premiumtext (premium)",
    destination: "contentKeys.bodytext (free)",
    missingDimension: "none",
    missing: "none: the accessGroup changes",
  },
  {
    id: "same-render-different-contentName",
    label: "same render, different contentName: premiumtext → premium (premium → premium)",
    action: "premium contentKey moved to a different contentName in the same render",
    source: "contentKeys.premiumtext (premium)",
    destination: "contentKeys.premium (premium)",
    missingDimension: "contentName",
    missing: "contentName",
  },
  {
    id: "cross-render",
    label: "render B premium contentKey → render A",
    action: "another render's premium contentKey pasted into this render",
    source: "render B contentKeys.premiumtext",
    destination: "render A contentKeys.premiumtext",
    missingDimension: "renderId",
    missing: "renderId",
  },
  {
    id: "cross-period",
    label: "periodKeys.premium.t2 → periodKeys.premium.t1",
    action: "t2 premium periodKey pasted into the t1 periodKey field",
    source: "periodKeys.premium.251023T1400 (t2)",
    destination: "periodKeys.premium.251023T1300 (t1)",
    missingDimension: "t",
    missing: "t",
  },
  {
    id: "key-kind",
    label: "contentKey grant → periodKey capability",
    action: "premium periodKey pasted where a granted premium contentKey is expected",
    source: "periodKeys.premium.251023T1300 (periodKey capability)",
    destination: "contentKeys.premium",
    missingDimension: "key kind",
    missing: "key kind",
  },
];

// An independent pin for the runner plan. Do not derive it from CASES: a case
// accidentally removed from the definitions must stay expected and fail the
// completeness check rather than shrinking both sides of the comparison.
const EXPECTED_CASE_IDS = [
  "cross-accessGroup",
  "same-render-different-contentName",
  "cross-render",
  "cross-period",
  "key-kind",
];

const COUNT_WORDS = [
  "zero",
  "one",
  "two",
  "three",
  "four",
  "five",
  "six",
  "seven",
  "eight",
  "nine",
  "ten",
];

const FREE = "free";
const PREMIUM = "premium";
const T1 = "251023T1300";
const T2 = "251023T1400";
const RENDER_A = makeRenderId(0xa1);
const RENDER_B = makeRenderId(0xb2);
const ACCESS_GROUP_OF = { bodytext: FREE, premiumtext: PREMIUM, premium: PREMIUM };

/** @param {number} value */
function key(value) {
  return new Uint8Array(16).fill(value);
}

/**
 * @typedef {{ seal: (config: any) => Promise<any>, unseal: (config: any) => Promise<any> }} BindingHarness
 */

/**
 * @param {BindingHarness} binding
 * @param {any} carrier
 * @param {{ renderId: string, mark: number, domain?: string, keys?: CryptoKeyPair }} config
 */
async function render(binding, carrier, { renderId, mark, domain = "publisher.example", keys }) {
  const issuer = keys ?? (await issuerKeypair(carrier.algorithm));
  const contentKeys = { bodytext: key(mark), premiumtext: key(mark + 1), premium: key(mark + 2) };
  const periodKeys = { [PREMIUM]: { [T1]: key(mark + 3), [T2]: key(mark + 4) } };
  const common = {
    renderId,
    contentKeys,
    periodKeys,
    accessGroupOf: ACCESS_GROUP_OF,
    publicKey: issuer.publicKey,
    algorithm: carrier.algorithm,
    random: seededRandom(20251023),
  };
  const sealed = await binding.seal(common);

  // A classified variant failure must prove that the returned key opens the
  // source content, rather than merely returning bytes that fail later in an
  // honest client using the destination coordinate.
  /** @type {Record<string, {nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, plaintext: string}>} */
  const content = {};
  for (const [index, [contentName, contentKey]] of Object.entries(contentKeys).entries()) {
    const nonce = new Uint8Array(NONCE_BYTES).fill(mark + index + 1);
    const aad = utf8Encode(`${domain}|${renderId}|${contentName}`);
    const plaintext = `${domain}:${renderId}:${contentName}`;
    content[contentName] = {
      nonce,
      aad,
      ciphertext: await encrypt(contentKey, nonce, utf8Encode(plaintext), aad),
      plaintext,
    };
  }

  // A periodKey is a capability, not merely a wire value. Each period gets
  // another premium article whose contentKey it unwraps and whose content it
  // then opens. The two key-kind cases use this to witness the exact reach
  // gained from the returned periodKey.
  /** @type {Record<string, {
   *   t: string,
   *   contentKey: Uint8Array,
   *   wrappedContentKey: {nonce: Uint8Array, ciphertext: Uint8Array},
   *   content: {nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, plaintext: string},
   * }>} */
  const periodContent = {};
  for (const [index, [t, periodKey]] of Object.entries(periodKeys[PREMIUM]).entries()) {
    const contentKey = key(mark + 0x20 + index);
    const wrappedContentKey = {
      nonce: new Uint8Array(NONCE_BYTES).fill(mark + 0x30 + index),
      ciphertext: await encrypt(
        periodKey,
        new Uint8Array(NONCE_BYTES).fill(mark + 0x30 + index),
        contentKey,
      ),
    };
    const articleRenderId = makeRenderId(mark + 0x40 + index);
    const aad = utf8Encode(`${domain}|${articleRenderId}|premiumtext`);
    const plaintext = `${domain}:${articleRenderId}:premiumtext:${t}`;
    periodContent[t] = {
      t,
      contentKey,
      wrappedContentKey,
      content: {
        nonce: new Uint8Array(NONCE_BYTES).fill(mark + 0x50 + index),
        aad,
        ciphertext: await encrypt(
          contentKey,
          new Uint8Array(NONCE_BYTES).fill(mark + 0x50 + index),
          utf8Encode(plaintext),
          aad,
        ),
        plaintext,
      },
    };
  }

  const unlock = (presented, granted) =>
    binding.unseal({
      sealed: presented,
      renderId,
      accessGroupOf: ACCESS_GROUP_OF,
      privateKey: issuer.privateKey,
      algorithm: carrier.algorithm,
      granted,
    });
  return {
    renderId,
    domain,
    keys: issuer,
    contentKeys,
    periodKeys,
    content,
    periodContent,
    sealed,
    unlock,
  };
}

/**
 * Build the exact moved request for one shared case.  A successful operation
 * returns the response and the exact source key it must contain; a refusal is
 * checked by the shared assertion below.
 *
 * @param {BindingHarness} binding
 * @param {any} carrier
 * @param {string} caseId
 */
async function prepareRelabelCase(binding, carrier, caseId) {
  const definition = CASES.find(({ id }) => id === caseId);
  if (!definition) throw new Error(`unknown binding relabel case ${caseId}`);
  const a = await render(binding, carrier, { renderId: RENDER_A, mark: 0x11 });

  switch (caseId) {
    case "cross-accessGroup":
      return {
        definition,
        operation: () =>
          a.unlock(
            { contentKeys: { bodytext: a.sealed.contentKeys.premiumtext } },
            { contentNames: ["bodytext"] },
          ),
        responseKey: (result) => result.contentKeys.bodytext,
        expectedKey: a.contentKeys.premiumtext,
        sourceContent: a.content.premiumtext,
      };
    case "same-render-different-contentName":
      return {
        definition,
        operation: () =>
          a.unlock(
            { contentKeys: { premium: a.sealed.contentKeys.premiumtext } },
            { contentNames: ["premium"] },
          ),
        responseKey: (result) => result.contentKeys.premium,
        expectedKey: a.contentKeys.premiumtext,
        sourceContent: a.content.premiumtext,
      };
    case "cross-render": {
      const b = await render(binding, carrier, { renderId: RENDER_B, mark: 0x51, keys: a.keys });
      return {
        definition,
        operation: () =>
          a.unlock(
            { contentKeys: { premiumtext: b.sealed.contentKeys.premiumtext } },
            { contentNames: ["premiumtext"] },
          ),
        responseKey: (result) => result.contentKeys.premiumtext,
        expectedKey: b.contentKeys.premiumtext,
        sourceContent: b.content.premiumtext,
      };
    }
    case "cross-period":
      return {
        definition,
        operation: () =>
          a.unlock(
            { periodKeys: { [PREMIUM]: { [T1]: a.sealed.periodKeys[PREMIUM][T2] } } },
            { accessGroups: [PREMIUM] },
          ),
        responseKey: (result) => result.periodKeys[PREMIUM][T1],
        expectedKey: a.periodKeys[PREMIUM][T2],
        sourcePeriodContent: a.periodContent[T2],
      };
    case "key-kind":
      return {
        definition,
        operation: () =>
          a.unlock(
            { contentKeys: { premium: a.sealed.periodKeys[PREMIUM][T1] } },
            { contentNames: ["premium"] },
          ),
        responseKey: (result) => result.contentKeys.premium,
        expectedKey: a.periodKeys[PREMIUM][T1],
        sourcePeriodContent: a.periodContent[T1],
      };
  }
  throw new Error(`unhandled binding relabel case ${caseId}`);
}

/**
 * A readable strict assertion for a case the binding is required to refuse.
 * If a weak binding returns a key, the failure says what was returned and why
 * that is a security consequence rather than dumping bytes.
 *
 * @param {{ definition: typeof CASES[number], operation: () => Promise<any> }} prepared
 * @param {string} bindingLabel
 * @param {string} carrierLabel
 */
async function assertBindingRefusal(prepared, bindingLabel, carrierLabel) {
  try {
    await prepared.operation();
  } catch (error) {
    assert.equal(
      error?.code,
      "binding_failed",
      `${bindingLabel}; ${carrierLabel}; ${prepared.definition.action}: required binding_failed`,
    );
    return;
  }
  assert.fail(
    [
      "required binding_failed; issuer returned a key",
      `binding: ${bindingLabel}`,
      `carrier: ${carrierLabel}`,
      `move: ${prepared.definition.source}`,
      `   → ${prepared.definition.destination}`,
      `missing BIND dimension: ${prepared.definition.missingDimension}`,
      ...(prepared.definition.fixtureContext
        ? [`fixture: ${prepared.definition.fixtureContext}`]
        : []),
    ].join("\n"),
  );
}

/**
 * Prove the specific adverse outcome before a rejected variant deliberately
 * fails the unchanged refusal assertion. A returned contentKey must open the
 * source ciphertext under the source AAD. A returned periodKey must unwrap a
 * source contentKey and open that content. Bytes that only look like a key do
 * not classify a security-relevant relabel.
 *
 * @param {Awaited<ReturnType<typeof prepareRelabelCase>>} prepared
 * @param {string} bindingLabel
 * @param {string} carrierLabel
 * @param {(message: string) => void} diagnostic
 */
async function assertExactMovedKeyWitness(prepared, bindingLabel, carrierLabel, diagnostic) {
  const { definition } = prepared;
  let result;
  try {
    result = await prepared.operation();
  } catch (error) {
    assert.equal(
      error?.code,
      "binding_failed",
      `${bindingLabel}; ${carrierLabel}; ${definition.action}: required binding_failed`,
    );
    assert.fail(
      `${definition.action}: expected relabel acceptance was refused; reclassify this comparison`,
    );
  }

  const returnedKeyWire = prepared.responseKey(result);
  assert.equal(
    returnedKeyWire,
    asWire(prepared.expectedKey),
    `${definition.action}: returned key is the exact moved source key`,
  );
  const returnedKey = base64urlDecode(returnedKeyWire);

  if (prepared.sourceContent) {
    const plaintext = await decrypt(
      returnedKey,
      prepared.sourceContent.nonce,
      prepared.sourceContent.ciphertext,
      prepared.sourceContent.aad,
    );
    assert.equal(
      utf8Decode(plaintext),
      prepared.sourceContent.plaintext,
      `${definition.action}: a hostile client opens the source ciphertext with the returned key`,
    );
  }

  if (prepared.sourcePeriodContent) {
    const unwrappedContentKey = await decrypt(
      returnedKey,
      prepared.sourcePeriodContent.wrappedContentKey.nonce,
      prepared.sourcePeriodContent.wrappedContentKey.ciphertext,
    );
    assert.deepEqual(
      unwrappedContentKey,
      prepared.sourcePeriodContent.contentKey,
      `${definition.action}: returned periodKey unwraps ${prepared.sourcePeriodContent.t}'s contentKey`,
    );
    const plaintext = await decrypt(
      unwrappedContentKey,
      prepared.sourcePeriodContent.content.nonce,
      prepared.sourcePeriodContent.content.ciphertext,
      prepared.sourcePeriodContent.content.aad,
    );
    assert.equal(
      utf8Decode(plaintext),
      prepared.sourcePeriodContent.content.plaintext,
      `${definition.action}: returned periodKey opens premium content in ${prepared.sourcePeriodContent.t}`,
    );
  }

  diagnostic(
    prepared.sourcePeriodContent
      ? `witness: issuer returned the exact moved periodKey; it unwrapped a contentKey and opened ${prepared.sourcePeriodContent.t} premium content`
      : prepared.sourceContent
        ? "witness: issuer returned the exact moved key and it opened the source content"
        : "witness: issuer returned the exact moved key",
  );
  diagnostic(`${definition.source} → ${definition.destination}`);
  diagnostic(`missing binding dimension: ${definition.missingDimension}`);
  if (definition.fixtureContext) diagnostic(`fixture context: ${definition.fixtureContext}`);
}

/** @param {number} value */
function spell(value) {
  return COUNT_WORDS[value] ?? String(value);
}

/**
 * @param {number} value
 * @param {string} noun
 */
function counted(value, noun) {
  return `${spell(value)} ${noun}${value === 1 ? "" : "s"}`;
}

function planLabel() {
  return (
    "the relabel plan is complete: " +
    `${counted(EXPECTED_CASE_IDS.length, "case")} × ${counted(CARRIERS.length, "carrier")}`
  );
}

/** @param {string[]} expectedFailures */
function assertPinnedExpectedFailures(expectedFailures) {
  const seen = new Set();
  for (const caseId of expectedFailures) {
    if (!EXPECTED_CASE_IDS.includes(caseId)) {
      throw new Error(`unknown expected relabel failure ${caseId}`);
    }
    if (seen.has(caseId)) throw new Error(`duplicate expected relabel failure ${caseId}`);
    seen.add(caseId);
  }
}

/**
 * Register the relabel suite for one binding.  Every case runs against every
 * carrier. Every run uses the same strict refusal assertion. The variant lane
 * may pin known failures as TODOs, but the completeness check still requires
 * those assertions to fail: a repaired or reclassified construction turns red.
 *
 * @param {{
 *     binding: BindingHarness,
 *     bindingLabel: string,
 *     suiteLabel: string,
 *     expectedFailures?: string[],
 * }} config
 */
export function registerBindingRelabelSuite({
  binding,
  bindingLabel,
  suiteLabel,
  expectedFailures = [],
}) {
  assertPinnedExpectedFailures(expectedFailures);

  /** @type {string[]} */
  const registered = [];
  /** @type {string[]} */
  const completed = [];
  /** @type {string[]} */
  const observedExpectedFailures = [];
  /** @type {string[]} */
  const observedStrictFailures = [];

  describe(suiteLabel, () => {
    for (const carrier of CARRIERS) {
      describe(carrier.label, () => {
        describe("Relabel requests from a dishonest reader", () => {
          for (const definition of CASES) {
            const runId = `${carrier.id}/${definition.id}`;
            registered.push(runId);

            const expectedFailure = expectedFailures.includes(definition.id);
            const title = `${expectedFailure ? "ACCEPTED RELABEL" : "BLOCKED"}: ${definition.label}`;
            const options = expectedFailure ? { todo: "required binding_failed" } : {};
            test(title, options, async (t) => {
              try {
                const prepared = await prepareRelabelCase(binding, carrier, definition.id);
                if (expectedFailure) {
                  await assertExactMovedKeyWitness(
                    prepared,
                    bindingLabel,
                    carrier.label,
                    (message) => t.diagnostic(message),
                  );
                  observedExpectedFailures.push(runId);
                }
                try {
                  await assertBindingRefusal(prepared, bindingLabel, carrier.label);
                } catch (error) {
                  if (expectedFailure) observedStrictFailures.push(runId);
                  throw error;
                }
              } finally {
                completed.push(runId);
              }
            });
          }
        });
      });
    }

    test(planLabel(), () => {
      const expectedRuns = CARRIERS.flatMap(({ id }) =>
        EXPECTED_CASE_IDS.map((caseId) => `${id}/${caseId}`),
      ).sort();
      const expectedFailureRuns = CARRIERS.flatMap(({ id }) =>
        expectedFailures.map((caseId) => `${id}/${caseId}`),
      ).sort();

      assert.deepEqual(
        [...registered].sort(),
        expectedRuns,
        "the complete case plan is registered",
      );
      assert.deepEqual([...completed].sort(), expectedRuns, "the complete case plan ran");
      assert.deepEqual(
        observedExpectedFailures.sort(),
        expectedFailureRuns,
        "every expected failure still has an exact moved-key witness before failing the shipped assertion",
      );
      assert.deepEqual(
        observedStrictFailures.sort(),
        expectedFailureRuns,
        "every expected failure still fails the shipped refusal assertion",
      );
    });
  });
}

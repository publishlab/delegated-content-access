// @ts-check
//
// The omission route through the real issuer processor: structural admission,
// then miss processing over the base engine composed with this extension's
// source. The engine-only tests beside this file skip admission, so these pin
// what admission lets reach the source and what the source spends on it.
//
// Two gaps stay open and untested here. The processor reads no `boundCandidates`
// member, so a request presenting only candidates has no coordinate at
// admission, and its candidates count toward no entry budget. Registering an
// extension's request members with the processor is a held design decision.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../../core-client/DcaData.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { base64urlDecode, base64urlEncode } from "../../../core-shared/codec.js";
import { ISSUER_A, PERIODS, PUB, contentOnlyPolicy, render, world } from "../test-lib/world.js";

/**
 * One active-issuer render and the request document an omission client sends
 * for it, with the period family relayed.
 *
 * @param {{ items?: string[] }} [options]
 */
async function activeRequest(options = {}) {
  const { issuerConfig, periodKeySupply, registration, sealerConfig } = await world();
  const items = options.items ?? ["bodytext"];
  const page = await render(
    new OmittingSealer(
      sealerConfig({ issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })] }),
    ),
    { items },
  );
  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    items,
  );
  return {
    document: JSON.parse(JSON.stringify(request.toObject())),
    registration,
    periodKeySupply,
  };
}

/**
 * Admission and miss processing as an issuer application runs them, from the
 * raw request bytes.
 *
 * @param {any} document
 * @param {any} registration
 * @param {{ engine?: any, processor?: object }} [options]
 */
async function processed(document, registration, options = {}) {
  const engine =
    options.engine ??
    omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      accessPolicy: contentOnlyPolicy(["bodytext"]),
    });
  const processor = new IssuerProcessor(engine, { periodKeyInput: true, ...options.processor });
  const admitted = processor.admit(JSON.stringify(document));
  if (admitted.kind !== "admitted") return admitted;
  return processor.processMiss({ request: admitted.request, registration });
}

/**
 * Counts the AES-128-GCM decrypts while `run` runs. Each trial unwrap of a
 * forwarded candidate is one such decrypt, so the count is the number of trials
 * the source started; sealed period blobs open under AES-256-GCM and are not
 * counted.
 *
 * @param {() => Promise<any>} run
 */
async function trialsDuring(run) {
  const subtle = globalThis.crypto.subtle;
  const decrypt = subtle.decrypt;
  let trials = 0;
  Object.defineProperty(subtle, "decrypt", {
    configurable: true,
    value: (/** @type {any[]} */ ...args) => {
      const [algorithm, key] = args;
      if (algorithm?.name === "AES-GCM" && key?.algorithm?.length === 128) trials++;
      return decrypt.apply(subtle, /** @type {any} */ (args));
    },
  });
  try {
    return { result: await run(), trials };
  } finally {
    delete (/** @type {any} */ (subtle).decrypt);
  }
}

/**
 * The same wrap with its authentication tag flipped: the right widths, and it
 * fails authentication under the right period key.
 *
 * @param {any} candidate
 */
function corrupted(candidate, flip = 1) {
  const key = base64urlDecode(candidate.key);
  key[key.length - 1] ^= flip;
  return { ...candidate, key: base64urlEncode(key) };
}

const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * The same bytes with a padding bit set in the last character: a 32-byte value
 * leaves two such bits, which the one admitted spelling keeps zero.
 *
 * @param {string} spelled
 */
function withSpareBit(spelled) {
  return spelled.slice(0, -1) + BASE64URL[BASE64URL.indexOf(spelled.at(-1) ?? "") | 1];
}

/**
 * The honest request's key for `bodytext`, the one every alternative below has
 * to reach.
 *
 * @param {any} document
 * @param {any} registration
 */
async function honestKey(document, registration) {
  const result = /** @type {any} */ (await processed(structuredClone(document), registration));
  return result.document.keys.contentKeys.bodytext;
}

test("relayed period keys reach the omission source through admission", async () => {
  const { document, registration } = await activeRequest();

  const result = /** @type {any} */ (await processed(document, registration));

  assert.equal(result.kind, "success");
  assert.deepEqual(Object.keys(result.document.keys.contentKeys), ["bodytext"]);
  assert.equal(Object.hasOwn(result.document.keys, "periodKeys"), false);
});

test("a candidate under a content name the format refuses is inert", async () => {
  const { document, registration } = await activeRequest();
  document.boundCandidates["not|a-name"] = document.boundCandidates.bodytext;

  const result = /** @type {any} */ (await processed(document, registration));

  assert.equal(result.kind, "success");
  assert.deepEqual(Object.keys(result.document.keys.contentKeys), ["bodytext"]);
  assert.equal(Object.hasOwn(result.document, "errors"), false);
});

test("a candidate that fails authentication leaves a later distinct one at its coordinate to open", async () => {
  const { document, registration } = await activeRequest();
  const expected = await honestKey(document, registration);
  const [atT0] = document.boundCandidates.bodytext;
  document.boundCandidates.bodytext = [corrupted(atT0), atT0];

  const { result, trials } = await trialsDuring(() => processed(document, registration));

  assert.equal(result.kind, "success");
  assert.equal(result.document.keys.contentKeys.bodytext, expected);
  assert.equal(Object.hasOwn(result.document, "errors"), false);
  assert.equal(trials, 2, "the corrupted wrap, then the valid one at the same coordinate");
});

test("an item whose candidates all fail authentication reports its own unseal failure", async () => {
  const { document, registration } = await activeRequest();
  const [atT0, atT1] = document.boundCandidates.bodytext;
  document.boundCandidates.bodytext = [corrupted(atT0, 1), corrupted(atT0, 2), corrupted(atT1)];

  const { result, trials } = await trialsDuring(() => processed(document, registration));

  assert.equal(result.kind, "success");
  assert.equal(Object.hasOwn(result.document.keys.contentKeys ?? {}, "bodytext"), false);
  assert.equal(result.document.errors.bodytext.error, "unseal_failed");
  assert.equal(trials, 3, "each distinct wrap once");
});

test("exact repeats of one wrap at one coordinate cost one trial", async () => {
  const { document, registration } = await activeRequest();
  const expected = await honestKey(document, registration);
  const [atT0, atT1] = document.boundCandidates.bodytext;
  assert.deepEqual(
    [atT0.t, atT1.t],
    PERIODS,
    "the honest client forwards one candidate per period",
  );
  const junkT0 = corrupted(atT0);
  const junkT1 = corrupted(atT1);
  document.boundCandidates.bodytext = [
    ...Array(100).fill(junkT0),
    ...Array(100).fill({ ...junkT0 }),
    ...Array(100).fill(junkT1),
    atT1,
    atT1,
  ];

  const { result, trials } = await trialsDuring(() => processed(document, registration));

  assert.equal(result.kind, "success");
  assert.equal(result.document.keys.contentKeys.bodytext, expected);
  assert.equal(trials, 3, "one trial per distinct wrap at each coordinate");
});

test("the same wrap material at another coordinate is a distinct alternative", async () => {
  const { document, registration } = await activeRequest();
  const expected = await honestKey(document, registration);
  const [atT0, atT1] = document.boundCandidates.bodytext;
  // atT1's own nonce and wrap, first labelled at T0, where it fails authentication.
  document.boundCandidates.bodytext = [{ ...atT1, t: atT0.t }, corrupted(atT0), atT1];

  const { result, trials } = await trialsDuring(() => processed(document, registration));

  assert.equal(result.kind, "success");
  assert.equal(result.document.keys.contentKeys.bodytext, expected);
  assert.equal(trials, 3);
});

test("a candidate whose wrap is not a canonical v1 nonce and wrapped key is never trial-decrypted", async () => {
  const { document, registration } = await activeRequest();
  const [atT0, atT1] = document.boundCandidates.bodytext;
  document.boundCandidates.bodytext = [
    { ...atT0, nonce: base64urlEncode(new Uint8Array(8)) },
    { ...atT0, key: base64urlEncode(new Uint8Array(48)) },
    { ...atT0, key: base64urlEncode(new Uint8Array(16)) },
    // The valid wrap's bytes under a spelling section 2.2 does not admit.
    { ...atT0, key: withSpareBit(atT0.key) },
    { ...atT0, nonce: `${atT0.nonce}==` },
    atT1,
  ];

  const { result, trials } = await trialsDuring(() => processed(document, registration));

  assert.equal(result.kind, "success");
  assert.deepEqual(Object.keys(result.document.keys.contentKeys), ["bodytext"]);
  assert.equal(trials, 1, "only the well-formed candidate at the second period");
});

test("a period-key view that throws a caller-facing code is an internal fault", async () => {
  const { document, registration } = await activeRequest();
  const periodKeyLookup = new WeakMap([
    [
      registration,
      async () => {
        throw Object.assign(new Error("period store refused"), { code: "denied" });
      },
    ],
  ]);
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"]),
    periodKeyLookup,
  });

  const result = await processed(document, registration, { engine });

  assert.deepEqual(result, { kind: "failure", code: "internal_error" });
});

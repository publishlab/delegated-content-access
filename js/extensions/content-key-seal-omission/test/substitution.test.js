// @ts-check
//
// The labels beside a forwarded candidate select which blob the issuer tries
// and nothing else. Every case below moves a candidate to a coordinate it was
// not wrapped at, and every one of them ends the same way: authentication
// fails, no content key comes back, and the failure is that item's own.

import test from "node:test";
import assert from "node:assert/strict";

import { base64urlDecode } from "../../../core-shared/codec.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { ISSUER_A, PERIODS, PUB, contentOnlyPolicy, render, world } from "../test-lib/world.js";

/**
 * Two renders out of one world, so a candidate can be carried from the second
 * into the first, plus the request and engine every case below drives.
 *
 * @param {{ items?: string[] }} [options]
 */
async function twoRenders(options = {}) {
  const items = options.items ?? ["bodytext"];
  const { issuerConfig, registration, sealerConfig } = await world();

  /** @param {string} resourceId @param {number} seed */
  const one = (resourceId, seed) =>
    render(
      new OmittingSealer(
        sealerConfig({
          seed,
          issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
        }),
      ),
      { resourceId, items },
    );

  const page = await one("123456", 1);
  const other = await one("123457", 2);

  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    items,
  );
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(items),
  });

  return { page, other, request, registration, engine, document: request.toObject() };
}

/**
 * The candidates a request document forwards for one content name.
 *
 * @param {any} document
 * @param {string} contentName
 * @returns {any[]}
 */
function candidatesOf(document, contentName) {
  return document.boundCandidates.filter(
    (/** @type {any} */ candidate) => candidate.contentName === contentName,
  );
}

/**
 * Swap the candidates one content name forwards for `replacement`, and leave
 * every other name's candidates as they were.
 *
 * @param {any} document
 * @param {string} contentName
 * @param {any[]} replacement
 */
function replaceCandidates(document, contentName, replacement) {
  document.boundCandidates = [
    ...document.boundCandidates.filter(
      (/** @type {any} */ candidate) => candidate.contentName !== contentName,
    ),
    ...replacement,
  ];
}

/**
 * The names an unlock result opened, once each: several records at one name
 * are rival candidates that opened the same item.
 *
 * @param {any} result
 */
const openedNames = (result) => [
  ...new Set(result.contentKeys.map((/** @type {any} */ record) => record.contentName)),
];

/**
 * The error an unlock result reports at one coordinate.
 *
 * @param {any} result
 * @param {string} coordinate
 */
const errorAt = (result, coordinate) =>
  result.errors.find((/** @type {any} */ record) => record.coordinate === coordinate)?.error;

/** @param {any} result */
const erroredCoordinates = (result) =>
  result.errors.map((/** @type {any} */ record) => record.coordinate);

test("the wrapper relays period keys only when its base selector is explicitly true", async () => {
  const { page } = await twoRenders();
  const data = new DcaData(page, { publisherOrigin: PUB });
  for (const [config, relaysPeriodKeys] of [
    [{}, false],
    [{ relayPeriodKeys: false }, false],
    [{ relayPeriodKeys: true }, true],
  ]) {
    const request = new OmissionRequestBuilder(config)
      .build(data, ISSUER_A, ["bodytext"])
      .toObject();
    assert.equal(
      Object.hasOwn(request.sealed, "periodKeys"),
      relaysPeriodKeys,
      JSON.stringify(config),
    );
  }
});

test("a candidate lifted out of another render opens nothing", async () => {
  const { other, request, registration, engine, document } = await twoRenders();
  const lifted = other.contentData.find(
    (/** @type {any} */ item) => item.contentName === "bodytext",
  );
  replaceCandidates(
    document,
    "bodytext",
    lifted.keys
      .filter((/** @type {any} */ entry) => entry.accessGroup === "premium")
      .map((/** @type {any} */ entry) => ({ contentName: "bodytext", ...entry })),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result, "bodytext"), "unseal_failed");
});

test("a candidate presented under another content name opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "note"],
  });
  replaceCandidates(
    document,
    "note",
    candidatesOf(document, "bodytext").map((candidate) => ({ ...candidate, contentName: "note" })),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(openedNames(result), ["bodytext"], "the item at its own coordinate still opens");
  assert.equal(errorAt(result, "note"), "unseal_failed");
});

test("a candidate relabelled to another access group the issuer can open still opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "sidebar"],
  });
  replaceCandidates(
    document,
    "bodytext",
    candidatesOf(document, "bodytext").map((candidate) => ({ ...candidate, accessGroup: "free" })),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(openedNames(result), ["sidebar"]);
  assert.equal(errorAt(result, "bodytext"), "unseal_failed");
});

test("a candidate relabelled to another period of its own group opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders();
  const [first, second] = candidatesOf(document, "bodytext");
  assert.notEqual(first.period, second.period, "the two candidates sit at two periods");
  replaceCandidates(document, "bodytext", [{ ...first, period: second.period }]);

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result, "bodytext"), "unseal_failed");
});

test("a candidate labelled with a period the issuer holds no material for opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders();
  replaceCandidates(
    document,
    "bodytext",
    candidatesOf(document, "bodytext").map((candidate) => ({
      ...candidate,
      period: "251023T2300",
    })),
  );
  assert.equal(PERIODS.includes("251023T2300"), false);

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result, "bodytext"), "unseal_failed");
});

test("a candidate carrying no binding marker is refused rather than tried unbound", async () => {
  const { request, registration, engine, document } = await twoRenders();
  replaceCandidates(
    document,
    "bodytext",
    candidatesOf(document, "bodytext").map((candidate) => {
      const { bind, ...rest } = candidate;
      void bind;
      return rest;
    }),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result, "bodytext"), "unseal_failed");
});

test("one malformed candidate reports its own failure beside a sibling that opened", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "note"],
  });
  replaceCandidates(
    document,
    "note",
    candidatesOf(document, "note").map((candidate) => ({ ...candidate, key: "not base64url ***" })),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(openedNames(result), ["bodytext"]);
  assert.deepEqual(erroredCoordinates(result), ["note"]);
  assert.equal(errorAt(result, "note"), "unseal_failed");
});

test("a candidate padded off the canonical spelling reports its own failure", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "note"],
  });
  // A 16-byte key need not happen to contain a `-` or `_`, so use its padded
  // base64 spelling: a lenient decoder recovers the same bytes, but v1 admits
  // only unpadded base64url on a forwarded candidate.
  replaceCandidates(
    document,
    "note",
    candidatesOf(document, "note").map((candidate) => {
      const key = `${candidate.key}==`;
      assert.notEqual(key, candidate.key, "the forwarded key is padded");
      assert.deepEqual(
        new Uint8Array(Buffer.from(key, "base64url")),
        base64urlDecode(candidate.key),
        "the lenient spelling is the same bytes",
      );
      return { ...candidate, key };
    }),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(openedNames(result), ["bodytext"], "the item forwarded canonically still opens");
  assert.deepEqual(erroredCoordinates(result), ["note"]);
  assert.equal(errorAt(result, "note"), "unseal_failed");
});

test("a candidate at a real coordinate the policy did not select opens nothing", async () => {
  const { issuerConfig, periodKeySupply, registration, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items: ["both"] },
  );

  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    ["both"],
  );
  // Only the free-group wraps go forward. They are the publisher's own, and
  // they authenticate: without the coordinate check the item opens through a
  // group the policy never selected.
  const document = request.toObject();
  replaceCandidates(
    document,
    "both",
    candidatesOf(document, "both").filter((candidate) => candidate.accessGroup === "free"),
  );

  const policy = contentOnlyPolicy(["both"], {
    sourceGrants: [{ accessGroup: "premium", periods: [...PERIODS] }],
  });

  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  periodKeyLookup.set(registration, (accessGroup, t) => periodKeySupply.derive(accessGroup, t));

  for (const engine of [
    omissionIssuerEngine({ operatingIssuerNames: [ISSUER_A], accessPolicy: policy }),
    omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      accessPolicy: policy,
      periodKeyLookup,
    }),
  ]) {
    const result = await engine.unlock(request, registration);
    assert.deepEqual(result.contentKeys, []);
    assert.equal(errorAt(result, "both"), "unseal_failed");
  }
});

test("a candidate at a period outside the granted prefix of its own group opens nothing", async () => {
  const { issuerConfig, registration, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
  );

  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    ["bodytext"],
  );
  const document = request.toObject();
  const [first, second] = candidatesOf(document, "bodytext");
  replaceCandidates(document, "bodytext", [second]);
  assert.equal(first.period < second.period, true, "the granted prefix is the earlier label");

  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"], {
      sourceGrants: [{ accessGroup: "premium", periods: [PERIODS[0]] }],
    }),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result, "bodytext"), "unseal_failed");
});

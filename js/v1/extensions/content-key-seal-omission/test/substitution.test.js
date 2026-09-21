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
import { ALL_PERIODS } from "../../../demo/support/AccessPolicy.js";
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

  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    items,
  );
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(items),
  });

  return { page, other, request, registration, engine, document: request.toObject() };
}

test("the wrapper relays exact material only when its base selector is explicitly true", async () => {
  const { page } = await twoRenders();
  const data = new DcaData(page, { publisherOrigin: PUB });
  for (const [config, relaysExact] of [
    [{}, false],
    [{ relayExactPeriod: false }, false],
    [{ relayExactPeriod: true }, true],
  ]) {
    const request = new OmissionRequestBuilder(config)
      .build(data, ISSUER_A, ["bodytext"])
      .toObject();
    assert.equal(Object.hasOwn(request.sealed, "periodKeys"), relaysExact, JSON.stringify(config));
  }
});

test("a candidate lifted out of another render opens nothing", async () => {
  const { other, request, registration, engine, document } = await twoRenders();
  document.boundCandidates.bodytext = other.contentData.bodytext.keys.premium.map(
    (/** @type {any} */ entry) => ({
      accessGroup: "premium",
      ...entry,
    }),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

test("a candidate presented under another content name opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "note"],
  });
  document.boundCandidates.note = document.boundCandidates.bodytext;

  const result = await engine.unlock(request, registration);

  assert.deepEqual(
    Object.keys(result.contentKeys),
    ["bodytext"],
    "the item at its own coordinate still opens",
  );
  assert.equal(result.errors.note.error, "unseal_failed");
});

test("a candidate relabelled to another access group the issuer can open still opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "sidebar"],
  });
  document.boundCandidates.bodytext = document.boundCandidates.bodytext.map(
    (/** @type {any} */ candidate) => ({
      ...candidate,
      accessGroup: "free",
    }),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(Object.keys(result.contentKeys), ["sidebar"]);
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

test("a candidate relabelled to another period of its own group opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders();
  const [first, second] = document.boundCandidates.bodytext;
  document.boundCandidates.bodytext = [{ ...first, t: second.t }];

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

test("a candidate labelled with a period the issuer holds no material for opens nothing", async () => {
  const { request, registration, engine, document } = await twoRenders();
  document.boundCandidates.bodytext = document.boundCandidates.bodytext.map(
    (/** @type {any} */ candidate) => ({
      ...candidate,
      t: "251023T23",
    }),
  );
  assert.equal(PERIODS.includes("251023T23"), false);

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

test("a candidate carrying no binding marker is refused rather than tried unbound", async () => {
  const { request, registration, engine, document } = await twoRenders();
  document.boundCandidates.bodytext = document.boundCandidates.bodytext.map(
    (/** @type {any} */ candidate) => {
      const { bind, ...rest } = candidate;
      void bind;
      return rest;
    },
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

test("one malformed candidate reports its own failure beside a sibling that opened", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "note"],
  });
  document.boundCandidates.note = document.boundCandidates.note.map(
    (/** @type {any} */ candidate) => ({
      ...candidate,
      key: "not base64url ***",
    }),
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(Object.keys(result.contentKeys), ["bodytext"]);
  assert.deepEqual(Object.keys(result.errors), ["note"]);
  assert.equal(result.errors.note.error, "unseal_failed");
});

test("a candidate padded off the canonical spelling reports its own failure", async () => {
  const { request, registration, engine, document } = await twoRenders({
    items: ["bodytext", "note"],
  });
  // A 16-byte key need not happen to contain a `-` or `_`, so use its padded
  // base64 spelling: a lenient decoder recovers the same bytes, but v1 admits
  // only unpadded base64url on a forwarded candidate.
  document.boundCandidates.note = document.boundCandidates.note.map(
    (/** @type {any} */ candidate) => {
      const key = `${candidate.key}==`;
      assert.notEqual(key, candidate.key, "the forwarded key is padded");
      assert.deepEqual(
        new Uint8Array(Buffer.from(key, "base64url")),
        base64urlDecode(candidate.key),
        "the lenient spelling is the same bytes",
      );
      return { ...candidate, key };
    },
  );

  const result = await engine.unlock(request, registration);

  assert.deepEqual(
    Object.keys(result.contentKeys),
    ["bodytext"],
    "the item forwarded canonically still opens",
  );
  assert.deepEqual(Object.keys(result.errors), ["note"]);
  assert.equal(result.errors.note.error, "unseal_failed");
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

  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    ["both"],
  );
  // Only the free-group wraps go forward. They are the publisher's own, and
  // they authenticate: without the coordinate check the item opens through a
  // group the policy never selected.
  const document = request.toObject();
  document.boundCandidates.both = document.boundCandidates.both.filter(
    (/** @type {any} */ candidate) => candidate.accessGroup === "free",
  );

  const policy = contentOnlyPolicy(["both"], {
    sourceGrants: [{ accessGroup: "premium", periodCount: ALL_PERIODS }],
  });

  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const exactPeriodLeaves = new WeakMap();
  exactPeriodLeaves.set(registration, (accessGroup, t) => periodKeySupply.derive(accessGroup, t));

  for (const engine of [
    omissionIssuerEngine({ accessPolicy: policy }),
    omissionIssuerEngine({ accessPolicy: policy, exactPeriodLeaves }),
  ]) {
    const result = await engine.unlock(request, registration);
    assert.deepEqual(result.contentKeys, {});
    assert.equal(result.errors.both.error, "unseal_failed");
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

  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    ["bodytext"],
  );
  const document = request.toObject();
  const [first, second] = document.boundCandidates.bodytext;
  document.boundCandidates.bodytext = [second];
  assert.equal(first.t < second.t, true, "the granted prefix is the earlier label");

  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"], {
      sourceGrants: [{ accessGroup: "premium", periodCount: 1 }],
    }),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

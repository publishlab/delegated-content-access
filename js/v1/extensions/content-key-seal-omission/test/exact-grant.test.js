// @ts-check
//
// The route itself: a publisher that sealed no contentKey for this issuer, and
// an issuer that still answers with exactly one exact contentKey, taken from
// period material it was already entrusted with.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../../core-client/DcaData.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { openContent } from "../../../core-client/openContent.js";
import { base64urlDecode, utf8Decode } from "../../../core-shared/codec.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import {
  ARTICLE,
  ISSUER_A,
  PERIODS,
  PUB,
  contentOnlyPolicy,
  render,
  world,
} from "../test-lib/world.js";

test("the omission issuer composition admits only the options it reads", () => {
  const accessPolicy = new AllowAllPolicy();
  assert.doesNotThrow(() =>
    omissionIssuerEngine({
      supportedVersions: ["1"],
      accessPolicy,
      developmentHttpOrigin: true,
      exactPeriodLeaves: new WeakMap(),
    }),
  );
  assert.throws(
    () => omissionIssuerEngine({ accessPolicy, clock: { now: () => new Date() } }),
    /** @param {any} error */ (error) =>
      error.code === "unsupported_option" &&
      error.message === "omissionIssuerEngine has no clock yet, and will not pretend to",
  );
});

/**
 * One active-issuer render, its client request and the pieces a test asserts
 * against.
 *
 * @param {{ items?: string[], granted?: string[] }} [options]
 */
async function activeRender(options = {}) {
  const { issuerConfig, periodKeySupply, registration, sealerConfig } = await world();
  const items = options.items ?? ["bodytext"];
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items },
  );

  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    items,
  );

  return { page, request, registration, periodKeySupply, granted: options.granted ?? items };
}

test("the request carries the support signal and one bound candidate per period", async () => {
  const { request } = await activeRender();
  const document = request.toObject();

  assert.deepEqual(document.extensions, [EXTENSION_NAME]);
  assert.deepEqual(
    document.boundCandidates.bodytext.map((/** @type {any} */ candidate) => [
      candidate.accessGroup,
      candidate.t,
    ]),
    PERIODS.map((t) => ["premium", t]),
  );
  assert.deepEqual(
    document.sealed.contentKeys,
    {},
    "an active issuer sealed no direct contentKey to forward",
  );
});

test("the issuer returns one exact contentKey and no source capability beside it", async () => {
  const { page, request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(Object.keys(result.contentKeys), ["bodytext"]);
  assert.deepEqual(result.periodKeys, {}, "the exact route returns no period capability");
  assert.equal(
    Object.hasOwn(result, "periodChainKeys"),
    false,
    "the exact route has no chain section",
  );
  assert.deepEqual(result.errors, {});

  const record = page.contentData.bodytext;
  const plaintext = await openContent(
    base64urlDecode(result.contentKeys.bodytext),
    "bodytext",
    record.nonce,
    page.sealedContent.bodytext,
    record.aad,
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("only the granted item comes back, from a request presenting two", async () => {
  const { request, registration } = await activeRender({ items: ["bodytext", "note"] });
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["note"]),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(Object.keys(result.contentKeys), ["note"]);
  assert.deepEqual(result.errors, {});
});

test("periodGrants supplies an omitted sourceGrants selection for an exact grant", async () => {
  const { page, request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    accessPolicy: {
      decide(claims, requested) {
        void claims;
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periodCount: 1 }],
        };
      },
    },
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(Object.keys(result.contentKeys), ["bodytext"]);
  assert.deepEqual(Object.keys(result.periodKeys.premium), [PERIODS[0]]);
  assert.deepEqual(result.errors, {});

  const record = page.contentData.bodytext;
  const plaintext = await openContent(
    base64urlDecode(result.contentKeys.bodytext),
    "bodytext",
    record.nonce,
    page.sealedContent.bodytext,
    record.aad,
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("a fallback prefix retains earlier presented labels when a later candidate is forwarded alone", async () => {
  const { request, registration } = await activeRender();
  const document = request.toObject();
  const [, later] = document.boundCandidates.bodytext;
  document.boundCandidates.bodytext = [later];

  const engine = omissionIssuerEngine({
    accessPolicy: {
      decide(claims, requested) {
        void claims;
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periodCount: 1 }],
        };
      },
    },
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

test("an explicit empty sourceGrants selection does not fall back to periodGrants", async () => {
  const { request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    accessPolicy: {
      decide(claims, requested) {
        void claims;
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periodCount: 1 }],
          sourceGrants: [],
        };
      },
    },
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "unseal_failed");
});

for (const [name, sourceGrants] of [
  ["a non-list", "premium"],
  ["a non-object grant", [null]],
  ["a grant without a string accessGroup", [{ periodCount: 1 }]],
  ["a negative periodCount", [{ accessGroup: "premium", periodCount: -1 }]],
  ["a fractional periodCount", [{ accessGroup: "premium", periodCount: 1.5 }]],
]) {
  test(`a policy returning ${name} sourceGrants is refused`, async () => {
    const { request, registration } = await activeRender();
    const engine = omissionIssuerEngine({
      accessPolicy: {
        decide(claims, requested) {
          void claims;
          return { contentNames: requested.contentNames, sourceGrants };
        },
      },
    });

    await assert.rejects(
      engine.unlock(request, registration),
      (/** @type {any} */ error) => error.code === "bad_policy",
    );
  });
}

test("an injected exact leaf source answers when the request forwards no sealed period material", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const document = request.toObject();
  delete document.sealed.periodKeys;

  const withoutLeaves = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
  });
  const bare = await withoutLeaves.unlock(request, registration);
  assert.deepEqual(bare.contentKeys, {}, "no period source is no key");
  assert.equal(bare.errors.bodytext.error, "unseal_failed");

  // The leaf view is held for this registration and takes the coordinate
  // alone. Which publisher's material it holds was settled when the
  // application put it here, under the registration object it constructed.
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const exactPeriodLeaves = new WeakMap();
  exactPeriodLeaves.set(registration, (accessGroup, t) => periodKeySupply.derive(accessGroup, t));

  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
    exactPeriodLeaves,
  });

  const result = await engine.unlock(request, registration);
  assert.deepEqual(Object.keys(result.contentKeys), ["bodytext"]);
});

test("a base issuer engine composed without this extension returns no key for an active render", async () => {
  const { request, registration } = await activeRender();
  const engine = new IssuerEngine({ accessPolicy: new AllowAllPolicy() });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(
    result.contentKeys,
    {},
    "the forwarded member is unknown to base and grants nothing",
  );
  assert.deepEqual(result.errors, {});
});

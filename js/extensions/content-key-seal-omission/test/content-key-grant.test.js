// @ts-check
//
// The route itself: a publisher that sealed no contentKey for this issuer, and
// an issuer that still answers with exactly one item contentKey, taken from
// period material it was already entrusted with.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { openContent } from "../../../core-client/openContent.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { base64urlDecode, utf8Decode } from "../../../core-shared/codec.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { candidatesFor } from "../core-issuer/omissionCandidates.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import {
  ARTICLE,
  NOTE,
  ISSUER_A,
  ISSUER_B,
  PERIODS,
  PUB,
  contentOnlyPolicy,
  render,
  world,
} from "../test-lib/world.js";

// The wire carries keys, errors and sealed content as arrays of named records.
// These helpers reach one record's value by its name, the way the old map
// lookups did.

/**
 * The key of the contentKeys record for `contentName`.
 *
 * @param {any[]} contentKeys
 * @param {string} contentName
 */
function contentKeyOf(contentKeys, contentName) {
  return contentKeys.find((record) => record.contentName === contentName)?.key;
}

/**
 * The error record for one coordinate.
 *
 * @param {any[]} errors
 * @param {string} coordinate
 */
function errorAt(errors, coordinate) {
  return errors.find((record) => record.coordinate === coordinate);
}

/**
 * The sealed content of one item on the page.
 *
 * @param {any} page
 * @param {string} contentName
 */
function sealedContentOf(page, contentName) {
  return page.sealedContent.find((/** @type {any} */ record) => record.contentName === contentName)
    ?.content;
}

/** @param {any[]} records */
const contentNames = (records) => records.map((record) => record.contentName);

test("the omission issuer composition admits only the options it reads", () => {
  const accessPolicy = new AllowAllPolicy();
  assert.doesNotThrow(() =>
    omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      supportedVersions: ["1"],
      accessPolicy,
      developmentHttpOrigin: true,
      periodKeyLookup: new WeakMap(),
    }),
  );
  assert.throws(
    () =>
      omissionIssuerEngine({
        operatingIssuerNames: [ISSUER_A],
        accessPolicy,
        clock: { now: () => new Date() },
      }),
    /** @param {any} error */ (error) =>
      error.code === "unsupported_option" &&
      error.message === "omissionIssuerEngine has no clock yet, and will not pretend to",
  );
  for (const periodKeyLookup of [{}, null])
    assert.throws(
      () =>
        omissionIssuerEngine({ operatingIssuerNames: [ISSUER_A], accessPolicy, periodKeyLookup }),
      { code: "bad_config" },
    );
});

test("the omission request builder admits only the options it reads", () => {
  assert.throws(() => new OmissionRequestBuilder({ chainCache: {} }), {
    code: "unsupported_option",
  });
  // The inner builder decides the base request, so a base option beside it would go unused.
  for (const baseOption of [{ clientPublicKey: {} }, { relayPeriodKeys: true }])
    assert.throws(
      () => new OmissionRequestBuilder({ innerBuilder: new DcaRequestBuilder(), ...baseOption }),
      { code: "bad_config" },
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

  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
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
  // Array position means nothing, so both sides are compared sorted.
  assert.deepEqual(
    document.boundCandidates
      .filter((/** @type {any} */ candidate) => candidate.contentName === "bodytext")
      .map((/** @type {any} */ candidate) => [candidate.accessGroup, candidate.period])
      .sort(),
    PERIODS.map((t) => ["premium", t]).sort(),
  );
  assert.deepEqual(
    document.sealed.contentKeys,
    [],
    "an active issuer sealed no contentKey to forward",
  );
});

test("an ordinary render's request forwards no bound candidates", async () => {
  const { sealerConfig } = await world();
  const page = await render(new OmittingSealer(sealerConfig()), { items: ["bodytext", "note"] });
  const document = new OmissionRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(page, { publisherOrigin: PUB }), ISSUER_A, ["bodytext", "note"])
    .toObject();

  assert.deepEqual(document.extensions, [EXTENSION_NAME]);
  assert.deepEqual(contentNames(document.sealed.contentKeys).sort(), ["bodytext", "note"]);
  assert.equal(
    Object.hasOwn(document, "boundCandidates"),
    false,
    "unbound entries are not candidates",
  );
});

test("the issuer returns one item contentKey and no period key beside it", async () => {
  const { page, request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"]),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(contentNames(result.contentKeys), ["bodytext"]);
  assert.deepEqual(result.periodKeys, [], "the content-key route returns no period key");
  assert.equal(
    Object.hasOwn(result, "chainKeys"),
    false,
    "the content-key route has no chainKeys section",
  );
  assert.deepEqual(result.errors, []);

  const plaintext = await openContent(
    base64urlDecode(contentKeyOf(result.contentKeys, "bodytext")),
    "bodytext",
    sealedContentOf(page, "bodytext"),
    contentAadOctets(page, "bodytext"),
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("only the granted item comes back, from a request presenting two", async () => {
  const { request, registration } = await activeRender({ items: ["bodytext", "note"] });
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["note"]),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(contentNames(result.contentKeys), ["note"]);
  assert.deepEqual(result.errors, []);
});

test("periodGrants supplies an omitted sourceGrants selection for a content-key grant", async () => {
  const { page, request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: {
      decide(claims, requested) {
        void claims;
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periods: [PERIODS[0]] }],
        };
      },
    },
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(contentNames(result.contentKeys), ["bodytext"]);
  assert.deepEqual(
    result.periodKeys
      .filter((/** @type {any} */ record) => record.accessGroup === "premium")
      .map((/** @type {any} */ record) => record.period),
    [PERIODS[0]],
  );
  assert.deepEqual(result.errors, []);

  const plaintext = await openContent(
    base64urlDecode(contentKeyOf(result.contentKeys, "bodytext")),
    "bodytext",
    sealedContentOf(page, "bodytext"),
    contentAadOctets(page, "bodytext"),
  );
  assert.equal(utf8Decode(plaintext), ARTICLE);
});

for (const member of ["sourceGrants", "periodGrants"]) {
  test(`${member} unions split grants before selecting an omitted item's candidate`, async () => {
    const { page, request, registration } = await activeRender();
    const document = request.toObject();
    // Keep only the bodytext candidate at the first period: the split grant
    // for that period alone must be enough.
    document.boundCandidates = document.boundCandidates.filter(
      (/** @type {any} */ candidate) =>
        candidate.contentName !== "bodytext" || candidate.period === PERIODS[0],
    );
    const engine = omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      accessPolicy: {
        decide: (_claims, requested) => ({
          contentNames: requested.contentNames,
          [member]: PERIODS.map((t) => ({ accessGroup: "premium", periods: [t] })),
        }),
      },
    });
    const result = await engine.unlock(request, registration);
    assert.deepEqual(result.errors, []);
    assert.equal(
      utf8Decode(
        await openContent(
          base64urlDecode(contentKeyOf(result.contentKeys, "bodytext")),
          "bodytext",
          sealedContentOf(page, "bodytext"),
          contentAadOctets(page, "bodytext"),
        ),
      ),
      ARTICLE,
    );
  });
}

test("empty ordinary grant selection leaves a sealed sibling usable beside an omitted-item miss", async () => {
  const { issuerConfig, sealerConfig, registration } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A), issuerConfig(ISSUER_B, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items: ["bodytext", "note"] },
  );
  const request = new OmissionRequestBuilder({ relayPeriodKeys: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    ["bodytext", "note"],
  );
  const document = request.toObject();
  document.sealed.contentKeys = document.sealed.contentKeys.filter(
    (/** @type {any} */ record) => record.contentName !== "bodytext",
  );
  document.boundCandidates = document.boundCandidates.filter(
    (/** @type {any} */ candidate) => candidate.contentName !== "note",
  );
  for (const selection of [{}, { periodGrants: [{ accessGroup: "premium", periods: [] }] }]) {
    const engine = omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      accessPolicy: {
        decide: (_claims, requested) => ({ contentNames: requested.contentNames, ...selection }),
      },
    });
    const result = await engine.unlock(request, registration);
    assert.deepEqual(contentNames(result.contentKeys), ["note"]);
    assert.equal(errorAt(result.errors, "bodytext")?.error, "unseal_failed");
    assert.equal(
      utf8Decode(
        await openContent(
          base64urlDecode(contentKeyOf(result.contentKeys, "note")),
          "note",
          sealedContentOf(page, "note"),
          contentAadOctets(page, "note"),
        ),
      ),
      NOTE,
    );
  }
});

test("ordinary-label fallback does not move permission to a later forwarded candidate", async () => {
  const { request, registration } = await activeRender();
  const document = request.toObject();
  // Forward only the bodytext candidate at the later period, which the
  // policy below does not grant.
  document.boundCandidates = document.boundCandidates.filter(
    (/** @type {any} */ candidate) =>
      candidate.contentName === "bodytext" && candidate.period === PERIODS[1],
  );

  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: {
      decide(claims, requested) {
        void claims;
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periods: [PERIODS[0]] }],
        };
      },
    },
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result.errors, "bodytext")?.error, "unseal_failed");
});

test("an explicit empty sourceGrants selection does not fall back to periodGrants", async () => {
  const { request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: {
      decide(claims, requested) {
        void claims;
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periods: [PERIODS[0]] }],
          sourceGrants: [],
        };
      },
    },
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(result.contentKeys, []);
  assert.equal(errorAt(result.errors, "bodytext")?.error, "unseal_failed");
});

test("a present malformed sourceGrants member does not fall back to ordinary grants", async () => {
  const { request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: {
      decide(_claims, requested) {
        return {
          contentNames: requested.contentNames,
          periodGrants: [{ accessGroup: "premium", periods: [PERIODS[0]] }],
          sourceGrants: null,
        };
      },
    },
  });

  await assert.rejects(
    engine.unlock(request, registration),
    (/** @type {any} */ error) => error.code === "bad_policy",
  );
});

test("independent chain authorization does not imply omission-source authority", async () => {
  const { request } = await activeRender();
  for (const futurePeriodCount of [0, 2]) {
    const candidates = candidatesFor({
      request,
      decision: {
        periodGrants: [{ accessGroup: "premium", futurePeriodCount, authorizePeriod: () => true }],
      },
      periodKeyFor: null,
    });
    assert.deepEqual(candidates.get("bodytext"), []);
  }
});

for (const [name, sourceGrants] of [
  ["a non-list", "premium"],
  ["a non-object grant", [null]],
  ["a grant without a string accessGroup", [{ periods: [PERIODS[0]] }]],
  ["a grant without periods", [{ accessGroup: "premium" }]],
  ["a retired count grant", [{ accessGroup: "premium", periodCount: 1 }]],
  ["a noncanonical label", [{ accessGroup: "premium", periods: ["not-a-period"] }]],
  [
    "a mixed count and label grant",
    [{ accessGroup: "premium", periodCount: 1, periods: [PERIODS[0]] }],
  ],
  [
    "a mixed future horizon and label grant",
    [{ accessGroup: "premium", futurePeriodCount: 0, periods: [PERIODS[0]] }],
  ],
  [
    "a mixed authorization callback and label grant",
    [{ accessGroup: "premium", authorizePeriod: () => true, periods: [PERIODS[0]] }],
  ],
]) {
  test(`a policy returning ${name} sourceGrants is refused`, async () => {
    const { request, registration } = await activeRender();
    const engine = omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
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

test("an injected period-key source answers when the request forwards no sealed period material", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const document = request.toObject();
  delete document.sealed.periodKeys;
  const withoutSealedPeriods = new DcaRequest(document);

  const withoutPeriodKeyLookup = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"]),
  });
  const bare = await withoutPeriodKeyLookup.unlock(withoutSealedPeriods, registration);
  assert.deepEqual(bare.contentKeys, [], "no period source is no key");
  assert.equal(errorAt(bare.errors, "bodytext")?.error, "unseal_failed");

  // The period-key view is held for this registration and takes the coordinate
  // alone. Which publisher's material it holds was settled when the
  // application put it here, under the registration object it constructed.
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const periodKeyLookup = new WeakMap();
  periodKeyLookup.set(registration, (accessGroup, t) => periodKeySupply.derive(accessGroup, t));

  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext"], {
      sourceGrants: [{ accessGroup: "premium", periods: [...PERIODS] }],
    }),
    periodKeyLookup,
  });

  const result = await engine.unlock(withoutSealedPeriods, registration);
  assert.deepEqual(contentNames(result.contentKeys), ["bodytext"]);
});

test("a base issuer engine composed without this extension returns no key for an active render", async () => {
  const { request, registration } = await activeRender();
  const engine = new IssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: new AllowAllPolicy(),
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(
    result.contentKeys,
    [],
    "the forwarded member is unknown to base and grants nothing",
  );
  assert.deepEqual(result.errors, []);
});

test("held-key omission exposes source labels separately and tries both rollover orders", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const document = structuredClone(request.toObject());
  delete document.sealed.periodKeys;
  for (const reverse of [false, true]) {
    const periodKeyLookup = new WeakMap([
      [
        registration,
        async (group, t) => {
          const right = await periodKeySupply.derive(group, t);
          const wrong = new Uint8Array(16);
          return reverse ? [right, wrong] : [wrong, right];
        },
      ],
    ]);
    const engine = omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      periodKeyLookup,
      accessPolicy: {
        decide(_claims, requested) {
          assert.deepEqual(requested.periodCoordinates, {});
          assert.deepEqual(requested.sourcePeriodCoordinates, { premium: PERIODS });
          return {
            contentNames: ["bodytext"],
            periodGrants: [
              { accessGroup: "premium", periods: requested.sourcePeriodCoordinates.premium },
            ],
            sourceGrants: [
              { accessGroup: "premium", periods: requested.sourcePeriodCoordinates.premium },
            ],
          };
        },
      },
    });
    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(contentNames(result.contentKeys), ["bodytext"]);
    assert.equal(result.periodKeys.length, 0);
  }
});

test("malformed and over-bound trusted held-key results fail as host faults", async () => {
  const { request, registration } = await activeRender();
  const document = structuredClone(request.toObject());
  delete document.sealed.periodKeys;
  for (const held of [
    undefined,
    {},
    [new Uint8Array(15)],
    Array.from({ length: 5 }, (_, i) => new Uint8Array(16).fill(i)),
  ]) {
    const periodKeyLookup = new WeakMap([[registration, async () => held]]);
    const engine = omissionIssuerEngine({
      operatingIssuerNames: [ISSUER_A],
      accessPolicy: contentOnlyPolicy(["bodytext"]),
      periodKeyLookup,
    });
    await assert.rejects(engine.unlock(new DcaRequest(document), registration), {
      code: "internal_error",
    });
  }
});

test("held rivals deduplicate and snapshot once per coordinate within each unlock", async () => {
  const { request, registration, periodKeySupply } = await activeRender({
    items: ["bodytext", "note"],
  });
  const document = structuredClone(request.toObject());
  delete document.sealed.periodKeys;
  let calls = 0;
  const periodKeyLookup = new WeakMap([
    [
      registration,
      async (group, t) => {
        calls++;
        const right = await periodKeySupply.derive(group, t);
        return [new Uint8Array(16), right, right, right, right];
      },
    ],
  ]);
  const engine = omissionIssuerEngine({
    operatingIssuerNames: [ISSUER_A],
    accessPolicy: contentOnlyPolicy(["bodytext", "note"]),
    periodKeyLookup,
  });
  for (let unlock = 1; unlock <= 2; unlock++) {
    const result = await engine.unlock(new DcaRequest(document), registration);
    assert.deepEqual(contentNames(result.contentKeys), ["bodytext", "note"]);
    assert.equal(calls, unlock, "one coordinate snapshot per unlock, shared by both items");
  }
});

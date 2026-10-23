// @ts-check
//
// The copyable issuer entry. `createIssuerCore` builds the issuer engine, the
// processor over it and the unlock endpoint over that, and hands all three
// back. The host keeps everything the entry cannot know: the publisher
// registration it selects from the verified key id, the reader it
// authenticated, the instant it captured, the observed Origin and the HTTP
// admission around it, and any response cache or transport.
//
// Pinned here: which configuration the entry takes, that each named member
// reaches its owning component, one serialized period-key request through
// both paths the entry exposes, and a clean copy of
// `copy-manifest--issuer.json` that answers on its own. The engine, processor
// and endpoint suites under `test-reference/core-issuer/` and
// `test-reference/integration-ports/` own every rule below this seam.

import { copyManifestFiles } from "../../tools/copyManifest.js";
import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createIssuerCore } from "../../integration-issuer/createIssuerCore.js";
import { createBrowserIssuer } from "../../integration-issuer/createBrowserIssuer.js";
import { admitBrowserRequest } from "../../integration-issuer/admitBrowserRequest.js";
import { createPublisher } from "../../integration-publisher/createPublisher.js";
import { IssuerEngine, checkEnvelopes } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { dcaError } from "../../core-shared/errors.js";
import { admitHeader } from "../../core-shared--publisher-issuer/jwt.js";
import { DcaData } from "../../core-client/DcaData.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { decrypt } from "../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../../core-shared/codec.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { cryptoMeter } from "../../test-lib/fixtures/endpoint-hardening-world.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { wrapNonceOf } from "../support/contentKeyWrapNonceOctets.js";
import { contentKeyMap, keyAt, notDeliveredMap, periodKeyMap } from "../support/namedRecords.js";
import { wrapsOf } from "../../test-lib/helpers/inspect.js";

const V1 = new URL("../../", import.meta.url);

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const ORIGIN = "https://www.news-site.example";
const AT = "2025-10-23T14:20:00Z";
const CONTENT_NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GROUP = "premium";

// An hourly, two-slot render at AT wraps under these two labels
// (docs/spec-profile--period-keys.md, 5.5); the first sorts first.
const T_NOW = "251023T1400";
const T_NEXT = "251023T1500";

/** The period keys the publisher's supply holds. */
const PERIOD_KEYS = Object.freeze({
  [T_NOW]: Uint8Array.from({ length: 16 }, (_, i) => 0x40 + i),
  [T_NEXT]: Uint8Array.from({ length: 16 }, (_, i) => 0x60 + i),
});

/** A policy that grants the first requested labels, up to its configured limit. */
function prefixPolicy(limit = 1) {
  const decisions = /** @type {any[]} */ ([]);
  return {
    decisions,
    /** @param {any} claims @param {any} requested @param {any} input */
    decide(claims, requested, input) {
      decisions.push({ claims, requested, input });
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          periods: (requested.periodCoordinates[accessGroup] ?? []).slice(0, limit),
        })),
      };
    },
  };
}

const denyAll = { decide: () => ({ contentNames: [], periodGrants: [] }) };

/** @param {any} config */
function configuredIssuerCore(config) {
  return createIssuerCore({ operatingIssuerNames: [ISSUER_NAME], ...config });
}

/**
 * One period-key render, the registration an issuer host holds for its
 * publisher, and the serialized request a client relays for the item.
 *
 * @param {{ origin?: string, developmentHttpOrigin?: boolean, includeContentKeys?: boolean }} [publisher]
 */
async function world({
  origin = ORIGIN,
  developmentHttpOrigin = false,
  includeContentKeys = false,
} = {}) {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();
  const render = await createPublisher({
    origin,
    developmentHttpOrigin,
    clock: { now: () => new Date(AT) },
    random: { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) },
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
    issuerSupplyPlanFor: (_issuer, { accessGroups }) => ({
      contentKeyNames: includeContentKeys ? [CONTENT_NAME] : [],
      suppliedAccessGroups: [...accessGroups],
    }),
    periodKeySupply: {
      derive: async (_accessGroup, t) =>
        Uint8Array.from(PERIOD_KEYS[/** @type {keyof PERIOD_KEYS} */ (t)]),
    },
    period: { length: 60, slots: 2 },
  }).publish({
    resourceId: "123456",
    data: { section: "politics" },
    items: [
      { name: CONTENT_NAME, value: ARTICLE, contentType: "text/html", accessGroups: [GROUP] },
    ],
  });

  // The page crosses the wire as JSON, and the client relays what it carries.
  const dcaData = JSON.parse(JSON.stringify(render.dcaData));
  const request = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(dcaData, { publisherOrigin: origin }), ISSUER_NAME, [CONTENT_NAME])
    .toObject();

  // The issuer host's own record of this publisher. It is issuer-held
  // configuration, never read from the request.
  const registration = {
    kid: SIGNING_KID,
    publicKey: signingKeys.publicKey,
    openingKeys: {
      /** @param {string} issuerName @param {string} keyId */
      get(issuerName, keyId) {
        if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
        return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
      },
    },
  };

  return {
    dcaData,
    sealedContent: render.sealedContent,
    document: JSON.stringify(request),
    registration,
  };
}

/**
 * The article, opened with a returned period key: unwrap the item's content key
 * from its wrap at that label, then decrypt the item.
 *
 * @param {any} dcaData
 * @param {Record<string, string>} sealedContent
 * @param {string} t
 * @param {string} key - base64url, as the issuer returned it
 */
async function openWith(dcaData, sealedContent, t, key) {
  const wrap = wrapsOf(dcaData, CONTENT_NAME, GROUP).find(
    (/** @type {any} */ entry) => entry.period === t,
  );
  const contentKey = await decrypt(
    base64urlDecode(key),
    wrapNonceOf(dcaData, CONTENT_NAME, GROUP, t),
    base64urlDecode(wrap.key),
  );
  const plaintext = await decrypt(
    contentKey,
    new Uint8Array(12),
    base64urlDecode(sealedContent[CONTENT_NAME]),
    contentAadOctets(dcaData, CONTENT_NAME),
  );
  return utf8Decode(plaintext);
}

describe("What createIssuerCore takes", () => {
  test("a missing configuration or access policy is refused", async () => {
    await refuses(() => createIssuerCore(), "bad_config", "no configuration at all");
    await refuses(
      () => createIssuerCore(/** @type {any} */ ([])),
      "bad_config",
      "an array in place of the configuration",
    );
    await refuses(
      () => createIssuerCore(/** @type {any} */ ({ accessPolicy: denyAll })),
      "bad_config",
      "operating issuer names are required",
    );
    await refuses(
      () => createIssuerCore(/** @type {any} */ ({ operatingIssuerNames: [ISSUER_NAME] })),
      "bad_config",
      "the endpoint also needs an access policy",
    );
  });

  test("a malformed member is refused by the component that owns it", async () => {
    const accessPolicy = denyAll;
    const cases = [
      ["periodKeyInput is boolean", { periodKeyInput: "yes" }, "bad_config"],
      ["a limit is a positive number", { limits: { maxEntries: 0 } }, "bad_config"],
      ["a limit the processor has not got", { limits: { maxDepth: 3 } }, "unsupported_option"],
      ["errorDetail is code or uniform", { errorDetail: "verbose" }, "unsupported_option"],
      ["notDeliveredReport is one of three", { notDeliveredReport: "all" }, "bad_config"],
      ["the development profile is on or off", { developmentHttpOrigin: "on" }, "bad_config"],
    ];
    for (const [why, member, code] of cases) {
      await refuses(
        () =>
          createIssuerCore(
            /** @type {any} */ ({
              operatingIssuerNames: [ISSUER_NAME],
              accessPolicy,
              ...member,
            }),
          ),
        /** @type {string} */ (code),
        /** @type {string} */ (why),
      );
    }
  });

  test("a member this entry does not take is refused by name", async () => {
    // Trusted request facts such as a registration or principal arrive per
    // request, never in the entry's construction record.
    for (const name of ["engineOptions", "registrations", "principal", "origin"]) {
      await refuses(
        () =>
          createIssuerCore(
            /** @type {any} */ ({
              operatingIssuerNames: [ISSUER_NAME],
              accessPolicy: denyAll,
              [name]: {},
            }),
          ),
        { code: "unsupported_option", message: new RegExp(name) },
        `createIssuerCore names ${name} when it refuses it`,
      );
    }
  });

  test("the entry hands back its three components and the declared response sections", () => {
    const core = configuredIssuerCore({ accessPolicy: denyAll });
    assert.ok(core.engine instanceof IssuerEngine);
    assert.ok(core.processor instanceof IssuerProcessor);
    assert.ok(core.endpoint instanceof UnlockEndpoint);
    assert.deepEqual(Object.keys(core).sort(), [
      "endpoint",
      "engine",
      "processor",
      "responseSections",
    ]);
    assert.deepEqual(core.responseSections, [], "no contribution declares a section");
  });

  test("an injected engine's declared extensions join the contributions' unless the host lists them", async () => {
    // The engine routes chain keys, whose built-in coordinate admission counts
    // only while chain-keys is selected; the contribution brings its own reading.
    const engine = {
      selectedExtensions: ["chain-keys"],
      checkOperatingIssuerName(/** @type {any} */ request) {
        if (request.issuerName !== ISSUER_NAME) throw dcaError("out_of_scope_issuer", "not served");
      },
      async unlock() {
        throw new Error("admission never unlocks");
      },
    };
    const widget = {
      name: "widget",
      extensionCoordinate: (/** @type {any} */ request) =>
        Object.hasOwn(request.toObject(), "widget"),
    };
    /** @param {Record<string, unknown>} extra */
    const document = (extra) =>
      JSON.stringify({
        version: "1",
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        sealed: { contentKeys: [] },
        ...extra,
      });
    const chainOnly = document({
      sealed: { contentKeys: [], chainKeys: [{ accessGroup: GROUP, cutoff: T_NOW, key: "AAAA" }] },
    });
    const widgetOnly = document({ widget: {} });

    // Omitted, or written as undefined: the engine's declaration and the
    // contribution's name both count. Explicit and naming the engine's
    // extension: the contribution appends.
    for (const config of [
      { engine },
      { engine, selectedExtensions: undefined },
      { engine, selectedExtensions: ["chain-keys"] },
    ]) {
      const core = createIssuerCore(/** @type {any} */ (config), widget);
      const label = JSON.stringify(Object.keys(config));
      assert.equal(core.processor.admit(widgetOnly).kind, "admitted", `widget ${label}`);
      assert.equal(core.processor.admit(chainOnly).kind, "admitted", `chain keys ${label}`);
      assert.deepEqual(core.processor.admit(document({})), {
        kind: "failure",
        code: "binding_failed",
      });
    }

    for (const [why, config, contributions] of [
      [
        "an explicit list omits the engine's extension",
        { engine, selectedExtensions: [] },
        [widget],
      ],
      [
        "the host and a contribution both select widget",
        { engine, selectedExtensions: ["chain-keys", "widget"] },
        [widget],
      ],
      [
        "a contribution selects the engine's extension again",
        { engine },
        [{ ...widget, name: "chain-keys" }],
      ],
      ["two contributions select widget", { engine }, [widget, widget]],
    ]) {
      await refuses(
        () =>
          createIssuerCore(/** @type {any} */ (config), .../** @type {any[]} */ (contributions)),
        "bad_config",
        /** @type {string} */ (why),
      );
    }
  });
});

describe("Contribution admission without ordinary key coordinates", () => {
  const document = JSON.stringify({
    version: "1",
    issuerName: ISSUER_NAME,
    keyId: KEY_ID,
    sealed: { contentKeys: [] },
    widget: {},
  });

  test("the source predicate retains its receiver and original function", () => {
    class PrivateSource {
      #calls = 0;
      name = "widget";
      members = ["widget"];

      presented(request) {
        this.#calls++;
        return Object.hasOwn(request.toObject(), "widget");
      }

      async respond() {
        return {};
      }

      get calls() {
        return this.#calls;
      }
    }
    const source = new PrivateSource();
    const core = createIssuerCore(
      { operatingIssuerNames: [ISSUER_NAME], accessPolicy: denyAll },
      {
        name: "widget",
        responseSections: [{ path: ["widget"], fields: ["contentName"], keyKind: "contentKey" }],
        responseSectionSource: source,
      },
    );
    source.presented = () => {
      throw new Error("the caller replaced the admission method after construction");
    };
    assert.equal(core.processor.admit(document).kind, "admitted");
    assert.equal(source.calls, 1);
  });

  for (const allow of [false, true]) {
    test(`an explicit admission override ${allow ? "admits" : "refuses"} instead of the source predicate`, () => {
      const core = createIssuerCore(
        { operatingIssuerNames: [ISSUER_NAME], accessPolicy: denyAll },
        {
          name: "widget",
          responseSections: [{ path: ["widget"], fields: ["contentName"], keyKind: "contentKey" }],
          extensionCoordinate: () => allow,
          responseSectionSource: {
            name: "widget",
            members: ["widget"],
            presented: () => !allow,
            respond: async () => ({}),
          },
        },
      );
      assert.equal(core.processor.admit(document).kind, allow ? "admitted" : "failure");
    });
  }

  test("a contribution without a response source does not invent an admission coordinate", () => {
    const core = createIssuerCore(
      { operatingIssuerNames: [ISSUER_NAME], accessPolicy: denyAll },
      { name: "widget" },
    );
    assert.deepEqual(core.processor.admit(document), { kind: "failure", code: "binding_failed" });
  });
});

describe("Each named member reaches its owning component", () => {
  test("operating issuer names are an explicit endpoint scope checked during admission", () => {
    const policy = {
      calls: 0,
      decide() {
        this.calls++;
        return denyAll.decide();
      },
    };
    const oneName = configuredIssuerCore({ accessPolicy: policy });
    const outside = oneName.processor.admit(
      JSON.stringify({
        version: "1",
        issuerName: "another_issuer_service",
        keyId: KEY_ID,
        sealed: { contentKeys: [{ contentName: CONTENT_NAME, key: "opaque" }] },
      }),
    );
    assert.deepEqual(outside, { kind: "failure", code: "out_of_scope_issuer" });
    assert.equal(policy.calls, 0, "an out-of-scope name is refused before policy");

    const shared = createIssuerCore({
      operatingIssuerNames: [ISSUER_NAME, "another_issuer_service"],
      accessPolicy: denyAll,
    });
    const explicitlyShared = shared.processor.admit(
      JSON.stringify({
        version: "1",
        issuerName: "another_issuer_service",
        keyId: KEY_ID,
        sealed: { contentKeys: [{ contentName: CONTENT_NAME, key: "opaque" }] },
      }),
    );
    assert.equal(explicitlyShared.kind, "admitted", "shared authority is an explicit host choice");
  });

  test("periodKeyInput is the processor's choice, off unless the host selects it", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();

    const off = await configuredIssuerCore({ accessPolicy: policy }).endpoint.handleDocument(
      document,
      registration,
    );
    assert.equal(off.response.status, 400, "relayed period-key material activates no issuer input");
    assert.equal(policy.decisions.length, 0);

    const on = await configuredIssuerCore({
      accessPolicy: policy,
      periodKeyInput: true,
    }).endpoint.handleDocument(document, registration);
    assert.equal(on.response.status, 200);
  });

  test("limits reach the processor and errorDetail reaches the endpoint", async () => {
    const { document, registration } = await world();
    const capped = await configuredIssuerCore({
      accessPolicy: denyAll,
      periodKeyInput: true,
      limits: { maxBodyBytes: 64 },
    }).endpoint.handleDocument(document, registration);
    assert.equal(capped.response.status, 413);
    assert.deepEqual(capped.response.body, { error: "body_too_large" });

    const uniform = await configuredIssuerCore({
      accessPolicy: denyAll,
      periodKeyInput: true,
      errorDetail: "uniform",
    }).endpoint.handleDocument(document, registration);
    assert.equal(uniform.response.status, 401);
    assert.deepEqual(uniform.response.body, { error: "rejected" });
    assert.equal(uniform.code, "denied");
  });

  test("notDeliveredReport reaches the engine", async () => {
    const { document, registration } = await world();
    const complete = await configuredIssuerCore({
      accessPolicy: denyAll,
      periodKeyInput: true,
      notDeliveredReport: "complete",
    }).endpoint.handleDocument(document, registration);
    assert.equal(complete.response.status, 200);
    assert.deepEqual(notDeliveredMap(complete.response.body.notDelivered), {
      [GROUP]: { reason: "denied" },
    });
    assert.equal(Object.hasOwn(complete.response.body.keys, "periodKeys"), false);
  });

  test("the development profile reaches the engine's check of the signed origin", async () => {
    const { document, registration } = await world({
      origin: "http://localhost:8080",
      developmentHttpOrigin: true,
    });
    const production = await configuredIssuerCore({
      accessPolicy: prefixPolicy(),
      periodKeyInput: true,
    }).endpoint.handleDocument(document, registration);
    assert.equal(production.response.status, 400);

    const development = await configuredIssuerCore({
      accessPolicy: prefixPolicy(),
      periodKeyInput: true,
      developmentHttpOrigin: true,
    }).endpoint.handleDocument(document, registration);
    assert.equal(development.response.status, 200);
  });

  test("the host's principal and context reach the policy beside the verified origin", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    const principal = { reader: "r-17" };
    await configuredIssuerCore({
      accessPolicy: policy,
      periodKeyInput: true,
    }).endpoint.handleDocument(
      document,
      registration,
      { principal, context: { plan: "monthly" } },
      Date.parse(AT),
    );
    assert.equal(policy.decisions.length, 1);
    const [{ requested, input }] = policy.decisions;
    assert.deepEqual(requested, {
      contentNames: [],
      accessGroups: [GROUP],
      periodCoordinates: { [GROUP]: [T_NOW, T_NEXT] },
    });
    assert.equal(input.principal, principal);
    assert.deepEqual(input.context, { plan: "monthly" });
    assert.deepEqual(input.publisher, { origin: ORIGIN });
  });
});

describe("One serialized period-key request through the entry", () => {
  test("handleDocument returns the policy's period-key grant, and that key opens the item", async () => {
    const { dcaData, sealedContent, document, registration } = await world();
    const policy = prefixPolicy(1);
    const { endpoint } = configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true });

    const { response, code } = await endpoint.handleDocument(document, registration, {
      principal: { reader: "r-17" },
    });
    assert.equal(response.status, 200);
    assert.equal(code, undefined);

    // The policy granted a prefix of one: the first label and nothing past it.
    assert.deepEqual(response.body.keys.contentKeys, []);
    const periodKeys = periodKeyMap(response.body.keys.periodKeys);
    assert.deepEqual(Object.keys(periodKeys), [GROUP]);
    assert.deepEqual(Object.keys(periodKeys[GROUP]), [T_NOW]);

    // The issuer opened the publisher's own period key for that label.
    const returned = periodKeys[GROUP][T_NOW];
    assert.equal(returned, base64urlEncode(PERIOD_KEYS[T_NOW]));
    assert.equal(await openWith(dcaData, sealedContent, T_NOW, returned), ARTICLE);
    assert.equal(JSON.stringify(response.body).includes("periodGeometry"), false);
  });

  test("the same request under a policy that grants nothing returns no key", async () => {
    const { document, registration } = await world();
    const { endpoint } = configuredIssuerCore({ accessPolicy: denyAll, periodKeyInput: true });
    const { response, code } = await endpoint.handleDocument(document, registration);
    assert.equal(response.status, 401);
    assert.deepEqual(response.body, { error: "denied" });
    assert.equal(code, "denied");
  });

  test("processor admit and endpoint miss answer as handleDocument does", async () => {
    const { document, registration } = await world();
    const { processor, endpoint } = configuredIssuerCore({
      accessPolicy: prefixPolicy(2),
      periodKeyInput: true,
    });

    // The host's order: admit, select the registration from the header hint,
    // verify and compare the signed origin with the one it observed, look up
    // its own cache, and only on a miss hand the admitted request on.
    const admission = processor.admit(document);
    assert.equal(admission.kind, "admitted");
    if (admission.kind !== "admitted") return;
    assert.equal(admitHeader(admission.request.resourceJWT), registration.kid);
    const claims = await checkEnvelopes(admission.request, registration.publicKey, false);
    assert.equal(claims.resource.origin, ORIGIN, "the host compares this with the observed Origin");

    const miss = await endpoint.handleRequest({
      request: admission.request,
      registration,
      policyInput: { principal: { reader: "r-17" } },
      capturedAtMs: Date.parse(AT),
    });
    assert.equal(miss.response.status, 200);
    const missKeys = periodKeyMap(miss.response.body.keys.periodKeys);
    assert.deepEqual(Object.keys(missKeys[GROUP]), [T_NOW, T_NEXT]);
    assert.equal(missKeys[GROUP][T_NEXT], base64urlEncode(PERIOD_KEYS[T_NEXT]));

    const refused = processor.admit("{");
    assert.equal(refused.kind, "failure");
    if (refused.kind !== "failure") return;
    const mapped = endpoint.refusal(refused);
    assert.equal(mapped.response.status, 400);
    assert.deepEqual(mapped.response.body, { error: "invalid_json" });
  });
});

describe("A registration the host built wrong is an issuer fault, not the request's", () => {
  // These keys are the JavaScript reference's WebCrypto shape. Another
  // language checks its own key type; the status split is the portable part.
  test("a verification key of the wrong kind or an opening store without get answers 5xx", async () => {
    const { document, registration } = await world();
    const raw = await globalThis.crypto.subtle.exportKey("raw", registration.publicKey);
    const subtle = globalThis.crypto.subtle;
    const wrong = {
      "an ECDH key": await subtle.importKey(
        "raw",
        raw,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        [],
      ),
      "a JWK object": await subtle.exportKey("jwk", registration.publicKey),
      "an ECDSA key without verify usage": await subtle.importKey(
        "raw",
        raw,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        [],
      ),
      "a P-384 ECDSA key": /** @type {CryptoKeyPair} */ (
        await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, false, ["sign", "verify"])
      ).publicKey,
    };
    for (const [why, publicKey] of Object.entries(wrong)) {
      const { processor, endpoint } = configuredIssuerCore({
        accessPolicy: prefixPolicy(1),
        periodKeyInput: true,
      });
      const answer = await endpoint.handleDocument(document, { ...registration, publicKey }, {});
      assert.equal(answer.response.status, 500, why);
      assert.equal(answer.code, "internal_error", why);
      const admission = processor.admit(document);
      assert.equal(admission.kind, "admitted");
      if (admission.kind !== "admitted") return;
      await assert.rejects(
        checkEnvelopes(admission.request, /** @type {any} */ (publicKey)),
        { code: "bad_config" },
        why,
      );
    }

    const { endpoint } = configuredIssuerCore({
      accessPolicy: prefixPolicy(1),
      periodKeyInput: true,
    });
    const storeless = await endpoint.handleDocument(
      document,
      { ...registration, openingKeys: {} },
      {},
    );
    assert.equal(storeless.response.status, 500);
    assert.equal(storeless.code, "internal_error");
  });

  test("a right-kind key that did not sign the token is still the request's bad_signature", async () => {
    const { document, registration } = await world();
    const stranger = await signingKeypair();
    const { endpoint } = configuredIssuerCore({
      accessPolicy: prefixPolicy(1),
      periodKeyInput: true,
    });
    const answer = await endpoint.handleDocument(
      document,
      { ...registration, publicKey: stranger.publicKey },
      {},
    );
    assert.equal(answer.response.status, 400);
    assert.equal(answer.code, "bad_signature");
    // A missing registration stays a request refusal too.
    const missing = await endpoint.handleDocument(document, /** @type {any} */ (undefined), {});
    assert.equal(missing.response.status, 400);
    assert.equal(missing.code, "unknown_publisher_key");
  });
});

describe("A host collaborator's fault stays an issuer fault", () => {
  // Node system and driver errors carry string codes such as ECONNREFUSED; a
  // collaborator could as well throw one spelled like a DCA refusal. Neither is
  // the request's refusal.
  const fault = (/** @type {string} */ code) =>
    Object.assign(new Error(`store failed: ${code}`), { code });

  test("a registration lookup or caller admission that throws answers 500 internal_error", async () => {
    const { document, registration } = await world();
    const core = configuredIssuerCore({ accessPolicy: prefixPolicy(1), periodKeyInput: true });
    for (const code of ["ECONNREFUSED", "denied", "unknown_publisher_key"]) {
      const lookup = await admitBrowserRequest({
        processor: core.processor,
        endpoint: core.endpoint,
        document,
        origin: ORIGIN,
        registrationForKid: () => {
          throw fault(code);
        },
      });
      assert.deepEqual(
        {
          kind: lookup.kind,
          status: /** @type {any} */ (lookup).status,
          code: /** @type {any} */ (lookup).code,
        },
        { kind: "refused", status: 500, code: "internal_error" },
        code,
      );
      const caller = await admitBrowserRequest({
        processor: core.processor,
        endpoint: core.endpoint,
        document,
        origin: ORIGIN,
        registrationForKid: () => registration,
        beforeVerify: () => {
          throw fault(code);
        },
      });
      assert.deepEqual(
        {
          kind: caller.kind,
          status: /** @type {any} */ (caller).status,
          code: /** @type {any} */ (caller).code,
        },
        { kind: "refused", status: 500, code: "internal_error" },
        code,
      );
    }
    // A registration built with a wrong-kind key fails at verification as a
    // host fault too, while a key that did not sign stays the request's 400.
    const ecdh = await globalThis.crypto.subtle.importKey(
      "raw",
      await globalThis.crypto.subtle.exportKey("raw", registration.publicKey),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      [],
    );
    const misbuilt = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => ({ ...registration, publicKey: ecdh }),
    });
    assert.equal(/** @type {any} */ (misbuilt).status, 500);
    assert.equal(/** @type {any} */ (misbuilt).code, "internal_error");
    const stranger = await signingKeypair();
    const unsigned = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => ({ ...registration, publicKey: stranger.publicKey }),
    });
    assert.equal(/** @type {any} */ (unsigned).status, 400);
    assert.equal(/** @type {any} */ (unsigned).code, "bad_signature");
    // A token the registered key signed without a renderId is the request's
    // binding_failed, not an issuer fault.
    const publisherKeys = await signingKeypair();
    const signed = JSON.parse(document);
    const [header, body] = signed.resourceJWT.split(".");
    const claims = { ...JSON.parse(utf8Decode(base64urlDecode(body))), renderId: "" };
    const input = `${header}.${base64urlEncode(new TextEncoder().encode(JSON.stringify(claims)))}`;
    const signature = await globalThis.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      publisherKeys.privateKey,
      new TextEncoder().encode(input),
    );
    signed.resourceJWT = `${input}.${base64urlEncode(new Uint8Array(signature))}`;
    const unbound = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document: JSON.stringify(signed),
      origin: ORIGIN,
      registrationForKid: () => ({ ...registration, publicKey: publisherKeys.publicKey }),
    });
    assert.equal(/** @type {any} */ (unbound).status, 400);
    assert.equal(/** @type {any} */ (unbound).code, "binding_failed");
  });

  test("a caller admission result that is neither admitted nor refused answers 500 before policy", async () => {
    const { document, registration } = await world();
    for (const result of [{ kind: "maybe", principal: { id: "reader" } }, undefined]) {
      const core = configuredIssuerCore({ accessPolicy: prefixPolicy(1), periodKeyInput: true });
      const gate = await admitBrowserRequest({
        processor: core.processor,
        endpoint: core.endpoint,
        document,
        origin: ORIGIN,
        registrationForKid: () => registration,
        beforeVerify: () => /** @type {any} */ (result),
      });
      assert.deepEqual(
        {
          kind: gate.kind,
          status: /** @type {any} */ (gate).status,
          code: /** @type {any} */ (gate).code,
        },
        { kind: "refused", status: 500, code: "internal_error" },
        String(result?.kind),
      );
      const policy = prefixPolicy();
      const browser = createBrowserIssuer({
        core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
        registrationForKid: () => registration,
        preflight: () => false,
        admitCaller: () => /** @type {any} */ (result),
        clock: { now: () => new Date(AT) },
      });
      const response = await browser.handle({
        method: "POST",
        contentType: "application/json",
        origin: ORIGIN,
        body: document,
      });
      assert.equal(response.status, 500, String(result?.kind));
      assert.deepEqual(response.body, { error: "internal_error" });
      assert.equal(policy.decisions.length, 0);
    }
  });

  test("an opening-key store that throws a coded error answers 500 internal_error", async () => {
    const { document, registration } = await world();
    for (const code of ["ECONNREFUSED", "denied", "unknown_key"]) {
      const { endpoint } = configuredIssuerCore({
        accessPolicy: prefixPolicy(1),
        periodKeyInput: true,
      });
      const answer = await endpoint.handleDocument(
        document,
        {
          ...registration,
          openingKeys: {
            get() {
              throw fault(code);
            },
          },
        },
        {},
      );
      assert.deepEqual(
        { status: answer.response.status, body: answer.response.body, code: answer.code },
        { status: 500, body: { error: "internal_error" }, code: "internal_error" },
        code,
      );
    }
  });
});

describe("Browser issuer composition", () => {
  test("uniform admission hides browser refusal codes without granting early CORS", async () => {
    const { document } = await world();
    const browser = createBrowserIssuer({
      core: configuredIssuerCore({ accessPolicy: denyAll, errorDetail: "uniform" }),
      registrationForKid: () => null,
      preflight: () => false,
      admitCaller: () => ({ kind: "admitted" }),
      clock: { now: () => new Date(AT) },
    });
    const response = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: document,
    });
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: "rejected" });
    assert.equal(response.headers["access-control-allow-origin"], undefined);
    const media = await browser.handle({ method: "POST", origin: ORIGIN, body: document });
    assert.equal(media.status, 415);
    assert.deepEqual(media.body, { error: "rejected" });
    assert.equal(media.headers["access-control-allow-origin"], undefined);
  });

  test("completed denial and typed policy outage have distinct fallback status classes", async () => {
    const { document, registration } = await world();
    for (const [policy, status] of [
      [{ decide: () => ({}) }, 401],
      [
        {
          decide: () => {
            throw dcaError("policy_unavailable", "timed out");
          },
        },
        503,
      ],
      [
        {
          decide: () => {
            throw new Error("unexpected");
          },
        },
        500,
      ],
    ]) {
      const browser = createBrowserIssuer({
        core: configuredIssuerCore({
          accessPolicy: /** @type {any} */ (policy),
          periodKeyInput: true,
        }),
        registrationForKid: () => registration,
        preflight: () => false,
        admitCaller: () => ({ kind: "admitted", principal: null }),
        clock: { now: () => new Date(AT) },
      });
      const response = await browser.handle({
        method: "POST",
        contentType: "application/json",
        origin: ORIGIN,
        body: document,
      });
      assert.equal(response.status, status);
      assert.equal(response.headers["access-control-allow-origin"], ORIGIN);
      assert.equal(response.headers.vary, "Origin");
    }
  });

  test("one host setup admits an exact signed origin and returns its period key", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    const browser = createBrowserIssuer({
      core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
      registrationForKid: async (kid) => (kid === registration.kid ? registration : null),
      preflight: (origin) => origin === ORIGIN,
      admitCaller: () => ({
        kind: "admitted",
        principal: { id: "reader" },
        context: { plan: "monthly" },
      }),
      clock: { now: () => new Date(AT) },
    });
    const answered = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: document,
    });
    assert.equal(answered.status, 200);
    assert.equal(answered.headers?.["access-control-allow-origin"], ORIGIN);
    // The base browser profile is uncredentialed unless the host selects credentials.
    assert.equal(answered.headers?.["access-control-allow-credentials"], undefined);
    const preflight = await browser.handle({ method: "OPTIONS", origin: ORIGIN });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers?.["access-control-allow-credentials"], undefined);
    assert.equal(
      keyAt(answered.body.keys.periodKeys, { accessGroup: GROUP, period: T_NOW }),
      base64urlEncode(PERIOD_KEYS[T_NOW]),
    );
    assert.equal(policy.decisions.length, 1);
    assert.deepEqual(policy.decisions[0].input.principal, { id: "reader" });
    assert.deepEqual(policy.decisions[0].input.context, { plan: "monthly" });
  });

  test("wrong origin and unknown registration stop before policy and opening", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    let opened = 0;
    const scoped = {
      ...registration,
      openingKeys: {
        get(...args) {
          opened++;
          return registration.openingKeys.get(...args);
        },
      },
    };
    let found = true;
    const browser = createBrowserIssuer({
      core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
      registrationForKid: () => (found ? scoped : null),
      preflight: () => false,
      admitCaller: () => ({ kind: "admitted", principal: null }),
      clock: { now: () => new Date(AT) },
    });
    const wrong = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: "https://copy.example",
      body: document,
    });
    assert.equal(wrong.status, 403);
    assert.equal(wrong.headers?.["access-control-allow-origin"], undefined);
    assert.equal(policy.decisions.length, 0);
    assert.equal(opened, 0);
    found = false;
    const unknown = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: document,
    });
    assert.equal(unknown.status, 400);
    assert.equal(policy.decisions.length, 0);
    assert.equal(opened, 0);
  });

  test("malformed host origin limits are issuer faults, while valid exclusions are client refusals", async () => {
    const { document, registration } = await world();
    for (const [origins, expectedStatus, expectedCode] of [
      [ORIGIN, 500, "internal_error"],
      [new Set([ORIGIN]), 500, "internal_error"],
      [null, 500, "internal_error"],
      [[42], 500, "internal_error"],
      [[ORIGIN, 42], 500, "internal_error"],
      [[], 403, "origin_refused"],
      [["https://other.example"], 403, "origin_refused"],
    ]) {
      const policy = prefixPolicy();
      let opened = 0;
      const browser = createBrowserIssuer({
        core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
        registrationForKid: () => ({
          ...registration,
          origins: /** @type {any} */ (origins),
          openingKeys: {
            get(...args) {
              opened++;
              return registration.openingKeys.get(...args);
            },
          },
        }),
        preflight: () => false,
        admitCaller: () => ({ kind: "admitted", principal: null }),
        clock: { now: () => new Date(AT) },
      });
      const response = await browser.handle({
        method: "POST",
        contentType: "application/json",
        origin: ORIGIN,
        body: document,
      });
      assert.equal(response.status, expectedStatus, String(origins));
      assert.deepEqual(response.body, { error: expectedCode });
      assert.equal(response.headers?.["access-control-allow-origin"], undefined);
      assert.equal(policy.decisions.length, 0);
      assert.equal(opened, 0);
    }
  });

  test("preflight applies the selected origin scheme before trusted allow policy", async () => {
    for (const [developmentHttpOrigin, origin, status] of [
      [false, "https://publisher.example", 204],
      [false, "http://publisher.example", 403],
      [false, "http://localhost", 403],
      [true, "http://localhost", 204],
      [true, "http://127.0.0.1:8080", 204],
      [true, "http://[::1]:8080", 403],
      [true, "http://publisher.example", 403],
    ]) {
      const seen = [];
      const browser = createBrowserIssuer({
        core: configuredIssuerCore({ accessPolicy: prefixPolicy(), periodKeyInput: true }),
        registrationForKid: () => {
          throw new Error("preflight has no registration");
        },
        preflight: (value) => {
          seen.push(value);
          return true;
        },
        admitCaller: () => {
          throw new Error("preflight has no caller");
        },
        clock: { now: () => new Date(AT) },
        developmentHttpOrigin,
      });
      const response = await browser.handle({ method: "OPTIONS", origin });
      assert.equal(response.status, status, `${developmentHttpOrigin}: ${origin}`);
      assert.deepEqual(seen, status === 204 ? [origin] : []);
      assert.equal(
        response.headers["access-control-allow-origin"],
        status === 204 ? origin : undefined,
      );
      assert.equal(response.headers.vary, "Origin");
    }
  });

  test("the selected bearer reaches host admission before policy", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    const seen = [];
    const browser = createBrowserIssuer({
      core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
      registrationForKid: () => registration,
      preflight: () => false,
      authorization: true,
      admitCaller: (_host, _registration, bearer) => {
        seen.push(bearer);
        return bearer === "member-token"
          ? { kind: "admitted", principal: { id: "reader" } }
          : { kind: "refused", status: 401, code: "unauthenticated" };
      },
      clock: { now: () => new Date(AT) },
    });
    const refused = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: document,
    });
    assert.equal(refused.status, 401);
    assert.deepEqual(seen, [], "missing bearer is refused before caller admission");
    const hostRefused = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: document,
      authorization: "Bearer unknown-token",
    });
    assert.equal(hostRefused.status, 401);
    assert.deepEqual(hostRefused.body, { error: "unauthenticated" });
    assert.deepEqual(seen, ["unknown-token"]);
    assert.equal(policy.decisions.length, 0, "the host refusal stops before policy");
    const answered = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: document,
      authorization: "Bearer member-token",
    });
    assert.equal(answered.status, 200);
    assert.deepEqual(seen, ["unknown-token", "member-token"]);
    assert.equal(policy.decisions.length, 1);
  });

  test("admission owns an immutable parsed document; standalone engine still verifies", async () => {
    const { document, registration } = await world();
    const core = configuredIssuerCore({ accessPolicy: prefixPolicy(), periodKeyInput: true });
    const admitted = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => registration,
    });
    assert.equal(admitted.kind, "admitted");
    assert.equal(
      admitted.state,
      null,
      "without a host hook the admitted state is explicitly empty",
    );
    const parsed = admitted.request.toObject();
    assert.equal(Object.isFrozen(parsed), true);
    assert.equal(Object.isFrozen(parsed.sealed), true);
    assert.throws(() => {
      parsed.resourceJWT = "forged";
    }, TypeError);
    const tampered = JSON.parse(document);
    const parts = tampered.resourceJWT.split(".");
    const signature = base64urlDecode(parts[2]);
    signature[0] ^= 1;
    parts[2] = base64urlEncode(signature);
    tampered.resourceJWT = parts.join(".");
    const result = await core.endpoint.handleDocument(JSON.stringify(tampered), registration);
    assert.equal(result.response.status, 400);
    assert.equal(result.response.body.error, "bad_signature");
  });

  test("request version and required container refusals precede all downstream issuer work", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    const reached = { kid: 0, caller: 0, opening: 0 };
    const scoped = {
      ...registration,
      openingKeys: {
        get(issuerName, keyId) {
          reached.opening++;
          return registration.openingKeys.get(issuerName, keyId);
        },
      },
    };
    const browser = createBrowserIssuer({
      core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
      origin: ORIGIN,
      registrationForKid: () => {
        reached.kid++;
        return scoped;
      },
      preflight: () => false,
      admitCaller: () => {
        reached.caller++;
        return { kind: "admitted", principal: null };
      },
      clock: { now: () => new Date(AT) },
    });
    const input = JSON.parse(document);
    const absent = { ...input, sealed: { periodKeys: input.sealed.periodKeys } };
    for (const [body, code] of [
      [JSON.stringify({ ...input, version: "2" }), "bad_version"],
      [JSON.stringify({ ...input, version: "2", sealed: { contentKeys: 7 } }), "bad_version"],
      [JSON.stringify({ ...input, sealed: { contentKeys: 7 } }), "binding_failed"],
      [JSON.stringify(absent), "binding_failed"],
      // A host that hands over an already parsed body sends no raw JSON to measure.
      [input, "invalid_json"],
    ]) {
      const meter = cryptoMeter();
      let result;
      try {
        result = await browser.handle({
          method: "POST",
          contentType: "application/json",
          origin: ORIGIN,
          body,
        });
      } finally {
        meter.stop();
      }
      assert.equal(result.status, 400);
      assert.deepEqual(result.body, { error: code });
      assert.equal(result.headers?.["access-control-allow-origin"], undefined);
      assert.deepEqual(reached, { kid: 0, caller: 0, opening: 0 });
      assert.equal(policy.decisions.length, 0);
      assert.equal(meter.counts.verify, 0);
      assert.equal(meter.counts.asymmetric, 0);
    }
    const meter = cryptoMeter();
    let valid;
    try {
      valid = await browser.handle({
        method: "POST",
        contentType: "application/json",
        origin: ORIGIN,
        body: document,
      });
    } finally {
      meter.stop();
    }
    assert.equal(valid.status, 200, "the same measured path accepts the original request");
    assert.equal(reached.kid, 1);
    assert.equal(reached.caller, 1);
    assert.ok(reached.opening > 0);
    assert.equal(policy.decisions.length, 1);
    assert.ok(meter.counts.verify > 0);
  });

  test("browser composition verifies the signed resource once and opens real content", async () => {
    const { document, registration, dcaData, sealedContent } = await world();
    const policy = prefixPolicy();
    const browser = createBrowserIssuer({
      core: configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true }),
      registrationForKid: () => registration,
      preflight: () => false,
      admitCaller: () => ({ kind: "admitted", principal: null }),
      clock: { now: () => new Date(AT) },
    });
    const meter = cryptoMeter();
    let response;
    try {
      response = await browser.handle({
        method: "POST",
        contentType: "application/json",
        origin: ORIGIN,
        body: document,
      });
    } finally {
      meter.stop();
    }
    assert.equal(response.status, 200);
    assert.equal(meter.counts.verify, 1);
    const keys = periodKeyMap(response.body.keys.periodKeys)[GROUP];
    const t = Object.keys(keys)[0];
    assert.equal(await openWith(dcaData, sealedContent, t, keys[t]), ARTICLE);
    assert.equal(policy.decisions.length, 1);
  });

  test("verification handoff is immutable, single-use and never caches policy", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    let allow = true;
    let decisions = 0;
    const core = configuredIssuerCore({
      periodKeyInput: true,
      accessPolicy: {
        decide(...args) {
          decisions++;
          return allow ? policy.decide(...args) : { contentNames: [], periodGrants: [] };
        },
      },
    });
    const admitted = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => registration,
    });
    assert.equal(admitted.kind, "admitted");
    if (admitted.kind !== "admitted") throw new Error("admission failed");
    assert.ok(Object.isFrozen(admitted.claims));
    assert.ok(Object.isFrozen(admitted.claims.resource.data));
    assert.throws(() => {
      admitted.claims.resource.data.section = "other";
    }, TypeError);
    const invocation = { request: admitted.request, registration, verification: admitted.claims };
    let meter = cryptoMeter();
    try {
      assert.equal((await core.endpoint.handleRequest(invocation)).response.status, 200);
    } finally {
      meter.stop();
    }
    assert.equal(meter.counts.verify, 0, "the original verification was consumed");
    allow = false;
    meter = cryptoMeter();
    try {
      assert.equal((await core.endpoint.handleRequest(invocation)).response.status, 401);
    } finally {
      meter.stop();
    }
    assert.equal(meter.counts.verify, 1, "a consumed handoff is independently verified");
    assert.equal(decisions, 2, "new policy applies even to the same request");
  });

  test("copied claims, different request identity and changed keys cannot waive verification", async () => {
    const { document, registration } = await world();
    const core = configuredIssuerCore({ accessPolicy: prefixPolicy(), periodKeyInput: true });
    const wrongKey = (await signingKeypair()).publicKey;
    for (const variant of ["copy", "request", "key"]) {
      const admitted = await admitBrowserRequest({
        processor: core.processor,
        endpoint: core.endpoint,
        document,
        origin: ORIGIN,
        registrationForKid: () => registration,
      });
      if (admitted.kind !== "admitted") throw new Error("admission failed");
      const request =
        variant === "request" ? new DcaRequest(JSON.parse(document)) : admitted.request;
      const verification = variant === "copy" ? structuredClone(admitted.claims) : admitted.claims;
      const selected = variant === "key" ? { ...registration, publicKey: wrongKey } : registration;
      const meter = cryptoMeter();
      let result;
      try {
        result = await core.endpoint.handleRequest({
          request,
          registration: selected,
          verification,
        });
      } finally {
        meter.stop();
      }
      assert.equal(meter.counts.verify, 1, variant);
      assert.equal(result.response.status, variant === "key" ? 400 : 200, variant);
      if (variant === "key") assert.equal(result.response.body.error, "bad_signature");
    }
  });

  test("changing the signed token after verification is refused before policy or opening", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    const core = configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true });
    const request = new DcaRequest(JSON.parse(document));
    const verification = await checkEnvelopes(request, registration.publicKey);
    const parts = request.resourceJWT.split(".");
    const signature = base64urlDecode(parts[2]);
    signature[0] ^= 1;
    parts[2] = base64urlEncode(signature);
    request.toObject().resourceJWT = parts.join(".");
    let openings = 0;
    const scoped = {
      ...registration,
      openingKeys: {
        get(...args) {
          openings++;
          return registration.openingKeys.get(...args);
        },
      },
    };
    const result = await core.endpoint.handleRequest({
      request,
      registration: scoped,
      verification,
    });
    assert.equal(result.response.status, 400);
    assert.equal(result.response.body.error, "bad_signature");
    assert.equal(policy.decisions.length, 0);
    assert.equal(openings, 0);
  });

  test("one verification result cannot skip verification in two concurrent unlocks", async () => {
    const { document, registration } = await world();
    const policy = prefixPolicy();
    const core = configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true });
    const admitted = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => registration,
    });
    if (admitted.kind !== "admitted") throw new Error("admission failed");
    const invocation = { request: admitted.request, registration, verification: admitted.claims };
    const meter = cryptoMeter();
    let results;
    try {
      results = await Promise.all([
        core.endpoint.handleRequest(invocation),
        core.endpoint.handleRequest(invocation),
      ]);
    } finally {
      meter.stop();
    }
    assert.deepEqual(
      results.map((result) => result.response.status),
      [200, 200],
    );
    assert.equal(meter.counts.verify, 1);
    assert.equal(policy.decisions.length, 2);
  });

  test("development-origin verification cannot waive the production engine check", async () => {
    const { document, registration } = await world({
      origin: "http://localhost",
      developmentHttpOrigin: true,
    });
    const request = new DcaRequest(JSON.parse(document));
    const verification = await checkEnvelopes(request, registration.publicKey, true);
    const policy = prefixPolicy();
    const core = configuredIssuerCore({ accessPolicy: policy, periodKeyInput: true });
    const result = await core.endpoint.handleRequest({ request, registration, verification });
    assert.equal(result.response.status, 400);
    assert.equal(result.response.body.error, "bad_jwt");
    assert.equal(policy.decisions.length, 0);
  });

  test("optional input projection safely verifies the selected request independently", async () => {
    const { document, registration } = await world({ includeContentKeys: true });
    const core = configuredIssuerCore({
      accessPolicy: { decide: () => ({ contentNames: [CONTENT_NAME], periodGrants: [] }) },
      periodKeyInput: false,
    });
    const admitted = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => registration,
    });
    if (admitted.kind !== "admitted") throw new Error("admission failed");
    const meter = cryptoMeter();
    try {
      const result = await core.endpoint.handleRequest({
        request: admitted.request,
        registration,
        verification: admitted.claims,
      });
      assert.equal(result.response.status, 200);
      assert.ok(contentKeyMap(result.response.body.keys.contentKeys)[CONTENT_NAME]);
    } finally {
      meter.stop();
    }
    assert.equal(
      meter.counts.verify,
      1,
      "the projected identity does not reuse the original proof",
    );
  });

  test("deep JSON stays immutable and a deep unsupported version is refused", async () => {
    const { document, registration } = await world();
    const core = configuredIssuerCore({ accessPolicy: prefixPolicy(), periodKeyInput: true });
    const depth = 28000;
    const nestedArray = `${"[".repeat(depth)}0${"]".repeat(depth)}`;
    const deepDocument = `${document.slice(0, -1)},"deepProbe":${nestedArray}}`;
    assert.ok(deepDocument.length < 64 * 1024, "the deep request stays within the body cap");

    const admitted = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document: deepDocument,
      origin: ORIGIN,
      registrationForKid: () => registration,
    });
    assert.equal(admitted.kind, "admitted");
    if (admitted.kind !== "admitted") return;
    let nested = admitted.request.toObject().deepProbe;
    for (let index = 0; index < depth; index++) {
      assert.equal(Object.isFrozen(nested), true, `nested array ${index} is frozen`);
      nested = nested[0];
    }

    const deepVersionDocument = document.replace('"version":"1"', `"version":${nestedArray}`);
    assert.notEqual(deepVersionDocument, document, "the request version was replaced");
    assert.ok(
      deepVersionDocument.length < 64 * 1024,
      "the invalid request stays within the body cap",
    );
    const browser = createBrowserIssuer({
      core,
      origin: ORIGIN,
      registrationForKid: () => registration,
      preflight: (origin) => origin === ORIGIN,
      admitCaller: () => ({ kind: "admitted", principal: null }),
      clock: { now: () => new Date(AT) },
    });
    const refused = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: deepVersionDocument,
    });
    assert.equal(refused.status, 400);
    assert.deepEqual(refused.body, { error: "bad_version" });
  });

  test("a registration with the wrong kid is refused before caller admission even with the right key", async () => {
    const { document, registration } = await world();
    const core = configuredIssuerCore({ accessPolicy: prefixPolicy(), periodKeyInput: true });
    let callers = 0;
    const result = await admitBrowserRequest({
      processor: core.processor,
      endpoint: core.endpoint,
      document,
      origin: ORIGIN,
      registrationForKid: () => ({ ...registration, kid: "some-other-kid" }),
      beforeVerify: () => {
        callers++;
        return { kind: "admitted", state: {} };
      },
    });
    assert.equal(result.kind, "refused");
    assert.equal(result.code, "unknown_publisher_key");
    assert.equal(callers, 0);
  });
});

/**
 * Copy what a manifest names into a scratch tree: every `.js` file directly in
 * each named directory, under the same directory names.
 *
 * @param {string} manifestName
 * @returns {{ root: string, files: string[] }}
 */
function copySlice(manifestName) {
  const manifest = JSON.parse(readFileSync(new URL(manifestName, V1), "utf8"));
  const root = mkdtempSync(join(tmpdir(), "dca-copy-slice-"));
  /** @type {string[]} */
  const files = [];
  for (const path of copyManifestFiles(manifest, V1)) {
    const directory = path.slice(0, path.lastIndexOf("/"));
    mkdirSync(join(root, directory), { recursive: true });
    copyFileSync(fileURLToPath(new URL(path, V1)), join(root, path));
    files.push(path);
  }
  return { root, files };
}

/**
 * Every import and re-export specifier in one copied file, static or dynamic.
 *
 * @param {string} source
 */
function specifiersIn(source) {
  return [
    ...[...source.matchAll(/^(?:import|export)\b[^'"]*?from\s*(['"])([^'"]+)\1/gm)].map(
      (match) => match[2],
    ),
    ...[...source.matchAll(/\bimport\s*\(\s*(['"])([^'"]+)\1/g)].map((match) => match[2]),
  ];
}

describe("A clean copy of the issuer manifest", () => {
  test("every copied import resolves inside the copy, and the copied entry answers", async () => {
    const { root, files } = copySlice("copy-manifest--issuer.json");
    try {
      const copied = new Set(files);
      for (const file of files) {
        const source = readFileSync(join(root, file), "utf8");
        for (const specifier of specifiersIn(source)) {
          assert.ok(
            specifier.startsWith("."),
            `${file} imports ${specifier}, which no copy carries`,
          );
          const target = new URL(specifier, `file:///slice/${file}`).pathname.slice(
            "/slice/".length,
          );
          assert.ok(copied.has(target), `${file} imports ${target}, which the manifest leaves out`);
        }
      }

      const { createIssuerCore: copiedEntry } = await import(
        pathToFileURL(join(root, "integration-issuer/createIssuerCore.js")).href
      );
      const { dcaData, sealedContent, document, registration } = await world();
      const { endpoint } = copiedEntry({
        operatingIssuerNames: [ISSUER_NAME],
        accessPolicy: prefixPolicy(1),
        periodKeyInput: true,
      });
      const { response } = await endpoint.handleDocument(document, registration);
      assert.equal(response.status, 200);
      const returned = periodKeyMap(response.body.keys.periodKeys)[GROUP][T_NOW];
      assert.equal(await openWith(dcaData, sealedContent, T_NOW, returned), ARTICLE);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

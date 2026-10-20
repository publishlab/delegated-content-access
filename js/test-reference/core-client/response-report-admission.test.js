// @ts-check
//
// Which failure scope keeps an admitted `notDelivered` report. Response
// binding Sections 3, 6 and 10 give three scopes: a rejected key entry and a
// rejected client-bound transport reject keys, not the otherwise admitted
// report; a whole-response rejection admits no report. The family-conflict
// rule reads only admitted error entries and non-array own-member key maps.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../core-client/DcaData.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";

const ISSUER = "issuer_example";
const T = "251023T1500";
const EC_OFFER = Object.freeze({
  clientPublicKey: { kty: "EC", crv: "P-256", x: "request-x", y: "request-y" },
});
const REPORT = Object.freeze({ premium: { reason: "unavailable" } });
const ADMITTED_REPORT = [{ accessGroup: "premium", reason: "unavailable" }];
const MALFORMED = Object.freeze({
  accepted: 0,
  errors: [],
  issues: [{ section: "notDelivered", code: "malformed_response" }],
});

/** @param {number} fill */
const key = (fill) => base64urlEncode(new Uint8Array(16).fill(fill));

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

function deliveredPage() {
  return new DcaData(
    {
      version: "1",
      resourceJWT: compactJwt({ origin: "https://signed.example", renderId: "r-1" }),
      issuerData: {
        [ISSUER]: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
      },
      contentData: { bodytext: { contentType: "text/html", nonce: "n", aad: "a" } },
    },
    { publisherOrigin: "https://publisher.example" },
  );
}

/**
 * A request presenting two content names and the `premium` period family.
 * @param {DcaData} page @param {object} [members] @param {object} [endpoint]
 */
function associationFor(page, members = {}, endpoint) {
  return new ResponseAssociation(
    page,
    ISSUER,
    {
      version: page.version,
      issuerName: ISSUER,
      resourceJWT: page.resourceJWT,
      keyId: page.keyIdFor(ISSUER),
      sealed: {
        contentKeys: { bodytext: "AA", summary: "AA" },
        periodKeys: { premium: { [T]: "AA" } },
      },
      ...members,
    },
    endpoint,
  );
}

/** A cache that fails the test if a refused response files a period key. */
function refusingCache() {
  return {
    put() {
      throw new Error("no period key may file");
    },
    candidatesAt: () => [],
    attempted() {},
  };
}

/**
 * A client-bound capability that counts opener requests and opens nothing
 * unless a test supplies an opener.
 * @param {(transport: unknown) => any} [openDeliveredKeys]
 */
function countingCapability(openDeliveredKeys) {
  const calls = { opens: 0 };
  return {
    calls,
    capability: {
      async openDeliveredKeys(/** @type {unknown} */ transport) {
        calls.opens++;
        if (openDeliveredKeys) return openDeliveredKeys(transport);
        throw new Error("this transport is never opened");
      },
    },
  };
}

describe("error admission precedes the family-conflict check", () => {
  for (const [name, coordinate, entry, issue] of [
    [
      "a malformed period label",
      "premium|not-a-label",
      { error: "unseal_failed" },
      "malformed_error",
    ],
    ["a group-only spelling", "premium|", { error: "unseal_failed" }, "malformed_error"],
    ["a doubled separator", `premium||${T}`, { error: "unseal_failed" }, "malformed_error"],
    [
      "an unsolicited period label",
      "premium|251023T1600",
      { error: "unseal_failed" },
      "unsolicited_coordinate",
    ],
    [
      "an admitted coordinate whose entry has no error string",
      `premium|${T}`,
      { error: 7 },
      "malformed_error",
    ],
    [
      "an admitted coordinate whose entry is not an object",
      `premium|${T}`,
      "unseal_failed",
      "malformed_error",
    ],
  ]) {
    test(`${name} cannot conflict with the report; the content key stays`, async () => {
      const page = deliveredPage();
      const resolver = new ContentKeyResolver({ cache: refusingCache() });
      const application = await resolver.applyResponse(
        page,
        ISSUER,
        {
          keys: { contentKeys: { bodytext: key(1) } },
          errors: { [coordinate]: entry },
          notDelivered: REPORT,
        },
        associationFor(page),
      );
      assert.deepEqual(application, {
        accepted: 1,
        errors: [],
        issues: [{ section: "errors", code: issue }],
        notDelivered: ADMITTED_REPORT,
      });
      assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
    });
  }

  test("an admitted family error refuses the report but retains an independent item key", async () => {
    const page = deliveredPage();
    const resolver = new ContentKeyResolver({ cache: refusingCache() });
    const application = await resolver.applyResponse(
      page,
      ISSUER,
      {
        keys: { contentKeys: { bodytext: key(1) } },
        errors: { [`premium|${T}`]: { error: "unseal_failed" } },
        notDelivered: REPORT,
      },
      associationFor(page),
    );
    assert.deepEqual(application, {
      ...MALFORMED,
      accepted: 1,
      errors: [{ coordinate: `premium|${T}`, error: "unseal_failed" }],
    });
    assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
  });

  test("an admitted content-name error stands beside the report", async () => {
    const page = deliveredPage();
    const application = await new ContentKeyResolver().applyResponse(
      page,
      ISSUER,
      {
        keys: { contentKeys: { bodytext: key(1) } },
        errors: { summary: { error: "unseal_failed" } },
        notDelivered: REPORT,
      },
      associationFor(page),
    );
    assert.deepEqual(application.errors, [{ coordinate: "summary", error: "unseal_failed" }]);
    assert.deepEqual(application.notDelivered, ADMITTED_REPORT);
  });
});

describe("a rejected client-bound transport rejects keys, not admitted non-key results", () => {
  /** @type {[string, any][]} */
  const transports = [
    ["a method the request did not offer", { method: "RSA-OAEP" }],
    ["an unknown method", { method: "unknown-method" }],
    ["a missing method", {}],
    ["a non-object transport", "client-bound"],
  ];
  for (const [name, transport] of transports) {
    test(`${name}: every wrapped entry is rejected, the report is kept, no direct retry`, async () => {
      const page = deliveredPage();
      const { calls, capability } = countingCapability();
      const resolver = new ContentKeyResolver({
        cache: refusingCache(),
        clientBoundKeyCapability: capability,
      });
      const application = await resolver.applyResponse(
        page,
        ISSUER,
        {
          keys: { contentKeys: { bodytext: { key: "wrapped" } } },
          errors: { summary: { error: "unseal_failed", message: "summary unavailable" } },
          transport,
          notDelivered: REPORT,
        },
        associationFor(page, EC_OFFER),
      );
      assert.deepEqual(application, {
        accepted: 0,
        errors: [{ coordinate: "summary", error: "unseal_failed", message: "summary unavailable" }],
        issues: [{ code: "invalid_transport" }],
        notDelivered: ADMITTED_REPORT,
      });
      assert.equal(calls.opens, 0, "no opener is obtained for a rejected transport");
      assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
    });
  }

  for (const [name, openDeliveredKeys] of [
    [
      "the capability refuses malformed transport members",
      () => {
        throw dcaError("bad_response", "malformed transport member");
      },
    ],
    ["the capability yields no opener", () => null],
  ]) {
    test(`${name}: the report is kept and no key is held`, async () => {
      const page = deliveredPage();
      const { calls, capability } = countingCapability(openDeliveredKeys);
      const resolver = new ContentKeyResolver({ clientBoundKeyCapability: capability });
      const application = await resolver.applyResponse(
        page,
        ISSUER,
        {
          keys: { contentKeys: { bodytext: { key: "wrapped" } } },
          errors: { summary: { error: "unseal_failed" } },
          transport: { method: "ECDH-P256" },
          notDelivered: REPORT,
        },
        associationFor(page, EC_OFFER),
      );
      assert.equal(calls.opens, 1);
      assert.deepEqual(application, {
        accepted: 0,
        errors: [{ coordinate: "summary", error: "unseal_failed" }],
        issues: [{ code: "invalid_transport" }],
        notDelivered: ADMITTED_REPORT,
      });
      assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
    });
  }

  test("admitted content and period errors survive; malformed, unsolicited and key-conflicting errors do not", async () => {
    const page = deliveredPage();
    const resolver = new ContentKeyResolver({
      clientBoundKeyCapability: countingCapability().capability,
    });
    const application = await resolver.applyResponse(
      page,
      ISSUER,
      {
        keys: { contentKeys: { bodytext: { key: "wrapped" } } },
        errors: {
          summary: { error: "unseal_failed" },
          [`premium|${T}`]: { error: "unseal_failed" },
          bodytext: { error: "unseal_failed" },
          "premium|not-a-label": { error: "unseal_failed" },
          other: { error: "unseal_failed" },
        },
        transport: { method: "RSA-OAEP" },
      },
      associationFor(page, EC_OFFER),
    );
    assert.deepEqual(application, {
      accepted: 0,
      errors: [
        { coordinate: "summary", error: "unseal_failed" },
        { coordinate: `premium|${T}`, error: "unseal_failed" },
      ],
      issues: [
        { code: "invalid_transport" },
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "malformed_error" },
        { section: "errors", code: "unsolicited_coordinate" },
      ],
    });
  });

  test("an individual unwrap failure keeps the report beside a valid sibling", async () => {
    const page = deliveredPage();
    const opened = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(16).fill(5),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const { capability } = countingCapability(() => ({
      open: async (/** @type {any} */ value) => (value.key === "good" ? opened : null),
    }));
    const resolver = new ContentKeyResolver({ clientBoundKeyCapability: capability });
    const application = await resolver.applyResponse(
      page,
      ISSUER,
      {
        keys: { contentKeys: { bodytext: { key: "good" }, summary: { key: "unreadable" } } },
        transport: { method: "ECDH-P256" },
        notDelivered: REPORT,
      },
      associationFor(page, EC_OFFER),
    );
    assert.equal(application.accepted, 1);
    assert.deepEqual(application.notDelivered, ADMITTED_REPORT);
    assert.equal(await resolver.contentKeyFor(page, "bodytext"), opened);
  });
});

describe("a whole-response rejection admits no report", () => {
  /** @type {[string, object, object, object|undefined][]} */
  const cases = [
    [
      "mixed direct and wrapped entries",
      { keys: { contentKeys: { bodytext: key(1), summary: { key: "wrapped" } } } },
      {},
      { acceptDirectResponse: true },
    ],
    [
      "direct entries below a client-bound marker",
      {
        keys: { contentKeys: { bodytext: key(1) } },
        transport: { method: "ECDH-P256" },
      },
      EC_OFFER,
      undefined,
    ],
    [
      "a direct key-bearing answer from a strict client-bound endpoint",
      { keys: { contentKeys: { bodytext: key(1) } } },
      EC_OFFER,
      undefined,
    ],
  ];
  for (const [name, response, members, endpoint] of cases) {
    test(`${name}: invalid_transport without the report`, async () => {
      const page = deliveredPage();
      const { calls, capability } = countingCapability();
      const resolver = new ContentKeyResolver({
        cache: refusingCache(),
        clientBoundKeyCapability: capability,
      });
      const application = await resolver.applyResponse(
        page,
        ISSUER,
        {
          ...response,
          errors: { summary: { error: "unseal_failed" } },
          notDelivered: REPORT,
        },
        associationFor(page, members, endpoint),
      );
      assert.deepEqual(application, {
        accepted: 0,
        errors: [],
        issues: [{ section: "response", code: "invalid_transport" }],
      });
      assert.equal(calls.opens, 0);
      assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
    });
  }

  test("a malformed report beside a rejected transport admits nothing", async () => {
    const page = deliveredPage();
    const { capability } = countingCapability();
    const application = await new ContentKeyResolver({
      clientBoundKeyCapability: capability,
    }).applyResponse(
      page,
      ISSUER,
      {
        keys: { contentKeys: { bodytext: { key: "wrapped" } } },
        transport: { method: "RSA-OAEP" },
        notDelivered: { premium: { reason: "withheld" } },
      },
      associationFor(page, EC_OFFER),
    );
    assert.deepEqual(application, {
      ...MALFORMED,
      issues: [...MALFORMED.issues, { code: "invalid_transport" }],
    });
  });

  test("an unassociated response is refused before any report is read", async () => {
    const page = deliveredPage();
    const other = new DcaData(
      {
        version: "1",
        resourceJWT: compactJwt({ origin: "https://signed.example", renderId: "r-2" }),
        issuerData: {
          [ISSUER]: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
        },
        contentData: {},
      },
      { publisherOrigin: "https://publisher.example" },
    );
    await assert.rejects(
      new ContentKeyResolver().applyResponse(
        page,
        ISSUER,
        { keys: { contentKeys: {} }, notDelivered: REPORT },
        associationFor(other),
      ),
      { code: "bad_config" },
    );
  });
});

describe("response binding Section 3 family conflict reads non-array own-member maps", () => {
  /** An array cannot carry a named key family, even when a member is attached. */
  const arrayWithFamily = Object.assign([], { premium: { [T]: key(2) } });
  /** An inherited member is no own key entry. */
  const inheritedOnly = Object.create({ [T]: key(2) });

  /** @type {[string, (section: string) => object][]} */
  const noConflict = [
    ["an empty key section", () => ({})],
    ["an array key section", () => []],
    ["a scalar key section", () => 7],
    ["a null key section", () => null],
    ["an array key section carrying a named member", () => arrayWithFamily],
    ["an empty family", () => ({ premium: {} })],
    ["an empty array family", () => ({ premium: [] })],
    ["a nonempty array family", () => ({ premium: [key(2)] })],
    ["a string family", () => ({ premium: key(2) })],
    ["a numeric family", () => ({ premium: 7 })],
    ["a null family", () => ({ premium: null })],
    ["a family with only an inherited member", () => ({ premium: inheritedOnly })],
  ];
  for (const section of ["periodKeys", "chainKeys"]) {
    for (const [name, value] of noConflict) {
      test(`${section}: ${name} does not conflict with the report`, async () => {
        const page = deliveredPage();
        const resolver = new ContentKeyResolver({ cache: refusingCache() });
        const application = await resolver.applyResponse(
          page,
          ISSUER,
          {
            keys: { contentKeys: { bodytext: key(1) }, [section]: value(section) },
            notDelivered: REPORT,
          },
          associationFor(page),
        );
        assert.deepEqual(application.notDelivered, ADMITTED_REPORT);
        assert.equal(
          application.issues.some((issue) => issue.code === "malformed_response"),
          false,
        );
        assert.deepEqual(
          await resolver.contentKeyFor(page, "bodytext"),
          new Uint8Array(16).fill(1),
        );
      });
    }

    for (const [name, family] of [
      ["an invalid label", { "not-a-label": key(2) }],
      ["a numeric leaf", { [T]: 7 }],
      ["a null leaf", { [T]: null }],
      ["an empty-object leaf", { [T]: {} }],
    ]) {
      test(`${section}: a nonempty family with ${name} conflicts before leaf admission`, async () => {
        const page = deliveredPage();
        const resolver = new ContentKeyResolver({ cache: refusingCache() });
        const application = await resolver.applyResponse(
          page,
          ISSUER,
          {
            keys: { contentKeys: { bodytext: key(1) }, [section]: { premium: family } },
            notDelivered: REPORT,
          },
          associationFor(page),
        );
        assert.deepEqual(application, {
          ...MALFORMED,
          accepted: name === "an empty-object leaf" && section === "periodKeys" ? 0 : 1,
          issues:
            name === "an empty-object leaf" && section === "periodKeys"
              ? [{ section: "response", code: "invalid_transport" }]
              : MALFORMED.issues,
        });
        if (name === "an empty-object leaf" && section === "periodKeys")
          assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
        else
          assert.deepEqual(
            await resolver.contentKeyFor(page, "bodytext"),
            new Uint8Array(16).fill(1),
          );
      });
    }
  }
});

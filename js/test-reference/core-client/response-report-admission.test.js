// @ts-check
//
// Which failure scope keeps an admitted `notDelivered` report. Response
// binding Sections 3, 6 and 10 give three scopes: a rejected key entry and a
// rejected client-bound transport reject keys, not the otherwise admitted
// report; a whole-response rejection admits no report. The family-conflict
// rule reads only admitted error records and key records that name the family.
// Several records for one `coordinate` or `accessGroup` resolve to the last
// whole record (data format Section 2.3) before the conflict rule runs.

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
const REPORT = Object.freeze([Object.freeze({ accessGroup: "premium", reason: "unavailable" })]);
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
      issuerData: [
        {
          issuerName: ISSUER,
          keyId: "k1",
          unlockUrl: "https://issuer.example/unlock",
          sealed: {},
        },
      ],
      contentData: [{ contentName: "bodytext", contentType: "text/html", nonce: "n", aad: "a" }],
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
        contentKeys: [
          { contentName: "bodytext", key: "AA" },
          { contentName: "summary", key: "AA" },
        ],
        periodKeys: [{ accessGroup: "premium", period: T, key: "AA" }],
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
  for (const [name, record, issue] of [
    [
      "a malformed period label",
      { coordinate: "premium|not-a-label", error: "unseal_failed" },
      "malformed_error",
    ],
    [
      "a group-only spelling",
      { coordinate: "premium|", error: "unseal_failed" },
      "malformed_error",
    ],
    [
      "a doubled separator",
      { coordinate: `premium||${T}`, error: "unseal_failed" },
      "malformed_error",
    ],
    [
      "an unsolicited period label",
      { coordinate: "premium|251023T1600", error: "unseal_failed" },
      "unsolicited_coordinate",
    ],
    [
      "an admitted coordinate whose record has no error string",
      { coordinate: `premium|${T}`, error: 7 },
      "malformed_error",
    ],
    ["an element that is not a record", "unseal_failed", "malformed_error"],
    ["a record without a coordinate", { error: "unseal_failed" }, "malformed_error"],
    [
      "an admitted coordinate whose last record has no error string",
      [
        { coordinate: `premium|${T}`, error: "unseal_failed" },
        { coordinate: `premium|${T}`, error: 7 },
      ],
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
          keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] },
          errors: Array.isArray(record) ? record : [record],
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
        keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] },
        errors: [{ coordinate: `premium|${T}`, error: "unseal_failed" }],
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
        keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] },
        errors: [{ coordinate: "summary", error: "unseal_failed" }],
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
          keys: { contentKeys: [{ contentName: "bodytext", key: { key: "wrapped" } }] },
          errors: [
            { coordinate: "summary", error: "unseal_failed", message: "summary unavailable" },
          ],
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
          keys: { contentKeys: [{ contentName: "bodytext", key: { key: "wrapped" } }] },
          errors: [{ coordinate: "summary", error: "unseal_failed" }],
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
        keys: { contentKeys: [{ contentName: "bodytext", key: { key: "wrapped" } }] },
        errors: [
          { coordinate: "summary", error: "unseal_failed" },
          { coordinate: `premium|${T}`, error: "unseal_failed" },
          { coordinate: "bodytext", error: "unseal_failed" },
          { coordinate: "premium|not-a-label", error: "unseal_failed" },
          { coordinate: "other", error: "unseal_failed" },
        ],
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
        keys: {
          contentKeys: [
            { contentName: "bodytext", key: { key: "good" } },
            { contentName: "summary", key: { key: "unreadable" } },
          ],
        },
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
      {
        keys: {
          contentKeys: [
            { contentName: "bodytext", key: key(1) },
            { contentName: "summary", key: { key: "wrapped" } },
          ],
        },
      },
      {},
      { acceptDirectResponse: true },
    ],
    [
      "direct entries below a client-bound marker",
      {
        keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] },
        transport: { method: "ECDH-P256" },
      },
      EC_OFFER,
      undefined,
    ],
    [
      "a direct key-bearing answer from a strict client-bound endpoint",
      { keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] } },
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
          errors: [{ coordinate: "summary", error: "unseal_failed" }],
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
        keys: { contentKeys: [{ contentName: "bodytext", key: { key: "wrapped" } }] },
        transport: { method: "RSA-OAEP" },
        notDelivered: [{ accessGroup: "premium", reason: "withheld" }],
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
        issuerData: [
          {
            issuerName: ISSUER,
            keyId: "k1",
            unlockUrl: "https://issuer.example/unlock",
            sealed: {},
          },
        ],
        contentData: [],
      },
      { publisherOrigin: "https://publisher.example" },
    );
    await assert.rejects(
      new ContentKeyResolver().applyResponse(
        page,
        ISSUER,
        { keys: { contentKeys: [] }, notDelivered: REPORT },
        associationFor(other),
      ),
      { code: "bad_config" },
    );
  });
});

describe("period keys Section 5.6 family conflict reads key records that name the family", () => {
  /** An inherited accessGroup is no own identity. */
  const inherited = Object.assign(Object.create({ accessGroup: "premium" }), {
    period: T,
    cutoff: T,
    key: key(2),
  });

  /** @type {[string, (field: string) => unknown][]} */
  const noConflict = [
    ["an empty key section", () => []],
    ["an object key section", () => ({})],
    ["the old family map", () => ({ premium: { [T]: key(2) } })],
    ["a scalar key section", () => 7],
    ["a null key section", () => null],
    ["a string element", () => [key(2)]],
    ["a null element", () => [null]],
    ["an array element", () => [["premium", T, key(2)]]],
    ["a record of another family", (field) => [{ accessGroup: "other", [field]: T, key: key(2) }]],
    ["a record without a family", (field) => [{ [field]: T, key: key(2) }]],
    ["a record whose family is inherited", () => [inherited]],
  ];
  for (const [section, field] of [
    ["periodKeys", "period"],
    ["chainKeys", "cutoff"],
  ]) {
    for (const [name, value] of noConflict) {
      test(`${section}: ${name} does not conflict with the report`, async () => {
        const page = deliveredPage();
        const resolver = new ContentKeyResolver({ cache: refusingCache() });
        const application = await resolver.applyResponse(
          page,
          ISSUER,
          {
            keys: {
              contentKeys: [{ contentName: "bodytext", key: key(1) }],
              [section]: value(field),
            },
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

    for (const [name, record] of [
      ["an invalid label", { [field]: "not-a-label", key: key(2) }],
      ["no label", { key: key(2) }],
      ["a numeric key", { [field]: T, key: 7 }],
      ["a null key", { [field]: T, key: null }],
      ["an empty-object key", { [field]: T, key: {} }],
    ]) {
      test(`${section}: a record naming the family with ${name} conflicts before key admission`, async () => {
        const page = deliveredPage();
        const resolver = new ContentKeyResolver({ cache: refusingCache() });
        const application = await resolver.applyResponse(
          page,
          ISSUER,
          {
            keys: {
              contentKeys: [{ contentName: "bodytext", key: key(1) }],
              [section]: [{ accessGroup: "premium", ...record }],
            },
            notDelivered: REPORT,
          },
          associationFor(page),
        );
        // An object key in a supported section beside a direct key is a
        // mixed representation, which rejects the whole response first.
        const mixed = name === "an empty-object key" && section === "periodKeys";
        assert.deepEqual(application, {
          ...MALFORMED,
          accepted: mixed ? 0 : 1,
          issues: mixed ? [{ section: "response", code: "invalid_transport" }] : MALFORMED.issues,
        });
        if (mixed) assert.equal(await resolver.contentKeyFor(page, "bodytext"), null);
        else
          assert.deepEqual(
            await resolver.contentKeyFor(page, "bodytext"),
            new Uint8Array(16).fill(1),
          );
      });
    }
  }
});

describe("several records for one identity resolve to the last whole record", () => {
  /** @param {object} response */
  async function apply(response) {
    const page = deliveredPage();
    return new ContentKeyResolver({ cache: refusingCache() }).applyResponse(
      page,
      ISSUER,
      { keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] }, ...response },
      associationFor(page),
    );
  }

  test("the last report entry for a family is the one admitted, in its order", async () => {
    const bad = { accessGroup: "premium", reason: "withheld" };
    const good = { accessGroup: "premium", reason: "denied", message: "no" };
    assert.deepEqual((await apply({ notDelivered: [bad, good] })).notDelivered, [
      { accessGroup: "premium", reason: "denied", message: "no" },
    ]);
    assert.deepEqual(await apply({ notDelivered: [good, bad] }), { ...MALFORMED, accepted: 1 });
    // Identical entries give the same result as one.
    assert.deepEqual((await apply({ notDelivered: [good, good] })).notDelivered, [good]);
  });

  test("every report entry's family is admitted, not only the last one's", async () => {
    for (const notDelivered of [
      [
        { accessGroup: "other", reason: "denied" },
        { accessGroup: "premium", reason: "denied" },
      ],
      [{ accessGroup: "bad group", reason: "denied" }, ...REPORT],
      ["premium", ...REPORT],
      [null, ...REPORT],
      [{ reason: "denied" }, ...REPORT],
    ]) {
      assert.deepEqual(
        await apply({ notDelivered }),
        { ...MALFORMED, accepted: 1 },
        JSON.stringify(notDelivered),
      );
    }
    for (const notDelivered of [[], {}, REPORT[0], "premium"]) {
      assert.deepEqual(
        await apply({ notDelivered }),
        { ...MALFORMED, accepted: 1 },
        JSON.stringify(notDelivered),
      );
    }
  });

  test("the last error record for a coordinate is the one admitted, in its order", async () => {
    const bad = { coordinate: "summary", error: 7 };
    const good = { coordinate: "summary", error: "unseal_failed" };
    const admitted = await apply({ errors: [bad, good] });
    assert.deepEqual(admitted.errors, [good]);
    assert.deepEqual(admitted.issues, []);
    const refused = await apply({ errors: [good, bad] });
    assert.deepEqual(refused.errors, []);
    assert.deepEqual(refused.issues, [{ section: "errors", code: "malformed_error" }]);
  });

  test("the family conflict reads the replaced error record", async () => {
    const family = { coordinate: `premium|${T}`, error: "unseal_failed" };
    const broken = { coordinate: `premium|${T}`, error: 7 };
    // The admitted period error came first and was replaced by a malformed
    // one, so nothing conflicts with the report.
    const kept = await apply({ errors: [family, broken], notDelivered: REPORT });
    assert.deepEqual(kept.notDelivered, ADMITTED_REPORT);
    assert.deepEqual(kept.errors, []);
    // The other order leaves an admitted period error for the family.
    const conflicted = await apply({ errors: [broken, family], notDelivered: REPORT });
    assert.deepEqual(conflicted, { ...MALFORMED, accepted: 1, errors: [family] });
  });

  test("an error element without a coordinate is one malformed record; its siblings stay", async () => {
    const application = await apply({
      errors: [7, { coordinate: "summary", error: "unseal_failed" }, { error: "x" }],
    });
    assert.deepEqual(application.errors, [{ coordinate: "summary", error: "unseal_failed" }]);
    assert.deepEqual(application.issues, [
      { section: "errors", code: "malformed_error" },
      { section: "errors", code: "malformed_error" },
    ]);
  });

  test("an errors member that is not a non-empty array is malformed", async () => {
    for (const errors of [[], {}, { summary: { error: "unseal_failed" } }, "summary"]) {
      const application = await apply({ errors });
      assert.deepEqual(application.errors, [], JSON.stringify(errors));
      assert.deepEqual(application.issues, [{ code: "malformed_error" }], JSON.stringify(errors));
    }
  });
});

// Response binding Section 3 admits response keys per record, as explicitly
// allowed by data-format Section 2.1. A bad identity leaves valid sibling
// records available; these tests pin that admission scope.

describe("a response key record with a bad identity costs only that record", () => {
  /** @param {object} keys */
  async function apply(keys) {
    const page = deliveredPage();
    /** @type {string[]} */
    const filed = [];
    const resolver = new ContentKeyResolver({
      cache: {
        put(/** @type {string} */ accessGroup, /** @type {string} */ t) {
          filed.push(`${accessGroup}|${t}`);
        },
        candidatesAt: () => [],
        attempted() {},
      },
    });
    const application = await resolver.applyResponse(page, ISSUER, { keys }, associationFor(page));
    return { application, filed, resolver, page };
  }

  for (const [label, record, code] of /** @type {[string, object, string][]} */ ([
    ["a number", { contentName: 7, key: key(2) }, "malformed_key"],
    ["missing", { key: key(2) }, "malformed_key"],
    ["outside the grammar", { contentName: "2bad", key: key(2) }, "unsolicited_coordinate"],
  ])) {
    test(`a contentName that is ${label} leaves its valid sibling accepted`, async () => {
      const { application, resolver, page } = await apply({
        contentKeys: [{ contentName: "bodytext", key: key(1) }, record],
      });
      assert.equal(application.accepted, 1);
      assert.deepEqual(application.issues, [{ section: "contentKeys", code }]);
      assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(1));
    });
  }

  for (const [label, record, code] of /** @type {[string, object, string][]} */ ([
    [
      "an accessGroup that is a number",
      { accessGroup: 7, period: T, key: key(2) },
      "malformed_key",
    ],
    ["a missing accessGroup", { period: T, key: key(2) }, "malformed_key"],
    [
      "a period outside the grammar",
      { accessGroup: "premium", period: "x", key: key(2) },
      "unsolicited_coordinate",
    ],
  ])) {
    test(`${label} leaves its valid period-key sibling filed`, async () => {
      const { application, filed } = await apply({
        contentKeys: [],
        periodKeys: [{ accessGroup: "premium", period: T, key: key(1) }, record],
      });
      assert.equal(application.accepted, 1);
      assert.deepEqual(application.issues, [{ section: "periodKeys", code }]);
      assert.deepEqual(filed, [`premium|${T}`]);
    });
  }
});

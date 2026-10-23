// @ts-check

import { describe } from "node:test";
import assert from "node:assert/strict";

import {
  DcaRequest,
  SEALED_FIELDS,
  parseDcaRequest,
  sealedCandidates,
  sealedRecordsAdmit,
} from "../../core-shared--client-issuer/DcaRequest.js";
import { test, portableTest } from "../support/portable-test.js";

const objectCoreTest = portableTest("portable-object-core");
const objectCoreDynamicTest = portableTest("portable-object-core-dynamic");

describe("The request document, and what reads it", () => {
  test("one leading HTTP UTF-8 BOM is ignored exactly once", () => {
    const json = '{"version":"1"}';
    const bytes = new TextEncoder().encode(json);
    const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
    const prefixed = new Uint8Array(bom.length + bytes.length);
    prefixed.set(bom);
    prefixed.set(bytes, bom.length);
    assert.equal(parseDcaRequest(prefixed).version, "1");
    assert.equal(parseDcaRequest(`\uFEFF${json}`).version, "1");
    for (const text of [`\uFEFF\uFEFF${json}`, ` \uFEFF${json}`]) {
      assert.throws(() => parseDcaRequest(text), { code: "invalid_json" });
      assert.throws(() => parseDcaRequest(new TextEncoder().encode(text)), {
        code: "invalid_json",
      });
    }
    assert.throws(() => parseDcaRequest(Uint8Array.of(0xff, 0x7b, 0x7d)), {
      code: "invalid_json",
    });
  });
  test("a built request survives the round trip the wire puts it through", () => {
    const request = DcaRequest.fromParts({
      version: "1",
      issuerName: "issuer.example",
      resourceJWT: "header.payload.signature",
      keyId: "k1",
      contentKeys: [{ contentName: "bodytext", key: "blob" }],
      periodKeys: [{ accessGroup: "premium", period: "251023T1500", key: "blob" }],
    });

    const document = request.toObject();
    assert.deepEqual(
      JSON.parse(JSON.stringify(document)),
      document,
      "the built document is plain JSON data",
    );

    const parsed = parseDcaRequest(JSON.stringify(document));
    assert.equal(parsed.version, "1");
    assert.equal(parsed.issuerName, "issuer.example");
    assert.equal(parsed.keyId, "k1");
    assert.equal(parsed.resourceJWT, "header.payload.signature");
    assert.deepEqual(parsed.sealedContentKeys, [{ contentName: "bodytext", key: "blob" }]);
    assert.deepEqual(parsed.sealedPeriodKeys, [
      { accessGroup: "premium", period: "251023T1500", key: "blob" },
    ]);
  });

  test("an optional member the client cannot fill sends no member in its place", () => {
    const document = DcaRequest.fromParts({
      version: "1",
      issuerName: "issuer.example",
      resourceJWT: 17,
      keyId: null,
      contentKeys: [{ contentName: "bodytext", key: "blob" }],
      periodKeys: [],
    }).toObject();

    assert.deepEqual(Object.keys(document), ["version", "issuerName", "sealed"]);
    assert.deepEqual(
      Object.keys(document.sealed),
      ["contentKeys"],
      "an empty periodKeys is no periodKeys",
    );

    // The client offers it and never demands it: an issuer with no
    // client-bound mode ignores it, and its absence is not a request for
    // direct delivery either.
    const offered = DcaRequest.fromParts({
      version: "1",
      issuerName: "issuer.example",
      contentKeys: [],
      clientPublicKey: { kty: "EC" },
    }).toObject();
    assert.deepEqual(Object.keys(offered), ["version", "issuerName", "sealed", "clientPublicKey"]);
  });

  objectCoreTest("the document goes back as it arrived, members nobody named included", () => {
    // A cache keys on this, so an unknown member and the order it arrived in
    // both have to survive. Narrowing here would file two different requests
    // under one key.
    const document = JSON.parse('{"issuerName":"i","version":"1","spurious":true}');
    assert.equal(parseDcaRequest(JSON.stringify(document)).toObject().spurious, true);
    assert.deepEqual(
      Object.keys(parseDcaRequest('{"issuerName":"i","version":"1","spurious":true}').toObject()),
      ["issuerName", "version", "spurious"],
    );
  });

  test("a fixed field is read as an own property and never off the prototype", () => {
    const request = new DcaRequest({});

    assert.equal(request.version, undefined, "not the constructor, not a function, nothing");
    assert.equal(new DcaRequest({ version: "constructor" }).version, "constructor");
    assert.equal(new DcaRequest(null).version, undefined);
    assert.equal(new DcaRequest("a string is not a request").sealed, undefined);
  });

  test("a sealed section that is not an array contributes no records", () => {
    // A map keyed by name is the retired shape; walking its member names
    // would rebuild coordinates no record states. The raw container stays
    // raw, because admission counting reads it and refuses the malformed.
    const request = new DcaRequest({
      sealed: { contentKeys: { bodytext: "blob" }, periodKeys: "not a collection" },
    });

    assert.equal(request.sealedContentKeys, undefined);
    assert.equal(request.sealedPeriodKeys, undefined);
    assert.equal(request.sealedChainKeys, undefined);
    assert.deepEqual(request.sealed, {
      contentKeys: { bodytext: "blob" },
      periodKeys: "not a collection",
    });
  });

  test("the sealed accessors hand back every record as it arrived, rivals included", () => {
    // Several records at one coordinate are candidate alternatives. The
    // accessor neither merges nor drops them; admission and the engine decide.
    const records = [
      { contentName: "bodytext", key: "blobA" },
      { contentName: "bodytext", key: "blobB" },
      "not a record",
    ];
    const request = new DcaRequest({
      sealed: {
        contentKeys: records,
        chainKeys: [{ accessGroup: "premium", cutoff: "251023T1500", key: "blobC" }],
      },
    });

    assert.strictEqual(request.sealedContentKeys, records);
    assert.deepEqual(request.sealedChainKeys, [
      { accessGroup: "premium", cutoff: "251023T1500", key: "blobC" },
    ]);
  });

  test("reading a request establishes nothing about it", () => {
    // The accessors narrow containers. Publisher authenticity comes from
    // signature verification and access from the issuer's policy, so a
    // request naming whoever it likes still reads back exactly that.
    const request = parseDcaRequest(
      JSON.stringify({
        version: "1",
        issuerName: "issuer.example",
        resourceJWT: "not.a.token",
        sealed: { contentKeys: [{ contentName: "bodytext", key: "blob" }] },
      }),
    );

    assert.equal(request.resourceJWT, "not.a.token");
    assert.deepEqual(request.sealedContentKeys, [{ contentName: "bodytext", key: "blob" }]);
  });

  test("a document that is not JSON, and a document that is not a document", () => {
    assert.throws(
      () => parseDcaRequest("{not json"),
      (/** @type {any} */ e) => e.code === "invalid_json",
    );
    assert.throws(
      () => parseDcaRequest(/** @type {any} */ ({ version: "1" })),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => DcaRequest.fromParts(/** @type {any} */ (null)),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });

  // The portable twins of the case above. `DcaRequest.fromParts` is the
  // client's builder and a static member of the reference class, so its
  // refusal runs only in the direct case. A record is not the string
  // parseDcaRequest declares, so that refusal runs in the dynamic twin.
  objectCoreTest("a document that is not JSON, parsed", () => {
    assert.throws(
      () => parseDcaRequest("{not json"),
      (/** @type {any} */ e) => e.code === "invalid_json",
    );
  });

  objectCoreDynamicTest("a document that is not a string, parsed", () => {
    assert.throws(
      () => parseDcaRequest(/** @type {any} */ ({ version: "1" })),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });

  test("a sealed collection is admitted whole, on its records and their identities", () => {
    const fields = SEALED_FIELDS.periodKeys;
    const grammars = { accessGroup: (/** @type {string} */ name) => /^[a-z]+$/.test(name) };
    assert.equal(sealedRecordsAdmit([], fields, grammars), true);
    assert.equal(
      sealedRecordsAdmit(
        [
          { accessGroup: "premium", period: "251023T1500", key: 7 },
          { accessGroup: "premium", period: "251023T1500", key: "blob" },
        ],
        fields,
        grammars,
      ),
      true,
      "a bad key value is its own scope's to judge",
    );
    for (const collection of [
      { premium: { "251023T1500": "blob" } },
      ["blob"],
      [{ accessGroup: "premium", key: "blob" }],
      [{ accessGroup: "Premium!", period: "251023T1500", key: "blob" }],
      [
        { accessGroup: "premium", period: "251023T1500", key: "blob" },
        { accessGroup: "premium", period: 1500, key: "blob" },
      ],
    ]) {
      assert.equal(
        sealedRecordsAdmit(collection, fields, grammars),
        false,
        JSON.stringify(collection),
      );
    }
  });

  test("sealed candidates keep each distinct value at its coordinate, in order", () => {
    const candidates = sealedCandidates(
      [
        { accessGroup: "premium", period: "251023T1500", key: "blobB" },
        { accessGroup: "premium", period: "251023T1500", key: "blobA" },
        { accessGroup: "premium", period: "251023T1500", key: "blobB" },
        { accessGroup: "premium", period: "251023T1515", key: "blobC" },
        { accessGroup: "__proto__", period: "251023T1500", key: "blobD" },
        { accessGroup: "premium", key: "no period" },
      ],
      SEALED_FIELDS.periodKeys,
    );
    assert.deepEqual([...candidates.keys()], ["premium", "__proto__"]);
    assert.deepEqual(candidates.get("premium").get("251023T1500"), ["blobB", "blobA"]);
    assert.deepEqual(candidates.get("premium").get("251023T1515"), ["blobC"]);
    assert.deepEqual(candidates.get("__proto__").get("251023T1500"), ["blobD"]);
    assert.deepEqual(
      [...sealedCandidates([{ contentName: "a", key: "x" }], SEALED_FIELDS.contentKeys)],
      [["a", ["x"]]],
    );
    assert.equal(sealedCandidates({ a: "x" }, SEALED_FIELDS.contentKeys).size, 0);
  });
});

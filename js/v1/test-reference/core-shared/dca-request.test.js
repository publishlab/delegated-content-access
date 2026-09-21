// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { DcaRequest, parseDcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";

describe("The request document, and what reads it", () => {
  test("a built request survives the round trip the wire puts it through", () => {
    const request = DcaRequest.fromParts({
      version: "1",
      issuerName: "issuer.example",
      resourceJWT: "header.payload.signature",
      keyId: "k1",
      contentKeys: { bodytext: "blob" },
      periodKeys: { premium: { "251023T15": "blob" } },
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
    assert.deepEqual(parsed.sealedContentKeys, { bodytext: "blob" });
    assert.deepEqual(parsed.sealedPeriodKeys, { premium: { "251023T15": "blob" } });
  });

  test("an optional member the client cannot fill sends no member in its place", () => {
    const document = DcaRequest.fromParts({
      version: "1",
      issuerName: "issuer.example",
      resourceJWT: 17,
      keyId: null,
      contentKeys: { bodytext: "blob" },
      periodKeys: {},
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
      contentKeys: {},
      clientPublicKey: { kty: "EC" },
    }).toObject();
    assert.deepEqual(Object.keys(offered), ["version", "issuerName", "sealed", "clientPublicKey"]);
  });

  test("the document goes back as it arrived, members nobody named included", () => {
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

  test("a sealed section that is not a map contributes no coordinates", () => {
    // An array has index names, so walking one would rebuild bindings for
    // coordinates nobody sealed. The raw container stays raw, because
    // admission counting reads it and a cap should refuse the malformed.
    const request = new DcaRequest({ sealed: { contentKeys: ["blob"], periodKeys: "not a map" } });

    assert.equal(request.sealedContentKeys, undefined);
    assert.equal(request.sealedPeriodKeys, undefined);
    assert.deepEqual(request.sealed, { contentKeys: ["blob"], periodKeys: "not a map" });
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
        sealed: { contentKeys: { bodytext: "blob" } },
      }),
    );

    assert.equal(request.resourceJWT, "not.a.token");
    assert.deepEqual(request.sealedContentKeys, { bodytext: "blob" });
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
});

// @ts-check
//
// The client relays an issuer block's `envelope` member into the unlock
// request unchanged (docs/spec-profile--compact-ecdh.md Section 3.2). The
// client opens nothing, so it neither validates nor infers the value: the
// issuer refuses a value it does not support. What the client owns is the
// association. The value must come from the same captured issuer block as
// `keyId`, survive a narrowed retry, and stay absent when the block has none,
// because an issuer reads an absent member as the key's ordinary procedure.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../core-client/DcaRequestBuilder.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { projectEligibleIdentities, routeIdentities } from "../../adapter-client/routeAttempts.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";

const COMPACT = "compact_issuer";
const ORDINARY = "ordinary_issuer";

/** A structurally valid token; nothing here verifies its signature. */
function compactJwt(/** @type {object} */ payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/** @param {Record<string, unknown>} [compactBlockExtra] */
function page(compactBlockExtra = { envelope: "compact-ecdh" }) {
  return new DcaData({
    version: "1",
    resourceJWT: compactJwt({ origin: "https://news.example", renderId: "r-1" }),
    issuerData: [
      {
        issuerName: COMPACT,
        keyId: "key-A",
        ...compactBlockExtra,
        unlockUrl: "https://a.example/unlock",
        sealed: {
          contentKeys: [
            { contentName: "bodytext", key: "AQ" },
            { contentName: "premium", key: "Ag" },
          ],
        },
      },
      {
        issuerName: ORDINARY,
        keyId: "key-B",
        unlockUrl: "https://b.example/unlock",
        sealed: { contentKeys: [{ contentName: "bodytext", key: "Aw" }] },
      },
    ],
    contentData: [
      { contentName: "bodytext", contentType: "text/html", nonce: "n", aad: "a" },
      { contentName: "premium", contentType: "text/html", nonce: "n", aad: "a" },
    ],
  });
}

describe("envelope selector relay", () => {
  test("the page reports each issuer block's own envelope member", () => {
    const delivered = page();
    assert.equal(delivered.envelopeFor(COMPACT), "compact-ecdh");
    assert.equal(delivered.envelopeFor(ORDINARY), undefined);
  });

  test("the request carries the selected block's envelope beside its keyId", () => {
    const request = new DcaRequestBuilder().build(page(), COMPACT, ["bodytext"]).toObject();
    assert.equal(request.keyId, "key-A");
    assert.equal(request.envelope, "compact-ecdh");
  });

  test("a block without envelope sends a request without the member", () => {
    const request = new DcaRequestBuilder().build(page(), ORDINARY, ["bodytext"]).toObject();
    assert.equal(Object.hasOwn(request, "envelope"), false);
  });

  test("the client relays a value it does not know without judging it", () => {
    for (const value of ["future-procedure", "", 7, null, { x: 1 }]) {
      const request = new DcaRequestBuilder()
        .build(page({ envelope: value }), COMPACT, ["bodytext"])
        .toObject();
      assert.deepEqual(request.envelope, value);
    }
  });

  test("fromParts writes envelope only when the caller gives one", () => {
    const base = { version: "1", issuerName: COMPACT, keyId: "key-A" };
    assert.equal(Object.hasOwn(DcaRequest.fromParts(base).toObject(), "envelope"), false);
    const request = DcaRequest.fromParts({ ...base, envelope: "compact-ecdh" });
    assert.equal(request.toObject().envelope, "compact-ecdh");
    assert.equal(request.envelope, "compact-ecdh");
  });

  test("a narrowed retry keeps the envelope", () => {
    const request = new DcaRequestBuilder()
      .build(page(), COMPACT, ["bodytext", "premium"])
      .toObject();
    const identities = { ...routeIdentities(request), contentNames: ["premium"] };
    const narrowed = projectEligibleIdentities(request, identities);
    assert.notEqual(narrowed, null);
    assert.equal(narrowed.envelope, "compact-ecdh");
    assert.deepEqual(
      narrowed.sealed.contentKeys.map((/** @type {any} */ record) => record.contentName),
      ["premium"],
    );
  });

  test("the response association pins the envelope sent with the request", () => {
    const delivered = page();
    const request = new DcaRequestBuilder().build(delivered, COMPACT, ["bodytext"]);
    const association = new ResponseAssociation(delivered, COMPACT, request);
    assert.equal(association.request.envelope, "compact-ecdh");
    assert.equal(association.matches(delivered, COMPACT), true);
  });

  test("a request from another issuer, version, render token or opening key is not associated", () => {
    const delivered = page();
    const request = new DcaRequestBuilder().build(delivered, COMPACT, ["bodytext"]).toObject();
    assert.equal(
      new ResponseAssociation(delivered, COMPACT, request).matches(delivered, COMPACT),
      true,
    );
    for (const delta of [
      { issuerName: ORDINARY },
      { version: "another-version" },
      { resourceJWT: "another-render-token" },
      { keyId: "another-opening-key" },
    ]) {
      assert.throws(() => new ResponseAssociation(delivered, COMPACT, { ...request, ...delta }), {
        code: "bad_config",
      });
    }
  });

  test("a request whose envelope differs from its block is not associated", () => {
    const delivered = page();
    const sent = new DcaRequestBuilder().build(delivered, COMPACT, ["bodytext"]).toObject();
    for (const document of [
      { ...sent, envelope: "other" },
      Object.fromEntries(Object.entries(sent).filter(([name]) => name !== "envelope")),
    ]) {
      assert.throws(() => new ResponseAssociation(delivered, COMPACT, document), {
        code: "bad_config",
      });
    }
    const ordinary = new DcaRequestBuilder().build(delivered, ORDINARY, ["bodytext"]).toObject();
    assert.throws(
      () => new ResponseAssociation(delivered, ORDINARY, { ...ordinary, envelope: "compact-ecdh" }),
      { code: "bad_config" },
    );
  });
});

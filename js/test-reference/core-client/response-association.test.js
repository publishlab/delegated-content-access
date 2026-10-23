// @ts-check
//
// What one captured request presents, as the response reader asks it. The
// request carries its sealed coordinates as records, so a coordinate is
// presented when some record names it, however many records do and wherever
// they sit in the array.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../core-client/DcaData.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";

const ISSUER = "issuer_example";

/** @param {object} value */
function segment(value) {
  return base64urlEncode(utf8Encode(JSON.stringify(value)));
}

const RESOURCE_JWT = `${segment({ alg: "ES256", typ: "JWT" })}.${segment({ renderId: "r-1" })}.c2ln`;

function page() {
  return new DcaData({
    version: "1",
    resourceJWT: RESOURCE_JWT,
    contentData: [{ contentName: "bodytext", contentType: "text/html" }],
    issuerData: [{ issuerName: ISSUER, keyId: "k1", sealed: { contentKeys: [] } }],
  });
}

/** @param {object} sealed */
function association(sealed) {
  return new ResponseAssociation(page(), ISSUER, {
    version: "1",
    issuerName: ISSUER,
    resourceJWT: RESOURCE_JWT,
    keyId: "k1",
    sealed,
  });
}

test("a coordinate is presented when a record names it, rivals and order aside", () => {
  const sealed = {
    contentKeys: [
      { contentName: "premium", key: "Ag" },
      { contentName: "bodytext", key: "AQ" },
      { contentName: "bodytext", key: "Aw" },
    ],
    periodKeys: [
      { accessGroup: "vault", period: "251023T1500", key: "BQ" },
      { accessGroup: "article", period: "251023T1400", key: "Aw" },
    ],
    chainKeys: [{ accessGroup: "article", cutoff: "251023T2300", key: "Bw" }],
  };
  const reversed = {
    contentKeys: [...sealed.contentKeys].reverse(),
    periodKeys: [...sealed.periodKeys].reverse(),
    chainKeys: sealed.chainKeys,
  };
  for (const captured of [association(sealed), association(reversed)]) {
    assert.equal(captured.presentsContent("bodytext"), true);
    assert.equal(captured.presentsContent("premium"), true);
    assert.equal(captured.presentsContent("other"), false);
    assert.equal(captured.presentsPeriodKey("article", "251023T1400"), true);
    assert.equal(captured.presentsPeriodKey("article", "251023T1500"), false);
    assert.equal(captured.presentsPeriodKey("vault", "251023T1500"), true);
    assert.equal(captured.presentsChainKey("article", "251023T2300"), true);
    assert.equal(captured.presentsChainKey("article", "251023T1400"), false);
    // A period record is not a chain record at the same label, nor the reverse.
    assert.equal(captured.presentsChainKey("vault", "251023T1500"), false);
  }
});

test("a field that is not the coordinate's presents nothing", () => {
  const captured = association({
    contentKeys: [{ name: "bodytext", key: "AQ" }, "bodytext"],
    periodKeys: [{ accessGroup: "article", t: "251023T1400", key: "Aw" }],
    chainKeys: { article: { "251023T2300": "Bw" } },
  });
  assert.equal(captured.presentsContent("bodytext"), false);
  assert.equal(captured.presentsPeriodKey("article", "251023T1400"), false);
  assert.equal(captured.presentsChainKey("article", "251023T2300"), false);
  assert.equal(association({ contentKeys: [] }).presentsContent("constructor"), false);
});

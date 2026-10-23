// @ts-check
//
// A map item opens through rival content-key candidates (core Section 7, data
// format Section 2.3). The response lists the working key first, so the wrong
// one is the newest candidate the resolver holds. The opener's predicate makes
// authenticated selection pass over it, and the item opens with the key that
// authenticated.

import test from "node:test";
import assert from "node:assert/strict";

import { openMapItems } from "../core-client/mapItems.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { ContentRepresentationOpener } from "../../../core-client/ContentRepresentationOpener.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { encrypt } from "../../../core-shared/aead.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";

const ISSUER = "issuer_example";
const PUBLISHER = "https://publisher.example";
const ARTICLE = "The council voted 7-2 to rezone the harbour.";

/** @param {number} fill */
const bytes = (fill) => new Uint8Array(16).fill(fill);
/** @param {number} fill */
const key = (fill) => base64urlEncode(bytes(fill));

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

test("a map item opens through a wrong newest candidate", async () => {
  const json = {
    version: "1",
    resourceJWT: compactJwt({ origin: PUBLISHER, renderId: base64urlEncode(bytes(7)) }),
    issuerData: [
      {
        issuerName: ISSUER,
        keyId: "k1",
        sealed: { contentKeys: [{ contentName: "bodytext", key: "AA" }] },
      },
    ],
    contentData: [{ contentName: "bodytext", contentType: "text/plain" }],
  };
  // Only the key filled with 2 opens the article.
  const ciphertext = base64urlEncode(
    await encrypt(
      bytes(2),
      new Uint8Array(12),
      utf8Encode(ARTICLE),
      contentAadOctets(json, "bodytext"),
    ),
  );
  const dcaData = new DcaData(json, { publisherOrigin: PUBLISHER });
  const resolver = new ContentKeyResolver();
  const application = await resolver.applyResponse(
    dcaData,
    ISSUER,
    {
      keys: {
        contentKeys: [
          { contentName: "bodytext", key: key(2) },
          { contentName: "bodytext", key: key(1) },
        ],
      },
    },
    new ResponseAssociation(dcaData, ISSUER, {
      version: dcaData.version,
      issuerName: ISSUER,
      resourceJWT: dcaData.resourceJWT,
      keyId: dcaData.keyIdFor(ISSUER),
      sealed: { contentKeys: [{ contentName: "bodytext", key: "AA" }] },
    }),
  );
  assert.equal(application.accepted, 2);

  const results = await openMapItems(
    {
      dcaData,
      reader: { extract: () => ciphertext },
      resolver,
      opener: new ContentRepresentationOpener(),
      unlock: async () => {
        throw new Error("a held key needs no unlock");
      },
    },
    ["bodytext"],
  );
  assert.deepEqual(results.bodytext, { state: "opened", text: ARTICLE, contentType: "text/plain" });
});

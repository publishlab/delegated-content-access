// @ts-check
//
// Neutral request composition for two removable extensions. The chain-key
// extension adds its carrier around omission's completed request; neither extension imports
// or otherwise references its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../core-client/DcaData.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";

test("chain-key relay preserves omission members and the client transport offer", () => {
  const clientPublicKey = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  const page = new DcaData({
    version: "1",
    resourceJWT: "header.payload.signature",
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        keys: {
          premium: [
            {
              t: "251023T1400",
              nonce: "wn",
              key: "wk",
              bind: "dca-bind-seal-omission",
            },
          ],
        },
      },
    },
    issuerData: {
      "issuer-a": {
        keyId: "key-a",
        unlockUrl: "https://issuer.example/unlock",
        sealed: {
          chainKeys: { premium: { "251023T2345": "sealed-chain" } },
        },
      },
    },
  });
  const request = new ChainKeyRequestBuilder({
    innerBuilder: new OmissionRequestBuilder({ clientPublicKey }),
  })
    .build(page, "issuer-a", ["bodytext"])
    .toObject();

  assert.deepEqual(request.extensions, [EXTENSION_NAME]);
  assert.ok(request.boundCandidates.bodytext);
  assert.deepEqual(request.clientPublicKey, clientPublicKey);
  assert.deepEqual(request.periodGeometry, { chainsPerDay: 2, periodMinutes: 15 });
  assert.deepEqual(request.sealed.chainKeys, { premium: { "251023T2345": "sealed-chain" } });
});

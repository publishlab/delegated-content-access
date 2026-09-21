// @ts-check
//
// Neutral request composition for two removable extensions. Period-chain adds
// its carrier around omission's completed request; neither extension imports
// or otherwise references its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../core-client/DcaData.js";
import { PeriodChainRequestBuilder } from "../extensions/period-chain/core-client/PeriodChainRequestBuilder.js";
import { OmissionRequestBuilder } from "../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";

test("period-chain relay preserves omission members and the client transport offer", () => {
  const clientPublicKey = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  const page = new DcaData({
    version: "1",
    resourceJWT: "header.payload.signature",
    periodChain: { chainsPerDay: 2, periodMinutes: 15 },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        aad: "a",
        keys: {
          premium: [
            {
              t: "251023T1400",
              nonce: "wn",
              key: "wk",
              bind: "dca-seal-omission-bind-v1",
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
          periodChainKeys: { premium: { "251023T2345": "sealed-chain" } },
        },
      },
    },
  });
  const request = new PeriodChainRequestBuilder({
    innerBuilder: new OmissionRequestBuilder({ clientPublicKey }),
  })
    .build(page, "issuer-a", ["bodytext"])
    .toObject();

  assert.deepEqual(request.extensions, [EXTENSION_NAME]);
  assert.ok(request.boundCandidates.bodytext);
  assert.deepEqual(request.clientPublicKey, clientPublicKey);
  assert.deepEqual(request.periodChain, { chainsPerDay: 2, periodMinutes: 15 });
  assert.deepEqual(request.sealed.periodChainKeys, { premium: { "251023T2345": "sealed-chain" } });
});

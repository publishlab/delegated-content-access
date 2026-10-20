// @ts-check
// Replay the existing baseline refusal package with optional period input off.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { selectFixtureFiles } from "../test-contract/support/fixture-manifest.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";

const files = selectFixtureFiles(
  fileURLToPath(new URL("../../verification/", import.meta.url)),
  ["fixtures/v1/baseline/issuer-admission"],
  "base-contract",
  ["2"],
);
assert.equal(files.length, 17, "every baseline refusal is selected independently");
for (const file of files) {
  const vector = JSON.parse(readFileSync(file, "utf8"));
  test(`baseline-only issuer admission: ${vector.name}`, async () => {
    let policyCalls = 0;
    let openingKeyReads = 0;
    const processor = new IssuerProcessor(
      new IssuerEngine({
        operatingIssuerNames: [vector.issuer.issuerName],
        accessPolicy: {
          decide() {
            policyCalls++;
            throw new Error("refusal reached policy");
          },
        },
      }),
      { periodKeyInput: false },
    );
    const admission = processor.admit(vector.rawBody);
    let result = admission;
    if (admission.kind === "admitted") {
      const { header } = decodeCompactJwt(admission.request.resourceJWT);
      const signing = vector.publisher.signingKeys.find((entry) => entry.kid === header.kid);
      assert.ok(signing);
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        signing.publicKeyJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      );
      result = await processor.processMiss({
        request: admission.request,
        registration: {
          kid: signing.kid,
          publicKey,
          openingKeys: {
            get() {
              openingKeyReads++;
              throw new Error("refusal reached opening key");
            },
          },
        },
      });
    }
    assert.deepEqual(result, { kind: "failure", code: vector.expected.code });
    assert.equal(policyCalls, 0);
    assert.equal(openingKeyReads, 0);
  });
}

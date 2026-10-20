// @ts-check
// Focused publisher-to-issuer evidence, not a complete profile claim. One
// publisher registration retains both algorithms at different key generations.
import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";

const ORIGIN = "https://publisher.example";
const NAME = "issuer";
const BODY = "body";
const TEXT = "The authorized original content.";
const ALGORITHMS = ["ecdh-p256", "rsa-oaep"];

async function world() {
  const signing = await signingKeypair();
  const pairs = await Promise.all(ALGORITHMS.map((algorithm) => issuerKeypair(algorithm)));
  const entries = ALGORITHMS.map((algorithm, i) => ({
    algorithm,
    privateKey: pairs[i].privateKey,
  }));
  const lookups = [];
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: {
      get(issuerName, keyId) {
        lookups.push([issuerName, keyId]);
        return issuerName === NAME ? entries[Number(keyId)] : undefined;
      },
    },
  };
  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [NAME], accessPolicy: new AllowAllPolicy() }),
    { periodKeyInput: false },
  );
  const endpoint = new UnlockEndpoint(processor);
  const renders = [];
  for (const [i, algorithm] of ALGORITHMS.entries()) {
    const sealer = new Sealer({
      origin: ORIGIN,
      clock: new Clock("2025-10-23T14:20:00Z"),
      random: new Random({ seed: i + 3 }),
      signingKeys: { signing: signing.privateKey },
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: NAME,
          keyId: String(i),
          algorithm,
          publicKey: pairs[i].publicKey,
        },
      ],
    });
    sealer.resource("resource", {});
    sealer.content(BODY, TEXT, "text/plain");
    const rendered = await sealer.seal();
    const client = new Client({ publisherOrigin: ORIGIN });
    const page = client.parse({ ...rendered.dcaData, sealedContent: rendered.sealedContent });
    renders.push({
      client,
      page,
      ciphertext: rendered.sealedContent[BODY],
      request: client.buildRequest(page, NAME, [BODY]),
    });
  }
  return {
    entries,
    lookups,
    renders,
    unlock: (request) => unlockThroughAdmission(processor, endpoint, request, registration),
  };
}

for (const [i, algorithm] of ALGORITHMS.entries()) {
  const id = i === 0 ? "ecdh-p256" : "rsa-oaep";
  test(
    `${algorithm}: its registered generation returns a key that opens the original content`,
    {
      tags: [`envelope/${id}/publisher`, `envelope/${id}/issuer`],
    },
    async () => {
      const { renders, lookups, unlock } = await world();
      const { client, page, request, ciphertext } = renders[i];
      const { status, body } = await unlock(request);
      assert.equal(status, 200);
      assert.equal(body.errors, undefined);
      assert.deepEqual(lookups, [[NAME, String(i)]], "only the selected registered generation");
      await client.applyResponse(page, NAME, body);
      assert.equal(new TextDecoder().decode(await client.decrypt(page, BODY, ciphertext)), TEXT);
    },
  );

  test(`${algorithm}: a valid blob for the other generation is refused without key fallback`, async () => {
    const { renders, lookups, unlock } = await world();
    // The blob remains valid for its original key and signed coordinate. Trying
    // that other registered key as a fallback would grant this request.
    const request = structuredClone(renders[1 - i].request);
    request.keyId = String(i);
    const { status, body } = await unlock(request);
    assert.equal(status, 200);
    assert.equal(body.keys?.contentKeys?.[BODY], undefined);
    assert.ok(body.errors?.[BODY], "opening failed rather than trying the other key");
    assert.deepEqual(lookups, [[NAME, String(i)]]);
  });
}

test("an unsupported registered algorithm refuses instead of trying an available generation", async () => {
  const { entries, renders, lookups, unlock } = await world();
  entries[1].algorithm = "invented-envelope";
  const { status, body } = await unlock(renders[1].request);
  assert.equal(status, 500);
  assert.equal(body.keys, undefined);
  assert.deepEqual(lookups, [[NAME, "1"]]);
});

test("an uppercase registered provisioning token is not an alias for its envelope", async () => {
  // `ECDH-P256` and `RSA-OAEP` are the client-bound method names. A key store
  // that records one of them for an opening key names no envelope algorithm,
  // so the issuer refuses as for any other unsupported registration.
  for (const [i, spelling] of ["ECDH-P256", "RSA-OAEP"].entries()) {
    const { entries, renders, lookups, unlock } = await world();
    entries[i].algorithm = spelling;
    const { status, body } = await unlock(renders[i].request);
    assert.equal(status, 500, spelling);
    assert.equal(body.keys, undefined, spelling);
    assert.deepEqual(lookups, [[NAME, String(i)]], spelling);
  }
});

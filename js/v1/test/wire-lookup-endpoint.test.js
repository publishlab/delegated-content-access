//
// The map itself is the attacker's too. A section that arrives as a string or
// an array still has member names, so a walk that does not ask whether it is a
// map reads index names as coordinates. That is the last test here.
//
// The issuer half runs on `demo/scenarios/world.js`'s direct family, over a real
// `IssuerKeyStore` holding a key that opens what this publisher sealed. That is
// what "no coordinate was walked" rests on here: an issuer whose
// store carries a null private key fails every walk it makes, so empty
// contentKeys says nothing about whether it walked anything. Here a walked
// coordinate comes back as a key or as a per-item failure, and both are
// asserted absent.

import test from "node:test";
import assert from "node:assert/strict";

import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { sign } from "../core-shared--publisher-issuer/jwt.js";
import { directWorld } from "../demo/scenarios/world.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { ISSUER_NAME, KEY_ID, RESOURCE_ID, SIGNING_KID } from "../demo/scenarios/fixtures.js";
import { makeRenderId } from "../test-lib/fixtures/renderId.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";

/** The origin this render is delivered from, and every blob bound under. */
const ORIGIN = "https://www.news-site.example";

/** A renderId to anchor on; the value is incidental. */
const RENDER_ID = makeRenderId(3);

/**
 * A signed request for one issuer. The envelope carries the renderId the engine
 * anchors on, so a request that reaches the walks below is one the engine was
 * willing to walk, and that lets these tests stay about the lookups.
 *
 * The signing key is the world's, whose publisher registration holds the other half:
 * the engine verifies the envelope before it opens anything, so a request that
 * reaches the lookups below has to be signed for real; a stub here would be
 * testing a gate that is not the one running.
 *
 * @param {CryptoKey} signingKey - the private half of the world's signing pair
 * @param {{ contentKeys?: any, periodKeys?: any }} [sealed]
 * @returns {Promise<object>}
 */
async function signedRequest(signingKey, sealed) {
  const resource = {
    renderId: RENDER_ID,
    origin: ORIGIN,
    issuedAt: "2025-10-23T14:00:00.000Z",
    resourceId: RESOURCE_ID,
    data: {},
  };

  const request = {
    version: "1",
    issuerName: ISSUER_NAME,
    resource,
    resourceJWT: await sign(resource, signingKey, { kid: SIGNING_KID }),
    keyId: KEY_ID,
  };

  return sealed === undefined ? request : { ...request, sealed };
}

test("a missing sealed section is a typed refusal, not a crash", async () => {
  const { keyStore, publisherRegistration, signingKeys } = await directWorld();
  const endpointProcessor = new IssuerProcessor(
    new IssuerEngine({
      accessPolicy: new AllowAllPolicy(),
    }),
  );
  const endpoint = new UnlockEndpoint(endpointProcessor);

  const { status, body } = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    await signedRequest(signingKeys.privateKey),
    publisherRegistration,
  );

  // No sealed section at all presents no coordinate, so the request is
  // refused whole and before the key store. The claim here is about the
  // shape of that refusal: a code the port maps, not a walk over an
  // absent container and not a throw out of one.
  assert.equal(status, 400);
  assert.equal(body.error, "binding_failed");
  assert.equal(body.keys, undefined, "nothing partial comes back");
  assert.equal(body.errors, undefined, "and no coordinate the request never sent is answered for");
  assert.equal(keyStore.reachCount, 0, "an empty ask reaches no opening key");
});

test("unsupported chain-only and malformed exact families stop before private work", async () => {
  const { keyStore, publisherRegistration, signingKeys } = await directWorld();
  const allow = new AllowAllPolicy();
  let policyCalls = 0;
  const endpointProcessor = new IssuerProcessor(
    new IssuerEngine({
      accessPolicy: {
        decide(claims, requested) {
          policyCalls++;
          return allow.decide(claims, requested);
        },
      },
    }),
    { exactPeriodInput: true },
  );
  const endpoint = new UnlockEndpoint(endpointProcessor);
  const cases = [
    { contentKeys: {}, periodChainKeys: { premium: { "251023T1400": "AAAA" } } },
    { contentKeys: {}, periodKeys: { premium: ["AAAA"] } },
  ];

  for (const sealed of cases) {
    const { status, body } = await unlockThroughAdmission(
      endpointProcessor,
      endpoint,
      await signedRequest(signingKeys.privateKey, sealed),
      publisherRegistration,
    );
    assert.equal(status, 400);
    assert.equal(body.error, "binding_failed");
    assert.equal(body.keys, undefined);
    assert.equal(body.errors, undefined);
  }
  assert.equal(policyCalls, 0, "neither refused shape reaches policy");
  assert.equal(keyStore.reachCount, 0, "neither refused shape reaches an opening key");
});

test("a top-level sealed section that is not a keyed map fails the whole request", async () => {
  const { keyStore, publisherRegistration, signingKeys } = await directWorld();
  let policyCalls = 0;
  const engine = new IssuerEngine({
    accessPolicy: {
      decide(claims, requested) {
        policyCalls++;
        return new AllowAllPolicy().decide(claims, requested);
      },
    },
  });
  // Capped where the padded string is well over it: a section counted as a
  // shape nobody sealed would slip past the cap on its way to becoming that
  // many error entries.
  const endpointProcessor = new IssuerProcessor(engine, {
    exactPeriodInput: true,
    limits: { maxEntries: 5 },
  });
  const endpoint = new UnlockEndpoint(endpointProcessor);

  // 'abc' has member names '0', '1', '2' and a one-character member behind
  // each; [blob] has '0'. None of these is a map, and a named request map that
  // is not a non-array object is a whole-request admission failure, so the
  // well-formed sibling in the other section is not answered either.
  const arms = [
    { section: "contentKeys", sibling: { periodKeys: { premium: { "251023T14": "AAAA" } } } },
    { section: "periodKeys", sibling: { contentKeys: { bodytext: "AAAA" } } },
  ];
  for (const { section, sibling } of arms) {
    for (const notAMap of ["abc", "x".repeat(50), ["AAAA"], 7, true]) {
      const { status, body } = await unlockThroughAdmission(
        endpointProcessor,
        endpoint,
        await signedRequest(signingKeys.privateKey, { ...sibling, [section]: notAMap }),
        publisherRegistration,
      );

      const arm = `sealed.${section} = ${JSON.stringify(notAMap)}`;
      assert.equal(status, 400, arm);
      assert.equal(body.error, "binding_failed", arm);
      assert.equal(body.keys, undefined, arm);
      assert.equal(body.errors, undefined, arm);
    }
  }

  assert.equal(policyCalls, 0, "a malformed named map never reaches policy");
  assert.equal(keyStore.reachCount, 0, "and never reaches an opening key");
});

test("the endpoint reads a raw JSON string the same as a parsed object", async () => {
  const { publisherRegistration, signingKeys } = await directWorld();
  const endpointProcessor = new IssuerProcessor(
    new IssuerEngine({
      accessPolicy: new AllowAllPolicy(),
    }),
  );
  const endpoint = new UnlockEndpoint(endpointProcessor);
  const request = await signedRequest(signingKeys.privateKey, { contentKeys: {} });

  const parsed = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    request,
    publisherRegistration,
  );
  const raw = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    JSON.stringify(request),
    publisherRegistration,
  );

  assert.deepEqual(raw, parsed);
});

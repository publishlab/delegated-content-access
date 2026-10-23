//
// Every map on the wire is keyed by a name an attacker picks: contentName,
// accessGroup, issuerName. A bare `map[name]` reaches Object.prototype, so
// 'constructor' or 'toString' resolves to a function instead of missing.
// Lookups over wire-derived objects go through Object.hasOwn.
//
// The issuer half runs on `demo/scenarios/world.js`'s direct family, over a real
// `IssuerKeyStore` holding a key that opens what this publisher sealed. That is
// what backs the claim that no coordinate was walked: an issuer whose
// store carries a null private key fails every walk it makes, so empty
// contentKeys says nothing about whether it walked anything. Here a walked
// coordinate comes back as a key or as a per-item failure, and both are
// asserted absent.

import test from "node:test";
import assert from "node:assert/strict";

import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { sign } from "../../core-shared--publisher-issuer/jwt.js";
import { directWorld } from "../../demo/scenarios/world.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { ISSUER_NAME, KEY_ID, RESOURCE_ID, SIGNING_KID } from "../../demo/scenarios/fixtures.js";
import { makeRenderId } from "../../test-lib/fixtures/renderId.js";
import { contentKeyMap, errorMap } from "../support/namedRecords.js";

/** The origin this render is delivered from, and every blob bound under. */
const ORIGIN = "https://www.news-site.example";

/** A renderId to anchor on; the value is incidental. */
const RENDER_ID = makeRenderId(3);

/**
 * A signed request for one issuer. The envelope carries the renderId the engine
 * anchors on, so a request that reaches the walks below is one the engine was
 * willing to walk, which keeps these tests about the lookups.
 *
 * The signing key is the world's, whose publisher registration holds the other half:
 * the engine verifies the envelope before it opens anything, so a request that
 * reaches the lookups below has to be signed for real; a stub here would test a
 * gate that is not the one running.
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

test("an empty sealed.contentKeys map needs no opening-key lookup", async () => {
  const { keyStore, publisherRegistration, signingKeys } = await directWorld();
  const engine = new IssuerEngine({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: new AllowAllPolicy(),
  });

  const result = await engine.unlock(
    new DcaRequest(await signedRequest(signingKeys.privateKey, { contentKeys: [] })),
    publisherRegistration,
  );

  // An empty sealed map asks for no coordinate, so no authorized operation
  // needs the registration's opening-key view.
  assert.equal(keyStore.reachCount, 0);
  assert.deepEqual(contentKeyMap(result.contentKeys), {});
  assert.deepEqual(errorMap(result.errors), {});
  assert.equal(Object.getPrototypeOf(contentKeyMap(result.contentKeys)), Object.prototype);
});

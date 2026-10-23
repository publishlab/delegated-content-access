// @ts-check
// Browser admission must precede private-key work in the selected client-bound
// extension. Keep this real-profile composition outside the base test tree.

import test from "node:test";
import assert from "node:assert/strict";
import * as ecdhProfile from "../ecdhP256.js";
import { actorWorld } from "../../../demo/scenarios/world.js";
import {
  DOMAIN,
  ORIGIN,
  SIGNING_KID,
  UNLOCK_URL,
  ISSUER_NAME,
  article,
} from "../../../demo/scenarios/fixtures.js";
import { requestFor } from "../../../test-lib/harnesses/issuer-endpoint.js";
import {
  clientPublicKey,
  cryptoMeter,
} from "../../../test-lib/fixtures/endpoint-hardening-world.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { BrowserUnlockHttp } from "../../../adapter-issuer/BrowserUnlockHttp.js";
import { sign } from "../../../core-shared--publisher-issuer/jwt.js";

const OTHER_ORIGIN = "https://other-publisher.example";

/**
 * A policy that grants everything and counts the decisions it was asked for, so
 * "refused before policy" is an assertion rather than a reading of the source.
 */
function countingPolicy() {
  const allowAll = new AllowAllPolicy();
  const asked = { count: 0 };
  return {
    asked,
    policy: {
      /** @param {any} claims @param {any} requested @param {any} input */
      decide(claims, requested, input) {
        asked.count++;
        return allowAll.decide(claims, requested, input);
      },
    },
  };
}

/**
 * Every HTTP response the browser adapter hands back while this is running,
 * headers included. The simulated network carries only status and body, so
 * "no CORS permission left the issuer" is an assertion this way rather than a
 * reading of the source.
 *
 * @returns {{ responses: any[], stop: () => void }}
 */
function adapterResponses() {
  /** @type {any[]} */
  const responses = [];
  const original = BrowserUnlockHttp.prototype.handle;
  /** @this {any} @param {any} request */
  const spy = async function (request) {
    const response = await original.call(this, request);
    responses.push(response);
    return response;
  };
  BrowserUnlockHttp.prototype.handle = spy;
  return {
    responses,
    stop() {
      BrowserUnlockHttp.prototype.handle = original;
    },
  };
}

/**
 * The CORS fields on one adapter response, by lowercase name.
 *
 * @param {any} response
 * @returns {Record<string, string>}
 */
function corsFieldsOf(response) {
  return Object.fromEntries(
    Object.entries(response?.headers ?? {}).filter(([name]) =>
      name.toLowerCase().startsWith("access-control-"),
    ),
  );
}

/**
 * Replace one byte of the signature, so the token no longer verifies under the
 * registration's key and nothing else about it changes.
 *
 * @param {string} token
 * @returns {string}
 */
function flippedSignature(token) {
  const [header, payload, signature] = token.split(".");
  return `${header}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
}

/**
 * The actor's coded profile puts exactly the refusal code and issuer name on
 * the wire. A deep equality is deliberate: an origin refusal carrying a
 * partial `keys` or `errors` section is not a refusal that returned no key
 * material.
 *
 * @param {{ status: number, body: unknown }} answer
 * @param {number} status
 * @param {string} code
 * @param {string|null} [issuerName] - null when the adapter or core port owns
 *   the response and therefore has no actor issuer name to put on it
 */
function assertCodedRefusal(answer, status, code, issuerName = ISSUER_NAME) {
  assert.equal(answer.status, status);
  assert.deepEqual(
    answer.body,
    issuerName === null ? { error: code } : { error: code, issuerName },
  );
}

/**
 * A resourceJWT the registered publisher really signed, carrying one changed
 * origin. The demo publisher cannot seal an http origin at all, so the claim
 * this boundary refuses has to be signed here: this tests the
 * issuer's reading of a verified claim, not the publisher's refusal to make it.
 *
 * @param {any} stage
 * @param {any} page
 * @param {string} origin
 * @returns {Promise<any>}
 */
async function requestSignedFor(stage, page, origin) {
  const resourceJWT = await sign(
    { ...page.asJson().resource, origin },
    stage.signingKeys.privateKey,
    {
      kid: SIGNING_KID,
    },
  );
  return { ...requestFor(page), resourceJWT };
}

test("client-bound agreement follows signature and both origin checks", async () => {
  let seals = 0;
  const { asked, policy } = countingPolicy();
  const stage = await actorWorld({
    domains: [DOMAIN],
    signingKids: { [DOMAIN]: [SIGNING_KID] },
    registrationOrigins: true,
    accessPolicy: policy,
    transportMode: "client-bound",
    clientBoundProfile: {
      ...ecdhProfile,
      seal(key, options) {
        seals++;
        return ecdhProfile.seal(key, options);
      },
    },
  });
  const page = await stage.publisher.render(article("A"));
  const request = { ...requestFor(page), clientPublicKey: await clientPublicKey() };
  const restricted = {
    ...(await requestSignedFor(stage, page, OTHER_ORIGIN)),
    clientPublicKey: request.clientPublicKey,
  };
  const cases = [
    { request, origin: OTHER_ORIGIN, status: 403, code: "origin_refused" },
    { request: restricted, origin: OTHER_ORIGIN, status: 403, code: "origin_refused" },
    {
      request: { ...request, resourceJWT: flippedSignature(request.resourceJWT) },
      origin: ORIGIN,
      status: 400,
      code: "bad_signature",
    },
  ];
  for (const refusal of cases) {
    const meter = cryptoMeter();
    const spy = adapterResponses();
    let answer;
    try {
      answer = await stage.network.post(UNLOCK_URL, refusal.request, { origin: refusal.origin });
    } finally {
      meter.stop();
      spy.stop();
    }
    assertCodedRefusal(answer, refusal.status, refusal.code);
    assert.equal(seals, 0, "refusal never reaches the selected transport profile");
    assert.equal(meter.counts.generateKey, 0, "no ephemeral private key is generated");
    assert.equal(meter.counts.deriveBits, 0, "no private-key agreement is performed");
    assert.equal(asked.count, 0, "no access policy is consulted");
    assert.equal(stage.keyStores.primary.reachCount, 0, "no publisher opening key is reached");
    assert.equal(spy.responses.length, 1);
    assert.deepEqual(corsFieldsOf(spy.responses[0]), {});
  }
  const meter = cryptoMeter();
  let granted;
  try {
    granted = await stage.network.post(UNLOCK_URL, request, { origin: ORIGIN });
  } finally {
    meter.stop();
  }
  assert.equal(granted.status, 200);
  assert.equal(Object.hasOwn(granted.body.transport, "mode"), false);
  assert.equal(seals, 1, "the admitted request still uses its selected transport");
  assert.equal(meter.counts.generateKey, 1);
  assert.ok(meter.counts.deriveBits > 0);
});

test("post-origin transport refusals preserve exact CORS and caller/server status classes", async (t) => {
  for (const [name, config, offer, status, code] of [
    [
      "invalid host mode",
      {
        transportPolicy: { modeFor: () => "neither" },
        clientBoundProfile: { ...ecdhProfile, RANDOM_REQUIRED: false },
      },
      undefined,
      500,
      "bad_transport_policy",
    ],
    [
      "missing offer",
      {
        transportMode: "client-bound",
        clientBoundProfile: { ...ecdhProfile, RANDOM_REQUIRED: false },
      },
      undefined,
      400,
      "client_key_required",
    ],
    [
      "RSA offer at ECDH endpoint",
      {
        transportMode: "client-bound",
        clientBoundProfile: { ...ecdhProfile, RANDOM_REQUIRED: false },
      },
      { kty: "RSA", n: "AQ", e: "AQAB" },
      400,
      "bad_client_key",
    ],
    [
      "malformed EC offer",
      {
        transportMode: "client-bound",
        clientBoundProfile: { ...ecdhProfile, RANDOM_REQUIRED: false },
      },
      { kty: "EC", crv: "P-256", x: "bad", y: "bad" },
      400,
      "bad_client_key",
    ],
    [
      "host transport failure",
      {
        transportMode: "client-bound",
        clientBoundProfile: {
          METHOD: "test-failure",
          RANDOM_REQUIRED: false,
          seal() {
            throw new Error("host transport fault");
          },
        },
      },
      {},
      500,
      "internal_error",
    ],
  ]) {
    await t.test(name, async () => {
      const stage = await actorWorld(config);
      const page = await stage.publisher.render(article("A"));
      const request = requestFor(page);
      if (offer !== undefined) request.clientPublicKey = offer;
      const spy = adapterResponses();
      let response;
      try {
        response = await stage.network.post(UNLOCK_URL, request, { origin: ORIGIN });
      } finally {
        spy.stop();
      }
      assert.equal(response.status, status, name);
      if (code !== "internal_error") assert.equal(response.body.error, code, name);
      assert.equal(stage.keyStores.primary.reachCount, 0, name);
      assert.equal(spy.responses.length, 1);
      assert.deepEqual(
        corsFieldsOf(spy.responses[0]),
        {
          "access-control-allow-origin": ORIGIN,
          "access-control-allow-credentials": "true",
        },
        name,
      );
      assert.equal(spy.responses[0].headers["cache-control"], "no-store");
      assert.equal(spy.responses[0].headers.vary, "Origin");
    });
  }
});

// @ts-check
// Sibling to base suite: js/v1/test/endpoint-hardening.test.js
//
// Client-bound transport cases at the same admission boundaries as the base
// endpoint-hardening suite.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { requestFor } from "../../../test-lib/harnesses/issuer-endpoint.js";
import {
  ARTICLE_GROUP,
  BODYTEXT,
  clientPublicKey,
  cryptoMeter,
  ISSUER_NAME,
  PREMIUM,
  PUBLISHER_ORIGIN,
  UNLOCK_URL,
  world,
} from "../../../test-lib/fixtures/endpoint-hardening-world.js";
import * as clientBoundEcdh from "../ecdhP256.js";

describe("The auth gate, ahead of client-bound agreement", () => {
  test("the gate is ahead of the transport agreement, not merely ahead of the port", async () => {
    const { render, network, random, serverWith } = await world();
    const page = await render();

    const server = serverWith({
      transportMode: "client-bound",
      clientBoundProfile: clientBoundEcdh,
      random,
      requireAuthentication: true,
    });
    server.grant("alice", { entitlements: ["premium"] });

    // The most expensive thing this server does per request is agree a
    // transport key: an ephemeral keypair and an ECDH agreement, spent before
    // anything is opened and spent whatever the request turns out to be. A
    // gate that sat anywhere after it would leave that spend open to a caller
    // who never identified themselves, and every assertion in the test above
    // would still hold: the endpoint there is direct and agrees nothing.
    const request = {
      ...requestFor(page, ISSUER_NAME, [BODYTEXT]),
      clientPublicKey: await clientPublicKey(),
    };

    const meter = cryptoMeter();
    /** @type {any} */
    let anonymous;
    try {
      anonymous = await network.post(UNLOCK_URL, request, { from: {}, origin: PUBLISHER_ORIGIN });
    } finally {
      meter.stop();
    }

    assert.equal(anonymous.status, 401);
    assert.equal(anonymous.body.error, "unauthenticated");
    assert.equal(
      meter.counts.generateKey,
      0,
      "no ephemeral pair was made for a caller who is nobody",
    );
    assert.equal(meter.counts.deriveBits, 0, "and nothing was agreed with them");
    assert.equal(meter.counts.asymmetric, 0);

    // The same request with a credential: the agreement happens, so the zero
    // above is the gate's doing rather than the mode's.
    const spent = cryptoMeter();
    /** @type {any} */
    let granted;
    try {
      granted = await network.post(UNLOCK_URL, request, {
        from: {},
        credential: { user: "alice" },
        origin: PUBLISHER_ORIGIN,
      });
    } finally {
      spent.stop();
    }

    assert.equal(granted.status, 200);
    assert.equal(granted.body.transport.mode, "client-bound");
    assert.equal(spent.counts.generateKey, 1, "one ephemeral pair, once the caller was somebody");
    assert.ok(spent.counts.deriveBits > 0);
  });
});

describe("The entry caps, ahead of client-bound agreement", () => {
  test("structural admission bounds the request ahead of the transport agreement", async () => {
    const { render, network, random, serverWith } = await world();
    const page = await render();

    serverWith({
      transportMode: "client-bound",
      clientBoundProfile: clientBoundEcdh,
      random,
      limits: { maxEntries: 4, maxEntriesPerGroup: 2 },
    });

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
    const padded = structuredClone(request);
    const [firstPeriod] = Object.keys(padded.sealed.periodKeys[ARTICLE_GROUP]);
    for (let index = 0; index < 50; index++) {
      padded.sealed.periodKeys[ARTICLE_GROUP][`991023T${String(index).padStart(2, "0")}`] =
        padded.sealed.periodKeys[ARTICLE_GROUP][firstPeriod];
    }
    padded.clientPublicKey = await clientPublicKey();

    const meter = cryptoMeter();
    /** @type {any} */
    let answer;
    try {
      answer = await network.post(UNLOCK_URL, padded, { from: {}, origin: PUBLISHER_ORIGIN });
    } finally {
      meter.stop();
    }

    // Structural admission runs at stage 2, ahead of the stage-3 transport
    // preflight, so a request refused on shape costs no agreement at all:
    // neither the verification and unseal it never reaches, nor the one
    // client-bound agreement per request. The refusal is the cap's,
    // and it is written down here rather than implied by a direct-transport
    // test that never agrees anything.
    assert.equal(answer.status, 400);
    assert.equal(answer.body.error, "too_many_entries");
    assert.equal(meter.counts.verify, 0, "no envelope was verified");
    assert.equal(
      meter.counts.deriveBits,
      0,
      "and nothing was agreed: admission refused before preflight",
    );
    assert.equal(meter.counts.generateKey, 0, "no transport keypair was generated");

    // Structural admission is ahead of authentication in this deployment:
    // the over-cap request is refused for its shape before any caller or
    // transport capability is considered.
    const {
      render: renderAgain,
      network: other,
      random: entropy,
      serverWith: standUp,
    } = await world();
    const gatedPage = await renderAgain();
    standUp({
      transportMode: "client-bound",
      clientBoundProfile: clientBoundEcdh,
      random: entropy,
      requireAuthentication: true,
      limits: { maxEntries: 4, maxEntriesPerGroup: 2 },
    });

    const gatedRequest = structuredClone(requestFor(gatedPage, ISSUER_NAME, [BODYTEXT, PREMIUM]));
    const [gatedFirstPeriod] = Object.keys(gatedRequest.sealed.periodKeys[ARTICLE_GROUP]);
    for (let index = 0; index < 50; index++) {
      gatedRequest.sealed.periodKeys[ARTICLE_GROUP][`991023T${String(index).padStart(2, "0")}`] =
        gatedRequest.sealed.periodKeys[ARTICLE_GROUP][gatedFirstPeriod];
    }
    gatedRequest.clientPublicKey = await clientPublicKey();

    const gated = cryptoMeter();
    /** @type {any} */
    let refused;
    try {
      refused = await other.post(UNLOCK_URL, gatedRequest, { from: {}, origin: PUBLISHER_ORIGIN });
    } finally {
      gated.stop();
    }

    assert.equal(refused.status, 400);
    assert.equal(refused.body.error, "too_many_entries");
    assert.equal(gated.counts.asymmetric, 0);
  });
});

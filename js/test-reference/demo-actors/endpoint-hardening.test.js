import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { contentKeyMap, keyAt } from "../support/namedRecords.js";
import {
  ARTICLE_GROUP,
  BODYTEXT,
  cryptoMeter,
  flipSignature,
  HEALTH_URL,
  ISSUER_NAME,
  PREMIUM,
  PUBLISHER_ORIGIN,
  refusalLog,
  UNLOCK_URL,
  world,
} from "../../test-lib/fixtures/endpoint-hardening-world.js";

describe("The refusal observer, application-side", () => {
  test("the log says everything the uniform wire does not, wherever the refusal was made", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    // Observation is the application's now, not the port's: one log, injected
    // as the server's own, catches every refusal the server makes whatever
    // stage turned the request away.
    const log = refusalLog();
    const server = serverWith({
      requireAuthentication: true,
      errorDetail: "uniform",
      limits: { maxEntries: 32, maxEntriesPerGroup: 8 },
      log,
    });
    server.grant("bob", {});

    // Admission gate: a caller this server does not know, turned away before
    // anything is read.
    const gate = await network.post(UNLOCK_URL, requestFor(page, ISSUER_NAME, [BODYTEXT]), {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });

    // Admission processor: a known caller, but a request whose shape the caps
    // refuse ahead of the engine.
    const padded = structuredClone(requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]));
    const blob = keyAt(padded.sealed.periodKeys, { accessGroup: ARTICLE_GROUP });
    for (let index = 0; index < 50; index++) {
      padded.sealed.periodKeys.push({
        accessGroup: ARTICLE_GROUP,
        period: `991023T${String(Math.floor(index / 60)).padStart(2, "0")}${String(index % 60).padStart(2, "0")}`,
        key: blob,
      });
    }
    const structural = await network.post(UNLOCK_URL, padded, {
      from: {},
      credential: { user: "bob" },
      origin: PUBLISHER_ORIGIN,
    });

    // Endpoint miss: a known caller asking for premium they are not entitled
    // to, refused by the policy behind the endpoint.
    const denied = await network.post(UNLOCK_URL, requestFor(page, ISSUER_NAME, [PREMIUM]), {
      from: {},
      credential: { user: "bob" },
      origin: PUBLISHER_ORIGIN,
    });

    // Nothing on the wire tells the three apart: one uniform body under the
    // uniform setting, whatever the refusal was for.
    for (const answer of [gate, structural, denied]) {
      assert.deepEqual(answer.body, { error: "rejected" });
    }
    assert.deepEqual([gate.status, structural.status, denied.status], [401, 400, 401]);

    // And the log keeps every distinction the caller was not given, each with
    // its true code: the gate, the structural admission, and the endpoint.
    assert.deepEqual(
      log.entries.map((entry) => entry.code),
      ["unauthenticated", "too_many_entries", "denied"],
    );
    assert.deepEqual(
      log.entries.map((entry) => entry.status),
      [401, 400, 401],
    );

    // The counters agree: three refusals, and the one that was an access
    // decision named as a denial too.
    assert.equal(server.stats().refusals, 3);
    assert.equal(server.stats().denials, 1);
    assert.equal(server.stats().faults, 0);
    assert.equal(server.stats().grants, 0);
  });
});

describe("The demo issuer's raw document route", () => {
  test("null business data is refused as bad configuration", async () => {
    const { serverWith } = await world();
    assert.throws(
      () => serverWith({ businessData: null }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("the body cap counts original whitespace and malformed JSON is refused at admission", async () => {
    const { network, render, serverWith } = await world();
    let documentHandler;
    const serveDocument = network.serveDocument.bind(network);
    network.serveDocument = (url, handler) => {
      documentHandler = handler;
      return serveDocument(url, handler);
    };
    const page = await render();
    const request = requestFor(page, ISSUER_NAME, [BODYTEXT]);
    const compact = JSON.stringify(request);
    const cap = compact.length;
    serverWith({ limits: { maxBodyBytes: cap } });
    assert.equal(typeof documentHandler, "function");

    const context = {
      origin: PUBLISHER_ORIGIN,
      contentType: "application/json",
      credential: undefined,
    };
    const admitted = await documentHandler(compact, context);
    assert.equal(admitted.status, 200, "the compact serialized document fits its byte cap");
    const overCap = await documentHandler(` ${compact} `, context);
    assert.equal(overCap.status, 413);
    assert.equal(overCap.body.error, "body_too_large");

    const malformed = await documentHandler("{", context);
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.error, "invalid_json");
  });

  test("a captured raw document reaches an ordinary successful admission", async () => {
    const { network, render, serverWith } = await world();
    let documentHandler;
    const serveDocument = network.serveDocument.bind(network);
    network.serveDocument = (url, handler) => {
      documentHandler = handler;
      return serveDocument(url, handler);
    };
    const page = await render();
    serverWith();
    const answer = await documentHandler(
      JSON.stringify(requestFor(page, ISSUER_NAME, [BODYTEXT])),
      { origin: PUBLISHER_ORIGIN, contentType: "application/json" },
    );
    assert.equal(answer.status, 200);
    assert.ok(answer.headers["access-control-allow-origin"]);
  });
});

describe("The auth gate, ahead of any asymmetric operation", () => {
  test("an unauthenticated unlock costs the issuer no asymmetric crypto", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    const server = serverWith({ requireAuthentication: true });
    server.grant("alice", { entitlements: ["premium"] });

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
    const caller = { name: "a client" };

    const meter = cryptoMeter();
    /** @type {any} */
    let anonymous;
    /** @type {any} */
    let flood;
    try {
      anonymous = await network.post(UNLOCK_URL, request, {
        from: caller,
        origin: PUBLISHER_ORIGIN,
      });
      // The flood: junk that is not a request at all. Structural admission
      // rejects it before JWT selection, authentication or asymmetric work.
      flood = await network.post(
        UNLOCK_URL,
        { version: "1", sealed: { contentKeys: [{ contentName: "a", key: "b" }] } },
        { from: caller, origin: PUBLISHER_ORIGIN },
      );
    } finally {
      meter.stop();
    }

    assert.equal(anonymous.status, 401);
    assert.equal(anonymous.body.error, "unauthenticated");
    assert.equal(flood.status, 400);
    assert.equal(flood.body.error, "out_of_scope_issuer");

    assert.equal(meter.counts.asymmetric, 0, "nothing was verified, agreed or decrypted");
    assert.equal(meter.counts.verify, 0);
    assert.equal(meter.counts.digest, 0, "structural admission and the auth gate need no hash");

    // The gate is an admission decision, counted where the fallback's refusal
    // is counted: nothing was decided about access, so nothing was denied.
    assert.equal(server.stats().refusals, 2);
    assert.equal(server.stats().denials, 0);
    assert.equal(server.stats().grants, 0);

    // The same request with a credential: through the gate, and the crypto
    // that was avoided is spent.
    const spent = cryptoMeter();
    /** @type {any} */
    let granted;
    try {
      granted = await network.post(UNLOCK_URL, request, {
        from: caller,
        credential: { user: "alice" },
        origin: PUBLISHER_ORIGIN,
      });
    } finally {
      spent.stop();
    }

    assert.equal(granted.status, 200);
    assert.deepEqual(Object.keys(contentKeyMap(granted.body.keys.contentKeys)), [
      BODYTEXT,
      PREMIUM,
    ]);
    // Once: the browser boundary's verified claims are reused by the engine
    // for this same admitted request. What the gate above buys is unchanged:
    // an unidentified caller pays for neither verification nor unsealing.
    assert.equal(
      spent.counts.verify,
      1,
      "the resource envelope is verified once and its claims are reused",
    );
    assert.ok(spent.counts.asymmetric > 1, "and the unseals behind it");
  });

  test("an issuer that was never told to require a caller still answers one", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    // Configuration turns the gate on, and it changes no protocol: without it
    // the public bodytext is still served to nobody in particular, which is
    // what the rest of the suite runs.
    serverWith({});

    const answer = await network.post(UNLOCK_URL, requestFor(page, ISSUER_NAME, [BODYTEXT]), {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(answer.status, 200);
    assert.deepEqual(Object.keys(contentKeyMap(answer.body.keys.contentKeys)), [BODYTEXT]);
  });

  test("a uniform server says nothing about who it turned away", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    const server = serverWith({ requireAuthentication: true, errorDetail: "uniform" });
    server.grant("bob", {});

    const request = requestFor(page, ISSUER_NAME, [PREMIUM]);

    const anonymous = await network.post(UNLOCK_URL, request, {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });
    const known = await network.post(UNLOCK_URL, request, {
      from: {},
      credential: { user: "bob" },
      origin: PUBLISHER_ORIGIN,
    });

    // One is "we do not know you", the other "you may not have this". The
    // statuses agree by the spec's own mapping, and under a uniform issuer the
    // bodies do too - so the endpoint cannot be used to enumerate users.
    assert.equal(anonymous.status, 401);
    assert.equal(known.status, 401);
    assert.deepEqual(JSON.stringify(anonymous.body), JSON.stringify(known.body));
    assert.deepEqual(anonymous.body, { error: "rejected" });
  });

  test("an unidentified caller costs the primary no probe", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    network.serve(HEALTH_URL, () => ({
      status: 200,
      body: { healthy: true, issuerName: "primary" },
    }));

    const server = serverWith({
      role: "fallback",
      healthCheckUrl: HEALTH_URL,
      requireAuthentication: true,
    });
    server.grant("alice", { entitlements: ["premium"] });

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT]);

    const anonymous = await network.post(UNLOCK_URL, request, {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(anonymous.status, 401);
    assert.equal(anonymous.body.error, "unauthenticated");
    assert.equal(
      server.stats().probes,
      0,
      "the primary heard nothing about a caller who is nobody",
    );
    assert.equal(network.stats()[HEALTH_URL], undefined, "nothing reached the health url at all");

    // With a credential the probe happens - and comes back healthy, so this
    // fallback refuses for the reason it exists to refuse for. Two different
    // refusals, and only the second one cost the primary anything.
    const known = await network.post(UNLOCK_URL, request, {
      from: {},
      credential: { user: "alice" },
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(known.status, 403);
    assert.equal(known.body.error, "primary_healthy");
    assert.equal(server.stats().probes, 1);
  });
});

describe("The entry caps, ahead of the unseal", () => {
  test("the caps reach the server the same way, and count as refusals", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    const server = serverWith({
      limits: { maxEntries: 4, maxEntriesPerGroup: 2 },
      errorDetail: "uniform",
    });

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
    const padded = structuredClone(request);
    const blob = keyAt(padded.sealed.periodKeys, { accessGroup: ARTICLE_GROUP });
    for (let index = 0; index < 50; index++) {
      padded.sealed.periodKeys.push({
        accessGroup: ARTICLE_GROUP,
        period: `991023T${String(Math.floor(index / 60)).padStart(2, "0")}${String(index % 60).padStart(2, "0")}`,
        key: blob,
      });
    }

    const meter = cryptoMeter();
    /** @type {any} */
    let answer;
    try {
      answer = await network.post(UNLOCK_URL, padded, { from: {}, origin: PUBLISHER_ORIGIN });
    } finally {
      meter.stop();
    }

    assert.equal(answer.status, 400);
    assert.deepEqual(answer.body, { error: "rejected" });
    assert.equal(meter.counts.asymmetric, 0);

    // A cap is refused inside the port and the server still counts it, because
    // the record of what a deployment did is kept in one place and a caller
    // that got nothing does not care which layer said so.
    assert.equal(server.stats().requests, 1);
    assert.equal(server.stats().refusals, 1);
    assert.equal(server.stats().denials, 0, "a cap is not an access decision");
    assert.equal(server.stats().grants, 0);
  });
});

describe("The fallback health gate, behind the verified render", () => {
  test("an invalid signature reaches no probe or health read, cold and primed", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    network.serve(HEALTH_URL, () => ({
      status: 200,
      body: { healthy: true, issuerName: "primary" },
    }));

    const server = serverWith({
      role: "fallback",
      healthCheckUrl: HEALTH_URL,
    });

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT]);
    const forged = { ...request, resourceJWT: flipSignature(request.resourceJWT) };

    // The fallback has asked the primary nothing yet, so a probe is the only
    // way it could answer for the primary at all.
    const refused = await network.post(UNLOCK_URL, forged, { from: {}, origin: PUBLISHER_ORIGIN });

    assert.equal(refused.status, 400);
    assert.equal(
      refused.body.error,
      "bad_signature",
      "the signature is what turned it away, not the primary being up",
    );
    assert.equal(server.stats().probes, 0);
    assert.equal(server.stats().healthReads, 0);
    assert.equal(network.stats()[HEALTH_URL], undefined, "nothing reached the health url at all");

    // An admitted request primes the health gate, then the invalid signature
    // still refuses without a probe or health read.
    const admitted = await network.post(UNLOCK_URL, request, {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });
    assert.equal(admitted.status, 403);
    assert.equal(admitted.body.error, "primary_healthy");
    const before = server.stats();
    assert.equal(before.probes, 1);

    const again = await network.post(UNLOCK_URL, forged, { from: {}, origin: PUBLISHER_ORIGIN });

    assert.equal(again.status, 400);
    assert.equal(again.body.error, "bad_signature");
    assert.equal(server.stats().probes - before.probes, 0);
    assert.equal(
      server.stats().healthReads - before.healthReads,
      0,
      "signature refusal precedes the health read",
    );
  });

  test("an admitted request is the one that reaches the gate, and a healthy primary refuses it there", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    network.serve(HEALTH_URL, () => ({
      status: 200,
      body: { healthy: true, issuerName: "primary" },
    }));

    const server = serverWith({ role: "fallback", healthCheckUrl: HEALTH_URL });

    const answer = await network.post(UNLOCK_URL, requestFor(page, ISSUER_NAME, [BODYTEXT]), {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });

    assert.equal(answer.status, 403);
    assert.equal(answer.body.error, "primary_healthy");
    assert.equal(
      server.stats().probes,
      1,
      "the gate is reached from cold by the request that got past everything else",
    );
    assert.equal(server.stats().refusals, 1);
    assert.equal(server.stats().grants, 0);
  });

  test("an unhealthy primary lets that same request through to a normal answer", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    network.serve(HEALTH_URL, () => ({ status: 503, body: { healthy: false } }));

    const server = serverWith({ role: "fallback", healthCheckUrl: HEALTH_URL });

    const answer = await network.post(UNLOCK_URL, requestFor(page, ISSUER_NAME, [BODYTEXT]), {
      from: {},
      origin: PUBLISHER_ORIGIN,
    });

    assert.equal(answer.status, 200);
    assert.equal(typeof keyAt(answer.body.keys.contentKeys, { contentName: BODYTEXT }), "string");
    assert.equal(server.stats().probes, 1);
    assert.equal(server.stats().grants, 1);
  });
});

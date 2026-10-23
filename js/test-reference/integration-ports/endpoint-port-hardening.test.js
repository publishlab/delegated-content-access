import test, { describe, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { utf8Encode } from "../../core-shared/codec.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { referenceIssuerEndpointDriver } from "../../test-contract/issuer-endpoint/bindings/reference-issuer-endpoint-binding.js";
import { dcaTestBinding as fixtureBinding } from "../../test-contract/issuer-endpoint/bindings/fixture-issuer-endpoint-binding.js";
import {
  ARTICLE_GROUP,
  BODYTEXT,
  cryptoMeter,
  flipSignature,
  ISSUER_NAME,
  PREMIUM,
  PUBLISHER_ORIGIN,
  refusalLog,
  UNLOCK_URL,
  VIDEO,
  world,
} from "../../test-lib/fixtures/endpoint-hardening-world.js";
import { contentKeyMap, errorMap, periodKeyMap } from "../support/namedRecords.js";

describe("Uniform error bodies", () => {
  test("a uniform issuer answers every refusal with one body, and only the status differs", async () => {
    const { render, endpointWith } = await world();
    const page = await render();

    const { endpoint, registration } = endpointWith({ errorDetail: "uniform" });

    // Four ways to be refused, three of the classes the security model names.
    const clean = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);

    // Invalid request: the signature over the resource does not hold, so there
    // is no verified renderId and nothing in the request can be anchored.
    const tampered = { ...clean, resourceJWT: flipSignature(clean.resourceJWT) };

    // Access denied: premium asked for by nobody in particular.
    const denied = requestFor(page, ISSUER_NAME, [PREMIUM]);

    // Unknown content: a name the publisher sealed and this issuer has never
    // been told about, asked for on its own so nothing is granted. Its blobs
    // are the publisher's own and sit at the coordinate they were sealed at,
    // so the request is sound and the refusal is the policy's.
    const unknownContent = requestFor(page, ISSUER_NAME, [VIDEO]);

    // Unknown key: the keyId probe, a different door on the same issuer.
    const unknownKey = structuredClone(clean);
    unknownKey.keyId = "2019-01";

    // Malformed document.
    const malformed = '{"version":"1"';

    // Read through `handleDocument`, so the in-process envelope carries the
    // true `code` beside the response. `post` would hand back the response
    // alone, which is the wire and says nothing. The malformed case is a raw
    // document already, so it is passed as written rather than re-serialised.
    const envelopes = {
      tampered: await endpoint.handleDocument(JSON.stringify(tampered), registration),
      denied: await endpoint.handleDocument(JSON.stringify(denied), registration),
      unknownContent: await endpoint.handleDocument(JSON.stringify(unknownContent), registration),
      unknownKey: await endpoint.handleDocument(JSON.stringify(unknownKey), registration),
      malformed: await endpoint.handleDocument(malformed, registration),
    };
    const answers = Object.fromEntries(
      Object.entries(envelopes).map(([name, envelope]) => [name, envelope.response]),
    );

    // An unknown opening key is an operational failure; malformed input and
    // a complete denial remain terminal.
    assert.deepEqual(
      Object.fromEntries(Object.entries(answers).map(([name, answer]) => [name, answer.status])),
      {
        tampered: 400,
        denied: 401,
        unknownContent: 401,
        unknownKey: 503,
        malformed: 400,
      },
    );

    // And the bodies are one body. Compared as written rather than against a
    // literal: uniformity is a property between answers, so the assertion has
    // to be between them.
    const bodies = new Set(Object.values(answers).map((answer) => JSON.stringify(answer.body)));
    assert.equal(bodies.size, 1, "nothing on the wire separates one refusal from another");
    for (const answer of Object.values(answers)) {
      assert.deepEqual(
        Object.keys(answer.body),
        ["error"],
        "one member, and no detail hung off it",
      );
      assert.deepEqual(answer.body, { error: "rejected" });
      assert.equal(answer.body.keys, undefined, "nothing partial comes back");
      assert.equal(answer.body.errors, undefined);
    }

    // The port's structured result carries the other half of the claim: the
    // true code rides in the envelope beside the uniform response, for the
    // application to observe. The wire never carried these; the port did,
    // and only in-process.
    assert.deepEqual(
      Object.values(envelopes).map((envelope) => envelope.code),
      ["bad_signature", "denied", "denied", "unknown_key", "invalid_json"],
    );
  });

  test("the coded default is the probe the recommendation is about", async () => {
    const { render, endpointWith } = await world();
    const page = await render();

    const { processor, endpoint, registration } = endpointWith({});
    const clean = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);

    const tampered = { ...clean, resourceJWT: flipSignature(clean.resourceJWT) };

    const unknownKey = structuredClone(clean);
    unknownKey.keyId = "2019-01";

    const first = await unlockThroughAdmission(processor, endpoint, tampered, registration);
    const second = await unlockThroughAdmission(processor, endpoint, unknownKey, registration);

    // The default body retains the code for a host integrating this port.
    assert.equal(first.status, 400);
    assert.equal(second.status, 503);
    assert.equal(first.body.error, "bad_signature");
    assert.equal(second.body.error, "unknown_key");
    assert.notEqual(JSON.stringify(first.body), JSON.stringify(second.body));
  });

  test("a granted request is untouched by the uniform setting", async () => {
    const { render, endpointWith } = await world();
    const page = await render();

    const {
      processor: uniformProcessor,
      endpoint: uniform,
      registration,
    } = endpointWith({ errorDetail: "uniform" });
    const { processor: codedProcessor, endpoint: coded } = endpointWith({});

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT]);
    const one = await unlockThroughAdmission(
      uniformProcessor,
      uniform,
      JSON.stringify(request),
      registration,
    );
    const other = await unlockThroughAdmission(
      codedProcessor,
      coded,
      JSON.stringify(request),
      registration,
    );

    assert.equal(one.status, 200);
    assert.deepEqual(Object.keys(contentKeyMap(one.body.keys.contentKeys)), [BODYTEXT]);
    assert.deepEqual(
      JSON.stringify(one.body),
      JSON.stringify(other.body),
      "the setting is about refusals only",
    );
  });

  test("an error detail this port has no meaning for is refused at construction", async () => {
    const { endpointWith } = await world();

    assert.throws(
      () => endpointWith({ errorDetail: "terse" }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
    assert.throws(
      () => endpointWith({ maxBodyBytes: 4096 }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
      "the caps live under `limits`, and a cap the port never read would be worse than none",
    );
    assert.throws(
      () => endpointWith({ limits: { maxBodyBytes: 0 } }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
    assert.throws(
      () => endpointWith({ limits: { maxEntries: -1 } }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
    assert.throws(
      () => endpointWith({ limits: { maxBlobs: 10 } }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
  });
});

describe("The body cap, ahead of the parse", () => {
  test("a document over the cap is refused before it is parsed, verified or unsealed", async () => {
    const { render, endpointWith, asked } = await world();
    const page = await render();

    const document = JSON.stringify(requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]));
    const size = utf8Encode(document).length;

    const { processor, endpoint, registration } = endpointWith({
      limits: { maxBodyBytes: size - 1 },
    });

    const meter = cryptoMeter();
    /** @type {any} */
    let refused;
    /** @type {any} */
    let junk;
    try {
      refused = await unlockThroughAdmission(processor, endpoint, document, registration);
      // The same cap, over something that is not JSON at all. If the port
      // parsed first, this would come back `invalid_json` and the two
      // answers would differ - which is how "before parsing" is asserted
      // rather than asserted about.
      junk = await unlockThroughAdmission(processor, endpoint, "x".repeat(size + 1), registration);
    } finally {
      meter.stop();
    }

    assert.equal(refused.status, 413);
    assert.equal(refused.body.error, "body_too_large");
    assert.deepEqual(
      JSON.stringify(junk),
      JSON.stringify(refused),
      "the parse never ran, so it cannot have failed",
    );

    assert.equal(asked.engine, 0, "the engine was never reached");
    assert.equal(meter.counts.asymmetric, 0, "no signature was verified and no blob was opened");
    assert.equal(meter.counts.digest, 0, "and nothing was hashed on the way to refusing it");
  });

  test("the cap is bytes, and a document at it is served", async () => {
    const { render, endpointWith, asked } = await world();
    const page = await render();

    const document = JSON.stringify(requestFor(page, ISSUER_NAME, [BODYTEXT]));
    const size = utf8Encode(document).length;

    // Exactly at the cap: an answer, not a refusal.
    const { processor, endpoint, registration } = endpointWith({ limits: { maxBodyBytes: size } });
    const served = await unlockThroughAdmission(processor, endpoint, document, registration);
    assert.equal(served.status, 200);
    assert.equal(asked.engine, 1);

    // A document short enough by JavaScript's count and too long by the wire's.
    // A cap counted in string length would let this through; the wire carries
    // bytes, so it is counted in bytes.
    const wide = `{"version":"1","note":"${"å".repeat(20)}"}`;
    assert.ok(
      wide.length < 60 && utf8Encode(wide).length > 60,
      "the two counts disagree, which is the point",
    );

    const { processor: overWideProcessor, endpoint: overWideEndpoint } = endpointWith({
      limits: { maxBodyBytes: 60 },
    });
    const overWide = await unlockThroughAdmission(
      overWideProcessor,
      overWideEndpoint,
      wide,
      registration,
    );
    assert.equal(overWide.status, 413);
  });

  test("a parsed object is not a document, and the byte cap says nothing about one", async () => {
    const { render, endpointWith, asked } = await world();
    const page = await render();

    // A library caller hands over an object. Nothing crossed a wire, so there
    // are no bytes to measure - measuring would mean serialising it here,
    // which is the work the cap exists to avoid. The entry caps still apply,
    // and they are what bounds this path.
    const { processor, endpoint, registration } = endpointWith({ limits: { maxBodyBytes: 1 } });
    const answer = await unlockThroughAdmission(
      processor,
      endpoint,
      requestFor(page, ISSUER_NAME, [BODYTEXT]),
      registration,
    );

    assert.equal(answer.status, 200);
    assert.equal(asked.engine, 1);
  });

  test("the browser path caps the body that crossed, before it is admitted", async () => {
    const { render, network, serverWith } = await world();
    const page = await render();

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT]);
    const size = utf8Encode(JSON.stringify(request)).length;

    // One byte more, made by widening a value the request already carries:
    // the same members in the same order, one character longer. That
    // character breaks the token's signature, which is the point - the cap
    // has to answer before anything looks at it.
    const oversize = { ...request, resourceJWT: `${request.resourceJWT}x` };
    assert.equal(
      utf8Encode(JSON.stringify(oversize)).length,
      size + 1,
      "one byte over, and nothing else changed",
    );

    const log = refusalLog();
    const server = serverWith({ limits: { maxBodyBytes: size }, log });

    const meter = cryptoMeter();
    /** @type {any} */
    let refused;
    try {
      refused = await network.post(UNLOCK_URL, oversize, { from: {}, origin: PUBLISHER_ORIGIN });
    } finally {
      meter.stop();
    }

    assert.equal(refused.status, 413);
    assert.equal(refused.body.error, "body_too_large");
    assert.deepEqual(log.entries, [{ status: 413, code: "body_too_large" }]);
    assert.equal(server.stats().refusals, 1);
    assert.equal(server.stats().grants, 0, "no issuer operation ran");
    assert.equal(meter.counts.asymmetric, 0, "no signature was verified and no blob was opened");
    assert.equal(meter.counts.digest, 0, "and nothing was hashed on the way to refusing it");

    // The same request at the cap is served, so what refused the one above
    // was its size and not the path it took.
    const served = await network.post(UNLOCK_URL, request, { from: {}, origin: PUBLISHER_ORIGIN });
    assert.equal(served.status, 200);
    assert.deepEqual(Object.keys(contentKeyMap(served.body.keys.contentKeys)), [BODYTEXT]);
    assert.equal(server.stats().grants, 1);
    assert.equal(log.entries.length, 1, "and nothing else was turned away");
  });
});

// Admission bounds every request on its own, so a trail that has to reach
// the engine with a padded request lifts the caps it is not about. One
// deliberately large finite profile, named once, keeps each test's own cap the
// only thing it states.
const LIFTED = Object.freeze({
  maxBodyBytes: 4 * 1024 * 1024,
  maxEntries: 4096,
  maxEntriesPerGroup: 4096,
});

/**
 * The first period-key record of the article group: the blob the padding
 * copies under invented periods and groups.
 *
 * @param {any} request
 * @returns {{ accessGroup: string, period: string, key: string }}
 */
function firstArticleRecord(request) {
  return request.sealed.periodKeys.find(
    (/** @type {any} */ record) => record.accessGroup === ARTICLE_GROUP,
  );
}

/**
 * The period-key records a request carries under one group.
 *
 * @param {any} request
 * @param {string} accessGroup
 */
function periodRecordsOf(request, accessGroup) {
  return request.sealed.periodKeys.filter(
    (/** @type {any} */ record) => record.accessGroup === accessGroup,
  );
}

describe("The entry caps, ahead of the unseal", () => {
  test("an issuer with its caps lifted pays a private key operation for every padded entry", async () => {
    const { render, endpointWith } = await world();
    const page = await render();

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
    const padded = structuredClone(request);
    const { key: blob } = firstArticleRecord(padded);
    const honest = periodRecordsOf(padded, ARTICLE_GROUP).length;
    for (let index = 0; index < 500; index++) {
      padded.sealed.periodKeys.push({
        accessGroup: ARTICLE_GROUP,
        period: `${String(index).padStart(6, "0")}T0000`,
        key: blob,
      });
    }

    const { processor, endpoint, registration } = endpointWith({ limits: { ...LIFTED } });

    const meter = cryptoMeter();
    /** @type {any} */
    let answer;
    try {
      answer = await unlockThroughAdmission(processor, endpoint, padded, registration);
    } finally {
      meter.stop();
    }

    // The amplification the attack trail describes, run. Every padded period
    // sits inside an accessGroup this issuer grants to anyone, so the policy
    // says yes to all 502 of them and each one is an ECDH agreement against the
    // private key - one signature verification in, five hundred key operations
    // out. The cap exists for that ratio.
    assert.equal(meter.counts.verify, 1, "one envelope, and then the work");
    assert.equal(
      meter.counts.deriveBits,
      honest + 500 + 1,
      "a private key operation per granted coordinate",
    );

    // And the padding bought a key at not one of the coordinates it invented:
    // the blob is bound to the period it was sealed for, so 500 copies of it
    // under 500 other periods are 500 per-item failures beside the two real
    // ones. A caller learns from this exactly what it already knew.
    assert.equal(answer.status, 200);
    assert.equal(
      Object.keys(periodKeyMap(answer.body.keys.periodKeys)[ARTICLE_GROUP]).length,
      honest,
    );
    const errors = errorMap(answer.body.errors);
    assert.equal(Object.keys(errors).length, 500);
    for (const failure of Object.values(errors)) {
      assert.equal(/** @type {any} */ (failure).error, "unseal_failed");
    }
  });

  test("a capped issuer refuses the padding before it verifies anything", async () => {
    const { render, endpointWith, asked } = await world();
    const page = await render();

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
    const padded = structuredClone(request);
    const { key: blob } = firstArticleRecord(padded);
    for (let index = 0; index < 500; index++) {
      padded.sealed.periodKeys.push({
        accessGroup: ARTICLE_GROUP,
        period: `991023T${String(Math.floor(index / 60)).padStart(2, "0")}${String(index % 60).padStart(2, "0")}`,
        key: blob,
      });
    }

    // The padding is also past the body default, and this test is about the
    // entry caps, so the body cap is lifted and the entry caps are what
    // refuse.
    const { processor, endpoint, registration } = endpointWith({
      limits: { maxBodyBytes: LIFTED.maxBodyBytes, maxEntries: 32, maxEntriesPerGroup: 8 },
    });

    const meter = cryptoMeter();
    // Through `handleDocument`, so the envelope carries the true code the
    // uniform wire would not. The refusal stays the port's; the observing
    // moved to the application.
    /** @type {any} */
    let refused;
    try {
      refused = await endpoint.handleDocument(JSON.stringify(padded), registration);
    } finally {
      meter.stop();
    }

    assert.equal(refused.response.status, 400);
    assert.equal(refused.response.body.error, "too_many_entries");
    assert.equal(refused.code, "too_many_entries");
    assert.equal(asked.engine, 0, "the engine was never reached");
    assert.equal(meter.counts.asymmetric, 0);
    assert.equal(meter.counts.digest, 0);

    // And the honest request underneath it is served by the same endpoint.
    const served = await unlockThroughAdmission(processor, endpoint, request, registration);
    assert.equal(served.status, 200);
  });

  test("the two caps bound different shapes of the same request", async () => {
    const { render, endpointWith } = await world();
    const page = await render();

    const request = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
    const { period: firstPeriod, key: blob } = firstArticleRecord(request);

    // Wide: many groups, none of them fat. The per-group cap never fires; the
    // request cap is what bounds it.
    const wide = structuredClone(request);
    for (let index = 0; index < 40; index++) {
      wide.sealed.periodKeys.push({
        accessGroup: `group-${index}`,
        period: firstPeriod,
        key: blob,
      });
    }

    // Deep: one group, far past the per-group cap, and inside a request cap
    // generous enough to admit it.
    const deep = structuredClone(request);
    for (let index = 0; index < 20; index++) {
      deep.sealed.periodKeys.push({
        accessGroup: ARTICLE_GROUP,
        period: `991023T${String(Math.floor(index / 60)).padStart(2, "0")}${String(index % 60).padStart(2, "0")}`,
        key: blob,
      });
    }

    // Six coordinates to start with: two contentKeys and two groups over two
    // periods. Wide is 46 of them in 42 groups, deep is 26 in two.
    assert.equal(
      new Set(wide.sealed.periodKeys.map((/** @type {any} */ r) => r.accessGroup)).size,
      42,
    );
    assert.equal(periodRecordsOf(deep, ARTICLE_GROUP).length, 22);

    // Both padded shapes stay well inside the lifted body cap, so the entry
    // caps this test names are the only thing that can refuse them.
    const { processor, endpoint, registration } = endpointWith({
      limits: { maxBodyBytes: LIFTED.maxBodyBytes, maxEntries: 32, maxEntriesPerGroup: 8 },
    });

    const wideAnswer = await unlockThroughAdmission(processor, endpoint, wide, registration);
    assert.equal(wideAnswer.status, 400);
    assert.equal(wideAnswer.body.error, "too_many_entries");

    const deepAnswer = await unlockThroughAdmission(processor, endpoint, deep, registration);
    assert.equal(deepAnswer.status, 400);
    assert.equal(deepAnswer.body.error, "too_many_entries");

    // Each cap with the other lifted lets through what the other refuses, so
    // neither is doing both jobs by accident. A cap that fired answers 400
    // naming itself; a cap that did not lets the request through to be
    // answered, and the two padded shapes are answered differently because the
    // policy sees them differently. The invented groups of `wide` are names this issuer was
    // never told about, so nothing is granted there and the padding costs
    // nothing at all.
    const { processor: perGroupProcessor, endpoint: perGroupOnly } = endpointWith({
      limits: {
        maxBodyBytes: LIFTED.maxBodyBytes,
        maxEntries: LIFTED.maxEntries,
        maxEntriesPerGroup: 8,
      },
    });
    const widePassed = await unlockThroughAdmission(
      perGroupProcessor,
      perGroupOnly,
      wide,
      registration,
    );
    assert.equal(widePassed.status, 200, "thin groups pass a per-group cap");
    assert.deepEqual(Object.keys(periodKeyMap(widePassed.body.keys.periodKeys)), [ARTICLE_GROUP]);
    assert.equal(widePassed.body.errors, undefined, "a group nobody granted is never opened");
    assert.equal(
      (await unlockThroughAdmission(perGroupProcessor, perGroupOnly, deep, registration)).body
        .error,
      "too_many_entries",
    );

    // `deep` pads inside a group that is granted to anyone, so every one of its
    // invented periods is opened for and fails - which is the cost the request
    // cap is there to bound, and here the per-group cap is lifted out of the
    // way so that the request cap alone decides.
    const { processor: perRequestProcessor, endpoint: perRequestOnly } = endpointWith({
      limits: {
        maxBodyBytes: LIFTED.maxBodyBytes,
        maxEntries: 32,
        maxEntriesPerGroup: LIFTED.maxEntriesPerGroup,
      },
    });
    const deepPassed = await unlockThroughAdmission(
      perRequestProcessor,
      perRequestOnly,
      deep,
      registration,
    );
    assert.equal(deepPassed.status, 200, "one fat group fits a wide request cap");
    assert.equal(Object.keys(errorMap(deepPassed.body.errors)).length, 20);
    assert.equal(
      (await unlockThroughAdmission(perRequestProcessor, perRequestOnly, wide, registration)).body
        .error,
      "too_many_entries",
    );
  });
});

test("endpoint construction refuses a processor without miss processing", () => {
  assert.throws(
    () => new UnlockEndpoint(/** @type {any} */ ({ admit() {} })),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
});

test("refusal takes an admission failure, and refuses a success rather than 200-ing it", () => {
  // `refusal` maps a structural-admission failure to the wire. Admission never
  // refuses with a success, so one arriving here is a host wiring mistake -
  // and mapping it through would answer 200 with whatever document it carried.
  const endpoint = new UnlockEndpoint(
    /** @type {any} */ ({
      admit: () => ({ kind: "admitted", request: {} }),
      processMiss: async () => ({ kind: "success", document: {}, policyData: null }),
    }),
  );
  const success = { kind: "success", document: { keys: { contentKeys: [] } }, policyData: null };

  assert.throws(
    () => endpoint.refusal(/** @type {any} */ (success)),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
});

test("the reusable endpoint puts a host processor's refusal code on the wire, 400 or 500", () => {
  // This covers the status projection only. `request_mismatch` is raised by no JS
  // issuer core and `client_key_required` by a host's delivery preflight; the
  // reusable endpoint maps any failure a compatible host processor hands it
  // without changing who creates it. A code it has no request status for is a
  // 500, so a host fault never reads as a caller mistake.
  const endpoint = new UnlockEndpoint(
    /** @type {any} */ ({
      admit: () => ({ kind: "admitted", request: {} }),
      processMiss: async () => ({ kind: "success", document: {}, policyData: null }),
    }),
  );
  for (const code of [
    "request_mismatch",
    "unsupported_option",
    "client_key_required",
    "bad_client_key",
  ]) {
    const result = endpoint.refusal({ kind: "failure", code });
    assert.deepEqual(
      result.response,
      { status: 400, body: { error: code } },
      `${code} is a request refusal`,
    );
    assert.equal(result.code, code);
  }
  const unknown = endpoint.refusal({ kind: "failure", code: "future_host_fault" });
  assert.deepEqual(unknown.response, { status: 500, body: { error: "future_host_fault" } });
});

test("the composed unlock returns the bare wire response, and never the observing code beside it", async () => {
  // The composed unlock hands back `{ status, body }`
  // and nothing else. The true refusal code lives in the envelope the
  // observing calls (`handleRequest`, `handleDocument`, `refusal`) return, so a
  // caller reading the wire response cannot read a code the wire was never meant to carry.
  const { render, endpointWith } = await world();
  const page = await render();

  const { processor, endpoint, registration } = endpointWith({ errorDetail: "uniform" });
  const clean = requestFor(page, ISSUER_NAME, [BODYTEXT, PREMIUM]);
  const tampered = { ...clean, resourceJWT: flipSignature(clean.resourceJWT) };

  const refused = await unlockThroughAdmission(processor, endpoint, tampered, registration);
  assert.deepEqual(Object.keys(refused).sort(), ["body", "status"]);
  assert.equal(refused.code, undefined, "post carries no code");
  assert.deepEqual(refused.body, { error: "rejected" });

  const granted = await unlockThroughAdmission(
    processor,
    endpoint,
    JSON.stringify(requestFor(page, ISSUER_NAME, [BODYTEXT])),
    registration,
  );
  assert.deepEqual(Object.keys(granted).sort(), ["body", "status"], "a granted answer is bare too");
});

describe("CORS", () => {
  test(
    "CORS and the preflight",
    {
      skip:
        "no response headers here: Network carries { status, body } and nothing else, " +
        "so the allowed origins, the preflight and the silent browser " +
        "block are production and browser territory, asserted by neither a stub " +
        "header nor a fake OPTIONS",
    },
    () => {},
  );
});

// Both contract bindings are worked examples a porter copies, so both are held
// to the same order.
for (const [name, driver] of /** @type {const} */ ([
  ["reference", referenceIssuerEndpointDriver],
  ["fixture", fixtureBinding.targets["issuer-endpoint"].driver],
])) {
  describe(`The ${name} contract binding admits the raw request first`, () => {
    // Core 6.2 orders body limits, parse and version before the registration the
    // `kid` selects, and keeps one parsed request value. The binding is the host
    // here, so its own parse of the raw body is what these cases count.
    const vector = JSON.parse(
      readFileSync(
        new URL(
          "../../../verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-admission/seal-ecdh.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const dcaData = vector.expected.dcaData;
    const [issuerFixture] = vector.input.issuers;
    const [publisherFixture] = vector.input.signingKeys;
    // Built per test, so a fixture that does not read cannot unregister the cases.
    const validRequest = () => ({
      version: dcaData.version,
      issuerName: issuerFixture.issuerName,
      resourceJWT: dcaData.resourceJWT,
      keyId: issuerFixture.keyId,
      sealed: dcaData.issuerData.find(
        (/** @type {any} */ record) => record.issuerName === issuerFixture.issuerName,
      ).sealed,
    });

    async function binding() {
      const privateKey = await driver.importIssuerPrivateKey(issuerFixture.privateKeyJwk);
      const publicKey = await driver.importPublisherPublicKey(publisherFixture.publicKeyJwk);
      const reached = { store: 0, policy: 0 };
      const endpoint = driver.createIssuerEndpoint({
        operatingIssuerNames: [issuerFixture.issuerName],
        issuerName: issuerFixture.issuerName,
        keyId: issuerFixture.keyId,
        issuerKeys: {
          get() {
            reached.store++;
            return { algorithm: issuerFixture.algorithm, privateKey };
          },
        },
        publisherRegistration: { kid: publisherFixture.kid, publicKey },
        accessPolicy: {
          decide(_claims, requested) {
            reached.policy++;
            return { contentNames: requested.contentNames, periodGrants: [] };
          },
        },
        limits: { maxBodyBytes: 4096 },
        errorDetail: "code",
      });
      return { endpoint, reached };
    }

    /** @param {string} raw @param {() => Promise<unknown>} run */
    async function parsesOf(raw, run) {
      const parse = mock.method(JSON, "parse");
      try {
        const answer = await run();
        return {
          answer,
          parses: parse.mock.calls.filter((call) => call.arguments[0] === raw).length,
        };
      } finally {
        parse.mock.restore();
      }
    }

    test("an unsupported version is refused before the binding parses or selects a registration", async () => {
      const { endpoint, reached } = await binding();
      for (const version of ["2", "", 1]) {
        const raw = JSON.stringify({ ...validRequest(), version });
        const { answer, parses } = await parsesOf(raw, () => endpoint.unlock(raw));
        assert.deepEqual(answer, { status: 400, body: { error: "bad_version" } }, String(version));
        assert.equal(parses, 1, `one parse, admission's own: ${version}`);
      }
      assert.deepEqual(reached, { store: 0, policy: 0 });
    });

    test("an over-cap body answers 413 before any parse", async () => {
      const { endpoint, reached } = await binding();
      const raw = JSON.stringify({ ...validRequest(), padding: "x".repeat(5000) });
      const { answer, parses } = await parsesOf(raw, () => endpoint.unlock(raw));
      assert.deepEqual(answer, { status: 413, body: { error: "body_too_large" } });
      assert.equal(parses, 0);
      assert.deepEqual(reached, { store: 0, policy: 0 });
    });

    test("a valid request is parsed once and that admitted value is processed", async () => {
      const { endpoint, reached } = await binding();
      const raw = JSON.stringify(validRequest());
      const { answer, parses } = await parsesOf(raw, () => endpoint.unlock(raw));
      assert.equal(/** @type {any} */ (answer).status, 200);
      assert.ok(contentKeyMap(/** @type {any} */ (answer).body.keys.contentKeys).bodytext);
      assert.equal(parses, 1);
      assert.deepEqual(reached, { store: 1, policy: 1 });
    });
  });
}

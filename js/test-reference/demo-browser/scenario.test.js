//
// The scenario the browser page renders, run here instead. The page renders
// the trace this returns, so everything the page shows is under test even
// though no browser runs in this suite.
//
// The scenario itself carries no assertions and prints nothing: it wires the
// world, takes its steps, and hands back plain data. That is what lets the
// page and this file run the identical one. So the assertions below are all
// about the trace - its shape, the story it records, and its being plain JSON
// with no Uint8Array or CryptoKey left in it.
//
// The story: article A arrives locked, one unlock opens it, the clock crosses
// a period boundary, and article B opens out of the cache with the unlock
// count still at one.
//
// The scenario runs on the actors, so every unlock in the trace crossed a
// `Network`: the byte counts asserted below are the strings that crossed, and an
// unlock that never left the process would report the same steps with an empty
// wire beside them. What the scenario's knobs reach - a fallback issuer, a
// primary that is down, a transport the client cannot speak - is asserted here
// too, because the page binds a control to each of them.

import test from "node:test";
import assert from "node:assert/strict";

import { run } from "../../demo/browser/scenario.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
import { contentKeyMap, periodKeyMap } from "../support/namedRecords.js";
// `demo/browser/scenario.js` wires the shared actor world, so both sides read these
// from one place and an assertion against the fixture is the two of them
// agreeing. The `t` labels a period arithmetic produces are the fixtures' own;
// the ones below that are not stay written out.
import {
  ACCESS_GROUP,
  AT,
  CONTENT_NAME,
  FALLBACK_ISSUER_NAME,
  ISSUER_NAME,
  SIGNING_KID,
  T_NOW,
  UNLOCK_URL,
} from "../../demo/scenarios/fixtures.js";

const MINUTE = 60_000;

/** @param {any} trace */
function kinds(trace) {
  return trace.steps.map((/** @type {any} */ step) => step.kind);
}

/**
 * @param {any} trace
 * @param {string} kind
 * @returns {any[]}
 */
function stepsOf(trace, kind) {
  return trace.steps.filter((/** @type {any} */ step) => step.kind === kind);
}

test("the trace tells the story in order, and every step reports the count and the cache", async () => {
  const trace = await run();

  assert.deepEqual(kinds(trace), [
    "render",
    "resolve",
    "decrypt",
    "unlock",
    "decrypt",
    "advance",
    "render",
    "resolve",
    "decrypt",
  ]);

  for (const step of trace.steps) {
    assert.equal(typeof step.observedAt, "string", `${step.kind} is stamped with the actor clock`);
    assert.equal(
      step.observedAt,
      step.kind === "advance" || step.label === "B"
        ? "2025-10-23T15:10:00.000Z"
        : new Date(AT).toISOString(),
      `${step.kind} reports when its observed state was actually reached`,
    );
    assert.equal(
      typeof step.unlockCalls,
      "number",
      `${step.kind} reports the running unlock count`,
    );
    assert.ok(Array.isArray(step.cache), `${step.kind} reports what the cache holds`);
    for (const entry of step.cache) {
      assert.equal(typeof entry.accessGroup, "string");
      assert.equal(typeof entry.t, "string");
      assert.equal(
        typeof entry.key,
        "string",
        "a cached key reaches the page as base64url, never as bytes",
      );
    }

    assert.equal(typeof step.wire, "object", `${step.kind} reports what has crossed the wire`);

    // The advance is the one step no page is loading during, and the trace
    // says so rather than repeating the numbers of a load that had already
    // finished.
    if (step.kind === "advance") {
      assert.equal(step.load, null, "nothing was loading while the clock moved");
      continue;
    }
    assert.equal(
      typeof step.load.trials,
      "number",
      `${step.kind} reports the trial unwraps this load made`,
    );
    assert.equal(
      typeof step.load.attempts,
      "number",
      `${step.kind} reports what this load put on the wire`,
    );
    assert.ok("answeredBy" in step.load);
    assert.ok("transportMode" in step.load);
  }

  assert.equal(trace.world.issuerName, ISSUER_NAME);
  assert.equal(trace.world.signingKid, SIGNING_KID, "the page can say which key signed the render");
  assert.equal(trace.world.accessGroup, ACCESS_GROUP);
  assert.equal(trace.world.contentName, CONTENT_NAME);
  assert.equal(trace.world.at, AT);
  assert.deepEqual(trace.world.period, { length: 60, slots: 2 });

  // The knobs the page binds a control to, in the state a run with no
  // arguments is in: one issuer, up, answering direct.
  assert.equal(trace.world.transportMode, "direct");
  assert.equal(trace.world.fallback, false);
  assert.equal(trace.world.primaryOffline, false);
  assert.deepEqual(trace.world.issuers, [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }]);
});

test("article A arrives sealed, is refused, and one unlock opens it", async () => {
  const trace = await run();
  const [renderA, , lockedA, unlock, openedA] = trace.steps;

  assert.equal(renderA.label, "A");
  assert.equal(renderA.t, "251023T1400");
  assert.deepEqual(
    renderA.periods,
    ["251023T1400", "251023T1500"],
    "the period it was rendered in, and one forward",
  );
  assert.match(
    renderA.ciphertext,
    /^[A-Za-z0-9_-]+$/,
    "base64url gibberish is what the page starts with",
  );
  assert.ok(renderA.ciphertext.length > 40);
  assert.equal(typeof renderA.renderId, "string");
  assert.equal(renderA.unlockCalls, 0);
  assert.deepEqual(renderA.cache, [], "a fresh client holds nothing");
  assert.deepEqual(renderA.wire, {}, "and a render costs the wire nothing");

  // These are publisher delivery artifacts, not display substitutes: the
  // dca-data it signed and shipped, the canonical emitted markup, and the
  // compact token with its decoded view. Plaintext is not duplicated into
  // this page-facing trace artifact before the client opens it.
  assert.equal(Object.hasOwn(renderA.publisher, "article"), false);
  assert.equal(renderA.publisher.dcaData.resourceJWT, renderA.publisher.resourceJWT.compact);
  assert.deepEqual(renderA.publisher.resourceJWT.payload, renderA.publisher.dcaData.resource);
  assert.equal(renderA.publisher.resourceJWT.header.kid, SIGNING_KID);
  assert.deepEqual(
    decodeCompactJwt(renderA.publisher.resourceJWT.compact).payload,
    renderA.publisher.resourceJWT.payload,
    "the inspectable payload is decoded from the compact token, not copied from the resource",
  );
  assert.deepEqual(
    renderA.publisher.sealedContent,
    [{ contentName: CONTENT_NAME, content: renderA.ciphertext }],
    "the trace shows the ciphertext as the wire carries it",
  );
  assert.equal(
    renderA.publisher.markup,
    writeMarkupDelivery({
      dcaData: renderA.publisher.dcaData,
      sealedContent: { [CONTENT_NAME]: renderA.ciphertext },
    }),
    "the markup is emitted from this render, not assembled for the trace",
  );

  const [resolveA] = stepsOf(trace, "resolve");
  assert.deepEqual(resolveA.covered, []);
  assert.deepEqual(
    resolveA.missing,
    [CONTENT_NAME],
    "nothing held opens it, so the issuer has to be asked",
  );

  assert.equal(lockedA.text, null);
  assert.equal(lockedA.error, "no_key", "locked is a typed miss, not a wrong plaintext");
  assert.equal(lockedA.unlockCalls, 0);

  assert.equal(unlock.status, 200);
  assert.equal(unlock.unlockCalls, 1);
  assert.equal(unlock.request.issuerName, ISSUER_NAME);

  // It went over the `Network`, and what the page shows is what crossed it:
  // the counted bytes are the bodies in the trace, to the character.
  assert.deepEqual(unlock.attempts, [
    { issuerName: ISSUER_NAME, url: UNLOCK_URL, outcome: "answered", status: 200 },
  ]);
  assert.equal(unlock.unlockUrl, UNLOCK_URL);
  assert.equal(unlock.wire[UNLOCK_URL].attempts, 1);
  assert.equal(unlock.wire[UNLOCK_URL].failures, 0);
  assert.equal(unlock.wire[UNLOCK_URL].requestBytes, JSON.stringify(unlock.request).length);
  assert.equal(unlock.wire[UNLOCK_URL].responseBytes, JSON.stringify(unlock.response).length);

  assert.equal(unlock.transportMode, "direct");
  assert.equal(unlock.load.answeredBy, ISSUER_NAME);
  assert.equal(unlock.load.attempts, 1, "one issuer asked, and it answered");
  assert.deepEqual(
    unlock.load.keyResolutions.at(-1),
    {
      operation: "re-resolve-after-unlock",
      origins: [{ contentName: CONTENT_NAME, kind: "held-content-key" }],
    },
    "the applied item content-key grant is this render's key path",
  );
  assert.deepEqual(
    openedA.load.keyResolutions.at(-1),
    {
      operation: "open",
      origins: [{ contentName: CONTENT_NAME, kind: "held-content-key" }],
    },
    "opening A uses that held render key",
  );

  // The request the page shows is the whole one, envelope included: the
  // issuer verifies it before it opens a blob, and rebuilds the binding from
  // the renderId inside it, so a trace without it would be showing a request
  // that could not have been answered.
  assert.deepEqual(Object.keys(unlock.request), [
    "version",
    "issuerName",
    "resourceJWT",
    "keyId",
    "sealed",
  ]);
  assert.match(
    unlock.request.resourceJWT,
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    "resourceJWT reaches the page as a compact token",
  );

  assert.deepEqual(Object.keys(contentKeyMap(unlock.request.sealed.contentKeys)), [CONTENT_NAME]);
  assert.deepEqual(Object.keys(periodKeyMap(unlock.request.sealed.periodKeys)[ACCESS_GROUP]), [
    "251023T1400",
    "251023T1500",
  ]);
  assert.deepEqual(Object.keys(periodKeyMap(unlock.response.keys.periodKeys)[ACCESS_GROUP]), [
    "251023T1400",
    "251023T1500",
  ]);
  assert.equal(unlock.response.errors, undefined);
  assert.deepEqual(
    unlock.cache.map((/** @type {any} */ entry) => entry.t),
    ["251023T1500", "251023T1400"],
    "newest first, which is the order the trial unwrap walks",
  );

  assert.equal(openedA.label, "A");
  assert.equal(openedA.error, null);
  assert.equal(openedA.text, trace.world.articles.A);
  assert.notEqual(openedA.text, renderA.ciphertext);
});

test("the trace exposes a boundary-focused view of the first delivery and unlock", async () => {
  const trace = await run();
  const render = trace.steps.find((step) => step.kind === "render");
  const unlock = trace.steps.find((step) => step.kind === "unlock");

  assert.deepEqual(Object.keys(trace.flow), [
    "publisherDelivery",
    "unlockRequest",
    "unlockResponse",
  ]);
  assert.deepEqual(trace.flow.publisherDelivery, {
    dcaData: render.publisher.dcaData,
    sealedContent: render.publisher.sealedContent,
    markup: render.publisher.markup,
  });
  assert.deepEqual(trace.flow.unlockRequest, {
    unresolvedContentNames: unlock.needed,
    body: unlock.request,
  });
  assert.deepEqual(trace.flow.unlockResponse, {
    status: unlock.status,
    body: unlock.response,
  });
  assert.deepEqual(trace.inspection, {
    resourceJWT: render.publisher.resourceJWT,
  });
});

test("the clock crosses a period, and article B opens out of the cache at no unlock", async () => {
  const trace = await run();
  const [advance, renderB, resolveB, openedB] = trace.steps.slice(5);

  assert.equal(advance.from, "2025-10-23T14:20:00.000Z");
  assert.equal(advance.to, "2025-10-23T15:10:00.000Z");
  assert.equal(advance.fromT, "251023T1400");
  assert.equal(advance.toT, "251023T1500", "the far side of the flip");

  assert.equal(renderB.label, "B");
  assert.deepEqual(renderB.periods, ["251023T1500", "251023T1600"]);
  assert.notEqual(
    renderB.renderId,
    trace.steps[0].renderId,
    "a second render, not the first one again",
  );

  assert.deepEqual(
    resolveB.covered,
    [CONTENT_NAME],
    "the overlap key from the T14 unlock opens a T15 render",
  );
  assert.deepEqual(resolveB.missing, []);
  assert.equal(resolveB.unlockCalls, 1, "and it cost nothing to find that out");
  assert.equal(resolveB.load.attempts, 0, "this load never reached the wire at all");
  assert.ok(resolveB.load.trials > 0, "it was the trial unwrap that answered");
  assert.deepEqual(
    resolveB.load.keyResolutions,
    [
      {
        operation: "resolve",
        origins: [
          {
            contentName: CONTENT_NAME,
            kind: "cached-period-key",
            accessGroup: ACCESS_GROUP,
            t: "251023T1500",
          },
        ],
      },
    ],
    "B names the exact sealed entry the cached period key opened",
  );
  assert.deepEqual(
    openedB.load.keyResolutions.at(-1),
    {
      operation: "open",
      origins: [
        {
          contentName: CONTENT_NAME,
          kind: "held-content-key",
        },
      ],
    },
    "the open consumes the render-scoped content key recovered during resolution",
  );
  for (const observation of openedB.load.keyResolutions) {
    for (const origin of observation.origins) {
      assert.equal(
        Object.hasOwn(origin, "key"),
        false,
        "a trace observation never contains key material",
      );
    }
  }

  assert.equal(openedB.text, trace.world.articles.B);
  assert.equal(openedB.error, null);
  assert.equal(openedB.unlockCalls, 1);
  assert.deepEqual(
    openedB.cache.map((/** @type {any} */ entry) => entry.t),
    ["251023T1500", "251023T1400"],
    "the client acquired nothing new to do it",
  );

  assert.equal(trace.summary.unlockCalls, 1);
  assert.equal(trace.summary.articlesOpened, 2);
  assert.deepEqual(
    trace.summary.cache.map((/** @type {any} */ entry) => entry.t),
    ["251023T1500", "251023T1400"],
  );

  // Two articles read, one call on the wire. The count is the network's own,
  // so it is the second article's silence that is being asserted and not the
  // client's account of it.
  assert.equal(trace.summary.wire[UNLOCK_URL].attempts, 1);
  assert.deepEqual(trace.summary.client.loads, 2);
  assert.deepEqual(trace.summary.client.unlocks, 1);
  assert.deepEqual(trace.summary.client.unlockFailures, 0);
  assert.equal(trace.summary.servers.primary.grants, 1);
  assert.equal(trace.summary.servers.fallback, undefined, "no fallback was stood up");
});

test("the trace is plain data: it survives a JSON round trip unchanged", async () => {
  const trace = await run();

  // The page renders this, a `Uint8Array` or a `CryptoKey` in it would be
  // silently mangled on the way, and the same rule holds at the `Network`
  // seam when one arrives.
  assert.deepEqual(JSON.parse(JSON.stringify(trace)), trace);
});

test("the seed makes the run replayable, down to the renderIds", async () => {
  const [first, second] = await Promise.all([run({ seed: 4 }), run({ seed: 4 })]);

  assert.deepEqual(
    first.steps.map((step) => step.observedAt),
    second.steps.map((step) => step.observedAt),
    "the actor-clock stamps replay with the same run",
  );
  assert.deepEqual(
    stepsOf(first, "render").map((step) => step.renderId),
    stepsOf(second, "render").map((step) => step.renderId),
  );
  assert.notDeepEqual(
    stepsOf(await run({ seed: 5 }), "render").map((step) => step.renderId),
    stepsOf(first, "render").map((step) => step.renderId),
  );
});

test("the period is an argument: quarter-hourly, three slots, and the flip still costs nothing", async () => {
  const trace = await run({ period: { length: 15, slots: 3 }, advance: 20 * MINUTE });

  const [renderA, renderB] = stepsOf(trace, "render");
  assert.deepEqual(renderA.periods, ["251023T1415", "251023T1430", "251023T1445"]);
  assert.deepEqual(renderB.periods, ["251023T1430", "251023T1445", "251023T1500"]);

  const [, resolveB] = stepsOf(trace, "resolve");
  assert.deepEqual(resolveB.covered, [CONTENT_NAME]);
  assert.equal(trace.summary.unlockCalls, 1);
  assert.deepEqual(
    trace.summary.cache.map((/** @type {any} */ entry) => entry.t),
    ["251023T1445", "251023T1430", "251023T1415"],
  );
});

test("the primary is down, the fallback stands in, and the next period is a second unlock", async () => {
  const trace = await run({ fallback: true, primaryOffline: true });

  assert.deepEqual(
    kinds(trace),
    [
      "render",
      "resolve",
      "decrypt",
      "unlock",
      "decrypt",
      "advance",
      "render",
      "resolve",
      "unlock",
      "decrypt",
    ],
    "article B needs a call of its own, and the trace takes the step rather than showing it locked",
  );

  const [first, second] = stepsOf(trace, "unlock");
  assert.deepEqual(
    first.attempts.map((/** @type {any} */ attempt) => [attempt.issuerName, attempt.outcome]),
    [
      [ISSUER_NAME, "offline"],
      [FALLBACK_ISSUER_NAME, "answered"],
    ],
    "the walk reaches the fallback only after the primary refused the connection",
  );
  assert.equal(first.issuerName, FALLBACK_ISSUER_NAME);
  assert.equal(first.status, 200);
  assert.deepEqual(
    first.cache.map((/** @type {any} */ entry) => entry.t),
    [T_NOW],
    "a fallback grants the period the client is reading in, and no forward one",
  );

  assert.deepEqual(second.needed, [CONTENT_NAME], "so the render a period on is not covered");
  assert.equal(second.issuerName, FALLBACK_ISSUER_NAME);
  assert.equal(trace.summary.unlockCalls, 2, "the second call is what the failover cost");
  assert.equal(trace.summary.articlesOpened, 2, "both articles open all the same");

  assert.equal(trace.summary.servers.primary.requests, 0, "nothing reached the primary");
  assert.equal(trace.summary.servers.fallback.grants, 2);
  assert.ok(
    trace.summary.servers.fallback.probes > 0,
    "a fallback confirms the primary is down before it grants",
  );
  assert.equal(
    trace.summary.client.breaker[UNLOCK_URL].state,
    "open",
    "two failures take the primary out of the walk",
  );
});

test("an option the scenario does not have is refused, not ignored", async () => {
  await assert.rejects(
    () => run({ credential: "a-subscriber" }),
    (/** @type {any} */ err) => err.code === "unsupported_option",
  );
});

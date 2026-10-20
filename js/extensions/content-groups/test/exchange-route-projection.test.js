// @ts-check
//
// The generic retry-projection seam of the base route walk, driven by an
// invented extension request member. A conditional retry replays only the
// route identities that are still outstanding and authorized for retry, never
// the original request. The content-groups builder supplies the same seam; its
// own projection is pinned in exchange-request-builder.test.js.

import test from "node:test";
import assert from "node:assert/strict";

import {
  projectEligibleIdentities,
  routeIdentities,
  settleRouteProjection,
} from "../../../adapter-client/routeAttempts.js";
import {
  A,
  B,
  C,
  JWT,
  URL_OF,
  WidgetRequestBuilder,
  projection,
  world,
} from "./_lib/widgetRequests.js";

test("a conditional retry replays only the outstanding authorized route identities", async () => {
  const { client, posted } = world({
    answers: {
      [A]: () => ({ fail: "offline" }),
      [B]: () => ({ resolves: ["headline"] }),
      [C]: () => ({}),
    },
  });
  const walk = await client.unlockRoutes(
    ["bodytext", "headline"],
    [
      { issuerName: A, unlockUrl: URL_OF[A], retryOperational: true },
      { issuerName: B, unlockUrl: URL_OF[B], independent: true },
      { issuerName: C, unlockUrl: URL_OF[C] },
    ],
  );
  assert.deepEqual(
    walk.attempts.map((a) => a.outcome),
    ["offline", "answered", "answered"],
  );
  assert.deepEqual(
    posted.map((p) => p.issuer),
    [A, B, C],
  );
  // A failed on all three identities and authorized their retry; B answered
  // headline/w3 and resolved headline. C receives only bodytext's two routes.
  const retried = posted[2].request;
  assert.deepEqual(retried.requestedWidgets, { bodytext: ["w1", "w2"] });
  assert.deepEqual(retried.sealed.widgetSeeds, { bodytext: "seed-bodytext" });
  assert.deepEqual(retried.sealed.contentKeys, {});
});

test("a failed route without retry authority leaves nothing for the conditional route", async () => {
  const { client, posted } = world({
    answers: { [A]: () => ({ fail: "offline" }), [C]: () => ({}) },
  });
  const walk = await client.unlockRoutes(
    ["bodytext"],
    [
      { issuerName: A, unlockUrl: URL_OF[A] },
      { issuerName: C, unlockUrl: URL_OF[C] },
    ],
  );
  assert.deepEqual(
    walk.attempts.map((a) => a.outcome),
    ["offline"],
  );
  assert.equal(posted.length, 1);
});

test("an extension request without a projection seam is never replayed whole", async () => {
  const builder = new WidgetRequestBuilder();
  // An own data member shadows the class field: no projection is offered.
  Object.defineProperty(builder, "routeProjection", { value: undefined });
  const { client, posted } = world({
    builder,
    answers: { [A]: () => ({ fail: "offline" }), [C]: () => ({}) },
  });
  const walk = await client.unlockRoutes(
    ["bodytext"],
    [
      { issuerName: A, unlockUrl: URL_OF[A], retryOperational: true },
      { issuerName: C, unlockUrl: URL_OF[C] },
    ],
  );
  // Without a projection the extension identities are not tracked, so the
  // conditional route has nothing eligible and posts nothing.
  assert.deepEqual(
    walk.attempts.map((a) => a.outcome),
    ["offline"],
  );
  assert.equal(posted.length, 1);
});

test("projectEligibleIdentities composes base and extension selection", () => {
  const settled = settleRouteProjection(projection);
  const request = {
    version: "1",
    issuerName: A,
    resourceJWT: JWT,
    keyId: "kid",
    sealed: {
      contentKeys: { bodytext: "item" },
      periodKeys: { premium: { t1: "p" } },
      widgetSeeds: { bodytext: "seed-bodytext", headline: "seed-headline" },
    },
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    requestedWidgets: { bodytext: ["w1", "w2"], headline: ["w3"] },
  };
  assert.deepEqual(routeIdentities(request, settled), {
    contentNames: ["bodytext"],
    accessGroups: ["premium"],
    routes: ["bodytext/w1", "bodytext/w2", "headline/w3"],
  });
  const narrowed = projectEligibleIdentities(
    request,
    { contentNames: [], accessGroups: [], routes: ["headline/w3"] },
    settled,
  );
  assert.deepEqual(narrowed, {
    version: "1",
    issuerName: A,
    resourceJWT: JWT,
    keyId: "kid",
    sealed: { contentKeys: {}, widgetSeeds: { headline: "seed-headline" } },
    requestedWidgets: { headline: ["w3"] },
  });
  // Without the seam an extension member cannot be projected at all.
  assert.equal(
    projectEligibleIdentities(request, { contentNames: [], accessGroups: [], routes: [] }),
    null,
  );
  // A projection may not return a member it did not declare.
  const lying = settleRouteProjection({
    ...projection,
    project: () => ({ members: { requestedOther: {} } }),
  });
  assert.throws(
    () =>
      projectEligibleIdentities(
        request,
        { contentNames: [], accessGroups: [], routes: ["headline/w3"] },
        lying,
      ),
    /undeclared/,
  );
});

test("a projection may not claim a base request member", () => {
  for (const members of [["sealed"], ["issuerName"], ["clientPublicKey"], ["requestedPeriodKeys"]])
    assert.throws(() => settleRouteProjection({ ...projection, members }), /base request member/);
  for (const sealedMembers of [["contentKeys"], ["periodKeys"], ["chainKeys"]])
    assert.throws(
      () => settleRouteProjection({ ...projection, sealedMembers }),
      /base request member/,
    );
  assert.throws(
    () => settleRouteProjection({ ...projection, identities: undefined }),
    /routeProjection/,
  );
});

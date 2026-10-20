// Issuer policy and registration-key ordering for the source-only route.
import test from "node:test";
import assert from "node:assert/strict";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { contentGroupsProfile } from "../referenceProfile.js";
import { CHAIN, PUBLISHER, chainPolicy, item, world } from "./_lib/world.js";

async function groupOnlyRequest(publication, w) {
  const refused = {
    name: "issuer",
    answer: async () => ({ status: 401, body: { error: "denied" } }),
  };
  const client = w.reader().client(publication, refused, {
    narrowing: { requestedContentGroups: { bodytext: ["sports"] } },
  });
  await client.attempt(["bodytext"]);
  assert.equal(client.sent.length, 1);
  assert.equal(client.sent[0].requestedContentKeys, undefined);
  return client.sent[0];
}

test("source-only denial precedes opening-key resolution; authorized work resolves once", async () => {
  const w = await world();
  const publication = await w.publish({
    items: [item("bodytext", ["sports"], "entitled story")],
  });
  const request = await groupOnlyRequest(publication, w);
  const events = [];
  const storedGet = w.registration.openingKeys.get.bind(w.registration.openingKeys);
  w.registration.openingKeys.get = (...args) => {
    events.push("lookup");
    return storedGet(...args);
  };

  const deniedIssuer = w.issuer({
    policy: () => {
      events.push("policy");
      return { grants: [], authorizePeriod: () => false };
    },
  });
  const denied = await deniedIssuer.answer(request);
  assert.equal(denied.status, 401);
  assert.equal(denied.code, "denied");
  assert.deepEqual(events, ["policy"]);

  events.length = 0;
  const deniedUnknown = await deniedIssuer.answer({ ...request, keyId: "unknown" });
  assert.equal(deniedUnknown.status, 401);
  assert.equal(deniedUnknown.code, "denied");
  assert.deepEqual(events, ["policy"]);

  events.length = 0;
  const down = new Error("policy offline");
  down.code = "policy_unavailable";
  const unavailableIssuer = w.issuer({
    policy: () => {
      events.push("policy");
      throw down;
    },
  });
  const unavailable = await unavailableIssuer.answer({ ...request, keyId: "unknown" });
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.code, "policy_unavailable");
  assert.deepEqual(events, ["policy"]);

  events.length = 0;
  const authorizedUnknownIssuer = w.issuer({
    policy: (input) => {
      events.push("policy");
      return chainPolicy()(input);
    },
  });
  const unknown = await authorizedUnknownIssuer.answer({ ...request, keyId: "unknown" });
  assert.equal(unknown.status, 503);
  assert.equal(unknown.code, "unknown_key");
  assert.deepEqual(events, ["policy", "lookup"]);

  events.length = 0;
  w.registration.openingKeys.get = (...args) => {
    events.push("lookup");
    if (args[1] === request.keyId) return { retired: true };
    return storedGet(...args);
  };
  const retiredIssuer = w.issuer({
    policy: (input) => {
      events.push("policy");
      return chainPolicy()(input);
    },
  });
  const retired = await retiredIssuer.answer(request);
  assert.equal(retired.status, 200);
  assert.match(JSON.stringify(retired.body), /key_retired/);
  assert.deepEqual(events, ["policy", "lookup"]);

  events.length = 0;
  w.registration.openingKeys.get = (...args) => {
    events.push("lookup");
    return storedGet(...args);
  };
  const authorizedIssuer = w.issuer({
    policy: (input) => {
      events.push("policy");
      return chainPolicy()(input);
    },
  });
  const client = w.reader().client(publication, authorizedIssuer, {
    narrowing: { requestedContentGroups: { bodytext: ["sports"] } },
  });
  await client.attempt(["bodytext"]);
  assert.deepEqual(events, ["policy", "lookup"]);
  assert.equal(await client.open("bodytext"), "entitled story");
});

test("source policy receives the host's opaque principal and context by identity", async () => {
  const w = await world();
  const publication = await w.publish({
    items: [
      item("headline", undefined, "ordinary story"),
      item("bodytext", ["sports"], "entitled story"),
    ],
    ordinary: ["headline"],
  });
  const request = await groupOnlyRequest(publication, w);
  const principal = { readerId: "reader-1" };
  const pendingEvent = Object.freeze({ type: "render-view", id: "render-1" });
  const accounting = { allowed: true, baseReads: 0, sourceReads: 0 };
  const context = new Map([[principal, accounting]]);
  const observations = [];
  let failSource = false;

  const core = createIssuerCore(
    {
      operatingIssuerNames: ["issuer"],
      accessPolicy: {
        decide(_claims, requested, input) {
          const samePrincipal = input.principal === principal;
          const sameContext = input.context === context;
          const sameSnapshot = input.context.get(input.principal) === accounting;
          observations.push({
            role: "base",
            samePrincipal,
            sameContext,
            sameSnapshot,
            origin: input.publisher.origin,
          });
          assert.ok(samePrincipal && sameContext && sameSnapshot);
          accounting.baseReads++;
          return {
            contentNames: requested.contentNames.filter((name) => name === "headline"),
            policyData: pendingEvent,
          };
        },
      },
    },
    contentGroupsProfile.issuerContribution({
      chain: CHAIN,
      policy: {
        decide(input) {
          const samePrincipal = input.principal === principal;
          const sameContext = input.context === context;
          const sameSnapshot = input.context.get(input.principal) === accounting;
          observations.push({
            role: "content-groups",
            samePrincipal,
            sameContext,
            sameSnapshot,
            origin: input.publisher.origin,
          });
          assert.ok(samePrincipal && sameContext && sameSnapshot);
          if (failSource) throw new Error("source unavailable after base opening");
          accounting.sourceReads++;
          return chainPolicy()(input);
        },
      },
    }),
  );

  const outcome = await core.endpoint.handleDocument(JSON.stringify(request), w.registration, {
    principal,
    context,
  });
  assert.equal(outcome.response.status, 200, outcome.code);
  assert.equal(outcome.policyData, pendingEvent);
  assert.deepEqual(accounting, { allowed: true, baseReads: 1, sourceReads: 1 });
  assert.deepEqual(observations, [
    {
      role: "base",
      samePrincipal: true,
      sameContext: true,
      sameSnapshot: true,
      origin: PUBLISHER,
    },
    {
      role: "content-groups",
      samePrincipal: true,
      sameContext: true,
      sameSnapshot: true,
      origin: PUBLISHER,
    },
  ]);
  assert.equal(Object.isFrozen(principal), false);
  assert.equal(Object.isFrozen(context), false);

  let mixedOutcome;
  const mixedIssuer = {
    name: "issuer",
    answer: async (sent) => {
      mixedOutcome = await core.endpoint.handleDocument(JSON.stringify(sent), w.registration, {
        principal,
        context,
      });
      return { status: mixedOutcome.response.status, body: mixedOutcome.response.body };
    },
  };
  const mixedClient = w.reader().client(publication, mixedIssuer, {
    narrowing: { requestedContentGroups: { bodytext: ["sports"] } },
  });
  await mixedClient.attempt(["headline", "bodytext"]);
  assert.equal(mixedOutcome.response.status, 200);
  assert.equal(mixedOutcome.policyData, pendingEvent);
  assert.equal(await mixedClient.open("headline"), "ordinary story");
  assert.equal(await mixedClient.open("bodytext"), "entitled story");
  assert.deepEqual(accounting, { allowed: true, baseReads: 2, sourceReads: 2 });

  failSource = true;
  const refused = await core.endpoint.handleDocument(
    JSON.stringify(mixedClient.sent[0]),
    w.registration,
    { principal, context },
  );
  assert.equal(refused.response.status, 500);
  assert.equal(refused.code, "internal_error");
  assert.equal(refused.policyData, undefined);
  assert.equal(Object.hasOwn(refused.response.body, "keys"), false);
  assert.equal(Object.hasOwn(refused.response.body, "contentGroups"), false);
  assert.deepEqual(accounting, { allowed: true, baseReads: 3, sourceReads: 2 });

  const replay = {
    name: "issuer",
    answer: async () => ({
      status: outcome.response.status,
      body: JSON.parse(JSON.stringify(outcome.response.body)),
    }),
  };
  const client = w.reader().client(publication, replay, {
    narrowing: { requestedContentGroups: { bodytext: ["sports"] } },
  });
  await client.attempt(["bodytext"]);
  assert.equal(await client.open("bodytext"), "entitled story");
});

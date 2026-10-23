// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import {
  hasEligibleCoordinates,
  projectEligibleIdentities,
  settleRouteProjection,
  projectUnavailableFamilies,
  retryableUnavailableFamilies,
} from "../../adapter-client/routeAttempts.js";

const request = {
  version: "dca-v1",
  issuerName: "backup",
  resourceJWT: "token",
  keyId: "key",
  sealed: {
    contentKeys: [{ contentName: "article", key: "item-envelope" }],
    periodKeys: [
      { accessGroup: "premium", period: "t1", key: "premium-envelope" },
      { accessGroup: "sport", period: "t1", key: "sport-envelope" },
      { accessGroup: "premium", period: "t1", key: "premium-rival" },
    ],
    chainKeys: [
      { accessGroup: "premium", cutoff: "t1", key: "premium-chain" },
      { accessGroup: "sport", cutoff: "t1", key: "sport-chain" },
    ],
  },
  periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
  requestedPeriodKeys: [
    { accessGroup: "premium", periods: ["t1"] },
    { accessGroup: "sport", periods: ["t1"] },
  ],
};

/** @param {any} records @returns {string[]} */
function groups(records) {
  return (records ?? []).map((/** @type {any} */ record) => record.accessGroup);
}

test("a family retry excludes item and sibling-family coordinates before association", () => {
  const selected = projectUnavailableFamilies(request, ["premium"]);
  assert.deepEqual(selected.sealed.contentKeys, []);
  // Both rival records of the premium family stay: a projection narrows
  // identities and never picks among candidates.
  assert.deepEqual(selected.sealed.periodKeys, [
    { accessGroup: "premium", period: "t1", key: "premium-envelope" },
    { accessGroup: "premium", period: "t1", key: "premium-rival" },
  ]);
  assert.deepEqual(groups(selected.sealed.chainKeys), ["premium"]);
  assert.deepEqual(selected.periodGeometry, request.periodGeometry);
  assert.deepEqual(groups(selected.requestedPeriodKeys), ["premium"]);
  assert.equal(hasEligibleCoordinates(selected), true);
  assert.equal(hasEligibleCoordinates({ sealed: { contentKeys: [], periodKeys: [] } }), false);
  assert.deepEqual(
    groups(request.sealed.periodKeys),
    ["premium", "sport", "premium"],
    "original intact",
  );
});

test("a retry with no authored family is skipped and unknown extension material is not relayed", () => {
  const noFamily = projectUnavailableFamilies(request, ["unrelated"]);
  assert.equal(hasEligibleCoordinates(noFamily), false);
  assert.equal(
    projectUnavailableFamilies({ ...request, experimentalOffer: true }, ["premium"]),
    null,
  );
});

test("only an admitted and still-useful unavailable family qualifies", () => {
  const dcaData = { accessGroupsFor: (name) => (name === "article" ? ["premium"] : []) };
  const base = {
    missing: ["article"],
    dcaData,
    retryUnavailable: true,
    application: {
      issues: [],
      notDelivered: [
        { accessGroup: "premium", reason: "unavailable" },
        { accessGroup: "sport", reason: "unavailable" },
        { accessGroup: "premium", reason: "unavailable" },
      ],
    },
  };
  assert.deepEqual(retryableUnavailableFamilies(base), ["premium"]);
  assert.deepEqual(retryableUnavailableFamilies({ ...base, retryUnavailable: false }), []);
  assert.deepEqual(retryableUnavailableFamilies({ ...base, missing: [] }), []);
  assert.deepEqual(
    retryableUnavailableFamilies({
      ...base,
      application: {
        issues: [],
        notDelivered: [{ accessGroup: "premium", reason: "denied" }],
      },
    }),
    [],
  );
  assert.deepEqual(
    retryableUnavailableFamilies({
      ...base,
      application: {
        issues: [],
        notDelivered: [],
      },
    }),
    [],
  );
  // A rejected key entry keeps the admitted report's meaning (period keys
  // Section 5.6); a whole-response refusal admits no report at all.
  assert.deepEqual(
    retryableUnavailableFamilies({
      ...base,
      application: {
        ...base.application,
        issues: [{ section: "contentKeys", code: "malformed_key" }],
      },
    }),
    ["premium"],
  );
  assert.deepEqual(
    retryableUnavailableFamilies({
      ...base,
      application: {
        accepted: 0,
        errors: [],
        issues: [{ section: "notDelivered", code: "malformed_response" }],
      },
    }),
    [],
  );
});

test("family-only retries retain exactly the selected geometry and chain hints", () => {
  for (const kind of ["periodKeys", "chainKeys"]) {
    for (const hintSource of ["absent", "selected", "unrelated"]) {
      const input = {
        ...request,
        sealed: { [kind]: request.sealed[kind] },
      };
      if (hintSource === "absent") delete input.requestedPeriodKeys;
      if (hintSource === "unrelated")
        input.requestedPeriodKeys = [{ accessGroup: "sport", periods: ["t1"] }];
      const selected = projectUnavailableFamilies(input, ["premium"]);
      assert.deepEqual(selected.periodGeometry, request.periodGeometry);
      assert.deepEqual(
        selected.requestedPeriodKeys,
        kind === "chainKeys" && hintSource === "selected"
          ? [{ accessGroup: "premium", periods: ["t1"] }]
          : undefined,
      );
    }
  }
  const projection = settleRouteProjection({
    members: ["periodGeometry"],
    sealedMembers: [],
    identities: () => [],
    project: () => ({}),
    useful: () => false,
  });
  const selected = projectEligibleIdentities(
    request,
    {
      contentNames: [],
      accessGroups: ["premium"],
      routes: [],
    },
    projection,
  );
  assert.deepEqual(selected.periodGeometry, request.periodGeometry);
});

test("extension item-only routes remain eligible and undeclared sealed material cannot be retried", () => {
  assert.equal(
    hasEligibleCoordinates({ sealed: {} }, () => ({ contentKeys: true, familyKeys: false })),
    true,
  );
  assert.equal(
    hasEligibleCoordinates({ sealed: {} }, () => ({ contentKeys: false, familyKeys: false })),
    false,
  );
  assert.equal(
    projectUnavailableFamilies(
      {
        ...request,
        sealed: { ...request.sealed, unknownRoute: { premium: "value" } },
      },
      ["premium"],
    ),
    null,
  );
});

test("route projection refuses malformed declarations and non-object answers", () => {
  const valid = {
    members: ["custom"],
    sealedMembers: ["customKeys"],
    identities: () => [],
    project: () => ({}),
    useful: () => false,
  };
  for (const patch of [
    { members: [""] },
    { members: [1] },
    { sealedMembers: [""] },
    { sealedMembers: [null] },
    { members: ["custom", "resourceJWT"] },
    { sealedMembers: ["customKeys", "contentKeys"] },
  ])
    assert.throws(() => settleRouteProjection({ ...valid, ...patch }), { code: "bad_config" });
  assert.throws(() => settleRouteProjection(Object.assign(() => {}, valid)), {
    code: "bad_config",
  });
  for (const answer of [null, [], "bad"]) {
    const projection = settleRouteProjection({ ...valid, project: () => answer });
    assert.throws(
      () =>
        projectEligibleIdentities(
          request,
          {
            contentNames: [],
            accessGroups: ["premium"],
            routes: [],
          },
          projection,
        ),
      { code: "bad_config" },
    );
  }
});

// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { planSiteResources } from "../../core-publisher/siteResourcePlan.js";
import {
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_EXACT_LEAVES_PER_FAMILY,
  MAX_EXACT_LEAVES_PER_RESPONSE,
  MAX_POSITIONS_PER_WINDOW,
} from "../../core-shared/geometryBounds.js";

function baseInput() {
  return {
    renders: [
      {
        name: "front-page",
        volume: 4,
        accessGroups: [
          {
            name: "premium",
            exactMembers: 2,
            chain: {
              chainsPerDay: 2,
              periodMinutes: 60,
              windows: [{ projectedLeaves: 3 }, { projectedLeaves: 2 }],
            },
          },
          { name: "free", exactMembers: 1 },
        ],
        items: [
          { name: "article", accessGroups: ["premium"], volume: 2 },
          { name: "brief", accessGroups: ["premium", "free"] },
        ],
        issuers: [
          { issuerName: "alpha", method: "ECDH-P256" },
          {
            issuerName: "beta",
            method: "RSA-OAEP",
            supply: {
              suppliedAccessGroups: ["premium"],
              directContentKeys: false,
              reachableContentNames: ["article"],
              periodKeyDelivery: { premium: ["exact", "chain"] },
            },
          },
        ],
      },
    ],
  };
}

function oneChainGroup(name, windows, projectedLeaves = 1) {
  return {
    name,
    exactMembers: 1,
    chain: {
      chainsPerDay: 5,
      periodMinutes: 1,
      windows: Array.from({ length: windows }, () => ({ projectedLeaves })),
    },
  };
}

function chainInput(groups, responseScenario) {
  return {
    renders: [
      {
        name: "chain-render",
        accessGroups: groups,
        items: [{ name: "article", accessGroups: groups.map((group) => group.name) }],
        issuers: [
          {
            issuerName: "issuer",
            method: "ECDH-P256",
            supply: {
              directContentKeys: false,
              suppliedAccessGroups: groups.map((group) => group.name),
              periodKeyDelivery: Object.fromEntries(groups.map((group) => [group.name, ["chain"]])),
            },
          },
        ],
        ...(responseScenario === undefined ? {} : { responseScenario }),
      },
    ],
  };
}

test("one multi-group and multi-issuer render aggregates structural and repeated counts", () => {
  const report = planSiteResources(baseInput());
  const render = report.renders[0];

  assert.equal(report.profile.exactPeriod.leafBytes, 16);
  assert.equal(report.profile.exactPeriod.wrapAlgorithm, "AES-128-GCM");
  assert.equal(render.certainty, "upperBound");
  assert.deepEqual(render.counts, {
    protectedItems: 3,
    contentKeyInstances: 3,
    contentToAccessGroupAssignments: 4,
    contentKeyWraps: 7,
    issuerRoutes: 13,
    directSealedCapabilities: 3,
    exactFamilies: 3,
    exactMembers: 5,
    exactResponseKeyCandidates: 5,
    chainFamilies: 1,
    chainMembers: 2,
    chainWindows: 2,
    projectedLeafCandidates: 5,
    responseKeyCandidates: 15,
    combinedFamilies: 4,
    combinedMembers: 7,
  });
  assert.equal(render.issuers.find((issuer) => issuer.issuerName === "alpha").response.total, 6);
  assert.deepEqual(render.items.find((item) => item.name === "article").counts, {
    protectedItems: 2,
    contentKeyInstances: 2,
    contentToAccessGroupAssignments: 2,
    contentKeyWraps: 4,
    issuerRoutes: 8,
    directSealedCapabilities: 2,
  });
  const premium = render.accessGroups.find((group) => group.name === "premium").counts;
  assert.deepEqual(
    {
      issuerRoutes: premium.issuerRoutes,
      exactResponseKeyCandidates: premium.exactResponseKeyCandidates,
      responseKeyCandidates: premium.responseKeyCandidates,
    },
    { issuerRoutes: 9, exactResponseKeyCandidates: 4, responseKeyCandidates: 11 },
  );
  assert.deepEqual(render.issuers.find((issuer) => issuer.issuerName === "beta").response, {
    directContentKeys: 0,
    exactMembers: 2,
    chainMembers: 2,
    projectedLeaves: 5,
    total: 9,
  });
  assert.deepEqual(
    report.site.counts,
    Object.fromEntries(Object.entries(render.counts).map(([name, value]) => [name, value * 4])),
  );
  assert.deepEqual(
    report.site.byIssuerMethod.map(({ issuerName, method }) => ({ issuerName, method })),
    [
      { issuerName: "alpha", method: "ECDH-P256" },
      { issuerName: "beta", method: "RSA-OAEP" },
    ],
  );
});

test("equivalent unordered plain input returns one stable frozen report", () => {
  const first = baseInput();
  const second = baseInput();
  second.renders[0].accessGroups.reverse();
  second.renders[0].items.reverse();
  second.renders[0].items[0].accessGroups.reverse();
  second.renders[0].issuers.reverse();

  const left = planSiteResources(first);
  const right = planSiteResources(second);
  assert.deepEqual(right, left);
  assert.ok(Object.isFrozen(left));
  assert.ok(Object.isFrozen(left.renders[0].issuers[0].counts));
});

test("an explicit grant selection is scenario data and cannot select unavailable candidates", () => {
  const input = baseInput();
  input.renders[0].responseScenario = {
    issuers: [
      {
        issuerName: "beta",
        directContentKeys: 0,
        families: [
          { accessGroup: "premium", exactMembers: 1, chainMembers: 1, projectedLeaves: 2 },
        ],
      },
    ],
  };
  const report = planSiteResources(input);
  assert.equal(report.renders[0].certainty, "scenario");
  assert.equal(
    report.renders[0].issuers.find((issuer) => issuer.issuerName === "alpha").response.total,
    0,
  );
  assert.deepEqual(
    report.renders[0].issuers.find((issuer) => issuer.issuerName === "beta").response,
    {
      directContentKeys: 0,
      exactMembers: 1,
      chainMembers: 1,
      projectedLeaves: 2,
      total: 4,
    },
  );

  input.renders[0].responseScenario.issuers[0].directContentKeys = 1;
  assert.throws(
    () => planSiteResources(input),
    (error) => error.code === "bad_config" && /unavailable direct/.test(error.message),
  );
});

test("unknown policy is an upper bound and clamps projected leaves to the fixed response maxima", () => {
  const groups = [oneChainGroup("familyA", 2, MAX_POSITIONS_PER_WINDOW)];
  const report = planSiteResources(chainInput(groups));
  const issuer = report.renders[0].issuers[0];
  assert.equal(issuer.counts.projectedLeafCandidates, 2 * MAX_POSITIONS_PER_WINDOW);
  assert.equal(issuer.response.projectedLeaves, MAX_EXACT_LEAVES_PER_FAMILY);
  assert.equal(issuer.certainty, "upperBound");

  const many = Array.from({ length: 8 }, (_, index) =>
    oneChainGroup(`family${String.fromCharCode(65 + index)}`, 2, 40),
  );
  const aggregate = planSiteResources(chainInput(many)).renders[0].issuers[0];
  assert.equal(aggregate.response.projectedLeaves, MAX_EXACT_LEAVES_PER_RESPONSE);
});

test("chain-only issuer delivery still counts publisher exact wraps, not exact issuer members", () => {
  const report = planSiteResources(chainInput([oneChainGroup("family", 1, 3)]));
  const render = report.renders[0];
  const issuer = render.issuers[0];
  assert.equal(render.counts.contentKeyWraps, 1);
  assert.equal(issuer.counts.exactFamilies, 0);
  assert.equal(issuer.counts.exactMembers, 0);
  assert.equal(issuer.counts.chainFamilies, 1);
  assert.equal(issuer.counts.chainMembers, 1);
});

test("zero exact members describes a direct-only group and cannot create a reusable route", () => {
  const direct = baseInput();
  direct.renders[0].accessGroups = [{ name: "premium", exactMembers: 0 }];
  direct.renders[0].items = [{ name: "article", accessGroups: ["premium"] }];
  direct.renders[0].issuers = [
    {
      issuerName: "alpha",
      method: "ECDH-P256",
      supply: { suppliedAccessGroups: [], directContentKeys: true },
    },
  ];
  const report = planSiteResources(direct);
  assert.equal(report.renders[0].counts.contentKeyWraps, 0);
  assert.equal(report.renders[0].counts.directSealedCapabilities, 1);

  direct.renders[0].issuers[0].supply = {
    suppliedAccessGroups: ["premium"],
    directContentKeys: false,
  };
  assert.throws(
    () => planSiteResources(direct),
    (error) => error.code === "bad_config" && /no complete issuer route/.test(error.message),
  );
});

test("unused group declarations are refused rather than counted as phantom capability families", () => {
  const input = baseInput();
  input.renders[0].accessGroups.push({ name: "unused", exactMembers: 100 });
  assert.throws(
    () => planSiteResources(input),
    (error) => error.code === "bad_config" && /declares unused accessGroup/.test(error.message),
  );
});

test("every fixed bound admits its ceiling and refuses an explicit one-over use", () => {
  const positionCeiling = planSiteResources(chainInput([oneChainGroup("family", 1)]));
  assert.equal(positionCeiling.renders[0].accessGroups[0].name, "family");
  assert.equal(MAX_POSITIONS_PER_WINDOW, 288);

  assert.throws(
    () =>
      planSiteResources(
        chainInput([
          {
            name: "family",
            exactMembers: 1,
            chain: {
              chainsPerDay: 4,
              periodMinutes: 1,
              windows: [{ projectedLeaves: 1 }],
            },
          },
        ]),
      ),
    (error) => error.code === "bad_config" && /tooManyPositions/.test(error.message),
  );

  assert.doesNotThrow(() =>
    planSiteResources(chainInput([oneChainGroup("family", MAX_CHAIN_MEMBERS_PER_FAMILY)])),
  );
  assert.throws(
    () =>
      planSiteResources(chainInput([oneChainGroup("family", MAX_CHAIN_MEMBERS_PER_FAMILY + 1)])),
    (error) => error.code === "bad_config" && /protocol maximum is 2/.test(error.message),
  );

  const eightFamilies = Array.from({ length: 8 }, (_, index) =>
    oneChainGroup(`family${String.fromCharCode(65 + index)}`, 2),
  );
  assert.doesNotThrow(() => planSiteResources(chainInput(eightFamilies)));
  assert.throws(
    () => planSiteResources(chainInput([...eightFamilies, oneChainGroup("familyZ", 1)])),
    (error) => error.code === "bad_config" && /protocol maximum is 16/.test(error.message),
  );

  const projected = oneChainGroup("family", 2, 200);
  const familyOneOver = {
    issuers: [
      {
        issuerName: "issuer",
        families: [{ accessGroup: "family", projectedLeaves: MAX_EXACT_LEAVES_PER_FAMILY + 1 }],
      },
    ],
  };
  assert.throws(
    () => planSiteResources(chainInput([projected], familyOneOver)),
    (error) => error.code === "bad_config" && /protocol maximum is 288/.test(error.message),
  );

  const responseGroups = [oneChainGroup("familyA", 2, 150), oneChainGroup("familyB", 2, 150)];
  const responseOneOver = {
    issuers: [
      {
        issuerName: "issuer",
        families: [
          { accessGroup: "familyA", projectedLeaves: 256 },
          { accessGroup: "familyB", projectedLeaves: MAX_EXACT_LEAVES_PER_RESPONSE - 255 },
        ],
      },
    ],
  };
  assert.throws(
    () => planSiteResources(chainInput(responseGroups, responseOneOver)),
    (error) => error.code === "bad_config" && /protocol maximum is 512/.test(error.message),
  );
});

test("a tighter local limit is distinct, takes precedence and names the first binding dimension", () => {
  const input = chainInput([oneChainGroup("family", 1, 2)]);
  input.renders[0].accessGroups[0].chain.chainsPerDay = 2;
  input.renders[0].accessGroups[0].chain.periodMinutes = 60;
  input.localLimits = { chainMembersPerFamily: 1, chainMembersPerMessage: 2 };
  const report = planSiteResources(input);
  const binding = report.renders[0].firstBindingDimension;
  assert.equal(binding.dimension, "chainMembersPerFamily");
  assert.equal(binding.limitingSource, "local");
  assert.equal(binding.remaining, 0);
  const row = report.renders[0].limits.find(
    (candidate) => candidate.dimension === "chainMembersPerFamily",
  );
  assert.deepEqual(
    { protocol: row.protocolLimit, local: row.localLimit, effective: row.effectiveLimit },
    {
      protocol: MAX_CHAIN_MEMBERS_PER_FAMILY,
      local: 1,
      effective: 1,
    },
  );

  const messageInput = chainInput([oneChainGroup("family", 2, 2)]);
  messageInput.localLimits = { chainMembersPerMessage: 1 };
  assert.throws(
    () => planSiteResources(messageInput),
    (error) => error.code === "bad_config" && /local limit is 1/.test(error.message),
  );
  messageInput.localLimits.chainMembersPerMessage = MAX_CHAIN_MEMBERS_PER_MESSAGE + 1;
  assert.throws(
    () => planSiteResources(messageInput),
    (error) => error.code === "bad_config" && /not redefine/.test(error.message),
  );
});

test("incomplete routes and chain delivery without a chain plan fail before a report exists", () => {
  const input = baseInput();
  input.renders[0].issuers = [
    {
      issuerName: "alpha",
      method: "ECDH-P256",
      supply: {
        suppliedAccessGroups: [],
        directContentKeys: false,
      },
    },
  ];
  assert.throws(
    () => planSiteResources(input),
    (error) => error.code === "bad_config" && /no complete issuer route/.test(error.message),
  );

  const missing = baseInput();
  missing.renders[0].issuers[0].supply = {
    suppliedAccessGroups: ["free"],
    periodKeyDelivery: { free: ["chain"] },
  };
  assert.throws(
    () => planSiteResources(missing),
    (error) => error.code === "bad_config" && /without a chain plan/.test(error.message),
  );
});

test("only plain planning data enters, and runtime wrap identity remains excluded", () => {
  for (const forbidden of [() => {}, new Date(), new Uint8Array(16), Symbol("key")]) {
    const input = baseInput();
    input.runtime = forbidden;
    assert.throws(
      () => planSiteResources(input),
      (error) => ["bad_config", "unsupported_option"].includes(error.code),
    );
  }
  const input = baseInput();
  input.renders[0].issuers[0].supply = { contentKeyWrap: {} };
  assert.throws(
    () => planSiteResources(input),
    (error) => error.code === "unsupported_option" && /contentKeyWrap identity/.test(error.message),
  );

  let called = false;
  class RuntimeRenders extends Array {
    map(...args) {
      called = true;
      return super.map(...args);
    }
  }
  const subclassed = baseInput();
  subclassed.renders = new RuntimeRenders(...subclassed.renders);
  assert.throws(
    () => planSiteResources(subclassed),
    (error) => error.code === "bad_config" && /runtime objects/.test(error.message),
  );
  assert.equal(called, false);

  const nullSupply = baseInput();
  nullSupply.renders[0].issuers[0].supply = null;
  assert.throws(
    () => planSiteResources(nullSupply),
    (error) => error.code === "bad_config" && /supply.*object/.test(error.message),
  );
});

test("sparse planning arrays refuse as typed malformed data before they can distort capability counts", () => {
  const topLevelHole = baseInput();
  topLevelHole.renders.push(undefined);
  delete topLevelHole.renders[1];

  const windowHole = chainInput([oneChainGroup("family", 2, 1)]);
  delete windowHole.renders[0].accessGroups[0].chain.windows[1];

  for (const input of [topLevelHole, windowHole]) {
    assert.throws(
      () => planSiteResources(input),
      (error) => error.code === "bad_config" && /sparse array/.test(error.message),
    );
  }
});

test("a reachable name needs a usable route from its named issuer, not only another issuer", () => {
  const input = baseInput();
  input.renders[0].accessGroups = [{ name: "premium", exactMembers: 0 }];
  input.renders[0].items = [{ name: "article", accessGroups: ["premium"] }];
  input.renders[0].issuers = [
    {
      issuerName: "alpha",
      method: "ECDH-P256",
      supply: {
        suppliedAccessGroups: ["premium"],
        directContentKeys: false,
        reachableContentNames: ["article"],
      },
    },
    {
      issuerName: "beta",
      method: "RSA-OAEP",
      supply: {
        suppliedAccessGroups: [],
        directContentKeys: true,
      },
    },
  ];

  assert.throws(
    () => planSiteResources(input),
    (error) =>
      error.code === "bad_config" && /no complete issuer route.*article/.test(error.message),
  );
});

test("the planner source imports only browser-safe base value and validation modules", async () => {
  const source = await readFile(
    new URL("../../core-publisher/siteResourcePlan.js", import.meta.url),
    "utf8",
  );
  const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]);
  assert.deepEqual(imports, [
    "../core-shared/errors.js",
    "../core-shared/names.js",
    "../core-shared/geometryBounds.js",
    "../core-shared/exactPeriodProfiles.js",
    "./issuerSupplyPlan.js",
  ]);
  assert.doesNotMatch(
    imports.join("\n"),
    /globalThis|\bcrypto\b|\bwindow\b|\bdocument\b|node:|adapter-|demo\/|extensions\//,
  );
});

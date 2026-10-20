// @ts-check

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { test as full, portableTest } from "../support/portable-test.js";

import { planSiteResources } from "../../core-publisher/siteResourcePlan.js";
import {
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_PERIOD_KEYS_PER_FAMILY,
  MAX_PERIOD_KEYS_PER_RESPONSE,
  MAX_POSITIONS_PER_WINDOW,
} from "../../core-shared/geometryBounds.js";

const test = portableTest("portable-publisher");
const dynamicTest = portableTest("portable-publisher-dynamic");

function baseInput() {
  return {
    renders: [
      {
        name: "front-page",
        volume: 4,
        accessGroups: [
          {
            name: "premium",
            periodKeyMembers: 2,
            chain: {
              chainsPerDay: 2,
              periodMinutes: 60,
              windows: [{ projectedPeriodKeys: 3 }, { projectedPeriodKeys: 2 }],
            },
          },
          { name: "free", periodKeyMembers: 1 },
        ],
        items: [
          { name: "article", accessGroups: ["premium"], volume: 2 },
          { name: "brief", accessGroups: ["premium", "free"] },
        ],
        issuers: [
          {
            issuerName: "alpha",
            method: "ecdh-p256",
            supply: {
              contentKeyNames: ["article", "brief"],
              suppliedAccessGroups: ["premium", "free"],
            },
          },
          {
            issuerName: "beta",
            method: "rsa-oaep",
            supply: {
              suppliedAccessGroups: ["premium"],
              contentKeyNames: [],
              reachableContentNames: ["article"],
              periodKeyDelivery: { premium: ["period-keys", "chain-keys"] },
            },
          },
        ],
      },
    ],
  };
}

function oneChainGroup(name, windows, projectedPeriodKeys = 1) {
  return {
    name,
    periodKeyMembers: 1,
    chain: {
      chainsPerDay: 5,
      periodMinutes: 1,
      windows: Array.from({ length: windows }, () => ({ projectedPeriodKeys })),
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
            method: "ecdh-p256",
            supply: {
              contentKeyNames: [],
              suppliedAccessGroups: groups.map((group) => group.name),
              periodKeyDelivery: Object.fromEntries(
                groups.map((group) => [group.name, ["chain-keys"]]),
              ),
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

  assert.equal(report.profile.periodKeys.periodKeyBytes, 16);
  assert.equal(report.profile.periodKeys.wrapAlgorithm, "AES-128-GCM");
  assert.equal(render.certainty, "upperBound");
  assert.deepEqual(render.counts, {
    protectedItems: 3,
    contentKeyInstances: 3,
    contentToAccessGroupAssignments: 4,
    contentKeyWraps: 7,
    issuerRoutes: 13,
    sealedContentKeys: 3,
    periodKeyFamilies: 3,
    periodKeyMembers: 5,
    periodKeyResponseCandidates: 5,
    chainFamilies: 1,
    chainMembers: 2,
    chainWindows: 2,
    projectedPeriodKeyCandidates: 5,
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
    sealedContentKeys: 2,
  });
  const premium = render.accessGroups.find((group) => group.name === "premium").counts;
  assert.deepEqual(
    {
      issuerRoutes: premium.issuerRoutes,
      periodKeyResponseCandidates: premium.periodKeyResponseCandidates,
      responseKeyCandidates: premium.responseKeyCandidates,
    },
    { issuerRoutes: 9, periodKeyResponseCandidates: 4, responseKeyCandidates: 11 },
  );
  assert.deepEqual(render.issuers.find((issuer) => issuer.issuerName === "beta").response, {
    contentKeys: 0,
    periodKeyMembers: 2,
    chainMembers: 2,
    projectedPeriodKeys: 5,
    total: 9,
  });
  assert.deepEqual(
    report.site.counts,
    Object.fromEntries(Object.entries(render.counts).map(([name, value]) => [name, value * 4])),
  );
  assert.deepEqual(
    report.site.byIssuerMethod.map(({ issuerName, method }) => ({ issuerName, method })),
    [
      { issuerName: "alpha", method: "ecdh-p256" },
      { issuerName: "beta", method: "rsa-oaep" },
    ],
  );
});

full("equivalent unordered plain input returns one stable frozen report", () => {
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
        contentKeys: 0,
        families: [
          { accessGroup: "premium", periodKeyMembers: 1, chainMembers: 1, projectedPeriodKeys: 2 },
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
      contentKeys: 0,
      periodKeyMembers: 1,
      chainMembers: 1,
      projectedPeriodKeys: 2,
      total: 4,
    },
  );

  input.renders[0].responseScenario.issuers[0].contentKeys = 1;
  assert.throws(
    () => planSiteResources(input),
    (error) => error.code === "bad_config" && /unavailable content keys/.test(error.message),
  );
});

test("unknown policy is an upper bound and clamps projected period keys to the fixed response maxima", () => {
  const groups = [oneChainGroup("familyA", 2, MAX_POSITIONS_PER_WINDOW)];
  const report = planSiteResources(chainInput(groups));
  const issuer = report.renders[0].issuers[0];
  assert.equal(issuer.counts.projectedPeriodKeyCandidates, 2 * MAX_POSITIONS_PER_WINDOW);
  assert.equal(issuer.response.projectedPeriodKeys, MAX_PERIOD_KEYS_PER_FAMILY);
  assert.equal(issuer.certainty, "upperBound");

  const many = Array.from({ length: 8 }, (_, index) =>
    oneChainGroup(`family${String.fromCharCode(65 + index)}`, 2, 40),
  );
  const aggregate = planSiteResources(chainInput(many)).renders[0].issuers[0];
  assert.equal(aggregate.response.projectedPeriodKeys, MAX_PERIOD_KEYS_PER_RESPONSE);
});

test("chain-only issuer delivery still counts publisher period-key wraps, not period-key issuer members", () => {
  const report = planSiteResources(chainInput([oneChainGroup("family", 1, 3)]));
  const render = report.renders[0];
  const issuer = render.issuers[0];
  assert.equal(render.counts.contentKeyWraps, 1);
  assert.equal(issuer.counts.periodKeyFamilies, 0);
  assert.equal(issuer.counts.periodKeyMembers, 0);
  assert.equal(issuer.counts.chainFamilies, 1);
  assert.equal(issuer.counts.chainMembers, 1);
});

test("zero period-key members describes a content-key-only group and cannot create a reusable route", () => {
  const contentKeyOnly = baseInput();
  contentKeyOnly.renders[0].accessGroups = [{ name: "premium", periodKeyMembers: 0 }];
  contentKeyOnly.renders[0].items = [{ name: "article", accessGroups: ["premium"] }];
  contentKeyOnly.renders[0].issuers = [
    {
      issuerName: "alpha",
      method: "ecdh-p256",
      supply: { suppliedAccessGroups: [], contentKeyNames: ["article"] },
    },
  ];
  const report = planSiteResources(contentKeyOnly);
  assert.equal(report.renders[0].counts.contentKeyWraps, 0);
  assert.equal(report.renders[0].counts.sealedContentKeys, 1);

  contentKeyOnly.renders[0].issuers[0].supply = {
    suppliedAccessGroups: ["premium"],
    contentKeyNames: [],
  };
  assert.throws(
    () => planSiteResources(contentKeyOnly),
    (error) => error.code === "bad_config" && /no complete issuer route/.test(error.message),
  );
});

// Plain data, but outside the portable-publisher selection until its count is
// raised with it.
full(
  "sealed content keys count only the selected content names, and a missing selection is refused",
  () => {
    const input = baseInput();
    input.renders[0].issuers[0].supply = {
      contentKeyNames: ["brief"],
      suppliedAccessGroups: ["premium", "free"],
    };
    const alpha = planSiteResources(input).renders[0].issuers.find(
      (issuer) => issuer.issuerName === "alpha",
    );
    // brief has volume 1; article (volume 2) is not selected, so it adds none.
    assert.equal(alpha.counts.sealedContentKeys, 1);

    // The whole-render selection counts both items, three instances in all. If
    // the count ignored the selection, the narrowed plan above would read 3.
    const whole = planSiteResources(baseInput()).renders[0].issuers.find(
      (issuer) => issuer.issuerName === "alpha",
    );
    assert.equal(whole.counts.sealedContentKeys, 3);

    for (const supply of [
      undefined,
      { suppliedAccessGroups: ["premium"] },
      { contentKeyNames: [] },
    ]) {
      const missing = baseInput();
      if (supply === undefined) delete missing.renders[0].issuers[0].supply;
      else missing.renders[0].issuers[0].supply = supply;
      assert.throws(
        () => planSiteResources(missing),
        (error) =>
          error.code === "bad_config" &&
          /no (content-key|accessGroup) selection/.test(error.message),
      );
    }
  },
);

test("unused group declarations are refused rather than counted as phantom capability families", () => {
  const input = baseInput();
  input.renders[0].accessGroups.push({ name: "unused", periodKeyMembers: 100 });
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
            periodKeyMembers: 1,
            chain: {
              chainsPerDay: 4,
              periodMinutes: 1,
              windows: [{ projectedPeriodKeys: 1 }],
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
        families: [{ accessGroup: "family", projectedPeriodKeys: MAX_PERIOD_KEYS_PER_FAMILY + 1 }],
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
          { accessGroup: "familyA", projectedPeriodKeys: 256 },
          { accessGroup: "familyB", projectedPeriodKeys: MAX_PERIOD_KEYS_PER_RESPONSE - 255 },
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
      method: "ecdh-p256",
      supply: {
        suppliedAccessGroups: [],
        contentKeyNames: [],
      },
    },
  ];
  assert.throws(
    () => planSiteResources(input),
    (error) => error.code === "bad_config" && /no complete issuer route/.test(error.message),
  );

  const missing = baseInput();
  missing.renders[0].issuers[0].supply = {
    contentKeyNames: [],
    suppliedAccessGroups: ["free"],
    periodKeyDelivery: { free: ["chain-keys"] },
  };
  assert.throws(
    () => planSiteResources(missing),
    (error) => error.code === "bad_config" && /without a chain plan/.test(error.message),
  );
});

// A bridge carries a date, bytes, a null and a plain record, so these inputs cross. The declared
// input type admits none of them, so a typed port meets them only in this selection.
dynamicTest("only plain planning data enters, and runtime wrap identity remains excluded", () => {
  for (const forbidden of [new Date(), new Uint8Array(16)]) {
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

  const nullSupply = baseInput();
  nullSupply.renders[0].issuers[0].supply = null;
  assert.throws(
    () => planSiteResources(nullSupply),
    (error) => error.code === "bad_config" && /supply.*object/.test(error.message),
  );
});

// A function, a symbol and an array subclass cannot cross a bridge, so these stay contentKeyOnly.
full("a function, a symbol or an array subclass is refused before a callback runs", () => {
  for (const forbidden of [() => {}, Symbol("key")]) {
    const input = baseInput();
    input.runtime = forbidden;
    assert.throws(
      () => planSiteResources(input),
      (error) => ["bad_config", "unsupported_option"].includes(error.code),
    );
  }

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
});

full(
  "sparse planning arrays refuse as typed malformed data before they can distort capability counts",
  () => {
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
  },
);

test("a reachable name needs a usable route from its named issuer, not only another issuer", () => {
  const input = baseInput();
  input.renders[0].accessGroups = [{ name: "premium", periodKeyMembers: 0 }];
  input.renders[0].items = [{ name: "article", accessGroups: ["premium"] }];
  input.renders[0].issuers = [
    {
      issuerName: "alpha",
      method: "ecdh-p256",
      supply: {
        suppliedAccessGroups: ["premium"],
        contentKeyNames: [],
        reachableContentNames: ["article"],
      },
    },
    {
      issuerName: "beta",
      method: "rsa-oaep",
      supply: {
        suppliedAccessGroups: [],
        contentKeyNames: ["article"],
      },
    },
  ];

  assert.throws(
    () => planSiteResources(input),
    (error) =>
      error.code === "bad_config" && /no complete issuer route.*article/.test(error.message),
  );
});

full("the planner source imports only browser-safe base value and validation modules", async () => {
  const source = await readFile(
    new URL("../../core-publisher/siteResourcePlan.js", import.meta.url),
    "utf8",
  );
  const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]);
  assert.deepEqual(imports, [
    "../core-shared/errors.js",
    "../core-shared/names.js",
    "../core-shared/geometryBounds.js",
    "../core-shared/periodKeyProfiles.js",
    "./issuerSupplyPlan.js",
  ]);
  assert.doesNotMatch(
    imports.join("\n"),
    /globalThis|\bcrypto\b|\bwindow\b|\bdocument\b|node:|adapter-|demo\/|extensions\//,
  );
});

full("an issuer method takes the lowercase provisioning token and no uppercase alias", () => {
  // The method names the envelope the issuer's opening key selects. The
  // uppercase spellings are client-bound method names and plan nothing here.
  for (const method of ["ECDH-P256", "RSA-OAEP", "Ecdh-P256"]) {
    const input = baseInput();
    input.renders[0].issuers[0].method = method;
    assert.throws(
      () => planSiteResources(input),
      (/** @type {any} */ error) =>
        error.code === "bad_config" &&
        error.message === 'issuer "alpha" method is ecdh-p256 or rsa-oaep',
      method,
    );
  }
});

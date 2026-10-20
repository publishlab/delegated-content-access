// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  classifyTestTags,
  completedTestFiles,
  discoverFixturePackageRoots,
  evaluateScenario,
  failedTestFiles,
  recordedPackageCheckCommand,
  reduceClaimTestEvents,
  selectEvidenceTestFiles,
  validateClaimIndex,
  validateRecordedPackageInventory,
} from "./claim-index.js";

const realIndex = JSON.parse(
  readFileSync(new URL("../../verification/claim-index/v1.json", import.meta.url), "utf8"),
);
const realCatalogue = JSON.parse(
  readFileSync(new URL("../../verification/profile-catalogue/v1.json", import.meta.url), "utf8"),
);

test("fixture and vector records keep their owning integrity checkers", () => {
  assert.deepEqual(
    recordedPackageCheckCommand(
      "verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition/",
    ),
    {
      executable: "node",
      args: ["js/tools/record-period-key-composition.js", "--check"],
    },
  );
  assert.deepEqual(
    recordedPackageCheckCommand("verification/vectors/v1/baseline/ecdh-p256-envelope-open/"),
    {
      executable: "sh",
      args: ["verification/vectors/check-sums.sh", "v1/baseline/ecdh-p256-envelope-open"],
    },
  );
  assert.deepEqual(
    recordedPackageCheckCommand("verification/fixtures/v1/baseline/issuer-admission"),
    { executable: "node", args: ["js/tools/make-vectors.js", "--check"] },
  );
  assert.deepEqual(
    recordedPackageCheckCommand(
      "verification/fixtures/v1/profiles/dca-profile-chain-keys/geometry-admission",
    ),
    {
      executable: "node",
      args: ["js/tools/record-chain-keys-geometry-admission.js", "--check"],
    },
  );
  assert.throws(
    () => recordedPackageCheckCommand("verification/conformance-primitives/"),
    /no recorded package checker/,
  );
});

test("fixture discovery keeps nested packages visible and rejects undeclared container files", () => {
  const root = mkdtempSync(join(tmpdir(), "dca-scoped-index-"));
  try {
    mkdirSync(join(root, "v1", "profiles", "dca-profile-period-keys", "composition"), {
      recursive: true,
    });
    assert.deepEqual(discoverFixturePackageRoots(root), [
      "fixtures/v1/profiles/dca-profile-period-keys/composition",
    ]);
    writeFileSync(join(root, "v1", "stray.json"), "{}\n");
    assert.throws(() => discoverFixturePackageRoots(root), /undeclared stray\.json/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("package inventory checks directory presence without granting role evidence", () => {
  assert.doesNotThrow(() =>
    validateRecordedPackageInventory(
      ["v1/baseline/a"],
      ["vectors/v1/baseline/a"],
      ["vectors/v1/baseline/a", "fixtures/v1/reference/r"],
      ["fixtures/v1/reference/r"],
    ),
  );
  assert.throws(
    () => validateRecordedPackageInventory([], ["vectors/v1/baseline/new"], [], []),
    /recorded package inventory mismatch/,
  );
  assert.equal(
    realIndex.recordedPackages
      .find(
        (entry) => entry.id === "fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix",
      )
      .associatedDuties.includes("dca-profile-chain-keys/issuer/chain-output"),
    true,
  );
});

test("the migrated index validates and makes absent catalogue profiles visibly unclaimed", () => {
  assert.equal(validateClaimIndex(realIndex, realCatalogue), realIndex);
  const claimedProfiles = new Set(realIndex.support.map((entry) => entry.profile));
  assert.deepEqual(
    realCatalogue.profiles
      .filter((entry) => !claimedProfiles.has(entry.id))
      .map((entry) => entry.id),
    ["dca-profile-browser-origin", "dca-profile-recipient-grant-unlock"],
  );
  assert.equal(realIndex.deploymentEnablement, null);
  assert.equal(realIndex.scenarios.length, 8);
});

test("empty role scopes cannot pass as verified composition evidence", () => {
  const changed = structuredClone(realIndex);
  changed.scenarios[0].roles = [];
  changed.scenarios[0].compositionEvidence.roles = [];
  assert.throws(
    () => validateClaimIndex(changed, realCatalogue),
    /scenario .*roles must name at least one role/,
  );
  changed.scenarios[0].roles = ["publisher", "issuer", "client"];
  changed.subject.roles = [];
  assert.throws(
    () => validateClaimIndex(changed, realCatalogue),
    /subject\.roles must name at least one role/,
  );
});

test("baseline dependency duties cannot disappear when someone narrows the required list", () => {
  const changed = structuredClone(realIndex);
  changed.scenarios[0].requiredDuties = changed.scenarios[0].requiredDuties.filter(
    (duty) => duty !== "dca-profile-baseline/publisher/representation-declaration",
  );
  assert.throws(() => validateClaimIndex(changed, realCatalogue), /omits mandatory baseline duty/);
});

test("every projected duty is required or explicitly unresolved, never silently dropped", () => {
  const changed = structuredClone(realIndex);
  changed.scenarios[2].unresolvedApplicability =
    changed.scenarios[2].unresolvedApplicability.filter(
      (duty) => duty !== "dca-profile-content-compression/client/gzip-decompression",
    );
  assert.throws(
    () => validateClaimIndex(changed, realCatalogue),
    /leaves catalogue duty unclassified/,
  );
});

test("invalid typed choices and forbidden chain combinations are validation errors", () => {
  const badValue = structuredClone(realIndex);
  badValue.scenarios[2].selections["dca-profile-content-compression"].itemRepresentation = "brotli";
  assert.throws(
    () => validateClaimIndex(badValue, realCatalogue),
    /invalid dca-profile-content-compression/,
  );
  const badCombination = structuredClone(realIndex);
  badCombination.scenarios[3].selections["dca-profile-chain-keys"].selectedInput = "period-keys";
  assert.throws(() => validateClaimIndex(badCombination, realCatalogue), /invalid combination/);
});

test("a supported chain alternative does not imply a Cartesian product", () => {
  const changed = structuredClone(realIndex);
  const clientSupport = changed.support.find(
    (entry) => entry.profile === "dca-profile-chain-keys" && entry.role === "client",
  );
  clientSupport.compatibleSelections = [
    {
      selectedInput: "chain-keys",
      relay: true,
      projectedPeriodKeyAdmission: true,
      clientDerivation: false,
      responseForm: "direct",
    },
  ];
  const result = evaluateScenario(
    changed,
    realCatalogue,
    "chain-output-with-simulated-html-carrier",
    [],
  );
  assert.equal(result.supportStatus, "unsupported");
  assert.ok(result.unsupportedSelections.includes("dca-profile-chain-keys/client"));
});

test("support selection comparison ignores JSON property ordering", () => {
  const changed = structuredClone(realIndex);
  const clientSupport = changed.support.find(
    (entry) => entry.profile === "dca-profile-chain-keys" && entry.role === "client",
  );
  clientSupport.compatibleSelections[0] = {
    responseForm: "direct",
    clientDerivation: false,
    projectedPeriodKeyAdmission: true,
    relay: true,
    selectedInput: "chain-keys",
  };
  const result = evaluateScenario(
    changed,
    realCatalogue,
    "chain-period-projection-with-simulated-html-carrier",
    [],
  );
  assert.ok(!result.unsupportedSelections.includes("dca-profile-chain-keys/client"));
});

test("missing role support is unclaimed, while an explicit unsupported declaration stays distinct", () => {
  const missing = structuredClone(realIndex);
  missing.support = missing.support.filter(
    (entry) => !(entry.profile === "dca-profile-html-carrier" && entry.role === "publisher"),
  );
  const unclaimed = evaluateScenario(missing, realCatalogue, "html-carrier-in-simulated-dom", []);
  assert.equal(unclaimed.supportStatus, "unclaimed");
  assert.ok(unclaimed.unclaimedSupport.includes("dca-profile-html-carrier/publisher"));

  const unsupported = structuredClone(realIndex);
  unsupported.support.find(
    (entry) => entry.profile === "dca-profile-html-carrier" && entry.role === "publisher",
  ).status = "unsupported";
  assert.equal(
    evaluateScenario(unsupported, realCatalogue, "html-carrier-in-simulated-dom", []).supportStatus,
    "unsupported",
  );
});

test("exact scenario and test identity gate duty credit; unrelated tags and package checks cannot fill it", () => {
  const scenario = realIndex.scenarios[0];
  const expected = scenario.evidence[0];
  const matching = {
    file: expected.test.file,
    name: expected.test.name,
    outcome: "passed",
    duties: [...expected.duties],
  };
  const unrelated = {
    file: "test-profiles/dca-profile-html-carrier.test.js",
    name: "an unrelated passing test with the same baseline tag",
    outcome: "passed",
    duties: ["dca-profile-baseline/client/representation-processing"],
  };
  const result = evaluateScenario(realIndex, realCatalogue, scenario.id, [matching, unrelated]);
  assert.equal(result.status, "incomplete");
  assert.ok(result.missingDuties.includes("dca-profile-baseline/client/representation-processing"));
  assert.ok(result.recordedPackages.every((entry) => entry.status === "not-checked"));
});

test("ambiguous duplicate observed identities cannot let a later pass hide a failure", () => {
  const scenario = realIndex.scenarios[0];
  const expected = scenario.evidence[0];
  const event = {
    file: expected.test.file,
    name: expected.test.name,
    duties: expected.duties,
  };
  assert.throws(
    () =>
      evaluateScenario(realIndex, realCatalogue, scenario.id, [
        { ...event, outcome: "failed" },
        { ...event, outcome: "passed" },
      ]),
    /ambiguous observed test identity/,
  );
});

test("package integrity is necessary for completeness but never earns a role duty", () => {
  const catalogue = {
    authority: "profile-spec.md",
    baseline: "base",
    profiles: [{ id: "base", dependsOn: [], ref: "#base" }],
    duties: [{ id: "base/client/open", profile: "base", role: "client", ref: "#open" }],
    selections: [],
  };
  const index = {
    schema: "dca-scoped-profile-evidence/v1",
    catalogue: "verification/profile-catalogue/v1.json",
    subject: { id: "fixture", roles: ["client"] },
    support: [
      {
        id: "base/client",
        profile: "base",
        role: "client",
        status: "supported",
        duties: ["base/client/open"],
        alternatives: {},
        compatibleSelections: [],
      },
    ],
    deploymentEnablement: null,
    scenarios: [
      {
        id: "one-open",
        requestedProfiles: ["base"],
        roles: ["client"],
        selections: {},
        requiredDuties: ["base/client/open"],
        unresolvedApplicability: [],
        recordedPackages: ["vectors/test"],
        legacy: { id: "old", declaredDuties: ["base/client/open"], algorithms: [], gaps: [] },
        compositionEvidence: {
          test: { file: "base.test.js", name: "opens one item" },
          roles: ["client"],
          requestedProfiles: ["base"],
        },
        evidence: [
          {
            test: { file: "base.test.js", name: "opens one item" },
            roles: ["client"],
            duties: ["base/client/open"],
          },
        ],
      },
    ],
    recordedPackages: [
      {
        id: "vectors/test",
        path: "verification/vectors/test",
        profile: null,
        associatedDuties: ["base/client/open"],
        status: "claim",
      },
    ],
  };
  const observed = [
    {
      file: "base.test.js",
      name: "opens one item",
      outcome: "passed",
      duties: ["base/client/open"],
    },
  ];
  assert.equal(evaluateScenario(index, catalogue, "one-open", observed).status, "incomplete");
  assert.equal(
    evaluateScenario(index, catalogue, "one-open", observed, [
      { id: "vectors/test", status: "failed" },
    ]).status,
    "failed",
  );
  const passed = evaluateScenario(index, catalogue, "one-open", observed, [
    { id: "vectors/test", status: "passed" },
  ]);
  assert.equal(passed.status, "verified-in-scope");
  assert.deepEqual(passed.passingDuties, ["base/client/open"]);
});

test("an exact matching pass can verify a fully declared, evidence-complete baseline scope", () => {
  const catalogue = {
    authority: "profile-spec.md",
    baseline: "base",
    profiles: [{ id: "base", dependsOn: [], ref: "#base" }],
    duties: [{ id: "base/client/open", profile: "base", role: "client", ref: "#open" }],
    selections: [],
  };
  const index = {
    schema: "dca-scoped-profile-evidence/v1",
    catalogue: "verification/profile-catalogue/v1.json",
    subject: { id: "fixture", roles: ["client"] },
    support: [
      {
        id: "base/client",
        profile: "base",
        role: "client",
        status: "supported",
        duties: ["base/client/open"],
        alternatives: {},
        compatibleSelections: [],
      },
    ],
    deploymentEnablement: null,
    scenarios: [
      {
        id: "one-open",
        requestedProfiles: ["base"],
        roles: ["client"],
        selections: {},
        requiredDuties: ["base/client/open"],
        unresolvedApplicability: [],
        recordedPackages: [],
        legacy: { id: "old", declaredDuties: ["base/client/open"], algorithms: [], gaps: [] },
        compositionEvidence: {
          test: { file: "base.test.js", name: "opens one item" },
          roles: ["client"],
          requestedProfiles: ["base"],
        },
        evidence: [
          {
            test: { file: "base.test.js", name: "opens one item" },
            roles: ["client"],
            duties: ["base/client/open"],
          },
        ],
      },
    ],
    recordedPackages: [],
  };
  const event = {
    file: "base.test.js",
    name: "opens one item",
    outcome: "passed",
    duties: ["base/client/open"],
  };
  assert.equal(evaluateScenario(index, catalogue, "one-open", [event]).status, "verified-in-scope");
});

test("a composition needs its own exact passing witness beyond separate role evidence", () => {
  const catalogue = {
    authority: "profile-spec.md",
    baseline: "base",
    profiles: [{ id: "base", dependsOn: [], ref: "#base" }],
    duties: [{ id: "base/client/open", profile: "base", role: "client", ref: "#open" }],
    selections: [],
  };
  const index = {
    schema: "dca-scoped-profile-evidence/v1",
    catalogue: "verification/profile-catalogue/v1.json",
    subject: { id: "fixture", roles: ["client"] },
    support: [
      {
        id: "base/client",
        profile: "base",
        role: "client",
        status: "supported",
        duties: ["base/client/open"],
        alternatives: {},
        compatibleSelections: [],
      },
    ],
    deploymentEnablement: null,
    scenarios: [
      {
        id: "one-open",
        requestedProfiles: ["base"],
        roles: ["client"],
        selections: {},
        requiredDuties: ["base/client/open"],
        unresolvedApplicability: [],
        recordedPackages: [],
        legacy: { id: "old", declaredDuties: ["base/client/open"], algorithms: [], gaps: [] },
        compositionEvidence: {
          test: { file: "compose.test.js", name: "host and client open together" },
          roles: ["client"],
          requestedProfiles: ["base"],
        },
        evidence: [
          {
            test: { file: "client.test.js", name: "client opens an item" },
            roles: ["client"],
            duties: ["base/client/open"],
          },
          {
            test: { file: "compose.test.js", name: "host and client open together" },
            roles: ["client"],
            duties: [],
          },
        ],
      },
    ],
    recordedPackages: [],
  };
  const roleEvidence = [
    {
      file: "client.test.js",
      name: "client opens an item",
      outcome: "passed",
      duties: ["base/client/open"],
    },
  ];
  const separateOnly = evaluateScenario(index, catalogue, "one-open", roleEvidence);
  assert.equal(separateOnly.status, "incomplete");
  assert.equal(separateOnly.composition.status, "missing");
  assert.deepEqual(separateOnly.passingDuties, ["base/client/open"]);

  const composed = evaluateScenario(index, catalogue, "one-open", [
    ...roleEvidence,
    {
      file: "compose.test.js",
      name: "host and client open together",
      outcome: "passed",
      duties: [],
    },
  ]);
  assert.equal(composed.status, "verified-in-scope");
});

test("an empty optional compatibility list is unverified rather than a wildcard", () => {
  const changed = structuredClone(realIndex);
  const clientSupport = changed.support.find(
    (entry) => entry.profile === "dca-profile-chain-keys" && entry.role === "client",
  );
  clientSupport.compatibleSelections = [];
  const result = evaluateScenario(
    changed,
    realCatalogue,
    "chain-output-with-simulated-html-carrier",
    [],
  );
  assert.ok(result.unverifiedSelections.includes("dca-profile-chain-keys/client"));
  assert.ok(!result.unsupportedSelections.includes("dca-profile-chain-keys/client"));
  assert.equal(result.status, "incomplete");
});

test("skipped and TODO tests do not satisfy exact evidence references", () => {
  const scenario = realIndex.scenarios[0];
  const selector = scenario.evidence[0];
  for (const outcome of ["skipped", "todo", "failed"]) {
    const result = evaluateScenario(realIndex, realCatalogue, scenario.id, [
      {
        file: selector.test.file,
        name: selector.test.name,
        outcome,
        duties: selector.duties,
      },
    ]);
    assert.notEqual(result.status, "verified-in-scope");
    assert.ok(result.missingDuties.length > 0);
  }
});

test("the event reducer preserves exact file/name, tags, and skip/TODO outcomes", () => {
  const events = [
    {
      type: "test:pass",
      data: {
        name: "runs",
        file: "/js/a.test.js",
        details: { type: "test" },
        tags: ["dca-profile-baseline/client/direct-admission"],
      },
    },
    {
      type: "test:pass",
      data: {
        name: "skips",
        file: "/js/a.test.js",
        details: { type: "test" },
        skip: "later",
        tags: ["dca-profile-baseline/client/direct-admission"],
      },
    },
    {
      type: "test:pass",
      data: {
        name: "todo",
        file: "/js/a.test.js",
        details: { type: "test" },
        todo: true,
        tags: [],
      },
    },
    {
      type: "test:pass",
      data: { name: "suite", file: "/js/a.test.js", details: { type: "suite" }, tags: ["unknown"] },
    },
  ];
  assert.deepEqual(
    reduceClaimTestEvents(events, realCatalogue).map((entry) => [entry.name, entry.outcome]),
    [
      ["runs", "passed"],
      ["skips", "skipped"],
      ["todo", "todo"],
    ],
  );
  assert.deepEqual(classifyTestTags(["envelope/ecdh-p256/issuer"], realCatalogue), {
    duties: [],
    untagged: true,
  });
  assert.throws(() => classifyTestTags(["not/a-duty"], realCatalogue), /unknown test duty tag/);
});

test("failed files still count as completed and can be reported by the runner", () => {
  const events = [
    { type: "test:summary", data: { file: "/js/failed.test.js", success: false } },
    { type: "test:summary", data: { file: "/js/passed.test.js", success: true } },
  ];
  const completed = completedTestFiles(events);
  assert.deepEqual([...completed].sort(), ["/js/failed.test.js", "/js/passed.test.js"]);
  assert.deepEqual([...failedTestFiles(events)], ["/js/failed.test.js"]);
});

test("focused command selects only referenced tests and full command covers the admitted gate", () => {
  const files = [
    ...new Set(
      realIndex.scenarios.flatMap((scenario) => scenario.evidence.map((row) => row.test.file)),
    ),
  ];
  const admitted = [...files, "test-tools/unrelated.test.js"];
  const focused = selectEvidenceTestFiles(admitted, files, "evidence");
  assert.deepEqual(focused.unobservedFiles, ["test-tools/unrelated.test.js"]);
  assert.equal(focused.selected.length, files.length);
  assert.equal(selectEvidenceTestFiles(admitted, files, "all").selected.length, admitted.length);
  assert.throws(
    () => selectEvidenceTestFiles(admitted, ["absent.test.js"], "evidence"),
    /outside test:unit/,
  );
});

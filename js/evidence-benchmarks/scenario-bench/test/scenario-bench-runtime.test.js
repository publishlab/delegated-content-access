// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { runBench } from "../runBench.js";
import { scenario as itemScenario } from "../scenarios/item.js";
import { scenario as chainScenario } from "../scenarios/chain-keys/groups.js";
import { scenario as compactScenario } from "../scenarios/chain-keys/compact-ecdh.js";
import { scenario as groupScenario } from "../scenarios/content-groups/groups.js";
import { checkedEndpoint, deliveryPartitions } from "../scenarios/_shared/exchange.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const scenarioUrl = new URL("../scenarios/item.js", import.meta.url).href;

/** The contentData names in wire order; each item is one named record. */
function contentNames(dcaData) {
  return dcaData.contentData.map((item) => item.contentName);
}

function checkMap(sample) {
  return Object.fromEntries(sample.checks.map((check) => [check.name, check]));
}

test("baseline case respects publisher, publisher-issuer, and full scopes", async () => {
  const publisher = await runBench({ scenario: itemScenario, measurement: { scope: "publisher" } });
  const publisherIssuer = await runBench({
    scenario: itemScenario,
    measurement: { scope: "publisher-issuer" },
  });
  const full = await runBench({ scenario: itemScenario, measurement: { scope: "full" } });

  for (const report of [publisher, publisherIssuer, full])
    assert.equal(report.success, true, JSON.stringify(report.checks));
  assert.ok(publisher.captures.delivery.text.length > 0);
  assert.ok(publisher.captures.dcaData.text.length > 0);
  assert.equal(publisher.captures.request.available, false);
  assert.equal(publisher.captures.response.available, false);
  assert.equal(publisher.cache.available, false);

  assert.ok(publisherIssuer.captures.request.text.length > 0);
  assert.ok(publisherIssuer.captures.response.text.length > 0);
  assert.ok(publisherIssuer.captures.delivery.text.length > 0);
  assert.ok(publisherIssuer.captures.dcaData.text.length > 0);
  assert.equal(publisherIssuer.timings.issuer.nested, false);
  assert.equal(publisherIssuer.cache.available, false);

  assert.ok(full.captures.request.text.length > 0);
  assert.ok(full.captures.response.text.length > 0);
  assert.equal(
    full.checks.some((check) => check.name === "item:bodytext" && check.passed),
    true,
  );
  assert.equal(full.timings.issuer.nested, true);
  assert.equal(full.timings.client.nested, false);
  assert.deepEqual(full.cache.before, {
    available: false,
    reason: "Baseline item-key resolver does not expose retained-key enumeration",
  });
  assert.deepEqual(full.cache.after, full.cache.before);
});

test("baseline resolves a saved two-item input and enforces a partial grant", async () => {
  const input = {
    publisher: {
      items: [
        { name: "first", value: "First saved article", contentType: "text/plain" },
        { name: "second", value: "Second saved article", contentType: "text/plain" },
      ],
    },
    issuer: { authorizedItems: ["first"] },
  };
  const report = await runBench({ scenario: itemScenario, input });
  assert.equal(report.success, true, JSON.stringify(report.checks));
  assert.deepEqual(report.setup.input.publisher.items, input.publisher.items);
  assert.deepEqual(report.setup.input.issuer.authorizedItems, ["first"]);
  const checks = checkMap(report.samples[0]);
  assert.equal(checks["item:first"].passed, true);
  assert.equal(checks["item:second"].passed, true);
  assert.equal(checks["item:second"].details.code, "no_key");
  assert.equal(report.work.unlock, 1);
  assert.deepEqual(contentNames(report.captures.dcaData.document).sort(), ["first", "second"]);
});

test("saved JSON input has equivalent callable and CLI execution", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "dca-bench-runtime-input-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const inputPath = join(dir, "saved-article.json");
  const input = {
    publisher: {
      resourceId: "saved-story",
      data: { section: "archive" },
      items: [{ name: "bodytext", value: "Saved article body", contentType: "text/plain" }],
    },
  };
  await writeFile(inputPath, `${JSON.stringify(input)}\n`);

  const callable = await runBench({
    scenario: itemScenario,
    input: JSON.parse(await readFile(inputPath, "utf8")),
  });
  const cli = spawnSync(
    process.execPath,
    [
      "cli.js",
      "--scenario",
      "scenarios/item.js",
      "--input",
      inputPath,
      "--format",
      "json",
      "--show",
      "all",
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(cli.status, 0, cli.stderr);
  const commandReport = JSON.parse(cli.stdout);
  assert.equal(callable.success, true, JSON.stringify(callable.checks));
  assert.equal(commandReport.success, true, cli.stdout);
  assert.deepEqual(commandReport.setup.input, callable.setup.input);
  for (const report of [callable, commandReport]) {
    assert.equal(
      report.checks.some((check) => check.name === "item:bodytext" && check.passed),
      true,
    );
    assert.equal(report.captures.dcaData.document.resource.resourceId, "saved-story");
    assert.deepEqual(contentNames(report.captures.dcaData.document), ["bodytext"]);
  }
});

test("two fresh samples keep one effective input and produce distinct renders", async () => {
  const report = await runBench({ scenario: itemScenario, measurement: { runs: 2 } });
  assert.equal(report.success, true, JSON.stringify(report.samples.map((sample) => sample.checks)));
  assert.equal(report.samples.length, 2);
  const [first, second] = report.samples;
  assert.equal(report.setup.input.publisher.resourceId, "article");
  assert.equal(first.success, true);
  assert.equal(second.success, true);
  assert.notEqual(
    first.captures.dcaData.document.resource.renderId,
    second.captures.dcaData.document.resource.renderId,
  );
  assert.notEqual(
    first.captures.dcaData.document.resourceJWT,
    second.captures.dcaData.document.resourceJWT,
  );
  assert.notEqual(first.captures.delivery.text, second.captures.delivery.text);
  assert.equal(
    first.captures.dcaData.document.resource.resourceId,
    report.setup.input.publisher.resourceId,
  );
  assert.equal(
    second.captures.dcaData.document.resource.resourceId,
    report.setup.input.publisher.resourceId,
  );
  assert.deepEqual(
    first.captures.dcaData.document.resource.data,
    report.setup.input.publisher.data,
  );
  assert.deepEqual(
    second.captures.dcaData.document.resource.data,
    report.setup.input.publisher.data,
  );
  for (const sample of [first, second]) {
    assert.ok(sample.checks.some((check) => check.name === "item:bodytext" && check.passed));
  }
  assert.equal(report.summary.runs, 2);
});

test("crypto-counted baseline agrees with plain execution and leaves parent crypto untouched", async () => {
  const parentMethods = {
    generateKey: globalThis.crypto.subtle.generateKey,
    encrypt: globalThis.crypto.subtle.encrypt,
    decrypt: globalThis.crypto.subtle.decrypt,
    sign: globalThis.crypto.subtle.sign,
    deriveBits: globalThis.crypto.subtle.deriveBits,
    getRandomValues: globalThis.crypto.getRandomValues,
  };
  const plain = await runBench({ scenario: itemScenario });
  const counted = await runBench({
    scenario: itemScenario,
    scenarioUrl,
    measurement: { countCrypto: true },
  });

  assert.equal(plain.success, true, JSON.stringify(plain.checks));
  assert.equal(counted.success, true, JSON.stringify(counted.checks));
  assert.equal(counted.setup.scenario, itemScenario.id);
  assert.deepEqual(counted.setup.requestedProfiles, plain.setup.requestedProfiles);
  assert.deepEqual(counted.setup.resolvedProfiles, plain.setup.resolvedProfiles);
  assert.equal(JSON.stringify(counted.cache), JSON.stringify(plain.cache));
  const withoutCrypto = ({ crypto, cryptoTotal, ...work }) => work;
  assert.equal(JSON.stringify(withoutCrypto(counted.work)), JSON.stringify(plain.work));
  const countedOperations = Object.values(counted.work.crypto).flatMap((group) =>
    Object.values(group),
  );
  assert.ok(countedOperations.some((count) => count > 0));
  assert.equal(counted.samples[0].checks.length, plain.samples[0].checks.length);
  assert.deepEqual(
    counted.samples[0].checks.map(({ name, passed }) => ({ name, passed })),
    plain.samples[0].checks.map(({ name, passed }) => ({ name, passed })),
  );
  assert.ok(plain.timings.issuer.milliseconds > 0);
  for (const [name, method] of Object.entries(parentMethods)) {
    const actual =
      name === "getRandomValues" ? globalThis.crypto[name] : globalThis.crypto.subtle[name];
    assert.equal(actual, method, `parent WebCrypto ${name} identity changed`);
  }
  const plainResource = plain.captures.dcaData.document.resource;
  const countedResource = counted.captures.dcaData.document.resource;
  assert.equal(countedResource.origin, plainResource.origin);
  assert.equal(countedResource.resourceId, plainResource.resourceId);
  assert.deepEqual(
    contentNames(counted.captures.dcaData.document),
    contentNames(plain.captures.dcaData.document),
  );
});

test("ordinary chain-key scenario executes its declared composition", async () => {
  const chain = await runBench({
    scenario: chainScenario,
    input: { publisher: { groups: 2 }, client: { routeProbes: false } },
  });
  assert.equal(chain.success, true, JSON.stringify(chain.checks));
  assert.ok(chain.setup.resolvedProfiles.includes("dca-profile-chain-keys"));
  assert.equal(chain.work.applicableGroups, 2);
  assert.equal(Array.isArray(chain.captures.request.document.sealed.chainKeys), true);
  assert.equal(
    chain.checks.some((check) => check.name === "item:bodytext" && check.passed),
    true,
  );
});

test("content-groups handles a sparse 100-of-1000 vocabulary", async () => {
  const contentGroups = await runBench({
    scenario: groupScenario,
    input: {
      publisher: { groups: 100, groupVocabulary: 1000 },
      client: { routeProbes: false },
    },
  });
  assert.equal(contentGroups.success, true, JSON.stringify(contentGroups.checks));
  assert.ok(contentGroups.setup.resolvedProfiles.includes("dca-profile-content-groups"));
  assert.equal(contentGroups.work.applicableGroups, 100);
  assert.deepEqual(
    contentGroups.captures.request.document.requested.contentGroups.map(
      ({ contentName, groups }) => [contentName, groups.length],
    ),
    [["bodytext", 100]],
  );
  assert.equal(
    contentGroups.checks.some((check) => check.name === "item:bodytext" && check.passed),
    true,
  );
});

test("content-group partial grant denies only the unauthorized item", async () => {
  const partial = await runBench({
    scenario: groupScenario,
    input: {
      publisher: {
        groups: 2,
        items: [
          { name: "first", value: "First", groups: ["group0000"] },
          { name: "second", value: "Second", groups: ["group0001"] },
        ],
      },
      issuer: { authorizedGroups: ["group0000"] },
      client: { routeProbes: false },
    },
  });
  assert.equal(partial.success, true, JSON.stringify(partial.checks));
  assert.equal(partial.checks.find((check) => check.name === "item:first").passed, true);
  assert.equal(partial.checks.find((check) => check.name === "item:second").passed, true);
});

test("content-group initial-cache reuse avoids a second unlock", async () => {
  const warm = await runBench({
    scenario: groupScenario,
    input: { publisher: { groups: 1 }, client: { initialCache: true, routeProbes: false } },
  });
  assert.equal(warm.success, true, JSON.stringify(warm.checks));
  assert.equal(warm.work.initialCacheSetupUnlock, 1);
  assert.equal(warm.work.unlock ?? 0, 0);
  assert.equal(
    warm.checks.some((check) => check.name === "item:bodytext" && check.passed),
    true,
  );
});

test("group cases preserve expected denials and cache observation does not change access", async () => {
  for (const scenario of [chainScenario, groupScenario]) {
    const denied = await runBench({ scenario, input: { issuer: { authorizedGroups: [] } } });
    assert.equal(denied.success, true, JSON.stringify(denied.checks));
    assert.equal(denied.captures.response.status, 401);
    assert.equal(
      denied.checks.find((check) => check.name === "item:bodytext").details.code,
      "no_key",
    );
    const observed = await runBench({ scenario, input: { client: { routeProbes: false } } });
    const unobserved = await runBench({
      scenario,
      input: { client: { observeCache: false, routeProbes: false } },
    });
    assert.equal(unobserved.success, true, JSON.stringify(unobserved.checks));
    assert.equal(unobserved.work.unlock, observed.work.unlock);
    assert.deepEqual(
      unobserved.checks.filter(({ name }) => name.startsWith("item:")),
      observed.checks.filter(({ name }) => name.startsWith("item:")),
    );
    assert.equal(unobserved.cache.after.measured, false);
    const { storage, caches } = observed.cache.after;
    assert.equal(storage.totalBytes, storage.keyBytes + storage.valueBytes);
    assert.ok(storage.valueBytes > 0);
    assert.equal(
      caches.chain.chainKeys,
      caches.chain.coordinates.filter(({ kind }) => kind === "chain-key").length,
    );
    assert.ok(!JSON.stringify(caches).includes('"key":'));
  }
});

test("selected group sizes run honestly, preserving the ordinary fixed source bound", async () => {
  for (const groups of [1, 2, 10, 100]) {
    const report = await runBench({ scenario: groupScenario, input: { publisher: { groups } } });
    assert.equal(
      report.success,
      true,
      JSON.stringify(report.checks.filter(({ passed }) => !passed)),
    );
    assert.equal(report.work.applicableGroups, groups);
    assert.equal(report.work.unlock, 1);
    const [item] = report.captures.dcaData.document.contentData;
    assert.equal(item.contentName, "bodytext");
    assert.equal(new Set(item.connectors.map(({ group }) => group)).size, groups);
    assert.equal(item.connectors.length, groups);
    assert.equal(report.cache.after.caches.chain.chainKeys, groups);
    assert.equal(
      report.cache.after.caches.chain.coordinates.length,
      report.cache.after.caches.chain.entries,
    );
    const ordinary = await runBench({ scenario: chainScenario, input: { publisher: { groups } } });
    assert.equal(ordinary.success, groups <= 8);
    if (groups > 8) {
      assert.equal(ordinary.captures.delivery.available, false);
      assert.equal(
        ordinary.checks.find(({ name }) => name === "chain-member-bound").details.requested,
        groups * 2,
      );
    }
  }
  const sparse = await runBench({
    scenario: groupScenario,
    input: { publisher: { groups: 3, groupVocabulary: 1000 }, client: { routeProbes: false } },
  });
  assert.equal(sparse.success, true);
  assert.equal(sparse.work.applicableGroups, 3);
  assert.equal(sparse.cache.after.caches.chain.chainKeys, 3);
});

test("matched midnight grants retain both windows and compact ECDH changes the actual envelope", async () => {
  for (const scenario of [chainScenario, groupScenario]) {
    const report = await runBench({
      scenario,
      input: { publisher: { groups: 2, at: "2026-10-14T23:59:00Z" } },
    });
    assert.equal(report.success, true, JSON.stringify(report.checks));
    assert.equal(report.cache.after.caches.chain.chainKeys, 4);
    const cutoffs = report.cache.after.caches.chain.coordinates
      .filter(({ kind }) => kind === "chain-key")
      .map(({ t }) => t);
    assert.ok(cutoffs.includes("261014T2300"));
    assert.ok(cutoffs.includes("261015T0500"));
  }
  const compact = await runBench({
    scenario: compactScenario,
    input: { publisher: { variant: "compact-ecdh" } },
  });
  assert.equal(compact.success, true, JSON.stringify(compact.checks));
  assert.ok(compact.setup.resolvedProfiles.includes("dca-profile-compact-ecdh"));
  assert.equal(compact.setup.profileDeclarations[0].status, "public-working-draft");
  const issuers = compact.captures.dcaData.document.issuerData;
  assert.deepEqual(
    issuers.map(({ issuerName, envelope }) => [issuerName, envelope]),
    [["issuer", "compact-ecdh"]],
  );
});

test("group crypto counts and detailed timings keep route probes separate", async () => {
  const url = new URL("../scenarios/content-groups/groups.js", import.meta.url).href;
  const noProbes = await runBench({
    scenario: groupScenario,
    scenarioUrl: url,
    input: { client: { routeProbes: false } },
    measurement: { timeSteps: true, countCrypto: true },
  });
  const probes = await runBench({
    scenario: groupScenario,
    scenarioUrl: url,
    measurement: { timeSteps: true, countCrypto: true },
  });
  assert.equal(noProbes.success, true, JSON.stringify(noProbes.checks));
  assert.equal(probes.success, true, JSON.stringify(probes.checks));
  assert.deepEqual(probes.work.crypto.primary, noProbes.work.crypto.primary);
  assert.ok(Object.keys(probes.work.crypto.probes).length > 0);
  assert.equal(Object.keys(noProbes.work.crypto.probes).length, 0);
  const observations = (value) =>
    value === undefined ? 0 : Array.isArray(value) ? value.length : 1;
  assert.equal(
    observations(probes.timings["chain.chainCapability"]),
    observations(noProbes.timings["chain.chainCapability"]),
  );
  assert.ok(observations(probes.timings["probe:chain.chainCapability"]) > 0);
  const plain = await runBench({
    scenario: groupScenario,
    input: { client: { routeProbes: false } },
  });
  assert.equal(plain.success, noProbes.success);
  assert.equal(plain.work.unlock, noProbes.work.unlock);
  assert.deepEqual(plain.cache.after.caches, noProbes.cache.after.caches);
  assert.equal(plain.cache.after.storage.entries, noProbes.cache.after.storage.entries);
  for (const report of [plain, noProbes])
    assert.equal(
      report.cache.after.storage.totalBytes,
      report.cache.after.storage.keyBytes + report.cache.after.storage.valueBytes,
    );
});

test("instrumentation refuses a modified callable scenario instead of replacing its behavior", async () => {
  const modified = Object.freeze({
    ...itemScenario,
    execute({ observe }) {
      observe.check("deliberate failure", false);
    },
  });
  const plain = await runBench({ scenario: modified });
  assert.equal(plain.success, false);
  await assert.rejects(
    runBench({ scenario: modified, scenarioUrl, measurement: { countCrypto: true } }),
    /scenario.*module|module.*scenario|unmodified/i,
  );
});

test("an intended denial carries no key member under its current wire name", async () => {
  const cases = [
    [{ error: "denied" }, true],
    [{ error: "denied", keys: { contentKeys: [] } }, false],
    [{ error: "denied", contentGroupKeys: { chainKeys: [] } }, false],
  ];
  for (const [body, passed] of cases) {
    /** @type {{name: string, passed: boolean}[]} */
    const checks = [];
    const observe = {
      /** @param {string} name @param {boolean} ok */
      check: (name, ok) => checks.push({ name, passed: ok }),
    };
    const endpoint = checkedEndpoint(
      { handleDocument: async () => ({ response: { status: 401, body } }) },
      observe,
      () => [],
      [],
    );
    await endpoint.handleDocument();
    assert.deepEqual(
      checks,
      [{ name: "returned-chain-coordinates", passed }],
      JSON.stringify(body),
    );
  }
});

test("delivery partitions follow named records and keep repeated coordinates apart", () => {
  const seals = [
    { accessGroup: "g1", period: "261014T1200", key: "first" },
    { accessGroup: "g1", period: "261014T1200", key: "second" },
  ];
  const document = {
    version: "1",
    contentData: [
      {
        contentName: "a",
        contentType: "text/plain",
        keys: seals,
        connectors: [{ group: "g1", connector: "c" }],
      },
      { contentName: "b", contentType: "text/plain" },
    ],
    issuerData: [{ issuerName: "issuer", keyId: "k1", sealed: { contentKeys: [] } }],
    sealedContent: [{ contentName: "a", content: "AA" }],
  };
  const parts = deliveryPartitions(document);
  assert.equal(Object.values(parts).join(""), JSON.stringify(document));
  assert.equal(parts['items:0:"a":seals:0:"g1"'], JSON.stringify(seals[0]));
  assert.equal(parts['items:0:"a":seals:1:"g1"'], JSON.stringify(seals[1]));
  assert.equal(
    parts['items:0:"a":connectors:0:"g1"'],
    JSON.stringify(document.contentData[0].connectors[0]),
  );
  assert.equal(parts['items:1:"b":metadata:"contentType"'], '"text/plain"');
  assert.equal(parts.sources, JSON.stringify(document.issuerData));
  assert.equal(parts.ciphertext, JSON.stringify(document.sealedContent));
});

// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { namedRecordEnvelope } from "../../support/named-record-controls.js";
import { registeredJwsControls } from "../../support/registered-jws-controls.js";
import { assertBindingSupportsTarget } from "../../support/contract-runner-validation.js";

const T0 = "251023T1400";
const T1 = "251023T1500";

/** @param {any} vector */
function wireRequest(vector) {
  const dcaData = vector.expected.dcaData;
  const [issuer] = vector.input.issuers;
  const block = dcaData.issuerData.find(
    (/** @type {any} */ record) => record.issuerName === issuer.issuerName,
  );
  return JSON.stringify({
    version: dcaData.version,
    issuerName: issuer.issuerName,
    resourceJWT: dcaData.resourceJWT,
    keyId: issuer.keyId,
    sealed: block.sealed,
  });
}

/**
 * A record collection as a map from its identity fields to the rest. A
 * repeated identity fails: a map would keep one record, and a rival at one
 * coordinate must never disappear inside an assertion.
 *
 * @param {unknown} records
 * @param {string} what
 * @param {(record: any) => string[]} identity
 * @param {(record: any) => any} value
 * @returns {Record<string, any>}
 */
function recordMap(records, what, identity, value) {
  assert.ok(Array.isArray(records), `${what} is a record array`);
  /** @type {Record<string, any>} */
  const map = {};
  for (const record of records) {
    const path = identity(record);
    let level = map;
    for (const name of path.slice(0, -1)) {
      if (!Object.hasOwn(level, name)) level[name] = {};
      level = level[name];
    }
    const last = /** @type {string} */ (path.at(-1));
    assert.equal(Object.hasOwn(level, last), false, `${what} carries ${path.join(".")} once`);
    level[last] = value(record);
  }
  return map;
}

/** @param {unknown} records */
const contentKeyMap = (records) =>
  recordMap(
    records,
    "contentKeys",
    (r) => [r.contentName],
    (r) => r.key,
  );
/** @param {unknown} records */
const periodKeyMap = (records) =>
  recordMap(
    records,
    "periodKeys",
    (r) => [r.accessGroup, r.period],
    (r) => r.key,
  );
/** @param {unknown} records */
const errorMap = (records) =>
  recordMap(
    records,
    "errors",
    (r) => [r.coordinate],
    ({ coordinate, ...failure }) => failure,
  );

/** @param {any} vector */
function allRequestedPolicy(vector, policyData) {
  return { contentNames: "requested", periodGrants: "requested", policyData };
}

/** @param {any} driver @param {any} vector @param {any} policy */
async function provisioning(driver, vector, policy) {
  const issuer = vector.vectorFormat === "1" ? vector.input.issuers[0] : vector.issuer;
  const signingKeys =
    vector.vectorFormat === "1" ? vector.input.signingKeys : vector.publisher.signingKeys;
  const privateKey = await driver.importIssuerPrivateKey(issuer.privateKeyJwk);
  const publisherRegistrations = await Promise.all(
    signingKeys.map(async (entry) => ({
      kid: entry.kid,
      publicKey: await driver.importPublisherPublicKey(entry.publicKeyJwk),
    })),
  );
  return {
    issuerKey: {
      issuerName: issuer.issuerName,
      keyId: issuer.keyId,
      algorithm: issuer.algorithm,
      privateKey,
    },
    publisherRegistrations: publisherRegistrations.map(({ kid, publicKey }) => ({
      kid,
      publicKey,
    })),
    policy,
  };
}

/** @param {any} expected @param {any} base */
function expectedKeys(expected, base) {
  const contentKeys = Object.fromEntries(
    expected.keys.contentKeys.map((name) => [name, base.expected.contentKeys[name]]),
  );
  const periodKeys = {};
  for (const [group, labels] of Object.entries(expected.keys.periodKeys ?? {})) {
    periodKeys[group] = Object.fromEntries(
      labels.map((t) => [t, base.expected.periodKeys[group][t]]),
    );
  }
  return { contentKeys, periodKeys };
}

/** @param {any} result @param {any} keys @param {any} expectedErrors @param {any} policyData */
function assertSuccess(result, keys, expectedErrors, policyData) {
  assert.deepEqual(Object.keys(result).sort(), ["document", "kind", "policyData"]);
  assert.equal(result.kind, "success");
  assert.deepEqual(result.policyData, policyData, "policyData");
  const expectedDocumentMembers =
    Object.keys(expectedErrors).length === 0 ? ["keys"] : ["errors", "keys"];
  assert.deepEqual(
    Object.keys(result.document).sort(),
    expectedDocumentMembers,
    "success document has only DCA keys and optional errors, never endpoint fields",
  );
  assert.deepEqual(
    Object.keys(result.document.keys).sort(),
    Object.keys(keys.periodKeys).length === 0 ? ["contentKeys"] : ["contentKeys", "periodKeys"],
    "success keys has only the direct sections this profile returns",
  );
  assert.deepEqual(contentKeyMap(result.document.keys.contentKeys), keys.contentKeys);
  if (Object.keys(keys.periodKeys).length === 0) {
    assert.equal(Object.hasOwn(result.document.keys, "periodKeys"), false);
  } else {
    assert.deepEqual(periodKeyMap(result.document.keys.periodKeys), keys.periodKeys);
  }
  assert.equal(Object.hasOwn(result.document.keys, "chainKeys"), false);
  const errors = errorMap(result.document.errors ?? []);
  assert.deepEqual(Object.keys(errors).sort(), Object.keys(expectedErrors).sort());
  for (const [coordinate, code] of Object.entries(expectedErrors)) {
    assert.equal(errors[coordinate]?.error, code, `${coordinate}.error`);
  }
}

/** @param {any} core @param {string} raw @param {any} input */
async function admittedResult(core, raw, input) {
  const admission = await core.admit(raw);
  if (admission.kind === "failure") return admission;
  assert.deepEqual(Object.keys(admission).sort(), ["handle", "kind"]);
  assert.equal(admission.kind, "admitted");
  return core.processMiss({ request: admission.handle, policyInput: input });
}

/**
 * @param {any} binding
 * @param {any} target
 * @param {{ file: string, vector: any }[]} vectors
 */
export function registerIssuerCoreContract(binding, target, vectors) {
  const driver = binding.targets["issuer-core"].driver;
  const seals = vectors.filter(({ vector }) => vector.vectorFormat === "1");
  const base = seals.find(({ vector }) => vector.name === "seal-ecdh")?.vector;
  if (!base)
    throw new Error("issuer-core contract needs seal-ecdh in its selected format-1 vectors");
  const byName = new Map(vectors.map(({ vector }) => [vector.name, vector]));
  const rejects = vectors.filter(({ vector }) => vector.vectorFormat === "2");
  const executedFormat1 = new Set();
  const executedFormat2 = new Set();

  describe("portable issuer-core contract", () => {
    test("the binding declares the direct v1 issuer-core target", () => {
      assertBindingSupportsTarget("issuer-core", target, binding.targets["issuer-core"]);
    });

    for (const { file, vector } of seals) {
      test(`${file}: admit carries the original document to one closed raw success result`, async () => {
        const policyData = [{ opaqueCoreContractSentinel: `policy-data:${file}` }];
        const core = driver.createIssuerCore(
          await provisioning(driver, vector, allRequestedPolicy(vector, policyData)),
        );
        const result = await admittedResult(core, wireRequest(vector), {
          principal: { user: "contract-reader" },
          context: { source: "contract-test" },
        });
        assertSuccess(
          result,
          {
            contentKeys: vector.expected.contentKeys,
            periodKeys: vector.expected.periodKeys,
          },
          {},
          policyData,
        );
        executedFormat1.add(file);
      });
    }

    test("registered signing key wins over untrusted JWS header key material", async () => {
      const controls = await registeredJwsControls(base);
      for (const [signer, resourceJWT] of Object.entries(controls)) {
        const core = driver.createIssuerCore(
          await provisioning(driver, base, allRequestedPolicy(base, [])),
        );
        const request = { ...JSON.parse(wireRequest(base)), resourceJWT };
        const result = await admittedResult(core, JSON.stringify(request), {
          principal: null,
          context: null,
        });
        if (signer === "attacker") {
          assert.deepEqual(result, { kind: "failure", code: "bad_signature" });
        } else {
          assertSuccess(
            result,
            { contentKeys: base.expected.contentKeys, periodKeys: base.expected.periodKeys },
            {},
            [],
          );
        }
      }
    });

    for (const section of ["contentKeys", "periodKeys"]) {
      const identity = section === "contentKeys" ? "contentName" : "accessGroup";
      for (const [label, corrupt] of [
        ["non-array collection", () => ({})],
        ["missing identity", (records) => [{ key: records[0].key }, ...records]],
        ["invalid identity", (records) => [{ ...records[0], [identity]: "bad|name" }, ...records]],
      ]) {
        test(`${section}: ${label} refuses the entire request with valid siblings`, async () => {
          const request = JSON.parse(wireRequest(base));
          request.sealed[section] = corrupt(request.sealed[section]);
          const core = driver.createIssuerCore(
            await provisioning(driver, base, allRequestedPolicy(base, [])),
          );
          assert.deepEqual(await core.admit(JSON.stringify(request)), {
            kind: "failure",
            code: "binding_failed",
          });
        });
      }
      test(`${section}: non-object element has its specified scope`, async () => {
        const request = JSON.parse(wireRequest(base));
        request.sealed[section].splice(1, 0, null);
        const core = driver.createIssuerCore(
          await provisioning(driver, base, allRequestedPolicy(base, [])),
        );
        const result = await admittedResult(core, JSON.stringify(request), {
          principal: null,
          context: null,
        });
        if (section === "periodKeys") {
          assert.deepEqual(result, { kind: "failure", code: "binding_failed" });
        } else {
          assertSuccess(
            result,
            {
              contentKeys: base.expected.contentKeys,
              periodKeys: base.expected.periodKeys,
            },
            {},
            [],
          );
        }
      });
    }

    for (const section of ["contentKeys", "periodKeys"]) {
      test(`${section}: distinct authenticating rivals survive either record order`, async () => {
        const initial = JSON.parse(wireRequest(base));
        const original = initial.sealed[section][0];
        const coordinate =
          section === "contentKeys"
            ? { contentName: original.contentName }
            : { accessGroup: original.accessGroup, period: original.period };
        const rivalBytes = new Uint8Array(16).fill(0xa7);
        const rivalKey = Buffer.from(rivalBytes).toString("base64url");
        const originalKey =
          section === "contentKeys"
            ? base.expected.contentKeys[original.contentName]
            : base.expected.periodKeys[original.accessGroup][original.period];
        assert.notEqual(rivalKey, originalKey);
        const rival = {
          ...coordinate,
          key: await namedRecordEnvelope(base, coordinate, rivalBytes),
        };
        for (const records of [
          [original, rival],
          [rival, original],
        ]) {
          const request = JSON.parse(wireRequest(base));
          request.sealed[section] = [...records, ...request.sealed[section].slice(1)];
          const core = driver.createIssuerCore(
            await provisioning(driver, base, allRequestedPolicy(base, [])),
          );
          const result = await admittedResult(core, JSON.stringify(request), {
            principal: null,
            context: null,
          });
          assert.equal(result.kind, "success");
          assert.deepEqual(result.document.errors ?? [], []);
          const expectedContent = Object.entries(base.expected.contentKeys).map(
            ([contentName, key]) => [contentName, key],
          );
          const expectedPeriods = Object.entries(base.expected.periodKeys).flatMap(
            ([accessGroup, periods]) =>
              Object.entries(periods).map(([period, key]) => [accessGroup, period, key]),
          );
          if (section === "contentKeys") expectedContent.push([original.contentName, rivalKey]);
          else expectedPeriods.push([original.accessGroup, original.period, rivalKey]);
          const sorted = (records) => records.map((record) => JSON.stringify(record)).sort();
          assert.deepEqual(
            sorted(result.document.keys.contentKeys.map((r) => [r.contentName, r.key])),
            sorted(expectedContent),
            "all content candidates and sibling coordinates survive unchanged",
          );
          assert.deepEqual(
            sorted(result.document.keys.periodKeys.map((r) => [r.accessGroup, r.period, r.key])),
            sorted(expectedPeriods),
            "all period candidates and sibling coordinates survive unchanged",
          );
        }
      });
    }

    test("the selected format-1 baseline is complete", () => {
      assert.ok(seals.length > 0, "the manifest selected format-1 vectors");
      assert.deepEqual(
        [...executedFormat1].sort(),
        seals.map(({ file }) => file).sort(),
        "every selected format-1 file completed its registered success case",
      );
    });

    for (const { file, vector } of rejects) {
      test(`${file}: consumes the selected format-2 vector exactly once`, async () => {
        const policyData = [{ opaqueCoreContractSentinel: `policy-data:${file}` }];
        const core = driver.createIssuerCore(
          await provisioning(driver, vector, allRequestedPolicy(vector, policyData)),
        );
        const result = await admittedResult(core, vector.rawBody, {
          principal: { user: "contract-reader" },
          context: {},
        });
        if (vector.expected.code !== null) {
          assert.deepEqual(result, { kind: "failure", code: vector.expected.code });
          executedFormat2.add(file);
          return;
        }
        const source = byName.get(vector.derivedFrom);
        assert.ok(source, `${file}: ${vector.derivedFrom} is selected`);
        assertSuccess(
          result,
          expectedKeys(vector.expected, source),
          vector.expected.errors,
          policyData,
        );
        executedFormat2.add(file);
      });
    }

    test("the selected format-2 baseline is complete", () => {
      assert.ok(rejects.length > 0, "the manifest selected format-2 vectors");
      assert.deepEqual(
        [...executedFormat2].sort(),
        rejects.map(({ file }) => file).sort(),
        "every selected format-2 file completed its registered reject case",
      );
    });

    test("period grants open only the explicitly listed labels, not request record order", async () => {
      const request = JSON.parse(wireRequest(base));
      // The later period first: a grant that opened by position would open T1.
      const isPremium = (/** @type {any} */ record) => record.accessGroup === "premium";
      request.sealed.periodKeys = [
        ...request.sealed.periodKeys.filter(isPremium).reverse(),
        ...request.sealed.periodKeys.filter((/** @type {any} */ r) => !isPremium(r)),
      ];
      assert.equal(request.sealed.periodKeys[0].period, T1);
      const policyData = [];
      const core = driver.createIssuerCore(
        await provisioning(driver, base, {
          contentNames: ["bodytext"],
          periodGrants: [{ accessGroup: "premium", periods: [T0] }],
          policyData,
        }),
      );
      const result = await admittedResult(core, JSON.stringify(request), {
        principal: null,
        context: null,
      });
      assertSuccess(
        result,
        {
          contentKeys: { bodytext: base.expected.contentKeys.bodytext },
          periodKeys: {
            premium: { "251023T1400": base.expected.periodKeys.premium["251023T1400"] },
          },
        },
        {},
        policyData,
      );
    });

    test("period grants union duplicate labels and invent no group", async () => {
      const policyData = [];
      const core = driver.createIssuerCore(
        await provisioning(driver, base, {
          contentNames: ["bodytext"],
          periodGrants: [
            { accessGroup: "premium", periods: [T0] },
            { accessGroup: "premium", periods: [T1] },
            { accessGroup: "not-present", periods: [T0] },
          ],
          policyData,
        }),
      );
      const result = await admittedResult(core, wireRequest(base), {
        principal: null,
        context: null,
      });
      assertSuccess(
        result,
        {
          contentKeys: { bodytext: base.expected.contentKeys.bodytext },
          periodKeys: { premium: base.expected.periodKeys.premium },
        },
        {},
        policyData,
      );
      assert.equal(
        result.document.keys.periodKeys.some(
          (/** @type {any} */ record) => record.accessGroup === "not-present",
        ),
        false,
      );
    });

    test("duplicate period grants union labels and never invent coordinates", async () => {
      const policyData = [];
      const core = driver.createIssuerCore(
        await provisioning(driver, base, {
          contentNames: ["bodytext"],
          periodGrants: [
            { accessGroup: "premium", periods: [T1] },
            { accessGroup: "premium", periods: [T0] },
            { accessGroup: "locked-data", periods: [T0] },
            { accessGroup: "locked-data", periods: [T0] },
          ],
          policyData,
        }),
      );
      const result = await admittedResult(core, wireRequest(base), {
        principal: null,
        context: null,
      });
      assertSuccess(
        result,
        {
          contentKeys: { bodytext: base.expected.contentKeys.bodytext },
          periodKeys: {
            premium: base.expected.periodKeys.premium,
            "locked-data": {
              "251023T1400": base.expected.periodKeys["locked-data"]["251023T1400"],
            },
          },
        },
        {},
        policyData,
      );
    });
  });
}

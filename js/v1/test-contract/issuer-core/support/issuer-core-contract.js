// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { assertBindingSupportsTarget } from "../../support/contract-runner-validation.js";

const ALL_PRESENTED_PERIODS = Number.MAX_SAFE_INTEGER;

/** @param {any} vector */
function wireRequest(vector) {
  const dcaData = vector.expected.dcaData;
  const [issuer] = vector.input.issuers;
  return JSON.stringify({
    version: dcaData.version,
    issuerName: issuer.issuerName,
    resourceJWT: dcaData.resourceJWT,
    keyId: issuer.keyId,
    sealed: dcaData.issuerData[issuer.issuerName].sealed,
  });
}

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
    "success document has only DCA keys and an optional errors map, never endpoint fields",
  );
  assert.deepEqual(
    Object.keys(result.document.keys).sort(),
    Object.keys(keys.periodKeys).length === 0 ? ["contentKeys"] : ["contentKeys", "periodKeys"],
    "success keys has only the direct sections this profile returns",
  );
  assert.deepEqual(result.document.keys.contentKeys, keys.contentKeys);
  if (Object.keys(keys.periodKeys).length === 0) {
    assert.equal(Object.hasOwn(result.document.keys, "periodKeys"), false);
  } else {
    assert.deepEqual(result.document.keys.periodKeys, keys.periodKeys);
  }
  assert.equal(Object.hasOwn(result.document.keys, "periodChainKeys"), false);
  const errors = result.document.errors ?? {};
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

    test("period grants take a canonical prefix, not request member order", async () => {
      const request = JSON.parse(wireRequest(base));
      request.sealed.periodKeys.premium = Object.fromEntries([
        ["251023T15", request.sealed.periodKeys.premium["251023T15"]],
        ["251023T14", request.sealed.periodKeys.premium["251023T14"]],
      ]);
      const policyData = [];
      const core = driver.createIssuerCore(
        await provisioning(driver, base, {
          contentNames: ["bodytext"],
          periodGrants: [{ accessGroup: "premium", periodCount: 1 }],
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
          periodKeys: { premium: { "251023T14": base.expected.periodKeys.premium["251023T14"] } },
        },
        {},
        policyData,
      );
    });

    test("period grants clamp, choose duplicate longest reach, and invent no group", async () => {
      const policyData = [];
      const core = driver.createIssuerCore(
        await provisioning(driver, base, {
          contentNames: ["bodytext"],
          periodGrants: [
            { accessGroup: "premium", periodCount: 1 },
            { accessGroup: "premium", periodCount: 9 },
            { accessGroup: "not-present", periodCount: ALL_PRESENTED_PERIODS },
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
      assert.equal(Object.hasOwn(result.document.keys.periodKeys, "not-present"), false);
    });

    test("duplicate period grants fold by longest reach, not by member order and not by sum", async () => {
      // The case above presents the duplicate narrow first, so a fold that
      // keeps the first count or the smallest one stops at one label and
      // fails it. Two directions stay open there, and both hand out more
      // than the documented rule grants:
      //
      //   premium takes the wide count first, so a fold that keeps the
      //   last count stops at one label while longest reach clamps 9 to
      //   the two labels the request presented.
      //
      //   locked-data takes the same count twice, below the labels it
      //   presented, so a fold that sums reaches two labels while longest
      //   reach opens exactly the first one.
      const policyData = [];
      const core = driver.createIssuerCore(
        await provisioning(driver, base, {
          contentNames: ["bodytext"],
          periodGrants: [
            { accessGroup: "premium", periodCount: 9 },
            { accessGroup: "premium", periodCount: 1 },
            { accessGroup: "locked-data", periodCount: 1 },
            { accessGroup: "locked-data", periodCount: 1 },
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
            "locked-data": { "251023T14": base.expected.periodKeys["locked-data"]["251023T14"] },
          },
        },
        {},
        policyData,
      );
    });
  });
}

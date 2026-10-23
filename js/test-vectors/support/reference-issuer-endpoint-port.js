// @ts-check

// Reference-only endpoint-port fixtures. They deliberately observe adapter
// calls and pin this implementation's coded response mapping, so they must not
// travel with the wire-only issuer-endpoint contract in Step 3.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

/**
 * The one issuer block a delivery's `issuerData` records name `issuerName`.
 *
 * @param {any} dcaData
 * @param {string} issuerName
 * @returns {any}
 */
function issuerBlock(dcaData, issuerName) {
  const blocks = dcaData.issuerData.filter(
    (/** @type {any} */ record) => record.issuerName === issuerName,
  );
  assert.equal(blocks.length, 1, `one issuerData record names ${issuerName}`);
  return blocks[0];
}

/**
 * Sealed period-key records as the period labels the request presents per
 * accessGroup, in record order.
 *
 * @param {{ accessGroup: string, period: string }[]} records
 * @returns {Record<string, string[]>}
 */
function periodsByGroup(records) {
  /** @type {Record<string, string[]>} */
  const periods = {};
  for (const { accessGroup, period } of records) {
    (periods[accessGroup] ??= []).push(period);
  }
  return periods;
}

/**
 * @param {{ importIssuerPrivateKey: (jwk: JsonWebKey) => Promise<CryptoKey>, importPublisherPublicKey: (jwk: JsonWebKey) => Promise<CryptoKey>, createIssuerEndpoint: (config: any) => { unlock: (rawRequest: string, input?: any) => Promise<{ status: number, body: any }> } }} driver
 * @param {any} vector
 */
async function fixtures(driver, vector) {
  const dcaData = vector.expected.dcaData;
  const [issuerFixture] = vector.input.issuers;
  const [publisherFixture] = vector.input.signingKeys;
  const presentedPeriodKeys =
    issuerBlock(dcaData, issuerFixture.issuerName).sealed.periodKeys ?? [];
  const privateKey = await driver.importIssuerPrivateKey(issuerFixture.privateKeyJwk);
  const publicKey = await driver.importPublisherPublicKey(publisherFixture.publicKeyJwk);
  const origin = vector.input.origin;
  const calls = [];
  const policyData = [{ delivery: "reference-port-fixture" }];
  const principal = { user: "contract-reader" };
  const policyContext = { source: "contract-test", principal: { user: "not-the-caller" } };

  return {
    calls,
    principal,
    policyContext,
    base: {
      operatingIssuerNames: [issuerFixture.issuerName],
      publisherRegistration: {
        kid: publisherFixture.kid,
        publicKey,
        openingKeys: {
          async get(issuerName, keyId) {
            calls.push("issuerKeys");
            assert.equal(issuerName, issuerFixture.issuerName);
            assert.equal(keyId, issuerFixture.keyId);
            return { algorithm: issuerFixture.algorithm, privateKey };
          },
        },
      },
      accessPolicy: {
        async decide(claims, requested, input) {
          calls.push("accessPolicy");
          assert.deepEqual(requested, {
            contentNames: ["bodytext", "locked-data"],
            accessGroups: ["premium", "locked-data"],
            periodCoordinates: periodsByGroup(presentedPeriodKeys),
          });
          assert.equal(claims.resource.renderId, dcaData.resource.renderId);
          assert.strictEqual(input.principal, principal);
          assert.strictEqual(input.context, policyContext);
          assert.deepEqual(input.publisher, { origin });
          return {
            contentNames: ["bodytext"],
            periodGrants: [
              { accessGroup: "premium", periods: requested.periodCoordinates.premium ?? [] },
            ],
            policyData,
          };
        },
      },
      limits: { maxBodyBytes: 64 * 1024, maxEntries: 16, maxEntriesPerGroup: 4 },
      errorDetail: "uniform",
    },
  };
}

/**
 * @param {{ importIssuerPrivateKey: (jwk: JsonWebKey) => Promise<CryptoKey>, importPublisherPublicKey: (jwk: JsonWebKey) => Promise<CryptoKey>, createIssuerEndpoint: (config: any) => { unlock: (rawRequest: string, input?: any) => Promise<{ status: number, body: any }> } }} driver
 * @param {any} vector
 */
export function referenceIssuerEndpointPortChecks(driver, vector) {
  const dcaData = vector.expected.dcaData;
  const [issuerFixture] = vector.input.issuers;
  const sealed = issuerBlock(dcaData, issuerFixture.issuerName).sealed;
  const rawRequest = JSON.stringify({
    version: dcaData.version,
    issuerName: issuerFixture.issuerName,
    resource: dcaData.resource,
    resourceJWT: dcaData.resourceJWT,
    keyId: issuerFixture.keyId,
    sealed,
  });

  describe("reference issuer endpoint port behavior", () => {
    test("a signing registration miss is protocol input; opening-key misses and failures are operational", async () => {
      const publisherMiss = await fixtures(driver, vector);
      publisherMiss.base.errorDetail = "code";
      publisherMiss.base.publisherRegistration = undefined;
      assert.deepEqual(await driver.createIssuerEndpoint(publisherMiss.base).unlock(rawRequest), {
        status: 400,
        body: { error: "unknown_publisher_key" },
      });
      assert.deepEqual(publisherMiss.calls, []);

      const policyFailure = await fixtures(driver, vector);
      policyFailure.base.errorDetail = "code";
      policyFailure.base.accessPolicy = {
        async decide() {
          policyFailure.calls.push("policyFailure");
          throw new Error("policy dependency unavailable");
        },
      };
      assert.deepEqual(await driver.createIssuerEndpoint(policyFailure.base).unlock(rawRequest), {
        status: 500,
        body: { error: "internal_error" },
      });
      assert.deepEqual(policyFailure.calls, ["policyFailure"]);

      const issuerMiss = await fixtures(driver, vector);
      issuerMiss.base.errorDetail = "code";
      issuerMiss.base.publisherRegistration.openingKeys = {
        async get() {
          issuerMiss.calls.push("issuerMiss");
          return undefined;
        },
      };
      assert.deepEqual(
        await driver.createIssuerEndpoint(issuerMiss.base).unlock(rawRequest, {
          principal: issuerMiss.principal,
          policyContext: issuerMiss.policyContext,
        }),
        { status: 503, body: { error: "unknown_key" } },
      );
      assert.deepEqual(issuerMiss.calls, ["accessPolicy", "issuerMiss"]);

      const issuerFailure = await fixtures(driver, vector);
      issuerFailure.base.errorDetail = "code";
      issuerFailure.base.publisherRegistration.openingKeys = {
        async get() {
          issuerFailure.calls.push("issuerFailure");
          throw new Error("issuer store unavailable");
        },
      };
      assert.deepEqual(
        await driver.createIssuerEndpoint(issuerFailure.base).unlock(rawRequest, {
          principal: issuerFailure.principal,
          policyContext: issuerFailure.policyContext,
        }),
        { status: 500, body: { error: "internal_error" } },
      );
      assert.deepEqual(issuerFailure.calls, ["accessPolicy", "issuerFailure"]);
    });
  });
}

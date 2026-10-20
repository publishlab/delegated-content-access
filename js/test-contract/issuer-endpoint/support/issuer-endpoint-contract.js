// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { registeredJwsControls } from "../../support/registered-jws-controls.js";
import { assertBindingSupportsTarget } from "../../support/contract-runner-validation.js";
import {
  assertContractOwnsItsStatuses,
  endpointStatuses,
  endpointStatusesSource,
  NON_VECTOR_STATUS_CASES,
  resolveStatus,
  statusForVector,
} from "./issuer-endpoint-statuses.js";

/**
 * Which reject vector ran the reject contract, and the status the table
 * projected for it there. Filled as those tests execute, so the status
 * projection can assert that every selected vector reached the endpoint through
 * the table instead of asserting a shape it built itself.
 *
 * @type {Map<string, number>}
 */
const rejectVectorStatuses = new Map();

/** A completed answer is exactly 200; whole-request refusals use the mapped class. */
/** @param {number} actual @param {number} expected @param {string} label */
function assertMappedStatus(actual, expected, label) {
  if (expected === 200) assert.equal(actual, 200, label);
  else assert.equal(Math.floor(actual / 100), Math.floor(expected / 100), label);
}

/**
 * @typedef {object} IssuerEndpointDriver
 * @property {(jwk: JsonWebKey) => Promise<CryptoKey>} importIssuerPrivateKey
 * @property {(jwk: JsonWebKey) => Promise<CryptoKey>} importPublisherPublicKey
 * @property {(config: any) => { unlock: (rawRequest: string, input?: any) => Promise<{ status: number, body: any }> }} createIssuerEndpoint
 */

/**
 * @typedef {object} IssuerEndpointBinding
 * @property {Record<string, { versions: string[], deliveryModes: string[], contractProfiles: string[], observations: string[], driver: IssuerEndpointDriver }>} targets
 */

/**
 * @param {IssuerEndpointDriver} driver
 * @param {any} vector
 */
async function fixtures(driver, vector) {
  const [issuerFixture] = vector.input.issuers;
  const [publisherFixture] = vector.input.signingKeys;
  const privateKey = await driver.importIssuerPrivateKey(issuerFixture.privateKeyJwk);
  const publicKey = await driver.importPublisherPublicKey(publisherFixture.publicKeyJwk);
  const policyData = [{ delivery: "contract-fixture" }];
  const principal = { user: "contract-reader" };
  const policyContext = { source: "contract-test", principal: { user: "not-the-caller" } };

  return {
    policyData,
    principal,
    policyContext,
    base: {
      issuerName: issuerFixture.issuerName,
      operatingIssuerNames: [issuerFixture.issuerName],
      keyId: issuerFixture.keyId,
      issuerKeys: {
        async get() {
          return { algorithm: issuerFixture.algorithm, privateKey };
        },
      },
      publisherRegistration: {
        kid: publisherFixture.kid,
        publicKey,
      },
      accessPolicy: {
        async decide(claims, requested) {
          void claims;
          return {
            contentNames: ["bodytext"],
            periodGrants: [
              {
                accessGroup: "premium",
                periods: requested.periodCoordinates.premium ?? [],
              },
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
 * The raw document a reader would post for this render.
 *
 * @param {any} vector
 * @returns {string}
 */
function wireRequest(vector) {
  const dcaData = vector.expected.dcaData;
  const [issuerFixture] = vector.input.issuers;
  return JSON.stringify({
    version: dcaData.version,
    issuerName: issuerFixture.issuerName,
    resourceJWT: dcaData.resourceJWT,
    keyId: issuerFixture.keyId,
    sealed: dcaData.issuerData[issuerFixture.issuerName].sealed,
  });
}

/**
 * The wire-only issuer-endpoint contract. A binding provisions test fixtures,
 * then receives the raw request and returns only the final `{ status, body }`.
 *
 * @param {IssuerEndpointBinding} binding
 * @param {any} target
 * @param {any} vector
 */
export function issuerEndpointContract(binding, target, vector) {
  const driver = binding.targets["issuer-endpoint"].driver;
  const rawRequest = wireRequest(vector);

  const expectedResponse = {
    status: endpointStatuses.success,
    body: {
      keys: {
        contentKeys: { bodytext: vector.expected.contentKeys.bodytext },
        periodKeys: { premium: vector.expected.periodKeys.premium },
      },
    },
  };

  describe("portable issuer-endpoint contract", () => {
    test("the binding declares the direct v1 issuer-endpoint target", () => {
      const declared = binding.targets["issuer-endpoint"];
      assertBindingSupportsTarget("issuer-endpoint", target, declared);
    });

    test("a raw request reaches one complete wire answer", async () => {
      const { base, principal, policyContext } = await fixtures(driver, vector);
      const issuer = driver.createIssuerEndpoint(base);
      const response = await issuer.unlock(rawRequest, { principal, policyContext });

      assert.deepEqual(Object.keys(response).sort(), ["body", "status"]);
      assert.deepEqual(response, expectedResponse);
    });

    test("untrusted JWS header keys never replace the registered verification key", async () => {
      const controls = await registeredJwsControls(vector);
      for (const [signer, resourceJWT] of Object.entries(controls)) {
        const { base, principal, policyContext } = await fixtures(driver, vector);
        let openings = 0;
        const get = base.issuerKeys.get;
        base.issuerKeys.get = async () => {
          openings += 1;
          return get();
        };
        const request = { ...JSON.parse(rawRequest), resourceJWT };
        const result = await driver
          .createIssuerEndpoint(base)
          .unlock(JSON.stringify(request), { principal, policyContext });
        if (signer === "attacker") {
          assert.equal(result.status, 400);
          assert.equal(openings, 0, "unverified publisher input reaches no private opening key");
          assert.equal(Object.hasOwn(result.body, "keys"), false);
        } else {
          assert.deepEqual(result, expectedResponse);
          assert.ok(openings > 0, "the registered-signature control reaches its provisioned key");
        }
      }
    });

    test("policy cannot add coordinates absent from the request", async () => {
      const { base, policyData, principal, policyContext } = await fixtures(driver, vector);
      base.accessPolicy = {
        decide(claims, requested) {
          void claims;
          return {
            contentNames: ["bodytext", "not-present"],
            periodGrants: [
              { accessGroup: "premium", periods: requested.periodCoordinates.premium ?? [] },
              { accessGroup: "also-not-present", periods: ["251023T1400"] },
            ],
            policyData,
          };
        },
      };

      const response = await driver
        .createIssuerEndpoint(base)
        .unlock(rawRequest, { principal, policyContext });
      assert.deepEqual(response, expectedResponse);
      assert.equal(JSON.stringify(response).includes("not-present"), false);
    });
  });
}

/**
 * The format-2 vectors through the same wire-only public driver. These
 * assertions hold exact status and delivered coordinates; refusal presentation
 * and collaborator reach remain outside the base endpoint contract.
 *
 * @param {IssuerEndpointBinding} binding
 * @param {{ file: string, vector: any }[]} rejectVectors
 * @param {{ file: string, vector: any }[]} sealVectors
 */
export function issuerEndpointRejectVectorContract(binding, rejectVectors, sealVectors) {
  const driver = binding.targets["issuer-endpoint"].driver;
  /** @param {any} expected @returns {Set<string>} */
  function expectedCoordinates(expected) {
    const coordinates = new Set(expected.keys.contentKeys.map((name) => `contentKeys.${name}`));
    for (const [accessGroup, periods] of Object.entries(expected.keys.periodKeys ?? {})) {
      for (const t of /** @type {string[]} */ (periods)) {
        coordinates.add(`periodKeys.${accessGroup}.${t}`);
      }
    }
    return coordinates;
  }

  /** @param {any} body @returns {Map<string, string>} */
  function answerCoordinates(body) {
    /** @type {Map<string, string>} */
    const coordinates = new Map();
    for (const [contentName, key] of Object.entries(body?.keys?.contentKeys ?? {})) {
      coordinates.set(`contentKeys.${contentName}`, /** @type {string} */ (key));
    }
    for (const [accessGroup, periods] of Object.entries(body?.keys?.periodKeys ?? {})) {
      for (const [t, key] of Object.entries(/** @type {any} */ (periods))) {
        coordinates.set(`periodKeys.${accessGroup}.${t}`, /** @type {string} */ (key));
      }
    }
    return coordinates;
  }

  /** @param {any} base @returns {Map<string, string>} */
  function renderKeys(base) {
    /** @type {Map<string, string>} */
    const keys = new Map();
    for (const [contentName, key] of Object.entries(base.expected.contentKeys)) {
      keys.set(`contentKeys.${contentName}`, /** @type {string} */ (key));
    }
    for (const [accessGroup, periods] of Object.entries(base.expected.periodKeys)) {
      for (const [t, key] of Object.entries(/** @type {any} */ (periods))) {
        keys.set(`periodKeys.${accessGroup}.${t}`, /** @type {string} */ (key));
      }
    }
    return keys;
  }

  describe("portable issuer-endpoint reject vectors", () => {
    for (const { file, vector } of rejectVectors) {
      test(`${file}: answers the raw document at the recorded boundary`, async () => {
        const privateKey = await driver.importIssuerPrivateKey(vector.issuer.privateKeyJwk);
        /** @type {Map<string, CryptoKey>} */
        const signingKeys = new Map();
        for (const fixture of vector.publisher.signingKeys) {
          signingKeys.set(fixture.kid, await driver.importPublisherPublicKey(fixture.publicKeyJwk));
        }
        const policyData = [{ opaqueEndpointContractSentinel: `policy-data:${file}` }];

        const issuer = driver.createIssuerEndpoint({
          issuerName: vector.issuer.issuerName,
          operatingIssuerNames: [vector.issuer.issuerName],
          keyId: vector.issuer.keyId,
          issuerKeys: {
            get(issuerName, keyId) {
              if (issuerName !== vector.issuer.issuerName || keyId !== vector.issuer.keyId) {
                return undefined;
              }
              return {
                algorithm: vector.issuer.algorithm,
                privateKey,
              };
            },
          },
          publisherRegistrations: [...signingKeys].map(([kid, publicKey]) => ({
            kid,
            publicKey,
          })),
          accessPolicy: {
            decide(claims, requested) {
              void claims;
              return {
                contentNames: requested.contentNames,
                periodGrants: requested.accessGroups.map((accessGroup) => ({
                  accessGroup,
                  periods: requested.periodCoordinates[accessGroup] ?? [],
                })),
                policyData,
              };
            },
          },
          limits: { maxBodyBytes: 64 * 1024, maxEntries: 32, maxEntriesPerGroup: 8 },
          errorDetail: "uniform",
        });

        const response = await issuer.unlock(vector.rawBody);
        const body = response.body;
        const serialized = JSON.stringify(response);
        const projected = statusForVector(vector.expected);
        rejectVectorStatuses.set(file, response.status);
        assertMappedStatus(
          response.status,
          projected,
          `${file}: the status the contract table projects for this answer`,
        );
        assert.equal(Object.hasOwn(body, "policyData"), false, "wire body omits host policy data");
        assert.equal(
          serialized.includes(policyData[0].opaqueEndpointContractSentinel),
          false,
          "opaque policy data never reaches the wire",
        );

        if (vector.expected.code !== null) {
          assert.equal(body.keys, undefined);
          assert.equal(body.errors, undefined);
        } else {
          assert.equal(body.error, undefined);
        }

        const expected = expectedCoordinates(vector.expected);
        const answered = answerCoordinates(body);
        assert.deepEqual([...answered.keys()].sort(), [...expected].sort());

        const base = sealVectors.find(
          ({ vector: candidate }) => candidate.name === vector.derivedFrom,
        )?.vector;
        assert.ok(base, `${vector.derivedFrom} is present`);
        const knownKeys = renderKeys(base);
        for (const [coordinate, key] of answered) {
          assert.equal(key, knownKeys.get(coordinate), `${coordinate} carries its own key`);
        }

        for (const [coordinate, key] of knownKeys) {
          if (!expected.has(coordinate)) assert.equal(serialized.includes(key), false);
        }

        const errors = body.errors ?? {};
        assert.deepEqual(Object.keys(errors).sort(), Object.keys(vector.expected.errors).sort());
        for (const [coordinate, code] of Object.entries(vector.expected.errors)) {
          assert.equal(errors[coordinate]?.error, code);
        }
      });
    }
  });
}

/**
 * The status projection itself: the contract-owned table, the tests that keep
 * it complete and honest, and one endpoint run per table entry that no reject
 * vector reaches. Every assertion here compares a public `{ status, body }`
 * against a number this contract wrote down, so running it against a second
 * binding tells the two implementations apart.
 *
 * @param {IssuerEndpointBinding} binding
 * @param {any} statusVector a positive vector, used as the working request the named cases perturb
 * @param {{ file: string, vector: any }[]} rejectVectors
 */
export function issuerEndpointStatusContract(binding, statusVector, rejectVectors) {
  const driver = binding.targets["issuer-endpoint"].driver;
  const rawRequest = wireRequest(statusVector);
  const vectorCodes = rejectVectors
    .map(({ vector }) => vector.expected.code)
    .filter((code) => code !== null && code !== undefined);

  describe("portable issuer-endpoint status projection", () => {
    test("the projection is the contract's own, reaching no implementation status table", () => {
      const failures = assertContractOwnsItsStatuses([
        new URL("./issuer-endpoint-statuses.js", import.meta.url),
        new URL("./issuer-endpoint-contract.js", import.meta.url),
        new URL("../issuer-endpoint.contract.test.js", import.meta.url),
      ]);
      assert.deepEqual(failures, [], "the contract runner reaches outside itself");
    });

    test("every refusal code the reject vectors record has exactly one status mapping", () => {
      assert.ok(vectorCodes.length > 0, "the selected vectors record whole-request refusals");
      for (const code of new Set(vectorCodes)) {
        assert.ok(Object.hasOwn(endpointStatuses.wholeRequest, code), `${code} is mapped`);
        const mappings = [...endpointStatusesSource.matchAll(new RegExp(`"${code}"\\s*:`, "g"))];
        assert.equal(mappings.length, 1, `${code} is written once in the table`);
        assert.equal(
          typeof endpointStatuses.wholeRequest[code],
          "number",
          `${code} maps to a status`,
        );
      }
    });

    test("no status entry is unused without a named non-vector contract case", () => {
      const named = NON_VECTOR_STATUS_CASES.map((contractCase) => contractCase.code);
      assert.equal(new Set(named).size, named.length, "each named case carries its own code");
      for (const contractCase of NON_VECTOR_STATUS_CASES) {
        assert.ok(contractCase.name.length > 0, `${contractCase.code} names its case`);
        assert.ok(
          Object.hasOwn(endpointStatuses.wholeRequest, contractCase.code),
          `${contractCase.code} is a table entry`,
        );
      }
      assert.deepEqual(
        Object.keys(endpointStatuses.wholeRequest).sort(),
        [...new Set([...vectorCodes, ...named])].sort(),
        "every table entry is carried by a reject vector or by a named case, and nothing else is listed",
      );
    });

    test("success, partial and each whole-request code select their own table member", () => {
      const probe = { success: 291, partial: 292, wholeRequest: { probe_code: 293 } };
      assert.equal(resolveStatus(probe, { code: null, errors: {} }), 291);
      assert.equal(
        resolveStatus(probe, { code: null, errors: { bodytext: "unseal_failed" } }),
        292,
      );
      assert.equal(resolveStatus(probe, { code: "probe_code", errors: {} }), 293);

      assert.equal(Object.hasOwn(endpointStatuses, "success"), true);
      assert.equal(Object.hasOwn(endpointStatuses, "partial"), true);
      assert.equal(endpointStatuses.success, 200, "an answered request is a 200");
      assert.equal(
        endpointStatuses.partial,
        200,
        "a coordinate that would not open did not refuse the request",
      );
      assert.equal(
        Object.hasOwn(endpointStatuses.wholeRequest, "unseal_failed"),
        false,
        "a coordinate code is never looked up as a whole-request refusal",
      );
      for (const { vector } of rejectVectors) {
        if (vector.expected.code === null) continue;
        assert.equal(
          statusForVector(vector.expected),
          endpointStatuses.wholeRequest[vector.expected.code],
          `${vector.name} maps by its own top-level code`,
        );
      }
    });

    // This runs after `portable issuer-endpoint reject vectors`, which is
    // registered earlier in the same file and whose tests execute one at a
    // time before this suite starts, so `rejectVectorStatuses` holds what
    // those runs actually resolved.
    test("every selected reject vector ran the reject contract and took its status from the table", () => {
      assert.ok(rejectVectors.length > 0, "the target selected reject vectors");
      assert.deepEqual(
        [...rejectVectorStatuses.keys()].sort(),
        rejectVectors.map(({ file }) => file).sort(),
        "each vector the target selected reached the endpoint through the reject contract",
      );
      for (const { file, vector } of rejectVectors) {
        const ran = rejectVectorStatuses.get(file);
        const fromTable = resolveStatus(endpointStatuses, {
          code: vector.expected.code,
          errors: vector.expected.errors,
        });
        assertMappedStatus(
          ran,
          fromTable,
          `${file}: the status it ran under is the one the table projects from code and errors alone`,
        );
      }
    });

    test("a request answered in full carries the contract success status", async () => {
      const { base, principal, policyContext } = await fixtures(driver, statusVector);
      const response = await driver
        .createIssuerEndpoint(base)
        .unlock(rawRequest, { principal, policyContext });

      assert.equal(response.status, endpointStatuses.success);
      assert.notEqual(response.body.keys, undefined, "the answer carries keys");
      assert.equal(
        response.body.error,
        undefined,
        "an answered request carries no whole-request code",
      );
    });

    for (const { code, name, perturb } of NON_VECTOR_STATUS_CASES) {
      test(`${code}: ${name}`, async () => {
        const { base, principal, policyContext } = await fixtures(driver, statusVector);
        base.errorDetail = "code";
        const setup = perturb({ base, rawRequest });
        const endpoint = driver.createIssuerEndpoint(setup.base);

        const response = await endpoint.unlock(setup.rawRequest, { principal, policyContext });

        assert.equal(
          response.body.error,
          code,
          `this case reaches ${code} and not another refusal`,
        );
        assertMappedStatus(
          response.status,
          endpointStatuses.wholeRequest[code],
          `${code} answers the status the contract table holds`,
        );
        assert.equal(response.body.keys, undefined, "a refused request carries no key section");
        assert.equal(
          response.body.errors,
          undefined,
          "a refused request reports nothing per coordinate",
        );
      });
    }
  });
}

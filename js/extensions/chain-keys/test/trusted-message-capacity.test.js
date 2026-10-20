import test from "node:test";
import assert from "node:assert/strict";
import { chainMemberLimit } from "../../../core-shared/chainMemberLimit.js";
import { chainKeyCarrierReader } from "../core-shared--client-issuer/chainKeyCarrierReader.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { chainKeyClientProfileFor, referenceChainKeyProfileFor } from "../referenceProfile.js";

test("chain message capacity is finite trusted configuration with unchanged default", () => {
  assert.equal(chainMemberLimit(), 16);
  assert.equal(chainMemberLimit(200), 200);
  for (const value of [0, -1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, "200", null]) {
    assert.throws(() => chainMemberLimit(value), { code: "bad_config" });
    assert.throws(() => new ChainKeyRequestBuilder({ maxChainMembersPerMessage: value }), {
      code: "bad_config",
    });
    assert.throws(() => chainKeyCapabilitySource({ maxChainMembersPerMessage: value }), {
      code: "bad_config",
    });
    assert.throws(() => chainKeyClientProfileFor(undefined, { maxChainMembersPerMessage: value }), {
      code: "bad_config",
    });
  }
  const profile = referenceChainKeyProfileFor(undefined, { maxChainMembersPerMessage: 200 });
  for (const make of [profile.issuerEngineFor, profile.explicitIssuerEngineFor])
    for (const value of [0, 16, Infinity])
      assert.throws(() => make({ maxChainMembersPerMessage: value }), { code: "bad_config" });
});

test("carrier bounds and memoized client admission stay local to each capacity", () => {
  const geometry = { chainsPerDay: 2, periodMinutes: 60 };
  const sealed = Object.fromEntries(
    Array.from({ length: 100 }, (_, n) => [
      `g${n}`,
      {
        "261014T2300": "AA",
        "261015T1100": "AA",
      },
    ]),
  );
  const request = { sealed: { chainKeys: sealed }, periodGeometry: geometry };
  const response = {
    keys: {
      chainKeys: Object.fromEntries(Object.keys(sealed).map((g) => [g, { "261014T1800": "AA" }])),
    },
  };
  const ordinary = chainKeyClientProfileFor();
  const large = chainKeyClientProfileFor(undefined, { maxChainMembersPerMessage: 200 });
  for (const profile of [ordinary, large, ordinary, large]) {
    const admitted = profile.parametersForResponse(response, null, "g99", request, "261014T1800");
    assert.equal(admitted !== null, profile === large);
  }
  const read = (maximum) =>
    chainKeyCarrierReader({
      container: request.sealed,
      context: geometry,
      valueName: "sealed",
      ...(maximum === undefined ? {} : { maxChainMembersPerMessage: maximum }),
    });
  assert.equal(read().family("g99").kind, "invalid");
  assert.equal(read(199).family("g99").kind, "invalid");
  assert.equal(read(200).family("g99").kind, "valid");
  // A carried member cannot select a larger receiver capacity.
  request.sealed.maxChainMembersPerMessage = 200;
  assert.equal(read().family("g99").kind, "invalid");
});

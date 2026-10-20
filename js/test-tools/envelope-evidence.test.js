// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { assessEnvelopeEvidence, observedEnvelopeTags } from "./envelope-evidence.js";
import { classifyTestTags, validateClaimIndex } from "./claim-index.js";
const ec = "envelope/ecdh-p256/issuer";
const rsa = "envelope/rsa-oaep/issuer";
const index = JSON.parse(
  readFileSync(new URL("../../verification/claim-index/v1.json", import.meta.url), "utf8"),
);
const catalogue = JSON.parse(
  readFileSync(new URL("../../verification/profile-catalogue/v1.json", import.meta.url), "utf8"),
);

test("baseline issuer roles explicitly retain mandatory EC envelope support", () => {
  for (const alternatives of [
    {},
    { envelopeAlgorithm: ["rsa-oaep"] },
    { envelopeAlgorithm: ["client-bound-rsa-oaep"] },
  ]) {
    const changed = structuredClone(index);
    const publisher = changed.support.find(
      (entry) => entry.profile === catalogue.baseline && entry.role === "publisher",
    );
    publisher.alternatives = alternatives;
    assert.throws(() => validateClaimIndex(changed, catalogue), /mandatory baseline ecdh-p256/);
  }
  assert.doesNotThrow(() => validateClaimIndex(index, catalogue));
});
test("every declared envelope algorithm owes evidence for each claimed envelope role", () => {
  const result = assessEnvelopeEvidence(
    ["publisher", "issuer", "client"],
    ["ecdh-p256", "rsa-oaep", "client-bound-rsa-oaep"],
    [ec, "envelope/ecdh-p256/publisher", rsa],
  );
  assert.deepEqual(result.missing, ["envelope/rsa-oaep/publisher"]);
  assert.equal(result.required.length, 4);
  assert.ok(result.gaps.some((gap) => gap.includes("rsa-oaep/publisher")));
  assert.equal(assessEnvelopeEvidence(["client"], [], []).required.length, 0);
  const narrow = assessEnvelopeEvidence(["issuer"], ["rsa-oaep"], [rsa]);
  assert.equal(narrow.scope, "narrower-envelope-behavior");
  assert.ok(narrow.gaps.some((gap) => gap.includes("mandatory EC")));
});
test("skips, TODOs, suites and client-bound tags prove no envelope observation", () => {
  const event = {
    type: "test:pass",
    data: { name: "open", details: { type: "test" }, tags: [ec] },
  };
  assert.deepEqual(observedEnvelopeTags([event]), [ec]);
  for (const extra of [
    { skip: true },
    { skip: "" },
    { todo: true },
    { todo: "" },
    { details: { type: "suite" } },
  ])
    assert.deepEqual(observedEnvelopeTags([{ ...event, data: { ...event.data, ...extra } }]), []);
  assert.deepEqual(observedEnvelopeTags([{ ...event, type: "test:fail" }]), []);
  assert.deepEqual(
    observedEnvelopeTags([
      {
        ...event,
        data: { ...event.data, tags: ["dca-profile-client-bound-rsa-oaep/issuer/wrapped-result"] },
      },
    ]),
    [],
  );
});
test("envelope tags cannot be credited as general profile duty tags", () => {
  assert.deepEqual(classifyTestTags([rsa], catalogue), { duties: [], untagged: true });
  assert.throws(
    () => classifyTestTags(["envelope/invented/issuer"], catalogue),
    /unknown test duty/,
  );
});

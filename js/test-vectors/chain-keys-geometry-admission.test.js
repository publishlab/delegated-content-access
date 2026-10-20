// @ts-check
// These JSON documents test mathematical number admission: chain keys §12.1 (#document-member)
// admits 2, 2.0 and 2e0 alike. They do not impose a lexical integer parser.
// Original geometry spelling evidence; no whole-profile composition claim.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { settleChainGeometry } from "../extensions/chain-keys/core-shared/chainKeyConstruction.js";
import { DcaError } from "../core-shared/errors.js";

const PACKAGE = new URL(
  "../../verification/fixtures/v1/profiles/dca-profile-chain-keys/geometry-admission/",
  import.meta.url,
);
const raw = readFileSync(new URL("inputs.json", PACKAGE), "utf8");
const inputs = JSON.parse(raw);
const expected = JSON.parse(readFileSync(new URL("expected.json", PACKAGE), "utf8"));
const recorded = JSON.parse(readFileSync(new URL("observations.json", PACKAGE), "utf8"));

test("the recorded input retains integer, decimal and exponent JSON spellings", () => {
  for (const spelling of ["2", "2.0", "2e0"]) {
    assert.ok(raw.includes(`"chainsPerDay": ${spelling},`), spelling);
  }
  for (const spelling of ["60", "60.0", "6e1"]) {
    assert.ok(raw.includes(`"periodMinutes": ${spelling} }`), spelling);
  }
  assert.notEqual(
    JSON.stringify(inputs, null, 2),
    raw.trim(),
    "reserialization would erase the original spellings",
  );
  const ids = inputs.cases.map((/** @type {{id: string}} */ entry) => entry.id);
  assert.equal(ids.length, 9);
  assert.equal(new Set(ids).size, 9);
  assert.deepEqual(
    expected.cases.map((/** @type {{id: string}} */ entry) => entry.id),
    ids,
  );
  assert.deepEqual(recorded.cases, expected.cases);
});

for (const input of inputs.cases) {
  test(`domain geometry admission: ${input.id}`, () => {
    const wanted = expected.cases.find(
      (/** @type {{id: string}} */ entry) => entry.id === input.id,
    );
    assert.ok(wanted, "every raw case has an independent expectation");
    if (wanted.admitted) {
      const admitted = settleChainGeometry(input.geometry);
      assert.deepEqual(admitted, wanted.geometry);
      assert.deepEqual(admitted, {
        chainsPerDay: 2,
        periodMinutes: 60,
        windowMinutes: 720,
        positionsPerWindow: 12,
      });
    } else {
      assert.throws(() => settleChainGeometry(input.geometry), DcaError);
    }
  });
}

// @ts-check

import { readFileSync } from "node:fs";
import { basename } from "node:path";

import { registerIssuerCoreContract } from "./support/issuer-core-contract.js";

const bindingPath = process.env.DCA_TEST_BINDING;
if (!bindingPath)
  throw new Error("DCA_TEST_BINDING is required; use test-contract/run-contract-target.js");
const dcaTestBinding = globalThis.__dcaTestBinding;
if (!dcaTestBinding) throw new Error("issuer-core contract requires the runner-preloaded binding");
const target = JSON.parse(process.env.DCA_TEST_TARGET_CONFIG ?? "null");
const fixtureFiles = JSON.parse(process.env.DCA_TEST_FIXTURE_FILES ?? "null");
const selectedFixtureCount = Number(process.env.DCA_TEST_SELECTED_FIXTURES);

if (process.env.DCA_TEST_TARGET !== "issuer-core" || !target || !Array.isArray(fixtureFiles)) {
  throw new Error(
    "issuer-core contract requires a manifest-selected target from test-contract/run-contract-target.js",
  );
}
if (!Number.isInteger(selectedFixtureCount) || selectedFixtureCount <= 0) {
  throw new Error("issuer-core contract requires the selected fixture count the runner counted");
}

const vectors = fixtureFiles.map((file) => ({
  file: basename(file),
  vector: JSON.parse(readFileSync(file, "utf8")),
}));

if (vectors.length !== selectedFixtureCount) {
  throw new Error(
    `issuer-core contract loaded ${vectors.length} of the ${selectedFixtureCount} fixtures the runner selected`,
  );
}
for (const format of target.fixtureFormats) {
  if (!vectors.some(({ vector }) => vector.vectorFormat === format)) {
    throw new Error(
      `issuer-core contract did not consume selected vector format ${JSON.stringify(format)}`,
    );
  }
}

registerIssuerCoreContract(dcaTestBinding, target, vectors);

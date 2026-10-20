// @ts-check

import { readFileSync } from "node:fs";
import { basename } from "node:path";

import {
  issuerEndpointContract,
  issuerEndpointRejectVectorContract,
  issuerEndpointStatusContract,
} from "./support/issuer-endpoint-contract.js";

const bindingPath = process.env.DCA_TEST_BINDING;
if (!bindingPath)
  throw new Error("DCA_TEST_BINDING is required; use test-contract/run-contract-target.js");
const { dcaTestBinding } = await import(bindingPath);
const targetName = process.env.DCA_TEST_TARGET;
const target = JSON.parse(process.env.DCA_TEST_TARGET_CONFIG ?? "null");
const fixtureFiles = JSON.parse(process.env.DCA_TEST_FIXTURE_FILES ?? "null");
const selectedFixtureCount = Number(process.env.DCA_TEST_SELECTED_FIXTURES);
if (targetName !== "issuer-endpoint" || !target || !Array.isArray(fixtureFiles)) {
  throw new Error(
    "issuer-endpoint contract requires a manifest-selected target from test-contract/run-contract-target.js",
  );
}
if (!Number.isInteger(selectedFixtureCount) || selectedFixtureCount <= 0) {
  throw new Error(
    "issuer-endpoint contract requires the selected fixture count the runner counted",
  );
}

const vectors = fixtureFiles.map((file) => ({
  file: basename(file),
  vector: JSON.parse(readFileSync(file, "utf8")),
}));
const sealVectors = vectors.filter(({ vector }) => vector.vectorFormat === "1");
const rejectVectors = vectors.filter(({ vector }) => vector.vectorFormat === "2");

const consumedFormats = new Set(vectors.map(({ vector }) => vector.vectorFormat));
for (const vectorFormat of target.fixtureFormats) {
  if (!consumedFormats.has(vectorFormat)) {
    throw new Error(
      `issuer-endpoint contract did not consume selected vector format ${JSON.stringify(vectorFormat)}`,
    );
  }
}
// The runner counted the selection before this process started. Reading the
// same sets and arriving at a smaller number means a vector the target claims
// to cover stays silently outside the run.
if (vectors.length !== selectedFixtureCount) {
  throw new Error(
    `issuer-endpoint contract loaded ${vectors.length} of the ${selectedFixtureCount} fixtures the runner selected`,
  );
}

const statusVector = sealVectors.find(({ vector }) => vector.name === "seal-ecdh").vector;

issuerEndpointContract(dcaTestBinding, target, statusVector);
issuerEndpointRejectVectorContract(dcaTestBinding, rejectVectors, sealVectors);
issuerEndpointStatusContract(dcaTestBinding, statusVector, rejectVectors);

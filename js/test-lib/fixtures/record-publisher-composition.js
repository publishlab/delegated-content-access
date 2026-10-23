// @ts-check
// Re-record the eight publisher-composition regression fixtures after an
// adopted wire change. Inputs, fixture keys and ECDH pairs remain recorded.
// Use the hand-nested Sealer paths, independently of publisher composition.
// The tests replay these saved bytes through the composition entry points.
// Run from the repository root, adding --check to compare without writing.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { format, resolveConfig } from "prettier";
import { Sealer } from "../../core-publisher/Sealer.js";
import { OmittingSealer } from "../../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { periodFamilyGeneration } from "../../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { recordedPublisherWorld, recordedForm } from "./publisher-composition-world.js";

const paths = [
  "test-reference/core-publisher/fixtures/publisher-composition--baseline.json",
  "test-reference/core-publisher/fixtures/publisher-composition--baseline-test-aad.json",
  "extensions/chain-keys/test/fixtures/publisher-composition--chain-supply.json",
  ...["active", "inactive", "mixed", "inactive-test-aad"].map(
    (name) =>
      `extensions/content-key-seal-omission/test/fixtures/publisher-composition--omission-${name}.json`,
  ),
  "test-extensions/fixtures/publisher-composition--chain-omission.json",
];
const args = process.argv.slice(2);
if (args.length > 1 || args.some((arg) => arg !== "--check")) {
  throw new Error("usage: node js/test-lib/fixtures/record-publisher-composition.js [--check]");
}
const check = args.includes("--check");
let differences = 0;
for (const path of paths) {
  const file = new URL(`../../${path}`, import.meta.url);
  const previous = readFileSync(file, "utf8");
  const record = JSON.parse(previous);
  const world = await recordedPublisherWorld(record.input);
  const config = world.config();
  const chain = record.input.chain;
  if (chain) {
    config.periodKeySupply = periodFamilySupply({
      periodKeySupply: world.periodKeySupply,
      families: Object.fromEntries(
        chain.groups.map((group) => [
          group,
          periodFamilyGeneration({
            keyDerivationSecret: Buffer.from(chain.keyDerivationSecret, "base64url"),
            geometry: chain.geometry,
          }),
        ]),
      ),
      chainWindows: chain.chainWindows,
      chainItemSlots: 2,
    });
  }
  const Constructor = path.includes("omission") ? OmittingSealer : Sealer;
  const render = await world.sealed(new Constructor(config));
  record.expected = recordedForm(render).form;
  // Preserve provenance once; this is a new wire recording, not evidence
  // that today's bytes were produced by the historical implementation.
  if (!record.recordedFrom.includes("fixed content nonce")) {
    record.recordedFrom +=
      "; re-recorded 2026-10-19 via js/test-lib/fixtures/record-publisher-composition.js for fixed content nonce and renderId/name AAD; seeded key/wrap/envelope draws shift after removing item nonce draws";
  }
  if (!record.recordedFrom.includes("derived period-wrap nonce")) {
    record.recordedFrom +=
      "; re-recorded 2026-10-20 via js/test-lib/fixtures/record-publisher-composition.js for the derived period-wrap nonce and { t, key } entries; seeded envelope draws shift after removing wrap nonce draws";
  }
  if (!record.recordedFrom.includes("named-record")) {
    record.recordedFrom +=
      "; re-recorded 2026-10-22 via js/test-lib/fixtures/record-publisher-composition.js for named-record wire collections and 97-byte ordinary ECDH envelopes with an implicit zero IV; recorded ECDH pairs are unchanged, and the IV draws were the last draws of each render, so no other draw moved";
  }
  const next = await format(JSON.stringify(record), {
    ...(await resolveConfig(fileURLToPath(file))),
    filepath: fileURLToPath(file),
  });
  if (next === previous) continue;
  differences++;
  if (check) console.error(`differs: ${path}`);
  else writeFileSync(file, next);
}
console.log(
  `${check ? "checked" : "recorded"} ${paths.length} publisher composition fixtures; ${differences} ${check ? "differences" : "updated"}`,
);
if (check && differences) process.exitCode = 1;

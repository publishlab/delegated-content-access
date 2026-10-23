// @ts-check
import { readFileSync } from "node:fs";
import { registerHtmlWriterContract } from "./support/html-writer-contract.js";

const target = JSON.parse(process.env.DCA_TEST_TARGET_CONFIG ?? "null");
const files = JSON.parse(process.env.DCA_TEST_FIXTURE_FILES ?? "null");
const count = Number(process.env.DCA_TEST_SELECTED_FIXTURES);
if (
  process.env.DCA_TEST_TARGET !== "html-writer" ||
  !process.env.DCA_TEST_BINDING ||
  !target ||
  !Array.isArray(files)
) {
  throw new Error("html-writer requires the manifest-backed contract selector");
}
if (!Number.isInteger(count) || count <= 0 || count !== files.length) {
  throw new Error("html-writer fixture count differs from the runner selection");
}
const binding = /** @type {any} */ (globalThis).__dcaTestBinding;
if (!binding) throw new Error("html-writer requires the runner-preloaded binding");
const cases = files.map((file) => JSON.parse(readFileSync(file, "utf8")));
if (cases.some((fixture) => fixture.vectorFormat !== "html-writer/1")) {
  throw new Error("html-writer consumes html-writer/1 fixture material only");
}
registerHtmlWriterContract(binding, cases);

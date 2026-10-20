// @ts-check
import { readFileSync } from "node:fs";
import { registerBrowserIssuerContract } from "./support/issuer-browser-origin-contract.js";

const target = JSON.parse(process.env.DCA_TEST_TARGET_CONFIG ?? "null");
const files = JSON.parse(process.env.DCA_TEST_FIXTURE_FILES ?? "null");
const count = Number(process.env.DCA_TEST_SELECTED_FIXTURES);
if (
  process.env.DCA_TEST_TARGET !== "issuer-browser-origin" ||
  !process.env.DCA_TEST_BINDING ||
  !target ||
  !Array.isArray(files)
) {
  throw new Error("issuer-browser-origin requires the manifest-backed contract selector");
}
if (!Number.isInteger(count) || count <= 0 || count !== files.length) {
  throw new Error("issuer-browser-origin fixture count differs from the runner selection");
}
const binding = /** @type {any} */ (globalThis).__dcaTestBinding;
if (!binding) throw new Error("issuer-browser-origin requires the runner-preloaded binding");
const vectors = files.map((file) => JSON.parse(readFileSync(file, "utf8")));
if (vectors.some((vector) => vector.vectorFormat !== "1")) {
  throw new Error("issuer-browser-origin consumes format-1 fixture material only");
}
registerBrowserIssuerContract(binding, target, vectors);

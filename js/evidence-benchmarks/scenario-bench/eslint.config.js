// Bench checks reuse the reference package's installed development tools.
import { createRequire } from "node:module";
import referenceConfig from "../../eslint.config.js";
const require = createRequire(new URL("../../package.json", import.meta.url));
const globals = require("globals");
export default [
  ...referenceConfig,
  { files: ["**/*.js"], languageOptions: { globals: globals.node } },
];

// @ts-check

import js from "@eslint/js";
import globals from "globals";

export default [
  {
    // paths lint does not cover yet; coverage grows as entries come off this list
    ignores: [
      ".stryker-tmp/**",
      "node_modules/**",
      "test/**",
      "test-base/**",
      "test-contract/**",
      "test-extensions/**",
      "test-lib/**",
      "test-profiles/**",
      "test-reference/**",
      "test-vectors/**",
      "extensions/**",
      "evidence-benchmarks/**",
      "experiments/**",
      "adapter-client/PeriodKeyCache.js",
      "core-shared--publisher-issuer/jwt.js",
      "demo/actors/IssuerServer.js",
      "demo/actors/issuer/FailoverGate.js",
      "ports/UnlockEndpoint.js",
      "tools/make-vectors.js",
    ],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
  },
  {
    // runtime-neutral: these directories run on Node and in the browser, so they see
    // WebCrypto and the web APIs the two share; a `process` or `window` here is a bug
    files: ["core-*/**", "adapter-*/**", "integration-*/**", "ports/**", "demo/**"],
    ignores: ["demo/browser/page.js"],
    languageOptions: {
      globals: {
        ...globals["shared-node-browser"],
      },
    },
  },
  {
    files: [
      "tools/**",
      "test-tools/**",
      "evidence-benchmarks/**",
      "evidence-platform-tests/**",
      "experiments/**",
      "extensions/**/test/**",
      "extensions/**/test-lib/**",
      "extensions/**/tools/**",
      "test/**",
      "test-base/**",
      "test-contract/**",
      "test-extensions/**",
      "test-lib/**",
      "test-reference/**",
      "test-vectors/**",
    ],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
  {
    files: ["demo/browser/page.js"],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },
];

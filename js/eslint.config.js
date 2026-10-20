// @ts-check

import js from "@eslint/js";
import globals from "globals";

export default [
  {
    // paths lint does not cover yet; coverage grows as entries come off this list
    ignores: [".stryker-tmp/**", "node_modules/**"],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
    rules: {
      "preserve-caught-error": "error",
      "array-callback-return": "error",
      "no-self-compare": "error",
      "no-throw-literal": "error",
      // a key named in a destructuring only to keep it out of a rest spread is
      // used by that exclusion
      "no-unused-vars": ["error", { ignoreRestSiblings: true }],
    },
  },
  {
    // runtime-neutral: these directories run on Node and in the browser, so they see
    // WebCrypto and the web APIs the two share; a `process` or `window` here is a bug
    files: [
      "core-*/**",
      "adapter-*/**",
      "integration-*/**",
      "ports/**",
      "demo/**",
      "extensions/**/core-*/**",
      "extensions/*/*.js",
      "extensions/**/adapter-*/**",
      "extensions/**/integration-*/**",
    ],
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
      "test-bridges/**",
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

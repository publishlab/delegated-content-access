// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { bodyElements } from "./support/html-writer-contract.js";

export const ASSERTED_HTML_WRITER_NEGATIVE_PROOF = true;

test("html-writer rejects a slash-only writer at the HTML carrier boundary", () => {
  /** @type {NodeJS.ProcessEnv} */
  const env = { ...process.env, npm_lifecycle_event: "test:contract:html-writer" };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(
    process.execPath,
    [
      "test-contract/run-contract-target.js",
      "test-contract/html-writer/bindings/slash-only-html-writer-binding.js",
    ],
    { cwd: new URL("../../", import.meta.url), env, encoding: "utf8" },
  );
  assert.notEqual(child.status, 0, "the faulty writer fails the portable contract");
  const transcript = `${child.stdout}\n${child.stderr}`;
  assert.match(
    transcript,
    /not ok 1 - dangerous-script-spellings: writer preserves inert body carriers/,
  );
  assert.match(transcript, /exactly one body dca-sealed-content carrier survives HTML parsing/);
});

test("HTML writer evidence uses scripting-enabled document parsing", () => {
  const markup =
    '<script type="application/json" class="dca-data">{}</script>' +
    '<noscript><script type="application/json" class="dca-data">{}</script></noscript>';
  /** @param {boolean} enabled */
  const scripts = (enabled) =>
    bodyElements(markup, enabled).filter((node) => node.tagName === "script");
  assert.equal(scripts(true).length, 1, "noscript text does not add an enabled-mode body carrier");
  assert.equal(scripts(false).length, 2, "disabled-mode parsing would count the extra carrier");
});

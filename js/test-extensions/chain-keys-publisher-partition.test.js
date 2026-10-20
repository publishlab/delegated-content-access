// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { base64urlDecode } from "../core-shared/codec.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";

const GROUP = "premium";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";
const C1 = JSON.parse(
  readFileSync(
    new URL(
      "../extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
).cases.find((/** @type {any} */ entry) => entry.id === "c1");

test("a chain key filed under one publisher is walked for no other publisher", async () => {
  const cache = new ChainKeyCache({ strategy: "retain" });
  await cache.put(GROUP, TERMINAL_T, base64urlDecode(C1.rootChainKey), {
    publisher: "https://a.example",
    ...GEOMETRY,
  });
  const other = { publisher: "https://b.example", ...GEOMETRY };
  assert.deepEqual(
    await cache.candidates(GROUP, TARGET_T, other),
    [],
    "no chain walk for publisher b",
  );
  assert.deepEqual(
    await cache.periodCandidates(GROUP, TARGET_T, { publisher: "https://b.example" }),
    [],
    "nothing was memoized into publisher b's ordinary view",
  );
  assert.equal(
    (await cache.candidates(GROUP, TARGET_T, { publisher: "https://a.example", ...GEOMETRY }))
      .length,
    1,
    "publisher a still derives its own period key",
  );
});

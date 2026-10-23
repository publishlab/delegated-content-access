// @ts-check
import assert from "node:assert/strict";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { portableTest } from "../support/portable-test.js";

const test = portableTest("portable-client-cache-ownership");

test("a resolver resets its original cache and leaves an independent cache intact", async () => {
  const cache = new PeriodKeyCache();
  const other = new PeriodKeyCache();
  const resolver = new ContentKeyResolver({ cache });
  const key = new Uint8Array(16).fill(7);
  const write = { publisher: "publisher.example", issuerName: "issuer" };
  const read = { publisher: "publisher.example", issuerNames: ["issuer"] };

  await cache.put("news", "261021T1200", key, write);
  await other.put("news", "261021T1200", key, write);
  assert.deepEqual(await cache.candidatesAt("news", "261021T1200", read), [key]);
  assert.deepEqual(await other.candidatesAt("news", "261021T1200", read), [key]);

  await resolver.clearReaderContext();
  assert.deepEqual(await cache.candidatesAt("news", "261021T1200", read), []);
  assert.deepEqual(await other.candidatesAt("news", "261021T1200", read), [key]);
});

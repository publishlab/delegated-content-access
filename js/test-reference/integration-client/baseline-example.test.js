import test from "node:test";
import assert from "node:assert/strict";
import { runBaselineExchange } from "../../example--baseline-exchange.js";

test("the public baseline example opens serialized content and reuses its held key", async () => {
  assert.deepEqual(await runBaselineExchange(), {
    plaintext: "Readable content",
    retainedPlaintext: "Readable content",
    contentType: "text/plain",
    issuerRequests: 1,
  });
});

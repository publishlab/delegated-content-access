// A reference handoff proof over genuine reference EC sealing/issuer/client.
// The callbacks implement their application effects independently: they import
// no handler internals, registry, account object, HTML parser or DOM substitute.
import test from "node:test";
import assert from "node:assert/strict";
import { createContentHandler } from "../implementation/content-handler.js";
import { exchange, deferred } from "../test-lib/exchange.js";
import {
  encode,
  decode,
} from "../../../extensions/content-compression/core-shared--client-publisher/gzipCodec.js";

const utf8 = (text) => new TextEncoder().encode(text);
const article = (text = "<p>Byrådet åpnet havna.</p>") => ({
  name: "bodytext",
  bytes: utf8(text),
  contentType: "text/html",
});

// Application callbacks are deliberately ordinary independent functions.
function renderInto(target) {
  return ({ contentType, value, commit }) => {
    if (contentType !== "text/html" || typeof value !== "string") {
      return { status: "refused", reason: "unsupported_type" };
    }
    commit(() => {
      target.text = value;
      target.effects += 1;
    });
    return { status: "handled" };
  };
}

test("serialized JSON exchange hands HTML and known-schema JSON to independent callbacks; bad UTF-8 isolates", async () => {
  const html = article();
  const data = {
    name: "measurements",
    contentType: "application/json",
    bytes: utf8(JSON.stringify({ unit: "C", temperatures: [4, 8] })),
  };
  const invalid = { name: "invalid", contentType: "text/plain", bytes: Uint8Array.of(0xc3, 0x28) };
  const publisher = await exchange([html, data, invalid]);
  assert.ok(publisher.bytes instanceof Uint8Array);
  const client = await publisher.client();
  const target = { text: null, effects: 0 };
  let mean = null;
  let badCalls = 0;
  const connection = createContentHandler().connect({
    delivery: client.delivery,
    isEligible: () => true,
    values: { bodytext: "strictUTF8", measurements: "strictUTF8", invalid: "strictUTF8" },
    targets: {
      bodytext: renderInto(target),
      measurements({ contentType, value, commit }) {
        if (contentType !== "application/json" || typeof value !== "string")
          return { status: "refused" };
        const decoded = JSON.parse(value);
        if (decoded.unit !== "C" || !Array.isArray(decoded.temperatures))
          return { status: "refused" };
        commit(() => {
          mean = decoded.temperatures.reduce((sum, n) => sum + n, 0) / decoded.temperatures.length;
        });
        return { status: "handled" };
      },
      invalid() {
        badCalls += 1;
        return { status: "handled" };
      },
    },
  });
  const outcomes = await connection.handleContent({
    bodytext: await client.open("bodytext"),
    measurements: await client.open("measurements"),
    invalid: await client.open("invalid"),
  });
  assert.equal(outcomes.bodytext.status, "handled");
  assert.equal(outcomes.measurements.status, "handled");
  assert.equal(outcomes.invalid.status, "refused");
  assert.equal(target.text, new TextDecoder().decode(html.bytes));
  assert.equal(mean, 6);
  assert.equal(badCalls, 0);
  assert.equal(
    client.delivery.contentData.find((record) => record.contentName === "bodytext").contentType,
    "text/html",
  );
  assert.equal(
    Object.hasOwn(
      client.delivery.contentData.find((record) => record.contentName === "bodytext"),
      "contentEncodings",
    ),
    false,
  );
  connection.dispose();
});

test("delayed A cannot mutate B's reused bodytext destination; independent B succeeds", async () => {
  const a = await (await exchange([article("<p>Article A</p>")])).client();
  const b = await (await exchange([article("<p>Article B</p>")])).client();
  const target = { text: null, effects: 0, owner: "A" };
  const started = deferred(),
    release = deferred();
  const handler = createContentHandler();
  const old = handler.connect({
    delivery: a.delivery,
    isEligible: () => target.owner === "A",
    values: { bodytext: "strictUTF8" },
    targets: {
      async bodytext({ value, commit }) {
        started.resolve();
        await release.promise;
        commit(() => {
          target.text = value;
          target.effects += 1;
        });
        return { status: "handled" };
      },
    },
  });
  const waiting = old.handleContent({ bodytext: await a.open("bodytext") });
  await started.promise;
  target.owner = "B"; // host retires A before reusing its destination
  const fresh = handler.connect({
    delivery: b.delivery,
    isEligible: () => target.owner === "B",
    values: { bodytext: "strictUTF8" },
    targets: { bodytext: renderInto(target) },
  });
  const current = await fresh.handleContent({ bodytext: await b.open("bodytext") });
  release.resolve();
  assert.equal((await waiting).bodytext.status, "stale");
  assert.equal(current.bodytext.status, "handled");
  assert.equal(target.text, "<p>Article B</p>");
  assert.equal(target.effects, 1);
  assert.equal(
    (await old.handleContent({ bodytext: await a.open("bodytext") })).bodytext.status,
    "stale",
  );
  fresh.dispose();
});

test("an early-only eligibility check demonstrably permits the delayed successor mutation", async () => {
  const client = await (await exchange([article("<p>A</p>")])).client();
  const started = deferred(),
    release = deferred();
  const target = { owner: "A", text: null };
  const unsafe = async () => {
    if (target.owner !== "A") return;
    const bytes = await client.open("bodytext");
    started.resolve();
    await release.promise;
    target.text = new TextDecoder().decode(bytes); // insufficient control: no final guard
  };
  const waiting = unsafe();
  await started.promise;
  target.owner = "B";
  target.text = "B";
  release.resolve();
  await waiting;
  assert.equal(target.text, "<p>A</p>");
});

test("handled repeats avoid effects; another real article's changed bytes are refused", async () => {
  const a = await (await exchange([article("<p>A</p>")])).client();
  const b = await (await exchange([article("<p>B</p>")])).client();
  const target = { text: null, effects: 0 };
  const connection = createContentHandler().connect({
    delivery: a.delivery,
    isEligible: () => true,
    values: { bodytext: "strictUTF8" },
    targets: { bodytext: renderInto(target) },
  });
  const first = await a.open("bodytext");
  assert.equal((await connection.handleContent({ bodytext: first })).bodytext.status, "handled");
  assert.equal(
    (await connection.handleContent({ bodytext: await a.open("bodytext") })).bodytext.status,
    "handled",
  );
  assert.equal(
    (await connection.handleContent({ bodytext: await b.open("bodytext") })).bodytext.status,
    "refused",
  );
  assert.equal(target.text, "<p>A</p>");
  assert.equal(target.effects, 1);
  connection.dispose();
});

test("existing gzip decodes before JSON handling; unsupported gzip releases no handler bytes and HTML still works", async () => {
  const json = utf8('{"unit":"C","temperatures":[4,8]}');
  const html = article();
  const publisher = await exchange([
    html,
    {
      name: "measurements",
      bytes: await encode(json),
      contentType: "application/json",
      contentEncodings: ["gzip"],
    },
  ]);
  const plain = await publisher.client();
  const gzip = await publisher.client({ gzip: decode });
  assert.deepEqual(
    gzip.delivery.contentData.find((record) => record.contentName === "measurements")
      .contentEncodings,
    ["gzip"],
  );
  let observed = null,
    calls = 0;
  const target = { text: null, effects: 0 };
  const setup = (client) => ({
    delivery: client.delivery,
    isEligible: () => true,
    targets: {
      bodytext: renderInto(target),
      measurements({ contentType, value, commit }) {
        assert.equal(contentType, "application/json");
        assert.ok(value instanceof Uint8Array);
        commit(() => {
          observed = Uint8Array.from(value);
          calls += 1;
        });
        return { status: "handled" };
      },
    },
    values: { bodytext: "strictUTF8" },
  });
  const base = createContentHandler().connect(setup(plain));
  await assert.rejects(plain.open("measurements"), { code: "unsupported_encoding" });
  assert.equal(calls, 0); // the host submits only successfully opened names
  assert.equal(
    (await base.handleContent({ bodytext: await plain.open("bodytext") })).bodytext.status,
    "handled",
  );
  const encoded = createContentHandler().connect(setup(gzip));
  assert.equal(
    (await encoded.handleContent({ measurements: await gzip.open("measurements") })).measurements
      .status,
    "handled",
  );
  assert.deepEqual(observed, json);
  assert.equal(calls, 1);
  base.dispose();
  encoded.dispose();
});

test("NDJSON framing and record meaning stay with the agreed application callback", async () => {
  const bytes = utf8('{"unit":"C","value":4}\n{"unit":"C","value":8}\n');
  const client = await (
    await exchange([{ name: "observations", bytes, contentType: "application/x-ndjson" }])
  ).client();
  let observations = null;
  const connection = createContentHandler().connect({
    delivery: client.delivery,
    isEligible: () => true,
    values: { observations: "strictUTF8" },
    targets: {
      observations({ contentType, value, commit }) {
        if (contentType !== "application/x-ndjson" || typeof value !== "string")
          return { status: "refused" };
        const records = value
          .trimEnd()
          .split("\n")
          .map((line) => JSON.parse(line));
        if (records.some((record) => record.unit !== "C" || typeof record.value !== "number"))
          return { status: "refused" };
        commit(() => {
          observations = records.map((record) => record.value);
        });
        return { status: "handled" };
      },
    },
  });
  const result = await connection.handleContent({
    observations: await client.open("observations"),
  });
  assert.equal(result.observations.status, "handled");
  assert.deepEqual(observations, [4, 8]);
  assert.equal(
    Object.hasOwn(
      client.delivery.contentData.find((record) => record.contentName === "observations"),
      "contentDescription",
    ),
    false,
  );
  connection.dispose();
});

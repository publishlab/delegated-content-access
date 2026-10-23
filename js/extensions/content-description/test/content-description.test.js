import test from "node:test";
import assert from "node:assert/strict";
import { admitContentDescription as admit } from "../core-shared--client-publisher/contentDescription.js";
import { withContentDescriptions } from "../core-publisher/withContentDescriptions.js";
import {
  contentDescriptionHandoff as handoff,
  selectContentDescriptionHandler as select,
} from "../core-client/contentDescriptionHandoff.js";
import { writeJsonDelivery } from "../../../adapter-publisher/writeJsonDelivery.js";
import { JsonDeliveryReader } from "../../../adapter-client/JsonDeliveryReader.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { MarkupDeliveryReader } from "../../../adapter-client/MarkupDeliveryReader.js";
import { DcaData } from "../../../core-client/DcaData.js";

const schema = "urn:example:measurements:v1";
const item = { contentType: "application/json", nonce: "AAAAAAAAAAAAAAAA" };
const desc = { version: "1", schema, description: "Temperature °C" };
const state = (value, options) => admit({ contentDescription: value }, options).state;
const policy = { requiresSchema: true, supportedSchemas: [schema] };
// Capture and handoff in one step, for tests where nothing edits the record between them.
const handoffFor = (contentName, record, bytes) =>
  handoff({ contentName, contentType: record.contentType }, admit(record), bytes);

test("absent, explanatory text, malformed and future metadata stay distinct", () => {
  assert.equal(admit({}).state, "absent");
  assert.equal(admit(Object.create({ contentDescription: desc })).state, "absent");
  assert.deepEqual(
    admit({ contentDescription: { version: "1", description: "<b>plain text</b>" } }),
    { state: "available", description: { version: "1", description: "<b>plain text</b>" } },
  );
  for (const value of [
    undefined,
    null,
    [],
    {},
    { version: 1 },
    { version: "1" },
    { ...desc, contentType: "text/html" },
    { ...desc, description: "" },
    { ...desc, schema: null },
    { ...desc, description: "\ud800" },
  ])
    assert.equal(state(value), "invalid");
  assert.equal(state({ version: "2", newField: { future: true } }), "unsupported");
  assert.equal(
    state({ version: "2", newField: "x".repeat(100) }, { maxSerializedBytes: 20 }),
    "invalid",
  );
});

test("schema identifiers are opaque and require exact trusted matching", () => {
  for (const schema of [
    "urn:x:a",
    "https://example.test/a%20b?q=x/y?z",
    "measurements-v1",
    "measurements/temperature/°C/😀",
    "https://x/#frag",
    "urn:x:%ZZ",
    " schema ",
  ]) {
    assert.equal(state({ version: "1", schema }), "available", schema);
    const opened = handoffFor(
      "measurements",
      { ...item, contentDescription: { version: "1", schema } },
      new Uint8Array(),
    );
    assert.deepEqual(select(opened, { requiresSchema: true, supportedSchemas: [schema] }), {
      state: "ready",
      schema,
    });
    assert.deepEqual(select(opened, policy), { state: "refused", schema: null });
  }
  for (const schema of ["", "\ud800", "x\udfff", null, 42])
    assert.equal(state({ version: "1", schema }), "invalid");

  for (const [registered, supplied] of [
    ["é", "e\u0301"],
    ["schema", " schema "],
    ["urn:x:a", "URN:x:a"],
    ["https://x/a", "https://x/%61"],
    ["https://x/a", "/a"],
  ]) {
    const opened = handoffFor(
      "measurements",
      { ...item, contentDescription: { version: "1", schema: supplied } },
      new Uint8Array(),
    );
    assert.equal(opened.description.state, "available");
    assert.deepEqual(select(opened, { requiresSchema: true, supportedSchemas: [registered] }), {
      state: "refused",
      schema: null,
    });
  }
});

test("finite configured bounds count code points and JSON UTF-8 bytes", () => {
  assert.equal(
    state({ version: "1", description: "😀" }, { maxDescriptionCodePoints: 1 }),
    "available",
  );
  assert.equal(
    state({ version: "1", description: "😀x" }, { maxDescriptionCodePoints: 1 }),
    "invalid",
  );
  assert.equal(state(desc, { maxSchemaCodePoints: 2 }), "invalid");
  assert.equal(state({ version: "1", schema: "😀" }, { maxSchemaCodePoints: 1 }), "available");
  assert.equal(state({ version: "1", schema: "😀x" }, { maxSchemaCodePoints: 1 }), "invalid");
  const value = { version: "1", description: "😀\n" };
  const size = Buffer.byteLength(JSON.stringify(value));
  assert.equal(state(value, { maxSerializedBytes: size }), "available");
  assert.equal(state(value, { maxSerializedBytes: size - 1 }), "invalid");
  assert.equal(state({ version: "2", nested: { deeper: true } }, { maxDepth: 2 }), "invalid");
  assert.equal(state(desc, { maxNodes: 2 }), "invalid");
  const cycle = { version: "2" };
  cycle.self = cycle;
  assert.equal(state(cycle), "invalid");
  for (const value of [undefined, 0, -1, Infinity, NaN, 1.5])
    assert.throws(() => admit({}, { maxNodes: value }), TypeError);
  let called = false;
  const accessor = {
    version: "1",
    get description() {
      called = true;
      return "text";
    },
  };
  assert.equal(state(accessor), "invalid");
  assert.equal(called, false);
});

/**
 * The record a delivery carries for one item.
 *
 * @param {any} dcaData
 * @param {string} contentName
 * @returns {any}
 */
const recordOf = (dcaData, contentName) =>
  dcaData.contentData.find((/** @type {any} */ record) => record.contentName === contentName);

test("publisher validates complete collection, copies records and preserves media type", () => {
  const original = {
    contentData: [
      { contentName: "html", ...item, contentType: "text/html" },
      { contentName: "measurements", ...item },
    ],
  };
  const result = withContentDescriptions(original, { measurements: desc });
  assert.deepEqual(
    result.contentData.map((/** @type {any} */ record) => record.contentName),
    ["html", "measurements"],
    "the records keep their names and order",
  );
  assert.equal(recordOf(result, "html").contentType, "text/html");
  assert.equal(recordOf(result, "measurements").contentType, "application/json");
  assert.notEqual(recordOf(result, "html"), recordOf(original, "html"));
  recordOf(result, "measurements").contentDescription.description = "changed";
  assert.equal(desc.description, "Temperature °C");
  assert.equal(Object.hasOwn(recordOf(original, "measurements"), "contentDescription"), false);
  assert.throws(() => withContentDescriptions(original, { missing: desc }));
  assert.throws(() =>
    withContentDescriptions(original, { measurements: desc, html: { version: "2" } }),
  );
  assert.throws(() =>
    withContentDescriptions(
      original,
      JSON.parse('{"__proto__":{"version":"1","description":"x"}}'),
    ),
  );
  const inherited = Object.create({ measurements: desc });
  assert.equal(
    admit(recordOf(withContentDescriptions(original, inherited), "measurements")).state,
    "absent",
  );
  assert.throws(() =>
    withContentDescriptions(
      { contentData: [{ contentName: "measurements", ...item, contentDescription: null }] },
      {},
    ),
  );
  assert.throws(
    () => withContentDescriptions({ contentData: { measurements: { ...item } } }, {}),
    "the name-keyed map is no collection",
  );
  assert.throws(
    () => withContentDescriptions({ contentData: [{ contentName: "bad|name", ...item }] }, {}),
    "a record named outside the grammar",
  );
});

test("publisher describes the last whole record for a repeated name, and nothing merges", () => {
  const original = {
    contentData: [
      { contentName: "measurements", ...item, contentType: "text/html", extra: "first" },
      { contentName: "measurements", ...item },
    ],
  };
  const result = withContentDescriptions(original, { measurements: desc });
  assert.equal(result.contentData.length, 1);
  assert.equal(recordOf(result, "measurements").contentType, "application/json");
  assert.equal(Object.hasOwn(recordOf(result, "measurements"), "extra"), false);
});

test("trusted JSON and NDJSON handlers validate payloads after explicit handoff policy", () => {
  const handlers = new Map([
    [
      schema,
      ({ contentType, bytes }) => {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        const rows =
          contentType === "application/x-ndjson"
            ? text
                .trim()
                .split("\n")
                .map((line) => JSON.parse(line))
            : JSON.parse(text);
        if (!Array.isArray(rows) || rows.some((row) => typeof row.celsius !== "number"))
          throw new Error("Invalid observations");
        return rows.map((row) => row.celsius);
      },
    ],
  ]);
  for (const [contentType, text] of [
    ["application/json", '[{"celsius":12}]'],
    ["application/x-ndjson", '{"celsius":12}\n'],
  ]) {
    const opened = handoffFor(
      "measurements",
      { ...item, contentType, contentDescription: desc },
      new TextEncoder().encode(text),
    );
    const selected = select(opened, policy);
    assert.equal(selected.state, "ready");
    assert.deepEqual(handlers.get(selected.schema)(opened), [12]);
    assert.equal(opened.contentType, contentType);
  }
  const badData = handoffFor(
    "measurements",
    { ...item, contentDescription: desc },
    new TextEncoder().encode("[{}]"),
  );
  assert.equal(select(badData, policy).state, "ready");
  assert.throws(() => handlers.get(schema)(badData), /Invalid observations/);
  for (const value of [
    null,
    { version: "2" },
    { version: "1", description: "only text" },
    { ...desc, schema: "urn:unknown" },
  ]) {
    const opened = handoffFor(
      "measurements",
      { ...item, contentDescription: value },
      new Uint8Array(),
    );
    assert.equal(select(opened, policy).state, "refused");
    assert.equal(select(opened, { requiresSchema: false, supportedSchemas: [] }).state, "ready");
  }
  const html = handoffFor(
    "html",
    { contentType: "text/html" },
    new TextEncoder().encode("<p>Hi</p>"),
  );
  assert.equal(html.description.state, "absent");
  assert.equal(select(html, { requiresSchema: false, supportedSchemas: [] }).state, "ready");
  assert.equal(select(html, policy).state, "refused");
  assert.throws(() => handoffFor("html", {}, new Uint8Array()), /contentType/);
  // The live record is not the captured view: it carries no contentName.
  assert.throws(() => handoff({ contentType: "text/html" }, admit({}), new Uint8Array()));
  assert.throws(() =>
    handoff({ contentName: "html", contentType: "text/html" }, desc, new Uint8Array()),
  );
});

test("real JSON and HTML carrier readers and baseline DcaData preserve descriptions", () => {
  const opaqueSchema = "measurements/temperature/°C/😀";
  const carrierDescription = { ...desc, schema: opaqueSchema };
  const dcaData = withContentDescriptions(
    {
      version: "1",
      resourceJWT: "unused",
      contentData: [{ contentName: "measurements", ...item }],
      issuerData: [
        { issuerName: "issuer", unlockUrl: "https://issuer.test/unlock", keyId: "key", sealed: {} },
      ],
    },
    { measurements: carrierDescription },
  );
  const render = { dcaData, sealedContent: {} };
  const jsonReader = new JsonDeliveryReader(writeJsonDelivery(render), {
    publisherOrigin: "https://publisher.test",
  });
  // The HTML reader's documented tree port: actual emitted script texts, no DOM dependency.
  const markup = writeMarkupDelivery(render);
  const scripts = [
    ...markup.matchAll(/<script type="application\/json" class="([^"]+)">([\s\S]*?)<\/script>/g),
  ];
  const markupReader = new MarkupDeliveryReader({
    location: { origin: "https://publisher.test" },
    querySelectorAll(selector) {
      return scripts
        .filter((match) => selector.endsWith("." + match[1]))
        .map((match) => ({
          tagName: "SCRIPT",
          getAttribute: () => "application/json",
          textContent: match[2],
        }));
    },
  });
  for (const reader of [jsonReader, markupReader]) {
    const baseline = new DcaData(reader.dcaData, { publisherOrigin: reader.publisherOrigin });
    assert.deepEqual(
      baseline.contentDataFor("measurements").contentDescription,
      carrierDescription,
    );
    const record = baseline.contentDataFor("measurements");
    assert.equal(admit(record).state, "available");
    const opened = handoffFor("measurements", record, new TextEncoder().encode("[]"));
    assert.deepEqual(select(opened, { requiresSchema: true, supportedSchemas: [opaqueSchema] }), {
      state: "ready",
      schema: opaqueSchema,
    });
    assert.deepEqual(select(opened, policy), { state: "refused", schema: null });
    recordOf(reader.dcaData, "measurements").contentDescription = { version: "2", newField: true };
    assert.equal(admit(baseline.contentDataFor("measurements")).state, "unsupported");
  }
});

test("handoff reports the contentType captured before the await, not the live record's", async () => {
  const delivery = {
    version: "1",
    resourceJWT: "eyJhbGciOiJFUzI1NiJ9.eyJyZW5kZXJJZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.c2ln",
    contentData: [{ contentName: "measurements", ...item, contentDescription: desc }],
    issuerData: [
      { issuerName: "issuer", unlockUrl: "https://issuer.test/unlock", keyId: "key", sealed: {} },
    ],
  };
  const page = new DcaData(delivery);
  const captured = page.contentItemFor("measurements");
  const description = admit(page.contentDataFor("measurements"));
  await Promise.resolve();
  // A page script edits the live record while the client awaits the key.
  delivery.contentData[0].contentType = "text/html";
  delivery.contentData[0].contentDescription = { version: "2" };
  const opened = handoff(captured, description, new Uint8Array([1]));
  assert.equal(opened.contentName, "measurements");
  assert.equal(opened.contentType, "application/json");
  assert.equal(opened.description.state, "available");
  assert.deepEqual(opened.description.description, desc);
});

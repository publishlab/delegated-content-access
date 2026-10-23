// @ts-check
import test from "node:test";
import assert from "node:assert/strict";

import { createFetchTransport } from "../../adapter-client/fetchTransport.js";
import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import { world, PUB, BODYTEXT } from "../../test-lib/fixtures/wire-policy-world.js";
import { ISSUER_NAME, UNLOCK_URL } from "../../demo/scenarios/fixtures.js";
import { issuerBlockOf } from "../../test-lib/helpers/inspect.js";

const context = { origin: PUB };
const json = (value) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

test("Fetch port sends one no-store JSON POST with explicit browser policy", async () => {
  const seen = [];
  const transport = createFetchTransport({
    fetch: async (url, init) => {
      seen.push({ url, init });
      return json({ keys: {} });
    },
  });
  assert.deepEqual(await transport.post(UNLOCK_URL, { a: 1 }, context), {
    status: 200,
    contentType: "application/json; charset=utf-8",
    body: { keys: {} },
  });
  assert.deepEqual(seen, [
    {
      url: UNLOCK_URL,
      init: {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        credentials: "omit",
        redirect: "manual",
        cache: "no-store",
        body: '{"a":1}',
      },
    },
  ]);
  const included = createFetchTransport({
    credentials: "include",
    fetch: async (_url, init) => {
      assert.equal(init?.credentials, "include");
      return json({});
    },
  });
  await included.post(UNLOCK_URL, {}, context);
});

test("request serialization and untagged programming failures remain visible", async () => {
  let calls = 0;
  const transport = createFetchTransport({
    fetch: async () => {
      calls++;
      return json({});
    },
  });
  const circular = {};
  circular.self = circular;
  await assert.rejects(transport.post(UNLOCK_URL, circular, context), TypeError);
  assert.equal(calls, 0);
  const fault = new Error("application bug");
  const faulty = createFetchTransport({
    fetch: async () => {
      throw fault;
    },
  });
  await assert.rejects(faulty.post(UNLOCK_URL, {}, context), (error) => error === fault);
});

test("unseen Fetch outcomes retain their cause, including opaque redirects", async () => {
  for (const cause of [new TypeError("network failed"), new DOMException("abort", "AbortError")]) {
    const transport = createFetchTransport({
      fetch: async () => {
        throw cause;
      },
    });
    await assert.rejects(transport.post(UNLOCK_URL, {}, context), (error) => {
      assert.equal(error.code, "indeterminate_transport");
      assert.equal(error.cause, cause);
      return true;
    });
  }
  for (const type of ["opaque", "opaqueredirect"]) {
    const transport = createFetchTransport({ fetch: async () => ({ type, status: 0 }) });
    await assert.rejects(transport.post(UNLOCK_URL, {}, context), {
      code: "indeterminate_transport",
    });
  }
});

test("explicit whole-acquisition cancellation escapes route classification", async () => {
  const controller = new AbortController();
  const cause = new DOMException("cancelled", "AbortError");
  const transport = createFetchTransport({
    signal: controller.signal,
    fetch: async () => {
      controller.abort(cause);
      throw cause;
    },
  });
  await assert.rejects(transport.post(UNLOCK_URL, {}, context), (error) => error === cause);
  let calls = 0;
  const stopped = createFetchTransport({
    signal: controller.signal,
    fetch: async () => {
      calls++;
      return json({});
    },
  });
  await assert.rejects(stopped.post(UNLOCK_URL, {}, context), (error) => error === cause);
  assert.equal(calls, 0);
});

test("known 403 and 503 responses cancel unread diagnostics without losing status", async () => {
  for (const status of [403, 503]) {
    let read = false;
    let cancelled = false;
    const body = new ReadableStream(
      {
        pull(controller) {
          read = true;
          controller.error(new TypeError("unreadable diagnostics"));
        },
        cancel() {
          cancelled = true;
          throw new TypeError("diagnostic cancellation failed");
        },
      },
      { highWaterMark: 0 },
    );
    const response = {
      status,
      type: "basic",
      body,
      headers: new Headers({ "content-type": "text/plain" }),
    };
    const transport = createFetchTransport({ fetch: async () => response });
    assert.deepEqual(await transport.post(UNLOCK_URL, {}, context), {
      status,
      contentType: "text/plain",
      body: undefined,
    });
    assert.equal(read, false);
    assert.equal(cancelled, true);
  }
});

test("200 body decoding accepts only strict UTF-8 and one initial BOM", async () => {
  const encoder = new TextEncoder();
  const bytes = [
    [Uint8Array.from([0xef, 0xbb, 0xbf, ...encoder.encode('{"ok":true}')]), { ok: true }],
    [Uint8Array.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, ...encoder.encode("{}")]), undefined],
    [Uint8Array.from([0x20, 0xef, 0xbb, 0xbf, ...encoder.encode("{}")]), undefined],
    [Uint8Array.from([0xff, ...encoder.encode("{}")]), undefined],
  ];
  for (const [body, expected] of bytes) {
    const transport = createFetchTransport({
      fetch: async () => new Response(body, { status: 200 }),
    });
    assert.deepEqual((await transport.post(UNLOCK_URL, {}, context)).body, expected);
  }
  const unreadable = createFetchTransport({
    fetch: async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new TypeError("body read failed"));
          },
        }),
        { status: 200 },
      ),
  });
  assert.deepEqual(await unreadable.post(UNLOCK_URL, {}, context), {
    status: 200,
    contentType: null,
    body: undefined,
  });
});

test("an explicit whole-acquisition abort during a known 200 body read still stops", async () => {
  const controller = new AbortController();
  const cause = new DOMException("cancelled", "AbortError");
  const transport = createFetchTransport({
    signal: controller.signal,
    fetch: async () =>
      new Response(
        new ReadableStream({
          pull(stream) {
            controller.abort(cause);
            stream.error(cause);
          },
        }),
        { status: 200 },
      ),
  });
  await assert.rejects(transport.post(UNLOCK_URL, {}, context), (error) => error === cause);
});

test("response cap rejects oversize streamed data before accumulating it", async () => {
  let cancelled = false;
  const transport = createFetchTransport({
    maxResponseBytes: 3,
    fetch: async () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            controller.enqueue(Uint8Array.from([1, 2, 3, 4]));
          },
          cancel() {
            cancelled = true;
          },
        }),
        { status: 200 },
      ),
  });
  assert.equal((await transport.post(UNLOCK_URL, {}, context)).body, undefined);
  assert.equal(cancelled, true);
  assert.throws(() => createFetchTransport({ maxResponseBytes: 0 }), { code: "bad_config" });
});

test("real Fetch rejection suppresses conditional B but visits independent C", async () => {
  const fixture = await world();
  const { dcaData, sealedContent } = await fixture.render({ periodKeySupply: null });
  const names = [ISSUER_NAME, "backup_issuer", "independent_issuer"];
  for (const name of names.slice(1))
    dcaData.issuerData.push({ ...structuredClone(issuerBlockOf(dcaData)), issuerName: name });
  const sent = [];
  const cause = new TypeError("network failed after possible POST");
  const transport = createFetchTransport({
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      sent.push(request.issuerName);
      if (request.issuerName === ISSUER_NAME) throw cause;
      return new Response("denied", { status: 403, headers: { "content-type": "text/plain" } });
    },
  });
  const client = createDeliveryClient({
    unlockUrl: "https://issuer.example/unlock",
    reader: { dcaData, publisherOrigin: PUB, extract: (name) => sealedContent[name] ?? null },
    issuerName: ISSUER_NAME,
    transport,
  });
  const result = await client.unlockRoutes(
    [BODYTEXT.name],
    names.map((issuerName, index) => ({
      issuerName,
      unlockUrl: UNLOCK_URL,
      ...(index === 0 ? { retryOperational: true } : {}),
      ...(index === 2 ? { independent: true } : {}),
    })),
  );
  assert.deepEqual(sent, [ISSUER_NAME, names[2]]);
  assert.deepEqual(result.attempts, [
    { issuerName: ISSUER_NAME, outcome: "indeterminate" },
    { issuerName: names[2], status: 403, outcome: "answered" },
  ]);
});

test("whole-acquisition abort stops the route walk before independent routes", async () => {
  const fixture = await world();
  const { dcaData, sealedContent } = await fixture.render({ periodKeySupply: null });
  dcaData.issuerData.push({
    ...structuredClone(issuerBlockOf(dcaData)),
    issuerName: "independent_issuer",
  });
  const controller = new AbortController();
  const cause = new DOMException("cancelled", "AbortError");
  let calls = 0;
  const client = createDeliveryClient({
    unlockUrl: "https://issuer.example/unlock",
    reader: { dcaData, publisherOrigin: PUB, extract: (name) => sealedContent[name] ?? null },
    issuerName: ISSUER_NAME,
    transport: createFetchTransport({
      signal: controller.signal,
      fetch: async () => {
        calls++;
        controller.abort(cause);
        throw cause;
      },
    }),
  });
  await assert.rejects(
    client.unlockRoutes(
      [BODYTEXT.name],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
        { issuerName: "independent_issuer", unlockUrl: UNLOCK_URL, independent: true },
      ],
    ),
    (error) => error === cause,
  );
  assert.equal(calls, 1);
});

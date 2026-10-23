import test from "node:test";
import assert from "node:assert/strict";
import { createRecipientGrantBrowserHost } from "../browserHost.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { world, response, SELECTION, REFERENCE, URL, NOW } from "./client-fixture.js";

async function fixture(overrides = {}) {
  const w = await world();
  const { root } = await w.render();
  const replacements = [];
  const config = {
    root,
    issuer: { ...SELECTION },
    fetch: w.fetch,
    location: { href: `https://publisher.example/article?keep=1&share=${REFERENCE}#body` },
    history: { state: { navigation: 1 }, replaceState: (...args) => replacements.push(args) },
    retainUntil: NOW + 60_000,
    now: () => NOW,
    ...overrides,
  };
  return { w, config, replacements };
}

test("percent-encoded opaque query credentials preserve literal plus, slash and padding", async () => {
  const reference = "ab+cd/ef==";
  const sent = [];
  const { config, replacements } = await fixture({
    location: { href: `https://publisher.example/article?share=${encodeURIComponent(reference)}` },
    fetch: async (_url, init) => {
      sent.push(init.headers.Authorization);
      return response({ error: "denied" }, 401);
    },
  });
  const host = createRecipientGrantBrowserHost(config);
  assert.equal((await host.unlockUnresolved(["body"])).status, 401);
  assert.deepEqual(sent, [`Bearer ${reference}`]);
  assert.equal(new globalThis.URL(replacements[0][2]).searchParams.has("share"), false);
  assert.throws(
    () =>
      createRecipientGrantBrowserHost({
        ...config,
        location: { href: "https://publisher.example/article?share=ab+cd" },
      }),
    { code: "bad_config" },
  );
});

test("query capture cleans only its carrier and opens unresolved original bytes at the trusted route", async () => {
  const { w, config, replacements } = await fixture();
  config.location.href = config.location.href.replace(
    "#body",
    "&issuer=https://attacker.example#body",
  );
  const host = createRecipientGrantBrowserHost(config);
  config.issuer.unlockUrl = "https://attacker.example/unlock";
  assert.equal(replacements.length, 1);
  const clean = new globalThis.URL(replacements[0][2]);
  assert.equal(clean.searchParams.has("share"), false);
  assert.equal(clean.searchParams.get("keep"), "1");
  assert.deepEqual(replacements[0][0], { navigation: 1 });
  assert.equal((await host.unlockUnresolved(["body", "extra"], ["extra"])).status, 200);
  assert.equal(
    new TextDecoder().decode((await host.openLocal("body")).bytes),
    "first article text",
  );
  assert.equal(w.calls.length, 1);
  assert.equal(w.calls[0].url, URL);
  assert.deepEqual(
    w.calls[0].request.sealed.contentKeys.map((/** @type {any} */ record) => record.contentName),
    ["body"],
  );
  assert.equal(w.calls[0].init.headers.Authorization, `Bearer ${REFERENCE}`);
  assert.equal(w.calls[0].init.credentials, "omit");
});

test("absent carrier leaves access alone; opened names cause no grant attempt", async () => {
  for (const href of [
    "https://publisher.example/article",
    `https://publisher.example/article?share=${REFERENCE}`,
  ]) {
    const { w, config, replacements } = await fixture({ location: { href } });
    const host = createRecipientGrantBrowserHost(config);
    assert.equal(await host.unlockUnresolved(["body"], ["body"]), null);
    if (!href.includes("share=")) {
      assert.equal(await host.unlockUnresolved(["body"]), null);
      assert.equal(replacements.length, 0);
    }
    assert.equal(w.calls.length, 0);
  }
});

test("duplicate, empty, malformed and oversized carriers fail without request or token diagnostics", async () => {
  const { w, config, replacements } = await fixture();
  for (const query of [
    `share=${REFERENCE}&share=${REFERENCE}`,
    "share=",
    "share=secret%20two",
    "share=secret%0A",
    "share=%ZZsecret",
    `share=${"x".repeat(8193)}`,
  ]) {
    assert.throws(
      () =>
        createRecipientGrantBrowserHost({
          ...config,
          location: { href: `https://publisher.example/article?${query}` },
        }),
      (error) =>
        error.code === "bad_config" &&
        !error.message.includes("secret") &&
        !error.message.includes(REFERENCE),
    );
  }
  assert.equal(w.calls.length, 0);
  assert.equal(replacements.length, 0);
});

test("custom query carrier and replacement reader use only their chosen input", async () => {
  const { w, config, replacements } = await fixture({
    queryName: "gift",
    location: { href: `https://publisher.example/article?gift=${REFERENCE}&share=ignored` },
  });
  const custom = createRecipientGrantBrowserHost(config);
  assert.equal((await custom.unlockUnresolved(["body"])).status, 200);
  assert.equal(new globalThis.URL(replacements[0][2]).searchParams.get("share"), "ignored");
  let reads = 0;
  const replaced = createRecipientGrantBrowserHost({
    ...config,
    location: { href: "not a URL" },
    readGrant: () => {
      reads++;
      return REFERENCE;
    },
  });
  assert.equal((await replaced.unlockUnresolved(["body"])).status, 200);
  assert.equal(reads, 1);
  assert.equal(replacements.length, 1, "replacement reader owns cleanup for its carrier");
  const absent = createRecipientGrantBrowserHost({ ...config, readGrant: () => null });
  assert.equal(await absent.unlockUnresolved(["body"]), null);
  assert.equal(w.calls.length, 2);
});

test("direct injection needs no URL and retained grant has explicit host expiry and clearing", async () => {
  const { w, config } = await fixture();
  const { location, history, ...direct } = config;
  let instant = 10;
  const host = createRecipientGrantBrowserHost({
    ...direct,
    grantReference: REFERENCE,
    retainUntil: 20,
    now: () => instant,
  });
  assert.equal((await host.unlockUnresolved(["body"])).status, 200);
  instant = 20;
  assert.equal(await host.unlockUnresolved(["body"]), null);
  await assert.rejects(host.openLocal("body"), { code: "bad_config" });
  assert.equal(w.calls.length, 1);
  const cleared = createRecipientGrantBrowserHost({ ...direct, grantReference: REFERENCE });
  cleared.clearGrant();
  assert.equal(await cleared.unlockUnresolved(["body"]), null);
});

test("a captured grant requires a finite trusted retention deadline", async () => {
  const { config } = await fixture();
  const { retainUntil, ...unbounded } = config;
  assert.throws(() => createRecipientGrantBrowserHost(unbounded), { code: "bad_config" });
  let reads = 0;
  assert.throws(
    () =>
      createRecipientGrantBrowserHost({
        ...unbounded,
        readGrant: () => {
          reads += 1;
          return REFERENCE;
        },
      }),
    { code: "bad_config" },
  );
  assert.equal(reads, 0, "the deadline is admitted before consulting a carrier");
  const absent = createRecipientGrantBrowserHost({
    ...unbounded,
    retainUntil: NOW + 60_000,
    location: { href: "https://publisher.example/article" },
  });
  assert.equal(await absent.unlockUnresolved(["body"]), null);
});

test("an unverified compact exp can only shorten local retention", async () => {
  const compact = (exp) =>
    [
      base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "dca-share+jwt" }))),
      base64urlEncode(utf8Encode(JSON.stringify({ exp }))),
      "c2ln",
    ].join(".");
  const { w, config, replacements } = await fixture();
  let instant = NOW;
  const early = createRecipientGrantBrowserHost({
    ...config,
    location: {
      href: `https://publisher.example/article?share=${compact(Math.floor((NOW + 1000) / 1000))}`,
    },
    retainUntil: NOW + 60_000,
    now: () => instant,
  });
  assert.equal(replacements.length, 1, "the URL is cleaned even when exp ends retention");
  instant = NOW + 1000;
  assert.equal(await early.unlockUnresolved(["body"]), null);
  assert.equal(w.calls.length, 0);

  const late = createRecipientGrantBrowserHost({
    ...config,
    grantReference: compact(Math.floor((NOW + 60_000) / 1000)),
    retainUntil: NOW + 1000,
    now: () => instant,
  });
  assert.equal(await late.unlockUnresolved(["body"]), null);
  assert.equal(w.calls.length, 0, "a later token exp cannot extend the trusted deadline");
});

test("transport error and issuer refusal remain distinct and trigger no automatic retry", async () => {
  const { config } = await fixture();
  let calls = 0;
  const refusal = createRecipientGrantBrowserHost({
    ...config,
    fetch: async () => {
      calls++;
      return response({}, 403);
    },
  });
  assert.deepEqual(await refusal.unlockUnresolved(["body"]), {
    status: 403,
    body: null,
    application: null,
  });
  assert.equal(calls, 1);
  const failure = new TypeError("network unavailable");
  const failed = createRecipientGrantBrowserHost({
    ...config,
    fetch: async () => {
      calls++;
      throw failure;
    },
  });
  await assert.rejects(failed.unlockUnresolved(["body"]), (error) => error === failure);
  assert.equal(calls, 2);
});

test("clearing or expiring a pending unlock retires its result", async () => {
  const { w, config } = await fixture();
  for (const retirement of ["clear", "expiry", "invalid-clock"]) {
    let instant = 10;
    let release;
    let started;
    const entered = new Promise((resolve) => {
      started = resolve;
    });
    const deferred = new Promise((resolve) => {
      release = resolve;
    });
    const host = createRecipientGrantBrowserHost({
      ...config,
      retainUntil: 20,
      now: () => instant,
      fetch: async (url, init) => {
        started();
        await deferred;
        return w.fetch(url, init);
      },
    });
    const pending = host.unlockUnresolved(["body"]);
    await entered;
    if (retirement === "clear") host.clearGrant();
    else instant = retirement === "expiry" ? 20 : NaN;
    release();
    await assert.rejects(pending, { code: "bad_config" });
    await assert.rejects(host.openLocal("body"), { code: "bad_config" });
  }
});

test("clearing or expiry during opening retires pending plaintext", async () => {
  const { config } = await fixture();
  for (const retirement of ["clear", "expiry"]) {
    let instant = 10;
    const host = createRecipientGrantBrowserHost({
      ...config,
      retainUntil: 20,
      now: () => instant,
    });
    await host.unlockUnresolved(["body"]);
    const pending = host.openLocal("body");
    // Retire before asynchronous WebCrypto decryption returns its plaintext.
    if (retirement === "clear") host.clearGrant();
    else instant = 20;
    await assert.rejects(pending, { code: "bad_config" });
  }
});

test("nonfinite retention clock fails closed before sending a grant", async () => {
  const { w, config } = await fixture();
  const host = createRecipientGrantBrowserHost({ ...config, retainUntil: 20, now: () => Infinity });
  await assert.rejects(host.unlockUnresolved(["body"]), { code: "bad_config" });
  assert.equal(w.calls.length, 0);
});

test("a throwing retention clock permanently retires the captured grant", async () => {
  const { w, config } = await fixture();
  let broken = false;
  const host = createRecipientGrantBrowserHost({
    ...config,
    now() {
      if (broken) throw new Error("clock unavailable");
      return NOW;
    },
  });
  broken = true;
  await assert.rejects(host.unlockUnresolved(["body"]), { code: "bad_config" });
  assert.equal(w.calls.length, 0);
  broken = false;
  assert.equal(await host.unlockUnresolved(["body"]), null);
  assert.equal(w.calls.length, 0, "restoring the clock does not restore the retired credential");
});

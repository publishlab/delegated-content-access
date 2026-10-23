import test from "node:test";
import assert from "node:assert/strict";
import { world, response, client, SELECTION, URL, REFERENCE } from "./client-fixture.js";

for (const [description, route] of [
  [
    "another issuer",
    { issuerName: "other_issuer", unlockUrl: "https://other-issuer.example/unlock" },
  ],
  [
    "the same issuer at a changed URL",
    { issuerName: SELECTION.issuerName, unlockUrl: "https://other-issuer.example/unlock" },
  ],
  ["a changed issuer at the same URL", { issuerName: "other_issuer", unlockUrl: URL }],
]) {
  test(`recipient route walks to ${description} are rejected before any Fetch`, async () => {
    const w = await world();
    const { root } = await w.render();
    const attempts = [];
    const c = client(root, async (url, init) => {
      attempts.push({ url, init });
      return response({}, 503);
    });
    await assert.rejects(
      c.unlockRoutes(
        ["body"],
        [{ issuerName: SELECTION.issuerName, unlockUrl: URL, retryOperational: true }, route],
      ),
      { code: "bad_config" },
    );
    assert.deepEqual(attempts, [], "no bearer-bearing request is sent on a route walk");
    assert.equal(await c.resolver.contentKeyFor(c.dcaData, "body"), null);
  });
}

test("selected-endpoint unlock and open still use the snapshotted recipient selection", async () => {
  const w = await world();
  const { root } = await w.render();
  const selection = { ...SELECTION };
  const c = client(root, w.fetch, { issuer: selection });
  selection.issuerName = "other_issuer";
  selection.unlockUrl = "https://other-issuer.example/unlock";
  assert.equal((await c.unlock(["body"])).status, 200);
  assert.equal(new TextDecoder().decode((await c.open("body")).bytes), "first article text");
  assert.equal(w.calls.length, 1, "open reuses the selected grant's admitted item key");
  assert.equal(w.calls[0].url, URL);
  assert.equal(w.calls[0].request.issuerName, SELECTION.issuerName);
  assert.equal(w.calls[0].init.headers.Authorization, `Bearer ${REFERENCE}`);
});

test("a recipient response with reusable results or chain geometry is refused before any item is retained or opened", async () => {
  const w = await world();
  const { root } = await w.render();
  let valid;
  const capture = client(root, async (url, init) => {
    const answer = await w.fetch(url, init);
    valid = await answer.json();
    return response(valid);
  });
  await capture.unlock(["body"]);
  for (const addition of [
    {
      keys: {
        ...valid.keys,
        periodKeys: [{ accessGroup: "premium", period: "260929T1200", key: "key" }],
      },
    },
    {
      keys: {
        ...valid.keys,
        chainKeys: [{ accessGroup: "premium", cutoff: "260929T1200", key: "key" }],
      },
    },
    { keys: { ...valid.keys, periodKeys: [], contentGroupKeys: [{ key: "ignored" }] } },
    { keys: { ...valid.keys, chainKeys: null } },
    { periodGeometry: {} },
    { chainGeometry: {} },
  ]) {
    let opens = 0;
    const c = client(root, async () => response({ ...valid, ...addition }), {
      clientBoundKeyCapability: {
        publicKey: { kty: "EC", crv: "P-256" },
        openDeliveredKeys: async () => {
          opens++;
          throw Error("must not open");
        },
      },
      acceptDirectFallback: true,
      acceptDirectResponse: true,
    });
    await assert.rejects(c.unlock(["body"]), { code: "bad_response" });
    assert.equal(opens, 0);
    assert.equal(await c.resolver.contentKeyFor(c.dcaData, "body"), null);
  }
});

test("unselected proposal result members are ignored without adding a capability", async () => {
  const w = await world();
  const { root } = await w.render();
  const c = client(root, async (url, init) => {
    const answer = await w.fetch(url, init);
    const body = await answer.json();
    body.keys.contentGroupKeys = [{ accessGroup: "premium", key: "ignored" }];
    return response(body);
  });
  const result = await c.unlock(["body"]);
  assert.equal(result.application.accepted, 1);
  assert.equal(new TextDecoder().decode((await c.open("body")).bytes), "first article text");
  assert.equal(await c.resolver.contentKeyFor(c.dcaData, "extra"), null);
});

test("ordinary response association excludes an unpresented item", async () => {
  const w = await world();
  const { root } = await w.render();
  const c = client(root, async (url, init) => {
    const answer = await w.fetch(url, init);
    const body = await answer.json();
    const { key } = body.keys.contentKeys.find(
      (/** @type {any} */ record) => record.contentName === "body",
    );
    body.keys.contentKeys.push({ contentName: "extra", key });
    return response(body);
  });
  const result = await c.unlock(["body"]);
  assert.equal(result.application.accepted, 1);
  assert.ok(result.application.issues.some((issue) => issue.code === "unsolicited_coordinate"));
  assert.equal(await c.resolver.contentKeyFor(c.dcaData, "extra"), null);
});

test("failed grants and redirects end the attempt without another issuer or credential replay", async () => {
  const w = await world();
  const { root } = await w.render();
  for (const status of [401, 403, 302, 307]) {
    let calls = 0;
    const c = client(root, async () => {
      calls++;
      return response({ keys: { contentKeys: [] } }, status);
    });
    assert.deepEqual(await c.unlock(["body"]), { status, body: null, application: null });
    assert.equal(calls, 1);
    assert.equal(await c.resolver.contentKeyFor(c.dcaData, "body"), null);
  }
  const c = client(root, async () => {
    throw new TypeError("Fetch redirect rejected");
  });
  await assert.rejects(c.unlock(["body"]), /Fetch redirect rejected/);
});

test("trusted endpoint and resource selection cannot be replaced by delivery or extra options", async () => {
  const w = await world();
  const { root } = await w.render();
  for (const selection of [
    { ...SELECTION, resourceId: "another-article" },
    { ...SELECTION, publisherOrigin: "https://other-publisher.example" },
  ]) {
    assert.throws(() => client(root, w.fetch, { issuer: selection }), { code: "bad_page" });
  }
  for (const unlockUrl of [
    undefined,
    "",
    "/unlock",
    "http://localhost/unlock",
    "https://reader@issuer.example/unlock",
    `${URL}#grant`,
  ]) {
    assert.throws(() => client(root, w.fetch, { issuer: { ...SELECTION, unlockUrl } }), {
      code: "bad_config",
    });
  }
  for (const option of [
    "unlockUrl",
    "transport",
    "relayPeriodKeys",
    "chainCache",
    "requestBuilderFactory",
    "resolverFactory",
    "cache",
  ]) {
    assert.throws(() => client(root, w.fetch, { [option]: true }), { code: "unsupported_option" });
  }
  assert.equal(w.calls.length, 0);
});

test("bearer reference must be one nonempty HTTP field value and configuration is snapshotted", async () => {
  const w = await world();
  const { root } = await w.render();
  for (const grantReference of [
    "",
    null,
    undefined,
    "two tokens",
    "a,b",
    "a:b",
    "a=b",
    "a\n",
    "a\r",
    "a\u2028",
    "a\u2029",
    "a\r\nAuthorization: Bearer b",
    "a\t",
    "a\x7f",
  ]) {
    assert.throws(() => client(root, w.fetch, { grantReference }), { code: "bad_config" });
  }
  const issuer = { ...SELECTION };
  const c = client(root, w.fetch, { issuer });
  issuer.unlockUrl = "https://other.example/unlock";
  issuer.resourceId = "other-resource";
  assert.equal((await c.unlock(["body"])).status, 200);
  assert.equal(w.calls[0].url, URL);
});

test("malformed successful bodies cannot supply a recipient result", async () => {
  const w = await world();
  const { root } = await w.render();
  for (const answer of [
    response([], 200),
    response({}, 200, "text/html"),
    {
      status: 200,
      headers: { get: () => "application/json" },
      json: async () => {
        throw Error("bad json");
      },
    },
    { ...response({}), redirected: true },
  ]) {
    const c = client(root, async () => answer);
    await assert.rejects(c.unlock(["body"]), { code: "bad_response" });
    assert.equal(await c.resolver.contentKeyFor(c.dcaData, "body"), null);
  }
});

test("recipient composition recursively resets item grants and fences pending acquisition", async () => {
  const w = await world();
  const { root } = await w.render();
  let enter, release;
  const entered = new Promise((resolve) => {
    enter = resolve;
  });
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let delay = false;
  const c = client(root, async (...args) => {
    const answer = await w.fetch(...args);
    if (delay) {
      delay = false;
      enter();
      await gate;
    }
    return answer;
  });
  await c.unlock(["body"]);
  await c.clearAccessDecisions();
  assert.equal(new TextDecoder().decode((await c.openLocal("body")).bytes), "first article text");
  await c.clearReaderContext();
  await assert.rejects(c.openLocal("body"), { code: "no_key" });
  delay = true;
  const old = c.unlock(["body"]);
  const retired = assert.rejects(old, { code: "context_retired" });
  await entered;
  await c.clearReaderContext();
  release();
  await retired;
  await assert.rejects(c.openLocal("body"), { code: "no_key" });
  await c.unlock(["body"]);
  assert.equal(new TextDecoder().decode((await c.openLocal("body")).bytes), "first article text");
});

for (const wrongFirst of [true, false]) {
  test(`recipient client authenticates rival content keys, wrong first: ${wrongFirst}`, async () => {
    const w = await world();
    const { root } = await w.render();
    const c = client(root, async (url, init) => {
      const answer = await w.fetch(url, init);
      const body = await answer.json();
      const wrong = { contentName: "body", key: Buffer.alloc(16, 99).toString("base64url") };
      body.keys.contentKeys = wrongFirst
        ? [wrong, ...body.keys.contentKeys]
        : [...body.keys.contentKeys, wrong];
      return response(body);
    });
    assert.equal((await c.unlock(["body"])).status, 200);
    assert.equal(new TextDecoder().decode((await c.open("body")).bytes), "first article text");
    assert.equal(w.calls.length, 1);
  });
}

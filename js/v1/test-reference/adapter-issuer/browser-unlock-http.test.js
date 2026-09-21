// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { BrowserUnlockHttp } from "../../adapter-issuer/BrowserUnlockHttp.js";

const REGISTERED = "https://publisher.example";

function fixture(options = {}) {
  const calls = [];
  const admitted = options.admitted ?? true;
  const preflight = options.preflight ?? true;
  const originAdmission = {
    preflight(origin) {
      calls.push(["preflight", origin]);
      return preflight;
    },
    admit(origin, body, hostContext) {
      calls.push(["admit", origin, body, hostContext]);
      return admitted
        ? { kind: "admitted", context: { registration: "publisher-1" } }
        : {
            kind: "refused",
            response: { status: 403, body: { error: "wrong_origin" } },
            ...(options.cors ? { cors: true } : {}),
          };
    },
  };
  const adapter = new BrowserUnlockHttp({
    originAdmission,
    credentials: options.credentials,
    unlock(body, context) {
      calls.push(["unlock", body, context]);
      return {
        status: 200,
        headers: {
          "access-control-allow-origin": "*",
          "x-issuer": "reference",
        },
        body: { keys: {} },
      };
    },
  });
  return { adapter, calls };
}

describe("BrowserUnlockHttp", () => {
  test("requires its replaceable application seams and validates options", () => {
    for (const config of [
      undefined,
      {},
      { originAdmission: {}, unlock() {} },
      { originAdmission: { preflight() {}, admit() {} } },
      { originAdmission: { preflight() {}, admit() {} }, unlock() {}, credentials: "yes" },
    ]) {
      assert.throws(
        () => new BrowserUnlockHttp(/** @type {any} */ (config)),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  });

  test("answers an admitted preflight with exact, never wildcard, CORS headers", async () => {
    const { adapter, calls } = fixture({ credentials: true });
    const response = await adapter.handle({ method: "OPTIONS", origin: REGISTERED });

    assert.deepEqual(response, {
      status: 204,
      headers: {
        "access-control-allow-origin": REGISTERED,
        "access-control-allow-credentials": "true",
        "access-control-allow-methods": "POST",
        "access-control-allow-headers": "content-type",
        vary: "Origin",
      },
    });
    assert.deepEqual(calls, [["preflight", REGISTERED]]);
  });

  test("missing, null and refused origins reach no issuer operation", async () => {
    for (const origin of [undefined, null, "", "null"]) {
      const { adapter, calls } = fixture();
      const response = await adapter.handle({ method: "POST", origin, body: { request: true } });
      assert.equal(response.status, 403);
      assert.deepEqual(response.headers, { vary: "Origin" });
      assert.deepEqual(calls, []);
    }

    const { adapter, calls } = fixture({ admitted: false });
    const response = await adapter.handle({
      method: "POST",
      origin: "https://other.example",
      body: { request: true },
    });
    assert.deepEqual(response, {
      status: 403,
      headers: { vary: "Origin" },
      body: { error: "wrong_origin" },
    });
    assert.deepEqual(calls, [["admit", "https://other.example", { request: true }, undefined]]);
  });

  test("an Origin no browser could have sent is refused before admission", async () => {
    // The threat model's HTTP boundary: exactly one canonical value reaches
    // the comparison. A host that observed the header twice hands over both
    // values, and a comma-joined list is one string that names two origins;
    // neither is an origin, so neither reaches the body, the registration
    // lookup or the signed-origin comparison.
    for (const origin of [
      ["https://publisher.example", "https://other.example"],
      "https://publisher.example, https://other.example",
      "https://publisher.example https://other.example",
      "HTTPS://publisher.example",
      "https://publisher.example/",
      "https://publisher.example:443",
      "https://user@publisher.example",
      "https://publisher.example/path",
      "publisher.example",
      "ftp://publisher.example",
      "https://[2001:DB8::1]",
      "https://[fe80::1%25eth0]",
      "https://[2001:db8::1",
    ]) {
      const { adapter, calls } = fixture();
      const response = await adapter.handle({
        method: "POST",
        origin: /** @type {any} */ (origin),
        body: { request: true },
      });
      assert.equal(response.status, 403, `${JSON.stringify(origin)} is not one canonical origin`);
      assert.deepEqual(response.headers, { vary: "Origin" });
      assert.deepEqual(calls, [], `${JSON.stringify(origin)} reached admission`);

      const preflight = fixture();
      const answered = await preflight.adapter.handle({
        method: "OPTIONS",
        origin: /** @type {any} */ (origin),
      });
      assert.equal(answered.status, 403);
      assert.deepEqual(preflight.calls, []);
    }
  });

  test("an admitted POST passes one origin context and replaces wildcard response permission", async () => {
    const { adapter, calls } = fixture({ credentials: true });
    const body = { resourceJWT: "header.payload.signature" };
    const hostContext = { credential: "reader-token" };
    const response = await adapter.handle({
      method: "POST",
      origin: REGISTERED,
      body,
      hostContext,
    });

    assert.deepEqual(calls, [
      ["admit", REGISTERED, body, hostContext],
      [
        "unlock",
        body,
        {
          origin: REGISTERED,
          admission: { registration: "publisher-1" },
          hostContext,
        },
      ],
    ]);
    assert.deepEqual(response, {
      status: 200,
      headers: {
        "access-control-allow-origin": REGISTERED,
        "access-control-allow-credentials": "true",
        "cache-control": "no-store",
        "content-type": "application/json",
        "x-issuer": "reference",
        vary: "Origin",
      },
      body: { keys: {} },
    });
  });

  test("a handler's own spellings of the mandatory 200 headers collapse into one field each", async () => {
    // HTTP field names are case-insensitive, so a handler that wrote
    // `Content-Type: text/html` next to the adapter's lowercase
    // `content-type` would put two of the same field on the wire and let the
    // wrong one be read. The adapter removes every other spelling before it
    // writes its own.
    const adapter = new BrowserUnlockHttp({
      originAdmission: {
        preflight: () => true,
        admit: () => ({ kind: "admitted", context: {} }),
      },
      unlock: () => ({
        status: 200,
        headers: {
          "Content-Type": "text/html",
          "CACHE-CONTROL": "public, max-age=600",
          "Cache-Control": "max-age=60",
          "x-issuer": "reference",
        },
        body: { keys: {} },
      }),
    });

    const response = await adapter.handle({ method: "POST", origin: REGISTERED, body: {} });

    assert.deepEqual(Object.keys(response.headers ?? {}).sort(), [
      "access-control-allow-origin",
      "cache-control",
      "content-type",
      "vary",
      "x-issuer",
    ]);
    assert.equal(response.headers["content-type"], "application/json");
    assert.equal(response.headers["cache-control"], "no-store");
  });

  test("a bracketed IPv6 origin is admitted and reflected exactly", async () => {
    // The literal reaches admission as the bytes it arrived as and comes
    // back in the permission header unchanged. Nothing past the origin
    // grammar has a case for a host spelling.
    const literal = "https://[2001:db8::1]";
    const { adapter, calls } = fixture();
    const body = { resourceJWT: "header.payload.signature" };

    const response = await adapter.handle({ method: "POST", origin: literal, body });

    assert.equal(response.status, 200);
    assert.equal(response.headers["access-control-allow-origin"], literal);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.headers["content-type"], "application/json");
    assert.notEqual(response.headers["access-control-allow-origin"], "*");
    assert.deepEqual(calls[0], ["admit", literal, body, undefined]);
  });

  test("an admitted origin receives exact CORS on a later application refusal", async () => {
    const { adapter, calls } = fixture({ admitted: false, cors: true, credentials: true });
    const response = await adapter.handle({
      method: "POST",
      origin: REGISTERED,
      body: { request: true },
    });

    assert.deepEqual(response, {
      status: 403,
      headers: {
        "access-control-allow-origin": REGISTERED,
        "access-control-allow-credentials": "true",
        vary: "Origin",
      },
      body: { error: "wrong_origin" },
    });
    assert.deepEqual(calls, [["admit", REGISTERED, { request: true }, undefined]]);
  });

  test("refuses a preflight without invoking request admission or unlock", async () => {
    const { adapter, calls } = fixture({ preflight: false });
    const response = await adapter.handle({ method: "OPTIONS", origin: "https://other.example" });

    assert.equal(response.status, 403);
    assert.deepEqual(response.headers, { vary: "Origin" });
    assert.deepEqual(calls, [["preflight", "https://other.example"]]);
  });

  test("fails loudly when an injected seam returns no contract answer", async () => {
    const badAdmission = new BrowserUnlockHttp({
      originAdmission: {
        preflight() {
          return true;
        },
        admit() {},
      },
      unlock() {
        return { status: 200 };
      },
    });
    await assert.rejects(
      () => badAdmission.handle({ method: "POST", origin: REGISTERED, body: {} }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );

    const badUnlock = new BrowserUnlockHttp({
      originAdmission: {
        preflight() {
          return true;
        },
        admit() {
          return { kind: "admitted" };
        },
      },
      unlock() {
        return /** @type {any} */ ({ status: "200" });
      },
    });
    await assert.rejects(
      () => badUnlock.handle({ method: "POST", origin: REGISTERED, body: {} }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

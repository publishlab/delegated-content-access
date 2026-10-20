// @ts-check

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { BrowserUnlockHttp } from "../../adapter-issuer/BrowserUnlockHttp.js";
import { parseBearerAuthorization } from "../../adapter-issuer/parseBearerAuthorization.js";

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
  test("media type is checked before request admission and grants no CORS", async () => {
    const { adapter, calls } = fixture();
    for (const contentType of [undefined, null, "text/plain", "application/jsonp"]) {
      const response = await adapter.handle({
        method: "POST",
        origin: REGISTERED,
        contentType,
        body: "not json",
      });
      assert.equal(response.status, 415);
      assert.equal(response.headers["access-control-allow-origin"], undefined);
    }
    assert.deepEqual(calls, []);
    for (const contentType of ["APPLICATION/JSON", "application/json; charset=UTF-8"]) {
      const response = await adapter.handle({
        method: "POST",
        origin: REGISTERED,
        contentType,
        body: { request: true },
      });
      assert.equal(response.status, 200);
    }
  });

  test("bearer parsing accepts its consumer grammar and rejects extra syntax", () => {
    assert.equal(parseBearerAuthorization("bearer  abc+/=="), "abc+/==");
    assert.equal(parseBearerAuthorization("BEARER token"), "token");
    for (const value of ["Bearer\ttoken", "Bearer token extra", "Bearer a=b", ["Bearer token"]]) {
      assert.equal(parseBearerAuthorization(value), null);
    }
  });

  test("an unexpected post-gate failure still gives exact CORS and a visible 5xx", async () => {
    const adapter = new BrowserUnlockHttp({
      originAdmission: { preflight: () => true, admit: () => ({ kind: "admitted" }) },
      unlock: () => {
        throw new Error("host outage");
      },
    });
    const response = await adapter.handle({
      method: "POST",
      origin: REGISTERED,
      contentType: "application/json",
      body: {},
    });
    assert.equal(response.status, 500);
    assert.equal(response.headers["access-control-allow-origin"], REGISTERED);
    assert.equal(response.headers.vary, "Origin");
  });
  test("selected recipient bearer adds authorization preflight without ambient credentials", async () => {
    const calls = [];
    const adapter = new BrowserUnlockHttp({
      authorization: true,
      originAdmission: {
        preflight: () => true,
        admit: () => ({ kind: "admitted" }),
      },
      unlock(_body, context) {
        calls.push(context.authorization);
        return { status: 200, body: { keys: { contentKeys: {} } } };
      },
    });
    const preflight = await adapter.handle({ method: "OPTIONS", origin: REGISTERED });
    assert.equal(preflight.headers["access-control-allow-headers"], "content-type, authorization");
    assert.equal(preflight.headers["access-control-allow-credentials"], undefined);

    const missing = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
    });
    assert.equal(missing.status, 401);
    assert.equal(missing.headers["access-control-allow-origin"], undefined);
    const duplicate = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
      authorization: ["Bearer one", "Bearer two"],
    });
    assert.equal(duplicate.status, 401);
    assert.deepEqual(calls, []);

    const served = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
      authorization: "Bearer opaque-reference",
    });
    assert.equal(served.status, 200);
    assert.deepEqual(calls, ["Bearer opaque-reference"]);
  });

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
      const response = await adapter.handle({
        method: "POST",
        contentType: "application/json",
        origin,
        body: { request: true },
      });
      assert.equal(response.status, 403);
      assert.deepEqual(response.headers, { "cache-control": "no-store", vary: "Origin" });
      assert.deepEqual(calls, []);
    }

    const { adapter, calls } = fixture({ admitted: false });
    const response = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: "https://other.example",
      body: { request: true },
    });
    assert.deepEqual(response, {
      status: 403,
      headers: { "cache-control": "no-store", vary: "Origin" },
      body: { error: "wrong_origin" },
    });
    assert.deepEqual(calls, [["admit", "https://other.example", { request: true }, undefined]]);
  });

  test("an Origin no browser could have sent is refused before admission", async () => {
    // The security model's HTTP boundary: exactly one canonical value reaches
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
        contentType: "application/json",
        origin: /** @type {any} */ (origin),
        body: { request: true },
      });
      assert.equal(response.status, 403, `${JSON.stringify(origin)} is not one canonical origin`);
      assert.deepEqual(response.headers, { "cache-control": "no-store", vary: "Origin" });
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
      contentType: "application/json",
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

    const response = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
    });

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

  test("an admitted non-200 POST also overrides a cacheable handler response", async () => {
    const adapter = new BrowserUnlockHttp({
      originAdmission: {
        preflight: () => true,
        admit: () => ({ kind: "admitted", context: {} }),
      },
      unlock: () => ({
        status: 503,
        headers: { "CACHE-CONTROL": "public, max-age=600" },
        body: { error: "unavailable" },
      }),
    });

    const response = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
    });
    assert.equal(response.status, 503);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(
      Object.keys(response.headers).filter((field) => field.toLowerCase() === "cache-control")
        .length,
      1,
    );
  });

  test("a bracketed IPv6 origin is admitted and reflected exactly", async () => {
    // The literal reaches admission as the bytes it arrived as and comes
    // back in the permission header unchanged. Nothing past the origin
    // grammar has a case for a host spelling.
    const literal = "https://[2001:db8::1]";
    const { adapter, calls } = fixture();
    const body = { resourceJWT: "header.payload.signature" };

    const response = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: literal,
      body,
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers["access-control-allow-origin"], literal);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.headers["content-type"], "application/json");
    assert.notEqual(response.headers["access-control-allow-origin"], "*");
    assert.deepEqual(calls[0], ["admit", literal, body, undefined]);
  });

  test("a handler's own spellings of the CORS fields leave only the adapter's exact permission", async () => {
    // A handler that writes `Access-Control-Allow-Origin: *` in capitals
    // would otherwise sit beside the adapter's lowercase exact value, and the
    // response would carry two permissions for one field. The adapter owns
    // every CORS field and the `Origin` member of `Vary`; it keeps the
    // handler's other headers and the other `Vary` members.
    const adapter = new BrowserUnlockHttp({
      originAdmission: {
        preflight: () => true,
        admit: () => ({ kind: "admitted", context: {} }),
      },
      credentials: true,
      unlock: () => ({
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "ACCESS-CONTROL-ALLOW-CREDENTIALS": "false",
          "Access-Control-Allow-Methods": "GET, POST",
          "Access-Control-Allow-Headers": "*",
          Vary: "Accept-Encoding",
          "x-issuer": "reference",
        },
        body: { keys: {} },
      }),
    });

    const response = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
    });

    assert.deepEqual(response.headers, {
      "access-control-allow-origin": REGISTERED,
      "access-control-allow-credentials": "true",
      "cache-control": "no-store",
      "content-type": "application/json",
      "x-issuer": "reference",
      vary: "Accept-Encoding, Origin",
    });
  });

  test("a refusal the admission has not verified exposes no CORS permission", async () => {
    // Only the admission component knows whether it has verified the
    // resource assertion and matched its signed origin to the observed one.
    // Until it says so, no permission leaves the adapter, including one the
    // refusal's own headers carry.
    /** @type {any[]} */
    const calls = [];
    const unverified = new BrowserUnlockHttp({
      originAdmission: {
        preflight: () => true,
        admit: (origin, body) => {
          calls.push(["admit", origin, body]);
          return {
            kind: "refused",
            response: {
              status: 400,
              headers: {
                "Access-Control-Allow-Origin": "*",
                "access-control-allow-credentials": "true",
                Vary: "Cookie",
              },
              body: { error: "bad_jwt" },
            },
          };
        },
      },
      credentials: true,
      unlock: () => {
        calls.push(["unlock"]);
        return { status: 200, body: { keys: {} } };
      },
    });

    const response = await unverified.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: { request: true },
    });

    assert.deepEqual(response, {
      status: 400,
      headers: { "cache-control": "no-store", vary: "Cookie, Origin" },
      body: { error: "bad_jwt" },
    });
    assert.deepEqual(calls, [["admit", REGISTERED, { request: true }]]);
  });

  test("GET from a canonical origin is refused without CORS and reaches no application seam", async () => {
    // The browser binding has one unlock method. A GET carries its request
    // in the URL, and this adapter answers it before the origin admission,
    // the registration lookup or the unlock operation hears of it.
    const { adapter, calls } = fixture({ credentials: true });

    const response = await adapter.handle({
      method: "GET",
      origin: REGISTERED,
      body: { request: true },
    });

    assert.equal(response.status, 405);
    assert.deepEqual(response.headers, { allow: "OPTIONS, POST", vary: "Origin" });
    assert.deepEqual(calls, []);
  });

  test("an admission that verified and matched the signed origin may refuse with exact CORS", async () => {
    // `cors: true` is the admission component's statement that it has
    // verified the resource assertion and found its signed origin equal to
    // the observed one. A refusal after that point, such as an application
    // denial, may be read by the page at that exact origin.
    const { adapter, calls } = fixture({ admitted: false, cors: true, credentials: true });
    const response = await adapter.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: { request: true },
    });

    assert.deepEqual(response, {
      status: 403,
      headers: {
        "access-control-allow-origin": REGISTERED,
        "access-control-allow-credentials": "true",
        "cache-control": "no-store",
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

  test("pre-gate contract faults get an owned 5xx without CORS; post-gate faults keep CORS", async () => {
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
    // A malformed admission answer is a host fault before the gate: an owned
    // 5xx without CORS, not a rejected handle() the host framework answers.
    assert.deepEqual(
      await badAdmission.handle({
        method: "POST",
        contentType: "application/json",
        origin: REGISTERED,
        body: {},
      }),
      {
        status: 500,
        headers: { "cache-control": "no-store", vary: "Origin" },
        body: { error: "internal_error" },
      },
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
    const response = await badUnlock.handle({
      method: "POST",
      contentType: "application/json",
      origin: REGISTERED,
      body: {},
    });
    assert.equal(response.status, 500);
    assert.equal(response.headers["access-control-allow-origin"], REGISTERED);
  });

  test("a throwing preflight or admission collaborator gets an owned 5xx without CORS", async () => {
    const owned = {
      status: 500,
      headers: { "cache-control": "no-store", vary: "Origin" },
      body: { error: "internal_error" },
    };
    const reached = [];
    const failing = (/** @type {string} */ where) => () => {
      reached.push(where);
      throw Object.assign(new Error(`${where} store down`), { code: "ECONNREFUSED" });
    };
    const preflightDown = new BrowserUnlockHttp({
      credentials: true,
      originAdmission: { preflight: failing("preflight"), admit: () => ({ kind: "admitted" }) },
      unlock: failing("unlock"),
    });
    assert.deepEqual(await preflightDown.handle({ method: "OPTIONS", origin: REGISTERED }), owned);

    const admissionDown = new BrowserUnlockHttp({
      credentials: true,
      originAdmission: { preflight: () => true, admit: failing("admit") },
      unlock: failing("unlock"),
    });
    const post = { method: "POST", contentType: "application/json", origin: REGISTERED, body: {} };
    assert.deepEqual(await admissionDown.handle(post), owned);

    // A refusal whose status is not an integer is malformed host output too.
    const badRefusal = new BrowserUnlockHttp({
      originAdmission: {
        preflight: () => true,
        admit: () => ({ kind: "refused", response: /** @type {any} */ ({ status: "403" }) }),
      },
      unlock: failing("unlock"),
    });
    assert.deepEqual(await badRefusal.handle(post), owned);
    assert.deepEqual(reached, ["preflight", "admit"]);
  });

  test("a bearer-mode 401 carries a Bearer challenge; a cookie-mode 401 carries none", async () => {
    const post = { method: "POST", contentType: "application/json", origin: REGISTERED, body: {} };
    const denying = (/** @type {boolean} */ authorization) =>
      new BrowserUnlockHttp({
        authorization,
        originAdmission: { preflight: () => true, admit: () => ({ kind: "admitted" }) },
        unlock: () => ({ status: 401, body: { error: "denied" } }),
      });
    const bearer = denying(true);
    const missing = await bearer.handle(post);
    assert.equal(missing.status, 401);
    assert.equal(missing.headers["www-authenticate"], "Bearer");
    const malformed = await bearer.handle({ ...post, authorization: "Bearer a b" });
    assert.equal(malformed.status, 401);
    assert.equal(malformed.headers["www-authenticate"], "Bearer");
    const refused = await bearer.handle({ ...post, authorization: "Bearer opaque" });
    assert.equal(refused.status, 401);
    assert.equal(refused.headers["www-authenticate"], "Bearer");

    // Cookie-mode authentication policy is not settled, so no scheme is named.
    const cookie = await denying(false).handle(post);
    assert.equal(cookie.status, 401);
    assert.equal(
      Object.keys(cookie.headers).some((field) => field.toLowerCase() === "www-authenticate"),
      false,
    );
    // A bearer-mode response that is not 401 gets no challenge.
    const served = await new BrowserUnlockHttp({
      authorization: true,
      originAdmission: { preflight: () => true, admit: () => ({ kind: "admitted" }) },
      unlock: () => ({ status: 200, body: { keys: {} } }),
    }).handle({ ...post, authorization: "Bearer opaque" });
    assert.equal(served.headers["www-authenticate"], undefined);
  });
});

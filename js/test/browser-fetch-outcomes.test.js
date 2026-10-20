// @ts-check

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import puppeteer from "puppeteer-core";

function browserExecutablePath() {
  const named = process.env.DCA_ORACLE_BROWSER;
  if (named) return existsSync(named) ? named : null;

  const cache = join(homedir(), ".cache", "puppeteer", "chrome-headless-shell");
  if (!existsSync(cache)) return null;
  for (const version of readdirSync(cache).sort().reverse()) {
    const candidate = join(
      cache,
      version,
      "chrome-headless-shell-linux64",
      "chrome-headless-shell",
    );
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

const executablePath = browserExecutablePath();

/** @returns {Record<string, string>} */
function browserEnvironment() {
  const libs = process.env.DCA_ORACLE_BROWSER_LIBS ?? join(homedir(), ".cache", "chrome-libs");
  if (!existsSync(libs)) return { ...process.env };
  return {
    ...process.env,
    LD_LIBRARY_PATH: [
      join(libs, "lib", "x86_64-linux-gnu"),
      join(libs, "usr", "lib", "x86_64-linux-gnu"),
      join(libs, "lib64"),
      process.env.LD_LIBRARY_PATH ?? "",
    ]
      .filter(Boolean)
      .join(":"),
    FONTCONFIG_PATH: join(libs, "etc", "fonts"),
  };
}

/** @param {import("node:http").Server} server */
async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return `http://127.0.0.1:${address.port}`;
}

/** @param {import("node:http").Server} server */
async function close(server) {
  if (!server.listening) return;
  server.closeAllConnections();
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

test(
  "native Chromium Fetch distinguishes visible exact-origin errors from opaque failures",
  { skip: executablePath === null && "no cached oracle Chromium executable", timeout: 30_000 },
  async (t) => {
    assert.ok(executablePath);

    /** @type {Array<{path: string, origin: string|undefined, cookie: string|undefined, status: number|null, body: string|null}>} */
    const requests = [];
    let sourceOrigin = "";
    const source = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><title>Fetch outcome fixture</title>");
    });
    const issuerFixture = createServer((request, response) => {
      const path = new URL(request.url ?? "/", "http://fixture.invalid").pathname;
      const entry = {
        path,
        origin: request.headers.origin,
        cookie: request.headers.cookie,
        status: /** @type {number|null} */ (null),
        body: /** @type {string|null} */ (null),
      };
      requests.push(entry);

      if (path === "/network-failure") {
        request.resume();
        request.socket.destroy();
        return;
      }

      const fixtures = {
        "/before-verification": {
          status: 403,
          body: '{"error":"origin_refused"}',
          cors: false,
        },
        "/visible-4xx": {
          status: 403,
          body: '{"error":"denied"}',
          cors: true,
        },
        "/visible-5xx": {
          status: 503,
          body: '{"error":"temporarily_unavailable"}',
          cors: true,
        },
      };
      const fixture = fixtures[path];
      if (fixture === undefined) {
        response.writeHead(404);
        response.end();
        return;
      }

      entry.status = fixture.status;
      entry.body = fixture.body;
      const headers = { "content-type": "application/json; charset=utf-8" };
      if (fixture.cors && request.headers.origin === sourceOrigin) {
        Object.assign(headers, {
          "access-control-allow-origin": sourceOrigin,
          "access-control-allow-credentials": "true",
          vary: "Origin",
        });
      }
      response.writeHead(fixture.status, headers);
      response.end(fixture.body);
    });

    let browser;
    t.after(async () => {
      try {
        await browser?.close();
      } finally {
        await Promise.all([close(source), close(issuerFixture)]);
      }
    });

    sourceOrigin = await listen(source);
    const issuerOrigin = await listen(issuerFixture);

    browser = await puppeteer.launch({
      executablePath,
      timeout: 10_000,
      env: browserEnvironment(),
      args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
    });

    const page = await browser.newPage();
    page.setDefaultTimeout(5_000);
    page.setDefaultNavigationTimeout(5_000);
    await page.goto(sourceOrigin, { waitUntil: "domcontentloaded", timeout: 5_000 });
    await page.evaluate(() => {
      // The two origins differ by port, so this same-site fixture cookie is
      // sent only because the Fetch call below explicitly includes credentials.
      globalThis.document.cookie = "issuer_session=fixture; SameSite=Lax; Path=/";
    });

    const observations = await page.evaluate(async (targetOrigin) => {
      /** @param {string} path */
      async function observe(path) {
        try {
          const response = await fetch(`${targetOrigin}${path}`, {
            method: "POST",
            mode: "cors",
            credentials: "include",
            headers: { "content-type": "text/plain" },
            body: "probe",
            signal: AbortSignal.timeout(4_000),
          });
          return {
            kind: "response",
            type: response.type,
            status: response.status,
            body: await response.text(),
          };
        } catch (error) {
          return {
            kind: "rejected",
            name: error instanceof Error ? error.name : "unknown",
            hasStatus: error instanceof Error && "status" in error,
            hasBody: error instanceof Error && "body" in error,
          };
        }
      }

      return {
        cookie: globalThis.document.cookie,
        beforeVerification: await observe("/before-verification"),
        networkFailure: await observe("/network-failure"),
        visible4xx: await observe("/visible-4xx"),
        visible5xx: await observe("/visible-5xx"),
      };
    }, issuerOrigin);

    assert.match(observations.cookie, /(?:^|; )issuer_session=fixture(?:;|$)/);
    assert.deepEqual(observations.beforeVerification, {
      kind: "rejected",
      name: "TypeError",
      hasStatus: false,
      hasBody: false,
    });
    assert.deepEqual(observations.networkFailure, observations.beforeVerification);
    assert.deepEqual(observations.visible4xx, {
      kind: "response",
      type: "cors",
      status: 403,
      body: '{"error":"denied"}',
    });
    assert.deepEqual(observations.visible5xx, {
      kind: "response",
      type: "cors",
      status: 503,
      body: '{"error":"temporarily_unavailable"}',
    });

    const before = requests.find(({ path }) => path === "/before-verification");
    assert.ok(before);
    assert.equal(before.origin, sourceOrigin);
    assert.match(before.cookie ?? "", /(?:^|; )issuer_session=fixture(?:;|$)/);
    assert.equal(before.status, 403);
    assert.equal(before.body, '{"error":"origin_refused"}');

    const network = requests.find(({ path }) => path === "/network-failure");
    assert.ok(network);
    assert.equal(network.origin, sourceOrigin);
    assert.equal(network.status, null);
    assert.equal(network.body, null);

    for (const path of ["/visible-4xx", "/visible-5xx"]) {
      const request = requests.find((entry) => entry.path === path);
      assert.ok(request);
      assert.equal(request.origin, sourceOrigin);
      assert.match(request.cookie ?? "", /(?:^|; )issuer_session=fixture(?:;|$)/);
    }
  },
);

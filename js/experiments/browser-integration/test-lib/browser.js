// @ts-check
// A real-DOM browser host for this experiment. Its routes are intercepted so
// the article and the imported reference ES modules need no network access.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import process from "node:process";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
const V1 = fileURLToPath(new URL("../../../", import.meta.url));
const JS_PREFIX = "/__js/";
const HARNESS_ORIGIN = "https://pub.example";

/** @returns {string | null} */
function oracleBrowserPath() {
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

/** @returns {Record<string, string>} */
function browserEnvironment() {
  /** @type {Record<string, string>} */
  const environment = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (typeof value === "string") environment[name] = value;
  }
  const libs = process.env.DCA_ORACLE_BROWSER_LIBS ?? join(homedir(), ".cache", "chrome-libs");
  if (!existsSync(libs)) return environment;
  const libraryPath = [
    join(libs, "lib", "x86_64-linux-gnu"),
    join(libs, "usr", "lib", "x86_64-linux-gnu"),
    join(libs, "lib64"),
    process.env.LD_LIBRARY_PATH ?? "",
  ]
    .filter(Boolean)
    .join(":");
  return {
    ...environment,
    LD_LIBRARY_PATH: libraryPath,
    FONTCONFIG_PATH: join(libs, "etc", "fonts"),
  };
}

/**
 * Launch the installed oracle browser against one actual host document.
 *
 * @param {{
 *   deliveries: Record<string, Uint8Array>,
 *   respond: (operation: string, request: string) => Promise<{ status: number, body: object }>
 * }} setup
 */
export async function openBrowser({ deliveries, respond }) {
  const executablePath = oracleBrowserPath();
  if (executablePath === null)
    throw new Error("the browser evidence requires the oracle Chromium executable");
  const { default: puppeteer } = await import("puppeteer-core");
  const browser = await puppeteer.launch({
    executablePath,
    env: browserEnvironment(),
    args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
  });
  const page = await browser.newPage();
  await page.exposeFunction("dcaRespond", respond);
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== HARNESS_ORIGIN) {
      void request.respond({ status: 404, body: "" });
      return;
    }
    if (url.pathname === "/article") {
      void request.respond({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: "<!doctype html><html><body><main><article id=article-body><p>Locked.</p></article></main></body></html>",
      });
      return;
    }
    const delivery = /^\/delivery\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (delivery !== null) {
      const bytes = deliveries[delivery[1]];
      void request.respond(
        bytes === undefined
          ? { status: 404, body: "" }
          : {
              status: 200,
              contentType: "application/json",
              body: Buffer.from(bytes),
            },
      );
      return;
    }
    if (!url.pathname.startsWith(JS_PREFIX)) {
      void request.respond({ status: 404, body: "" });
      return;
    }
    let file;
    try {
      file = resolve(V1, decodeURIComponent(url.pathname.slice(JS_PREFIX.length)));
    } catch {
      void request.respond({ status: 404, body: "" });
      return;
    }
    const fromRoot = relative(V1, file);
    if (
      fromRoot === "" ||
      fromRoot.startsWith(`..${sep}`) ||
      fromRoot === ".." ||
      isAbsolute(fromRoot)
    ) {
      void request.respond({ status: 404, body: "" });
      return;
    }
    if (!existsSync(file)) {
      void request.respond({ status: 404, body: "" });
      return;
    }
    void request.respond({
      status: 200,
      contentType: "text/javascript; charset=utf-8",
      body: readFileSync(file, "utf8"),
    });
  });
  try {
    await page.goto(`${HARNESS_ORIGIN}/article`, { waitUntil: "load" });
  } catch (error) {
    await browser.close();
    throw error;
  }
  return { browser, page };
}

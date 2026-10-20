// @ts-check
// Independently evaluated page participants use real Chromium modules, the
// serialized publisher delivery and issuer response, and the host's live DOM.

import test from "node:test";
import assert from "node:assert/strict";
import { exchange } from "../test-lib/exchange.js";
import { openBrowser } from "../test-lib/browser.js";

const KEY = Object.freeze({ interface: "dca.content-handler", major: 1, name: "article" });
const WRONG_NAME = Object.freeze({ ...KEY, name: "fallback" });
const WRONG_MAJOR = Object.freeze({ ...KEY, major: 2 });
const REGISTRY = "/__js/experiments/browser-integration/implementation/registry.js";
const HANDLER = "/__js/experiments/browser-integration/implementation/content-handler.js";
const SELECTED_CLIENT = "/__js/experiments/browser-integration/test-lib/registry-client.js";
const READER = "/__js/adapter-client/JsonDeliveryReader.js";
const DATA = "/__js/core-client/DcaData.js";
const ASSOCIATION = "/__js/core-client/ResponseAssociation.js";
const COMPOSE = "/__js/integration-client/composeClient.js";
const BODY = "<p>Byrådet åpnet havna.</p>";

/** @param {string} name @param {string} value */
async function published(name, value) {
  return exchange([
    {
      name,
      bytes: new TextEncoder().encode(value),
      contentType: "text/html",
    },
  ]);
}

/** @param {any} page @param {{ interface: string, major: number, name: string }} key */
async function installProvider(page, key) {
  return page.evaluate(
    async (module, handlerModule, selected) => {
      const { installRegistry } = await import(module);
      const { createContentHandler } = await import(handlerModule);
      const registry = installRegistry(globalThis);
      const disposer = registry.register(selected, createContentHandler());
      /** @type {any} */ (globalThis).__providerDisposers ??= [];
      /** @type {any} */ (globalThis).__providerDisposers.push(disposer);
      return registry.lookup(selected) !== null;
    },
    REGISTRY,
    HANDLER,
    key,
  );
}

/**
 * Run the independently loaded DCA client participant. It observes only its
 * configured key, captures the connection before the issuer await, and opens
 * the actual serialized JSON delivery in the browser.
 *
 * @param {any} page
 * @param {string} operation
 * @param {boolean} delayed
 */
async function installClient(page, operation, delayed = false) {
  return page.evaluate(
    async (modules, id, shouldDelay, selected) => {
      const [
        { installRegistry },
        { connectSelected },
        { JsonDeliveryReader },
        { DcaData },
        { ResponseAssociation },
        { composeClient },
      ] = await Promise.all([
        import(modules.registry),
        import(modules.client),
        import(modules.reader),
        import(modules.data),
        import(modules.association),
        import(modules.compose),
      ]);
      const registry = installRegistry(globalThis);
      const runs = /** @type {any} */ (globalThis.__browserRuns ??= Object.create(null));
      const eligibility = /** @type {any} */ (
        globalThis.__browserEligibility ??= Object.create(null)
      );
      const releases = /** @type {any} */ (globalThis.__browserReleases ??= Object.create(null));
      eligibility[id] = true;
      const state = {
        presence: [],
        started: false,
        settled: false,
        callbackEntered: false,
        outcomes: null,
        error: null,
        effects: 0,
      };
      runs[id] = state;

      const stop = registry.observe(selected, (entry) => {
        state.presence.push(entry.provider === null ? "absent" : "present");
        if (entry.provider === null || state.started) return;
        state.started = true;
        state.workflow = (async () => {
          const response = await fetch(`/delivery/${encodeURIComponent(id)}`, {
            cache: "no-store",
          });
          if (!response.ok) throw new Error(`delivery status ${response.status}`);
          const deliveryBytes = new Uint8Array(await response.arrayBuffer());
          const reader = new JsonDeliveryReader(deliveryBytes, {
            publisherOrigin: "https://news.example",
          });
          const dcaData = new DcaData(reader.dcaData, { publisherOrigin: "https://news.example" });
          const { resolver, builder, opener } = composeClient();
          const request = builder.build(dcaData, "subscription", ["bodytext"]).toObject();
          const association = new ResponseAssociation(dcaData, "subscription", request);
          const connection = connectSelected(registry, selected, {
            delivery: reader.dcaData,
            isEligible: () => eligibility[id] === true,
            values: { bodytext: "strictUTF8" },
            targets: {
              bodytext: async ({ contentType, value, commit }) => {
                if (contentType !== "text/html" || typeof value !== "string") {
                  return { status: "refused", reason: "unexpected_content" };
                }
                if (shouldDelay) {
                  state.callbackEntered = true;
                  await new Promise((resolve) => {
                    releases[id] = resolve;
                  });
                }
                const applied = commit(() => {
                  const target = globalThis.document.getElementById("article-body");
                  if (target === null) throw new Error("article destination disappeared");
                  target.innerHTML = value;
                  state.effects += 1;
                });
                return { status: applied ? "handled" : "refused" };
              },
            },
          });
          if (connection === null) throw new Error("selected handler became pending");
          const answer = await globalThis.dcaRespond(id, JSON.stringify(request));
          if (answer.status !== 200) throw new Error(`issuer status ${answer.status}`);
          await resolver.applyResponse(dcaData, "subscription", answer.body, association);
          const item = dcaData.contentItemFor("bodytext");
          if (item === null) throw new Error("bodytext item disappeared");
          const opened = await opener.open({
            item,
            ciphertext: reader.extract("bodytext"),
            resolveKey: () => resolver.contentKeyFor(dcaData, "bodytext"),
          });
          state.outcomes = await connection.handleContent({ bodytext: opened });
        })()
          .catch((error) => {
            state.error = String(error?.stack ?? error);
          })
          .finally(() => {
            state.settled = true;
          });
      });
      state.stop = stop;
      return { presence: [...state.presence], started: state.started };
    },
    {
      registry: REGISTRY,
      handler: HANDLER,
      client: SELECTED_CLIENT,
      reader: READER,
      data: DATA,
      association: ASSOCIATION,
      compose: COMPOSE,
    },
    operation,
    delayed,
    KEY,
  );
}

/** @param {any} page @param {string} operation */
async function completedRun(page, operation) {
  const handle = await page.waitForFunction(
    (id) => /** @type {any} */ (globalThis).__browserRuns?.[id]?.settled === true,
    { timeout: 15000 },
    operation,
  );
  await handle.dispose();
  return page.evaluate((id) => {
    const state = /** @type {any} */ (globalThis).__browserRuns[id];
    return {
      error: state.error,
      outcomes: state.outcomes,
      presence: state.presence,
      effects: state.effects,
    };
  }, operation);
}

/** @param {any} page @param {string} operation */
async function callbackEntered(page, operation) {
  const handle = await page.waitForFunction(
    (id) => /** @type {any} */ (globalThis).__browserRuns?.[id]?.callbackEntered === true,
    { timeout: 15000 },
    operation,
  );
  await handle.dispose();
}

/** @param {any} browser */
async function close(browser) {
  await browser.close();
}

test("provider-first independent browser modules open real serialized content into the DOM", async () => {
  const publication = await published("bodytext", BODY);
  const requests = [];
  const { browser, page } = await openBrowser({
    deliveries: { article: publication.bytes },
    async respond(operation, request) {
      requests.push({ operation, request });
      return publication.respond(request);
    },
  });
  try {
    assert.equal(await installProvider(page, KEY), true);
    const client = await installClient(page, "article");
    assert.deepEqual(client, { presence: ["present"], started: true });
    const result = await completedRun(page, "article");
    assert.equal(result.error, null);
    assert.deepEqual(result.outcomes, { bodytext: { status: "handled" } });
    assert.equal(result.effects, 1);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].operation, "article");
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      BODY,
      "the opened bytes reached the real page DOM",
    );
  } finally {
    await close(browser);
  }
});

test("client-first browser participant waits for its exact key without name or major fallback", async () => {
  const publication = await published("bodytext", BODY);
  const requests = [];
  const { browser, page } = await openBrowser({
    deliveries: { article: publication.bytes },
    async respond(operation, request) {
      requests.push({ operation, request });
      return publication.respond(request);
    },
  });
  try {
    const client = await installClient(page, "article");
    assert.deepEqual(client, { presence: ["absent"], started: false });
    await installProvider(page, WRONG_NAME);
    await installProvider(page, WRONG_MAJOR);
    const stillPending = await page.evaluate(() => {
      const state = /** @type {any} */ (globalThis).__browserRuns.article;
      return { presence: state.presence, started: state.started };
    });
    assert.deepEqual(stillPending, { presence: ["absent"], started: false });
    assert.equal(requests.length, 0, "unselected providers caused no DCA exchange");

    assert.equal(await installProvider(page, KEY), true);
    const result = await completedRun(page, "article");
    assert.equal(result.error, null);
    assert.deepEqual(result.outcomes, { bodytext: { status: "handled" } });
    assert.equal(result.effects, 1);
    assert.equal(requests.length, 1);
    assert.equal(await page.$eval("#article-body", (target) => target.innerHTML), BODY);
  } finally {
    await close(browser);
  }
});

test("an invalidated delayed handler cannot overwrite a successor on the same DOM target", async () => {
  const predecessorText = "<p>Predecessor</p>";
  const successorText = "<p>Successor</p>";
  const predecessor = await published("bodytext", predecessorText);
  const successor = await published("bodytext", successorText);
  const requests = [];
  const { browser, page } = await openBrowser({
    deliveries: { predecessor: predecessor.bytes, successor: successor.bytes },
    async respond(operation, request) {
      requests.push({ operation, request });
      return operation === "predecessor"
        ? predecessor.respond(request)
        : successor.respond(request);
    },
  });
  try {
    await installProvider(page, KEY);
    await installClient(page, "predecessor", true);
    await callbackEntered(page, "predecessor");

    await page.evaluate((id) => {
      /** @type {any} */ (globalThis).__browserEligibility[id] = false;
    }, "predecessor");
    await installClient(page, "successor");
    const successorResult = await completedRun(page, "successor");
    assert.equal(successorResult.error, null);
    assert.deepEqual(successorResult.outcomes, { bodytext: { status: "handled" } });
    assert.equal(successorResult.effects, 1);
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      successorText,
      "the eligible successor owns the shared article destination",
    );

    await page.evaluate((id) => {
      /** @type {any} */ (globalThis).__browserReleases[id]();
    }, "predecessor");
    const predecessorResult = await completedRun(page, "predecessor");
    assert.equal(predecessorResult.error, null);
    assert.deepEqual(predecessorResult.outcomes, { bodytext: { status: "stale" } });
    assert.equal(predecessorResult.effects, 0);
    assert.equal(requests.length, 2);
    assert.deepEqual(requests.map(({ operation }) => operation).sort(), [
      "predecessor",
      "successor",
    ]);
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      successorText,
      "the late predecessor effect did not replace successor content",
    );
  } finally {
    await close(browser);
  }
});

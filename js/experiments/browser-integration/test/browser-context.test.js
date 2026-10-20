// @ts-check
// Real-browser evidence for source-gated work and popup-sensitive account hints.

import test from "node:test";
import assert from "node:assert/strict";
import { exchange } from "../test-lib/exchange.js";
import { openBrowser } from "../test-lib/browser.js";

const ROOT = "/__js/experiments/browser-integration/";
const ROUTES = {
  registry: `${ROOT}implementation/registry.js`,
  contextSource: `${ROOT}implementation/context-source.js`,
  contextHost: `${ROOT}test-lib/context-host.js`,
  accountSource: `${ROOT}implementation/account-source.js`,
  accountMenu: `${ROOT}test-lib/account-menu.js`,
  handler: `${ROOT}implementation/content-handler.js`,
  reader: "/__js/adapter-client/JsonDeliveryReader.js",
  data: "/__js/core-client/DcaData.js",
  association: "/__js/core-client/ResponseAssociation.js",
  compose: "/__js/integration-client/composeClient.js",
};

/** @param {string} text */
async function publication(text) {
  return exchange([
    {
      name: "bodytext",
      bytes: new TextEncoder().encode(text),
      contentType: "text/html",
    },
  ]);
}

/** @param {any} page @param {string} name */
async function waitForRun(page, name) {
  const handle = await page.waitForFunction(
    (key) => /** @type {any} */ (globalThis).__contextRuns?.[key]?.settled === true,
    { timeout: 15000 },
    name,
  );
  await handle.dispose();
  return page.evaluate((key) => /** @type {any} */ (globalThis).__contextRuns[key], name);
}

async function installContextScenario(page) {
  await page.evaluate(async (modules) => {
    const [
      { installRegistry },
      { createContextSource },
      { createContextHost },
      { createContentHandler },
      { JsonDeliveryReader },
      { DcaData },
      { ResponseAssociation },
      { composeClient },
    ] = await Promise.all([
      import(modules.registry),
      import(modules.contextSource),
      import(modules.contextHost),
      import(modules.handler),
      import(modules.reader),
      import(modules.data),
      import(modules.association),
      import(modules.compose),
    ]);
    const registry = installRegistry(globalThis);
    const key = { interface: "dca.access-context", major: 1, name: "login" };
    const scope = { routes: ["subscription"] };
    const state = /** @type {any} */ (globalThis.__contextRuns = Object.create(null));
    const controllers = new Map();
    let host = null;
    let registration = null;
    registry.observe(key, (entry) => {
      host?.dispose();
      host = entry.provider ? createContextHost(entry.provider, scope) : null;
    });

    function replaceSource() {
      registration?.();
      const source = createContextSource({
        sequence: 0,
        contextKnown: true,
        contextRevision: "same-label",
      });
      controllers.set(source.provider, source);
      registration = registry.register(key, source.provider);
      return source;
    }
    replaceSource();

    /**
     * @template T
     * @param {import("../test-lib/context-host.js").CapturedWork} work
     * @param {() => Promise<T> | T} operation
     * @returns {Promise<{completed: true, value: T} | {completed: false}>}
     */
    async function gated(work, operation) {
      while (await work.waitUntilKnown()) {
        if (!work.isEligible()) continue;
        return { completed: true, value: await operation() };
      }
      return { completed: false };
    }

    /** @param {any} run @param {import("../test-lib/context-host.js").CapturedWork} work @param {string} phase @param {() => Promise<any> | any} operation */
    async function atBoundary(run, work, phase, operation) {
      run.phase = phase;
      const outcome = await gated(work, operation);
      run.phase = outcome.completed ? `${phase}:complete` : `${phase}:retired`;
      return outcome;
    }

    /** @param {string} id @param {boolean} delay @param {boolean} holdDelivery */
    function start(id, delay, holdDelivery = false) {
      const work = host?.capture("subscription");
      if (!work) throw new Error("known context did not capture work");
      const source = controllers.get(registry.lookup(key));
      if (!source) throw new Error("current source controller is missing");
      const run = {
        callbackEntered: false,
        deliveryWaiting: false,
        phase: "starting",
        settled: false,
        error: null,
        outcomes: null,
        effects: 0,
        openingStarts: 0,
      };
      state[id] = run;

      run.promise = (async () => {
        run.phase = "delivery";
        const response = await fetch(`/delivery/${encodeURIComponent(id)}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`delivery status ${response.status}`);
        if (holdDelivery) {
          run.deliveryWaiting = true;
          run.phase = "delivery-held";
          await new Promise((resolve) => {
            run.releaseDelivery = resolve;
          });
        }
        const reader = new JsonDeliveryReader(new Uint8Array(await response.arrayBuffer()), {
          publisherOrigin: "https://news.example",
        });
        const delivery = new DcaData(reader.dcaData, { publisherOrigin: "https://news.example" });
        const { resolver, builder, opener } = composeClient();
        const request = builder.build(delivery, "subscription", ["bodytext"]).toObject();
        const association = new ResponseAssociation(delivery, "subscription", request);
        const connection = createContentHandler().connect({
          delivery: reader.dcaData,
          isEligible: () => work.isEligible(),
          values: { bodytext: "strictUTF8" },
          targets: {
            bodytext: async ({ value, commit }) => {
              if (typeof value !== "string") return { status: "refused", reason: "not_text" };
              if (delay) {
                run.callbackEntered = true;
                await new Promise((resolve) => {
                  run.release = resolve;
                });
              }
              const applied = commit(() => {
                const target = globalThis.document.getElementById("article-body");
                if (!target) throw new Error("article target disappeared");
                target.innerHTML = value;
                run.effects += 1;
              });
              return { status: applied ? "handled" : "refused" };
            },
          },
        });
        try {
          const sent = await atBoundary(run, work, "issuer", () =>
            globalThis.dcaRespond(id, JSON.stringify(request)),
          );
          if (!sent.completed) {
            run.outcomes = { bodytext: { status: "stale" } };
            return;
          }
          const applied = await atBoundary(run, work, "apply-response", () => {
            if (sent.value.status !== 200) throw new Error(`issuer status ${sent.value.status}`);
            return resolver.applyResponse(delivery, "subscription", sent.value.body, association);
          });
          if (!applied.completed) {
            run.outcomes = { bodytext: { status: "stale" } };
            return;
          }
          const item = delivery.contentItemFor("bodytext");
          if (item === null) throw new Error("bodytext item disappeared");
          const opened = await atBoundary(run, work, "open", () => {
            run.openingStarts += 1;
            return opener.open({
              item,
              ciphertext: reader.extract("bodytext"),
              resolveKey: () => resolver.contentKeyFor(delivery, "bodytext"),
            });
          });
          if (!opened.completed) {
            run.outcomes = { bodytext: { status: "stale" } };
            return;
          }
          const handled = await atBoundary(run, work, "handle-content", () =>
            connection.handleContent({ bodytext: opened.value }),
          );
          run.outcomes = handled.completed ? handled.value : { bodytext: { status: "stale" } };
        } finally {
          connection.dispose();
          work.dispose();
        }
      })()
        .catch((error) => {
          run.error = String(error?.stack ?? error);
        })
        .finally(() => {
          run.settled = true;
        });
      return true;
    }

    /** @type {any} */ (globalThis).__contextControl = {
      start,
      publish(sequence, contextKnown, contextRevision = "same-label") {
        const source = controllers.get(registry.lookup(key));
        if (!source) throw new Error("current source controller is missing");
        return source.publish({ sequence, contextKnown, contextRevision });
      },
      replace: replaceSource,
      releaseDelivery(id) {
        state[id].releaseDelivery();
      },
      releaseHandler(id) {
        state[id].release();
      },
    };
  }, ROUTES);
}

test("unknown during delivery retrieval pauses issuer dispatch until the same revision is known", async () => {
  const content = await publication("<p>Resumed article</p>");
  const responses = [];
  const { browser, page } = await openBrowser({
    deliveries: { resumed: content.bytes },
    async respond(operation, request) {
      responses.push(operation);
      return content.respond(request);
    },
  });
  try {
    await installContextScenario(page);
    await page.evaluate(() => globalThis.__contextControl.start("resumed", false, true));
    const deliveryHeld = await page.waitForFunction(
      () => globalThis.__contextRuns.resumed.deliveryWaiting === true,
      { timeout: 15000 },
    );
    await deliveryHeld.dispose();
    await page.evaluate(() => {
      globalThis.__contextControl.publish(1, false);
      globalThis.__contextControl.releaseDelivery("resumed");
    });
    const waitingForContext = await page.waitForFunction(
      () => globalThis.__contextRuns.resumed.phase === "issuer",
      { timeout: 15000 },
    );
    await waitingForContext.dispose();
    assert.deepEqual(responses, [], "unknown context prevented issuer dispatch");
    assert.equal(await page.$eval("#article-body", (target) => target.textContent), "Locked.");
    await page.evaluate(() => globalThis.__contextControl.publish(2, true));
    const run = await waitForRun(page, "resumed");
    assert.equal(run.error, null);
    assert.deepEqual(run.outcomes, { bodytext: { status: "handled" } });
    assert.deepEqual(responses, ["resumed"]);
    assert.equal(run.openingStarts, 1);
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      "<p>Resumed article</p>",
    );
  } finally {
    await browser.close();
  }
});

test("an issuer response received during unknown waits before key opening or DOM output", async () => {
  const content = await publication("<p>After response gap</p>");
  let responseStartedResolve = () => {};
  const responseStarted = new Promise((resolve) => {
    responseStartedResolve = resolve;
  });
  let releaseResponse = () => {};
  const responseGate = new Promise((resolve) => {
    releaseResponse = resolve;
  });
  const responses = [];
  const { browser, page } = await openBrowser({
    deliveries: { gap: content.bytes },
    async respond(_operation, request) {
      responses.push("dispatched");
      const answer = await content.respond(request);
      responseStartedResolve();
      await responseGate;
      return answer;
    },
  });
  try {
    await installContextScenario(page);
    await page.evaluate(() => globalThis.__contextControl.start("gap", false));
    await responseStarted;
    await page.evaluate(() => globalThis.__contextControl.publish(1, false));
    releaseResponse();
    const waitingToApply = await page.waitForFunction(
      () => globalThis.__contextRuns.gap.phase === "apply-response",
      { timeout: 15000 },
    );
    await waitingToApply.dispose();
    assert.deepEqual(responses, ["dispatched"]);
    const waitingState = await page.evaluate(() => globalThis.__contextRuns.gap);
    assert.equal(waitingState.openingStarts, 0, "unknown context has not opened plaintext");
    assert.equal(await page.$eval("#article-body", (target) => target.textContent), "Locked.");

    await page.evaluate(() => globalThis.__contextControl.publish(2, true));
    const run = await waitForRun(page, "gap");
    assert.equal(run.error, null);
    assert.deepEqual(run.outcomes, { bodytext: { status: "handled" } });
    assert.equal(run.openingStarts, 1);
    assert.deepEqual(responses, ["dispatched"]);
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      "<p>After response gap</p>",
    );
  } finally {
    await browser.close();
  }
});

test("replacement source with the same revision retires delayed old DOM work", async () => {
  const old = await publication("<p>Old account</p>");
  const next = await publication("<p>New account</p>");
  const responses = [];
  const { browser, page } = await openBrowser({
    deliveries: { old: old.bytes, next: next.bytes },
    async respond(operation, request) {
      responses.push(operation);
      return operation === "old" ? old.respond(request) : next.respond(request);
    },
  });
  try {
    await installContextScenario(page);
    await page.evaluate(() => globalThis.__contextControl.start("old", true));
    const entered = await page.waitForFunction(() => globalThis.__contextRuns.old.callbackEntered, {
      timeout: 15000,
    });
    await entered.dispose();
    assert.deepEqual(responses, ["old"]);
    await page.evaluate(() => {
      globalThis.__contextControl.replace();
      globalThis.__contextControl.start("next", false);
    });
    const nextRun = await waitForRun(page, "next");
    assert.equal(nextRun.error, null);
    assert.deepEqual(nextRun.outcomes, { bodytext: { status: "handled" } });
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      "<p>New account</p>",
    );
    await page.evaluate(() => globalThis.__contextControl.releaseHandler("old"));
    const oldRun = await waitForRun(page, "old");
    assert.equal(oldRun.error, null);
    assert.equal(oldRun.effects, 0);
    assert.equal(oldRun.outcomes.bodytext.status, "stale");
    assert.deepEqual(responses.sort(), ["next", "old"]);
    assert.equal(
      await page.$eval("#article-body", (target) => target.innerHTML),
      "<p>New account</p>",
    );
  } finally {
    await browser.close();
  }
});

test("popup-sensitive sign-in starts in the real click and account expiry needs no source event", async () => {
  const { browser, page } = await openBrowser({
    deliveries: {},
    async respond() {
      throw new Error("account hint dispatched DCA");
    },
  });
  try {
    await page.evaluate(() => {
      globalThis.document.body.innerHTML =
        '<button id="sign-in">Sign in</button><output id="account-state"></output>';
    });
    await page.evaluate(async (modules) => {
      const [{ createAccountSource }, { createAccountMenu }] = await Promise.all([
        import(modules.accountSource),
        import(modules.accountMenu),
      ]);
      const state = /** @type {any} */ (
        globalThis.__accountState = {
          now: 1500,
          observations: 0,
          actionOutcome: null,
          activation: false,
          popupAccepted: false,
        }
      );
      const source = createAccountSource(
        {
          sequence: 0,
          observedAt: 1000,
          validUntil: 2000,
          signedIn: "unknown",
          actionReady: { signIn: true, signOut: false, openAccount: false },
        },
        {
          signIn() {
            state.activation = globalThis.navigator.userActivation.isActive;
            const popup = globalThis.open("about:blank", "dca-sign-in");
            state.popupAccepted = popup !== null;
            return popup === null ? "failed" : "started";
          },
        },
      );
      const menu = createAccountMenu(source.provider, () => state.now);
      function render() {
        const current = menu.view();
        globalThis.document.getElementById("account-state").textContent = current.signedIn;
        globalThis.document.getElementById("sign-in").disabled = !current.actionReady.signIn;
      }
      source.provider.subscribe(() => {
        state.observations += 1;
        render();
      });
      globalThis.document.getElementById("sign-in").addEventListener("click", () => {
        const pending = menu.invoke("signIn");
        render();
        void pending.then((outcome) => {
          state.actionOutcome = outcome;
          render();
        });
      });
      /** @type {any} */ (globalThis).__accountControl = {
        publishSignedIn() {
          return source.publish({
            sequence: 1,
            observedAt: 1200,
            validUntil: 2000,
            signedIn: "yes",
            actionReady: { signIn: false, signOut: true, openAccount: false },
          });
        },
        expireWithoutEvent() {
          state.now = 2000;
          render();
        },
      };
      render();
    }, ROUTES);
    assert.equal(await page.$eval("#account-state", (node) => node.textContent), "unknown");
    assert.equal(await page.$eval("#sign-in", (button) => button.disabled), false);
    await page.click("#sign-in");
    await page.waitForFunction(() => globalThis.__accountState.actionOutcome !== null);
    let state = await page.evaluate(() => globalThis.__accountState);
    assert.equal(state.activation, true, "the action observed transient user activation");
    assert.equal(state.popupAccepted, true, "window.open succeeded synchronously in the click");
    assert.equal(state.actionOutcome, "started");
    assert.equal(await page.$eval("#account-state", (node) => node.textContent), "unknown");
    assert.equal(state.observations, 1, "action completion did not invent account state");
    await page.evaluate(() => globalThis.__accountControl.publishSignedIn());
    assert.equal(await page.$eval("#account-state", (node) => node.textContent), "yes");
    state = await page.evaluate(() => globalThis.__accountState);
    const observations = state.observations;
    await page.evaluate(() => globalThis.__accountControl.expireWithoutEvent());
    assert.equal(await page.$eval("#account-state", (node) => node.textContent), "unknown");
    state = await page.evaluate(() => globalThis.__accountState);
    assert.equal(state.observations, observations, "expiry did not require a source event");
    assert.equal(await page.$eval("#sign-in", (button) => button.disabled), true);
  } finally {
    await browser.close();
  }
});

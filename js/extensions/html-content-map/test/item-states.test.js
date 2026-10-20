// @ts-check
//
// The three item states of docs/spec-proposal--html-content-map.md Section 6.2, reached
// through the real publisher, the real issuer core and the base client
// pieces. `openMapItems` adds no key path: it asks the base resolver, sends
// one base unlock for what is missing and opens with the base opener, so each
// state below comes from an ordinary issuer decision or delivery defect.
//
// - `opened`: the issuer granted the item, or retained capability opens it;
// - `locked`: no key opened the item, whatever the cause. An omission, a
//   `notDelivered` family, a per-coordinate error, a refusal status and a
//   completed responses end here, because Section 6.2 forbids an item-level
//   policy or availability claim;
// - `failed`: the key resolved but the ciphertext, the record or the text is
//   defective.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { parseLockedDocument } from "../adapter-client/parse5Tree.js";
import { openMapItems } from "../core-client/mapItems.js";
import { treeDeliveryRoot } from "../core-client/treeDeliveryRoot.js";
import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { ISSUER_NAME, ORIGIN, articlePage, mapWorld } from "./world.js";

/**
 * A base client over the server-side tree of one locked page.
 *
 * @param {string} html
 * @param {any} transport
 * @param {object} [options]
 */
function clientFor(html, transport, options = {}) {
  const root = treeDeliveryRoot(parseLockedDocument(html), ORIGIN);
  return createBrowserClient({
    unlockUrl: "https://issuer.example/unlock",
    root,
    issuerName: ISSUER_NAME,
    transport,
    ...options,
  });
}

/** @param {any} world @param {{ name: string, value: string|Uint8Array }[]} items */
async function render(world, items) {
  const { html } = await world.publish({
    items: items.map((item) => ({ ...item, contentType: "text/html" })),
    page: articlePage,
  });
  return html;
}

const TWO = [
  { name: "bodytext", value: "<p>body</p>" },
  { name: "factbox", value: "<b>facts</b>" },
];

describe("Section 6.2: item states from issuer decisions", () => {
  test("a visible 5xx keeps independently opened cached content in failure evidence", async () => {
    const client = {
      dcaData: {
        contentItemFor: (/** @type {string} */ contentName) => ({
          contentName,
          contentType: "text/html",
          contentEncodings: [],
          nonce: "",
          contentAad: new Uint8Array(0),
        }),
      },
      reader: { extract: () => "ciphertext" },
      resolver: {
        resolveDetailed: async () => ({ missing: ["factbox"] }),
        contentKeyWithOriginFor: async () => ({ key: new Uint8Array(16) }),
      },
      opener: { open: async () => new TextEncoder().encode("<p>cached</p>") },
      unlock: async () => ({ status: 503, body: { error: "outage" }, application: null }),
    };
    await assert.rejects(
      () => openMapItems(/** @type {any} */ (client), ["bodytext", "factbox"]),
      (/** @type {any} */ error) =>
        error.code === "key_acquisition_failed" &&
        error.knownItems.bodytext.state === "opened" &&
        !Object.hasOwn(error.knownItems, "factbox"),
    );
  });
  test("granted items open; an item the issuer silently omits is locked", async () => {
    const world = await mapWorld();
    world.grant.contentNames = ["factbox"];
    const html = await render(world, TWO);
    const states = await openMapItems(clientFor(html, world.transport), ["bodytext", "factbox"]);
    assert.deepEqual(states, {
      bodytext: { state: "locked", text: null },
      factbox: { state: "opened", text: "<b>facts</b>", contentType: "text/html" },
    });
    assert.equal(world.unlocks.length, 1, "one base unlock for both map items");
    assert.deepEqual(
      Object.keys(world.unlocks[0].request.sealed.contentKeys).sort(),
      ["bodytext", "factbox"],
      "the request presents exactly the map items through the base builder",
    );
  });

  test("a family the issuer names in notDelivered leaves its item locked, with no reason attached", async () => {
    const world = await mapWorld({ periodKeyInput: true, notDeliveredReport: "complete" });
    world.grant.contentNames = [];
    world.grant.periods = false;
    const html = await render(world, TWO);
    /** @type {any[]} */
    const bodies = [];
    const transport = {
      /** @param {string} url @param {object} request */
      async post(url, request) {
        const answer = await world.transport.post(url, request);
        bodies.push(answer.body);
        return answer;
      },
    };
    const states = await openMapItems(clientFor(html, transport, { relayPeriodKeys: true }), [
      "bodytext",
    ]);
    assert.deepEqual(bodies[0].notDelivered, { premium: { reason: "denied" } });
    assert.deepEqual(states, { bodytext: { state: "locked", text: null } });
  });

  test("a per-coordinate key_retired leaves the item locked", async () => {
    const world = await mapWorld();
    world.grant.retired = true;
    const html = await render(world, TWO);
    const states = await openMapItems(clientFor(html, world.transport), ["bodytext"]);
    assert.equal(world.unlocks.length, 1);
    assert.deepEqual(states, { bodytext: { state: "locked", text: null } });
  });

  test("a sealed content key the issuer cannot open is unseal_failed, so locked", async () => {
    const world = await mapWorld();
    const html = await render(world, TWO);
    // Change the first character of the issuer's sealed envelope for bodytext.
    const tampered = html.replace(
      /("contentKeys":\{"bodytext":")([A-Za-z0-9_-])/,
      (_m, head, first) => `${head}${first === "A" ? "B" : "A"}`,
    );
    assert.notEqual(tampered, html);
    /** @type {any[]} */
    const bodies = [];
    const transport = {
      /** @param {string} url @param {object} request */
      async post(url, request) {
        const answer = await world.transport.post(url, request);
        bodies.push(answer.body);
        return answer;
      },
    };
    const states = await openMapItems(clientFor(tampered, transport), ["bodytext", "factbox"]);
    assert.equal(bodies[0].errors.bodytext.error, "unseal_failed");
    assert.deepEqual(states.bodytext, { state: "locked", text: null });
    assert.equal(states.factbox.state, "opened");
  });

  test("a completed refusal leaves items locked; a thrown acquisition fails the attempt", async () => {
    const world = await mapWorld();
    const html = await render(world, TWO);
    await assert.rejects(
      () =>
        openMapItems(
          clientFor(html, {
            post: async () => {
              throw new TypeError("fetch failed");
            },
          }),
          ["bodytext", "factbox"],
        ),
      (/** @type {any} */ error) => error.code === "key_acquisition_failed",
    );
    await assert.rejects(
      () =>
        openMapItems(
          clientFor(html, {
            post: async () => ({
              status: 200,
              contentType: "text/html",
              body: "<p>proxy page</p>",
            }),
          }),
          ["bodytext", "factbox"],
        ),
      (/** @type {any} */ error) => error.code === "key_acquisition_failed",
    );
    const answers = [
      async () => ({ status: 503, contentType: "application/json", body: { error: "down" } }),
    ];
    for (const post of answers) {
      await assert.rejects(
        () => openMapItems(clientFor(html, { post }), ["bodytext", "factbox"]),
        (/** @type {any} */ error) =>
          error.code === "key_acquisition_failed" &&
          Object.keys(error.knownItems ?? {}).length === 0,
      );
    }
  });

  test("retained period capability opens an item with no issuer contact", async () => {
    const world = await mapWorld({ periodKeyInput: true });
    world.grant.periods = true;
    const first = await render(world, TWO);
    const second = await render(world, TWO);
    const cache = new (await import("../../../adapter-client/PeriodKeyCache.js")).PeriodKeyCache();
    const options = { relayPeriodKeys: true, cache };
    await openMapItems(clientFor(first, world.transport, options), ["bodytext"]);
    assert.equal(world.unlocks.length, 1);
    world.grant.contentNames = [];
    world.grant.periods = false;
    const states = await openMapItems(clientFor(second, world.transport, options), ["bodytext"]);
    assert.equal(world.unlocks.length, 1, "no second issuer call");
    assert.deepEqual(states, {
      bodytext: { state: "opened", text: "<p>body</p>", contentType: "text/html" },
    });
  });

  test("a configured issuer the page does not carry opens held items and contacts no issuer", async () => {
    // The page names no route to the configured issuer. Held capability still
    // opens; a missing item ends as a failed acquisition, never a request.
    const world = await mapWorld({ periodKeyInput: true });
    world.grant.periods = true;
    const first = await render(world, TWO);
    const second = await render(world, TWO);
    const cache = new (await import("../../../adapter-client/PeriodKeyCache.js")).PeriodKeyCache();
    await openMapItems(clientFor(first, world.transport, { relayPeriodKeys: true, cache }), [
      "bodytext",
    ]);
    assert.equal(world.unlocks.length, 1);
    const absent = { issuerName: "absent_issuer", relayPeriodKeys: true };
    assert.deepEqual(
      await openMapItems(clientFor(second, world.transport, { ...absent, cache }), [
        "bodytext",
        "factbox",
      ]),
      {
        bodytext: { state: "opened", text: "<p>body</p>", contentType: "text/html" },
        factbox: { state: "opened", text: "<b>facts</b>", contentType: "text/html" },
      },
    );
    await assert.rejects(
      () => openMapItems(clientFor(second, world.transport, absent), ["bodytext"]),
      (/** @type {any} */ error) =>
        error.code === "key_acquisition_failed" && Object.keys(error.knownItems ?? {}).length === 0,
    );
    assert.equal(world.unlocks.length, 1, "no request reaches any issuer");
  });
});

describe("Section 6.2: failed items", () => {
  test("ciphertext that does not authenticate is failed, not locked", async () => {
    const world = await mapWorld();
    const html = await render(world, TWO);
    const tampered = html.replace(
      /(class="dca-sealed-content">\n\{"bodytext":")([A-Za-z0-9_-])/,
      (_m, head, first) => `${head}${first === "A" ? "B" : "A"}`,
    );
    assert.notEqual(tampered, html);
    const states = await openMapItems(clientFor(tampered, world.transport), [
      "bodytext",
      "factbox",
    ]);
    assert.equal(states.bodytext.state, "failed");
    assert.equal(states.factbox.state, "opened");
  });

  test("opened octets that are not UTF-8 or begin with a byte order mark are failed", async () => {
    const world = await mapWorld();
    const html = await render(world, [
      { name: "bodytext", value: Uint8Array.from([0xef, 0xbb, 0xbf, 0x3c, 0x70, 0x3e]) },
      { name: "factbox", value: Uint8Array.from([0x3c, 0xff, 0x3e]) },
    ]);
    const states = await openMapItems(clientFor(html, world.transport), ["bodytext", "factbox"]);
    assert.deepEqual(states, {
      bodytext: { state: "failed", text: null },
      factbox: { state: "failed", text: null },
    });
  });
});

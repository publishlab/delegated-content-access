// @ts-check
//
// Units for the direct content-handler interface in
// `experiments/browser-integration/implementation/content-handler.js`. Each
// test applies effects to a small fake page and asserts what the page shows,
// not only the reported outcome: a handler that reports `stale` but still
// wrote into the successor's node has failed. Races use deferred promises the
// test resolves itself, never timers.

import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import { createContentHandler } from "../implementation/content-handler.js";
import { utf8Encode } from "../../../core-shared/codec.js";

const BODY = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GRAPH = '{"unit":"EUR","points":[12,15,14]}';

/** A delivery object as the client parsed it; only contentData matters here. */
function delivery() {
  return {
    version: "1",
    resource: { resourceId: "article-a" },
    contentData: {
      bodytext: { contentType: "text/html", nonce: "n1" },
      graphData: { contentType: "application/json", nonce: "n2" },
    },
  };
}

/** One destination per name, and a log of every write in order. */
function page() {
  /** @type {Record<string, unknown>} */
  const nodes = {};
  /** @type {string[]} */
  const writes = [];
  return {
    nodes,
    writes,
    /**
     * @param {string} name
     * @param {unknown} value
     */
    write(name, value) {
      // an own member even for "__proto__", whose assignment would hit the setter
      Object.defineProperty(nodes, name, { value, enumerable: true, configurable: true });
      writes.push(name);
    },
  };
}

function deferred() {
  /** @type {(value?: unknown) => void} */
  let resolve = () => {};
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * A callback that writes its value through `commit` and reports what commit said.
 *
 * @param {ReturnType<typeof page>} view
 * @param {{ calls?: string[] }} [log]
 */
function writer(view, log = {}) {
  /** @param {import("../implementation/content-handler.js").ContentInput} input */
  return ({ contentName, value, commit }) => {
    log.calls?.push(contentName);
    return commit(() => view.write(contentName, value))
      ? { status: /** @type {const} */ ("handled") }
      : { status: /** @type {const} */ ("failed"), reason: "not_committed" };
  };
}

test("text and bytes reach their callbacks with the captured contentType", async () => {
  const view = page();
  /** @type {Array<{ contentName: string, contentType: string, value: unknown }>} */
  const seen = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    values: { bodytext: "strictUTF8" },
    targets: {
      bodytext: ({ contentName, contentType, value, commit }) => {
        seen.push({ contentName, contentType, value });
        commit(() => view.write(contentName, value));
        return { status: "handled" };
      },
      graphData: ({ contentName, contentType, value, commit }) => {
        seen.push({ contentName, contentType, value });
        commit(() => view.write(contentName, value));
        return { status: "handled" };
      },
    },
  });

  const outcomes = await connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });

  assert.deepEqual(outcomes, { bodytext: { status: "handled" }, graphData: { status: "handled" } });
  assert.equal(seen[0].contentType, "text/html");
  assert.equal(seen[0].value, BODY);
  // graphData has no mode, so it stays bytes: a default of text would hand
  // a JSON parser a string here and a binary consumer corrupted data.
  assert.equal(seen[1].contentType, "application/json");
  assert.ok(seen[1].value instanceof Uint8Array);
  assert.deepEqual(seen[1].value, utf8Encode(GRAPH));
  assert.equal(view.nodes.bodytext, BODY);
});

test("strict UTF-8 refuses malformed bytes before the callback and keeps the sibling", async () => {
  const view = page();
  /** @type {string[]} */
  const calls = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    values: { bodytext: "strictUTF8", graphData: "strictUTF8" },
    targets: { bodytext: writer(view, { calls }), graphData: writer(view, { calls }) },
  });

  // 0xC3 0x28 is an invalid two-byte sequence; a replacing decoder would
  // hand the callback "�(" and the page would show it.
  const outcomes = await connection.handleContent({
    bodytext: new Uint8Array([0x3c, 0x70, 0x3e, 0xc3, 0x28]),
    graphData: utf8Encode(GRAPH),
  });

  assert.deepEqual(outcomes, {
    bodytext: { status: "refused", reason: "invalid_utf8" },
    graphData: { status: "handled" },
  });
  assert.deepEqual(calls, ["graphData"]);
  assert.deepEqual(Object.keys(view.nodes), ["graphData"]);
});

test("strict UTF-8 keeps a leading byte order mark as text", async () => {
  /** @type {unknown} */
  let received;
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    values: { bodytext: "strictUTF8" },
    targets: {
      bodytext: ({ value, commit }) => {
        commit(() => {
          received = value;
        });
        return { status: "handled" };
      },
    },
  });

  await connection.handleContent({ bodytext: new Uint8Array([0xef, 0xbb, 0xbf, 0x41]) });

  assert.equal(received, "﻿A");
});

test("unknown names, missing targets and bad item types refuse only their own item", async () => {
  const view = page();
  /** @type {string[]} */
  const calls = [];
  const data = delivery();
  // the record exists, but its required contentType is missing
  data.contentData.graphData = /** @type {any} */ ({ nonce: "n2" });
  Object.assign(data.contentData, { sidebar: { contentType: "text/html", nonce: "n3" } });
  const connection = createContentHandler().connect({
    delivery: data,
    isEligible: () => true,
    targets: { bodytext: writer(view, { calls }), graphData: writer(view, { calls }) },
  });

  const outcomes = await connection.handleContent({
    caption: utf8Encode("x"),
    sidebar: utf8Encode("<aside/>"),
    graphData: utf8Encode(GRAPH),
    bodytext: utf8Encode(BODY),
  });

  assert.deepEqual(outcomes, {
    caption: { status: "refused", reason: "unknown_content" },
    sidebar: { status: "refused", reason: "no_target" },
    graphData: { status: "refused", reason: "invalid_content_type" },
    bodytext: { status: "handled" },
  });
  assert.deepEqual(calls, ["bodytext"]);
});

test("a value that is not bytes is refused for that item", async () => {
  const view = page();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: { bodytext: writer(view), graphData: writer(view) },
  });

  const outcomes = await connection.handleContent(
    /** @type {any} */ ({ bodytext: BODY, graphData: utf8Encode(GRAPH) }),
  );

  assert.deepEqual(outcomes, {
    bodytext: { status: "refused", reason: "invalid_bytes" },
    graphData: { status: "handled" },
  });
  assert.equal(view.nodes.bodytext, undefined);
});

test("names are own properties: inherited members are neither items nor targets", async () => {
  const view = page();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: { bodytext: writer(view) },
  });

  // `constructor` resolves through Object.prototype on every plain object; an
  // `in` check would find an item and a target for it.
  const outcomes = await connection.handleContent({ constructor: utf8Encode("x") });

  assert.deepEqual(Object.keys(outcomes), ["constructor"]);
  assert.deepEqual(outcomes.constructor, { status: "refused", reason: "unknown_content" });
});

test("a __proto__ content name is an ordinary item and an ordinary outcome member", async () => {
  const view = page();
  const data = JSON.parse('{"contentData":{"__proto__":{"contentType":"text/plain","nonce":"n"}}}');
  const connection = createContentHandler().connect({
    delivery: data,
    isEligible: () => true,
    targets: JSON.parse('{"__proto__":null}', (key, value) =>
      key === "__proto__" ? writer(view) : value,
    ),
    values: JSON.parse('{"__proto__":"strictUTF8"}'),
  });

  const content = JSON.parse('{"__proto__":null}', (key, value) =>
    key === "__proto__" ? utf8Encode("plain") : value,
  );
  const outcomes = await connection.handleContent(content);

  assert.ok(Object.hasOwn(outcomes, "__proto__"));
  assert.deepEqual(Object.getOwnPropertyDescriptor(outcomes, "__proto__")?.value, {
    status: "handled",
  });
  assert.equal(Object.getPrototypeOf(outcomes), Object.prototype);
  assert.equal(Object.getOwnPropertyDescriptor(view.nodes, "__proto__")?.value, "plain");
});

test("connect snapshots targets, modes and item types", async () => {
  const view = page();
  /** @type {string[]} */
  const types = [];
  const data = delivery();
  const targets = {
    /** @param {import("../implementation/content-handler.js").ContentInput} input */
    bodytext: ({ contentName, contentType, value, commit }) => {
      types.push(contentType);
      commit(() => view.write(contentName, value));
      return { status: /** @type {const} */ ("handled") };
    },
  };
  /** @type {Record<string, "bytes" | "strictUTF8">} */
  const values = { bodytext: "strictUTF8" };
  const connection = createContentHandler().connect({
    delivery: data,
    isEligible: () => true,
    targets,
    values,
  });

  data.contentData.bodytext.contentType = "application/octet-stream";
  data.contentData = /** @type {any} */ ({});
  targets.bodytext = () => {
    throw new Error("the retargeted callback ran");
  };
  values.bodytext = "bytes";

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.deepEqual(outcomes, { bodytext: { status: "handled" } });
  assert.deepEqual(types, ["text/html"]);
  assert.equal(view.nodes.bodytext, BODY);
});

test("submitted bytes are copied at call entry, before any await", async () => {
  const gate = deferred();
  /** @type {unknown[]} */
  const received = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    values: { graphData: "strictUTF8" },
    targets: {
      bodytext: async ({ value, commit }) => {
        await gate.promise;
        commit(() => received.push(value));
        return { status: "handled" };
      },
      graphData: ({ value, commit }) => {
        commit(() => received.push(value));
        return { status: "handled" };
      },
    },
  });

  const graph = utf8Encode(GRAPH);
  const pending = connection.handleContent({ bodytext: utf8Encode(BODY), graphData: graph });
  graph.fill(0x78); // the caller reuses its buffer while bodytext waits
  gate.resolve();
  const outcomes = await pending;

  assert.deepEqual(outcomes, { bodytext: { status: "handled" }, graphData: { status: "handled" } });
  assert.equal(received[1], GRAPH);
});

test("a Buffer is copied too: its slice() would share the caller's memory", async () => {
  const gate = deferred();
  /** @type {unknown[]} */
  const received = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    values: { graphData: "strictUTF8" },
    targets: {
      bodytext: async ({ commit }) => {
        await gate.promise;
        commit(() => {});
        return { status: "handled" };
      },
      graphData: ({ value, commit }) => {
        commit(() => received.push(value));
        return { status: "handled" };
      },
    },
  });

  const graph = Buffer.from(GRAPH);
  const pending = connection.handleContent({ bodytext: utf8Encode(BODY), graphData: graph });
  graph.fill(0x78);
  gate.resolve();
  await pending;

  assert.deepEqual(received, [GRAPH]);
});

test("eligibility lost after the last commit makes the settled item stale, without rollback", async () => {
  const view = page();
  const gate = deferred();
  const started = deferred();
  let eligible = true;
  /** @type {string[]} */
  const calls = [];
  const data = delivery();
  Object.assign(data.contentData, { caption: { contentType: "text/plain", nonce: "n" } });
  const connection = createContentHandler().connect({
    delivery: data,
    isEligible: () => eligible,
    targets: {
      graphData: writer(view, { calls }),
      bodytext: async ({ contentName, value, commit }) => {
        calls.push(contentName);
        commit(() => view.write(contentName, value));
        started.resolve();
        await gate.promise; // e.g. waiting for a layout pass after the write
        return { status: "handled" }; // no further commit, so no guard sees the change
      },
      caption: writer(view, { calls }),
    },
  });

  const pending = connection.handleContent({
    graphData: utf8Encode(GRAPH),
    bodytext: utf8Encode(BODY),
    caption: utf8Encode("A caption"),
  });
  await started.promise;
  eligible = false;
  gate.resolve();
  const outcomes = await pending;

  assert.deepEqual(outcomes, {
    graphData: { status: "handled" },
    bodytext: { status: "stale" },
    caption: { status: "stale" },
  });
  assert.deepEqual(view.writes, ["graphData", "bodytext"]); // the write stays; stale promises no rollback
  assert.deepEqual(calls, ["graphData", "bodytext"]);
});

test("a handled repeat is stale once eligibility has ended", async () => {
  const view = page();
  let eligible = true;
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => eligible,
    targets: { bodytext: writer(view) },
  });

  await connection.handleContent({ bodytext: utf8Encode(BODY) });
  eligible = false;
  const repeat = await connection.handleContent({ bodytext: utf8Encode(BODY) });
  eligible = true;
  const later = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.deepEqual(repeat, { bodytext: { status: "stale" } });
  assert.deepEqual(later, { bodytext: { status: "stale" } }); // the repeat retired the connection
  assert.deepEqual(view.writes, ["bodytext"]);
});

test("an effect after an await is checked at the effect, and lost eligibility goes stale", async () => {
  const view = page();
  const gate = deferred();
  const started = deferred();
  let eligible = true;
  /** @type {boolean[]} */
  const committed = [];
  /** @type {string[]} */
  const calls = [];
  const data = delivery();
  Object.assign(data.contentData, { caption: { contentType: "text/plain", nonce: "n" } });
  const connection = createContentHandler().connect({
    delivery: data,
    isEligible: () => eligible,
    targets: {
      graphData: writer(view, { calls }),
      bodytext: async ({ contentName, value, commit }) => {
        calls.push(contentName);
        started.resolve();
        await gate.promise; // e.g. waiting for a template
        committed.push(commit(() => view.write(contentName, value)));
        return { status: "handled" };
      },
      caption: writer(view, { calls }),
    },
  });

  const pending = connection.handleContent({
    graphData: utf8Encode(GRAPH),
    bodytext: utf8Encode(BODY),
    caption: utf8Encode("A caption"),
  });
  await started.promise;
  eligible = false; // navigation: the article's destination now belongs to another
  gate.resolve();
  const outcomes = await pending;

  assert.deepEqual(outcomes, {
    graphData: { status: "handled" },
    bodytext: { status: "stale" },
    caption: { status: "stale" },
  });
  assert.deepEqual(committed, [false]);
  assert.deepEqual(view.writes, ["graphData"]); // no rollback of the earlier sibling
  assert.deepEqual(calls, ["graphData", "bodytext"]);

  // the connection has ended, even if eligibility comes back
  eligible = true;
  const later = await connection.handleContent({ caption: utf8Encode("again") });
  assert.deepEqual(later, { caption: { status: "stale" } });
  assert.deepEqual(view.writes, ["graphData"]);
});

test("delayed article A cannot write into article B's node under the same name", async () => {
  const node = { owner: "A", html: "" };
  const gate = deferred();
  const started = deferred();
  const handler = createContentHandler();

  const a = handler.connect({
    delivery: delivery(),
    isEligible: () => node.owner === "A",
    values: { bodytext: "strictUTF8" },
    targets: {
      bodytext: async ({ value, commit }) => {
        started.resolve();
        await gate.promise;
        return commit(() => {
          node.html = String(value);
        })
          ? { status: "handled" }
          : { status: "failed", reason: "not_committed" };
      },
    },
  });
  const pendingA = a.handleContent({ bodytext: utf8Encode("<p>A</p>") });
  await started.promise;

  node.owner = "B"; // the host reassigns the node and so ends A's eligibility for it
  const b = handler.connect({
    delivery: delivery(),
    isEligible: () => node.owner === "B",
    values: { bodytext: "strictUTF8" },
    targets: {
      bodytext: ({ value, commit }) => {
        commit(() => {
          node.html = String(value);
        });
        return { status: "handled" };
      },
    },
  });
  const outcomeB = await b.handleContent({ bodytext: utf8Encode("<p>B</p>") });
  gate.resolve();
  const outcomeA = await pendingA;

  assert.deepEqual(outcomeB, { bodytext: { status: "handled" } });
  assert.deepEqual(outcomeA, { bodytext: { status: "stale" } });
  assert.equal(node.html, "<p>B</p>");
});

test("dispose during a callback stops its effects and ends the connection", async () => {
  const view = page();
  const gate = deferred();
  const started = deferred();
  /** @type {boolean[]} */
  const committed = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: async ({ contentName, value, commit }) => {
        committed.push(commit(() => view.write(`${contentName}:first`, value)));
        started.resolve();
        await gate.promise;
        committed.push(commit(() => view.write(`${contentName}:second`, value)));
        return { status: "handled" };
      },
      graphData: writer(view),
    },
  });

  const pending = connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });
  await started.promise;
  connection.dispose();
  gate.resolve();
  const outcomes = await pending;

  assert.deepEqual(outcomes, { bodytext: { status: "stale" }, graphData: { status: "stale" } });
  assert.deepEqual(committed, [true, false]);
  assert.deepEqual(view.writes, ["bodytext:first"]); // disposal removes nothing already shown
  connection.dispose(); // a second dispose is a no-op
});

test("calls after disposal are stale while the retired callback still waits", async () => {
  const view = page();
  const gate = deferred();
  const started = deferred();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: async ({ contentName, value, commit }) => {
        started.resolve();
        await gate.promise;
        commit(() => view.write(contentName, value));
        return { status: "handled" };
      },
      graphData: writer(view),
    },
  });

  const pending = connection.handleContent({ bodytext: utf8Encode(BODY) });
  await started.promise;
  connection.dispose();
  try {
    assert.deepEqual(await connection.handleContent({ graphData: utf8Encode(GRAPH) }), {
      graphData: { status: "stale" },
    });
    assert.deepEqual(await connection.handleContent({ bodytext: utf8Encode(BODY) }), {
      bodytext: { status: "stale" },
    });
    assert.deepEqual(view.writes, []);
  } finally {
    gate.resolve();
    assert.deepEqual(await pending, { bodytext: { status: "stale" } });
  }
  assert.deepEqual(view.writes, []);
});

test("a guard saved past its callback no longer applies effects", async () => {
  const view = page();
  /** @type {import("../implementation/content-handler.js").Commit[]} */
  const saved = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ contentName, value, commit }) => {
        saved.push(commit);
        commit(() => view.write(contentName, value));
        return { status: "handled" };
      },
    },
  });

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });
  const late = saved[0](() => view.write("late", "queued work"));

  assert.deepEqual(outcomes, { bodytext: { status: "handled" } });
  assert.equal(late, false);
  assert.deepEqual(view.writes, ["bodytext"]);
});

test("a callback that only queues work and never commits is not handled", async () => {
  /** @type {Array<() => void>} */
  const queue = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      graphData: ({ value }) => {
        queue.push(() => value);
        return { status: "handled" };
      },
    },
  });

  const outcomes = await connection.handleContent({ graphData: utf8Encode(GRAPH) });

  assert.deepEqual(outcomes, { graphData: { status: "failed", reason: "handled_without_effect" } });
});

test("partial effects fail and stay: a throw or a refusal after an effect", async () => {
  const view = page();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ commit }) => {
        commit(() => view.write("bodytext", "half"));
        throw new Error("template missing");
      },
      graphData: ({ commit }) => {
        commit(() => view.write("graphData", "half"));
        return { status: "refused", reason: "schema" };
      },
    },
  });

  const outcomes = await connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });

  assert.deepEqual(outcomes, {
    bodytext: { status: "failed", reason: "callback_error" },
    graphData: { status: "failed", reason: "refused_after_effect" },
  });
  assert.deepEqual(view.nodes, { bodytext: "half", graphData: "half" });
});

test("a throwing effect fails its item even when the callback swallows the error", async () => {
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ commit }) => {
        try {
          commit(() => {
            throw new Error("node detached");
          });
        } catch {
          // the callback hides the failure and claims success
        }
        return { status: "handled" };
      },
    },
  });

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.deepEqual(outcomes, { bodytext: { status: "failed", reason: "effect_error" } });
});

test("an asynchronous effect is misuse: it ran, and the item fails", async () => {
  /** @type {boolean[]} */
  const committed = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ commit }) => {
        committed.push(commit(/** @type {any} */ (async () => {})));
        return { status: "handled" };
      },
    },
  });

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.deepEqual(committed, [true]);
  assert.deepEqual(outcomes, { bodytext: { status: "failed", reason: "async_effect" } });
});

test("a rejected asynchronous effect fails its item and leaves no unhandled rejection", async () => {
  /** @type {unknown[]} */
  const unhandled = [];
  /** @param {unknown} reason */
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", onUnhandled);
  try {
    const connection = createContentHandler().connect({
      delivery: delivery(),
      isEligible: () => true,
      targets: {
        bodytext: ({ commit }) => {
          commit(/** @type {any} */ (() => Promise.reject(new Error("late write failed"))));
          return { status: "handled" };
        },
      },
    });

    const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });
    // one macrotask turn, so Node's unhandled-rejection check has run
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepEqual(outcomes, { bodytext: { status: "failed", reason: "async_effect" } });
    assert.deepEqual(unhandled, []);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

test("an eligibility check that disposes the connection blocks the effect even if it answers true", async () => {
  const view = page();
  /** @type {boolean[]} */
  const committed = [];
  let checks = 0;
  /** @type {import("../implementation/content-handler.js").ContentConnection} */
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => {
      checks += 1;
      if (checks === 2) connection.dispose(); // reentrant: the session code tears down mid-check
      return true;
    },
    targets: {
      bodytext: ({ contentName, value, commit }) => {
        committed.push(commit(() => view.write(contentName, value)));
        return { status: "handled" };
      },
    },
  });

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.deepEqual(committed, [false]);
  assert.deepEqual(outcomes, { bodytext: { status: "stale" } });
  assert.deepEqual(view.writes, []);
});

test("commit refuses a value that is not a function", async () => {
  /** @type {unknown} */
  let thrown;
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ commit }) => {
        try {
          commit(/** @type {any} */ ("write"));
        } catch (error) {
          thrown = error;
        }
        return { status: "refused", reason: "gave_up" };
      },
    },
  });

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.equal(/** @type {any} */ (thrown)?.code, "bad_config");
  assert.deepEqual(outcomes, { bodytext: { status: "refused", reason: "gave_up" } });
});

test("invalid callback outcomes fail, and a callback cannot claim stale", async () => {
  const view = page();
  /**
   * @param {unknown} result
   * @returns {import("../implementation/content-handler.js").ContentCallback}
   */
  const reporting =
    (result) =>
    ({ contentName, commit }) => {
      commit(() => view.write(contentName, "x"));
      return /** @type {any} */ (result);
    };
  const data = delivery();
  Object.assign(data.contentData, {
    c: { contentType: "text/plain", nonce: "n" },
    d: { contentType: "text/plain", nonce: "n" },
  });
  const connection = createContentHandler().connect({
    delivery: data,
    isEligible: () => true,
    targets: {
      bodytext: reporting({ status: "stale" }),
      graphData: reporting({ status: "handled", retry: true }),
      c: reporting({ status: "handled", reason: 7 }),
      d: reporting(null),
    },
  });

  const outcomes = await connection.handleContent({
    bodytext: utf8Encode("a"),
    graphData: utf8Encode("b"),
    c: utf8Encode("c"),
    d: utf8Encode("d"),
  });

  for (const name of ["bodytext", "graphData", "c", "d"]) {
    assert.deepEqual(outcomes[name], { status: "failed", reason: "invalid_outcome" }, name);
  }
  // the connection is still live: an invalid report is not lost eligibility
  assert.deepEqual(await connection.handleContent({ caption: utf8Encode("x") }), {
    caption: { status: "refused", reason: "unknown_content" },
  });
});

test("an outcome whose getter throws fails its own item and keeps the sibling", async () => {
  const view = page();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ contentName, commit }) => {
        commit(() => view.write(contentName, "x"));
        return /** @type {any} */ ({
          get status() {
            throw new Error("status getter");
          },
        });
      },
      graphData: writer(view),
    },
  });

  const outcomes = await connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });

  assert.deepEqual(outcomes, {
    bodytext: { status: "failed", reason: "invalid_outcome" },
    graphData: { status: "handled" },
  });
});

test("a callback reason passes through as a diagnostic string", async () => {
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      graphData: () => ({ status: "refused", reason: "unknown_schema" }),
    },
  });

  const outcomes = await connection.handleContent({ graphData: utf8Encode(GRAPH) });

  assert.deepEqual(outcomes, { graphData: { status: "refused", reason: "unknown_schema" } });
});

test("an overlapping call rejects before any effect and the active call completes", async () => {
  const view = page();
  const gate = deferred();
  /** @type {string[]} */
  const calls = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: async ({ contentName, value, commit }) => {
        calls.push(contentName);
        await gate.promise;
        commit(() => view.write(contentName, value));
        return { status: "handled" };
      },
      graphData: writer(view, { calls }),
    },
  });

  const first = connection.handleContent({ bodytext: utf8Encode(BODY) });
  await assert.rejects(connection.handleContent({ graphData: utf8Encode(GRAPH) }), {
    code: "overlapping_call",
  });
  gate.resolve();

  assert.deepEqual(await first, { bodytext: { status: "handled" } });
  assert.deepEqual(calls, ["bodytext"]);
  assert.deepEqual(view.writes, ["bodytext"]);
  // the rejected call left no active flag behind
  assert.deepEqual(await connection.handleContent({ graphData: utf8Encode(GRAPH) }), {
    graphData: { status: "handled" },
  });
});

test("repeats: identical bytes have no new effect, changed bytes are refused", async () => {
  const view = page();
  /** @type {string[]} */
  const calls = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: { bodytext: writer(view, { calls }) },
  });

  await connection.handleContent({ bodytext: utf8Encode(BODY) });
  const repeat = await connection.handleContent({ bodytext: utf8Encode(BODY) });
  const changed = await connection.handleContent({ bodytext: utf8Encode(`${BODY} `) });

  assert.deepEqual(repeat, { bodytext: { status: "handled" } });
  assert.deepEqual(changed, { bodytext: { status: "refused", reason: "changed_content" } });
  assert.deepEqual(calls, ["bodytext"]);
  assert.deepEqual(view.writes, ["bodytext"]);
});

test("a refused item can be resubmitted; a failed item does not run again here", async () => {
  const view = page();
  let ready = false;
  /** @type {string[]} */
  const calls = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {
      bodytext: ({ contentName, value, commit }) => {
        calls.push(contentName);
        if (!ready) return { status: "refused", reason: "template_not_loaded" };
        commit(() => view.write(contentName, value));
        return { status: "handled" };
      },
      graphData: ({ contentName, commit }) => {
        calls.push(contentName);
        commit(() => view.write(contentName, "half"));
        throw new Error("chart failed midway");
      },
    },
  });

  const first = await connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });
  ready = true;
  const second = await connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });

  assert.deepEqual(first, {
    bodytext: { status: "refused", reason: "template_not_loaded" },
    graphData: { status: "failed", reason: "callback_error" },
  });
  assert.deepEqual(second, {
    bodytext: { status: "handled" },
    graphData: { status: "refused", reason: "needs_reconciliation" },
  });
  assert.deepEqual(calls, ["bodytext", "graphData", "bodytext"]);
});

test("after dispose a handled repeat is stale: repeat bookkeeping is released", async () => {
  const view = page();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: { bodytext: writer(view) },
  });

  await connection.handleContent({ bodytext: utf8Encode(BODY) });
  connection.dispose();

  assert.deepEqual(await connection.handleContent({ bodytext: utf8Encode(BODY) }), {
    bodytext: { status: "stale" },
  });
  assert.deepEqual(view.writes, ["bodytext"]);
});

test("a throwing eligibility check fails closed and retires the connection", async () => {
  const view = page();
  let calls = 0;
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => {
      calls += 1;
      if (calls > 1) throw new Error("session store unavailable");
      return true;
    },
    targets: {
      bodytext: async ({ contentName, value, commit }) => {
        await Promise.resolve();
        return commit(() => view.write(contentName, value))
          ? { status: "handled" }
          : { status: "handled" }; // a careless callback that ignores commit's answer
      },
      graphData: writer(view),
    },
  });

  const outcomes = await connection.handleContent({
    bodytext: utf8Encode(BODY),
    graphData: utf8Encode(GRAPH),
  });

  assert.deepEqual(outcomes, {
    bodytext: { status: "failed", reason: "eligibility_check_failed" },
    graphData: { status: "stale" },
  });
  assert.deepEqual(view.writes, []);
  assert.deepEqual(await connection.handleContent({ graphData: utf8Encode(GRAPH) }), {
    graphData: { status: "stale" },
  });
});

test("eligibility is checked before the callback, and only true counts", async () => {
  /** @type {string[]} */
  const calls = [];
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => /** @type {any} */ (1), // truthy, but not the boolean the contract asks for
    targets: { bodytext: writer(page(), { calls }) },
  });

  const outcomes = await connection.handleContent({ bodytext: utf8Encode(BODY) });

  assert.deepEqual(outcomes, { bodytext: { status: "stale" } });
  assert.deepEqual(calls, []);
});

test("connect refuses invalid setup", () => {
  const handler = createContentHandler();
  const ok = { delivery: delivery(), isEligible: () => true, targets: {} };
  /** @type {Array<[string, unknown, string]>} */
  const cases = [
    ["setup is not an object", null, "bad_config"],
    ["unknown member", { ...ok, whenOutputPermitted: () => true }, "unsupported_option"],
    ["delivery without contentData", { ...ok, delivery: { version: "1" } }, "bad_config"],
    ["isEligible missing", { delivery: delivery(), targets: {} }, "bad_config"],
    ["target is not a function", { ...ok, targets: { bodytext: "#body" } }, "bad_config"],
    ["targets is an array", { ...ok, targets: [] }, "bad_config"],
    [
      "unknown value mode",
      { ...ok, targets: { bodytext: () => null }, values: { bodytext: "utf8" } },
      "bad_config",
    ],
    ["value mode without a target", { ...ok, values: { bodytext: "strictUTF8" } }, "bad_config"],
  ];
  for (const [label, setup, code] of cases) {
    assert.throws(() => handler.connect(/** @type {any} */ (setup)), { code }, label);
  }
});

test("createContentHandler refuses options it does not support", () => {
  assert.throws(() => createContentHandler(/** @type {any} */ ({ registry: {} })), {
    code: "unsupported_option",
  });
  assert.throws(() => createContentHandler(/** @type {any} */ (null)), { code: "bad_config" });
});

test("a throwing input getter rejects the promised result before effects", async () => {
  const view = page();
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: { bodytext: writer(view), graphData: writer(view) },
  });
  const failure = new Error("input getter failed");
  const content = {
    bodytext: utf8Encode(BODY),
    get graphData() {
      throw failure;
    },
  };
  const pending = connection.handleContent(content);
  assert.ok(pending instanceof Promise);
  await assert.rejects(pending, (error) => error === failure);
  assert.deepEqual(view.writes, []);
  assert.deepEqual(await connection.handleContent({ bodytext: utf8Encode(BODY) }), {
    bodytext: { status: "handled" },
  });
});

test("handleContent rejects a submission that is not a map", async () => {
  const connection = createContentHandler().connect({
    delivery: delivery(),
    isEligible: () => true,
    targets: {},
  });

  await assert.rejects(connection.handleContent(/** @type {any} */ (utf8Encode(BODY))), {
    code: "bad_config",
  });
  await assert.rejects(connection.handleContent(/** @type {any} */ (null)), {
    code: "bad_config",
  });
});

for (const immediateEffect of [true, false]) {
  test(`synchronous callback return closes its saved guard before queued microtasks (${immediateEffect})`, async () => {
    const writes = [];
    let lateCommit = null;
    const connection = createContentHandler().connect({
      delivery: delivery(),
      isEligible: () => true,
      targets: {
        bodytext({ commit }) {
          if (immediateEffect) commit(() => writes.push("inside"));
          queueMicrotask(() => {
            lateCommit = commit(() => writes.push("after-return"));
          });
          return { status: "handled" };
        },
      },
    });
    const result = await connection.handleContent({ bodytext: utf8Encode(BODY) });
    assert.deepEqual(writes, immediateEffect ? ["inside"] : []);
    assert.equal(lateCommit, false);
    assert.equal(result.bodytext.status, immediateEffect ? "handled" : "failed");
    connection.dispose();
  });
}

for (const retirement of ["dispose", "eligibility"]) {
  test(`outcome normalization precedes final retirement decision (${retirement})`, async () => {
    const view = page();
    let eligible = true;
    const connection = createContentHandler().connect({
      delivery: delivery(),
      isEligible: () => eligible,
      targets: {
        bodytext({ commit }) {
          commit(() => view.write("bodytext", "partial"));
          return {
            get status() {
              if (retirement === "dispose") connection.dispose();
              else eligible = false;
              return "handled";
            },
          };
        },
        graphData: writer(view),
      },
    });
    const result = await connection.handleContent({
      bodytext: utf8Encode(BODY),
      graphData: utf8Encode(GRAPH),
    });
    assert.equal(result.bodytext.status, "stale");
    assert.equal(result.graphData.status, "stale");
    assert.deepEqual(view.writes, ["bodytext"]); // completed effect stays, never rolled back
    assert.equal(
      (await connection.handleContent({ bodytext: utf8Encode(BODY) })).bodytext.status,
      "stale",
    );
  });
}

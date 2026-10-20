// @ts-check
//
// Units for the optional page registry in
// `experiments/browser-integration/implementation/registry.js`. Each test
// installs on its own host object, so no test leaks state through globalThis.
// Ordering tests log every listener call and assert the whole sequence: an
// implementation that delivers nested notifications, or that hands a late
// subscriber an old change, produces a different log.

import test from "node:test";
import assert from "node:assert/strict";

import { installRegistry } from "../implementation/registry.js";

/** @typedef {import("../implementation/registry.js").RegistryEntry} RegistryEntry */

const HANDLER = { interface: "dca.content-handler", major: 1, name: "article" };
const SOURCE = { interface: "dca.access-context", major: 1, name: "site" };

/** @returns {Record<string, any>} */
function host() {
  return {};
}

/** @param {RegistryEntry} entry */
function label(entry) {
  return entry.provider === null ? "empty" : /** @type {any} */ (entry.provider).id;
}

test("installs once per host and keeps unrelated namespace members", () => {
  const page = host();
  page.DelegatedContentAccess = { version: "other-sdk" };

  const first = installRegistry(page);
  const second = installRegistry(page);

  assert.equal(first, second);
  assert.equal(first.apiMajor, 1);
  assert.equal(page.DelegatedContentAccess.version, "other-sdk");
  assert.equal(page.DelegatedContentAccess.clientRegistry, first);
});

test("installs on globalThis by default", () => {
  const existed = Object.hasOwn(globalThis, "DelegatedContentAccess");
  try {
    const registry = installRegistry();
    assert.equal(/** @type {any} */ (globalThis).DelegatedContentAccess.clientRegistry, registry);
  } finally {
    if (!existed) delete (/** @type {any} */ (globalThis).DelegatedContentAccess);
  }
});

test("installs an own member even when the host inherits a setter for the name", () => {
  const page = Object.create({
    set DelegatedContentAccess(_value) {
      throw new Error("the inherited setter ran");
    },
  });

  const registry = installRegistry(page);

  assert.ok(Object.hasOwn(page, "DelegatedContentAccess"));
  assert.equal(page.DelegatedContentAccess.clientRegistry, registry);
});

test("a compatible registry installed by another script is used as it is", () => {
  const foreign = {
    apiMajor: 1,
    register: () => () => {},
    lookup: () => null,
    observe: () => () => {},
    keys: () => [],
  };
  const page = host();
  page.DelegatedContentAccess = { clientRegistry: foreign };

  assert.equal(installRegistry(page), foreign);
});

test("refuses an incompatible namespace or registry, including explicit undefined and null", () => {
  const methods = {
    register: () => () => {},
    lookup: () => null,
    observe: () => () => {},
    keys: () => [],
  };
  /** @type {Array<[string, Record<string, unknown>]>} */
  const cases = [
    ["namespace undefined", { DelegatedContentAccess: undefined }],
    ["namespace null", { DelegatedContentAccess: null }],
    ["namespace string", { DelegatedContentAccess: "dca" }],
    ["registry undefined", { DelegatedContentAccess: { clientRegistry: undefined } }],
    ["registry null", { DelegatedContentAccess: { clientRegistry: null } }],
    ["apiMajor 2", { DelegatedContentAccess: { clientRegistry: { apiMajor: 2, ...methods } } }],
    ["apiMajor missing", { DelegatedContentAccess: { clientRegistry: { ...methods } } }],
    [
      "keys missing",
      {
        DelegatedContentAccess: {
          clientRegistry: { apiMajor: 1, ...methods, keys: undefined },
        },
      },
    ],
  ];
  for (const [name, page] of cases) {
    const before = page.DelegatedContentAccess;
    assert.throws(() => installRegistry(page), { code: "incompatible_registry" }, name);
    assert.equal(page.DelegatedContentAccess, before, `${name}: left in place`);
  }
  assert.throws(() => installRegistry(/** @type {any} */ ("window")), { code: "bad_config" });
});

test("either load order finds the same provider under the configured key", () => {
  const handler = { id: "handler" };

  // the handler script loads first
  const early = host();
  installRegistry(early).register(HANDLER, handler);
  assert.equal(installRegistry(early).lookup(HANDLER), handler);

  // the client script loads first and observes; the handler arrives later
  const late = host();
  /** @type {string[]} */
  const seen = [];
  installRegistry(late).observe(HANDLER, (entry) => seen.push(label(entry)));
  installRegistry(late).register(HANDLER, handler);

  assert.deepEqual(seen, ["empty", "handler"]);
  assert.equal(installRegistry(late).lookup(HANDLER), handler);
});

test("lookup is exact: another name or major is not a fallback", () => {
  const registry = installRegistry(host());
  registry.register({ interface: "dca.content-handler", major: 1, name: "sidebar" }, { id: "s" });
  registry.register({ interface: "dca.content-handler", major: 2, name: "article" }, { id: "v2" });

  assert.equal(registry.lookup(HANDLER), null);
});

test("keys with delimiter-like text stay distinct tuples", () => {
  const registry = installRegistry(host());
  const one = { interface: "a|b", major: 1, name: "c" };
  const two = { interface: "a", major: 1, name: "b|c" };
  registry.register(one, { id: "one" });
  registry.register(two, { id: "two" });

  assert.equal(/** @type {any} */ (registry.lookup(one)).id, "one");
  assert.equal(/** @type {any} */ (registry.lookup(two)).id, "two");
});

test("refuses keys that are not exactly three valid own members", () => {
  const registry = installRegistry(host());
  /** @type {Array<[string, unknown]>} */
  const cases = [
    ["null", null],
    ["string", "dca.content-handler/1/article"],
    [
      "function",
      Object.defineProperties(function key() {}, {
        interface: { value: HANDLER.interface, enumerable: true },
        major: { value: 1, enumerable: true },
        name: { value: "article", enumerable: true },
      }),
    ],
    ["extra member", { ...HANDLER, version: "1.0" }],
    ["nonenumerable extra member", Object.defineProperty({ ...HANDLER }, "extra", { value: true })],
    ["symbol extra member", { ...HANDLER, [Symbol("extra")]: true }],
    ["missing name", { interface: "dca.content-handler", major: 1 }],
    ["inherited members", Object.create(HANDLER)],
    ["empty interface", { ...HANDLER, interface: "" }],
    ["empty name", { ...HANDLER, name: "" }],
    ["major 0", { ...HANDLER, major: 0 }],
    ["major 1.5", { ...HANDLER, major: 1.5 }],
    ["major string", { ...HANDLER, major: "1" }],
    ["major unsafe", { ...HANDLER, major: 2 ** 53 }],
    ["interface number", { ...HANDLER, interface: 7 }],
  ];
  for (const [name, key] of cases) {
    assert.throws(
      () => registry.register(/** @type {any} */ (key), {}),
      { code: "bad_config" },
      name,
    );
    assert.throws(() => registry.lookup(/** @type {any} */ (key)), { code: "bad_config" }, name);
    assert.throws(
      () => registry.observe(/** @type {any} */ (key), () => {}),
      { code: "bad_config" },
      name,
    );
  }
  assert.deepEqual(registry.keys(), []);
});

test("refuses providers that are not objects or functions, and keeps functions", () => {
  const registry = installRegistry(host());
  for (const provider of [null, undefined, "handler", 7, true]) {
    assert.throws(() => registry.register(HANDLER, /** @type {any} */ (provider)), {
      code: "bad_config",
    });
  }
  const fn = () => {};
  registry.register(HANDLER, fn);
  assert.equal(registry.lookup(HANDLER), fn);
});

test("keys are copied on admission: editing the caller's key moves nothing", () => {
  const registry = installRegistry(host());
  const key = { ...HANDLER };
  registry.register(key, { id: "handler" });
  key.name = "sidebar";

  assert.equal(/** @type {any} */ (registry.lookup(HANDLER)).id, "handler");
  assert.equal(registry.lookup(key), null);

  const [listed] = registry.keys();
  assert.deepEqual(listed, HANDLER);
  assert.ok(Object.isFrozen(listed));
  assert.throws(() => {
    /** @type {any} */ (listed).name = "sidebar";
  }, TypeError);
  assert.equal(/** @type {any} */ (registry.lookup(HANDLER)).id, "handler");
});

test("the registry object and its entries are frozen", () => {
  const registry = installRegistry(host());
  /** @type {RegistryEntry[]} */
  const entries = [];
  registry.observe(HANDLER, (entry) => entries.push(entry));
  registry.register(HANDLER, { id: "handler" });

  assert.ok(Object.isFrozen(registry));
  assert.ok(entries.every((entry) => Object.isFrozen(entry)));
  assert.throws(() => {
    /** @type {any} */ (entries[1]).provider = { id: "other" };
  }, TypeError);
});

test("keys() lists current registrations for diagnostics", () => {
  const registry = installRegistry(host());
  const dispose = registry.register(HANDLER, { id: "handler" });
  registry.register(SOURCE, { id: "source" });
  assert.deepEqual(registry.keys(), [HANDLER, SOURCE]);

  dispose();
  assert.deepEqual(registry.keys(), [SOURCE]);
});

test("a duplicate registration throws and changes nothing", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const seen = [];
  registry.register(HANDLER, { id: "first" });
  registry.observe(HANDLER, (entry) => seen.push(label(entry)));

  assert.throws(() => registry.register(HANDLER, { id: "second" }), {
    code: "duplicate_registration",
  });
  assert.equal(/** @type {any} */ (registry.lookup(HANDLER)).id, "first");
  assert.deepEqual(seen, ["first"]);
});

test("replacement: a stale disposer cannot remove its successor, even with the same provider", () => {
  const registry = installRegistry(host());
  const provider = { id: "handler" };
  /** @type {RegistryEntry[]} */
  const entries = [];
  registry.observe(HANDLER, (entry) => entries.push(entry));

  const disposeOld = registry.register(HANDLER, provider);
  disposeOld();
  registry.register(HANDLER, provider); // same object, new registration
  disposeOld();
  disposeOld();

  assert.equal(registry.lookup(HANDLER), provider);
  assert.deepEqual(entries.map(label), ["empty", "handler", "empty", "handler"]);
  const [, first, , second] = entries;
  assert.equal(first.provider, second.provider);
  assert.notEqual(first.registration, second.registration);
  assert.notEqual(first.registration, null);
  assert.notEqual(second.registration, null);
});

test("observe replays synchronously before it returns, passing the returned stop", () => {
  const registry = installRegistry(host());
  registry.register(HANDLER, { id: "handler" });
  /** @type {string[]} */
  const log = [];
  /** @type {Array<() => void>} */
  const stops = [];

  const stop = registry.observe(HANDLER, (entry, s) => {
    log.push(label(entry));
    stops.push(s);
  });
  log.push("returned");

  assert.deepEqual(log, ["handler", "returned"]);
  assert.equal(stops[0], stop);
});

test("stop is idempotent and ends all later calls", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const seen = [];
  const stop = registry.observe(HANDLER, (entry) => seen.push(label(entry)));
  stop();
  stop();
  registry.register(HANDLER, { id: "handler" });

  assert.deepEqual(seen, ["empty"]);
});

test("stop during replay prevents every later notification", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const seen = [];
  registry.observe(HANDLER, (entry, stop) => {
    seen.push(label(entry));
    stop();
  });
  registry.register(HANDLER, { id: "handler" });

  assert.deepEqual(seen, ["empty"]);
});

test("a mutation inside a listener queues behind the current notification", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const log = [];
  registry.observe(HANDLER, (entry) => {
    log.push(`A:${label(entry)}`);
    if (entry.provider !== null) {
      registry.register(SOURCE, { id: "source" });
      log.push("A:registered");
    }
  });
  registry.observe(HANDLER, (entry) => log.push(`B:${label(entry)}`));
  registry.observe(SOURCE, (entry) => log.push(`C:${label(entry)}`));
  log.length = 0;

  registry.register(HANDLER, { id: "handler" });

  // Nested delivery would put C:source before A:registered and B:handler.
  assert.deepEqual(log, ["A:handler", "A:registered", "B:handler", "C:source"]);
});

test("a replacement made by a listener reaches every observer in mutation order", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const log = [];
  const disposeFirst = registry.register(HANDLER, { id: "first" });
  registry.observe(HANDLER, (entry) => log.push(`A:${label(entry)}`));
  registry.observe(SOURCE, (entry) => {
    if (entry.provider === null) return;
    disposeFirst();
    registry.register(HANDLER, { id: "second" });
    log.push("S:replaced");
  });
  registry.observe(HANDLER, (entry) => log.push(`B:${label(entry)}`));
  log.length = 0;

  registry.register(SOURCE, { id: "source" });

  assert.deepEqual(log, ["S:replaced", "A:empty", "B:empty", "A:second", "B:second"]);
});

test("a mutation inside replay is queued until the replay returns", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const log = [];
  registry.observe(HANDLER, (entry) => {
    log.push(`replay-start:${label(entry)}`);
    if (entry.provider === null) registry.register(HANDLER, { id: "handler" });
    log.push(`replay-end:${label(entry)}`);
  });
  log.push("returned");

  assert.deepEqual(log, [
    "replay-start:empty",
    "replay-end:empty",
    "replay-start:handler",
    "replay-end:handler",
    "returned",
  ]);
});

test("a throwing listener does not stop the others or the mutation", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const seen = [];
  registry.observe(HANDLER, () => {
    throw new Error("listener bug");
  });
  registry.observe(HANDLER, (entry) => seen.push(label(entry)));

  assert.doesNotThrow(() => registry.register(HANDLER, { id: "handler" }));
  assert.deepEqual(seen, ["empty", "handler"]);
  assert.equal(/** @type {any} */ (registry.lookup(HANDLER)).id, "handler");
});

test("a throwing error reporter does not stop the others or the mutation", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "reportError");
  /** @type {unknown[]} */
  const reported = [];
  Object.defineProperty(globalThis, "reportError", {
    configurable: true,
    writable: true,
    value: (/** @type {unknown} */ error) => {
      reported.push(error);
      throw new Error("reporter bug");
    },
  });
  try {
    const registry = installRegistry(host());
    /** @type {string[]} */
    const seen = [];
    registry.observe(HANDLER, (entry) => {
      if (entry.provider !== null) throw new Error("listener bug");
    });
    registry.observe(HANDLER, (entry) => seen.push(label(entry)));

    assert.doesNotThrow(() => registry.register(HANDLER, { id: "handler" }));
    assert.deepEqual(seen, ["empty", "handler"]);
    assert.equal(reported.length, 1);
  } finally {
    if (original) Object.defineProperty(globalThis, "reportError", original);
    else delete (/** @type {any} */ (globalThis).reportError);
  }
});

test("a listener that throws during replay still observes later changes", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const seen = [];
  const stop = registry.observe(HANDLER, (entry) => {
    seen.push(label(entry));
    if (entry.provider === null) throw new Error("not ready");
  });
  registry.register(HANDLER, { id: "handler" });

  assert.equal(typeof stop, "function");
  assert.deepEqual(seen, ["empty", "handler"]);
});

test("observing inside a notification replays at once and skips changes queued earlier", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const log = [];
  registry.observe(HANDLER, (entry) => {
    if (entry.provider === null) return;
    registry.register(SOURCE, { id: "source" }); // queued for current SOURCE observers
    registry.observe(SOURCE, (sourceEntry) => log.push(`late:${label(sourceEntry)}`));
    log.push("subscribed");
  });
  registry.observe(SOURCE, (entry) => log.push(`early:${label(entry)}`));
  log.length = 0;

  registry.register(HANDLER, { id: "handler" });

  // The late observer replays the current entry inside the notification and is
  // not a recipient of the queued registration it already saw by replay.
  assert.deepEqual(log, ["late:source", "subscribed", "early:source"]);
});

test("observing during another observer's replay replays synchronously too", () => {
  const registry = installRegistry(host());
  registry.register(SOURCE, { id: "source" });
  /** @type {string[]} */
  const log = [];

  registry.observe(HANDLER, () => {
    log.push("outer");
    registry.observe(SOURCE, (entry) => log.push(`inner:${label(entry)}`));
    log.push("outer-end");
  });

  assert.deepEqual(log, ["outer", "inner:source", "outer-end"]);
});

test("stopping inside a notification skips that listener's queued changes", () => {
  const registry = installRegistry(host());
  /** @type {string[]} */
  const log = [];
  /** @type {() => void} */
  let stopB = () => {};
  registry.observe(HANDLER, (entry) => {
    log.push(`A:${label(entry)}`);
    if (label(entry) === "first") {
      stopB();
      registry.register(SOURCE, { id: "source" });
    }
  });
  stopB = registry.observe(HANDLER, (entry) => log.push(`B:${label(entry)}`));
  log.length = 0;

  registry.register(HANDLER, { id: "first" });

  assert.deepEqual(log, ["A:first"]);
});

test("observe refuses a listener that is not a function", () => {
  const registry = installRegistry(host());
  assert.throws(() => registry.observe(HANDLER, /** @type {any} */ ("callback")), {
    code: "bad_config",
  });
});

test("lookup of an absent key is null, before and after a registration ends", () => {
  const registry = installRegistry(host());
  assert.equal(registry.lookup(HANDLER), null);
  const dispose = registry.register(HANDLER, { id: "handler" });
  dispose();
  assert.equal(registry.lookup(HANDLER), null);
});

// @ts-check
//
// The optional page registry in the browser-integration specification, Section 3.
// Independently loaded scripts find the providers the publisher configured
// under `globalThis.DelegatedContentAccess.clientRegistry`.
//
// The content-handler script registers under its configured key, say
// `{ interface: "dca.content-handler", major: 1, name: "article" }`; the client
// script observes that same key. Whichever loads first installs the registry,
// and the other finds it. If the handler arrives late, the observer's replay
// reports an empty entry and a later notification reports the provider. The
// observer never takes "whatever registered last": it names the exact key.
//
// The registry authenticates no provider and isolates no page script. A
// registration says only that some page code put this provider under this key.

import { dcaError } from "../../../core-shared/errors.js";

/**
 * An exact configured tuple. The registry copies and freezes it on admission.
 *
 * @typedef {object} RegistryKey
 * @property {string} interface - nonempty, for example "dca.content-handler"
 * @property {number} major - a positive safe integer
 * @property {string} name - nonempty, for example "article"
 */

/**
 * The registration under one key. Both members are null when the key is empty.
 * `registration` is a fresh opaque token per registration, also when the same
 * provider object registers again, so a replacement is visible.
 *
 * @template {object} [Provider=object]
 * @typedef {object} RegistryEntry
 * @property {Provider | null} provider
 * @property {object | null} registration
 */

/**
 * Receives the current entry once at subscription, then each presence change.
 * `stop` is the same function `observe` returns.
 *
 * @template {object} [Provider=object]
 * @callback RegistryListener
 * @param {RegistryEntry<Provider>} entry
 * @param {() => void} stop
 * @returns {void}
 */

/**
 * @typedef {object} ClientRegistry
 * @property {1} apiMajor
 * @property {<Provider extends object>(key: RegistryKey, provider: Provider) => () => void} register
 *   Throws when the key is taken. The returned disposer is idempotent and only
 *   ever removes its own registration.
 * @property {<Provider extends object>(key: RegistryKey) => Provider | null} lookup
 * @property {<Provider extends object>(key: RegistryKey, listener: RegistryListener<Provider>) => () => void} observe
 * @property {() => RegistryKey[]} keys - diagnostics only, never provider selection
 */

const NAMESPACE = "DelegatedContentAccess";
const REGISTRY = "clientRegistry";
const KEY_MEMBERS = ["interface", "major", "name"];
const REGISTRY_METHODS = ["register", "lookup", "observe", "keys"];

/** @type {RegistryEntry} */
const EMPTY = Object.freeze({ provider: null, registration: null });

/**
 * Finds a compatible registry on `host` or installs a new one. It keeps an
 * existing namespace and its unrelated members. It refuses a namespace that is
 * not an object and a registry without `apiMajor` 1 and the four methods. An
 * explicit `undefined` or `null` counts as an installation, and an invalid one.
 *
 * @param {object} [host]
 * @returns {ClientRegistry}
 */
export function installRegistry(host = globalThis) {
  if (!isObject(host)) {
    throw dcaError("bad_config", "the registry host is an object");
  }
  if (!Object.hasOwn(host, NAMESPACE)) {
    defineOwn(host, NAMESPACE, {});
  }
  const namespace = /** @type {Record<string, unknown>} */ (host)[NAMESPACE];
  if (!isObject(namespace)) {
    throw dcaError("incompatible_registry", `${NAMESPACE} on the host is not an object`);
  }
  if (!Object.hasOwn(namespace, REGISTRY)) {
    defineOwn(namespace, REGISTRY, createRegistry());
  }
  const registry = /** @type {Record<string, unknown>} */ (namespace)[REGISTRY];
  if (!isCompatible(registry)) {
    throw dcaError("incompatible_registry", `${NAMESPACE}.${REGISTRY} is not a version 1 registry`);
  }
  return /** @type {ClientRegistry} */ (registry);
}

/** @returns {ClientRegistry} */
function createRegistry() {
  /** @type {Map<string, { key: RegistryKey, entry: RegistryEntry }>} */
  const slots = new Map();
  /** @type {Map<string, Set<Observer>>} */
  const observers = new Map();
  /** @type {Array<{ recipients: Observer[], entry: RegistryEntry }>} */
  const queue = [];
  let delivering = 0;

  /**
   * Runs `deliver` with mutations queued, then drains the queue once the
   * outermost delivery ends. Registration and disposal notifications queue;
   * observe still replays synchronously when called during another delivery.
   *
   * @param {() => void} deliver
   */
  function delivery(deliver) {
    delivering += 1;
    try {
      deliver();
    } finally {
      delivering -= 1;
    }
    if (delivering > 0) return;
    delivering += 1;
    try {
      for (let next = queue.shift(); next; next = queue.shift()) {
        for (const observer of next.recipients) observer.call(next.entry);
      }
    } finally {
      delivering -= 1;
    }
  }

  /**
   * Queues the new entry for the observers subscribed now. One who subscribes
   * later gets the then-current entry by replay instead.
   *
   * @param {string} id
   * @param {RegistryEntry} entry
   */
  function changed(id, entry) {
    queue.push({ recipients: [...(observers.get(id) ?? [])], entry });
    delivery(() => {});
  }

  /** @type {ClientRegistry} */
  const registry = {
    apiMajor: 1,

    register(key, provider) {
      const admitted = admitKey(key);
      if (!isObject(provider)) {
        throw dcaError("bad_config", "a registered provider is an object or a function");
      }
      const id = keyId(admitted);
      if (slots.has(id)) {
        throw dcaError(
          "duplicate_registration",
          `${id} is already registered; dispose it before replacing it`,
        );
      }
      /** @type {RegistryEntry} */
      const entry = Object.freeze({ provider, registration: Object.freeze({}) });
      slots.set(id, { key: admitted, entry });
      changed(id, entry);
      return () => {
        // A successor under the same key holds another token, so a stale
        // disposer leaves it in place.
        if (slots.get(id)?.entry !== entry) return;
        slots.delete(id);
        changed(id, EMPTY);
      };
    },

    lookup(key) {
      const slot = slots.get(keyId(admitKey(key)));
      return /** @type {any} */ (slot?.entry.provider ?? null);
    },

    observe(key, listener) {
      const id = keyId(admitKey(key));
      if (typeof listener !== "function") {
        throw dcaError("bad_config", "an observer is a function");
      }
      const observer = new Observer(/** @type {RegistryListener} */ (listener), () => {
        const subscribed = observers.get(id);
        subscribed?.delete(observer);
        if (subscribed?.size === 0) observers.delete(id);
      });
      if (!observers.has(id)) observers.set(id, new Set());
      observers.get(id)?.add(observer);
      delivery(() => observer.call(slots.get(id)?.entry ?? EMPTY));
      return observer.stop;
    },

    keys() {
      return [...slots.values()].map((slot) => slot.key);
    },
  };
  return Object.freeze(registry);
}

class Observer {
  #stopped = false;

  /**
   * @param {RegistryListener} listener
   * @param {() => void} unsubscribe
   */
  constructor(listener, unsubscribe) {
    this.listener = listener;
    /** The one stop function, returned by observe and passed to every call. */
    this.stop = () => {
      if (this.#stopped) return;
      this.#stopped = true;
      unsubscribe();
    };
  }

  /**
   * Calls the listener unless it stopped. Its exception stays here, so the
   * other listeners and the registry operation that caused the change go on.
   *
   * @param {RegistryEntry} entry
   */
  call(entry) {
    if (this.#stopped) return;
    try {
      this.listener(entry, this.stop);
    } catch (error) {
      // A browser reports it like an uncaught error; Node 22 has no reportError.
      // The reporter is page code too, so its own throw stays here as well.
      try {
        if (typeof globalThis.reportError === "function") globalThis.reportError(error);
      } catch {
        // nothing left to report to
      }
    }
  }
}

/**
 * A frozen copy of a key with exactly its three members, so a caller who
 * keeps or edits the original cannot move a registration or retarget lookup.
 *
 * @param {unknown} key
 * @returns {RegistryKey}
 */
function admitKey(key) {
  if (!isObject(key) || typeof key === "function") {
    throw dcaError("bad_config", "a registry key is an object");
  }
  const names = Reflect.ownKeys(key);
  if (names.length !== KEY_MEMBERS.length || !KEY_MEMBERS.every((m) => Object.hasOwn(key, m))) {
    throw dcaError("bad_config", "a registry key has exactly interface, major and name");
  }
  const { interface: iface, major, name } = /** @type {Record<string, unknown>} */ (key);
  if (typeof iface !== "string" || iface === "" || typeof name !== "string" || name === "") {
    throw dcaError("bad_config", "a registry key's interface and name are nonempty strings");
  }
  if (typeof major !== "number" || !Number.isSafeInteger(major) || major < 1) {
    throw dcaError("bad_config", "a registry key's major is a positive safe integer");
  }
  return Object.freeze({ interface: iface, major, name });
}

/**
 * One string per exact tuple. JSON keeps `a|b`+`c` apart from `a`+`b|c`.
 *
 * @param {RegistryKey} key
 */
function keyId(key) {
  return JSON.stringify([key.interface, key.major, key.name]);
}

/**
 * @param {unknown} registry
 * @returns {boolean}
 */
function isCompatible(registry) {
  if (!isObject(registry)) return false;
  const methods = /** @type {Record<string, unknown>} */ (registry);
  return (
    methods.apiMajor === 1 && REGISTRY_METHODS.every((name) => typeof methods[name] === "function")
  );
}

/**
 * @param {unknown} value
 * @returns {value is object}
 */
function isObject(value) {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}

/**
 * Adds an own member without running an inherited setter.
 *
 * @param {object} target
 * @param {string} name
 * @param {unknown} value
 */
function defineOwn(target, name, value) {
  Object.defineProperty(target, name, {
    value,
    writable: true,
    enumerable: false,
    configurable: true,
  });
}

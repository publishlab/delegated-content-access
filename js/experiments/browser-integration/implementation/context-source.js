// @ts-check
//
// The optional context source in the browser-integration specification, Section 4.
// The session integration that owns login, logout and account switches
// publishes snapshots; independently loaded consumers subscribe to one shared
// observation of those transitions.
//
// A reader signs in: the adapter publishes `{ sequence: 1, contextKnown: true,
// contextRevision: "r1" }`. The SDK reloads and cannot tell for a moment:
// `{ sequence: 2, contextKnown: false, contextRevision: "r1" }`, and a host
// suspends its work. The SDK confirms the same session: sequence 3, known,
// "r1", and suspended work may resume. The reader switches account under the
// same "signed in" label: sequence 4, known, "r2", and the host retires every
// piece of work captured under "r1". A late sequence-2 publication changes
// nothing, because sequence 4 already passed. The adapter shuts down: the
// source sends sequence 5, unknown, "r2", and stops every subscriber. That is
// an ordinary unknown; the host retires work only when it disposes the
// association.
//
// A snapshot carries no identity, credential, key or entitlement. Unknown is
// uncertainty, never a signed-out reader. The source grants no access.

import { dcaError } from "../../../core-shared/errors.js";

/**
 * One observation. `contextRevision` is an opaque source-local scalar compared
 * by equality; it is not an account identifier.
 *
 * @typedef {object} ContextSnapshot
 * @property {number} sequence - nonnegative safe integer, increasing per source
 * @property {boolean} contextKnown
 * @property {string | number | boolean | null} contextRevision
 */

/**
 * @callback ContextListener
 * @param {ContextSnapshot} snapshot
 * @param {() => void} stop - the same function `subscribe` returns
 * @returns {void}
 */

/**
 * What a consumer sees, for example under `dca.access-context` in the registry.
 *
 * @typedef {object} ContextSourceProvider
 * @property {(listener: ContextListener) => () => void} subscribe
 */

/**
 * The producer side. Only the session adapter holds it.
 *
 * @typedef {object} ContextSourceController
 * @property {ContextSourceProvider} provider
 * @property {(snapshot: ContextSnapshot) => boolean} publish
 *   Accepts a later sequence and returns true; ignores an older or equal one, or
 *   any publication after `end`, and returns false.
 * @property {() => void} end
 *   Sends the next sequence as a final unknown snapshot and stops every subscriber.
 */

const SNAPSHOT_MEMBERS = ["sequence", "contextKnown", "contextRevision"];

/**
 * @param {ContextSnapshot} initialSnapshot - the state before any change; it may be unknown
 * @returns {ContextSourceController}
 */
export function createContextSource(initialSnapshot) {
  let current = admitPublished(initialSnapshot);
  /** Every revision this association has shown, to refuse a reuse after a change. */
  const revisions = new Set([current.contextRevision]);
  let ended = false;
  /** @type {Set<Subscriber>} */
  const subscribers = new Set();
  /** @type {Array<{ recipients: Subscriber[], snapshot: ContextSnapshot, final: boolean }>} */
  const queue = [];
  let delivering = 0;

  /**
   * Runs `deliver` with publications queued, then drains the queue once the
   * outermost delivery ends, so a listener never sees a nested call.
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
        for (const subscriber of next.recipients) {
          subscriber.call(next.snapshot);
          if (next.final) subscriber.stop();
        }
      }
    } finally {
      delivering -= 1;
    }
  }

  /** @param {boolean} final */
  function changed(final) {
    queue.push({ recipients: [...subscribers], snapshot: current, final });
    delivery(() => {});
  }

  /** @type {ContextSourceProvider} */
  const provider = Object.freeze({
    /** @param {ContextListener} listener */
    subscribe(listener) {
      if (typeof listener !== "function") {
        throw dcaError("bad_config", "a context listener is a function");
      }
      const subscriber = new Subscriber(listener, () => subscribers.delete(subscriber));
      const alreadyEnded = ended;
      if (!ended) subscribers.add(subscriber);
      delivery(() => {
        subscriber.call(current);
        // A late subscriber after the end replays the final unknown and stops.
        if (alreadyEnded) subscriber.stop();
      });
      return subscriber.stop;
    },
  });

  return Object.freeze({
    provider,

    /** @param {ContextSnapshot} snapshot */
    publish(snapshot) {
      const admitted = admitPublished(snapshot);
      if (ended || admitted.sequence <= current.sequence) return false;
      if (
        admitted.contextRevision !== current.contextRevision &&
        revisions.has(admitted.contextRevision)
      ) {
        throw dcaError(
          "revision_reused",
          `revision ${JSON.stringify(admitted.contextRevision)} returns after a different revision`,
        );
      }
      revisions.add(admitted.contextRevision);
      current = admitted;
      changed(false);
      return true;
    },

    end() {
      if (ended) return;
      ended = true;
      current = Object.freeze({
        sequence: current.sequence + 1,
        contextKnown: false,
        contextRevision: current.contextRevision,
      });
      changed(true);
    },
  });
}

class Subscriber {
  #stopped = false;

  /**
   * @param {ContextListener} listener
   * @param {() => void} unsubscribe
   */
  constructor(listener, unsubscribe) {
    this.listener = listener;
    /** The one stop function, returned by subscribe and passed to every call. */
    this.stop = () => {
      if (this.#stopped) return;
      this.#stopped = true;
      unsubscribe();
    };
  }

  /**
   * Calls the listener unless it stopped. Its exception, and a throwing
   * reporter, stay here, so the other listeners and the publication go on.
   *
   * @param {ContextSnapshot} snapshot
   */
  call(snapshot) {
    if (this.#stopped) return;
    try {
      this.listener(snapshot, this.stop);
    } catch (error) {
      try {
        // A browser reports it like an uncaught error; Node 22 has no reportError.
        if (typeof globalThis.reportError === "function") globalThis.reportError(error);
      } catch {
        // nothing left to report to
      }
    }
  }
}

/**
 * Producer admission. The producer stops below the last safe integer, so `end`
 * can always send one more sequence.
 *
 * @param {unknown} snapshot
 * @returns {ContextSnapshot}
 */
function admitPublished(snapshot) {
  const admitted = admitSnapshot(snapshot);
  if (admitted.sequence === Number.MAX_SAFE_INTEGER) {
    throw dcaError("bad_config", "a published sequence stays below the last safe integer");
  }
  return admitted;
}

/**
 * Consumer admission: a frozen copy with exactly the three members. Any
 * nonnegative safe integer is an ordinary sequence here, the last one included.
 *
 * @param {unknown} snapshot
 * @returns {ContextSnapshot}
 */
export function admitSnapshot(snapshot) {
  if (!isPlainRecord(snapshot)) {
    throw dcaError("bad_config", "a context snapshot is a plain object");
  }
  const names = Reflect.ownKeys(snapshot);
  if (
    names.length !== SNAPSHOT_MEMBERS.length ||
    !SNAPSHOT_MEMBERS.every((name) => names.includes(name))
  ) {
    throw dcaError(
      "bad_config",
      "a context snapshot has exactly sequence, contextKnown and contextRevision",
    );
  }
  const { sequence, contextKnown, contextRevision } = /** @type {Record<string, unknown>} */ (
    snapshot
  );
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw dcaError("bad_config", "a snapshot sequence is a nonnegative safe integer");
  }
  if (typeof contextKnown !== "boolean") {
    throw dcaError("bad_config", "a snapshot's contextKnown is a boolean");
  }
  if (!isJsonScalar(contextRevision)) {
    throw dcaError("bad_config", "a snapshot's contextRevision is a JSON scalar");
  }
  return Object.freeze({ sequence, contextKnown, contextRevision });
}

/**
 * @param {unknown} value
 * @returns {value is string | number | boolean | null}
 */
function isJsonScalar(value) {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}

/**
 * @param {unknown} value
 * @returns {value is object}
 */
function isPlainRecord(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// @ts-check
//
// The direct content-handler interface in the browser-integration specification,
// Sections 2 and 5. The host passes one captured delivery, a synchronous
// eligibility check and one callback per content name to `connect`. The
// connection hands each opened item to its callback, and the callback applies
// its effect through `commit`, the guard of that one operation.
//
// A delayed result shows why the guard sits at the effect. Article A's
// callback awaits a template, and meanwhile the reader navigates; the host
// gives A's DOM node to article B and A's `isEligible` turns false. When A's
// callback resumes and calls `commit(() => node.replaceChildren(...))`, the
// guard checks A's eligibility, finds it false and does not run the effect.
// The connection retires and reports `stale`; B's own connection is untouched.
//
// This is an experimental reference implementation. It grants no access and does not
// sandbox same-page code: a callback that ignores `commit` can still mutate the
// page. It shows that well-behaved callbacks need no scheduler to keep delayed
// work out of a successor's destination.

import { dcaError } from "../../../core-shared/errors.js";
import { own, setOwn } from "../../../core-shared/wire.js";

/**
 * How the connection presents an item's opened bytes to its callback.
 *
 * @typedef {"bytes" | "strictUTF8"} ValueMode
 */

/**
 * Applies one effect while the operation is live. Runs `effect` only after the
 * captured eligibility check returns true, and returns whether it ran.
 *
 * @callback Commit
 * @param {() => void} effect - a synchronous effect; a returned promise is misuse
 * @returns {boolean}
 */

/**
 * What one callback receives for one item.
 *
 * @typedef {object} ContentInput
 * @property {string} contentName
 * @property {string} contentType - the item's required `contentType`, as captured at connect
 * @property {Uint8Array | string} value - bytes, or text under `strictUTF8`
 * @property {Commit} commit
 */

/**
 * What a callback reports. `stale` belongs to the connection, never to a callback.
 *
 * @typedef {object} CallbackOutcome
 * @property {"handled" | "refused" | "failed"} status
 * @property {string} [reason]
 */

/**
 * @callback ContentCallback
 * @param {ContentInput} input
 * @returns {CallbackOutcome | Promise<CallbackOutcome>}
 */

/**
 * @typedef {object} ConnectionSetup
 * @property {object} delivery - the captured delivery object with own `contentData` records
 * @property {() => boolean} isEligible - synchronous check of the captured context and destination
 * @property {Record<string, ContentCallback>} targets - one callback per content name
 * @property {Record<string, ValueMode>} [values] - per-name mode; a name left out gets bytes
 */

/**
 * One outcome per submitted name. `reason` is a diagnostic string, never an
 * access decision or a retry instruction.
 *
 * @typedef {object} ContentOutcome
 * @property {"handled" | "refused" | "failed" | "stale"} status
 * @property {string} [reason]
 */

/**
 * @typedef {object} ContentConnection
 * @property {(content: Record<string, Uint8Array>) => Promise<Record<string, ContentOutcome>>} handleContent
 * @property {() => void} dispose
 */

/**
 * @typedef {object} ContentHandler
 * @property {(setup: ConnectionSetup) => ContentConnection} connect
 */

const SETUP_MEMBERS = new Set(["delivery", "isEligible", "targets", "values"]);
const VALUE_MODES = new Set(["bytes", "strictUTF8"]);
const CALLBACK_STATUSES = new Set(["handled", "refused", "failed"]);
const OUTCOME_MEMBERS = new Set(["status", "reason"]);

/**
 * The provider. It holds no state; every connection captures its own.
 *
 * @param {Record<string, never>} [options] - no member is supported yet
 * @returns {ContentHandler}
 */
export function createContentHandler(options = {}) {
  if (!isRecord(options)) {
    throw dcaError("bad_config", "content handler options are a plain object");
  }
  for (const name of Object.keys(options)) {
    throw dcaError("unsupported_option", `the content handler has no option ${name}`);
  }
  return { connect: (setup) => new Connection(setup).view() };
}

class Connection {
  /** @type {() => boolean} */
  #isEligible;
  /** @type {Map<string, { callback: ContentCallback, mode: ValueMode }>} */
  #targets = new Map();
  /**
   * The `contentType` of each item the delivery declares, or null when the
   * record carries none. Captured at connect, so a later edit of the delivery
   * cannot change what a callback is told.
   *
   * @type {Map<string, string | null>}
   */
  #itemTypes = new Map();
  /**
   * SHA-256 of the bytes each handled name was handled with. The digest
   * decides repeats without keeping a plaintext copy. Retirement clears it.
   *
   * @type {Map<string, string>}
   */
  #handled = new Map();
  /**
   * Names whose effects may be partial. They need reconciliation outside this
   * connection, so a resubmission here never runs their callback again.
   *
   * @type {Set<string>}
   */
  #failed = new Set();
  #retired = false;
  #active = false;

  /** @param {unknown} setup */
  constructor(setup) {
    if (!isRecord(setup)) {
      throw dcaError("bad_config", "connection setup is a plain object");
    }
    for (const name of Object.keys(setup)) {
      if (!SETUP_MEMBERS.has(name)) {
        throw dcaError("unsupported_option", `connection setup has no member ${name}`);
      }
    }

    const delivery = own(setup, "delivery");
    const contentData = own(delivery, "contentData");
    if (!isRecord(delivery) || !isRecord(contentData)) {
      throw dcaError("bad_config", "setup.delivery is a delivery object with a contentData object");
    }
    for (const name of Object.keys(contentData)) {
      const contentType = own(own(contentData, name), "contentType");
      this.#itemTypes.set(name, typeof contentType === "string" ? contentType : null);
    }

    const isEligible = own(setup, "isEligible");
    if (typeof isEligible !== "function") {
      throw dcaError("bad_config", "setup.isEligible is a function");
    }
    this.#isEligible = isEligible;

    const targets = own(setup, "targets");
    if (!isRecord(targets)) {
      throw dcaError("bad_config", "setup.targets maps content names to callbacks");
    }
    const values = Object.hasOwn(setup, "values") ? own(setup, "values") : {};
    if (!isRecord(values)) {
      throw dcaError("bad_config", "setup.values maps content names to value modes");
    }
    for (const name of Object.keys(values)) {
      if (!Object.hasOwn(targets, name)) {
        throw dcaError("bad_config", `setup.values names ${name}, which has no target`);
      }
      if (!VALUE_MODES.has(own(values, name))) {
        throw dcaError("bad_config", `setup.values.${name} is "bytes" or "strictUTF8"`);
      }
    }
    for (const name of Object.keys(targets)) {
      const callback = own(targets, name);
      if (typeof callback !== "function") {
        throw dcaError("bad_config", `setup.targets.${name} is a function`);
      }
      this.#targets.set(name, { callback, mode: own(values, name) ?? "bytes" });
    }
  }

  /** @returns {ContentConnection} */
  view() {
    return {
      handleContent: (content) => this.#handleContent(content),
      dispose: () => this.#retire(),
    };
  }

  /**
   * Not `async`: an overlapping call must reject before this call does any
   * work, and the check has to see the flag the active call set synchronously.
   *
   * @param {unknown} content
   * @returns {Promise<Record<string, ContentOutcome>>}
   */
  #handleContent(content) {
    // Retirement takes precedence: later submissions resolve stale even while
    // a callback from the retired call is still settling.
    if (this.#active && !this.#retired) {
      return Promise.reject(
        dcaError("overlapping_call", "this connection is already handling content"),
      );
    }
    // Copy the submitted bytes before the first await: a caller that reuses
    // its buffer while a callback waits must not change what was submitted.
    /** @type {Array<[string, Uint8Array | null]>} */
    let submitted;
    try {
      if (!isRecord(content)) {
        throw dcaError("bad_config", "handleContent takes a map of content names to bytes");
      }
      submitted = Object.keys(content).map((name) => {
        const value = own(content, name);
        // Uint8Array.from copies; a Buffer's slice() would be a view of the caller's memory.
        return [name, value instanceof Uint8Array ? Uint8Array.from(value) : null];
      });
    } catch (error) {
      return Promise.reject(error);
    }
    this.#active = true;
    return this.#handleAll(submitted).finally(() => {
      this.#active = false;
    });
  }

  /**
   * One item at a time, in submission order, so the item in flight when the
   * connection retires is the last one whose callback runs.
   *
   * @param {Array<[string, Uint8Array | null]>} submitted
   */
  async #handleAll(submitted) {
    /** @type {Record<string, ContentOutcome>} */
    const outcomes = {};
    for (const [name, bytes] of submitted) {
      setOwn(outcomes, name, await this.#handleOne(name, bytes));
    }
    return outcomes;
  }

  /**
   * @param {string} name
   * @param {Uint8Array | null} bytes
   * @returns {Promise<ContentOutcome>}
   */
  async #handleOne(name, bytes) {
    if (this.#retired) return { status: "stale" };
    if (!this.#itemTypes.has(name)) return refused("unknown_content");
    const target = this.#targets.get(name);
    if (target === undefined) return refused("no_target");
    const contentType = this.#itemTypes.get(name);
    if (typeof contentType !== "string") return refused("invalid_content_type");
    if (bytes === null) return refused("invalid_bytes");
    if (this.#failed.has(name)) return refused("needs_reconciliation");

    const digest = await sha256(bytes);
    if (this.#retired) return { status: "stale" };
    const handledDigest = this.#handled.get(name);
    if (handledDigest !== undefined) {
      if (handledDigest !== digest) return refused("changed_content");
      // A repeat reports handled only while the work is still eligible.
      const op = { eligibilityThrew: false };
      return this.#checkEligibility(op) ? { status: "handled" } : this.#retiredOutcome(op);
    }

    /** @type {Uint8Array | string} */
    let value = bytes;
    if (target.mode === "strictUTF8") {
      try {
        value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        return refused("invalid_utf8");
      }
    }

    const outcome = await this.#runCallback(name, contentType, value, target.callback);
    if (!this.#retired) {
      if (outcome.status === "handled") this.#handled.set(name, digest);
      if (outcome.status === "failed") this.#failed.add(name);
    }
    return outcome;
  }

  /**
   * Runs one callback and turns what happened into the item's outcome. The
   * guard `commit` belongs to this operation alone and stops working once the
   * callback settles, so a saved guard cannot apply a late effect.
   *
   * @param {string} contentName
   * @param {string} contentType
   * @param {Uint8Array | string} value
   * @param {ContentCallback} callback
   * @returns {Promise<ContentOutcome>}
   */
  async #runCallback(contentName, contentType, value, callback) {
    const op = {
      live: true,
      effects: 0,
      effectThrew: false,
      asyncEffect: false,
      eligibilityThrew: false,
    };

    /** @type {Commit} */
    const commit = (effect) => {
      if (!op.live || this.#retired) return false;
      if (typeof effect !== "function") {
        throw dcaError("bad_config", "commit takes a synchronous effect function");
      }
      if (!this.#checkEligibility(op)) return false;
      let result;
      try {
        result = effect();
      } catch (error) {
        op.effectThrew = true;
        throw error;
      }
      op.effects += 1;
      // An async effect could mutate after a later eligibility change, which is
      // the gap the guard closes. It already started, so the item fails; no
      // rollback follows.
      if (isThenable(result)) {
        op.asyncEffect = true;
        // Consume a later rejection so it does not surface as unhandled. The
        // handler does not control the effect; the item already failed.
        Promise.resolve(result).then(undefined, () => {});
      }
      return true;
    };

    if (!this.#checkEligibility(op)) return this.#retiredOutcome(op);

    /** @type {unknown} */
    let reported;
    let threw = false;
    try {
      const result = callback({ contentName, contentType, value, commit });
      // A synchronous callback ends immediately. Awaiting its plain outcome
      // would leave a saved guard active during already queued microtasks.
      reported = isThenable(result) ? await result : result;
    } catch {
      threw = true;
    } finally {
      op.live = false;
    }
    // Normalize external accessors before the final lifetime decision: reading
    // an outcome itself can retire the work. No external outcome getter runs
    // after the check below.
    const outcome = threw ? null : callbackOutcome(reported);
    // Eligibility may end after the last commit while the callback still awaits.
    // Handled is reported only for work that is still eligible when the callback
    // settles; its effects stay, and nothing is rolled back.
    if (!this.#retired) this.#checkEligibility(op);

    if (op.eligibilityThrew || this.#retired) return this.#retiredOutcome(op);
    if (op.asyncEffect) return failed("async_effect");
    if (op.effectThrew) return failed("effect_error");
    if (threw) return failed("callback_error");
    if (outcome === null) return failed("invalid_outcome");
    if (outcome.status === "handled" && op.effects === 0) return failed("handled_without_effect");
    if (outcome.status === "refused" && op.effects > 0) return failed("refused_after_effect");
    return outcome;
  }

  /**
   * Calls the captured check. False retires the connection; a throw also
   * retires it and marks the operation, which then reports a failure.
   *
   * @param {{ eligibilityThrew: boolean }} op
   * @returns {boolean}
   */
  #checkEligibility(op) {
    let eligible;
    try {
      eligible = this.#isEligible();
    } catch {
      op.eligibilityThrew = true;
      this.#retire();
      return false;
    }
    // The check itself may dispose this connection and still answer true.
    if (eligible === true && !this.#retired) return true;
    this.#retire();
    return false;
  }

  /**
   * @param {{ eligibilityThrew: boolean }} op
   * @returns {ContentOutcome}
   */
  #retiredOutcome(op) {
    return op.eligibilityThrew ? failed("eligibility_check_failed") : { status: "stale" };
  }

  /**
   * Ends this connection's eligibility. Effects that already happened stay;
   * repeat bookkeeping is released, and later submissions report stale.
   */
  #retire() {
    this.#retired = true;
    this.#handled.clear();
    this.#failed.clear();
  }
}

/**
 * @param {string} reason
 * @returns {ContentOutcome}
 */
function refused(reason) {
  return { status: "refused", reason };
}

/**
 * @param {string} reason
 * @returns {ContentOutcome}
 */
function failed(reason) {
  return { status: "failed", reason };
}

/**
 * A plain object, as JSON parsing or an object literal makes it. A typed array
 * or other class instance is not a record of names.
 *
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isThenable(value) {
  // Reads `then` through the prototype on purpose: a promise inherits it.
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    typeof (/** @type {{ then?: unknown }} */ (value).then) === "function"
  );
}

/**
 * A copy of a valid callback outcome, or null. Each member is read once, and
 * a throwing getter or proxy trap makes the outcome invalid, so a misbehaving
 * report fails its own item and never aborts its siblings.
 *
 * @param {unknown} value
 * @returns {CallbackOutcome | null}
 */
function callbackOutcome(value) {
  try {
    if (!isRecord(value)) return null;
    for (const name of Object.keys(value)) {
      if (!OUTCOME_MEMBERS.has(name)) return null;
    }
    const status = own(value, "status");
    if (!CALLBACK_STATUSES.has(status)) return null;
    if (!Object.hasOwn(value, "reason")) return { status };
    const reason = own(value, "reason");
    return typeof reason === "string" ? { status, reason } : null;
  } catch {
    return null;
  }
}

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<string>}
 */
async function sha256(bytes) {
  // Uint8Array.from gives WebCrypto the plain ArrayBuffer view its type requires.
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", Uint8Array.from(bytes)),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

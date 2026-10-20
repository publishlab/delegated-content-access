// @ts-check
// Private browser scheduling hints, never HTTP responses or authorization.
import { dcaError } from "../core-shared/errors.js";

/** @typedef {{ getItem: (key: string) => string|null, setItem: (key: string, value: string) => void, removeItem: (key: string) => void }} DenialStorage */
/** @typedef {{ key: string, contextKey: string, revision: number, context: string, storageEpoch: string, retryAt: number|null }} DenialAttempt */

/** @typedef {{ publisherOrigin: string, issuerName: string, unlockUrl: string }} DenialScope */
/** @typedef {DenialScope & { request: any }} DenialRequest */
/** @typedef {{ capture: (input: DenialRequest) => Promise<any>, deny: (attempt: any) => void }} DenialAttemptCache */
/** @typedef {DenialAttemptCache & { invalidate: () => void, setContext: (context: string) => void, denyContext: (scope: DenialScope) => Promise<void> }} BrowserDenialCache */

/** @param {any} value @returns {any} */
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  return value;
}

export class DeniedUnlockCache {
  #storage;
  /** @type {unknown} Unresolved persistence fault, even after detachment. */
  #persistenceFailure = null;
  #persistenceFailed = false;
  #storageKey;
  #context;
  #revision = 0;
  #storageEpoch = "initial";
  #duration;
  #clock;
  #maxEntries;
  /** @type {Map<string, number>} */
  #memory = new Map();

  /**
   * @param {{ context?: string, durationMs?: number, now?: () => number,
   * storage?: DenialStorage, namespace?: string, maxEntries?: number }} [options]
   */
  constructor({
    context = "anonymous",
    durationMs = 600000,
    now = Date.now,
    storage,
    namespace = "default",
    maxEntries = 256,
  } = {}) {
    if (
      typeof context !== "string" ||
      context.length === 0 ||
      typeof namespace !== "string" ||
      namespace.length === 0 ||
      !Number.isSafeInteger(durationMs) ||
      durationMs < 0 ||
      !Number.isSafeInteger(maxEntries) ||
      maxEntries < 1 ||
      typeof now !== "function" ||
      (storage !== undefined &&
        (storage === null ||
          typeof storage !== "object" ||
          ["getItem", "setItem", "removeItem"].some(
            (name) => typeof (/** @type {any} */ (storage)[name]) !== "function",
          )))
    )
      throw dcaError(
        "bad_config",
        "denial cache needs a context, duration, clock and optional Storage",
      );
    this.#context = context;
    this.#duration = durationMs;
    this.#clock = now;
    this.#storage = storage ?? null;
    this.#storageKey = `dca.deniedUnlocks.${namespace}`;
    this.#maxEntries = maxEntries;
  }

  /** Context changes also invalidate pending denial recordings.
   * @param {string} context @returns {void}
   */
  setContext(context) {
    if (typeof context !== "string" || context.length === 0)
      throw dcaError("bad_config", "denial context is a nonempty host identifier");
    this.invalidate();
    this.#context = context;
  }

  /** Call on login, logout, account switch or entitlement change.
   * @returns {void}
   */
  invalidate() {
    this.#revision++;
    this.#memory.clear();
    this.#storageEpoch = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    try {
      this.#storage?.setItem(
        this.#storageKey,
        JSON.stringify({ epoch: this.#storageEpoch, entries: [] }),
      );
    } catch (error) {
      if (!this.#persistenceFailed) this.#persistenceFailure = error;
      this.#persistenceFailed = true;
      // Stay in memory after a storage fault; re-reading an older snapshot
      // could undo this instance's successful local invalidation.
      this.#storage = null;
    }
  }

  /** Strict awaitable lifecycle clear. Local hints always retire; an unresolved
   * durable snapshot failure remains visible even after persistence detached.
   * @returns {Promise<void>}
   */
  async clearAccessDecisions() {
    this.invalidate();
    if (this.#persistenceFailed) throw this.#persistenceFailure;
  }

  /** @param {number} now @returns {Map<string, number>} */
  #read(now) {
    let entries = this.#memory;
    if (this.#storage) {
      try {
        const stored = JSON.parse(this.#storage.getItem(this.#storageKey) ?? "null");
        if (stored === null) entries = new Map();
        else if (typeof stored.epoch === "string" && Array.isArray(stored.entries)) {
          entries = new Map();
          this.#storageEpoch = stored.epoch;
          for (const entry of stored.entries)
            if (
              Array.isArray(entry) &&
              entry.length === 2 &&
              typeof entry[0] === "string" &&
              Number.isSafeInteger(entry[1])
            )
              entries.set(entry[0], entry[1]);
        } else throw new Error("invalid denial-cache snapshot");
      } catch (error) {
        if (!this.#persistenceFailed) this.#persistenceFailure = error;
        this.#persistenceFailed = true;
        this.#storage = null; // Do not later re-import stale persistent hints.
      }
    }
    entries = new Map(
      [...entries]
        .filter(([, until]) => until > now && until <= now + this.#duration)
        .slice(-this.#maxEntries),
    );
    this.#memory = entries;
    return entries;
  }

  /** Capture exact requested material; an ephemeral response-recipient offer is not a policy change.
   * @param {DenialRequest} input
   * @returns {Promise<DenialAttempt>}
   */
  async capture({ publisherOrigin, issuerName, unlockUrl, request }) {
    if (
      [publisherOrigin, issuerName, unlockUrl].some(
        (value) => typeof value !== "string" || value.length === 0,
      )
    )
      throw dcaError(
        "bad_config",
        "a denied-unlock scope needs publisher origin, issuer name and URL",
      );
    this.#read(this.#clock());
    const storageEpoch = this.#storageEpoch;
    const revision = this.#revision;
    const context = this.#context;
    const { clientPublicKey: _offer, ...material } = request;
    void _offer;
    const scope = [publisherOrigin, issuerName, unlockUrl, context];
    const fingerprint = async (/** @type {any} */ value) => {
      const bytes = new TextEncoder().encode(JSON.stringify(canonical(value)));
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(
        "",
      );
    };
    const [key, contextKey] = await Promise.all([
      fingerprint(["request", ...scope, material]),
      fingerprint(["context", ...scope]),
    ]);
    const now = this.#clock();
    let retryAt = null;
    if (revision === this.#revision && context === this.#context) {
      const entries = this.#read(now);
      const until = Math.max(entries.get(key) ?? 0, entries.get(contextKey) ?? 0);
      if (until > now) retryAt = until;
    }
    return {
      key,
      contextKey,
      revision,
      context,
      storageEpoch,
      retryAt: storageEpoch === this.#storageEpoch ? retryAt : null,
    };
  }

  /** The trusted issuer integration explicitly declares no access for this route/context.
   * This is never inferred from an article's response. Duration uses this cache's durationMs.
   * @param {DenialScope} scope @returns {Promise<void>}
   */
  async denyContext(scope) {
    const attempt = await this.capture({ ...scope, request: {} });
    this.deny({ ...attempt, key: attempt.contextKey });
  }

  /** Record only a classification already established by the integration.
   * @param {DenialAttempt} attempt @returns {void}
   */
  deny(attempt) {
    if (
      this.#duration === 0 ||
      attempt.revision !== this.#revision ||
      attempt.context !== this.#context
    )
      return;
    const now = this.#clock();
    const entries = this.#read(now);
    if (attempt.storageEpoch !== this.#storageEpoch) return;
    entries.delete(attempt.key);
    entries.set(attempt.key, now + this.#duration);
    while (entries.size > this.#maxEntries)
      entries.delete(/** @type {string} */ (entries.keys().next().value));
    try {
      this.#storage?.setItem(
        this.#storageKey,
        JSON.stringify({ epoch: this.#storageEpoch, entries: [...entries] }),
      );
    } catch (error) {
      if (!this.#persistenceFailed) this.#persistenceFailure = error;
      this.#persistenceFailed = true;
      this.#storage = null; // Local memory remains usable for this instance.
    }
  }
}

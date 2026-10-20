// @ts-check
// Optional companion account hints. They grant no entitlement and never replace
// access-context revisions. The page owns its expiry clock and display policy.
import { dcaError } from "../../../core-shared/errors.js";

/** @typedef {"signIn" | "signOut" | "openAccount"} AccountAction */
/** @typedef {"started" | "unsupported" | "failed"} ActionOutcome */
/** @typedef {{signIn: boolean, signOut: boolean, openAccount: boolean}} ActionReadiness */
/**
 * @typedef {object} AccountSnapshot
 * @property {number} sequence
 * @property {number} observedAt
 * @property {number} validUntil
 * @property {"yes" | "no" | "unknown"} signedIn
 * @property {ActionReadiness} actionReady
 */
/** @typedef {Partial<Record<AccountAction, () => Promise<ActionOutcome>>>} AccountActions */
/** @typedef {Partial<Record<AccountAction, () => ActionOutcome | Promise<ActionOutcome>>>} AccountInitiators */
/**
 * @callback AccountListener
 * @param {AccountSnapshot} snapshot
 * @param {() => void} stop
 * @returns {void}
 */
/**
 * @typedef {object} AccountProvider
 * @property {(listener: AccountListener) => () => void} subscribe
 * @property {AccountActions} actions
 */

const ACTIONS = ["signIn", "signOut", "openAccount"];
const MEMBERS = ["sequence", "observedAt", "validUntil", "signedIn", "actionReady"];

/**
 * The adapter supplies original times and sequence; late replay never refreshes
 * them. Calling an action starts the upstream function synchronously, before
 * returning its promise, so a popup-sensitive click keeps its activation.
 *
 * @param {AccountSnapshot} initial
 * @param {AccountInitiators} [actions]
 * @returns {{provider: AccountProvider, publish: (snapshot: AccountSnapshot) => boolean, end: () => void}}
 */
export function createAccountSource(initial, actions = {}) {
  let current = admit(initial);
  if (!record(actions) || Reflect.ownKeys(actions).some((name) => !ACTIONS.includes(String(name))))
    throw dcaError("bad_config", "account actions are signIn, signOut or openAccount");
  /** @type {Set<{listener: AccountListener, stop: () => void, live: boolean}>} */
  const subscribers = new Set();
  /** @type {Array<{snapshot: AccountSnapshot, recipients: Array<{listener: AccountListener, stop: () => void, live: boolean}>}>} */
  const queue = [];
  let depth = 0;
  let ended = false;

  /** @param {{listener: AccountListener, stop: () => void, live: boolean}} sub @param {AccountSnapshot} snap */
  function call(sub, snap) {
    if (!sub.live) return;
    depth += 1;
    try {
      sub.listener(snap, sub.stop);
    } catch (error) {
      try {
        if (typeof globalThis.reportError === "function") globalThis.reportError(error);
      } catch {
        /* Diagnostics must not disrupt peers. */
      }
    } finally {
      depth -= 1;
    }
  }
  function drain() {
    if (depth > 0) return;
    depth += 1;
    try {
      for (let next = queue.shift(); next; next = queue.shift())
        for (const sub of next.recipients) call(sub, next.snapshot);
    } finally {
      depth -= 1;
    }
    if (ended) for (const sub of subscribers) sub.stop();
  }
  /** @type {AccountActions} */
  const available = {};
  for (const action of /** @type {AccountAction[]} */ (ACTIONS)) {
    if (!Object.hasOwn(actions, action)) continue;
    const initiate = actions[action];
    if (typeof initiate !== "function")
      throw dcaError("bad_config", "present account action is callable");
    available[action] = () => {
      if (ended || !current.actionReady[action]) return Promise.resolve("unsupported");
      try {
        const outcome = initiate(); // Never await or queue before initiating.
        return Promise.resolve(outcome).then(
          (value) =>
            value === "started" || value === "unsupported" || value === "failed" ? value : "failed",
          () => "failed",
        );
      } catch {
        return Promise.resolve("failed");
      }
    };
  }
  /** @type {AccountProvider} */
  const provider = Object.freeze({
    actions: Object.freeze(available),
    subscribe(listener) {
      if (typeof listener !== "function")
        throw dcaError("bad_config", "account listener is callable");
      const sub = { listener, live: true, stop: () => {} };
      sub.stop = () => {
        if (!sub.live) return;
        sub.live = false;
        subscribers.delete(sub);
      };
      subscribers.add(sub);
      const alreadyEnded = ended;
      call(sub, current);
      if (alreadyEnded) sub.stop();
      drain();
      return sub.stop;
    },
  });
  return {
    provider,
    publish(snapshot) {
      if (ended) return false;
      const next = admit(snapshot);
      if (next.sequence <= current.sequence) return false;
      current = next;
      queue.push({ snapshot: current, recipients: [...subscribers] });
      drain();
      return true;
    },
    end() {
      if (ended) return;
      ended = true;
      current = Object.freeze({
        ...current,
        sequence: current.sequence + 1,
        signedIn: "unknown",
        actionReady: Object.freeze({ signIn: false, signOut: false, openAccount: false }),
      });
      queue.push({ snapshot: current, recipients: [...subscribers] });
      drain();
    },
  };
}

/**
 * Explicit adapter mapping for the deployment guide's local optional hint.
 * It creates no source association, context revision or entitlement.
 * @param {{state: "signed-in" | "signed-out" | "unknown", observedAt: number, validUntil: number}} account
 * @param {number} sequence
 * @param {ActionReadiness} actionReady
 * @returns {AccountSnapshot}
 */
export function accountFromLocal(account, sequence, actionReady) {
  const states = { "signed-in": "yes", "signed-out": "no", unknown: "unknown" };
  if (!record(account) || !Object.hasOwn(states, account.state))
    throw dcaError("bad_config", "local account state is signed-in, signed-out or unknown");
  return admit({
    sequence,
    observedAt: account.observedAt,
    validUntil: account.validUntil,
    signedIn: /** @type {AccountSnapshot["signedIn"]} */ (states[account.state]),
    actionReady,
  });
}

/** @param {unknown} value @returns {value is Record<string, any>} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
/** @param {unknown} value @returns {AccountSnapshot} */
function admit(value) {
  if (
    !record(value) ||
    Reflect.ownKeys(value).length !== MEMBERS.length ||
    !MEMBERS.every((key) => Object.hasOwn(value, key))
  )
    throw dcaError("bad_config", "account observation has its five named members");
  const { sequence, observedAt, validUntil, signedIn, actionReady } = value;
  if (
    !Number.isSafeInteger(sequence) ||
    sequence < 0 ||
    sequence >= Number.MAX_SAFE_INTEGER ||
    !Number.isSafeInteger(observedAt) ||
    observedAt < 0 ||
    !Number.isSafeInteger(validUntil) ||
    validUntil < observedAt ||
    !["yes", "no", "unknown"].includes(signedIn)
  )
    throw dcaError(
      "bad_config",
      "account observation has valid sequence, original times and signedIn hint",
    );
  if (
    !record(actionReady) ||
    Reflect.ownKeys(actionReady).length !== ACTIONS.length ||
    !ACTIONS.every(
      (key) => Object.hasOwn(actionReady, key) && typeof actionReady[key] === "boolean",
    )
  )
    throw dcaError("bad_config", "account readiness has three boolean action members");
  return Object.freeze({
    sequence,
    observedAt,
    validUntil,
    signedIn,
    actionReady: Object.freeze({
      signIn: actionReady.signIn,
      signOut: actionReady.signOut,
      openAccount: actionReady.openAccount,
    }),
  });
}

// @ts-check
import { ReaderContext } from "../../../core-client/ReaderContext.js";

// Client storage of one named construction profile. Chain keys and the period
// keys derived from them locally use ordinary period boundaries. Geometry
// partitions actual chain storage and derivation, not later period-key use. The profile is a segment of every
// partition name and the chain-key width comes from it, so two profiles at one
// geometry are separate partitions, and a chain key stored under one profile is
// never derived as the other.
//
// A selected extension can own a dedicated instance with an `entryKind` and
// `periodView: "none"`. That instance files chain keys under a structured
// partition the caller names, `{ kind, parts }`, in place of the publisher and
// `keyBy` family name, and refuses every call without one; an ordinary
// instance refuses every call with one. The family identity is the JSON array
// `[kind, ...parts, accessGroup, chainsPerDay, periodMinutes]`. The
// accessGroup stays the stock derivation input. Such an instance derives
// period keys for its caller and memoizes none, so no ordinary period view
// ever reads them. Window bounds per family and in total keep the most
// recently accepted windows.
//
// With a `storage` the retained chain keys are durable under the period-key
// cache's four-call contract. Each store operation of an instance takes a
// turn: it reads every family this instance owns, applies the window bounds
// to what it read, changes it, and writes back the families that differ. A
// stored family is a versioned value naming its entry kind, family identity
// and geometry; a load checks all of them and every key's width and window.
// Two tabs can still lose one write to each other between their turns;
// `reconcile` adds back what this instance filed and still holds. That record
// keeps the window bounds and the eviction policy, and a window this instance
// evicts leaves it, so reconcile never restores an evicted chain key.
// Response-private grants and the ordinary period memo are never stored.
// Reset drains this instance's store turns, then removes its entries.

import { base64urlDecode, base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import {
  nextPeriodFilingOrder,
  observePeriodFilingOrder,
} from "../../../core-client/periodKeyCandidateSource.js";
import { dcaError } from "../../../core-shared/errors.js";
import {
  MAX_RIVAL_CHAIN_CANDIDATES,
  MAX_RIVAL_PERIOD_KEY_CANDIDATES,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
  chainKeyCoordinate,
  chainKeyDerivations,
  settleChainGeometry,
  validateChainKeyAccessGroup,
} from "../core-shared/chainKeyConstruction.js";

/**
 * How many derived period keys one client cache keeps, counted across every
 * partition it holds rather than per partition. The reference implementation
 * sets this storage policy; the chain specification's Bounds table has no row
 * for it, and its Local retention policy section leaves the number to the
 * host, so a host that wants a different one passes `maxMemoPeriodKeys`.
 */
export const MAX_MEMOIZED_PERIOD_KEYS = 288;

/** @typedef {(entry: import('../../../adapter-client/periodKeyEviction.js').EvictionEntry, context: { now: Date }) => boolean} EvictionPolicy */
/** @typedef {{ id: number, cutoffT: string, position: number, key: Uint8Array, filed: number }} Retained */
/** @typedef {{ key: Uint8Array, filed: number, sources: Set<number> }} MemoizedPeriodKey */
/** @typedef {{ kind: string, parts: ReadonlyArray<string> }} CachePartition */
/** @typedef {{ publisher?: string, issuerName?: string, issuerNames?: string[], lease?: object, chainOnly?: boolean, triedPeriodKeys?: (Uint8Array|CryptoKey)[], chainCandidateBudget?: { remaining: number }, chainsPerDay?: number, periodMinutes?: number, partition?: CachePartition }} ChainContext */
/** @typedef {{ accessGroup: string, familyName: string, cutoffT: string, key: Uint8Array, context: ChainContext, filed: number }} Pending */
/** @typedef {{ kind: 'period-key', key: Uint8Array, filed: number, sources: Set<number>, pending: boolean }|{ kind: 'chain-key', id: number|null, chainKey: Uint8Array, cutoffT: string, familyName: string, issuerName?: string, geometry: object, filed: number, pending: boolean }} Candidate */

/** The store prefix of an ordinary instance's families. */
const CHAIN_STORAGE_PREFIX = "dca.chainKeys.";
/** The store prefix of a partitioned instance, before its base64url entry kind. */
const PARTITIONED_STORAGE_PREFIX = "dca.keyFamilies.";
/** The stored kind of an ordinary instance's families. */
const ORDINARY_ENTRY_KIND = "chainKey";
/** The remainder of a store key this instance owns: one family token. */
const FAMILY_TOKEN = /^[A-Za-z0-9_-]+$/;
const STORED_VERSION = 1;

/**
 * The period-key cache's store contract.
 *
 * @typedef {{ get: (key: string) => Promise<string|undefined>, set: (key: string, value: string) => Promise<void>, keys: () => Promise<string[]>, remove: (key: string) => Promise<void> }} CacheStorage
 */

/** @param {Uint8Array} a @param {Uint8Array} b */
function sameBytes(a, b) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/** @param {unknown} value @param {string} name */
function optionalBound(value, name) {
  if (value === undefined) return null;
  if (!Number.isSafeInteger(value) || /** @type {number} */ (value) < 1) {
    throw dcaError("bad_config", `${name} is a whole number, at least one; got ${value}`);
  }
  return /** @type {number} */ (value);
}

/** A stored window label back to its minute number. @param {string} label */
function windowStartOf(label) {
  return Number(label);
}

/** The most recent filing in one window: its acceptance recency. @param {Retained[]} held */
function recency(held) {
  return held.reduce((latest, candidate) => Math.max(latest, candidate.filed), -1);
}

/**
 * Evict whole windows, least recently accepted first: beyond the per-family
 * bound inside each family, then beyond the total bound across families.
 * Ties go by family name and window so two runs drop the same window.
 *
 * @param {Map<string, Map<number, Retained[]>>} families
 * @param {number|null} perFamily @param {number|null} total
 * @returns {{ familyName: string, windowStart: number }[]} the evicted windows
 */
function boundWindows(families, perFamily, total) {
  /** @type {{ familyName: string, windowStart: number }[]} */
  const evicted = [];
  if (perFamily !== null) {
    for (const [familyName, windows] of families) {
      while (windows.size > perFamily) {
        const [oldest] = [...windows].sort(
          ([a, heldA], [b, heldB]) => recency(heldA) - recency(heldB) || a - b,
        )[0];
        windows.delete(oldest);
        evicted.push({ familyName, windowStart: oldest });
      }
      if (windows.size === 0) families.delete(familyName);
    }
  }
  if (total === null) return evicted;
  let count = 0;
  for (const windows of families.values()) count += windows.size;
  while (count > total) {
    /** @type {{ familyName: string, windowStart: number, recency: number }|null} */
    let victim = null;
    for (const [familyName, windows] of families) {
      for (const [windowStart, held] of windows) {
        const at = recency(held);
        if (
          victim === null ||
          at < victim.recency ||
          (at === victim.recency &&
            (familyName < victim.familyName ||
              (familyName === victim.familyName && windowStart < victim.windowStart)))
        )
          victim = { familyName, windowStart, recency: at };
      }
    }
    if (victim === null) break;
    const windows = /** @type {Map<number, Retained[]>} */ (families.get(victim.familyName));
    windows.delete(victim.windowStart);
    if (windows.size === 0) families.delete(victim.familyName);
    evicted.push({ familyName: victim.familyName, windowStart: victim.windowStart });
    count--;
  }
  return evicted;
}

export class ChainKeyCache {
  #reader = new ReaderContext();
  /** @type {'retain'|'expand'} */
  #strategy;
  /** @type {Map<string, Map<number, Retained[]>>} */
  #chains = new Map();
  /** @type {Map<string, Map<string, MemoizedPeriodKey[]>>} */
  #periodKeys = new Map();
  /** @type {{ now: () => Date }|null} */
  #clock = null;
  /** @type {EvictionPolicy|null} */
  #evictionPolicy = null;
  /** @type {((context: { issuerName?: string, accessGroup: string }) => string)|null} */
  #keyBy = null;
  /** @type {number} */
  #maxMemoPeriodKeys = MAX_MEMOIZED_PERIOD_KEYS;
  /**
   * The construction profile this cache holds chain keys of: the identity
   * every partition name carries and the chain-key width every filing is
   * checked against.
   *
   * @type {{ name: string, constructionId: string, chainKeyBytes: number }}
   */
  #construction;
  /** @type {{ chainKeyFromChainKey: Function, periodKeyFromChainKey: Function, periodKeysFromChainKey: Function }} */
  #derivations;
  /** @type {Map<string, Promise<void>>} */
  #windowWrites = new Map();
  /** @type {WeakMap<object, Pending[]>} */
  #pending = new WeakMap();
  /** @type {WeakMap<object, Promise<void>>} */
  #promotions = new WeakMap();
  /** @type {WeakSet<object>} */
  #completed = new WeakSet();
  #retained = 0;
  /** @type {string|null} the one partition kind of a dedicated instance */
  #entryKind = null;
  /** @type {'ordinary'|'none'} */
  #periodView = "ordinary";
  /** @type {number} */
  #maxRivalsPerWindow = MAX_RIVAL_CHAIN_CANDIDATES;
  /** @type {number} chain members one pending answer may file */
  #maxMembersPerMessage = MAX_CHAIN_MEMBERS_PER_MESSAGE;
  /** @type {number} chain members one pending answer may file for one family */
  #maxMembersPerFamily = MAX_CHAIN_MEMBERS_PER_FAMILY;
  /** @type {number|null} */
  #maxWindowsPerFamily = null;
  /** @type {number|null} */
  #maxWindows = null;
  /** @type {CacheStorage|null} */
  #storage = null;
  #keyPrefix = CHAIN_STORAGE_PREFIX;
  /** The last store turn queued on this instance. */
  #storeTurn = Promise.resolve();
  /** @type {Map<string, { chainsPerDay: number, periodMinutes: number }>} geometry per family */
  #geometries = new Map();
  /**
   * What this instance filed for reuse, which `reconcile` adds back.
   * @type {Map<string, Map<number, Retained[]>>}
   */
  #filedHere = new Map();

  /**
   * @param {object} [config]
   * @param {'retain'|'expand'} [config.strategy]
   * @param {{ now: () => Date }} [config.clock]
   * @param {Function} [config.evictionPolicy]
   * @param {Function} [config.keyBy]
   * @param {number} [config.maxMemoPeriodKeys]
   * @param {string} [config.construction] - the canonical construction this
   *   cache is on. Absent is `dca-construction-chain-keys`, with 16-byte chain keys.
   * @param {string} [config.entryKind] - dedicate this instance to one
   *   partition kind; requires `periodView: "none"`
   * @param {'ordinary'|'none'} [config.periodView] - whether derived period
   *   keys are memoized and offered to the ordinary period-key view
   * @param {number} [config.maxRivalsPerWindow] - rival chain keys kept in one
   *   window; absent is the profile's rival bound
   * @param {number} [config.maxMembersPerMessage] - chain members one pending
   *   answer may file; absent is the chain-keys message bound. A composing
   *   profile whose answers carry more members passes its own bound.
   * @param {number} [config.maxMembersPerFamily] - chain members one pending
   *   answer may file for one family; absent is the chain-keys family bound.
   *   A composing profile whose answers carry more windows per family passes
   *   its own bound.
   * @param {number} [config.maxWindowsPerFamily] - windows kept per family
   * @param {number} [config.maxWindows] - windows kept across all families
   * @param {CacheStorage} [config.storage] - durable retained chain keys
   * @param {string} [config.namespace] - the logical client a shared store
   *   holds this instance's entries for
   */
  constructor(config = {}) {
    for (const name of Object.keys(config)) {
      if (
        ![
          "strategy",
          "clock",
          "evictionPolicy",
          "keyBy",
          "maxMemoPeriodKeys",
          "construction",
          "entryKind",
          "periodView",
          "maxRivalsPerWindow",
          "maxMembersPerMessage",
          "maxMembersPerFamily",
          "maxWindowsPerFamily",
          "maxWindows",
          "storage",
          "namespace",
        ].includes(name)
      ) {
        throw dcaError(
          "unsupported_option",
          `ChainKeyCache has no ${name} yet, and will not pretend to`,
        );
      }
    }
    const {
      strategy = "retain",
      clock,
      evictionPolicy,
      keyBy,
      maxMemoPeriodKeys,
      construction = CHAIN_KEY_CONSTRUCTION,
    } = config;
    // The name is settled before any width below is compared, and an unknown
    // name is refused instead of falling back to either profile.
    this.#construction = chainKeyConstructionProfile(construction);
    this.#derivations = chainKeyDerivations(this.#construction.name);
    if (strategy !== "retain" && strategy !== "expand") {
      throw dcaError("bad_config", `unknown chain-key cache strategy ${JSON.stringify(strategy)}`);
    }
    if (clock !== undefined && typeof clock?.now !== "function") {
      throw dcaError("bad_config", "a chain-cache clock answers now()");
    }
    if (evictionPolicy !== undefined && typeof evictionPolicy !== "function") {
      throw dcaError("bad_config", "a chain-cache evictionPolicy is a callback");
    }
    if ((clock === undefined) !== (evictionPolicy === undefined)) {
      throw dcaError(
        "bad_config",
        "a chain-cache evictionPolicy and clock are configured together",
      );
    }
    if (keyBy !== undefined && typeof keyBy !== "function") {
      throw dcaError("bad_config", "a chain-cache keyBy is a callback");
    }
    if (
      maxMemoPeriodKeys !== undefined &&
      (!Number.isInteger(maxMemoPeriodKeys) || maxMemoPeriodKeys < 1)
    ) {
      throw dcaError(
        "bad_config",
        `maxMemoPeriodKeys is a whole number of period keys, at least one; got ${maxMemoPeriodKeys}`,
      );
    }
    this.#maxMemoPeriodKeys = maxMemoPeriodKeys ?? MAX_MEMOIZED_PERIOD_KEYS;
    this.#strategy = strategy;
    this.#clock = clock ?? null;
    this.#evictionPolicy = /** @type {any} */ (evictionPolicy ?? null);
    this.#keyBy = /** @type {any} */ (keyBy ?? null);

    const { entryKind, periodView = "ordinary" } = config;
    if (periodView !== "ordinary" && periodView !== "none") {
      throw dcaError("bad_config", 'a chain-cache periodView is "ordinary" or "none"');
    }
    if (periodView === "none" && strategy === "expand") {
      throw dcaError("bad_config", "an expanding chain cache keeps only its period view");
    }
    this.#periodView = periodView;
    if (entryKind !== undefined) {
      if (typeof entryKind !== "string" || entryKind.length === 0) {
        throw dcaError("bad_config", "an entryKind names the one partition kind this cache files");
      }
      if (periodView !== "none") {
        throw dcaError("bad_config", 'a partitioned chain cache keeps periodView "none"');
      }
      if (keyBy !== undefined) {
        throw dcaError(
          "bad_config",
          "a partitioned chain cache takes its family identity from the partition, not a keyBy",
        );
      }
      this.#entryKind = entryKind;
    }
    this.#maxRivalsPerWindow =
      optionalBound(config.maxRivalsPerWindow, "maxRivalsPerWindow") ?? MAX_RIVAL_CHAIN_CANDIDATES;
    this.#maxMembersPerMessage =
      optionalBound(config.maxMembersPerMessage, "maxMembersPerMessage") ??
      MAX_CHAIN_MEMBERS_PER_MESSAGE;
    this.#maxMembersPerFamily =
      optionalBound(config.maxMembersPerFamily, "maxMembersPerFamily") ??
      MAX_CHAIN_MEMBERS_PER_FAMILY;
    this.#maxWindowsPerFamily = optionalBound(config.maxWindowsPerFamily, "maxWindowsPerFamily");
    this.#maxWindows = optionalBound(config.maxWindows, "maxWindows");

    const { storage, namespace } = config;
    if (storage !== undefined) {
      for (const call of ["get", "set", "keys", "remove"]) {
        if (typeof (/** @type {any} */ (storage)?.[call]) !== "function") {
          throw dcaError(
            "bad_config",
            `a chain-cache storage answers get, set, keys and remove; this one has no ${call}`,
          );
        }
      }
      if (strategy === "expand") {
        throw dcaError("bad_config", "an expanding chain cache keeps nothing a store could hold");
      }
      this.#storage = /** @type {CacheStorage} */ (storage);
    }
    if (namespace !== undefined) {
      if (storage === undefined || typeof namespace !== "string" || namespace.length === 0) {
        throw dcaError("bad_config", "a chain-cache namespace names the client a storage holds");
      }
    }
    if (this.#entryKind !== null)
      this.#keyPrefix = `${PARTITIONED_STORAGE_PREFIX}${base64urlEncode(utf8Encode(this.#entryKind))}.`;
    if (namespace !== undefined)
      this.#keyPrefix = `${this.#keyPrefix}${base64urlEncode(utf8Encode(namespace))}.`;
  }

  /** @param {string} familyName @returns {string} the family token in a store key */
  #tokenOf(familyName) {
    return this.#entryKind === null ? base64urlEncode(utf8Encode(familyName)) : familyName;
  }

  /** @param {string} familyName @returns {unknown} the stored family identity */
  #identityOf(familyName) {
    return this.#entryKind === null
      ? familyName
      : JSON.parse(new TextDecoder().decode(base64urlDecode(familyName)));
  }

  /**
   * Run one store operation after the previous one on this instance, under
   * the reader that queued it.
   *
   * @template T @param {() => Promise<T>} operation @returns {Promise<T>}
   */
  #inTurn(operation) {
    const readerRevision = this.#reader.capture();
    const run = this.#storeTurn.then(() => {
      this.#reader.check(readerRevision);
      return operation();
    });
    this.#storeTurn = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  /**
   * Run an operation on the retained windows. With a store it loads first,
   * then writes back what changed, as one turn.
   *
   * @template T @param {() => Promise<T>} operation @returns {Promise<T>}
   */
  async #onWindows(operation) {
    if (!this.#storage) return operation();
    const readerRevision = this.#reader.capture();
    return this.#reader.accept(
      await this.#inTurn(async () => {
        const raw = this.#reader.accept(await this.#load(), readerRevision);
        const result = this.#reader.accept(await operation(), readerRevision);
        this.#reader.accept(await this.#save(raw), readerRevision);
        return result;
      }),
      readerRevision,
    );
  }

  /**
   * Replace the working windows with what the store holds now, checked and
   * bounded. A loaded key keeps the id of the identical key it replaces, so
   * memo bookkeeping survives a reload.
   *
   * @returns {Promise<Map<string, string>>} the stored values read, by family
   */
  async #load() {
    const readerRevision = this.#reader.capture();
    const storage = /** @type {CacheStorage} */ (this.#storage);
    /** @type {Map<string, string>} */
    const raw = new Map();
    /** @type {Map<string, Map<number, Retained[]>>} */
    const chains = new Map();
    for (const storageKey of this.#reader.accept(await storage.keys(), readerRevision)) {
      if (!this.#owns(storageKey)) continue;
      const stored = this.#reader.accept(await storage.get(storageKey), readerRevision);
      if (stored === undefined) continue;
      const { familyName, geometry, windows } = this.#parse(storageKey, stored);
      raw.set(familyName, stored);
      this.#geometries.set(familyName, geometry);
      if (windows.size > 0) chains.set(familyName, windows);
    }
    this.#chains = chains;
    this.#evict();
    this.#bound();
    return raw;
  }

  /** @param {string} storageKey */
  #owns(storageKey) {
    return (
      storageKey.startsWith(this.#keyPrefix) &&
      FAMILY_TOKEN.test(storageKey.slice(this.#keyPrefix.length))
    );
  }

  /**
   * Read one stored family, refusing anything that is not this instance's
   * version, kind and family, or holds a key of another width or window.
   *
   * @param {string} storageKey @param {string} stored
   * @returns {{ familyName: string, geometry: { chainsPerDay: number, periodMinutes: number }, windows: Map<number, Retained[]> }}
   */
  #parse(storageKey, stored) {
    const bad = (/** @type {string} */ why) => dcaError("bad_storage", `${storageKey} ${why}`);
    let value;
    try {
      value = JSON.parse(stored);
    } catch {
      throw bad("does not hold a chain-key family");
    }
    if (value === null || typeof value !== "object" || value.v !== STORED_VERSION)
      throw bad("holds no chain-key family of a known version");
    if (value.kind !== (this.#entryKind ?? ORDINARY_ENTRY_KIND))
      throw bad("holds a family of another entry kind");
    const token = storageKey.slice(this.#keyPrefix.length);
    let familyName;
    try {
      familyName =
        this.#entryKind === null
          ? /** @type {string} */ (value.family)
          : base64urlEncode(utf8Encode(JSON.stringify(value.family)));
    } catch {
      throw bad("holds another family than its key names");
    }
    if (typeof familyName !== "string" || this.#tokenOf(familyName) !== token)
      throw bad("holds another family than its key names");
    let geometry;
    try {
      geometry = settleChainGeometry({
        chainsPerDay: value.chainsPerDay,
        periodMinutes: value.periodMinutes,
      });
    } catch {
      throw bad("holds no valid geometry");
    }
    if (value.windows === null || typeof value.windows !== "object")
      throw bad("holds no window map");
    /** @type {Map<number, Retained[]>} */
    const windows = new Map();
    for (const [windowLabel, list] of Object.entries(value.windows)) {
      if (!Array.isArray(list)) throw bad(`holds no candidate list at window ${windowLabel}`);
      /** @type {Retained[]} */
      const held = [];
      for (const entry of list) {
        let key;
        try {
          key = base64urlDecode(entry?.key);
        } catch {
          throw bad("holds a key that cannot be decoded");
        }
        if (key.length !== this.#construction.chainKeyBytes)
          throw bad("holds a key of another width");
        let at;
        try {
          at = chainKeyCoordinate(entry?.cutoffT, geometry);
        } catch {
          throw bad("holds a cutoff that is no label of its geometry");
        }
        if (String(at.windowStart) !== windowLabel) throw bad("holds a cutoff of another window");
        if (!Number.isSafeInteger(entry?.order) || entry.order < 0)
          throw bad("holds a filing order that is not a whole number");
        observePeriodFilingOrder(entry.order);
        const previous = this.#chains
          .get(familyName)
          ?.get(at.windowStart)
          ?.find((candidate) => candidate.cutoffT === at.t && sameBytes(candidate.key, key));
        held.push({
          id: previous?.id ?? ++this.#retained,
          cutoffT: at.t,
          position: at.position,
          key,
          filed: entry.order,
        });
      }
      held.sort((a, b) => b.filed - a.filed);
      held.splice(this.#maxRivalsPerWindow);
      if (held.length > 0) windows.set(windowStartOf(windowLabel), held);
    }
    return { familyName, geometry, windows };
  }

  /**
   * Write back every family whose stored value differs from the working
   * windows, and remove the ones that emptied.
   *
   * @param {Map<string, string>} raw
   */
  async #save(raw) {
    const readerRevision = this.#reader.capture();
    const storage = /** @type {CacheStorage} */ (this.#storage);
    for (const familyName of [...new Set([...raw.keys(), ...this.#chains.keys()])].sort()) {
      const storageKey = this.#keyPrefix + this.#tokenOf(familyName);
      const windows = this.#chains.get(familyName);
      if (!windows || windows.size === 0) {
        if (raw.has(familyName))
          this.#reader.accept(await storage.remove(storageKey), readerRevision);
        continue;
      }
      const geometry = /** @type {{ chainsPerDay: number, periodMinutes: number }} */ (
        this.#geometries.get(familyName)
      );
      /** @type {Record<string, { cutoffT: string, key: string, order: number }[]>} */
      const stored = {};
      for (const windowStart of [...windows.keys()].sort((a, b) => a - b))
        stored[String(windowStart)] = /** @type {Retained[]} */ (windows.get(windowStart)).map(
          ({ cutoffT, key, filed }) => ({ cutoffT, key: base64urlEncode(key), order: filed }),
        );
      const serialized = JSON.stringify({
        v: STORED_VERSION,
        kind: this.#entryKind ?? ORDINARY_ENTRY_KIND,
        family: this.#identityOf(familyName),
        chainsPerDay: geometry.chainsPerDay,
        periodMinutes: geometry.periodMinutes,
        windows: stored,
      });
      if (serialized !== raw.get(familyName))
        this.#reader.accept(await storage.set(storageKey, serialized), readerRevision);
    }
  }

  /**
   * Keep what this instance filed into a stored window, for `reconcile`: the
   * window's candidates as they stand after this filing, so a key the filing
   * subsumed goes too. Only a durable instance records; `#bound` keeps the
   * record inside the window bounds of the store.
   *
   * @param {string} familyName @param {number} windowStart @param {Retained[]} held
   * @param {Uint8Array} key
   */
  #recordFiled(familyName, windowStart, held, key) {
    if (!this.#storage) return;
    let windows = this.#filedHere.get(familyName);
    if (!windows) {
      windows = new Map();
      this.#filedHere.set(familyName, windows);
    }
    const mine = (windows.get(windowStart) ?? []).filter((candidate) =>
      held.some(
        (other) => other.cutoffT === candidate.cutoffT && sameBytes(other.key, candidate.key),
      ),
    );
    const filed = held.find((candidate) => sameBytes(candidate.key, key));
    if (filed) mine.unshift({ ...filed, key: Uint8Array.from(filed.key) });
    windows.set(windowStart, mine.slice(0, this.#maxRivalsPerWindow));
  }

  /**
   * Add back to the store every chain key this instance filed that the store
   * lost, candidate by candidate, under the window bounds. A caller invokes
   * it; nothing schedules it.
   *
   * @returns {Promise<void>}
   */
  async reconcile() {
    const readerRevision = this.#reader.capture();
    if (!this.#storage) return;
    this.#reader.accept(
      await this.#onWindows(async () => {
        for (const [familyName, filed] of this.#filedHere) {
          let windows = this.#chains.get(familyName);
          if (!windows) {
            windows = new Map();
            this.#chains.set(familyName, windows);
          }
          for (const [windowStart, mine] of filed) {
            const held = windows.get(windowStart) ?? [];
            for (const candidate of mine)
              if (
                !held.some(
                  (other) =>
                    other.cutoffT === candidate.cutoffT && sameBytes(other.key, candidate.key),
                )
              )
                held.push({ ...candidate, key: Uint8Array.from(candidate.key) });
            held.sort((a, b) => b.filed - a.filed);
            held.splice(this.#maxRivalsPerWindow);
            windows.set(windowStart, held);
          }
        }
        this.#bound();
      }),
      readerRevision,
    );
  }

  /**
   * Apply the window bounds to the retained windows, then to the reconcile
   * record: a window evicted from the first leaves the second, and the record
   * holds no more windows than the bounds allow, so `reconcile` never brings
   * back what this instance evicted. Geometry of a family neither holds goes.
   */
  #bound() {
    for (const { familyName, windowStart } of boundWindows(
      this.#chains,
      this.#maxWindowsPerFamily,
      this.#maxWindows,
    ))
      this.#forgetFiled(familyName, windowStart);
    boundWindows(this.#filedHere, this.#maxWindowsPerFamily, this.#maxWindows);
    this.#releaseGeometries();
  }

  /** @param {string} familyName @param {number} windowStart */
  #forgetFiled(familyName, windowStart) {
    const windows = this.#filedHere.get(familyName);
    if (!windows) return;
    windows.delete(windowStart);
    if (windows.size === 0) this.#filedHere.delete(familyName);
  }

  /** Drop the geometry of every family that neither the windows nor the record hold. */
  #releaseGeometries() {
    for (const familyName of this.#geometries.keys())
      if (!this.#chains.has(familyName) && !this.#filedHere.has(familyName))
        this.#geometries.delete(familyName);
  }

  /**
   * The family token of one partitioned call: base64url of the JSON array
   * `[kind, ...parts, accessGroup, chainsPerDay, periodMinutes]`.
   *
   * @param {string} accessGroup
   * @param {CachePartition|undefined} partition
   * @param {{ chainsPerDay: number, periodMinutes: number }} geometry
   */
  #partitionedFamily(accessGroup, partition, geometry) {
    if (this.#entryKind === null) {
      throw dcaError("bad_key", "an ordinary chain-key cache files no partitioned entry");
    }
    if (partition === null || typeof partition !== "object") {
      throw dcaError("bad_key", "this chain-key cache files under a partition");
    }
    if (partition.kind !== this.#entryKind) {
      throw dcaError("bad_key", `this cache holds only a partition of kind ${this.#entryKind}`);
    }
    const parts = partition.parts;
    if (
      !Array.isArray(parts) ||
      parts.length === 0 ||
      parts.some((part) => typeof part !== "string" || part.length === 0)
    ) {
      throw dcaError("bad_key", "a partition names its parts as nonempty strings");
    }
    return base64urlEncode(
      utf8Encode(
        JSON.stringify([
          partition.kind,
          ...parts,
          accessGroup,
          geometry.chainsPerDay,
          geometry.periodMinutes,
        ]),
      ),
    );
  }

  #evict() {
    if (this.#clock === null || this.#evictionPolicy === null) return;
    const now = this.#clock.now();
    // The reconcile record expires with the windows, or reconcile would
    // restore a chain key the policy retired.
    for (const families of [this.#chains, this.#filedHere]) {
      for (const [familyName, windows] of families) {
        for (const [windowStart, held] of windows) {
          const kept = held.filter(
            (candidate) =>
              !(
                /** @type {EvictionPolicy} */ (this.#evictionPolicy)(
                  { pool: "chain", t: candidate.cutoffT, kind: "chain-key" },
                  { now },
                )
              ),
          );
          if (kept.length > 0) windows.set(windowStart, kept);
          else windows.delete(windowStart);
        }
        if (windows.size === 0) families.delete(familyName);
      }
    }
    this.#releaseGeometries();
    for (const [familyName, periodKeys] of this.#periodKeys) {
      for (const [t, held] of periodKeys) {
        const kept = held.filter(
          () =>
            !(
              /** @type {EvictionPolicy} */ (this.#evictionPolicy)(
                { pool: "chain", t, kind: "period-key" },
                { now },
              )
            ),
        );
        if (kept.length > 0) periodKeys.set(t, kept);
        else periodKeys.delete(t);
      }
      if (periodKeys.size === 0) this.#periodKeys.delete(familyName);
    }
  }

  /** @param {ChainContext} context */
  #geometry(context) {
    try {
      return settleChainGeometry({
        chainsPerDay: context.chainsPerDay,
        periodMinutes: context.periodMinutes,
      });
    } catch {
      throw dcaError(
        "bad_key",
        "a chain cache entry needs explicit chainsPerDay and periodMinutes",
      );
    }
  }

  /** @param {string} accessGroup @param {ChainContext} context */
  #family(accessGroup, context) {
    try {
      validateChainKeyAccessGroup(accessGroup);
    } catch {
      throw dcaError("bad_key", "a chain cache entry needs an accessGroup");
    }
    if (this.#entryKind !== null || context.partition !== undefined) {
      const geometry = this.#geometry(context);
      return {
        familyName: this.#partitionedFamily(accessGroup, context.partition, geometry),
        geometry,
      };
    }
    if (typeof context.publisher !== "string" || context.publisher.length === 0) {
      throw dcaError("bad_key", "a chain cache entry files under its publisher");
    }
    const geometry = this.#geometry(context);
    let family = accessGroup;
    if (this.#keyBy) {
      if (typeof context.issuerName !== "string") {
        throw dcaError("bad_key", "an issuer-keyed chain cache is told which issuer granted a key");
      }
      family = this.#keyBy({ accessGroup, issuerName: context.issuerName });
      if (typeof family !== "string" || family.length === 0) {
        throw dcaError("bad_key", "a chain keyBy answers with the name of one family");
      }
    }
    return {
      // The construction is a segment of its own, so two profiles at one
      // publisher, family and geometry hold separate partitions: a walk
      // reads only chain keys of the width it derives from, and no candidate
      // crosses from one profile to the other.
      familyName: [
        context.publisher,
        this.#construction.constructionId,
        family,
        geometry.chainsPerDay,
        geometry.periodMinutes,
      ].join("\0"),
      geometry,
    };
  }

  /** Ordinary period family: construction/geometry no longer gate derived bytes.
   * @param {string} accessGroup @param {ChainContext} context
   */
  #periodFamily(accessGroup, context) {
    this.#requirePeriodView();
    validateChainKeyAccessGroup(accessGroup);
    if (typeof context.publisher !== "string" || context.publisher.length === 0)
      throw dcaError("bad_key", "a period candidate files under its publisher");
    let family = accessGroup;
    if (this.#keyBy) {
      if (typeof context.issuerName !== "string")
        throw dcaError("bad_key", "an issuer-keyed period view names its grantor");
      family = this.#keyBy({ accessGroup, issuerName: context.issuerName });
      if (typeof family !== "string" || family.length === 0)
        throw dcaError("bad_key", "a chain keyBy answers with the name of one family");
    }
    // This cache's canonical construction yields only the admitted v1 period profile.
    return [context.publisher, "dca-profile-period-keys", family].join("\0");
  }

  /** Geometry-free ordinary period view, including bounded generation rivals.
   * @param {string} accessGroup @param {string} t @param {ChainContext} [context]
   * @returns {Promise<Uint8Array[]>}
   */
  async periodCandidates(accessGroup, t, context = {}) {
    const readerRevision = this.#reader.capture();
    this.#requirePeriodView();
    return this.#reader
      .accept(await this.periodCandidateEntries(accessGroup, t, context), readerRevision)
      .map(({ key }) => key);
  }

  /** Shared ordinary filing metadata, independent of render geometry.
   * @param {string} accessGroup @param {string} t @param {ChainContext} [context]
   * @returns {Promise<{key: Uint8Array, order: number, pending: boolean}[]>}
   */
  async periodCandidateEntries(accessGroup, t, context = {}) {
    this.#reader.capture();
    this.#requirePeriodView();
    this.#evict();
    if (context.publisher === undefined) return [];
    const held = this.#readersOf(context).flatMap(
      (issuerName) =>
        this.#periodKeys.get(this.#periodFamily(accessGroup, { ...context, issuerName }))?.get(t) ??
        [],
    );
    held.sort((a, b) => b.filed - a.filed);
    /** @type {{key: Uint8Array, order: number, pending: boolean}[]} */
    const selected = [];
    for (const candidate of held) {
      if (!selected.some(({ key }) => sameBytes(key, candidate.key)))
        selected.push({
          key: Uint8Array.from(candidate.key),
          order: candidate.filed,
          pending: false,
        });
      if (selected.length === MAX_RIVAL_PERIOD_KEY_CANDIDATES) break;
    }
    return selected;
  }

  /** A dedicated instance offers no period key to the ordinary view. */
  #requirePeriodView() {
    if (this.#periodView === "none") {
      throw dcaError("bad_config", "this chain cache has no ordinary period view");
    }
  }

  /** @param {ChainContext} context @returns {(string|undefined)[]} */
  #readersOf(context) {
    if (!this.#keyBy || this.#entryKind !== null) return [undefined];
    if (Array.isArray(context.issuerNames)) {
      if (context.issuerNames.some((name) => typeof name !== "string")) {
        throw dcaError("bad_key", "the issuers a chain-cache read accepts are names");
      }
      return context.issuerNames;
    }
    if (typeof context.issuerName === "string") return [context.issuerName];
    throw dcaError("bad_key", "an issuer-keyed chain cache is told which issuers a read accepts");
  }

  /**
   * @param {string} familyName
   * @param {string} t
   * @param {Uint8Array} key
   * @param {number} filed
   * @param {number|null} [source] - the retained chain key this period key was derived from
   */
  #addPeriodKey(familyName, t, key, filed, source = null) {
    let family = this.#periodKeys.get(familyName);
    if (!family) {
      family = new Map();
      this.#periodKeys.set(familyName, family);
    }
    let held = family.get(t);
    if (!held) {
      held = [];
      family.set(t, held);
    }
    const duplicate = held.find((candidate) => sameBytes(candidate.key, key));
    if (duplicate) {
      duplicate.filed = Math.max(duplicate.filed, filed);
      if (source !== null) duplicate.sources.add(source);
    } else {
      held.push({
        key: Uint8Array.from(key),
        filed,
        sources: new Set(source === null ? [] : [source]),
      });
    }
    held.sort((a, b) => b.filed - a.filed);
    held.splice(MAX_RIVAL_PERIOD_KEY_CANDIDATES);
    this.#capMemo();
  }

  /**
   * Hold the derived period-key memo to its ceiling, least recently derived first.
   *
   * The ceiling counts single memoized period keys rather than whole coordinates:
   * rival period keys at one coordinate are derived at different moments and a repeat
   * read wants the newest of them, so dropping a whole coordinate would throw
   * away the entry the next read is about to rebuild. Period keys filed by one read
   * tie, and a tie goes by coordinate and then family name, so two runs of one
   * scenario drop the same period key.
   *
   * Both strategies are bounded here, `expand` included, where the store
   * holds the granted period keys themselves. Dropping the last copy of a period key
   * costs another unlock to reopen that render, and the spec asks for the
   * bound anyway: retention longer than this bounded cache is host policy, and
   * it does not revoke capability bytes already delivered elsewhere
   * (`spec-profile--chain-keys.md`, Local retention policy).
   *
   * The ceiling counts period keys across every partition the cache holds, not
   * per partition, so one busy partition can crowd out another.
   */
  #capMemo() {
    let total = 0;
    for (const family of this.#periodKeys.values()) {
      for (const held of family.values()) total += held.length;
    }
    while (total > this.#maxMemoPeriodKeys) {
      /** @type {{ familyName: string, t: string, held: MemoizedPeriodKey[], filed: number }|null} */
      let victim = null;
      for (const [familyName, family] of this.#periodKeys) {
        for (const [t, held] of family) {
          const oldest = held[held.length - 1];
          const takes =
            victim === null ||
            oldest.filed < victim.filed ||
            (oldest.filed === victim.filed &&
              (t < victim.t || (t === victim.t && familyName < victim.familyName)));
          if (takes) victim = { familyName, t, held, filed: oldest.filed };
        }
      }
      if (victim === null) return;
      victim.held.pop();
      const family = /** @type {Map<string, MemoizedPeriodKey[]>} */ (
        this.#periodKeys.get(victim.familyName)
      );
      if (victim.held.length === 0) family.delete(victim.t);
      if (family.size === 0) this.#periodKeys.delete(victim.familyName);
      total--;
    }
  }

  /**
   * Subsumption awaits WebCrypto. Queue one window so two filings cannot
   * both replace the same stale retained array after those awaits.
   *
   * @template T
   * @param {string} familyName
   * @param {number} windowStart
   * @param {() => Promise<T>} operation
   * @returns {Promise<T>}
   */
  async #writeWindow(familyName, windowStart, operation) {
    const readerRevision = this.#reader.capture();
    const id = `${familyName}\0${windowStart}`;
    const previous = this.#windowWrites.get(id) ?? Promise.resolve();
    /** @type {() => void} */
    let release = () => {};
    /** @type {Promise<void>} */
    const queued = new Promise((resolve) => {
      release = resolve;
    });
    this.#windowWrites.set(id, queued);
    try {
      this.#reader.accept(await previous, readerRevision);
      return this.#reader.accept(await operation(), readerRevision);
    } finally {
      release();
      if (this.#windowWrites.get(id) === queued) this.#windowWrites.delete(id);
    }
  }

  /** Retire retained, expanded, memoized and response-private capability.
   * Derivation may finish later, but its generation cannot file or return it.
   * @returns {Promise<void>}
   */
  clearReaderContext() {
    return this.#reader.clear(async () => {
      this.#chains.clear();
      this.#periodKeys.clear();
      this.#filedHere.clear();
      this.#windowWrites = new Map();
      this.#pending = new WeakMap();
      this.#promotions = new WeakMap();
      this.#completed = new WeakSet();
      const storage = this.#storage;
      if (!storage) return;
      // Drain issued store turns, then erase this instance's entries. A
      // failed erase detaches the store for good; the failure is terminal.
      try {
        await this.#storeTurn;
        const results = await Promise.allSettled(
          (await storage.keys())
            .filter((key) => this.#owns(key))
            .map((key) => Promise.resolve().then(() => storage.remove(key))),
        );
        const failed = results.find((result) => result.status === "rejected");
        if (failed?.status === "rejected") throw failed.reason;
      } catch (error) {
        this.#storage = null;
        throw error;
      } finally {
        this.#chains.clear();
      }
    });
  }

  /**
   * File one chain-key grant under the response geometry.
   *
   * @param {string} accessGroup
   * @param {string} cutoffT
   * @param {Uint8Array} key
   * @param {ChainContext} [context]
   */
  async put(accessGroup, cutoffT, key, context = {}) {
    const readerRevision = this.#reader.capture();
    this.#evict();
    if (!(key instanceof Uint8Array) || key.length !== this.#construction.chainKeyBytes) {
      throw dcaError(
        "bad_key",
        `a chain-key grant of this profile is ${this.#construction.chainKeyBytes} key bytes`,
      );
    }
    const { familyName: filedFamily, geometry } = this.#family(accessGroup, context);
    chainKeyCoordinate(cutoffT, geometry);
    const filed = nextPeriodFilingOrder();
    if (context.lease !== undefined) {
      if (context.lease === null || typeof context.lease !== "object") {
        throw dcaError("bad_key", "a pending chain grant is filed under its response lease");
      }
      this.#requireAcceptingLease(context.lease);
      let pending = this.#pending.get(context.lease);
      if (!pending) {
        pending = [];
        this.#pending.set(context.lease, pending);
      }
      // An ordinary instance counts a family by accessGroup; a partitioned
      // one by its partition, so two content names under one group do not
      // share a bound.
      if (
        pending.length >= this.#maxMembersPerMessage ||
        pending.filter((entry) =>
          this.#entryKind === null
            ? entry.accessGroup === accessGroup
            : entry.familyName === filedFamily,
        ).length >= this.#maxMembersPerFamily
      ) {
        throw dcaError("bad_key", "a pending chain response exceeds its member bound");
      }

      // A response-private lower cutoff can prove that an already-held
      // chain key is the family the issuer just re-delivered. Refresh that
      // retained authority now without making the pending grant reusable;
      // otherwise a rival filed before attempted() can evict it.
      if (this.#strategy === "retain") {
        const { familyName } = this.#family(accessGroup, context);
        const cutoff = chainKeyCoordinate(cutoffT, geometry);
        this.#reader.accept(
          await this.#onWindows(() =>
            this.#writeWindow(familyName, cutoff.windowStart, async () => {
              const held = this.#chains.get(familyName)?.get(cutoff.windowStart) ?? [];
              for (const candidate of held) {
                if (candidate.position < cutoff.position) continue;
                const atCutoff = this.#reader.accept(
                  await this.#derivations.chainKeyFromChainKey({
                    chainKey: candidate.key,
                    accessGroup,
                    suppliedT: candidate.cutoffT,
                    targetT: cutoffT,
                    geometry,
                  }),
                  readerRevision,
                );
                if (sameBytes(atCutoff, key)) candidate.filed = Math.max(candidate.filed, filed);
              }
              held.sort((a, b) => b.filed - a.filed);
            }),
          ),
          readerRevision,
        );
      }
      // A concurrent completion may have started during retained-key work.
      this.#requireAcceptingLease(context.lease);
      pending.push({
        accessGroup,
        familyName: filedFamily,
        cutoffT,
        key: Uint8Array.from(key),
        context: {
          publisher: context.publisher,
          issuerName: context.issuerName,
          chainsPerDay: geometry.chainsPerDay,
          periodMinutes: geometry.periodMinutes,
          ...(context.partition === undefined ? {} : { partition: context.partition }),
        },
        filed,
      });
      return;
    }
    return this.#reader.accept(
      await this.#putReusable(accessGroup, cutoffT, key, context, filed),
      readerRevision,
    );
  }

  /** @param {string} accessGroup @param {string} cutoffT @param {Uint8Array} key @param {ChainContext} context @param {number} filed */
  async #putReusable(accessGroup, cutoffT, key, context, filed) {
    const readerRevision = this.#reader.capture();
    const { familyName, geometry } = this.#family(accessGroup, context);
    const cutoff = chainKeyCoordinate(cutoffT, geometry);

    if (this.#strategy === "expand") {
      const periodKeys = this.#reader.accept(
        await this.#derivations.periodKeysFromChainKey({
          chainKey: key,
          accessGroup,
          suppliedT: cutoffT,
          cutoffT,
          geometry,
        }),
        readerRevision,
      );
      for (const periodKey of periodKeys)
        this.#addPeriodKey(
          this.#periodFamily(accessGroup, context),
          periodKey.t,
          periodKey.key,
          filed,
        );
      return;
    }

    return this.#reader.accept(
      await this.#onWindows(() =>
        this.#writeWindow(familyName, cutoff.windowStart, async () => {
          let held = this.#chains.get(familyName)?.get(cutoff.windowStart) ?? [];
          const duplicate = held.find(
            (candidate) => candidate.position === cutoff.position && sameBytes(candidate.key, key),
          );
          if (duplicate) {
            duplicate.filed = Math.max(duplicate.filed, filed);
            held.sort((a, b) => b.filed - a.filed);
            this.#bound();
            return;
          }

          const derivesDelivered = new Set();
          const subsumed = new Set();
          for (const candidate of held) {
            if (cutoff.position > candidate.position) {
              const atCandidate = this.#reader.accept(
                await this.#derivations.chainKeyFromChainKey({
                  chainKey: key,
                  accessGroup,
                  suppliedT: cutoffT,
                  targetT: candidate.cutoffT,
                  geometry,
                }),
                readerRevision,
              );
              if (sameBytes(atCandidate, candidate.key)) subsumed.add(candidate);
            } else if (candidate.position > cutoff.position) {
              const atCutoff = this.#reader.accept(
                await this.#derivations.chainKeyFromChainKey({
                  chainKey: candidate.key,
                  accessGroup,
                  suppliedT: candidate.cutoffT,
                  targetT: cutoffT,
                  geometry,
                }),
                readerRevision,
              );
              if (sameBytes(atCutoff, key)) {
                derivesDelivered.add(candidate);
              }
            }
          }
          // The issuer answered again with authority a retained cutoff already
          // derives. Nothing new is filed; each retained candidate that derives
          // the delivered chain key takes the arriving grant's filing stamp instead,
          // so the rival cap below cannot drop the family the issuer just
          // re-delivered. Its cutoff stays where it was, and so does its reach:
          // backward to the window start and no further.
          if (derivesDelivered.size > 0) {
            for (const candidate of derivesDelivered)
              candidate.filed = Math.max(candidate.filed, filed);
            held.sort((a, b) => b.filed - a.filed);
            this.#bound();
            return;
          }
          held = held.filter((candidate) => !subsumed.has(candidate));
          held.push({
            id: ++this.#retained,
            cutoffT,
            position: cutoff.position,
            key: Uint8Array.from(key),
            filed,
          });
          held.sort((a, b) => b.filed - a.filed);
          held.splice(this.#maxRivalsPerWindow);
          // Read the family after the awaits above: a bound applied meanwhile
          // may have dropped it, and a detached map would lose this filing.
          let windows = this.#chains.get(familyName);
          if (!windows) {
            windows = new Map();
            this.#chains.set(familyName, windows);
          }
          this.#geometries.set(familyName, { ...geometry });
          windows.set(cutoff.windowStart, held);
          this.#recordFiled(familyName, cutoff.windowStart, held, key);
          this.#bound();
        }),
      ),
      readerRevision,
    );
  }

  /**
   * Return locally derived candidates under the article geometry, newest
   * filed first.
   *
   * @param {string} accessGroup
   * @param {string} t
   * @param {ChainContext} [context]
   * @returns {Promise<Uint8Array[]>}
   */
  async candidates(accessGroup, t, context = {}) {
    const readerRevision = this.#reader.capture();
    // A trusted caller may share this finite work allowance across several
    // cache reads. Spending happens before derivation, including duplicate
    // results; retention and the returned distinct-key count cannot enlarge it.
    const chainCandidateBudget = context.chainCandidateBudget;
    if (
      chainCandidateBudget !== undefined &&
      (chainCandidateBudget === null ||
        typeof chainCandidateBudget !== "object" ||
        !Number.isSafeInteger(chainCandidateBudget.remaining) ||
        chainCandidateBudget.remaining < 0)
    )
      throw dcaError(
        "bad_config",
        "a chain candidate budget has nonnegative safe-integer remaining work",
      );
    const chainLimit = chainCandidateBudget?.remaining ?? MAX_RIVAL_CHAIN_CANDIDATES;
    // Read what the store holds now: another tab's filing is a key this
    // instance can derive from.
    if (this.#storage) this.#reader.accept(await this.#onWindows(async () => {}), readerRevision);
    this.#evict();
    const targetGeometry = this.#geometry(context);
    const target = chainKeyCoordinate(t, targetGeometry);
    const readers = this.#readersOf(context);
    const readableFamilies = new Set(
      readers.map((issuerName) => this.#family(accessGroup, { ...context, issuerName }).familyName),
    );
    /** @type {Candidate[]} */
    const available = [];

    if (context.lease !== undefined) {
      if (context.lease === null || typeof context.lease !== "object") {
        throw dcaError("bad_key", "a pending chain read names its response lease");
      }
      for (const entry of this.#pending.get(context.lease) ?? []) {
        if (entry.accessGroup !== accessGroup) continue;
        const { familyName, geometry } = this.#family(entry.accessGroup, entry.context);
        if (!readableFamilies.has(familyName)) continue;
        const supplied = chainKeyCoordinate(entry.cutoffT, geometry);
        if (supplied.windowStart !== target.windowStart || supplied.position < target.position)
          continue;
        available.push({
          kind: "chain-key",
          id: null,
          chainKey: entry.key,
          cutoffT: entry.cutoffT,
          familyName,
          issuerName: entry.context.issuerName,
          geometry,
          filed: entry.filed,
          pending: true,
        });
      }
    }

    for (const issuerName of readers) {
      const { familyName, geometry } = this.#family(accessGroup, { ...context, issuerName });
      for (const candidate of this.#chains.get(familyName)?.get(target.windowStart) ?? []) {
        if (candidate.position < target.position) continue;
        available.push({
          kind: "chain-key",
          id: candidate.id,
          chainKey: candidate.key,
          cutoffT: candidate.cutoffT,
          familyName,
          issuerName,
          geometry,
          filed: candidate.filed,
          pending: false,
        });
      }
    }

    for (const issuerName of this.#periodView === "none" ? [] : readers) {
      const familyName = this.#periodFamily(accessGroup, { ...context, issuerName });
      available.push(
        ...(this.#periodKeys.get(familyName)?.get(t) ?? []).map((candidate) => ({
          kind: /** @type {const} */ ("period-key"),
          ...candidate,
          pending: false,
        })),
      );
    }
    available.sort((a, b) => Number(b.pending) - Number(a.pending) || b.filed - a.filed);

    // Each bound governs its own kind. Chain keys, response-private ones
    // included, share the walk budget the trial cost is measured in, and
    // memoized period keys have their own ceiling at one coordinate; the two
    // constants are read apart rather than through their equal value.
    //
    // The cap applies to work, not merely to the returned array, so a chain
    // key whose period key at this coordinate is memoized drops out here when
    // that memo is offered for this wrap: this read returns it, or the caller
    // already tried its bytes. The memo then answers for the chain key instead
    // of trailing its walk as a duplicate. A memo a rival ceiling left out was
    // never tried, so it does not stand in for its walk. Because of
    // duplicates, a read may return fewer keys than the sum of both bounds.
    const periodKeys = available.filter((candidate) => candidate.kind === "period-key");
    const offered = context.chainOnly ? [] : periodKeys.slice(0, MAX_RIVAL_PERIOD_KEY_CANDIDATES);
    const tried = Array.isArray(context.triedPeriodKeys) ? context.triedPeriodKeys : [];
    const memoized = new Set();
    for (const candidate of periodKeys) {
      if (
        offered.includes(candidate) ||
        tried.some((key) => key instanceof Uint8Array && sameBytes(key, candidate.key))
      )
        for (const source of candidate.sources) memoized.add(source);
    }
    const bounded = [
      ...available
        .filter(
          (candidate) =>
            candidate.kind === "chain-key" &&
            (candidate.id === null || !memoized.has(candidate.id)),
        )
        .slice(0, chainLimit),
      ...offered,
    ].sort((a, b) => Number(b.pending) - Number(a.pending) || b.filed - a.filed);

    // One filing stamp for the whole read: a memoized period key files newer
    // than the chain key it came from, so the next read reaches it first, while
    // period keys derived together keep the rival order they were tried in.
    /** @type {number|null} */
    let memoFiled = null;
    /** @type {Uint8Array[]} */
    const selected = [];
    for (const candidate of bounded) {
      /** @type {Uint8Array} */
      let key;
      if (candidate.kind === "chain-key") {
        if (chainCandidateBudget !== undefined) {
          if (chainCandidateBudget.remaining <= 0) continue;
          chainCandidateBudget.remaining--;
        }
        const chainKey = this.#reader.accept(
          await this.#derivations.chainKeyFromChainKey({
            chainKey: candidate.chainKey,
            accessGroup,
            suppliedT: candidate.cutoffT,
            targetT: t,
            geometry: candidate.geometry,
          }),
          readerRevision,
        );
        key = this.#reader.accept(
          await this.#derivations.periodKeyFromChainKey({
            chainKey,
            accessGroup,
            t,
            geometry: candidate.geometry,
          }),
          readerRevision,
        );
        if (!candidate.pending && this.#periodView === "ordinary") {
          if (memoFiled === null) memoFiled = nextPeriodFilingOrder();
          this.#addPeriodKey(
            this.#periodFamily(accessGroup, { ...context, issuerName: candidate.issuerName }),
            t,
            key,
            memoFiled,
            candidate.id,
          );
        }
      } else {
        key = candidate.key;
      }
      if (selected.some((held) => sameBytes(held, key))) continue;
      selected.push(key);
    }
    return selected.map((key) => Uint8Array.from(key));
  }

  /**
   * Promote one response's private first-use material only after its article
   * attempt. Pending grants share the bounded chain budget rather than
   * enlarging it. Release is terminal even if promotion failed: successful
   * reusable writes survive, private material and the failed promise do not.
   * Repeated completion is a no-op; filing into a completing lease is refused.
   *
   * @param {{ lease: object }} context
   */
  async attempted(context) {
    try {
      await this.promote(context);
    } finally {
      if (context?.lease !== null && typeof context?.lease === "object") {
        this.#completed.add(context.lease);
        this.#pending.delete(context.lease);
        this.#promotions.delete(context.lease);
      }
    }
  }

  /** Joinable promotion keeps the obtaining lease visible through all awaits,
   * including a failed promotion until attempted() releases the lease.
   * Resolver completion releases it only after its concurrent readers finish.
   * @param {{ lease: object }} context
   * @returns {Promise<void>}
   */
  promote(context) {
    const readerRevision = this.#reader.capture();
    if (context?.lease === null || typeof context?.lease !== "object") {
      throw dcaError("bad_key", "a completed chain attempt names its response lease");
    }
    if (this.#completed.has(context.lease)) return Promise.resolve();
    const existing = this.#promotions.get(context.lease);
    if (existing) return existing;
    const pending = this.#pending.get(context.lease) ?? [];
    const promotion = (async () => {
      for (const entry of pending) {
        this.#reader.accept(
          await this.#putReusable(
            entry.accessGroup,
            entry.cutoffT,
            entry.key,
            entry.context,
            entry.filed,
          ),
          readerRevision,
        );
      }
    })();
    this.#promotions.set(context.lease, promotion);
    return promotion;
  }

  /** @param {object} lease */
  #requireAcceptingLease(lease) {
    if (this.#promotions.has(lease) || this.#completed.has(lease)) {
      throw dcaError("bad_key", "a completing chain attempt accepts no more grants");
    }
  }

  /** @returns {{ familyName: string, t: string, kind: 'chain-key'|'period-key' }[]} */
  entries() {
    this.#reader.capture();
    this.#evict();
    const entries = [];
    for (const [familyName, windows] of this.#chains) {
      for (const held of windows.values()) {
        for (const { cutoffT } of held)
          entries.push({ familyName, t: cutoffT, kind: /** @type {const} */ ("chain-key") });
      }
    }
    for (const [familyName, periodKeys] of this.#periodKeys) {
      for (const [t, held] of periodKeys) {
        for (let index = 0; index < held.length; index++) {
          entries.push({ familyName, t, kind: /** @type {const} */ ("period-key") });
        }
      }
    }
    return entries;
  }
}

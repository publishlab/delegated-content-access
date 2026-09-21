// @ts-check

// Client storage of one named construction profile. Chain state and locally
// projected leaves share one geometry partition; exact keys received on the
// wire use the base cache. The profile is a segment of every partition name and
// the state width comes from it, so two profiles at one geometry are separate
// partitions, and state stored under one profile is never derived as the other.

import { dcaError } from "../../../core-shared/errors.js";
import {
  MAX_RIVAL_CHAIN_CANDIDATES,
  MAX_RIVAL_EXACT_CANDIDATES,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  PERIOD_CHAIN_CONSTRUCTION,
  periodChainConstructionProfile,
  periodChainCoordinate,
  periodChainDerivations,
  settlePeriodChainGeometry,
  validatePeriodChainAccessGroup,
} from "../core-shared/periodChainConstruction.js";

/**
 * How many derived leaves one client cache keeps, counted across every
 * partition it holds rather than per partition. The reference implementation
 * sets this storage policy; the chain specification's Bounds table has no row
 * for it, and its Local retention policy section leaves the number to the
 * host, so a host that wants a different one passes `maxMemoLeaves`.
 */
export const MAX_MEMOIZED_LEAVES = 288;

/** @typedef {{ id: number, cutoffT: string, position: number, key: Uint8Array, filed: number }} Retained */
/** @typedef {{ key: Uint8Array, filed: number, sources: Set<number> }} Exact */
/** @typedef {{ publisher?: string, issuerName?: string, issuerNames?: string[], lease?: object, chainsPerDay?: number, periodMinutes?: number }} ChainContext */
/** @typedef {{ accessGroup: string, cutoffT: string, key: Uint8Array, context: ChainContext, filed: number }} Pending */
/** @typedef {{ kind: 'exact', key: Uint8Array, filed: number, sources: Set<number>, pending: boolean }|{ kind: 'chain', id: number|null, state: Uint8Array, cutoffT: string, familyName: string, geometry: object, filed: number, pending: boolean }} Candidate */

/** @param {Uint8Array} a @param {Uint8Array} b */
function sameBytes(a, b) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

export class PeriodChainCache {
  /** @type {'retain'|'expand'} */
  #strategy;
  /** @type {Map<string, Map<number, Retained[]>>} */
  #chains = new Map();
  /** @type {Map<string, Map<string, Exact[]>>} */
  #exact = new Map();
  /** @type {{ now: () => Date }|null} */
  #clock = null;
  /** @type {((entry: import('../../../adapter-client/periodKeyEviction.js').EvictionEntry, context: { now: Date }) => boolean)|null} */
  #evictionPolicy = null;
  /** @type {((context: { issuerName?: string, accessGroup: string }) => string)|null} */
  #keyBy = null;
  /** @type {number} */
  #maxMemoLeaves = MAX_MEMOIZED_LEAVES;
  /**
   * The construction profile this cache holds state of: the identity every
   * partition name carries and the state width every filing is checked
   * against.
   *
   * @type {{ constructionId: string, stateBytes: number }}
   */
  #construction;
  /** @type {{ stateFromState: Function, leafFromState: Function, expansionFromState: Function }} */
  #derivations;
  /** @type {Map<string, Promise<void>>} */
  #windowWrites = new Map();
  /** @type {WeakMap<object, Pending[]>} */
  #pending = new WeakMap();
  #filed = 0;
  #retained = 0;

  /**
   * @param {object} [config]
   * @param {'retain'|'expand'} [config.strategy]
   * @param {{ now: () => Date }} [config.clock]
   * @param {Function} [config.evictionPolicy]
   * @param {Function} [config.keyBy]
   * @param {number} [config.maxMemoLeaves]
   * @param {string} [config.construction] - the canonical construction this
   *   cache is on. Absent is `dca-period-chain-v1`, with 16-byte states.
   */
  constructor(config = {}) {
    for (const name of Object.keys(config)) {
      if (
        !["strategy", "clock", "evictionPolicy", "keyBy", "maxMemoLeaves", "construction"].includes(
          name,
        )
      ) {
        throw dcaError(
          "unsupported_option",
          `PeriodChainCache has no ${name} yet, and will not pretend to`,
        );
      }
    }
    const {
      strategy = "retain",
      clock,
      evictionPolicy,
      keyBy,
      maxMemoLeaves,
      construction = PERIOD_CHAIN_CONSTRUCTION,
    } = config;
    // The name is settled before any width below is compared, and an unknown
    // name is refused instead of falling back to either profile.
    this.#construction = periodChainConstructionProfile(construction);
    this.#derivations = periodChainDerivations(this.#construction.constructionId);
    if (strategy !== "retain" && strategy !== "expand") {
      throw dcaError(
        "bad_config",
        `unknown period-chain cache strategy ${JSON.stringify(strategy)}`,
      );
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
    if (maxMemoLeaves !== undefined && (!Number.isInteger(maxMemoLeaves) || maxMemoLeaves < 1)) {
      throw dcaError(
        "bad_config",
        `maxMemoLeaves is a whole number of leaves, at least one; got ${maxMemoLeaves}`,
      );
    }
    this.#maxMemoLeaves = maxMemoLeaves ?? MAX_MEMOIZED_LEAVES;
    this.#strategy = strategy;
    this.#clock = clock ?? null;
    this.#evictionPolicy = /** @type {any} */ (evictionPolicy ?? null);
    this.#keyBy = /** @type {any} */ (keyBy ?? null);
  }

  #evict() {
    if (this.#clock === null || this.#evictionPolicy === null) return;
    const now = this.#clock.now();
    for (const [familyName, windows] of this.#chains) {
      for (const [windowStart, held] of windows) {
        const kept = held.filter(
          (candidate) =>
            !this.#evictionPolicy({ pool: "chain", t: candidate.cutoffT, kind: "chain" }, { now }),
        );
        if (kept.length > 0) windows.set(windowStart, kept);
        else windows.delete(windowStart);
      }
      if (windows.size === 0) this.#chains.delete(familyName);
    }
    for (const [familyName, exact] of this.#exact) {
      for (const [t, held] of exact) {
        const kept = held.filter(
          () => !this.#evictionPolicy({ pool: "chain", t, kind: "exact" }, { now }),
        );
        if (kept.length > 0) exact.set(t, kept);
        else exact.delete(t);
      }
      if (exact.size === 0) this.#exact.delete(familyName);
    }
  }

  /** @param {ChainContext} context */
  #geometry(context) {
    try {
      return settlePeriodChainGeometry({
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
      validatePeriodChainAccessGroup(accessGroup);
    } catch {
      throw dcaError("bad_key", "a chain cache entry needs an accessGroup");
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
      // reads only state of the width it derives from, and no candidate
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

  /** @param {ChainContext} context @returns {(string|undefined)[]} */
  #readersOf(context) {
    if (!this.#keyBy) return [undefined];
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
   * @param {number|null} [source] - the retained chain state this leaf was derived from
   */
  #addExact(familyName, t, key, filed, source = null) {
    let family = this.#exact.get(familyName);
    if (!family) {
      family = new Map();
      this.#exact.set(familyName, family);
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
    held.splice(MAX_RIVAL_EXACT_CANDIDATES);
    this.#capMemo();
  }

  /**
   * Hold the derived-leaf memo to its ceiling, least recently derived first.
   *
   * The ceiling counts single memoized leaves rather than whole coordinates:
   * rival leaves at one coordinate are derived at different moments and a repeat
   * read wants the newest of them, so dropping a whole coordinate would throw
   * away the entry the next read is about to rebuild. Leaves filed by one read
   * tie, and a tie goes by coordinate and then family name, so two runs of one
   * scenario drop the same leaf.
   *
   * Both strategies are bounded here, `expand` included, where the store
   * holds the granted leaves themselves. Dropping the last copy of a leaf
   * costs another unlock to reopen that render, and the spec asks for the
   * bound anyway: retention longer than this bounded cache is host policy, and
   * it does not revoke capability bytes already delivered elsewhere
   * (`spec--period-key-chains.md`, Local retention policy).
   *
   * The ceiling counts leaves across every partition the cache holds, not
   * per partition, so one busy partition can crowd out another.
   */
  #capMemo() {
    let total = 0;
    for (const family of this.#exact.values()) {
      for (const held of family.values()) total += held.length;
    }
    while (total > this.#maxMemoLeaves) {
      /** @type {{ familyName: string, t: string, held: Exact[], filed: number }|null} */
      let victim = null;
      for (const [familyName, family] of this.#exact) {
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
      const family = /** @type {Map<string, Exact[]>} */ (this.#exact.get(victim.familyName));
      if (victim.held.length === 0) family.delete(victim.t);
      if (family.size === 0) this.#exact.delete(victim.familyName);
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
    const id = `${familyName}\0${windowStart}`;
    const previous = this.#windowWrites.get(id) ?? Promise.resolve();
    /** @type {() => void} */
    let release = () => {};
    const queued = new Promise((resolve) => {
      release = resolve;
    });
    this.#windowWrites.set(id, queued);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.#windowWrites.get(id) === queued) this.#windowWrites.delete(id);
    }
  }

  /**
   * File one direct chain-state grant under the response geometry.
   *
   * @param {string} accessGroup
   * @param {string} cutoffT
   * @param {Uint8Array} key
   * @param {ChainContext} [context]
   */
  async put(accessGroup, cutoffT, key, context = {}) {
    this.#evict();
    if (!(key instanceof Uint8Array) || key.length !== this.#construction.stateBytes) {
      throw dcaError(
        "bad_key",
        `a direct period-chain grant of this profile is ${this.#construction.stateBytes} key bytes`,
      );
    }
    const { geometry } = this.#family(accessGroup, context);
    periodChainCoordinate(cutoffT, geometry);
    const filed = ++this.#filed;
    if (context.lease !== undefined) {
      if (context.lease === null || typeof context.lease !== "object") {
        throw dcaError("bad_key", "a pending chain grant is filed under its response lease");
      }
      let pending = this.#pending.get(context.lease);
      if (!pending) {
        pending = [];
        this.#pending.set(context.lease, pending);
      }
      if (
        pending.length >= MAX_CHAIN_MEMBERS_PER_MESSAGE ||
        pending.filter((entry) => entry.accessGroup === accessGroup).length >=
          MAX_CHAIN_MEMBERS_PER_FAMILY
      ) {
        throw dcaError("bad_key", "a pending chain response exceeds its member bound");
      }

      // A response-private lower cutoff can prove that an already-held
      // state is the family the issuer just re-delivered. Refresh that
      // retained authority now without making the pending grant reusable;
      // otherwise a rival filed before attempted() can evict it.
      if (this.#strategy === "retain") {
        const { familyName } = this.#family(accessGroup, context);
        const cutoff = periodChainCoordinate(cutoffT, geometry);
        await this.#writeWindow(familyName, cutoff.windowStart, async () => {
          const held = this.#chains.get(familyName)?.get(cutoff.windowStart) ?? [];
          for (const candidate of held) {
            if (candidate.position < cutoff.position) continue;
            const atCutoff = await this.#derivations.stateFromState({
              state: candidate.key,
              accessGroup,
              suppliedT: candidate.cutoffT,
              targetT: cutoffT,
              geometry,
            });
            if (sameBytes(atCutoff, key)) candidate.filed = Math.max(candidate.filed, filed);
          }
          held.sort((a, b) => b.filed - a.filed);
        });
      }
      pending.push({
        accessGroup,
        cutoffT,
        key: Uint8Array.from(key),
        context: {
          publisher: context.publisher,
          issuerName: context.issuerName,
          chainsPerDay: geometry.chainsPerDay,
          periodMinutes: geometry.periodMinutes,
        },
        filed,
      });
      return;
    }
    return this.#putReusable(accessGroup, cutoffT, key, context, filed);
  }

  /** @param {string} accessGroup @param {string} cutoffT @param {Uint8Array} key @param {ChainContext} context @param {number} filed */
  async #putReusable(accessGroup, cutoffT, key, context, filed) {
    const { familyName, geometry } = this.#family(accessGroup, context);
    const cutoff = periodChainCoordinate(cutoffT, geometry);

    if (this.#strategy === "expand") {
      const leaves = await this.#derivations.expansionFromState({
        state: key,
        accessGroup,
        suppliedT: cutoffT,
        cutoffT,
        geometry,
      });
      for (const leaf of leaves) this.#addExact(familyName, leaf.t, leaf.key, filed);
      return;
    }

    return this.#writeWindow(familyName, cutoff.windowStart, async () => {
      let windows = this.#chains.get(familyName);
      if (!windows) {
        windows = new Map();
        this.#chains.set(familyName, windows);
      }
      let held = windows.get(cutoff.windowStart);
      if (!held) {
        held = [];
        windows.set(cutoff.windowStart, held);
      }
      const duplicate = held.find(
        (candidate) => candidate.position === cutoff.position && sameBytes(candidate.key, key),
      );
      if (duplicate) {
        duplicate.filed = Math.max(duplicate.filed, filed);
        held.sort((a, b) => b.filed - a.filed);
        return;
      }

      const derivesDelivered = new Set();
      const subsumed = new Set();
      for (const candidate of held) {
        if (cutoff.position > candidate.position) {
          const atCandidate = await this.#derivations.stateFromState({
            state: key,
            accessGroup,
            suppliedT: cutoffT,
            targetT: candidate.cutoffT,
            geometry,
          });
          if (sameBytes(atCandidate, candidate.key)) subsumed.add(candidate);
        } else if (candidate.position > cutoff.position) {
          const atCutoff = await this.#derivations.stateFromState({
            state: candidate.key,
            accessGroup,
            suppliedT: candidate.cutoffT,
            targetT: cutoffT,
            geometry,
          });
          if (sameBytes(atCutoff, key)) {
            derivesDelivered.add(candidate);
          }
        }
      }
      // The issuer answered again with authority a retained cutoff already
      // derives. Nothing new is filed; each retained candidate that derives
      // the delivered state takes the arriving grant's filing stamp instead,
      // so the rival cap below cannot drop the family the issuer just
      // re-delivered. Its cutoff stays where it was, and so does its reach:
      // backward to the window start and no further.
      if (derivesDelivered.size > 0) {
        for (const candidate of derivesDelivered)
          candidate.filed = Math.max(candidate.filed, filed);
        held.sort((a, b) => b.filed - a.filed);
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
      held.splice(MAX_RIVAL_CHAIN_CANDIDATES);
      windows.set(cutoff.windowStart, held);
    });
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
    this.#evict();
    const targetGeometry = this.#geometry(context);
    const target = periodChainCoordinate(t, targetGeometry);
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
        const supplied = periodChainCoordinate(entry.cutoffT, geometry);
        if (supplied.windowStart !== target.windowStart || supplied.position < target.position)
          continue;
        available.push({
          kind: "chain",
          id: null,
          state: entry.key,
          cutoffT: entry.cutoffT,
          familyName,
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
          kind: "chain",
          id: candidate.id,
          state: candidate.key,
          cutoffT: candidate.cutoffT,
          familyName,
          geometry,
          filed: candidate.filed,
          pending: false,
        });
      }
    }

    for (const issuerName of readers) {
      const { familyName } = this.#family(accessGroup, { ...context, issuerName });
      available.push(
        ...(this.#exact.get(familyName)?.get(t) ?? []).map((candidate) => ({
          kind: /** @type {const} */ ("exact"),
          ...candidate,
          pending: false,
        })),
      );
    }
    available.sort((a, b) => Number(b.pending) - Number(a.pending) || b.filed - a.filed);

    // Each bound governs its own kind. Chain states, response-private ones
    // included, share the walk budget the trial cost is measured in, and
    // memoized leaves have their own ceiling at one coordinate; the two
    // constants are read apart rather than through their equal value.
    //
    // The cap applies to work, not merely to the returned array, so a chain
    // state whose leaf at this coordinate is already memoized drops out
    // here: the memo answers for it instead of trailing its walk as a
    // duplicate. Because of duplicates, a read may return fewer keys than the
    // sum of both bounds.
    const memoized = new Set();
    for (const candidate of available) {
      if (candidate.kind === "exact") for (const source of candidate.sources) memoized.add(source);
    }
    const bounded = [
      ...available
        .filter(
          (candidate) =>
            candidate.kind === "chain" && (candidate.id === null || !memoized.has(candidate.id)),
        )
        .slice(0, MAX_RIVAL_CHAIN_CANDIDATES),
      ...available
        .filter((candidate) => candidate.kind === "exact")
        .slice(0, MAX_RIVAL_EXACT_CANDIDATES),
    ].sort((a, b) => Number(b.pending) - Number(a.pending) || b.filed - a.filed);

    // One filing stamp for the whole read: a memoized leaf files newer than
    // the state it came from, so the next read reaches it first, while
    // leaves derived together keep the rival order they were tried in.
    /** @type {number|null} */
    let memoFiled = null;
    const selected = [];
    for (const candidate of bounded) {
      let key = candidate.key;
      if (candidate.kind === "chain") {
        const state = await this.#derivations.stateFromState({
          state: candidate.state,
          accessGroup,
          suppliedT: candidate.cutoffT,
          targetT: t,
          geometry: candidate.geometry,
        });
        key = await this.#derivations.leafFromState({
          state,
          accessGroup,
          t,
          geometry: candidate.geometry,
        });
        if (!candidate.pending) {
          if (memoFiled === null) memoFiled = ++this.#filed;
          this.#addExact(candidate.familyName, t, key, memoFiled, candidate.id);
        }
      }
      if (selected.some((held) => sameBytes(held, key))) continue;
      selected.push(key);
    }
    return selected.map((key) => Uint8Array.from(key));
  }

  /**
   * Promote one response's private first-use material only after its article
   * attempt. Pending grants share the bounded chain budget rather than
   * enlarging it.
   *
   * @param {{ lease: object }} context
   */
  async attempted(context) {
    if (context?.lease === null || typeof context?.lease !== "object") {
      throw dcaError("bad_key", "a completed chain attempt names its response lease");
    }
    const pending = this.#pending.get(context.lease) ?? [];
    this.#pending.delete(context.lease);
    for (const entry of pending) {
      await this.#putReusable(
        entry.accessGroup,
        entry.cutoffT,
        entry.key,
        entry.context,
        entry.filed,
      );
    }
  }

  /** @returns {{ familyName: string, t: string, kind: 'chain'|'exact' }[]} */
  entries() {
    this.#evict();
    const entries = [];
    for (const [familyName, windows] of this.#chains) {
      for (const held of windows.values()) {
        for (const { cutoffT } of held)
          entries.push({ familyName, t: cutoffT, kind: /** @type {const} */ ("chain") });
      }
    }
    for (const [familyName, exact] of this.#exact) {
      for (const [t, held] of exact) {
        for (let index = 0; index < held.length; index++) {
          entries.push({ familyName, t, kind: /** @type {const} */ ("exact") });
        }
      }
    }
    return entries;
  }
}

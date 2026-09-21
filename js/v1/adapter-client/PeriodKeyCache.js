// @ts-check
//
// The client retains period keys between articles. Each key belongs to a
// coordinate (publisher, accessGroup, t). Different, non-interchangeable key
// bytes at one coordinate remain as rival candidates, so a supply rotation
// keeps renders sealed under both the old and new key families openable. When
// the same bytes re-arrive at a coordinate, they deduplicate, so a repeated
// article stays free.
//
// The cache returns rivals newest filed first. A period key carries no
// generation tag, so the only thing that separates two rivals at one coordinate
// is which of them arrived later, and the spec asks the trial unwrap to start
// there. The list a coordinate holds is insertion ordered and the store keeps it
// that way, so the order survives a page load rather than being rebuilt from the
// bytes.
//
// The cache stores `key` without reading it. `key` is raw bytes under direct
// transport and an opaque handle under client-bound transport. One cache serves
// both because no code here reads the value. A store under the cache is the
// exception: bytes serialise, a handle does not, and the cache refuses a handle
// with a stated error.
//
// The cache API stays async over a plain Map. With no `storage` the backing is
// a plain Map and every method still returns a promise, so every call has the
// await gap that lets one tab lose a write to another, whether or not a store is
// present.
//
// With a store under the cache there are two views. The `Storage` holds what
// the browser keeps; every tab shares it, and `candidatesAt` and `entries` read
// it. This instance holds one tab's view: what it has put and what it last
// read. The two views diverge exactly when two tabs write at once, and
// `reconcile` brings them back into agreement.
//
// `put` deliberately reads the store, changes what it read, and writes the
// result back across an await. Another tab runs in between. The write compares
// against the snapshot this call read, not against the store as it stands, so
// the second writer wins with a value it computed before the first write
// landed. A compare-and-swap here would close the gap and would also remove the
// lost-write case this cache demonstrates.
//
// The cache evicts under two rules. Capacity is a hard bound: oldest `t` first,
// ties broken by family name so two runs agree, and inside one coordinate the
// oldest-filed rival goes before the newer one. When the host supplies a clock,
// the shared period-key eviction callback also removes stale coordinates; the
// reference default is six hours. A failed trial unwrap evicts nothing under
// either rule, because the next article may be the one that key was cut for.
//
// A family always names its publisher origin and its accessGroup. The delivery
// boundary supplies the page's canonical origin outside `dca-data`; the resolver
// hands it to every put and read. Two publishers one logical client reads never
// collide on an accessGroup and period they happen to spell the same. A store
// requires it on put, so nothing is filed under a bare family. A read stays
// tolerant: a delivery with no origin takes the ordinary miss that sends the
// client to the issuer.
//
// `keyBy` composes the rest of the family name. The hazard depends on whether
// `issuerName` is part of that name. When it is not, the family name holds only
// the publisher and the accessGroup, so a key any issuer granted opens every
// article of that group, including one the publisher sealed for a stricter
// issuer alone. With `keyByIssuer`, the family name also records the granting
// issuer, and a read that names another issuer misses. Issuer partitioning is
// an option rather than the default because the leak is worth running; the
// publisher segment is not optional and cannot be turned off.
//
// The cache asks callers to name the issuer when it composes a family name.
// With a `keyBy` configured, a put names the issuer that granted the key and a
// read names the issuers it will accept one from; a call that names neither is
// refused rather than filed under a family with `undefined` in its name. Without
// a `keyBy` the context is ignored, and that is where the leak sits.
//
// `accessGroup` and `t` are names off the wire. Families live in Maps and the
// stored form is built on a null-prototype object, so a group or a period
// called `__proto__` is an ordinary name here.

import { base64urlDecode, base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { dcaError } from "../core-shared/errors.js";

/**
 * One storage entry per family, named by this prefix. A tab reads and writes a
 * whole family at a time, so two tabs collide inside one family and never
 * across two.
 *
 * A host that runs several logical clients over one backend injects a
 * `namespace`, folded in after this prefix so two clients' entries never share
 * a storage key and one client's `keys()` scan never reaches another's. With no
 * namespace injected the prefix is this bare string, and the key is the one a
 * single-client store has always held.
 */
const STORAGE_PREFIX = "dca.periodKeys.";

/** Local reference limits; neither is a wire or authorization maximum. */
const DEFAULT_MAX_ENTRIES = 12;
const MAX_RIVALS_PER_COORDINATE = 4;

/**
 * @typedef {Uint8Array|CryptoKey} PeriodKey
 */

/**
 * What a cache call says about the issuer behind the key. A put names the one
 * that granted it; a read names every issuer this page entrusts the group to,
 * because a key from any of them opens the same items here.
 *
 * @typedef {object} KeyContext
 * @property {string} [publisher] - the page's canonical delivery origin.
 *   Required on a put and always part of a stored coordinate; a read may leave
 *   it out and take the bare-family miss.
 * @property {string} [issuerName] - the granting issuer, on a put
 * @property {string[]} [issuerNames] - the acceptable issuers, on a read
 *   from the resolver that filed or asked for it. The configured `keyBy`
 *   decides which parts of this context become the stored family name.
 * @property {object} [lease] - the obtaining operation's private first-use
 *   lease; it is neither retained nor serialized.
 */

/**
 * `keyByIssuer` closes the leak the file header names: one family per (issuer,
 * accessGroup), so a key is only ever tried against pages that name the issuer
 * it came from.
 *
 * The join is `|`, which both name grammars refuse: `names.js` admits neither
 * an issuerName nor an accessGroup containing one, so `a|b-c` and `a-b|c` cannot
 * be the same family.
 *
 * @param {{ issuerName?: string, accessGroup: string }} context
 * @returns {string}
 */
export function keyByIssuer({ issuerName, accessGroup }) {
  return `${issuerName}|${accessGroup}`;
}

/**
 * What `entries` reports. `familyName` holds the family as filed: the
 * accessGroup itself, or what a `keyBy` composed from it. One row per candidate,
 * so a coordinate holding two coexisting keys reports twice.
 *
 * @typedef {object} CacheEntry
 * @property {string} familyName - the family name, as filed
 * @property {string} t
 * @property {PeriodKey} key
 */

/**
 * What a store has to answer. Duck-typed, the way `IssuerEngine` takes a key
 * store: `demo/actors/Storage` is one, localStorage and IndexedDB are the two this
 * shape was cut for.
 *
 * @typedef {object} CacheStorage
 * @property {(key: string) => Promise<string|undefined>} get
 * @property {(key: string, value: string) => Promise<void>} set
 * @property {() => Promise<string[]>} keys
 * @property {(key: string) => Promise<void>} remove
 */

/**
 * Family name -> t -> the candidates held at that coordinate. A Map of Maps
 * whose leaf is a list, because non-interchangeable keys that share a coordinate
 * coexist rather than replace one another. The outer Map is keyed by the family
 * name (the accessGroup itself, or what a `keyBy` composed), and the inner Map
 * by `t` off the wire.
 *
 * @typedef {Map<string, Map<string, PeriodKey[]>>} View
 */

/**
 * Whether two held keys are the same material, so one is a repeat of the other
 * rather than a rival to coexist beside it. Byte keys match on their bytes; a
 * handle has no readable bytes to compare, so it only ever matches itself. A
 * byte key and a handle are never the same.
 *
 * @param {PeriodKey} a
 * @param {PeriodKey} b
 * @returns {boolean}
 */
function interchangeable(a, b) {
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    return a.length === b.length && a.every((byte, i) => byte === b[i]);
  }
  return a === b;
}

/**
 * The candidates at one coordinate in trial order: the most recently filed
 * first, as `spec--period-keys.md` asks of rival keys at one coordinate. The
 * list itself is insertion ordered, oldest at the front, because `addCandidate`
 * appends and a re-put of bytes already held changes nothing. Reversing the
 * list is therefore all the rule asks, and it applies to a handle the same way,
 * since filing order is a fact about the put rather than about the value.
 *
 * @param {PeriodKey[]} list
 * @returns {PeriodKey[]}
 */
function newestFiledFirst(list) {
  return [...list].reverse();
}

/**
 * Add one candidate to a coordinate, keeping it beside the ones already there
 * unless it repeats one of them, in which case the list is left alone. An
 * identical re-put therefore costs nothing, while a rotation's different bytes
 * coexist.
 *
 * @param {PeriodKey[]} list - changed in place
 * @param {PeriodKey} key
 */
function addCandidate(list, key) {
  for (const held of list) {
    if (interchangeable(held, key)) return;
  }
  list.push(key);
}

/**
 * Retain only the newest locally permitted rivals at each coordinate.
 *
 * @param {View} view - changed in place
 * @returns {{ familyName: string, t: string, key: PeriodKey }[]}
 */
function evictRivalsToCapacity(view) {
  const evicted = [];
  for (const [familyName, family] of view) {
    for (const [t, list] of family) {
      while (list.length > MAX_RIVALS_PER_COORDINATE) {
        evicted.push({ familyName, t, key: /** @type {PeriodKey} */ (list.shift()) });
      }
      if (list.length === 0) family.delete(t);
    }
    if (family.size === 0) view.delete(familyName);
  }
  return evicted;
}

/**
 * The wire form of one family: `t` to the base64url of each candidate held at
 * it. The `t`s are sorted and each candidate list is written oldest to newest,
 * exactly as it is held, so a family holding the same keys serialises to the
 * same string. The write can then skip an unchanged family without keeping a
 * dirty flag, and `parse` returns the list with its filing order intact.
 *
 * @param {Map<string, PeriodKey[]>} family
 * @returns {string}
 */
function serialize(family) {
  /** @type {Record<string, string[]>} */
  const out = Object.create(null);
  for (const t of [...family.keys()].sort()) {
    out[t] = /** @type {PeriodKey[]} */ (family.get(t)).map((key) =>
      base64urlEncode(/** @type {Uint8Array} */ (key)),
    );
  }
  return JSON.stringify(out);
}

/**
 * Reads one stored family back. Anything else under our prefix is another
 * writer's data or a corrupted store, and either way is refused rather than
 * read past. Each `t` holds a list of keys, the candidates coexisting at that
 * coordinate.
 *
 * @param {string} stored
 * @param {string} storageKey - for the message
 * @returns {Map<string, PeriodKey[]>}
 */
function parse(stored, storageKey) {
  let parsed;
  try {
    parsed = JSON.parse(stored);
  } catch {
    throw dcaError("bad_storage", `${storageKey} does not hold a periodKey family`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw dcaError("bad_storage", `${storageKey} does not hold a periodKey family`);
  }

  /** @type {Map<string, PeriodKey[]>} */
  const family = new Map();
  for (const [t, value] of Object.entries(parsed)) {
    if (!Array.isArray(value)) {
      throw dcaError(
        "bad_storage",
        `${storageKey} holds something that is not a candidate list at ${t}`,
      );
    }
    /** @type {PeriodKey[]} */
    const list = [];
    for (const encoded of value) {
      if (typeof encoded !== "string") {
        throw dcaError("bad_storage", `${storageKey} holds something that is not a key at ${t}`);
      }
      try {
        list.push(base64urlDecode(encoded));
      } catch {
        throw dcaError("bad_storage", `${storageKey} holds a key that cannot be decoded at ${t}`);
      }
    }
    if (list.length > 0) family.set(t, list);
  }
  return family;
}

/**
 * How many candidates a view holds. `entries()` reports one row per candidate,
 * so capacity is counted the same way: a coordinate holding rival keys counts
 * once per candidate, not once per coordinate. Rival candidates coexist while
 * capacity permits, and capacity still applies to them.
 *
 * @param {View} view
 * @returns {number}
 */
function count(view) {
  let total = 0;
  for (const family of view.values()) {
    for (const list of family.values()) total += list.length;
  }
  return total;
}

/**
 * Evicts down to capacity, oldest `t` first across every family. Nothing else
 * is a reason to remove a candidate.
 *
 * The victim coordinate is the smallest `(t, family name)` there is: the period
 * orders them, and the name only where two families hold the same period. Which
 * name wins a tie is arbitrary; the coordinates settle it rather than insertion
 * order, since two runs of one scenario have to evict the same candidate.
 *
 * A coordinate holding rival candidates gives up its oldest-filed rival first,
 * the front of the insertion-ordered list, and stays the oldest coordinate
 * until its list empties, so the oldest coordinate is drained before the
 * next-oldest is touched. The coordinate itself is deleted only once nothing is
 * left at it. Filing order settles this the way it settles trial order: nothing
 * else tells two rivals apart.
 *
 * @param {View} view - changed in place
 * @param {number|null} maxEntries
 * @returns {{ familyName: string, t: string, key: PeriodKey }[]} what went, in the order it went
 */
function evictToCapacity(view, maxEntries) {
  /** @type {{ familyName: string, t: string, key: PeriodKey }[]} */
  const evicted = [];
  if (maxEntries === null) return evicted;

  let total = count(view);
  while (total > maxEntries) {
    /** @type {{ familyName: string, t: string }|null} */
    let victim = null;
    for (const [familyName, family] of view) {
      for (const t of family.keys()) {
        if (victim === null || t < victim.t || (t === victim.t && familyName < victim.familyName)) {
          victim = { familyName, t };
        }
      }
    }
    if (victim === null) break;

    const family = /** @type {Map<string, PeriodKey[]>} */ (view.get(victim.familyName));
    const list = /** @type {PeriodKey[]} */ (family.get(victim.t));
    const goes = /** @type {PeriodKey} */ (list.shift());
    if (list.length === 0) family.delete(victim.t);
    if (family.size === 0) view.delete(victim.familyName);

    evicted.push({ familyName: victim.familyName, t: victim.t, key: goes });
    total--;
  }
  return evicted;
}

/**
 * Apply the host's coordinate policy independently inside every exact-key
 * family. All rival candidates at an evicted coordinate leave together.
 *
 * @param {View} view
 * @param {(entry: any, context: { now: Date }) => boolean} policy
 * @param {Date} now
 * @returns {{ familyName: string, t: string, key: PeriodKey }[]}
 */
function evictByPolicy(view, policy, now) {
  const evicted = [];
  for (const [familyName, family] of view) {
    for (const [t, list] of family) {
      if (!policy({ pool: "independent", t, kind: "exact" }, { now })) continue;
      for (const key of list) evicted.push({ familyName, t, key });
      family.delete(t);
    }
    if (family.size === 0) view.delete(familyName);
  }
  return evicted;
}

export class PeriodKeyCache {
  /**
   * This instance's view. With no store it holds the whole cache. With one it
   * holds what this tab has put and last read, and `reconcile` repairs the
   * store from this record.
   *
   * @type {View}
   */
  #families = new Map();

  /** @type {CacheStorage|null} */
  #storage = null;

  /**
   * The storage-key prefix every family of this cache is filed under. The
   * bare `STORAGE_PREFIX` for a single-client store, or that prefix plus the
   * injected `namespace` when a host runs several clients over one backend, so
   * this cache's reads, writes and `keys()` scan stay inside its own client's
   * entries.
   *
   * @type {string}
   */
  #keyPrefix = STORAGE_PREFIX;

  /** @type {number|null} */
  #maxEntries = DEFAULT_MAX_ENTRIES;

  /** Response-private exact capabilities, keyed by their obtaining lease. */
  #pending = new WeakMap();

  /** @type {((context: { issuerName?: string, accessGroup: string }) => string)|null} */
  #keyBy = null;

  /** @type {{ now: () => Date }|null} */
  #clock = null;

  /** @type {((entry: any, context: { now: Date }) => boolean)|null} */
  #evictionPolicy = null;

  /**
   * @param {{ maxEntries?: number, storage?: CacheStorage, keyBy?: (context: { issuerName?: string, accessGroup: string }) => string, namespace?: string, clock?: { now: () => Date }, evictionPolicy?: Function }} [config]
   */
  constructor(config = {}) {
    for (const name of Object.keys(config)) {
      if (
        !["maxEntries", "storage", "keyBy", "namespace", "clock", "evictionPolicy"].includes(name)
      ) {
        throw dcaError(
          "unsupported_option",
          `PeriodKeyCache has no ${name} yet, and will not pretend to`,
        );
      }
    }

    const { maxEntries, storage, keyBy, namespace, clock, evictionPolicy } = config;

    if (clock !== undefined && typeof clock?.now !== "function") {
      throw dcaError("bad_config", "a period-key cache clock answers now()");
    }
    if (evictionPolicy !== undefined && typeof evictionPolicy !== "function") {
      throw dcaError("bad_config", "a period-key evictionPolicy is a callback");
    }
    if ((clock === undefined) !== (evictionPolicy === undefined)) {
      throw dcaError("bad_config", "a period-key evictionPolicy and clock are configured together");
    }
    this.#clock = clock ?? null;
    this.#evictionPolicy = /** @type {any} */ (evictionPolicy ?? null);

    // The host names the scope. Given one, it goes in the storage-key prefix
    // so two clients over one backend cannot read or overwrite each other;
    // left out, the prefix is bare and the key is what a single-client store
    // has always held.
    if (namespace !== undefined) {
      if (typeof namespace !== "string" || namespace.length === 0) {
        throw dcaError(
          "bad_config",
          "a namespace is the non-empty name of the logical client this cache is scoped to",
        );
      }
      // base64url the namespace's utf8 bytes so the segment holds only
      // [A-Za-z0-9_-] and never a `.`. The `.` boundary can then only
      // follow a complete encoded token, so one namespace's prefix can
      // never be a prefix of another's entries. A dotted `a.b` and a bare
      // `a` encode to unrelated tokens, so neither nests in the other. A
      // host may name a client with dots; the encoding keeps the boundary
      // unambiguous.
      this.#keyPrefix = `${STORAGE_PREFIX}${base64urlEncode(utf8Encode(namespace))}.`;
    }

    if (keyBy !== undefined) {
      if (typeof keyBy !== "function") {
        throw dcaError(
          "bad_config",
          "a keyBy composes the family name from { accessGroup, issuerName }",
        );
      }
      this.#keyBy = keyBy;
    }

    if (maxEntries !== undefined) {
      if (!Number.isInteger(maxEntries) || maxEntries < 1) {
        throw dcaError(
          "bad_config",
          `maxEntries is a whole number of entries, at least one; got ${maxEntries}`,
        );
      }
      this.#maxEntries = maxEntries;
    }

    if (storage !== undefined) {
      for (const call of ["get", "set", "keys", "remove"]) {
        if (typeof (/** @type {any} */ (storage)?.[call]) !== "function") {
          throw dcaError(
            "bad_config",
            `a cache storage answers get, set, keys and remove; this one has no ${call}`,
          );
        }
      }
      this.#storage = storage;
    }
  }

  /**
   * The family one call names. The publisher is the outermost segment and is
   * always there when the resolver drives the cache, so two publishers never
   * collide on an accessGroup and a period they spell the same. Inside that,
   * without a composer the family is the accessGroup and the issuer context is
   * not consulted. That causes the leak: whichever issuer granted the key, it
   * is filed in the same family under one publisher and opens that publisher's
   * items.
   *
   * The join is `|`, which no host, issuerName or accessGroup grammar admits,
   * so the segments cannot run together into one another's names.
   *
   * @param {string} accessGroup
   * @param {string|undefined} publisher - the folded publisher identity
   * @param {string|undefined} issuerName
   * @returns {string}
   */
  #familyName(accessGroup, publisher, issuerName) {
    let base = accessGroup;
    if (this.#keyBy) {
      const composed = this.#keyBy({ accessGroup, issuerName });
      if (typeof composed !== "string" || composed.length === 0) {
        throw dcaError("bad_key", "a keyBy answers with the name of one family");
      }
      base = composed;
    }
    return publisher === undefined ? base : `${publisher}|${base}`;
  }

  /**
   * Which issuers a read will take a key from. A composing cache requires the
   * caller to name them and refuses to guess: a read that names nobody would
   * either miss everything or fall back to the flat family, and treating either
   * result as an answer would reintroduce the leak under the mitigation's name.
   *
   * @param {KeyContext} context
   * @returns {(string|undefined)[]}
   */
  #readersOf(context) {
    if (!this.#keyBy) return [undefined];

    const { issuerName, issuerNames } = context;
    if (Array.isArray(issuerNames)) {
      if (issuerNames.some((name) => typeof name !== "string")) {
        throw dcaError("bad_key", "the issuers a read accepts a key from are names");
      }
      return issuerNames;
    }
    if (typeof issuerName === "string") return [issuerName];

    throw dcaError(
      "bad_key",
      "an issuer-keyed cache is told which issuers a read accepts a key from",
    );
  }

  /**
   * Reads one family from the store, along with the bytes it was read as. The
   * write compares against those bytes, so a family nobody changed is not
   * rewritten.
   *
   * Everything below this point works in family names, which is the
   * accessGroup itself unless a `keyBy` composed one.
   *
   * @param {string} name - the family name, already composed
   * @returns {Promise<{ view: View, raw: Map<string, string> }>}
   */
  async #readFamily(name) {
    /** @type {View} */
    const view = new Map();
    /** @type {Map<string, string>} */
    const raw = new Map();

    const storageKey = this.#keyPrefix + name;
    const stored = await /** @type {CacheStorage} */ (this.#storage).get(storageKey);
    if (stored !== undefined) {
      raw.set(name, stored);
      const family = parse(stored, storageKey);
      if (family.size > 0) view.set(name, family);
    }

    return { view, raw };
  }

  /**
   * Reads everything the store holds. Capacity is counted over all of it,
   * since a family this tab has never touched still takes room.
   *
   * @returns {Promise<{ view: View, raw: Map<string, string> }>}
   */
  async #readAll() {
    const storage = /** @type {CacheStorage} */ (this.#storage);

    /** @type {View} */
    const view = new Map();
    /** @type {Map<string, string>} */
    const raw = new Map();

    for (const storageKey of await storage.keys()) {
      if (!storageKey.startsWith(this.#keyPrefix)) continue;
      const stored = await storage.get(storageKey);
      if (stored === undefined) continue;

      const familyName = storageKey.slice(this.#keyPrefix.length);
      raw.set(familyName, stored);
      const family = parse(stored, storageKey);
      if (family.size > 0) view.set(familyName, family);
    }

    return { view, raw };
  }

  /**
   * Writes the families in `scope` that differ from how they were read.
   * A family emptied by eviction is removed rather than left as an empty
   * object, which is the form a store holds for something with nothing in it.
   *
   * @param {View} view
   * @param {Map<string, string>} raw
   * @param {Iterable<string>} scope
   * @returns {Promise<void>}
   */
  async #write(view, raw, scope) {
    const storage = /** @type {CacheStorage} */ (this.#storage);

    for (const familyName of [...scope].sort()) {
      const storageKey = this.#keyPrefix + familyName;
      const family = view.get(familyName);

      if (family === undefined || family.size === 0) {
        if (raw.has(familyName)) await storage.remove(storageKey);
        continue;
      }

      const serialized = serialize(family);
      if (serialized !== raw.get(familyName)) await storage.set(storageKey, serialized);
    }
  }

  /**
   * What this tab now has on record as held: everything it knew, plus what it
   * just read and wrote, minus what it evicted itself. A coordinate this tab
   * accepted stays in the record even after the store loses it, which leaves
   * `reconcile` something to restore.
   *
   * @param {View} view
   * @param {Iterable<string>} scope
   * @param {{ familyName: string, t: string, key: PeriodKey }[]} evicted
   */
  #record(view, scope, evicted) {
    for (const familyName of scope) {
      const family = view.get(familyName);
      if (family === undefined) continue;

      let held = this.#families.get(familyName);
      if (!held) {
        held = new Map();
        this.#families.set(familyName, held);
      }
      for (const [t, list] of family) {
        let heldList = held.get(t);
        if (!heldList) {
          heldList = [];
          held.set(t, heldList);
        }
        for (const key of list) addCandidate(heldList, key);
      }
    }

    // The union above only adds, so this loop removes each candidate this tab
    // evicted: it is gone from `view`, but the record may still hold it from
    // before. Only the evicted candidate goes; the rivals that
    // shared its coordinate stay, and the coordinate is dropped once nothing
    // is left at it.
    for (const { familyName, t, key } of evicted) {
      const held = this.#families.get(familyName);
      if (!held) continue;
      const list = held.get(t);
      if (!list) continue;
      const idx = list.findIndex((candidate) => interchangeable(candidate, key));
      if (idx !== -1) list.splice(idx, 1);
      if (list.length === 0) held.delete(t);
      if (held.size === 0) this.#families.delete(familyName);
    }
  }

  /**
   * @param {string} accessGroup
   * @param {string} t
   * @param {PeriodKey} key
   * @param {KeyContext} [context] - the publisher it belongs to, required and
   *   always part of the family, and who granted it, read only through the
   *   `keyBy` so a cache that does not compose by issuer never files by grantor.
   * @returns {Promise<void>}
   */
  async put(accessGroup, t, key, context = {}) {
    if (!accessGroup || !t || typeof accessGroup !== "string" || typeof t !== "string") {
      throw dcaError("bad_key", "a cache entry needs an accessGroup and a t");
    }
    // The publisher is part of every stored coordinate, so a delivered key
    // never files under a bare family two publishers would share. Required
    // on a store the way the grantor is required under a keyBy: a coordinate
    // missing it is refused rather than misfiled. A read stays tolerant: a
    // page whose domain did not fold looks up under the bare family and
    // takes the ordinary miss.
    if (typeof context.publisher !== "string" || context.publisher.length === 0) {
      throw dcaError("bad_key", "a cache entry files under its publisher, which is a name");
    }
    // A key whose grantor is unnamed cannot be filed by grantor. Refused
    // rather than filed under a family nothing will ever read again.
    if (this.#keyBy && typeof context.issuerName !== "string") {
      throw dcaError("bad_key", "an issuer-keyed cache is told which issuer granted a key");
    }

    const name = this.#familyName(accessGroup, context.publisher, context.issuerName);

    if (context.lease !== undefined) {
      if (context.lease === null || typeof context.lease !== "object") {
        throw dcaError("bad_key", "a response-private cache entry carries its operation lease");
      }
      let pending = this.#pending.get(context.lease);
      if (!pending) {
        pending = new Map();
        this.#pending.set(context.lease, pending);
      }
      let family = pending.get(name);
      if (!family) {
        family = new Map();
        pending.set(name, family);
      }
      let list = family.get(t);
      if (!list) {
        list = [];
        family.set(t, list);
      }
      addCandidate(list, key);
      evictRivalsToCapacity(pending);
      // File independently now. The lease copy is only the obtaining
      // operation's first-use guarantee; a retained application report
      // must not be the sole route by which a later resolve can see a
      // capability the ordinary bounded cache kept.
      await this.put(accessGroup, t, key, {
        publisher: context.publisher,
        issuerName: context.issuerName,
      });
      return;
    }

    if (!this.#storage) {
      let family = this.#families.get(name);
      if (!family) {
        family = new Map();
        this.#families.set(name, family);
      }
      let list = family.get(t);
      if (!list) {
        list = [];
        family.set(t, list);
      }
      addCandidate(list, key);
      if (this.#clock && this.#evictionPolicy)
        evictByPolicy(this.#families, this.#evictionPolicy, this.#clock.now());
      evictRivalsToCapacity(this.#families);
      evictToCapacity(this.#families, this.#maxEntries);
      return;
    }

    // The store keeps strings. Bytes serialise; an opaque handle does not,
    // and never will. This is the design's one asymmetry: client-bound
    // transport needs an IndexedDB adapter rather than this one. The check
    // refuses a handle before the read, so a caller cannot be left believing
    // it landed.
    if (!(key instanceof Uint8Array)) {
      throw dcaError(
        "bad_key",
        "a storage-backed cache holds key bytes; a CryptoKey needs a store that keeps handles",
      );
    }

    // READ. Capacity is counted over the whole store, so a put that has to
    // make room reads every family; one that cannot overflow reads only the
    // family it is writing.
    const { view, raw } = await this.#readAll();

    // Modify the snapshot. This runs after that await, and nothing another
    // tab did in between is visible here.
    let family = view.get(name);
    if (!family) {
      family = new Map();
      view.set(name, family);
    }
    let list = family.get(t);
    if (!list) {
      list = [];
      family.set(t, list);
    }
    addCandidate(list, key);

    const evicted = [
      ...(this.#clock && this.#evictionPolicy
        ? evictByPolicy(view, this.#evictionPolicy, this.#clock.now())
        : []),
      ...evictRivalsToCapacity(view),
      ...evictToCapacity(view, this.#maxEntries),
    ];
    const scope = new Set([...view.keys(), ...raw.keys(), ...evicted.map((e) => e.familyName)]);

    // Write back.
    await this.#write(view, raw, scope);
    this.#record(view, scope, evicted);
  }

  /**
   * Every key held for one exact coordinate, newest filed first. The caller
   * supplies the article's authored `t`; this cache never scans unrelated
   * coordinates in an access-group family on the resolution path.
   *
   * It reads the store rather than this tab's record: what another tab wrote
   * is a key this one can open an article with, and what another tab took
   * away is a key it no longer has.
   *
   * An unknown family is an empty list, not a throw: a miss is the ordinary
   * case that sends the client to an issuer. So is a trial that opens
   * nothing - reading takes nothing out of the cache.
   *
   * A composing cache reads one family per issuer the caller will take a key
   * from, in the order it named them: the page's own order, and the trial
   * stops at the first key that opens the item either way.
   *
   * @param {string} accessGroup
   * @param {string} t
   * @param {KeyContext} [context]
   * @returns {Promise<PeriodKey[]>}
   */
  async candidatesAt(accessGroup, t, context = {}) {
    if (context.publisher !== undefined && typeof context.publisher !== "string") {
      throw dcaError("bad_key", "a read files under a folded publisher, which is a name");
    }
    if (!t || typeof t !== "string") {
      throw dcaError("bad_key", "a cache read names its exact t coordinate");
    }

    /** @type {PeriodKey[]} */
    const held = [];

    for (const issuerName of this.#readersOf(context)) {
      const name = this.#familyName(accessGroup, context.publisher, issuerName);
      let family;
      if (this.#storage) {
        const { view, raw } = await this.#readAll();
        const evicted = [
          ...(this.#clock && this.#evictionPolicy
            ? evictByPolicy(view, this.#evictionPolicy, this.#clock.now())
            : []),
          ...evictRivalsToCapacity(view),
          ...evictToCapacity(view, this.#maxEntries),
        ];
        if (evicted.length > 0) {
          const scope = new Set([
            ...view.keys(),
            ...raw.keys(),
            ...evicted.map((e) => e.familyName),
          ]);
          await this.#write(view, raw, scope);
          this.#record(view, scope, evicted);
        }
        family = view.get(name);
      } else {
        if (this.#clock && this.#evictionPolicy)
          evictByPolicy(this.#families, this.#evictionPolicy, this.#clock.now());
        evictRivalsToCapacity(this.#families);
        evictToCapacity(this.#families, this.#maxEntries);
        family = this.#families.get(name);
      }
      const pending = context.lease === undefined ? undefined : this.#pending.get(context.lease);
      const pendingList = pending?.get(name)?.get(t) ?? [];
      if (!family && pendingList.length === 0) continue;
      // Private material leads retained material for this issuer, but a
      // repeated response key is still one trial, not two.
      for (const key of [
        ...newestFiledFirst(pendingList),
        ...newestFiledFirst(family?.get(t) ?? []),
      ]) {
        if (!held.some((candidate) => interchangeable(candidate, key))) held.push(key);
      }
    }

    return held;
  }

  /**
   * Everything held, for bookkeeping. Newest `t` first within a family and
   * newest filed first within a `t`, so two reads of an unchanged cache
   * report the same way and report it in trial order.
   *
   * With a `keyBy`, `familyName` carries the composed name: the cache files
   * what it was told to compose and does not take it apart again.
   *
   * @returns {Promise<CacheEntry[]>}
   */
  async entries() {
    let view;
    if (this.#storage) {
      const read = await this.#readAll();
      view = read.view;
      const evicted = [
        ...(this.#clock && this.#evictionPolicy
          ? evictByPolicy(view, this.#evictionPolicy, this.#clock.now())
          : []),
        ...evictRivalsToCapacity(view),
        ...evictToCapacity(view, this.#maxEntries),
      ];
      if (evicted.length > 0) {
        const scope = new Set(evicted.map(({ familyName }) => familyName));
        await this.#write(view, read.raw, scope);
        this.#record(view, scope, evicted);
      }
    } else {
      if (this.#clock && this.#evictionPolicy)
        evictByPolicy(this.#families, this.#evictionPolicy, this.#clock.now());
      evictRivalsToCapacity(this.#families);
      evictToCapacity(this.#families, this.#maxEntries);
      view = this.#families;
    }

    /** @type {CacheEntry[]} */
    const all = [];
    for (const familyName of [...view.keys()].sort()) {
      const family = /** @type {Map<string, PeriodKey[]>} */ (view.get(familyName));
      for (const t of [...family.keys()].sort().reverse()) {
        for (const key of newestFiledFirst(/** @type {PeriodKey[]} */ (family.get(t)))) {
          all.push({ familyName, t, key });
        }
      }
    }
    return all;
  }

  /**
   * Repairs a lost write. A caller invokes it; nothing here schedules
   * it. A timer would put it outside the test's control, and "the background
   * tab reconciled a second late" is a case worth being able to write.
   *
   * `reconcile` reads from two sources. The store is the source of truth for
   * what the browser holds: it is shared, and every tab reads it. This tab's
   * record is the source of truth for what it accepted from an issuer, and the
   * only place a candidate another tab wrote over still exists. So the two are
   * unioned candidate by candidate: a key the store already holds is left alone
   * and one it is missing is added beside it, so restoring a key never costs
   * another tab the one it just put there, and a coordinate the two tabs reach
   * with different bytes keeps both rather than one winning.
   *
   * That makes it additive to the store and idempotent by construction: a
   * second call finds nothing the store is missing, serialises to the bytes
   * already there, and writes nothing. Capacity is applied to the union, so
   * a repair cannot push the cache over its size.
   *
   * With no store there is nothing to reconcile against: the Map is both the
   * tab's view and the whole cache.
   *
   * @returns {Promise<void>}
   */
  async reconcile() {
    if (!this.#storage) return;

    const { view, raw } = await this.#readAll();

    for (const [familyName, held] of this.#families) {
      let family = view.get(familyName);
      if (!family) {
        family = new Map();
        view.set(familyName, family);
      }
      for (const [t, list] of held) {
        let family_t = family.get(t);
        if (!family_t) {
          family_t = [];
          family.set(t, family_t);
        }
        for (const key of list) addCandidate(family_t, key);
      }
    }

    if (this.#clock && this.#evictionPolicy)
      evictByPolicy(view, this.#evictionPolicy, this.#clock.now());
    evictRivalsToCapacity(view);
    evictToCapacity(view, this.#maxEntries);
    await this.#write(view, raw, new Set([...view.keys(), ...raw.keys()]));

    for (const [familyName, family] of view) {
      if (family.size === 0) view.delete(familyName);
    }
    this.#families = view;
  }

  /**
   * Discard one response's private first-use copy after its article attempt.
   *
   * @param {{ lease: object }} context
   */
  async attempted({ lease }) {
    if (lease === null || typeof lease !== "object") {
      throw dcaError("bad_key", "a completed cache attempt names its operation lease");
    }
    if (!this.#pending.has(lease)) return;
    this.#pending.delete(lease);
  }
}

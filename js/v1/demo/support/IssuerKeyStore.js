// @ts-check
//
// An issuer keeps its own keypairs here, filed under two coordinates: an
// issuerName and a keyId. Two coordinates, because one deployment can answer
// for more than one issuer name, and because the engine looks up with the name
// the request carried rather than one it already knew.
//
// A store says one of three things, and `core-issuer/IssuerEngine` reads all three:
// `undefined` is a keyId this issuer never held, an entry with a `privateKey`
// is one it holds, and `{ retired: true }` is one it held and has let go. The
// store carries the third case itself instead of leaving a test to hand-build
// it: a rollover is the case the split exists for, and a store that could only
// say two of the three would make it unreachable.
//
// Presence of the `privateKey` field makes the claim, whatever value sits
// behind it, so an entry that carries both fields, or neither, is refused where
// it is written. The engine answers that shape with `bad_config`, an operator's
// mistake; this store throws the same `bad_config` at the write, before any
// request arrives. A caller can
// still reach the engine with such an entry by handing it a plain object with a
// `get`, which is how the engine's own refusal is tested.
//
// The store counts the reaches it was asked for. `core-issuer/IssuerEngine`
// absorbs an unseal failure into a per-item error beside a 200, so a fixture
// holding a private key that opens nothing produces the same wire as one that was
// never consulted at all. Only the count separates those two, and the reject
// vectors record it as `privateKeyReached`; an assertion that the refusal
// landed before any private key was touched rests on that count.
//
// `publicKey` returns the other side of the same entry, the half handed over at
// onboarding and the only part a publisher ever sees. Asking for it counts no
// reach: nothing about the private key was consulted. A retired
// coordinate still answers, because the markup that outlived the key was sealed
// under it.
//
// `privateKeyOf` hands the private half over without counting either, which is
// its only difference from `get`. A call to `get` stands for the issuer reaching
// for a key to answer a request, and a test that unseals a blob on its own is
// not the issuer. Reading it through `get` would put a reach on the store that
// no request made, and a claim that nothing was touched rests on the count.

import { dcaError } from "../../core-shared/errors.js";

/**
 * One coordinate's worth of key material, in the form a store is built from.
 *
 * @typedef {object} KeyStoreEntry
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} [algorithm] - 'ECDH-P256' or 'RSA-OAEP'
 * @property {CryptoKey} [privateKey] - present on an entry this issuer holds
 * @property {CryptoKey} [publicKey] - the half the publisher seals with
 * @property {true} [retired] - present on an entry it has let go
 */

/**
 * Checks that an entry says which of the three things it is, and throws where
 * the entry is written if it does not.
 *
 * @param {any} entry
 * @param {string} where
 * @returns {void}
 */
function checkEntry(entry, where) {
  if (entry === null || typeof entry !== "object") {
    throw dcaError("bad_config", `${where} is a key entry or a retirement`);
  }

  const retired = entry.retired === true;
  const claimsKey = Object.hasOwn(entry, "privateKey") && entry.privateKey !== undefined;
  if (retired === claimsKey) {
    throw dcaError(
      "bad_config",
      `${where} is ` +
        (claimsKey ? "both held and retired" : "neither a private key nor a retirement"),
    );
  }
  if (claimsKey && typeof entry.algorithm !== "string") {
    throw dcaError(
      "bad_config",
      `${where} holds a private key and has to say which algorithm it is for`,
    );
  }
}

export class IssuerKeyStore {
  /**
   * issuerName -> keyId -> what is held there. Nested rather than a composed
   * string key, so no name can be spelled to collide with another pair.
   *
   * @type {Map<string, Map<string, any>>}
   */
  #entries = new Map();

  #reaches = 0;

  /**
   * @param {KeyStoreEntry[]} [entries] - every coordinate this store starts
   *   with. A later one arrives through `rotate`.
   */
  constructor(entries = []) {
    if (!Array.isArray(entries)) {
      throw dcaError("bad_config", "an IssuerKeyStore is built from a list of entries");
    }
    for (const entry of entries) {
      const { issuerName, keyId, ...rest } = entry ?? /** @type {any} */ ({});
      if (typeof issuerName !== "string" || typeof keyId !== "string") {
        throw dcaError("bad_config", "a key entry is filed under an issuerName and a keyId");
      }
      checkEntry(rest, `the entry for issuer "${issuerName}" keyId "${keyId}"`);
      this.#put(issuerName, keyId, rest);
    }
  }

  /**
   * @param {string} issuerName
   * @param {string} keyId
   * @param {any} entry
   * @returns {void}
   */
  #put(issuerName, keyId, entry) {
    let held = this.#entries.get(issuerName);
    if (!held) {
      held = new Map();
      this.#entries.set(issuerName, held);
    }
    held.set(keyId, entry);
  }

  /**
   * The engine reads this, and it is the only path that counts a reach. It
   * returns the private half alone: the public half is the publisher's
   * business, and an issuer about to unseal a blob has no use for it.
   *
   * A test that unseals a blob itself wants `privateKeyOf` instead. That read
   * is the test doing the issuer's arithmetic on its own, and counting it would
   * put a reach on the store that no request made.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @returns {{ algorithm: string, privateKey: CryptoKey }|{ retired: true }|undefined}
   */
  get(issuerName, keyId) {
    this.#reaches++;

    const entry = this.#entries.get(issuerName)?.get(keyId);
    if (entry === undefined) return undefined;
    if (entry.retired === true) return { retired: true };

    return {
      algorithm: entry.algorithm,
      privateKey: entry.privateKey,
    };
  }

  /**
   * What the publisher was given at onboarding. A retired coordinate still
   * answers: the markup an edge cache is serving was sealed under this half,
   * and the retirement is about the other one.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @returns {CryptoKey|undefined}
   */
  publicKey(issuerName, keyId) {
    return this.#entries.get(issuerName)?.get(keyId)?.publicKey;
  }

  /**
   * The private half, handed over without counting a reach. A test that opens a
   * blob itself uses this. `reachCount` records how far into the issuer a
   * request got, and a test reading the key on its own is not a request, so
   * counting it would spend the assertion the count exists for.
   *
   * A retired coordinate has no private half here, the same as one this store
   * never held: retiring a key removes it.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @returns {CryptoKey|undefined}
   */
  privateKeyOf(issuerName, keyId) {
    return this.#entries.get(issuerName)?.get(keyId)?.privateKey;
  }

  /**
   * Puts a key in, or forgets a coordinate. Writing a held entry over a keyId
   * replaces it; `null` removes the coordinate entirely, so a later request
   * naming it finds nothing. The older `{ retired: true }` form delegates to
   * `retire`, which keeps the public half.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @param {KeyStoreEntry|{ retired: true }|null} entry
   * @returns {void}
   */
  rotate(issuerName, keyId, entry) {
    if (typeof issuerName !== "string" || typeof keyId !== "string") {
      throw dcaError("bad_config", "a rotation names an issuerName and the keyId it lands on");
    }
    if (entry === null) {
      this.#entries.get(issuerName)?.delete(keyId);
      return;
    }

    const { issuerName: named, keyId: namedKey, ...rest } = /** @type {any} */ (entry ?? {});
    // A rotation says where it lands in its own arguments. An entry
    // repeating a different coordinate inside itself is two answers to one
    // question, and silently preferring either would file a key somewhere
    // the caller did not ask for.
    if (
      (named !== undefined && named !== issuerName) ||
      (namedKey !== undefined && namedKey !== keyId)
    ) {
      throw dcaError(
        "bad_config",
        "a rotation entry naming another coordinate contradicts the one it is filed at",
      );
    }
    checkEntry(rest, `the entry rotated to issuer "${issuerName}" keyId "${keyId}"`);
    if (rest.retired === true) {
      this.retire(issuerName, keyId);
      return;
    }
    this.#put(issuerName, keyId, rest);
  }

  /**
   * Remove one held private key while retaining its coordinate and public
   * half. Repeating a retirement is harmless; inventing a retirement for a
   * coordinate the store never held is a configuration error.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @returns {void}
   */
  retire(issuerName, keyId) {
    if (typeof issuerName !== "string" || typeof keyId !== "string" || keyId.length === 0) {
      throw dcaError("bad_config", "a retirement names an issuerName and a keyId");
    }

    const entry = this.#entries.get(issuerName)?.get(keyId);
    if (entry?.retired === true) return;
    if (entry === undefined) {
      throw dcaError("bad_config", `issuer "${issuerName}" holds no key "${keyId}" to retire`);
    }

    this.#put(issuerName, keyId, {
      retired: true,
      ...(entry.publicKey === undefined ? {} : { publicKey: entry.publicKey }),
    });
  }

  /**
   * How often this store was asked for a private key, over its whole life. A
   * refusal that landed on integrity should show zero here: the request was turned
   * away before any key was touched.
   */
  get reachCount() {
    return this.#reaches;
  }

  /** Whether anything reached the private-key side at all. */
  get privateKeyReached() {
    return this.#reaches > 0;
  }
}

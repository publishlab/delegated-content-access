// @ts-check
//
// A period-key cache that keeps the pre-open delivery rather than the opened
// material. Where `PeriodKeyCache` keeps bytes under direct or a `CryptoKey`
// handle under client-bound, this one keeps `context.delivery`, throws the
// opened key away, and re-opens the delivery on every read. A client-bound entry
// therefore holds no key material: only the wrapped wire value plus response
// transport. A direct entry is different: its base64url string is encoded raw
// period-key material, so the no-key claim does not apply to direct mode.
//
// The resolver's store seam allows this other cache-form, the client and
// host's choice, and it exercises the seam without the handle cache changing at
// all: `put` reads only `context.delivery`, `candidates` re-opens each held
// delivery through the client-bound capability (or decodes a direct string to
// bytes), and the resolver's trial unwrap cannot tell which cache it is reading
// from. Test support, not a component: nothing here is collected as a test file.

import { base64urlDecode } from "../../core-shared/codec.js";

/**
 * @typedef {object} SealedDelivery
 * @property {any} value - the raw delivered value for this `t`: `{ key, nonce }`
 *   or `{ key }` under client-bound, a base64url string under direct
 * @property {any} transport - the response's transport member, undefined under
 *   direct
 */

/**
 * @typedef {object} SealedEntry
 * @property {string} publisher
 * @property {string} accessGroup
 * @property {string|undefined} issuerName
 * @property {string} t
 * @property {SealedDelivery} delivery
 */

/**
 * A sealed-blob period-key cache over the resolver's `Cache` seam. It re-opens
 * client-bound deliveries through the one capability handed in, so the same
 * client that would open a response opens what the cache re-serves.
 *
 * @param {{ openDeliveredKeys: (transport: unknown) => Promise<{ open: (value: any, usages: KeyUsage[]) => Promise<CryptoKey|null> }> }} capability
 * @returns {{
 *   put: (accessGroup: string, t: string, key: any, context?: any) => Promise<void>,
 *   candidatesAt: (accessGroup: string, t: string, context?: any) => Promise<any[]>,
 *   attempted: (context: { lease: object }) => Promise<void>,
 *   entries: () => SealedEntry[],
 * }}
 */
export function sealedBlobCache(capability) {
  /** @type {SealedEntry[]} */
  const held = [];
  /** @type {WeakMap<object, SealedEntry[]>} */
  const pending = new WeakMap();

  /**
   * Keep the pre-open delivery under its coordinates and drop the opened key.
   * The delivery is what `applyResponse` rides along in `context.delivery`; a
   * store with none is a caller that never widened its seam, and there is
   * nothing this cache could hold, so it refuses rather than file an entry it
   * can never re-open.
   *
   * @param {string} accessGroup
   * @param {string} t
   * @param {any} _key - the opened material, deliberately unused here
   * @param {any} [context]
   * @returns {Promise<void>}
   */
  async function put(accessGroup, t, _key, context = {}) {
    const publisher = context.publisher;
    const delivery = context.delivery;
    if (typeof publisher !== "string" || publisher.length === 0) {
      throw new Error("a sealed-blob entry files under its publisher, which is a name");
    }
    if (delivery === null || typeof delivery !== "object") {
      throw new Error(
        "a sealed-blob cache keeps the delivery the store seam hands it in context.delivery",
      );
    }
    const entry = { publisher, accessGroup, issuerName: context.issuerName, t, delivery };
    if (context.lease !== undefined) {
      if (context.lease === null || typeof context.lease !== "object") {
        throw new Error("a response-private sealed-blob entry carries its operation lease");
      }
      const privateEntries = pending.get(context.lease) ?? [];
      privateEntries.push(entry);
      pending.set(context.lease, privateEntries);
    }
    held.push(entry);
  }

  /**
   * Every held delivery of one exact coordinate, newest filed first,
   * re-opened to the material the resolver's trial unwrap needs. A
   * client-bound value goes back through the capability to a handle; a direct
   * string decodes to bytes. `issuerNames` narrows the same way the resolver
   * asks: an entry whose granting issuer is not among them is left out.
   *
   * @param {string} accessGroup
   * @param {string} t
   * @param {any} [context]
   * @returns {Promise<any[]>}
   */
  async function candidatesAt(accessGroup, t, context = {}) {
    const publisher = context.publisher;
    const issuerNames = Array.isArray(context.issuerNames) ? context.issuerNames : null;
    const privateEntries = context.lease === undefined ? [] : (pending.get(context.lease) ?? []);

    const matches = (e) =>
      e.accessGroup === accessGroup &&
      e.publisher === publisher &&
      e.t === t &&
      (issuerNames === null || issuerNames.includes(e.issuerName));
    const matched = [
      ...privateEntries.filter(matches).reverse(),
      ...held.filter(matches).reverse(),
    ].filter((entry, i, all) => all.findIndex((other) => other.delivery === entry.delivery) === i);

    /** @type {any[]} */
    const out = [];
    for (const { delivery } of matched) {
      const opened = await openDelivery(delivery);
      if (opened !== null) out.push(opened);
    }
    return out;
  }

  /**
   * One held delivery back to key material. A direct entry is the base64url
   * string decoded to bytes; a client-bound entry re-opens through the
   * capability to a `['unwrapKey']` handle, the usage a periodKey carries.
   *
   * @param {SealedDelivery} delivery
   * @returns {Promise<Uint8Array|CryptoKey|null>}
   */
  async function openDelivery(delivery) {
    if (typeof delivery.value === "string") {
      try {
        return base64urlDecode(delivery.value);
      } catch {
        return null;
      }
    }
    const opener = await capability.openDeliveredKeys(delivery.transport);
    return opener.open(delivery.value, ["unwrapKey"]);
  }

  return {
    put,
    candidatesAt,
    async attempted({ lease }) {
      if (lease === null || typeof lease !== "object") {
        throw new Error("a completed sealed-blob cache attempt names its operation lease");
      }
      if (!pending.has(lease)) return;
      pending.delete(lease);
    },
    /**
     * What is held, for assertions: delivery entries. Client-bound entries
     * contain neither a handle nor raw key material; direct entries contain
     * raw period-key material in base64url form.
     *
     * @returns {SealedEntry[]}
     */
    entries() {
      return held.slice();
    },
  };
}

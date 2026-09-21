// @ts-check

// The demo issuer's response cache. Key construction, entry lifetime, and
// storage live here. `IssuerServer` decides whether caching is enabled and
// records hits as the server's own. The server's transport forces direct delivery
// whenever this cache is configured.
//
// Entries are keyed by the principal's user identity and every own request
// member except `clientPublicKey`. Configuring this cache forces direct
// delivery, so that client key cannot affect the answer. Other members stay in
// the key because the protocol or deployment policy may depend on them. Member
// order is retained: a differently ordered request may cost another unseal, and
// it still gets the right answer.

import { dcaError } from "../../../core-shared/errors.js";

export class IssuerResponseCache {
  #ttl;

  /** @type {Map<string, { at: number, status: number, body: any }>} */
  #entries = new Map();

  /**
   * @param {{ ttl: number }} config
   */
  constructor(config) {
    if (config === null || typeof config !== "object") {
      throw dcaError("bad_config", "a responseCache is { ttl }");
    }
    for (const name of Object.keys(config)) {
      if (name !== "ttl") {
        throw dcaError(
          "unsupported_option",
          `a response cache has no ${name} yet, and will not pretend to`,
        );
      }
    }
    if (!Number.isFinite(config.ttl) || config.ttl <= 0) {
      throw dcaError(
        "bad_config",
        `a response cache ttl is a positive number of milliseconds, got ${config.ttl}`,
      );
    }
    this.#ttl = config.ttl;
  }

  /**
   * @param {any} payload
   * @param {object|null} principal
   * @returns {string|null}
   */
  keyFor(payload, principal) {
    if (payload === null || typeof payload !== "object") return null;

    const asked = Object.keys(payload)
      .filter((name) => name !== "clientPublicKey")
      .map((name) => [name, payload[name]]);

    return JSON.stringify([/** @type {any} */ (principal)?.user ?? null, asked]);
  }

  /**
   * An expired entry is not returned. It remains resident until any later
   * insertion sweeps stale entries; this demo cache has no background timer.
   *
   * @param {string} key
   * @param {number} now
   * @returns {{ status: number, body: any }|undefined}
   */
  get(key, now) {
    const held = this.#entries.get(key);
    return held && now - held.at < this.#ttl ? { status: held.status, body: held.body } : undefined;
  }

  /**
   * @param {string} key
   * @param {{ status: number, body: any }} response
   * @param {number} now
   * @returns {void}
   */
  put(key, response, now) {
    for (const [heldKey, held] of this.#entries) {
      if (now - held.at >= this.#ttl) this.#entries.delete(heldKey);
    }
    this.#entries.set(key, { at: now, status: response.status, body: response.body });
  }
}

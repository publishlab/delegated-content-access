// @ts-check

// The demo issuer's business data: identities, entitlements, and recorded
// usage. Authentication resolves a credential here; access is still the
// injected policy's decision. Returned principals, view lists, and policy
// snapshots are copied so neither a caller nor a policy can write held data
// through a value it was handed.
//
// This demo policy returns pending view records as opaque `policyData`. This
// component validates all of them before applying any. `IssuerServer` decides
// the timing and calls `apply` only after the final response delivered a key;
// this component never infers delivery or request order for itself.

import { dcaError } from "../../../core-shared/errors.js";

/**
 * Recursively copy the plain business data accepted by this demo.
 *
 * @param {any} value
 * @returns {any}
 */
function copyPlain(value) {
  if (Array.isArray(value)) return value.map(copyPlain);
  if (value !== null && typeof value === "object") {
    /** @type {any} */
    const copied = {};
    for (const name of Object.keys(value)) copied[name] = copyPlain(value[name]);
    return copied;
  }
  return value;
}

export class IssuerBusinessData {
  /** user -> the principal and entitlements the issuer holds. */
  #principals = new Map();

  /** @type {Map<string, string[]>} user -> metered renderIds */
  #views = new Map();

  /**
   * @param {string} user
   * @param {Record<string, any>} [entitlement]
   * @returns {void}
   */
  grant(user, entitlement = {}) {
    if (typeof user !== "string" || user.length === 0) {
      throw dcaError("bad_config", "a grant names a user");
    }
    this.#principals.set(user, copyPlain({ user, ...entitlement }));
  }

  /** @param {string} user */
  expire(user) {
    this.#principals.delete(user);
  }

  /**
   * Resolve the credential to a copied principal, or null when it names no
   * known identity. A policy cannot change held entitlements through the
   * result.
   *
   * @param {string|{ user?: string }} [credential]
   * @returns {object|null}
   */
  authenticate(credential) {
    const user = typeof credential === "string" ? credential : credential?.user;
    if (typeof user !== "string") return null;
    const held = this.#principals.get(user);
    return held === undefined ? null : copyPlain(held);
  }

  /**
   * @param {string} user
   * @returns {string[]} a copy, so a caller cannot record a view by pushing
   */
  views(user) {
    return [...(this.#views.get(user) ?? [])];
  }

  /**
   * The state an access or transport policy may inspect. The caller supplies
   * time because this store keeps no clock and tracks no request ordering.
   *
   * @param {Date} now
   * @returns {{ now: Date, views: Record<string, string[]> }}
   */
  snapshot(now) {
    /** @type {Record<string, string[]>} */
    const views = Object.create(null);
    for (const [user, renderIds] of this.#views) views[user] = [...renderIds];
    return { now, views };
  }

  /**
   * Apply the demo policy's opaque host data. The issuer server calls this
   * only after final delivery. Every record is checked before any is written,
   * so malformed policy data cannot leave a partial update.
   *
   * @param {any} policyData
   * @returns {void}
   */
  apply(policyData) {
    if (policyData === undefined) return;
    if (!Array.isArray(policyData)) {
      throw dcaError(
        "bad_config",
        "this server expects policyData to be a list of pending view records",
      );
    }

    for (const record of policyData) {
      if (record === null || typeof record !== "object") {
        throw dcaError("bad_config", "this server cannot apply policy data without a record type");
      }
      const { type, user, renderId } = /** @type {any} */ (record);
      if (type !== "view" || typeof user !== "string" || typeof renderId !== "string") {
        throw dcaError(
          "bad_config",
          `this server cannot apply policy data of ${JSON.stringify(type)}`,
        );
      }
    }

    for (const { user, renderId } of policyData) {
      const seen = this.#views.get(user) ?? [];
      if (!seen.includes(renderId)) this.#views.set(user, [...seen, renderId]);
    }
  }
}

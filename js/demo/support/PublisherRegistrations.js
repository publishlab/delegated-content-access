// @ts-check

// Issuer onboarding state used by the demo application. One exact JWT header
// kid selects one publisher registration: the verification key and the
// opening-key view that publisher is allowed to address.
//
// A registration may also carry `origins`, a list of the browser origins this
// publisher is served from. That list only narrows where the publisher may be
// served. The publisher signs the delivering origin into its resourceJWT, and
// the application compares the observed HTTP Origin with that signed value
// first. Onboarding a publisher needs no origin at all.

import { dcaError } from "../../core-shared/errors.js";
import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";

/**
 * Restrict an issuer key store to named coordinates. A copied keyId outside
 * this view misses without reaching the underlying private-key store.
 *
 * @param {{ get: Function }} keyStore
 * @param {{ issuerName: string, keyId: string }[]} coordinates
 * @returns {{ get: (issuerName: string, keyId: string) => any, allows: (issuerName: string, keyId: string) => boolean, add: (issuerName: string, keyId: string) => void }}
 */
export function openingKeysOver(keyStore, coordinates) {
  if (typeof keyStore?.get !== "function" || !Array.isArray(coordinates)) {
    throw dcaError("bad_config", "openingKeysOver needs a key store and allowed coordinates");
  }
  const allowed = new Map();

  /** @param {string} issuerName @param {string} keyId */
  const add = (issuerName, keyId) => {
    if (
      typeof issuerName !== "string" ||
      issuerName.length === 0 ||
      typeof keyId !== "string" ||
      keyId.length === 0
    ) {
      throw dcaError("bad_config", "an allowed opening-key coordinate is issuerName and keyId");
    }
    let ids = allowed.get(issuerName);
    if (!ids) {
      ids = new Set();
      allowed.set(issuerName, ids);
    }
    ids.add(keyId);
  };

  for (const coordinate of coordinates) {
    add(coordinate?.issuerName, coordinate?.keyId);
  }
  return {
    get(issuerName, keyId) {
      if (!allowed.get(issuerName)?.has(keyId)) return undefined;
      return keyStore.get(issuerName, keyId);
    },
    allows(issuerName, keyId) {
      return allowed.get(issuerName)?.has(keyId) === true;
    },
    add,
  };
}

/**
 * Reads the optional origin limit of one registration. Every origin comes back
 * canonical, and the list is non-empty whenever it is there at all. Leaving it
 * out is the ordinary case; an empty list would describe a registration that
 * could never be served anywhere, so this refuses it instead of reading it as
 * no limit.
 *
 * @param {unknown} origins
 * @returns {string[]|null}
 */
function originLimit(origins) {
  if (origins === undefined) return null;
  if (!Array.isArray(origins) || origins.length === 0) {
    throw dcaError(
      "bad_config",
      "a registration origin limit is a non-empty list of canonical origins",
    );
  }
  return origins.map((origin) => {
    const canonical = normalizePublisherOrigin(origin);
    if (canonical === null) {
      throw dcaError(
        "bad_config",
        `${JSON.stringify(origin)} is not a canonical origin a registration can list`,
      );
    }
    return canonical;
  });
}

export class PublisherRegistrations {
  /** @type {Map<string, import('../../core-issuer/IssuerEngine.js').PublisherRegistration>} */
  #byKid = new Map();

  /**
   * @param {import('../../core-issuer/IssuerEngine.js').PublisherRegistration[]} entries
   */
  constructor(entries) {
    if (!Array.isArray(entries)) {
      throw dcaError("bad_config", "PublisherRegistrations is built from registrations");
    }
    for (const entry of entries) {
      if (
        typeof entry?.kid !== "string" ||
        entry.kid.length === 0 ||
        !entry.publicKey ||
        typeof entry.openingKeys?.get !== "function"
      ) {
        throw dcaError("bad_config", "a publisher registration is kid, publicKey and openingKeys");
      }
      if (this.#byKid.has(entry.kid)) {
        throw dcaError(
          "bad_config",
          `publisher kid ${JSON.stringify(entry.kid)} is registered more than once`,
        );
      }
      const origins = originLimit(entry.origins);
      const registration = Object.freeze({
        kid: entry.kid,
        publicKey: entry.publicKey,
        ...(origins === null ? {} : { origins: Object.freeze(origins) }),
        openingKeys: entry.openingKeys,
      });
      this.#byKid.set(entry.kid, registration);
    }
  }

  /** @param {string} kid */
  get(kid) {
    return this.#byKid.get(kid);
  }

  /**
   * Prepare an issuer-key rotation without changing any registration. With
   * `oldKeyId`, only views that can already address that coordinate join the
   * rotation. Without it, the rotation covers the whole demo server, and it
   * succeeds only when every registration shares one opening-key view.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @param {string} [oldKeyId]
   * @returns {() => void}
   */
  prepareOpeningKeyRotation(issuerName, keyId, oldKeyId = undefined) {
    const views = new Set([...this.#byKid.values()].map((entry) => entry.openingKeys));
    if (
      typeof issuerName !== "string" ||
      issuerName.length === 0 ||
      typeof keyId !== "string" ||
      keyId.length === 0 ||
      (oldKeyId !== undefined && (typeof oldKeyId !== "string" || oldKeyId.length === 0))
    ) {
      throw dcaError(
        "bad_config",
        "an issuer-key rotation names issuerName, keyId and an optional oldKeyId",
      );
    }

    const selected =
      oldKeyId === undefined
        ? [...views]
        : [...views].filter(
            (view) =>
              typeof (/** @type {any} */ (view).allows) === "function" &&
              /** @type {any} */ (view).allows(issuerName, oldKeyId),
          );

    if (
      (oldKeyId === undefined && views.size > 1) ||
      selected.length === 0 ||
      selected.some((view) => typeof (/** @type {any} */ (view).add) !== "function")
    ) {
      throw dcaError("bad_config", "publisher registrations cannot accept an issuer-key rotation");
    }

    return () => {
      for (const view of selected) /** @type {any} */ (view).add(issuerName, keyId);
    };
  }

  /**
   * Apply a rotation selected by `prepareOpeningKeyRotation`. Fixtures can use
   * this shortcut; `IssuerServer` prepares before mutating its store.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @param {string} [oldKeyId]
   */
  addOpeningKey(issuerName, keyId, oldKeyId = undefined) {
    this.prepareOpeningKeyRotation(issuerName, keyId, oldKeyId)();
  }
}

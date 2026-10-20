// @ts-check

import { createRecipientGrantBrowserClient } from "./client.js";
import { dcaError } from "../../core-shared/errors.js";
import { isContentName } from "../../core-shared/names.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";

/**
 * @typedef {Omit<import('./client.js').RecipientGrantBrowserOptions, 'grantReference'> & {
 *   grantReference?: string,
 *   readGrant?: () => string|null,
 *   location?: { href: string },
 *   history?: { state: any, replaceState: (state: any, unused: string, url: string) => void },
 *   queryName?: string,
 *   retainUntil?: number,
 *   now?: () => number
 * }} RecipientGrantHostOptions
 */
/**
 * @typedef {object} RecipientGrantBrowserHost
 * @property {(contentNames: string[], openedNames?: string[]) => Promise<import('../../integration-client/createDeliveryClient.js').UnlockResult|null>} unlockUnresolved
 * @property {(contentName: string) => Promise<import('../../integration-client/createDeliveryClient.js').OpenedContent>} openLocal
 * @property {() => void} clearGrant
 */

/**
 * Capture one credential, then remove its default URL carrier. The host calls
 * unlockUnresolved after ordinary access, supplying names already opened.
 * A refusal is returned unchanged; a transport failure remains a rejection.
 * It reads only an unverified compact `exp` to shorten local retention and
 * never selects authority or routes from the token or URL.
 *
 * Retention lasts only for this adapter instance and requires the host's
 * finite retainUntil (epoch milliseconds). A compact token's unverified exp
 * can shorten that deadline but never extends it or establishes validity. The
 * host owns navigation, reload retention and expiry policy; issuer validation
 * remains authoritative.
 * clearGrant discards the bearer and this attempt's cached keys. It cannot
 * retract keys or plaintext already delivered to the reader.
 *
 * @param {RecipientGrantHostOptions} config
 * @returns {RecipientGrantBrowserHost}
 */
export function createRecipientGrantBrowserHost(config) {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw dcaError("bad_config", "recipient host configuration is an object");
  }
  const allowed = [
    "root",
    "issuer",
    "fetch",
    "grantReference",
    "readGrant",
    "location",
    "history",
    "queryName",
    "retainUntil",
    "now",
    "contentDecoders",
    "clientBoundKeyCapability",
    "acceptDirectFallback",
    "acceptDirectResponse",
  ];
  if (
    Object.keys(config).some(
      (key) => !allowed.includes(key) || /** @type {any} */ (config)[key] === undefined,
    )
  ) {
    throw dcaError(
      "bad_config",
      "recipient host configuration has an unsupported or absent option",
    );
  }
  const {
    grantReference,
    readGrant,
    location,
    history,
    queryName = "share",
    retainUntil,
    now = Date.now,
    ...clientOptions
  } = config;
  if (
    typeof queryName !== "string" ||
    queryName.length === 0 ||
    typeof now !== "function" ||
    !Number.isFinite(retainUntil) ||
    (readGrant !== undefined && typeof readGrant !== "function") ||
    (Object.hasOwn(config, "grantReference") && readGrant !== undefined)
  ) {
    throw dcaError("bad_config", "recipient host needs one carrier and a finite lifetime policy");
  }
  // Copy trusted selection before obtaining any untrusted carrier input.
  const attemptOptions = { ...clientOptions, issuer: { ...config.issuer } };
  /** @type {string|null} */
  let retained = null;
  /** @type {ReturnType<typeof createRecipientGrantBrowserClient>|null} */
  let client = null;
  let deadline = retainUntil;
  /** @type {URL|null} */
  let capturedUrl = null;
  /** @type {unknown} */
  let candidate = null;
  if (Object.hasOwn(config, "grantReference")) {
    candidate = grantReference;
  } else if (readGrant !== undefined) {
    candidate = readGrant();
  } else if (location !== undefined) {
    try {
      capturedUrl = new URL(location.href);
    } catch {
      throw dcaError("bad_config", "recipient host needs a valid current URL");
    }
    const values = capturedUrl.searchParams.getAll(queryName);
    if (values.length > 1) {
      throw dcaError("bad_config", "recipient query carrier is ambiguous");
    }
    candidate = values.length === 0 ? null : values[0];
  }
  if (candidate !== null) {
    if (
      typeof candidate !== "string" ||
      candidate.length > 8192 ||
      /^[A-Za-z0-9._~+/-]+=*$/.exec(candidate)?.[0] !== candidate
    ) {
      throw dcaError("bad_config", "recipient carrier is not one bounded bearer value");
    }
    retained = candidate;
    // This unverified timestamp is only an additional local eviction bound.
    // Opaque references and malformed compact tokens use the host deadline.
    try {
      const exp = decodeCompactJwt(candidate).payload.exp;
      if (Number.isSafeInteger(exp) && exp >= 0) {
        deadline = Math.min(/** @type {number} */ (retainUntil), exp * 1000);
      }
    } catch {
      // The issuer still decides whether the credential is valid.
    }
    // Removal follows capture. No storage, cookie or diagnostics receive it.
    if (capturedUrl !== null) {
      if (typeof history?.replaceState !== "function") {
        throw dcaError("bad_config", "recipient URL capture needs host history cleanup");
      }
      capturedUrl.searchParams.delete(queryName);
      history.replaceState(history.state, "", capturedUrl.href);
    }
  }
  let generation = 0;
  /** @returns {void} */
  function clearGrant() {
    generation++;
    retained = null;
    client = null;
  }
  /** @returns {boolean} */
  function usable() {
    if (retained === null) return false;
    let instant;
    try {
      instant = now();
    } catch {
      clearGrant();
      throw dcaError("bad_config", "recipient host clock failed");
    }
    if (!Number.isFinite(instant)) {
      clearGrant();
      throw dcaError("bad_config", "recipient host clock needs a finite instant");
    }
    if (instant >= /** @type {number} */ (deadline)) clearGrant();
    return retained !== null;
  }
  /** @param {number} capturedGeneration @returns {void} */
  function assertCurrent(capturedGeneration) {
    if (!usable() || capturedGeneration !== generation) {
      throw dcaError("bad_config", "recipient host attempt is no longer retained");
    }
  }
  return {
    clearGrant,
    async unlockUnresolved(contentNames, openedNames = []) {
      if (
        !Array.isArray(contentNames) ||
        !contentNames.every(isContentName) ||
        !Array.isArray(openedNames) ||
        !openedNames.every(isContentName)
      ) {
        throw dcaError("bad_config", "recipient host needs named requested and opened items");
      }
      const unresolved = [...new Set(contentNames)].filter((name) => !openedNames.includes(name));
      if (unresolved.length === 0 || !usable()) return null;
      client ??= createRecipientGrantBrowserClient({
        ...attemptOptions,
        grantReference: /** @type {string} */ (retained),
      });
      const capturedGeneration = generation;
      try {
        return await client.unlock(unresolved);
      } finally {
        assertCurrent(capturedGeneration);
      }
    },
    async openLocal(contentName) {
      if (!usable() || client === null) {
        throw dcaError("bad_config", "recipient host has no retained grant attempt");
      }
      const capturedGeneration = generation;
      try {
        return await client.openLocal(contentName);
      } finally {
        assertCurrent(capturedGeneration);
      }
    },
  };
}

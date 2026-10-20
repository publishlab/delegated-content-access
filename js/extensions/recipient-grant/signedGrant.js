// @ts-check
// A compact, signed recipient credential. Untrusted header values select only
// a key inside the host's already configured sharing-key registry.
import {
  base64urlDecode,
  base64urlEncode,
  utf8Decode,
  utf8Encode,
} from "../../core-shared/codec.js";
import { decodeCompactJwt } from "../../core-shared/compactJwt.js";
import { es256Sign, es256Verify } from "../../core-shared/cryptoProvider.js";
import { isContentName } from "../../core-shared/names.js";
import { isResourceId } from "../../core-shared/names.js";
import { dcaError } from "../../core-shared/errors.js";

const TYP = "dca-share+jwt";
const MAX_TOKEN = 8192;
const MAX_NAMES = 64;
const MAX_ID = 256;
const MAX_JTI = 256;
const algs = ["ES256", "HS256"];

/** @param {unknown} value @returns {value is Record<string, any>} */
function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
/** @param {unknown} value @param {number} limit */
function identifier(value, limit = MAX_ID) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= limit &&
    !value.split("").some((character) => character.charCodeAt(0) <= 31)
  );
}
/** @param {unknown} value */
function jti(value) {
  return (
    typeof value === "string" &&
    value.length >= 22 &&
    value.length <= MAX_JTI &&
    /^[A-Za-z0-9_-]+$/.test(value)
  );
}
/** @param {unknown} value */
function names(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= MAX_NAMES &&
    value.every(isContentName) &&
    new Set(value).size === value.length
  );
}
/** @param {unknown} value */
function time(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
/** @param {any} claims */
function validClaims(claims) {
  return (
    object(claims) &&
    identifier(claims.publisher) &&
    isResourceId(claims.sub) &&
    names(claims.contentNames) &&
    time(claims.iat) &&
    time(claims.exp) &&
    claims.iat < claims.exp &&
    (claims.nbf === undefined || (time(claims.nbf) && claims.nbf < claims.exp)) &&
    jti(claims.jti) &&
    (claims.iss === undefined || identifier(claims.iss)) &&
    (claims.aud === undefined ||
      identifier(claims.aud) ||
      (Array.isArray(claims.aud) &&
        claims.aud.length > 0 &&
        claims.aud.every((entry) => identifier(entry)) &&
        new Set(claims.aud).size === claims.aud.length))
  );
}
/** @param {any} key @param {string} alg @param {'sign'|'verify'} use */
function validKey(key, alg, use) {
  if (!(key instanceof CryptoKey) || !key.usages.includes(use)) return false;
  const algorithm = /** @type {any} */ (key.algorithm);
  return alg === "ES256"
    ? key.type === (use === "sign" ? "private" : "public") &&
        algorithm.name === "ECDSA" &&
        algorithm.namedCurve === "P-256"
    : key.type === "secret" &&
        algorithm.name === "HMAC" &&
        algorithm.hash?.name === "SHA-256" &&
        algorithm.length >= 256;
}
/** @param {any} value */
function encoded(value) {
  return base64urlEncode(utf8Encode(JSON.stringify(value)));
}
/** @param {string} segment */
function strictUtf8(segment) {
  const bytes = base64urlDecode(segment);
  const rebuilt = utf8Encode(utf8Decode(bytes));
  return rebuilt.length === bytes.length && rebuilt.every((byte, index) => byte === bytes[index]);
}
/** @param {any} key @param {string} alg @param {Uint8Array} data */
function sign(key, alg, data) {
  return alg === "ES256"
    ? es256Sign(key, data)
    : crypto.subtle.sign("HMAC", key, Uint8Array.from(data));
}
/** @param {any} key @param {string} alg @param {Uint8Array} signature @param {Uint8Array} data */
function verify(key, alg, signature, data) {
  return alg === "ES256"
    ? es256Verify(key, signature, data)
    : crypto.subtle.verify("HMAC", key, Uint8Array.from(signature), Uint8Array.from(data));
}

/**
 * Mint from already authorized scope. `authorize` is the host's required
 * upstream editorial/reader/delegation decision, and must return a bounded
 * claim object. A denied decision cannot produce a token.
 * @param {{ request: any, authorize: (request: any) => Promise<any>|any,
 *   signer: { kid: string, alg: 'ES256'|'HS256', key: CryptoKey } }} input
 */
export async function mintSignedRecipientGrant({ request, authorize, signer }) {
  if (
    typeof authorize !== "function" ||
    !object(signer) ||
    !identifier(signer.kid) ||
    !algs.includes(signer.alg) ||
    !validKey(signer.key, signer.alg, "sign")
  )
    throw dcaError(
      "bad_config",
      "signed grant needs authorized scope and a configured signing key",
    );
  const { kid, alg, key } = signer;
  const decision = await authorize(request);
  let claims;
  try {
    // A structured clone strips a prototype's JSON hooks and refuses own
    // functions, so signed bytes describe exactly the validated snapshot.
    claims = structuredClone(decision);
  } catch {
    throw dcaError("denied", "sharing scope was not serializable");
  }
  if (!object(claims) || Object.hasOwn(claims, "jti"))
    throw dcaError("denied", "the signer generates each grant identifier");
  claims.jti = base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
  if (!validClaims(claims)) throw dcaError("denied", "sharing scope was not authorized");
  const header = { typ: TYP, alg, kid };
  const message = `${encoded(header)}.${encoded(claims)}`;
  const signature = await sign(key, alg, utf8Encode(message));
  const token = `${message}.${base64urlEncode(signature)}`;
  if (token.length > MAX_TOKEN) throw dcaError("denied", "sharing grant exceeds size limit");
  return token;
}

/**
 * Verify under trusted, issuer-local onboarding. Each key entry binds its
 * publisher registration, signing purpose and permitted scope. The returned
 * record has the existing recipient-grant issuer's grant-store shape.
 * @param {string} token
 * @param {{ keys: Record<string, Record<string, { key: CryptoKey, alg: 'ES256'|'HS256', purpose: 'recipient-unlock',
 *   publisher: string, publisherRegistrationId: string, issuer: string,
 *   contentNames?: string[], maxLifetimeSeconds: number, retired?: boolean }>>,
 *   issuerId: string, audience?: string, requireAudience?: boolean,
 *   now?: () => number, revoked?: (jti: string, entry: any) => Promise<boolean>|boolean }} config
 * @param {{nowMs?: number}} [options] - trusted captured instant shared with issuer admission
 */
export async function verifySignedRecipientGrant(token, config, options = {}) {
  if (
    !object(config) ||
    !object(config.keys) ||
    !identifier(config.issuerId) ||
    (config.audience !== undefined && !identifier(config.audience)) ||
    (config.requireAudience !== undefined && typeof config.requireAudience !== "boolean") ||
    (config.requireAudience && !config.audience) ||
    (config.revoked !== undefined && typeof config.revoked !== "function") ||
    (config.now !== undefined && typeof config.now !== "function")
  )
    throw dcaError("bad_config", "signed grant verifier needs issuer trust configuration");
  if (!object(options) || (Object.hasOwn(options, "nowMs") && !Number.isFinite(options.nowMs)))
    throw dcaError("bad_config", "signed grant captured clock must be finite");
  if (typeof token !== "string" || token.length > MAX_TOKEN) return null;
  let decoded;
  try {
    decoded = decodeCompactJwt(token);
  } catch {
    return null;
  }
  const { header, payload, parts } = decoded;
  if (!strictUtf8(parts[0]) || !strictUtf8(parts[1])) return null;
  if (
    header.typ !== TYP ||
    !algs.includes(header.alg) ||
    !identifier(header.kid) ||
    ["crit", "b64", "jwk", "jku", "x5u"].some((name) => Object.hasOwn(header, name))
  )
    return null;
  const publisherKeys =
    object(payload) &&
    identifier(payload.publisher) &&
    Object.hasOwn(config.keys, payload.publisher)
      ? config.keys[payload.publisher]
      : null;
  const selected =
    object(publisherKeys) && Object.hasOwn(publisherKeys, header.kid)
      ? publisherKeys[header.kid]
      : null;
  const entry = object(selected)
    ? {
        ...selected,
        contentNames: Array.isArray(selected.contentNames)
          ? [...selected.contentNames]
          : selected.contentNames,
      }
    : null;
  const expectedAudience = config.audience;
  const issuerId = config.issuerId;
  const requiresAudience = config.requireAudience === true;
  const revoked = config.revoked;
  const nowMs = options.nowMs === undefined ? (config.now ?? Date.now)() : options.nowMs;
  if (!Number.isFinite(nowMs)) throw dcaError("bad_config", "signed grant clock must be finite");
  if (
    !object(entry) ||
    entry.retired === true ||
    entry.purpose !== "recipient-unlock" ||
    entry.alg !== header.alg ||
    !validKey(entry.key, entry.alg, "verify") ||
    !identifier(entry.publisher) ||
    !identifier(entry.publisherRegistrationId) ||
    !identifier(entry.issuer) ||
    !time(entry.maxLifetimeSeconds) ||
    entry.maxLifetimeSeconds === 0
  )
    return null;
  const maxLifetimeSeconds = /** @type {number} */ (entry.maxLifetimeSeconds);
  let authenticated;
  try {
    const signature = base64urlDecode(parts[2]);
    if (
      (entry.alg === "ES256" && signature.length !== 64) ||
      (entry.alg === "HS256" && signature.length !== 32)
    )
      return null;
    authenticated = await verify(
      entry.key,
      entry.alg,
      signature,
      utf8Encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    return null;
  }
  if (
    !authenticated ||
    !validClaims(payload) ||
    payload.publisher !== entry.publisher ||
    (payload.iss !== undefined && payload.iss !== entry.issuer)
  )
    return null;
  const scopedNames = entry.contentNames;
  if (
    scopedNames !== undefined &&
    (!names(scopedNames) ||
      payload.contentNames.some((/** @type {string} */ name) => !scopedNames.includes(name)))
  )
    return null;
  if (payload.exp - payload.iat > maxLifetimeSeconds) return null;
  if (
    payload.aud !== undefined &&
    (!expectedAudience ||
      !(Array.isArray(payload.aud) ? payload.aud : [payload.aud]).includes(expectedAudience))
  )
    return null;
  if (requiresAudience && payload.aud === undefined) return null;
  const now = Math.floor(nowMs / 1000);
  if (payload.iat > now || payload.exp <= now || (payload.nbf !== undefined && payload.nbf > now))
    return null;
  if (revoked && (await revoked(payload.jti, entry))) return null;
  return {
    purpose: "recipient-unlock",
    issuerId,
    publisherRegistrationId: entry.publisherRegistrationId,
    resourceId: payload.sub,
    contentNames: [...payload.contentNames],
    notBeforeMs: Math.max(payload.iat, payload.nbf ?? payload.iat) * 1000,
    expiresAtMs: payload.exp * 1000,
    revoked: false,
  };
}

/** @param {Parameters<typeof verifySignedRecipientGrant>[1]} config
 */
export function createSignedGrantStore(config) {
  if (
    !object(config) ||
    !object(config.keys) ||
    !identifier(config.issuerId) ||
    (config.audience !== undefined && !identifier(config.audience)) ||
    (config.requireAudience !== undefined && typeof config.requireAudience !== "boolean") ||
    (config.requireAudience && !config.audience) ||
    (config.revoked !== undefined && typeof config.revoked !== "function") ||
    (config.now !== undefined && typeof config.now !== "function")
  )
    throw dcaError("bad_config", "signed grant store needs configured keys");
  const keys = Object.create(null);
  for (const [publisher, publisherKeys] of Object.entries(config.keys)) {
    if (!object(publisherKeys))
      throw dcaError("bad_config", "signed grant publisher key namespace is invalid");
    keys[publisher] = Object.create(null);
    for (const [kid, entry] of Object.entries(publisherKeys)) {
      if (
        !object(entry) ||
        !identifier(kid) ||
        !identifier(publisher) ||
        entry.publisher !== publisher ||
        !identifier(entry.publisherRegistrationId) ||
        !identifier(entry.issuer) ||
        entry.purpose !== "recipient-unlock" ||
        !algs.includes(entry.alg) ||
        !validKey(entry.key, entry.alg, "verify") ||
        !time(entry.maxLifetimeSeconds) ||
        entry.maxLifetimeSeconds === 0
      )
        throw dcaError("bad_config", "signed grant key entry is invalid");
      if (entry.contentNames !== undefined && !names(entry.contentNames))
        throw dcaError("bad_config", "signed grant key scope is invalid");
      keys[publisher][kid] = Object.freeze({
        ...entry,
        contentNames: entry.contentNames === undefined ? undefined : [...entry.contentNames],
      });
    }
    Object.freeze(keys[publisher]);
  }
  const snapshot = Object.freeze({ ...config, keys: Object.freeze(keys) });
  return Object.freeze({
    get: (/** @type {string} */ token, /** @type {{nowMs?: number}} */ options = {}) =>
      verifySignedRecipientGrant(token, snapshot, options),
  });
}

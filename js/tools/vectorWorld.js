// @ts-check
//
// This turns a vector's `input` section into a Sealer that reproduces its
// `expected` section exactly. The generator writes vectors through this; the
// replay test reads them back through the same call, so a vector cannot be
// green against a builder that has drifted from the one that wrote it.
//
// The other direction turns a reject vector's `issuer` and `publisher` sections
// into the issuer that has to refuse it. `buildSealer` makes the side that emits
// a wire, `buildIssuer` the side that reads one. A reject vector carries a
// request the issuer must refuse, in place of a render to seal.
//
// Everything WebCrypto will not seed is a fixture in the vector: the issuer
// keypair, the publisher's signing keypair, the ephemeral keypair per sealed
// blob, the Random seed and the clock. One source of entropy stays in a render
// even so: ECDSA draws a random `k` per signature, so the resourceJWT's
// signature segment differs every run. Its header and payload segments repeat,
// and the recorded signature verifies against the recorded public JWK. The
// replay test compares those segments and checks that signature.
//
// This file recovers a key at the coordinate it sits at. The publisher seals
// each blob under the render and the coordinate it belongs to, so the two
// recovery calls below rebuild that same pair per blob: renderId out of the
// recorded JWT payload, the content name from each `input.content` item, and the
// access group and period from the keys of the sealed period map. Reading the
// coordinate from anywhere else would recover a key under a label the wire does
// not carry.
//
// The caller loads the vector and passes the object in, so this module runs
// unchanged in a browser page.

import { Sealer } from "../core-publisher/Sealer.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { open } from "../core-shared--publisher-issuer/keySealing.js";
import { bindValue } from "../core-shared--publisher-issuer/bind.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { base64urlDecode, base64urlEncode } from "../core-shared/codec.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { deterministicEcdhFixtureSealing } from "./vector-fixtures/deterministicEcdhSealing.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

/** The curve an EC JWK names on the wire, and the algorithm importKey takes. */
const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };

/** The same curve in its other use: ES256 over the two envelopes. */
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/**
 * The key fixture shape, as it sits in a vector: a P-256 JWK and nothing else.
 * The `d` member separates the private half from the public one.
 *
 * @typedef {{ kty: string, crv: string, x: string, y: string, d?: string }} EcJwk
 */

/**
 * @typedef {object} VectorIssuer
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} algorithm
 * @property {string} unlockUrl
 * @property {EcJwk} publicKeyJwk
 * @property {EcJwk} privateKeyJwk
 */

/**
 * A supplied ephemeral keypair and the blob it belongs to: `contentName` for a
 * sealed contentKey, `accessGroup` with `t` for a sealed period capability,
 * and `chainKey` to distinguish a chain key from a period key.
 *
 * @typedef {object} VectorEphemeralKey
 * @property {string} issuerName
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t]
 * @property {boolean} [chainKey] - true only for a chain-key blob; period-key
 *   blobs omit it
 * @property {EcJwk} publicKeyJwk
 * @property {EcJwk} privateKeyJwk
 */

/**
 * The publisher's ES256 signing key, by `kid`. An issuer receives the public
 * half at onboarding, and a replay verifies the recorded signatures with it.
 *
 * @typedef {object} VectorSigningKey
 * @property {string} kid
 * @property {EcJwk} publicKeyJwk
 * @property {EcJwk} privateKeyJwk
 */

/**
 * @typedef {object} VectorInput
 * @property {number} seed
 * @property {string} clockIso
 * @property {string} origin - the canonical browser origin this render is
 *   delivered from, signed into the resourceJWT
 * @property {string} resourceId
 * @property {object} resourceData
 * @property {Record<string, Record<string, string>>} periodKeys - publisher-private
 *   period-key bytes, base64url per accessGroup and period coordinate
 * @property {{ length: number, slots: number }} period
 * @property {{ name: string, value: string, contentType: string, accessGroups: string[] }[]} content
 * @property {VectorIssuer[]} issuers
 * @property {VectorSigningKey[]} signingKeys
 * @property {string} signingKid - which of them signed this render
 * @property {VectorEphemeralKey[]} ephemeralKeys
 */

/**
 * Public fixture keys are extractable so the ephemeral-key call site can export
 * the raw point into a sealed blob. Issuer public keys share this importer even
 * though their call site does not export them. No usages: an ECDH public key
 * serves only as the `public` argument to a derivation.
 *
 * @param {EcJwk} jwk
 * @returns {Promise<CryptoKey>}
 */
function importPublicKey(jwk) {
  return subtle.importKey("jwk", jwk, ECDH_P256, true, []);
}

/**
 * Non-extractable, and `deriveBits` only, the narrowest usage that still agrees
 * a shared secret and the one the issuer reference asks for.
 *
 * @param {EcJwk} jwk
 * @returns {Promise<CryptoKey>}
 */
export function importIssuerPrivateKey(jwk) {
  return subtle.importKey("jwk", jwk, ECDH_P256, false, ["deriveBits"]);
}

/**
 * The publisher's signing half, imported non-extractable so it stays inside
 * WebCrypto.
 *
 * @param {EcJwk} jwk
 * @returns {Promise<CryptoKey>}
 */
export function importSigningPrivateKey(jwk) {
  return subtle.importKey("jwk", jwk, ECDSA_P256, false, ["sign"]);
}

/**
 * The half an issuer holds. A replay verifies a recorded signature with it,
 * since the signature itself cannot be pinned.
 *
 * @param {EcJwk} jwk
 * @returns {Promise<CryptoKey>}
 */
function importSigningPublicKey(jwk) {
  return subtle.importKey("jwk", jwk, ECDSA_P256, true, ["verify"]);
}

/**
 * @param {{ publicKeyJwk: EcJwk, privateKeyJwk: EcJwk }} fixture
 * @returns {Promise<CryptoKeyPair>}
 */
async function importEphemeralKeyPair({ publicKeyJwk, privateKeyJwk }) {
  return {
    publicKey: await importPublicKey(publicKeyJwk),
    privateKey: await importIssuerPrivateKey(privateKeyJwk),
  };
}

/**
 * Which blob an ephemeral keypair is for. The kind is in the key, so an
 * accessGroup and a contentName that happen to share a name cannot collide;
 * the delimiter is banned in every field, so nothing else collides either.
 *
 * The period kind mirrors BIND: period-key and chain-key blobs at the same
 * coordinates are different sealed messages and therefore have different
 * fixture slots.
 *
 * A fixture spells the period label `t`, and a Sealer's chain context spells the
 * same label `suppliedT`, so both reach the one slot.
 *
 * @param {object} context
 * @param {string} context.issuerName
 * @param {string} [context.contentName]
 * @param {string} [context.accessGroup]
 * @param {string} [context.t] - a fixture's period label
 * @param {string} [context.suppliedT] - a chain context's period label
 * @param {boolean} [context.chainKey]
 * @returns {string}
 */
function slot({ issuerName, contentName, accessGroup, t, suppliedT, chainKey }) {
  if (contentName !== undefined) return `${issuerName}|contentKey|${contentName}`;
  const kind = chainKey === true ? "chainKey" : "periodKey";
  return `${issuerName}|${kind}|${accessGroup}|${suppliedT ?? t}`;
}

/**
 * A Sealer loaded with the vector's resource and content, ready to `seal()`.
 *
 * PeriodKey bytes are publisher-private fixture input. A variant may
 * still inject another supply when it tests the construction itself.
 *
 * @param {VectorInput} input
 * @param {object} [options]
 * @param {import('../core-publisher/Sealer.js').PeriodKeySupply} [options.periodKeySupply]
 * @returns {Promise<Sealer>}
 */
export async function buildSealer(input, { periodKeySupply } = {}) {
  const supply = periodKeySupply ?? {
    async derive(accessGroup, t) {
      const encoded = input.periodKeys?.[accessGroup]?.[t];
      if (typeof encoded !== "string") {
        throw new Error(`the vector has no input periodKey for ${accessGroup}/${t}`);
      }
      const key = base64urlDecode(encoded);
      if (key.length !== 16) {
        throw new Error(`the vector input periodKey for ${accessGroup}/${t} is not 16 bytes`);
      }
      return key;
    },
  };

  /** @type {Map<string, CryptoKeyPair>} */
  const ephemeral = new Map();
  for (const fixture of input.ephemeralKeys) {
    ephemeral.set(slot(fixture), await importEphemeralKeyPair(fixture));
  }

  const issuers = [];
  /** @type {WeakMap<CryptoKey, string>} */
  const issuerNamesByPublicKey = new WeakMap();
  for (const issuer of input.issuers) {
    const publicKey = await importPublicKey(issuer.publicKeyJwk);
    issuerNamesByPublicKey.set(publicKey, issuer.issuerName);
    issuers.push({
      issuerName: issuer.issuerName,
      keyId: issuer.keyId,
      algorithm: issuer.algorithm,
      publicKey,
    });
  }

  /** @type {Record<string, CryptoKey>} */
  const signingKeys = {};
  for (const key of input.signingKeys) {
    signingKeys[key.kid] = await importSigningPrivateKey(key.privateKeyJwk);
  }

  const sealer = new Sealer({
    origin: input.origin,
    clock: new Clock(input.clockIso),
    random: new Random({ seed: input.seed }),
    signingKeys,
    signingKid: input.signingKid,
    period: input.period,
    periodKeySupply: supply,
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers,
    // The vector holds the recorded pair, and this adapter supplies it below
    // the production Sealer boundary. The adapter stays a fixture tool, outside
    // publisher configuration.
    keySealing: deterministicEcdhFixtureSealing((issuerPublicKey, binding) => {
      const issuerName = issuerNamesByPublicKey.get(issuerPublicKey);
      return issuerName === undefined ? undefined : ephemeral.get(slot({ issuerName, ...binding }));
    }),
  });

  sealer.resource(input.resourceId, input.resourceData);
  for (const item of input.content) {
    sealer.content(item.name, item.value, item.contentType, { accessGroups: item.accessGroups });
  }

  return sealer;
}

/**
 * The vector's signing keys as an issuer holds them: public halves by `kid`,
 * and `kid` alone selects one. A replay verifies the recorded envelopes through
 * this, and an engine run against the vector would verify them the same way.
 *
 * The argument is anything carrying `signingKeys`: a render vector's whole
 * `input`, or a reject vector's `publisher` section. Both carry public halves
 * only, because an issuer that held a publisher's private key could sign
 * renders in that publisher's name.
 *
 * @param {{ signingKeys: { kid: string, publicKeyJwk: EcJwk }[] }} input
 * @returns {Promise<{ get: (kid: string) => ({ publicKey: CryptoKey }|undefined) }>}
 */
export async function importPublisherKeys(input) {
  /** @type {Map<string, CryptoKey>} */
  const byKid = new Map();
  for (const key of input.signingKeys) {
    byKid.set(key.kid, await importSigningPublicKey(key.publicKeyJwk));
  }

  return {
    get(kid) {
      const publicKey = byKid.get(kid);
      return publicKey ? { publicKey } : undefined;
    },
  };
}

/**
 * What an issuer must answer one reject body with, in the shape a replay
 * compares against: the code a whole-request refusal carries, the contentNames
 * whose keys still come back, and the coordinates that come back as an error
 * instead with the code they carry.
 *
 * One shape covers both reaches of a refusal, because `code` and `errors`
 * already say which it is. A request that fails integrity is refused whole:
 * a code, and no keys and no errors, because nothing was asked yet. A blob that
 * will not open at the coordinate it was presented at is refused by itself,
 * with no code, an entry in `errors`, and whatever else the request carried
 * answered normally beside it.
 *
 * `privateKeyReached` records whether the run consulted the key store. An
 * integrity refusal must happen before the key store is consulted, and a
 * per-item unseal failure can only be found by consulting it.
 *
 * @typedef {object} RejectExpectation
 * @property {string|null} code - null when the request was answered per item
 * @property {{ contentKeys: string[], periodKeys?: Record<string, string[]> }} keys - what comes back
 * @property {Record<string, string>} errors - error code per refused coordinate
 * @property {boolean} privateKeyReached
 * @property {{ code: string|null, when: string }[]} [alsoConformant]
 */

/**
 * A reject vector: an unlock request an issuer must not answer as asked, and
 * the key material to answer it with. `rawBody` holds the request as a string,
 * because one of these repeats a member name and a parsed object cannot hold
 * the same key twice.
 *
 * @typedef {object} RejectVector
 * @property {string} name
 * @property {string} vectorFormat
 * @property {string} derivedFrom - the render vector the body was cut from
 * @property {string} description
 * @property {{ issuerName: string, keyId: string, algorithm: string, publicKeyJwk: EcJwk, privateKeyJwk: EcJwk }} issuer
 * @property {{ origin: string, signingKeys: { kid: string, publicKeyJwk: EcJwk }[] }} publisher
 * @property {string} rawBody
 * @property {RejectExpectation} expected
 */

/**
 * The issuer a reject vector describes, standing behind the port: its own
 * private key, the publisher public halves it collected at onboarding, and a
 * counter of key-store lookups, so a test can assert how far a refusal got
 * before it landed instead of reading the source.
 *
 * `buildIssuer` builds one registration per onboarded `kid`: the verification
 * key and the opening-key view that publisher may address, which for a
 * single-tenant issuer is its whole key store. Each render's resourceJWT
 * carries the origin it is delivered from, so registrations leave origin out.
 * An application would resolve `registration` for this vector's own body, by
 * the exact `kid` in its resourceJWT header. It is `undefined` for a
 * kid nobody onboarded, and on that answer the engine refuses a token signed
 * under a key this issuer never registered.
 *
 * @param {RejectVector} vector
 * @returns {Promise<{
 *   endpoint: UnlockEndpoint,
 *   processor: IssuerProcessor,
 *   registrations: Map<string, import('../core-issuer/IssuerEngine.js').PublisherRegistration>,
 *   registration: (import('../core-issuer/IssuerEngine.js').PublisherRegistration|undefined),
 *   asked: { keyStore: number },
 * }>}
 */
export async function buildIssuer(vector) {
  const asked = { keyStore: 0 };
  const privateKey = await importIssuerPrivateKey(vector.issuer.privateKeyJwk);

  const keyStore = {
    /**
     * @param {string} issuerName
     * @param {string} keyId
     */
    get(issuerName, keyId) {
      asked.keyStore++;
      if (issuerName !== vector.issuer.issuerName || keyId !== vector.issuer.keyId)
        return undefined;
      return { algorithm: vector.issuer.algorithm, privateKey };
    },
  };

  /** @type {Map<string, import('../core-issuer/IssuerEngine.js').PublisherRegistration>} */
  const registrations = new Map();
  for (const key of vector.publisher.signingKeys) {
    registrations.set(
      key.kid,
      Object.freeze({
        kid: key.kid,
        publicKey: await importSigningPublicKey(key.publicKeyJwk),
        openingKeys: keyStore,
      }),
    );
  }

  const processor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: [vector.issuer.issuerName],
      accessPolicy: new AllowAllPolicy(),
    }),
    { periodKeyInput: true },
  );

  // `processor` is returned beside `endpoint` for migration/test compatibility
  // and is not a production port. A reusable integration composes `IssuerProcessor`
  // and `UnlockEndpoint` directly and does not go through this handle.
  return {
    endpoint: new UnlockEndpoint(processor),
    processor,
    registrations,
    registration: registrations.get(/** @type {any} */ (headerKid(vector.rawBody))),
    asked,
  };
}

/**
 * The `kid` one request body's resourceJWT names, which alone selects a
 * publisher registration. Nothing verifies it here: the `kid` locates a
 * registration, and the engine verifies the signature under that registration
 * before it trusts the claims.
 *
 * @param {string} rawBody
 * @returns {string|undefined}
 */
function headerKid(rawBody) {
  try {
    return decodeCompactJwt(JSON.parse(rawBody).resourceJWT).header.kid;
  } catch {
    return undefined;
  }
}

/**
 * The contentKeys behind a sealed wire, recovered the way an issuer recovers
 * them. A Sealer hands out sealed blobs rather than keys, so recording the keys
 * means unsealing them.
 *
 * This asks the first issuer and unseals its sealed contentKeys.
 *
 * @param {VectorInput} input
 * @param {any} dcaData
 * @returns {Promise<Record<string, string>>} base64url contentKey per contentName
 */
export async function recoverContentKeys(input, dcaData) {
  const [issuer] = input.issuers;
  const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
  const sealed = dcaData.issuerData[issuer.issuerName].sealed.contentKeys;
  const renderId = decodeCompactJwt(dcaData.resourceJWT).payload.renderId;

  /** @type {Record<string, string>} */
  const keys = {};
  for (const item of input.content) {
    keys[item.name] = base64urlEncode(
      await open(sealed[item.name], privateKey, issuer.algorithm, {
        binding: { renderId, contentName: item.name },
      }),
    );
  }
  return keys;
}

/**
 * The binding value per coordinate of one render, which is the string an
 * implementation has to arrive at before any of these blobs open. Recorded
 * beside the keys so a runtime can check its own builder against it with no
 * crypto in the way. `expected.periodKeys` independently records what came
 * back out of the sealed blobs.
 *
 * @param {VectorInput} input
 * @param {any} dcaData
 * @returns {{ contentKeys: Record<string, string>, periodKeys: Record<string, Record<string, string>> }}
 */
export function bindingValues(input, dcaData) {
  const [issuer] = input.issuers;
  const sealed = dcaData.issuerData[issuer.issuerName].sealed;
  const renderId = decodeCompactJwt(dcaData.resourceJWT).payload.renderId;

  /** @type {Record<string, string>} */
  const contentKeys = {};
  for (const contentName of Object.keys(sealed.contentKeys)) {
    contentKeys[contentName] = bindValue({ renderId, contentName });
  }

  /** @type {Record<string, Record<string, string>>} */
  const periodKeys = {};
  for (const [accessGroup, periods] of Object.entries(sealed.periodKeys ?? {})) {
    /** @type {Record<string, string>} */
    const byPeriod = {};
    for (const t of Object.keys(/** @type {Record<string, string>} */ (periods))) {
      byPeriod[t] = bindValue({ renderId, accessGroup, t });
    }
    periodKeys[accessGroup] = byPeriod;
  }

  return { contentKeys, periodKeys };
}

/**
 * The periodKeys behind the sealed wire, recovered the way an issuer recovers
 * them: unseal `sealed.periodKeys[accessGroup][t]`.
 *
 * Recording these separately from publisher-private `input.periodKeys` checks
 * that the sealed wire recovers the exact bytes it was given.
 *
 * @param {VectorInput} input
 * @param {any} dcaData
 * @returns {Promise<Record<string, Record<string, string>>>} base64url periodKey per accessGroup per t
 */
export async function recoverPeriodKeys(input, dcaData) {
  const [issuer] = input.issuers;
  const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
  const sealed = dcaData.issuerData[issuer.issuerName].sealed.periodKeys ?? {};
  const renderId = decodeCompactJwt(dcaData.resourceJWT).payload.renderId;

  /** @type {Record<string, Record<string, string>>} */
  const keys = {};
  for (const [accessGroup, periods] of Object.entries(sealed)) {
    /** @type {Record<string, string>} */
    const byPeriod = {};
    for (const [t, blob] of Object.entries(/** @type {Record<string, string>} */ (periods))) {
      byPeriod[t] = base64urlEncode(
        await open(blob, privateKey, issuer.algorithm, {
          binding: { renderId, accessGroup, t },
        }),
      );
    }
    keys[accessGroup] = byPeriod;
  }
  return keys;
}

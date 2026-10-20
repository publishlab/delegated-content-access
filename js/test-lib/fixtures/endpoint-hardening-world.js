//
// Shared only by the split reference hardening stories. The local world stays
// exact: each test still builds its own endpoint or server with the options it
// is proving, and the engine remains wrapped for reachability counts.

import { Clock } from "../../demo/actors/Clock.js";
import { Network } from "../../demo/actors/Network.js";
import { Publisher } from "../../demo/actors/Publisher.js";
import { IssuerServer } from "../../demo/actors/IssuerServer.js";
import { IssuerKeyStore } from "../../demo/support/IssuerKeyStore.js";
import {
  PublisherRegistrations,
  openingKeysOver,
} from "../../demo/support/PublisherRegistrations.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { AccessPolicy } from "../../demo/support/AccessPolicy.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../../test-reference/support/keys.js";
import {
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME as BODYTEXT,
  CONTENT_TYPE,
  DOMAIN,
  HEALTH_URL,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
} from "../../demo/scenarios/fixtures.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

export { BODYTEXT, HEALTH_URL, ISSUER_NAME, UNLOCK_URL };

/**
 * A second content name beside the fixtures' one. It is spelled like the
 * fixtures' `ACCESS_GROUP` while serving as a content name here: the issuer
 * entitles it, and the groups this file seals under are the three below.
 */
export const PREMIUM = "premium";

/** Canonical delivery origin registered beside the fixture signing key. */
export const PUBLISHER_ORIGIN = `https://${DOMAIN}`;

/** Sealed by the publisher and never named in the issuer's rules. */
export const VIDEO = "premium-video";

export const ARTICLE_GROUP = "article";
const VAULT_GROUP = "premium-vault";
const VIDEO_GROUP = "video";

const TEXTS = {
  [BODYTEXT]: ARTICLES.A,
  [PREMIUM]: "<p>Two councillors hold shares in the developer.</p>",
  [VIDEO]: "<p>Nine minutes from the committee room.</p>",
};

/** Public bodytext, entitled premium: the smallest world a denial needs. */
const RULES = {
  contentNames: {
    [PUBLISHER_ORIGIN]: {
      [BODYTEXT]: { public: true },
      [PREMIUM]: { entitlement: "premium" },
    },
  },
  accessGroups: {
    [PUBLISHER_ORIGIN]: {
      [ARTICLE_GROUP]: { public: true },
      [VAULT_GROUP]: { entitlement: "premium" },
    },
  },
};

/**
 * Three names over three accessGroups, which is what a denial and an unknown
 * name need beside a grant: one group this issuer opens to anyone, one it
 * entitles, and one it was never told about. The fixtures' `article` is the
 * single-item render most of the suite is pinned to and has none of that.
 */
const ARTICLE = {
  resourceId: "123456",
  data: { section: "politics" },
  items: [
    {
      name: BODYTEXT,
      value: TEXTS[BODYTEXT],
      contentType: CONTENT_TYPE,
      accessGroups: [ARTICLE_GROUP],
    },
    {
      name: PREMIUM,
      value: TEXTS[PREMIUM],
      contentType: CONTENT_TYPE,
      accessGroups: [VAULT_GROUP],
    },
    { name: VIDEO, value: TEXTS[VIDEO], contentType: CONTENT_TYPE, accessGroups: [VIDEO_GROUP] },
  ],
};

/**
 * Every WebCrypto call the issuer makes while this is running, counted at the
 * one place that cannot be faked: `crypto.subtle` itself.
 *
 * A status code says a request was refused; it does not say what the refusal
 * cost. "Nothing was verified and nothing was unsealed" is the claim in the DoS
 * entries, and it is only a claim if the primitives are counted.
 *
 * `asymmetric` is what an attacker is trying to buy: signature verification,
 * ECDH agreement, RSA decryption, keypair generation. Hashing is counted apart
 * and is the cheap half: a cap that refuses ahead of the work leaves both at
 * zero, and one that only skips the expensive half would show the difference.
 *
 * @returns {{ counts: Record<string, number>, stop: () => Record<string, number> }}
 */
export function cryptoMeter() {
  const asymmetric = new Set(["ECDH", "ECDSA", "RSA-OAEP", "RSA-PSS", "RSASSA-PKCS1-v1_5"]);

  /** @param {any} algorithm @returns {string} */
  const named = (algorithm) =>
    typeof algorithm === "string" ? algorithm : (algorithm?.name ?? "");

  /** @type {Record<string, number>} */
  const counts = { asymmetric: 0, verify: 0, deriveBits: 0, decrypt: 0, generateKey: 0, digest: 0 };

  /** Which argument carries the algorithm, and whether the name makes it asymmetric. */
  const watched = {
    verify: () => true,
    sign: () => true,
    deriveBits: (/** @type {any[]} */ args) => asymmetric.has(named(args[0])),
    deriveKey: (/** @type {any[]} */ args) => asymmetric.has(named(args[0])),
    generateKey: (/** @type {any[]} */ args) => asymmetric.has(named(args[0])),
    decrypt: (/** @type {any[]} */ args) => asymmetric.has(named(args[0])),
    encrypt: (/** @type {any[]} */ args) => asymmetric.has(named(args[0])),
    importKey: (/** @type {any[]} */ args) => asymmetric.has(named(args[2])),
    unwrapKey: (/** @type {any[]} */ args) => asymmetric.has(named(args[4])),
    digest: () => false,
  };

  /** @type {Record<string, Function>} */
  const originals = {};

  for (const name of Object.keys(watched)) {
    const original = /** @type {any} */ (subtle)[name];
    originals[name] = original;
    /** @param {...any} args */
    const spy = function (...args) {
      counts[name] = (counts[name] ?? 0) + 1;
      if (/** @type {any} */ (watched)[name](args)) counts.asymmetric++;
      return original.apply(subtle, args);
    };
    /** @type {any} */ (subtle)[name] = spy;
  }

  return {
    counts,
    stop() {
      for (const [name, original] of Object.entries(originals)) {
        /** @type {any} */ (subtle)[name] = original;
      }
      return counts;
    },
  };
}

/**
 * One publisher, one issuer keypair, and the pieces on both sides. The engine
 * is handed out wrapped, so a test can say the engine was never called.
 *
 * @param {object} [config]
 * @param {any} [config.rules] - what the AccessPolicy is built from
 * @returns {Promise<any>}
 */
export async function world(config = {}) {
  const clock = new Clock(AT);
  const random = seededRandom(1);
  const network = new Network({ clock });

  const signingKeys = await signingKeypair();
  const issuerKeys = await issuerKeypair();

  const keyStore = new IssuerKeyStore([
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      privateKey: issuerKeys.privateKey,
      publicKey: issuerKeys.publicKey,
    },
  ]);
  const openingKeys = openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]);
  const publisherRegistration = Object.freeze({
    kid: SIGNING_KID,
    publicKey: signingKeys.publicKey,
    origin: PUBLISHER_ORIGIN,
    openingKeys,
  });
  const publisherRegistrations = new PublisherRegistrations([publisherRegistration]);

  const accessPolicy = new AccessPolicy(config.rules ?? RULES);

  const engineFor = () => new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], accessPolicy });

  /** How often the engine was reached at all. */
  const asked = { engine: 0 };

  /**
   * @param {object} [options] - the port's own configuration
   */
  const endpointWith = (options = {}) => {
    const { limits, ...portOptions } = options ?? {};
    const engine = engineFor();
    // The caps live on processor construction now, so a `limits` option is
    // routed there and only the port's own options reach the port. A cap
    // spelled wrong still throws, from the processor rather than the port.
    const processor = new IssuerProcessor(
      {
        /** @param {...any} args */
        unlock: (...args) => {
          asked.engine++;
          return engine.unlock(...args);
        },
        checkOperatingIssuerName: (...args) => engine.checkOperatingIssuerName(...args),
      },
      { limits, periodKeyInput: true },
    );
    return {
      processor,
      endpoint: new UnlockEndpoint(processor, portOptions),
      registration: publisherRegistration,
    };
  };

  const publisher = new Publisher({
    origin: PUBLISHER_ORIGIN,
    clock,
    random,
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    signingKid: SIGNING_KID,
    periodKeySupply: randomPeriodKeySupply(),
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: ALGORITHM,
        publicKey: issuerKeys.publicKey,
      },
    ],
  });

  /** @returns {Promise<any>} the page as it would sit in markup */
  const render = async () => (await publisher.render(ARTICLE)).asJson();

  /** @param {object} [options] */
  const serverWith = (options = {}) =>
    new IssuerServer({
      clock,
      network,
      issuerName: ISSUER_NAME,
      unlockUrl: UNLOCK_URL,
      keyStore,
      publisherRegistrations,
      accessPolicy,
      periodKeyInput: true,
      ...(options.role === "fallback" && options.emergencyUntil === undefined
        ? { emergencyUntil: clock.now().getTime() + 6 * 60 * 60 * 1000 }
        : {}),
      ...options,
    });

  return {
    clock,
    network,
    random,
    render,
    endpointWith,
    serverWith,
    asked,
    publisherRegistration,
    publisherRegistrations,
  };
}

/**
 * A client's public half, as it would ride along on a client-bound request.
 * Generated rather than fixed, and extractable where `test-reference/support/keys.js` is not:
 * WebCrypto has no seeded EC keygen, what these tests read off it is a count
 * rather than a byte, and the client is the one party that ships its own half.
 *
 * @returns {Promise<any>}
 */
export async function clientPublicKey() {
  const keys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  return subtle.exportKey("jwk", keys.publicKey);
}

/**
 * The same token with its signature moved, which is the cheapest thing a client
 * can do to a resourceJWT that the publisher's key will notice. The leading
 * character, because a P-256 signature is 64 bytes in 86 base64url characters
 * and the last two bits of the last one are not part of any byte.
 *
 * @param {string} token
 * @returns {string}
 */
export function flipSignature(token) {
  const [header, payload, signature] = token.split(".");
  return `${header}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
}

/**
 * A refusal collector, the sink a deployment would log through. It is what
 * makes "the wire says nothing, the log says everything" two claims rather
 * than one.
 *
 * @returns {{ entries: any[], refused: (record: any) => void }}
 */
export function refusalLog() {
  /** @type {any[]} */
  const entries = [];
  return { entries, refused: (record) => entries.push(record) };
}

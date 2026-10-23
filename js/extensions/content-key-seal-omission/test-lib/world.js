// @ts-check
//
// The one world every test in this extension renders from. It is test support
// for this extension only: base `test-lib/` cannot host it, because a bound
// render is produced by this extension's publisher and disappears with the
// directory.
//
// One publisher signing key, two issuer keypairs, one seeded random per render
// and one memoized ephemeral-keypair pool, so a render is byte-reproducible and
// two sealers fed the same inputs emit the same bytes. The inactive-parity
// test rests on that.

import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { randomPeriodKeySupply } from "../../../demo/support/randomPeriodKeySupply.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { deterministicEcdhFixtureSealing } from "../../../tools/vector-fixtures/deterministicEcdhSealing.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

export const ISSUER_A = "issuer_a";
export const ISSUER_B = "issuer_b";
export const KEY_ID = "2025-10";
export const SIGNING_KID = "sign-2025-10";
export const PUB = "https://www.news-site.example";
export const AT = "2025-10-23T14:20:00Z";
export const PERIODS = ["251023T1400", "251023T1500"];

export const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
export const SIDEBAR = "<p>Harbour plan timeline.</p>";
export const NOTE = "<p>Council contact details.</p>";

/**
 * The items every render below can carry, with the accessGroups they are
 * wrapped under. A test names the ones it wants.
 *
 * @type {{ name: string, value: string, contentType: string, accessGroups: string[] }[]}
 */
export const ITEMS = [
  { name: "bodytext", value: ARTICLE, contentType: "text/html", accessGroups: ["premium"] },
  { name: "sidebar", value: SIDEBAR, contentType: "text/html", accessGroups: ["free"] },
  { name: "note", value: NOTE, contentType: "text/html", accessGroups: ["premium"] },
  // Wrapped under two groups, so a candidate can be presented at a real
  // coordinate the policy did not select.
  { name: "both", value: NOTE, contentType: "text/html", accessGroups: ["premium", "free"] },
];

/**
 * A fixed pool of ECDH keypairs handed out by seal-context, in the order the
 * contexts are first seen. WebCrypto has no seeded EC generation, so a
 * byte-identical render needs the pool: two sealers walking the same contexts
 * in the same order draw the same pairs.
 *
 * @param {number} size
 * @returns {Promise<() => ((context: object) => CryptoKeyPair)>} a factory for one
 *   fresh provider per render, all sharing the pool
 */
export async function ephemeralPool(size = 48) {
  /** @type {CryptoKeyPair[]} */
  const pairs = [];
  for (let i = 0; i < size; i += 1) {
    pairs.push(
      /** @type {CryptoKeyPair} */ (
        await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
      ),
    );
  }

  return () => {
    /** @type {Map<string, CryptoKeyPair>} */
    const assigned = new Map();
    return (context) => {
      const key = JSON.stringify(context);
      let pair = assigned.get(key);
      if (!pair) {
        pair = pairs[assigned.size];
        if (!pair) throw new Error("the ephemeral pool ran out; raise its size");
        assigned.set(key, pair);
      }
      return pair;
    };
  };
}

/**
 * The publisher and the two issuers, sharing nothing but public keys.
 *
 * @returns {Promise<{
 *   signingKeys: CryptoKeyPair,
 *   issuerKeys: Record<string, CryptoKeyPair>,
 *   periodKeySupply: { derive: (accessGroup: string, t: string) => Promise<Uint8Array> },
 *   issuerConfig: (issuerName: string, extra?: object) => object,
 *   sealerConfig: (options?: object) => object,
 *   registration: any,
 *   keyStoreFor: (issuerName: string) => object,
 * }>}
 */
export async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  /** @type {Record<string, CryptoKeyPair>} */
  const issuerKeys = {};
  for (const issuerName of [ISSUER_A, ISSUER_B]) {
    issuerKeys[issuerName] = /** @type {CryptoKeyPair} */ (
      await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
    );
  }

  const periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed: 7 }) });

  /**
   * @param {string} issuerName
   * @param {object} [extra] - the extension's own per-issuer members
   */
  function issuerConfig(issuerName, extra = {}) {
    return {
      issuerName,
      keyId: KEY_ID,
      algorithm: "ecdh-p256",
      publicKey: issuerKeys[issuerName].publicKey,

      ...extra,
    };
  }

  /**
   * @param {{ issuers?: object[], at?: string, seed?: number, ephemeralKeyPairs?: Function }} [options]
   */
  function sealerConfig({ ephemeralKeyPairs: fixturePairs, ...options } = {}) {
    return {
      origin: PUB,
      clock: new Clock(options.at ?? AT),
      random: new Random({ seed: options.seed ?? 1 }),
      signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: options.issuers ?? [issuerConfig(ISSUER_A)],
      ...(fixturePairs
        ? {
            keySealing: deterministicEcdhFixtureSealing((issuerPublicKey, binding) => {
              const issuerName = Object.entries(issuerKeys).find(
                ([, pair]) => pair.publicKey === issuerPublicKey,
              )?.[0];
              return issuerName === undefined
                ? undefined
                : fixturePairs({ issuerName, ...binding });
            }),
          }
        : {}),
    };
  }

  /** @param {string} issuerName */
  function keyStoreFor(issuerName) {
    return {
      /**
       * @param {string} name
       * @param {string} keyId
       */
      get(name, keyId) {
        if (name !== issuerName || keyId !== KEY_ID) return undefined;
        return { algorithm: "ecdh-p256", privateKey: issuerKeys[issuerName].privateKey };
      },
    };
  }

  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver({ get: (name, keyId) => keyStoreFor(name).get(name, keyId) }, [
        { issuerName: ISSUER_A, keyId: KEY_ID },
        { issuerName: ISSUER_B, keyId: KEY_ID },
      ]),
    },
  ]).get(SIGNING_KID);

  return {
    signingKeys,
    issuerKeys,
    periodKeySupply,
    issuerConfig,
    sealerConfig,
    registration,
    keyStoreFor,
  };
}

/**
 * A render as the wire carries it: JSON round-tripped, so a test reads plain
 * data and never a live object the sealer still holds.
 *
 * @param {any} sealer
 * @param {{ resourceId?: string, items?: string[] }} [options]
 * @returns {Promise<any>}
 */
export async function render(sealer, options = {}) {
  sealer.resource(options.resourceId ?? "123456", { section: "politics" });
  for (const name of options.items ?? ["bodytext"]) {
    const item = ITEMS.find((candidate) => candidate.name === name);
    if (!item) throw new Error(`no fixture item "${name}"`);
    sealer.content(item.name, item.value, item.contentType, { accessGroups: item.accessGroups });
  }
  const sealed = await sealer.seal();
  // The page carries ciphertexts as named records, the way the JSON writer
  // writes the sealer's map.
  const sealedContent = Object.entries(sealed.sealedContent).map(([contentName, content]) => ({
    contentName,
    content,
  }));
  return JSON.parse(JSON.stringify({ ...sealed.dcaData, sealedContent }));
}

/**
 * A policy that grants content names and no period capability at all, so a
 * response carrying a `periodKeys` member would be the engine's doing and not
 * the policy's. The separate `sourceGrants` answer names the coordinates those
 * items may be opened through: every presented family by default, and exactly
 * what a caller names when it names one.
 *
 * @param {string[]} contentNames
 * @param {{ sourceGrants?: { accessGroup: string, periods: string[] }[] }} [options]
 * @returns {{ decide: Function }}
 */
export function contentOnlyPolicy(contentNames, options = {}) {
  return {
    /**
     * @param {any} claims
     * @param {{ contentNames: string[], accessGroups: string[], periodCoordinates: Record<string, string[]>, sourcePeriodCoordinates?: Record<string, string[]> }} requested
     */
    decide(claims, requested) {
      void claims;
      return {
        contentNames: requested.contentNames.filter((name) => contentNames.includes(name)),
        sourceGrants:
          options.sourceGrants ??
          requested.accessGroups.map((accessGroup) => ({
            accessGroup,
            periods: [
              ...new Set([
                ...(requested.periodCoordinates[accessGroup] ?? []),
                ...(requested.sourcePeriodCoordinates?.[accessGroup] ?? []),
              ]),
            ],
          })),
      };
    },
  };
}

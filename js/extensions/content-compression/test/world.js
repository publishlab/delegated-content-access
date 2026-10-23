// @ts-check
//
// The one world the tests in this directory render from. Test support for this
// extension alone: base `test-lib/` cannot host it, because the compressed
// render comes from this extension's publisher, which disappears with the
// directory.
//
// One publisher signing key, one issuer keypair, a seeded random per render and
// a memoized ephemeral-keypair pool, so a render is byte-reproducible and two
// sealers fed the same inputs emit the same bytes. The identity parity test
// rests on that.

import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { randomPeriodKeySupply } from "../../../demo/support/randomPeriodKeySupply.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { decrypt } from "../../../core-shared/aead.js";
import { base64urlDecode } from "../../../core-shared/codec.js";
import { wrapNonceOf } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";
import { deterministicEcdhFixtureSealing } from "../../../tools/vector-fixtures/deterministicEcdhSealing.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { wire as onWire, wrapsOf } from "../../../test-lib/helpers/inspect.js";

const { subtle } = globalThis.crypto;

export const ISSUER = "issuer_a";
export const KEY_ID = "2025-10";
export const SIGNING_KID = "sign-2025-10";
export const PUB = "https://www.news-site.example";
export const AT = "2025-10-23T14:20:00Z";
export const PERIODS = ["251023T1400", "251023T1500"];
export const GROUP = "premium";

export const ARTICLE =
  "<p>The council voted 7-2 to rezone the harbour, against the objections of the port authority.</p>";
export const SIDEBAR = "<p>Harbour plan timeline.</p>";

/**
 * A fixed pool of ECDH keypairs handed out by seal-context, in the order the
 * contexts are first seen. WebCrypto has no seeded EC generation, so a
 * byte-identical render needs this pool: two sealers walking the same contexts
 * in the same order draw the same pairs.
 *
 * @param {number} [size]
 * @returns {Promise<() => ((context: object) => CryptoKeyPair)>} a factory for one
 *   fresh provider per render, all sharing the pool
 */
export async function ephemeralPool(size = 24) {
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
 * The publisher and its one issuer, sharing nothing but public keys.
 *
 * @returns {Promise<{
 *   signingKeys: CryptoKeyPair,
 *   issuerKeys: CryptoKeyPair,
 *   periodKeySupply: { derive: (accessGroup: string, t: string) => Promise<Uint8Array> },
 *   sealerConfig: (options?: object) => any,
 *   registration: any,
 *   keyStoreFor: (issuerName: string) => object,
 * }>}
 */
export async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );

  const periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed: 7 }) });

  /**
   * @param {{ at?: string, seed?: number, ephemeralKeyPairs?: Function, periodKeySupply?: object }} [options]
   */
  function sealerConfig({ ephemeralKeyPairs: fixturePairs, ...options } = {}) {
    return {
      origin: PUB,
      clock: new Clock(options.at ?? AT),
      random: new Random({ seed: options.seed ?? 1 }),
      signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
      periodKeySupply: options.periodKeySupply ?? periodKeySupply,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: ISSUER,
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,
        },
      ],
      ...(fixturePairs
        ? {
            keySealing: deterministicEcdhFixtureSealing((issuerPublicKey, binding) => {
              if (issuerPublicKey !== issuerKeys.publicKey) return undefined;
              return fixturePairs({ issuerName: ISSUER, ...binding });
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
        return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
      },
    };
  }

  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver({ get: (name, keyId) => keyStoreFor(name).get(name, keyId) }, [
        { issuerName: ISSUER, keyId: KEY_ID },
      ]),
    },
  ]).get(SIGNING_KID);

  return { signingKeys, issuerKeys, periodKeySupply, sealerConfig, registration, keyStoreFor };
}

/**
 * A render as the wire carries it: JSON round-tripped, with the ciphertexts as
 * `{contentName, content}` records, so a test reads plain data and never a
 * live object the sealer still holds.
 *
 * @param {any} sealer
 * @param {{ name: string, value: string|Uint8Array|{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }, contentType?: string, options?: object }[]} items
 * @param {{ resourceId?: string }} [options]
 * @returns {Promise<any>}
 */
export async function render(sealer, items, options = {}) {
  sealer.resource(options.resourceId ?? "123456", { section: "politics" });
  for (const item of items) {
    const contentOptions = { accessGroups: [GROUP], ...(item.options ?? {}) };
    if (
      item.value !== null &&
      typeof item.value === "object" &&
      !(item.value instanceof Uint8Array)
    ) {
      sealer.content(item.name, item.value, contentOptions);
    } else {
      sealer.content(item.name, item.value, item.contentType ?? "text/html", contentOptions);
    }
  }
  return onWire(await sealer.seal());
}

/**
 * The content key of one item, taken back off the render the way the cached
 * path takes it: the period key this supply holds unwraps the first candidate
 * the item carries. The ordinary wrap binds no aad, which is base's v1 shape,
 * and its nonce derives from the render and the wrap's coordinate.
 *
 * @param {any} wire - a `render()` result
 * @param {string} contentName
 * @param {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }} periodKeySupply
 * @returns {Promise<Uint8Array>}
 */
export async function contentKeyOf(wire, contentName, periodKeySupply) {
  const entry = wrapsOf(wire, contentName, GROUP)[0];
  const periodKey = await periodKeySupply.derive(GROUP, entry.period);
  const nonce = wrapNonceOf(wire, contentName, GROUP, entry.period);
  return decrypt(periodKey, nonce, base64urlDecode(entry.key), undefined);
}

/**
 * One item of a render as the client opens it: the view `DcaData` captures,
 * with the content AAD rebuilt from the token and the record.
 *
 * @param {any} wire - a `render()` result, or a copy a test changed
 * @param {string} contentName
 * @returns {import('../../../core-client/DcaData.js').ContentItemView}
 */
export function itemOf(wire, contentName) {
  const item = new DcaData(wire).contentItemFor(contentName);
  if (item === null) throw new Error(`the render declares no item ${contentName}`);
  return item;
}

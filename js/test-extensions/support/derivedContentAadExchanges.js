// @ts-check
//
// One exchange of the derived content AAD adoption matrix: a stock `Sealer`
// render, a demo `IssuerServer` on a demo `Network`, and the public delivery
// client over the JSON carrier (`JsonDeliveryReader`, `createDeliveryClient`)
// or the HTML carrier (`createBrowserClient` over written markup). The key
// route and the response transport are the two other axes:
//
// - `item`: the issuer receives item envelopes only and returns content keys.
// - `period`: the issuer receives period-key envelopes only and returns period
//   keys; the client unwraps the item key from the cached wrap.
// - `chain`: the publisher selects chain-key delivery; the issuer returns a
//   chain key, the client derives the period key from it, then unwraps.
//
// `direct` answers carry raw keys; `client-bound` answers carry keys wrapped to
// one client ECDH-P256 key. The publisher's period keys come from the
// chain-keys family supply in every route, so the `period` and `chain` routes
// open the same wraps by two acquisition paths.

import { Sealer } from "../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { writeJsonDelivery } from "../../adapter-publisher/writeJsonDelivery.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { JsonDeliveryReader } from "../../adapter-client/JsonDeliveryReader.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { Network } from "../../demo/actors/Network.js";
import { IssuerServer } from "../../demo/actors/IssuerServer.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { periodFamilyGeneration } from "../../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { referenceChainKeyProfile } from "../../extensions/chain-keys/referenceProfile.js";
import { ChainKeyCache } from "../../extensions/chain-keys/core-client/ChainKeyCache.js";
import { chainKeyRequestBuilderFactory } from "../../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import * as ecdhProfile from "../../extensions/client-bound-transport/ecdhP256.js";
import * as bound from "../../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import { CompressingSealer } from "../../extensions/content-compression/core-publisher/CompressingSealer.js";
import { decoders } from "../../extensions/content-compression/core-shared--client-publisher/gzipCodec.js";

const { subtle } = globalThis.crypto;

export const PUB = "https://www.news-site.example";
export const ISSUER = "paywall_subscription_service";
export const KEY_ID = "opening-2026-10";
export const KID = "signing-2026-10";
export const AT = "2026-10-15T12:20:00Z";
export const UNLOCK_URL = "https://issuer.example/unlock";
export const GROUP = "premium";
export const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

export const BODY = Object.freeze({
  name: "bodytext",
  value: "<p>The council voted 7-2 to rezone the harbour.</p>",
  contentType: "text/html",
});
export const LOCKED = Object.freeze({
  name: "locked-data",
  value: '{"score":[3,1],"final":true}',
  contentType: "application/json",
});

/** @typedef {{ name: string, value: string, contentType: string }} Item */
/** @typedef {"item"|"period"|"chain"} KeyRoute */
/** @typedef {"direct"|"client-bound"} ResponseTransport */
/** @typedef {"json"|"html"} Carrier */

/**
 * @param {KeyRoute} route
 * @returns {import("../../core-issuer/IssuerEngine.js").AccessPolicy}
 */
function policyFor(route) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      if (route === "item") {
        return { contentNames: [...requested.contentNames], periodGrants: [], policyData: [] };
      }
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) =>
          route === "chain"
            ? { accessGroup, futurePeriodCount: 1, authorizePeriod: () => true }
            : { accessGroup, periods: [...(requested.periodCoordinates?.[accessGroup] ?? [])] },
        ),
        policyData: [],
      };
    },
  };
}

/** @param {KeyRoute} route */
function supplyPlanFor(route) {
  return (/** @type {any} */ issuer, /** @type {any} */ render) => {
    const whole = wholeRenderIssuerSupplyPlan(issuer, render);
    if (route === "item") return { ...whole, suppliedAccessGroups: [] };
    if (route === "period") return { ...whole, contentKeyNames: [] };
    return { ...whole, contentKeyNames: [], periodKeyDelivery: { [GROUP]: ["chain-keys"] } };
  };
}

/**
 * @param {{ route: KeyRoute, transport: ResponseTransport, resourceId?: string }} cell
 */
export async function exchangeWorld({ route, transport, resourceId = "article-42" }) {
  const signing = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const opening = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const periodKeySupply = periodFamilySupply({
    families: {
      [GROUP]: periodFamilyGeneration({
        keyDerivationSecret: new Uint8Array(32).fill(7),
        geometry: GEOMETRY,
      }),
    },
    chainWindows: 2,
  });
  let seed = 1;

  /**
   * @param {{ resourceId?: string, items?: Item[], gzip?: string[] }} [config] -
   *   `gzip` names the items the content-compression publisher encodes; with
   *   it, every item goes through that publisher and the rest stay identity
   */
  async function render(config = {}) {
    const sealerConfig = {
      origin: PUB,
      clock: new Clock(AT),
      random: new Random({ seed: seed++ }),
      signingKeys: { [KID]: signing.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: supplyPlanFor(route),
      issuers: [
        { issuerName: ISSUER, keyId: KEY_ID, algorithm: "ecdh-p256", publicKey: opening.publicKey },
      ],
    };
    const gzip = config.gzip;
    const sealer = gzip ? new CompressingSealer(sealerConfig) : new Sealer(sealerConfig);
    sealer.resource(config.resourceId ?? resourceId, { section: "politics" });
    for (const item of config.items ?? [BODY, LOCKED]) {
      sealer.content(item.name, item.value, item.contentType, {
        accessGroups: [GROUP],
        ...(gzip ? { contentEncoding: gzip.includes(item.name) ? "gzip" : "identity" } : {}),
      });
    }
    return sealer.seal();
  }

  const clock = new Clock(AT);
  const network = new Network({ clock });
  const keyStore = {
    get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
      issuerName === ISSUER && keyId === KEY_ID
        ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
        : undefined,
  };
  new IssuerServer({
    clock,
    network,
    issuerName: ISSUER,
    unlockUrl: UNLOCK_URL,
    keyStore,
    publisherRegistrations: new PublisherRegistrations([
      {
        kid: KID,
        publicKey: signing.publicKey,
        openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER, keyId: KEY_ID }]),
      },
    ]),
    accessPolicy: policyFor(route),
    periodKeyInput: true,
    ...(route === "chain"
      ? { periodGrantKind: "chain-keys", chainKeyProfile: referenceChainKeyProfile }
      : {}),
    ...(transport === "client-bound"
      ? {
          transportMode: "client-bound",
          clientBoundProfile: ecdhProfile,
          random: new Random({ seed: 99 }),
        }
      : {}),
  });

  /** Every answer the issuer gave, as the client received it. */
  const answers = /** @type {{ status: number, body: any }[]} */ ([]);
  const hostTransport = {
    /** @param {string} url @param {object} request @param {{ origin: string }} context */
    async post(url, request, context) {
      const answer = await network.post(url, request, { origin: context.origin });
      answers.push(answer);
      return { ...answer, contentType: "application/json" };
    },
  };

  /** Client options one reader keeps across loads: its caches and capability. */
  async function readerState() {
    /** @type {Record<string, any>} */
    const state = { cache: new PeriodKeyCache(), contentDecoders: decoders };
    if (transport === "client-bound") {
      const pair = /** @type {CryptoKeyPair} */ (
        await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
      );
      state.clientBoundKeyCapability = bound.clientBoundKeyCapability(
        { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) },
        ecdhProfile,
      );
    } else {
      state.persistRawPeriodKeys = true;
    }
    if (route === "chain") {
      state.chainCache = new ChainKeyCache();
      state.chainKeyProfile = referenceChainKeyProfile;
      state.requestBuilderFactory = chainKeyRequestBuilderFactory;
    }
    return state;
  }

  /**
   * The public client for one render over one carrier.
   *
   * @param {{ dcaData: any, sealedContent: any }} rendered
   * @param {Carrier} carrier
   * @param {Record<string, any>} state - from `readerState()`, shared to retain grants
   */
  function clientFor(rendered, carrier, state) {
    const common = {
      issuerName: ISSUER,
      unlockUrl: UNLOCK_URL,
      transport: hostTransport,
      relayPeriodKeys: true,
      ...state,
    };
    if (carrier === "json") {
      const reader = new JsonDeliveryReader(writeJsonDelivery(rendered), { publisherOrigin: PUB });
      return createDeliveryClient({ reader, ...common });
    }
    const root = domOver(writeMarkupDelivery(rendered), { publisherOrigin: PUB });
    return createBrowserClient({ root, ...common });
  }

  return { render, readerState, clientFor, answers };
}

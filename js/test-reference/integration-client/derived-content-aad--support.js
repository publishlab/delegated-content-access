// @ts-check
//
// One publisher, one issuer and the public delivery client, wired the way a
// host wires them, for the derived content AAD adoption tests beside this file.
// Every render runs the stock `Sealer`; every key comes from the stock issuer
// through explicit admission; every item opens through `createDeliveryClient`.
// Nothing here builds or checks an AAD. The test files hand-build octets where
// they need them, with `../support/contentAadOctets.js`.
//
// The world keeps the publisher's signing key so a test can re-sign a token the
// way a publisher refreshes a signature, and keeps one period-key supply across
// renders so two renders of one resourceId in one period share the period key a
// reader retained.

import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { Clock } from "../../demo/actors/Clock.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { es256Sign } from "../../core-shared/cryptoProvider.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../support/keys.js";

export const PUB = "https://publisher.example";
export const ISSUER = "news_issuer";
export const KEY_ID = "opening-2026-10";
export const KID = "signing-2026-10";
export const AT = "2026-10-15T12:20:00Z";
export const UNLOCK_URL = "https://issuer.example/unlock";
export const OTHER_UNLOCK_URL = "https://other-endpoint.example/unlock";
export const GROUP = "premium";
export const RESOURCE_ID = "article-42";

/** Two items in one group: one reusable period grant reaches both. */
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

/**
 * Two invented representation layers, so a test can change the encoding list
 * and still reach the opening step: a client refuses an encoding it holds no
 * decoder for before it resolves a key.
 */
export const DECODERS = Object.freeze({
  "x-reverse": (/** @type {Uint8Array} */ bytes) => Uint8Array.from(bytes).reverse(),
  "x-identity": (/** @type {Uint8Array} */ bytes) => Uint8Array.from(bytes),
});

/**
 * An item whose bytes already carry two layers. The publisher records them in
 * order; the client undoes `x-identity`, then `x-reverse`.
 */
export const ENCODED = Object.freeze({
  name: "encoded-note",
  plaintext: "<p>Ferry timetable for the winter season.</p>",
  contentType: "text/html",
  contentEncodings: Object.freeze(["x-reverse", "x-identity"]),
});

/** The `Sealer` descriptor for `ENCODED`. */
export function encodedItem() {
  return {
    name: ENCODED.name,
    value: {
      bytes: utf8Encode(ENCODED.plaintext).reverse(),
      contentType: ENCODED.contentType,
      contentEncodings: [...ENCODED.contentEncodings],
    },
  };
}

/** @typedef {{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} ContentDescriptor */

/**
 * @param {object} [options]
 * @param {"period"|"item"} [options.route] - `period` supplies the issuer only
 *   period-key envelopes, so every content key a reader holds came through a
 *   reusable period grant; `item` supplies only item envelopes.
 */
export async function world({ route = "period" } = {}) {
  const issuerKeys = await issuerKeypair();
  const signing = await signingKeypair();
  const periodKeySupply = randomPeriodKeySupply();
  let seed = 1;

  /**
   * @param {object} [config]
   * @param {string} [config.resourceId]
   * @param {object} [config.data]
   * @param {{ name: string, value: string|Uint8Array|ContentDescriptor, contentType?: string }[]} [config.items]
   * @returns {Promise<{ dcaData: any, sealedContent: Record<string, string> }>}
   */
  async function render(config = {}) {
    const sealer = new Sealer({
      origin: PUB,
      clock: new Clock(AT),
      random: seededRandom(seed++),
      signingKeys: { [KID]: signing.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: (issuer, plan) => ({
        ...wholeRenderIssuerSupplyPlan(issuer, plan),
        ...(route === "period" ? { contentKeyNames: [] } : { suppliedAccessGroups: [] }),
      }),
      issuers: [
        {
          issuerName: ISSUER,
          keyId: KEY_ID,
          algorithm: "ecdh-p256",
          publicKey: issuerKeys.publicKey,
        },
      ],
    });
    sealer.resource(config.resourceId ?? RESOURCE_ID, config.data ?? { section: "politics" });
    for (const item of config.items ?? [BODY, LOCKED]) {
      const groups = { accessGroups: route === "period" ? [GROUP] : [] };
      if (typeof item.value === "object" && !(item.value instanceof Uint8Array)) {
        sealer.content(item.name, item.value, groups);
      } else {
        sealer.content(item.name, item.value, item.contentType, groups);
      }
    }
    const rendered = await sealer.seal();
    // Both artefacts crossed a wire.
    return JSON.parse(
      JSON.stringify({ dcaData: rendered.dcaData, sealedContent: rendered.sealedContent }),
    );
  }

  const registration = /** @type {any} */ (
    new PublisherRegistrations([
      {
        kid: KID,
        publicKey: signing.publicKey,
        openingKeys: openingKeysOver(
          {
            get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
              issuerName === ISSUER && keyId === KEY_ID
                ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
                : undefined,
          },
          [{ issuerName: ISSUER, keyId: KEY_ID }],
        ),
      },
    ]).get(KID)
  );
  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [ISSUER], accessPolicy: new AllowAllPolicy() }),
    { periodKeyInput: true },
  );
  const endpoint = new UnlockEndpoint(processor);

  /** Every request the issuer answered, with its URL and answer. */
  const exchanges = /** @type {{ url: string, request: any, status: number, body: any }[]} */ ([]);

  /**
   * The issuer as a host transport reaches it. `hold` runs after the issuer
   * answered and before the client sees the answer, so a test can act while
   * the unlock awaits.
   *
   * @param {{ hold?: () => Promise<void>|void }} [options]
   */
  function transport({ hold } = {}) {
    return {
      /** @param {string} url @param {any} request */
      async post(url, request) {
        const answer = await unlockThroughAdmission(processor, endpoint, request, registration);
        exchanges.push({ url, request, status: answer.status, body: answer.body });
        await hold?.();
        return { ...answer, contentType: "application/json" };
      },
    };
  }

  /**
   * A public delivery client over one delivery. It relays period-key envelopes
   * and keeps the raw period keys the issuer returns, which is the reusable
   * grant these tests retain.
   *
   * @param {{ dcaData: any, sealedContent: Record<string, string> }} delivered
   * @param {object} [options]
   * @param {any} [options.cache] - a retained cache, shared with an earlier client
   * @param {any} [options.storage]
   * @param {string} [options.unlockUrl]
   * @param {() => Promise<void>|void} [options.hold]
   * @param {Record<string, (bytes: Uint8Array) => Uint8Array|Promise<Uint8Array>>} [options.contentDecoders]
   */
  function client(delivered, options = {}) {
    const reader = {
      dcaData: delivered.dcaData,
      publisherOrigin: PUB,
      extract: (/** @type {string} */ name) =>
        Object.hasOwn(delivered.sealedContent, name) ? delivered.sealedContent[name] : null,
    };
    return createDeliveryClient({
      reader,
      issuerName: ISSUER,
      unlockUrl: options.unlockUrl ?? UNLOCK_URL,
      transport: transport({ hold: options.hold }),
      relayPeriodKeys: true,
      persistRawPeriodKeys: true,
      ...(options.cache === undefined ? {} : { cache: options.cache }),
      ...(options.storage === undefined ? {} : { storage: options.storage }),
      contentDecoders: options.contentDecoders ?? DECODERS,
    });
  }

  /**
   * A client that can only open with what an earlier client retained: its
   * transport refuses every post, so a success proves the retained grant.
   *
   * @param {{ dcaData: any, sealedContent: Record<string, string> }} delivered
   * @param {any} cache
   * @param {Record<string, (bytes: Uint8Array) => Uint8Array|Promise<Uint8Array>>} [contentDecoders]
   */
  function retained(delivered, cache, contentDecoders = DECODERS) {
    const reader = {
      dcaData: delivered.dcaData,
      publisherOrigin: PUB,
      extract: (/** @type {string} */ name) =>
        Object.hasOwn(delivered.sealedContent, name) ? delivered.sealedContent[name] : null,
    };
    return createDeliveryClient({
      reader,
      issuerName: ISSUER,
      transport: {
        async post() {
          throw new Error("a retained-grant client sends no request");
        },
      },
      cache,
      contentDecoders,
    });
  }

  /**
   * A compact JWS over the given segments, signed by this publisher's key.
   *
   * @param {string} header - the base64url header segment
   * @param {string} payload - the base64url payload segment
   */
  async function signSegments(header, payload) {
    const input = `${header}.${payload}`;
    const signature = await es256Sign(signing.privateKey, utf8Encode(input));
    return `${input}.${base64urlEncode(new Uint8Array(signature))}`;
  }

  return {
    render,
    client,
    retained,
    signSegments,
    exchanges,
    registration,
    processor,
    endpoint,
  };
}

/**
 * Put a whole item record into the slot `contentName` names on a delivery,
 * over the last record of that name, or after the others when no record has
 * it. The record goes in under `contentName` whatever name it carried, which
 * is how a test moves a complete record to another slot.
 *
 * @param {any} dcaData
 * @param {string} contentName
 * @param {any} record
 */
export function putItemRecord(dcaData, contentName, record) {
  const placed = { ...record, contentName };
  const index = dcaData.contentData.findLastIndex(
    (/** @type {any} */ entry) => entry.contentName === contentName,
  );
  if (index === -1) dcaData.contentData.push(placed);
  else dcaData.contentData[index] = placed;
}

/**
 * The period-key records one unlock answer carries for `accessGroup`.
 *
 * @param {any} body - the issuer's answer
 * @param {string} accessGroup
 * @returns {any[]}
 */
export function periodKeysAnswered(body, accessGroup) {
  return body.keys.periodKeys.filter(
    (/** @type {any} */ record) => record.accessGroup === accessGroup,
  );
}

/**
 * One JSON value as a base64url segment.
 *
 * @param {unknown} value
 */
export function segment(value) {
  return base64urlEncode(utf8Encode(JSON.stringify(value)));
}

/** @param {Uint8Array} bytes */
export function text(bytes) {
  return new TextDecoder().decode(bytes);
}

// Shared roles for the content-groups tests that need the stock chain-key
// construction from the chain-keys extension. Every role is the production
// one: `createPublisher` with the content-groups publisher contribution,
// `createIssuerCore` with the issuer contribution, and `createDeliveryClient`
// with the client bundle's `composeOptions`, over the real `PeriodKeyCache`
// and `ChainKeyCache`. A page crosses the JSON delivery writer and reader, and
// a request and its answer cross JSON text, as on the wire.
import { writeJsonDelivery } from "../../../../adapter-publisher/writeJsonDelivery.js";
import { decodeCompactJwt } from "../../../../core-shared/compactJwt.js";
import { JsonDeliveryReader } from "../../../../adapter-client/JsonDeliveryReader.js";
import { PeriodKeyCache } from "../../../../adapter-client/PeriodKeyCache.js";
import { createPublisher } from "../../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../../integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "../../../../integration-client/createDeliveryClient.js";
import {
  chainKeyCoordinate,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../../../chain-keys/core-shared/chainKeyConstruction.js";
import { periodFamilyGeneration } from "../../../chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { ChainKeyCache } from "../../../chain-keys/core-client/ChainKeyCache.js";
import { contentGroupsProfile } from "../../referenceProfile.js";

export const PUBLISHER = "https://news.example";
export const UNLOCK = "https://issuer.example/unlock";
export const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 60 });
export const T12 = "261014T1200";
export const T18 = "261014T1800";
export const T19 = "261014T1900";
export const NEXT = "261015T0000";
export const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
/** The host's stock chain port: the chain-keys construction, nothing invented. */
export const CHAIN = Object.freeze({
  coordinate: chainKeyCoordinate,
  labelAt: chainKeyLabelAt,
  settleGeometry: settleChainGeometry,
  familyGeneration: periodFamilyGeneration,
});
const subtle = globalThis.crypto.subtle;
const random = { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) };

/** The signed resource claims of a page's `resourceJWT`, decoded without verification. */
export function claimsOf(resourceJWT) {
  return decodeCompactJwt(resourceJWT).payload;
}
/** `count` distinct group names that sort in creation order. */
export function names(count) {
  return Array.from({ length: count }, (_, i) => `group${String(i).padStart(4, "0")}`);
}
export function copy(value) {
  return structuredClone(value);
}
/** The instant 20 minutes into the period a label names, e.g. 261014T1900. */
export function instant(label) {
  const [, yy, mm, dd, hh, mi] = /^(\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)$/.exec(label);
  return new Date(
    Date.UTC(2000 + Number(yy), Number(mm) - 1, Number(dd), Number(hh), Number(mi) + 20),
  );
}
/** An item with connector groups; `groups` undefined means an ordinary-only item. */
export function item(name, groups, text = `content:${name}`) {
  return {
    name,
    value: text,
    contentType: "text/plain",
    ...(groups === undefined ? {} : { contentGroups: groups }),
  };
}

/**
 * A policy that answers a chain grant to `cutoffT` for every requested group
 * of every requested content name in `windowStart`, and the item key for every
 * requested item. `authorize(contentName, group, t, windowStart)` answers each
 * period of a chain grant's reach.
 */
export function chainPolicy({ cutoffT = T18, windowStart = T12, authorize = () => true } = {}) {
  return (input) => ({
    grants: [
      ...Object.entries(input.contentGroups).flatMap(([contentName, { groups, windows }]) =>
        windows.includes(windowStart)
          ? groups.map((group) => ({ kind: "chain", contentName, group, windowStart, cutoffT }))
          : [],
      ),
      ...input.items.map((contentName) => ({ kind: "item", contentName })),
    ],
    authorizePeriod: authorize,
  });
}

/**
 * Publisher signing keys, issuer opening keys and the trusted registration
 * both issuers read.
 */
export async function world({ issuers = ["issuer"] } = {}) {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = Object.fromEntries(
    await Promise.all(
      issuers.map(async (name) => [
        name,
        await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
      ]),
    ),
  );
  let verifierReads = 0;
  const openingLookups = [];
  const registration = {
    kid: "p1",
    get publicKey() {
      verifierReads++;
      return signing.publicKey;
    },
    openingKeys: {
      get(issuerName, keyId) {
        openingLookups.push([issuerName, keyId]);
        return Object.hasOwn(opening, issuerName) && keyId === `${issuerName}-k1`
          ? { algorithm: "ecdh-p256", privateKey: opening[issuerName].privateKey }
          : undefined;
      },
    },
  };

  /**
   * A publisher composed with the content-groups contribution. By default
   * every issuer receives the seeds of every connector item's content name for
   * the T12 and NEXT windows, and only the items named in `ordinary` get an
   * ordinary content-key envelope.
   */
  function publisher({
    at = T12,
    origin = PUBLISHER,
    retainedSecret = SECRET,
    periodGeometry = GEOMETRY,
    seedWindows,
    connectorNames = [],
    ordinary = [],
    limits,
  } = {}) {
    const issuerSeedWindows =
      seedWindows ??
      Object.fromEntries(
        issuers.map((name) => [
          name,
          Object.fromEntries(connectorNames.map((n) => [n, [T12, NEXT]])),
        ]),
      );
    const composed = createPublisher(
      {
        origin,
        clock: { now: () => instant(at) },
        random,
        signingKeys: { p1: signing.privateKey },
        issuers: issuers.map((issuerName) => ({
          issuerName,
          keyId: `${issuerName}-k1`,
          algorithm: "ecdh-p256",
          publicKey: opening[issuerName].publicKey,
        })),
        issuerSupplyPlanFor: (_issuer, render) => ({
          contentKeyNames: render.contentNames.filter((name) => ordinary.includes(name)),
          suppliedAccessGroups: [],
        }),
      },
      contentGroupsProfile.publisherContribution({
        retainedSecret,
        periodGeometry,
        issuerSeedWindows,
        limits,
        chain: CHAIN,
      }),
    );
    return {
      /** One render, returned as a reader receives it: the parsed JSON delivery. */
      async publish({ items, data = {}, resourceId = "story1" }) {
        const render = await composed.publish({ resourceId, data, items });
        const reader = new JsonDeliveryReader(writeJsonDelivery(render), {
          publisherOrigin: origin,
        });
        const sealedContent = Object.fromEntries(
          Object.keys(reader.dcaData.contentData).map((name) => [name, reader.extract(name)]),
        );
        return { page: copy(reader.dcaData), sealedContent, origin };
      },
    };
  }

  /** One render; `items` also name the connector items that receive seeds. */
  function publish({ items, data, resourceId, ...options }) {
    const connectorNames = items.filter((i) => i.contentGroups?.length).map((i) => i.name);
    return publisher({ connectorNames, ...options }).publish({ items, data, resourceId });
  }

  /**
   * One issuer core. `policy(input)` answers the content-groups policy port;
   * `purchased` lists the items base policy grants ordinary item keys for.
   */
  function issuer({ name = issuers[0], policy = chainPolicy(), limits, purchased } = {}) {
    const calls = { decide: [], answers: [] };
    const core = createIssuerCore(
      {
        operatingIssuerNames: issuers,
        accessPolicy: {
          decide: (_claims, requested) => ({
            contentNames: requested.contentNames.filter((n) => !purchased || purchased.includes(n)),
          }),
        },
      },
      contentGroupsProfile.issuerContribution({
        chain: CHAIN,
        limits,
        policy: {
          decide(input) {
            calls.decide.push(input);
            return policy(input);
          },
        },
      }),
    );
    /** Answer one request document as the endpoint answers its JSON text. */
    async function answer(request) {
      const result = await core.endpoint.handleDocument(JSON.stringify(request), registration);
      const response = {
        status: result.response.status,
        body: JSON.parse(JSON.stringify(result.response.body)),
        code: result.code,
      };
      calls.answers.push(response);
      return response;
    }
    return { name, core, calls, answer };
  }

  /**
   * One reader: a period-key cache and a chain-key cache that live across every
   * page this reader opens, as one browser profile keeps them.
   */
  function reader({ limits, chain = CHAIN } = {}) {
    let periodKeyCache;
    let chainKeyCache;
    const held = {
      periodKeyCache: () => periodKeyCache,
      chainKeyCache: () => chainKeyCache,
    };
    /**
     * A delivery client for one page, through `issuerCore`. `narrowing` is the
     * bundle's trusted local request selection; `answered(body, request)` may
     * replace the issuer's answer before the client reads it; `deliveryReader`
     * replaces the page's plain reader with a carrier reader; `capability` is a
     * client-bound key capability the request offers.
     */
    function client(
      published,
      issuerCore,
      { narrowing, answered, deliveryReader, capability, sent = [] } = {},
    ) {
      const bundle = contentGroupsProfile.client({
        chain,
        limits,
        ...(narrowing === undefined ? {} : { narrowing }),
        createPeriodKeyCache: (config) => (periodKeyCache ??= new PeriodKeyCache(config)),
        createChainKeyCache: (config) => (chainKeyCache ??= new ChainKeyCache(config)),
      });
      const transport = {
        async post(_url, request) {
          const document = JSON.parse(JSON.stringify(request));
          sent.push(document);
          const { status, body } = await issuerCore.answer(document);
          const delivered = answered ? answered(copy(body), document) : body;
          return { status, contentType: "application/json", body: delivered };
        },
      };
      const { page, sealedContent, origin } = published;
      const delivery = createDeliveryClient({
        reader: deliveryReader ?? {
          dcaData: copy(page),
          publisherOrigin: origin,
          extract: (name) => (Object.hasOwn(sealedContent, name) ? sealedContent[name] : null),
        },
        issuerName: issuerCore.name,
        unlockUrl: UNLOCK,
        transport,
        ...(capability === undefined ? {} : { clientBoundKeyCapability: capability }),
        ...bundle.composeOptions,
      });
      return {
        delivery,
        bundle,
        sent,
        /** Walk this client's one route for `contentNames`; an item that opens from cache asks nothing. */
        unlock: (contentNames) =>
          delivery.unlockRoutes(contentNames, [{ issuerName: issuerCore.name, unlockUrl: UNLOCK }]),
        /** One request to the issuer for `contentNames`, whatever the caches already open. */
        attempt: (contentNames) => delivery.unlock(contentNames),
        /** One item's plaintext, or null when no held or cached key opens it. */
        async open(name) {
          try {
            return new TextDecoder().decode((await delivery.openLocal(name)).bytes);
          } catch {
            return null;
          }
        },
      };
    }
    return { client, ...held };
  }

  return {
    publisher,
    publish,
    issuer,
    reader,
    registration,
    opening,
    signing,
    openingLookups,
    verifierReads: () => verifierReads,
  };
}

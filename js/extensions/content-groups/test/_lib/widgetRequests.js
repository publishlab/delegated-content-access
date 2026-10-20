// @ts-check
//
// A delivery client over an invented extension request member, for tests of
// the generic seams a selected request builder offers the base walk:
// `routeProjection` and `keyFamilies`. Route identity is `name/widget`. The
// resolver is a double that reports items missing until a scripted answer
// resolves them; no key is opened.

import { createDeliveryClient } from "../../../../integration-client/createDeliveryClient.js";
import { DcaRequestBuilder } from "../../../../core-client/DcaRequestBuilder.js";
import { DcaRequest } from "../../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../../../core-shared/codec.js";
import { dcaError } from "../../../../core-shared/errors.js";

export const PUB = "https://news.example";
export const A = "issuer_a";
export const B = "issuer_b";
export const C = "issuer_c";
export const URL_OF = /** @type {Record<string, string>} */ ({
  [A]: "https://a.example/unlock",
  [B]: "https://b.example/unlock",
  [C]: "https://c.example/unlock",
});

/** @param {any} value */
const json = (value) => base64urlEncode(utf8Encode(JSON.stringify(value)));
export const JWT = `${json({ alg: "ES256", kid: "k1" })}.${json({ origin: PUB, renderId: "AAAAAAAAAAAAAAAAAAAAAA" })}.c2ln`;
const NONCE = base64urlEncode(new Uint8Array(12));
const BODY = base64urlEncode(new Uint8Array(32));

/** Widgets each issuer block carries. */
export const WIDGETS = /** @type {Record<string, Record<string, string[]>>} */ ({
  [A]: { bodytext: ["w1", "w2"], headline: ["w3"] },
  [B]: { headline: ["w3"] },
  [C]: { bodytext: ["w1", "w2"], headline: ["w3"] },
});

export function page() {
  return {
    version: "1",
    resourceJWT: JWT,
    contentData: {
      bodytext: { contentType: "text/plain", nonce: NONCE },
      headline: { contentType: "text/plain", nonce: NONCE },
    },
    issuerData: Object.fromEntries(
      Object.entries(WIDGETS).map(([issuer, widgets]) => [
        issuer,
        {
          keyId: "kid",
          sealed: {
            contentKeys: {},
            widgetSeeds: Object.fromEntries(Object.keys(widgets).map((n) => [n, `seed-${n}`])),
          },
        },
      ]),
    ),
  };
}

/** @type {import("../../../../adapter-client/routeAttempts.js").RouteProjection} */
export const projection = {
  members: ["requestedWidgets"],
  sealedMembers: ["widgetSeeds"],
  identities(request) {
    return Object.entries(request.requestedWidgets ?? {}).flatMap(([name, list]) =>
      /** @type {string[]} */ (list).map((widget) => `${name}/${widget}`),
    );
  },
  project(request, routes) {
    /** @type {Record<string, string[]>} */
    const requestedWidgets = {};
    /** @type {Record<string, string>} */
    const widgetSeeds = {};
    for (const route of routes) {
      const [name, widget] = route.split("/");
      if (!request.requestedWidgets?.[name]?.includes(widget)) continue;
      (requestedWidgets[name] ??= []).push(widget);
      widgetSeeds[name] = request.sealed.widgetSeeds[name];
    }
    return Object.keys(requestedWidgets).length === 0
      ? {}
      : { members: { requestedWidgets }, sealed: { widgetSeeds } };
  },
  useful(route, missing) {
    return missing.includes(route.split("/")[0]);
  },
};

export class WidgetRequestBuilder {
  #inner;
  routeProjection = projection;
  /** What the widgets return: item content keys, or derivation keys. */
  returns = { contentKeys: false, familyKeys: true };
  /** @param {{ clientPublicKey?: unknown }} [options] */
  constructor(options = {}) {
    this.#inner = new DcaRequestBuilder(
      options.clientPublicKey === undefined ? {} : { clientPublicKey: options.clientPublicKey },
    );
  }
  /** @param {any} request */
  keyFamilies(request) {
    const present = Object.keys(request.requestedWidgets ?? {}).length > 0;
    return {
      contentKeys: present && this.returns.contentKeys,
      familyKeys: present && this.returns.familyKeys,
    };
  }
  /** @param {any} dcaData @param {string} issuerName @param {string[]} needed */
  build(dcaData, issuerName, needed) {
    const request = this.#inner.build(dcaData, issuerName, needed).toObject();
    const held = WIDGETS[issuerName] ?? {};
    const names = needed.filter((name) => Object.hasOwn(held, name));
    if (names.length === 0) return new DcaRequest(request);
    return new DcaRequest({
      ...request,
      sealed: {
        ...request.sealed,
        widgetSeeds: Object.fromEntries(names.map((n) => [n, `seed-${n}`])),
      },
      requestedWidgets: Object.fromEntries(names.map((n) => [n, [...held[n]]])),
    });
  }
}

/**
 * @param {{ builder?: any, answers?: Record<string, (request: any) => any>, options?: Record<string, unknown>, acceptDirectResponse?: boolean }} setup
 */
export function world({
  builder = new WidgetRequestBuilder(),
  answers = {},
  options = {},
  acceptDirectResponse,
}) {
  /** @type {{ issuer: string, request: any }[]} */
  const posted = [];
  const missing = new Set(["bodytext", "headline"]);
  const resolver = {
    async applyResponse() {
      return { accepted: 1, errors: [], issues: [], notDelivered: [] };
    },
    async resolveDetailed(/** @type {any} */ _d, /** @type {string[]} */ names) {
      return { covered: [], missing: names.filter((n) => missing.has(n)), origins: [] };
    },
    async resolveAuthenticated(/** @type {any} */ _d, /** @type {string[]} */ names) {
      return { missing: names.filter((n) => missing.has(n)) };
    },
    async resolve() {
      return [];
    },
    async contentKeyFor() {
      return null;
    },
    async contentKeyWithOriginFor() {
      return null;
    },
    async clearReaderContext() {},
  };
  const client = createDeliveryClient({
    reader: { dcaData: page(), publisherOrigin: PUB, extract: () => BODY },
    issuerName: A,
    unlockUrl: URL_OF[A],
    ...(acceptDirectResponse === undefined ? {} : { acceptDirectResponse }),
    transport: {
      async post(url, request) {
        const issuer = Object.keys(URL_OF).find((name) => URL_OF[name] === url) ?? "";
        posted.push({ issuer, request: structuredClone(request) });
        const answer = (answers[issuer] ?? (() => ({})))(request);
        for (const name of answer.resolves ?? []) missing.delete(name);
        if (answer.fail) throw dcaError(answer.fail, "scripted transport failure");
        return { status: 200, contentType: "application/json", body: {} };
      },
    },
    requestBuilderFactory: () => builder,
    resolverFactory: () => resolver,
    ...options,
  });
  return { client, posted };
}

// @ts-check
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "../../../integration-client/createDeliveryClient.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import {
  ISSUER,
  UNLOCK,
  keys,
  random,
  registrationFor,
  publishCapture,
} from "./_shared/exchange.js";

const DEFAULTS = Object.freeze({
  publisher: {
    origin: "https://news.example",
    resourceId: "article",
    data: { section: "news" },
    at: "2026-10-17T14:20:00.000Z",
    items: [{ name: "bodytext", value: "Readable content", contentType: "text/plain" }],
  },
  issuer: { authorizedItems: null },
  client: {},
});

/** @param {unknown} value @param {string} label @returns {asserts value is Record<string, any>} */
function record(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(`${label} must be an object`);
}

/** @param {Record<string, any>} value @param {string[]} members @param {string} label */
function known(value, members, label) {
  for (const name of Object.keys(value))
    if (!members.includes(name)) throw new Error(`Unknown ${label}.${name}`);
}

/** Resolve only documented overrides and return a fresh JSON-compatible input. */
function resolveInput(input = {}) {
  record(input, "input");
  known(input, ["publisher", "issuer", "client"], "input");
  const p = input.publisher === undefined ? {} : input.publisher;
  const i = input.issuer === undefined ? {} : input.issuer;
  const c = input.client === undefined ? {} : input.client;
  record(p, "publisher");
  record(i, "issuer");
  record(c, "client");
  known(p, ["origin", "resourceId", "data", "at", "items"], "publisher");
  known(i, ["authorizedItems"], "issuer");
  known(c, [], "client");

  const publisher = { ...structuredClone(DEFAULTS.publisher), ...structuredClone(p) };
  if (typeof publisher.origin !== "string" || publisher.origin.length === 0)
    throw new Error("publisher.origin must be a nonempty origin string");
  const parsedOrigin = new URL(publisher.origin);
  if (
    parsedOrigin.origin !== publisher.origin ||
    !["https:", "http:"].includes(parsedOrigin.protocol)
  )
    throw new Error("publisher.origin must be a canonical HTTP(S) origin");
  if (typeof publisher.resourceId !== "string" || publisher.resourceId.length === 0)
    throw new Error("publisher.resourceId must be a nonempty string");
  record(publisher.data, "publisher.data");
  if (
    typeof publisher.at !== "string" ||
    !publisher.at.includes("T") ||
    !Number.isFinite(Date.parse(publisher.at))
  )
    throw new Error("publisher.at must be an ISO date-time");
  publisher.at = new Date(publisher.at).toISOString();
  if (!Array.isArray(publisher.items) || publisher.items.length === 0)
    throw new Error("publisher.items must be a nonempty list");
  publisher.items = publisher.items.map((item, index) => {
    record(item, `publisher.items[${index}]`);
    known(item, ["name", "value", "contentType"], `publisher.items[${index}]`);
    if (
      typeof item.name !== "string" ||
      item.name.length === 0 ||
      typeof item.value !== "string" ||
      typeof item.contentType !== "string"
    )
      throw new Error(`publisher.items[${index}] needs string name, value, and contentType`);
    return { name: item.name, value: item.value, contentType: item.contentType };
  });
  if (new Set(publisher.items.map((item) => item.name)).size !== publisher.items.length)
    throw new Error("publisher item names must be distinct");

  const authorizedItems = i.authorizedItems ?? null;
  if (
    authorizedItems !== null &&
    (!Array.isArray(authorizedItems) ||
      authorizedItems.some((name) => typeof name !== "string") ||
      new Set(authorizedItems).size !== authorizedItems.length)
  )
    throw new Error("issuer.authorizedItems must be null or a list of distinct item names");
  return structuredClone({ publisher, issuer: { authorizedItems }, client: {} });
}

/** @type {import("../runBench.js").Scenario} */
export const scenario = Object.freeze({
  id: "item",
  requestedProfiles: ["dca-profile-baseline"],
  defaults: DEFAULTS,
  resolveInput,
  async execute({ input, observe, scope }) {
    const { publisher: p, issuer: policyInput } = input;
    observe.count("publisherRenders");
    const roleKeys = await observe.time("keySetup", () => keys());
    const publisher = createPublisher({
      origin: p.origin,
      clock: { now: () => new Date(p.at) },
      random,
      signingKeys: { p1: roleKeys.signing.privateKey },
      signingKid: "p1",
      issuers: [
        {
          issuerName: ISSUER,
          keyId: "k1",
          algorithm: "ecdh-p256",
          publicKey: roleKeys.opening.publicKey,
        },
      ],
      issuerSupplyPlanFor: (_issuer, render) => ({
        contentKeyNames: render.contentNames,
        suppliedAccessGroups: [],
      }),
    });
    const render = await observe.time("publisher", () =>
      publisher.publish({
        resourceId: p.resourceId,
        data: p.data,
        items: p.items,
      }),
    );
    const published = publishCapture(render, p.origin, observe);
    observe.check("delivery-captured", published.bytes.byteLength > 0, {
      bytes: published.bytes.byteLength,
    });

    if (scope === "publisher") return;

    const registration = registrationFor(roleKeys);
    const issuer = createIssuerCore({
      operatingIssuerNames: [ISSUER],
      accessPolicy: {
        decide(claims, requested) {
          const resourceMatches =
            claims.resource.origin === p.origin && claims.resource.resourceId === p.resourceId;
          const allowed =
            policyInput.authorizedItems === null
              ? requested.contentNames
              : requested.contentNames.filter((name) => policyInput.authorizedItems.includes(name));
          return { contentNames: resourceMatches ? allowed : [] };
        },
      },
    });

    const names = p.items.map((item) => item.name);
    if (scope === "publisher-issuer") {
      const wire = JSON.parse(new TextDecoder().decode(published.bytes));
      const page = new DcaData(wire, { publisherOrigin: p.origin });
      const request = new DcaRequestBuilder().build(page, ISSUER, names).toObject();
      const requestText = JSON.stringify(request);
      observe.capture("request", JSON.parse(requestText), { text: requestText });
      observe.count("unlock");
      const answer = await observe.time("issuer", () =>
        issuer.endpoint.handleDocument(requestText, registration, {}, Date.parse(p.at)),
      );
      const responseText = JSON.stringify(answer.response.body);
      observe.capture("response", JSON.parse(responseText), {
        text: responseText,
        status: answer.response.status,
      });
      observe.check("issuer-status", answer.response.status === 200, {
        status: answer.response.status,
        code: answer.code,
      });
      return;
    }

    const client = createDeliveryClient({
      reader: published.reader(),
      issuerName: ISSUER,
      unlockUrl: UNLOCK,
      transport: {
        async post(url, request) {
          if (url !== UNLOCK) throw new Error("unexpected issuer route");
          const requestText = JSON.stringify(request);
          observe.capture("request", JSON.parse(requestText), { text: requestText });
          observe.count("unlock");
          const answer = await observe.time(
            "issuer",
            () => issuer.endpoint.handleDocument(requestText, registration, {}, Date.parse(p.at)),
            { nested: true },
          );
          const responseText = JSON.stringify(answer.response.body);
          observe.capture("response", JSON.parse(responseText), {
            text: responseText,
            status: answer.response.status,
          });
          return {
            status: answer.response.status,
            contentType: "application/json",
            body: JSON.parse(responseText),
          };
        },
      },
    });
    observe.snapshot("before", {
      available: false,
      reason: "Baseline item-key resolver does not expose retained-key enumeration",
    });
    const walk = await observe.time("client", () =>
      client.unlockRoutes(names, [{ issuerName: ISSUER, unlockUrl: UNLOCK }]),
    );
    const deniedNames = names.filter(
      (name) => policyInput.authorizedItems !== null && !policyInput.authorizedItems.includes(name),
    );
    observe.check(
      "route-walk",
      walk.failed.length === 0 &&
        deniedNames.every((name) => walk.missing.includes(name)) &&
        walk.missing.every((name) => deniedNames.includes(name)),
      walk,
    );
    for (const item of p.items) {
      let plaintext = null;
      let failure;
      try {
        plaintext = new TextDecoder().decode(
          (await observe.time("opening", () => client.openLocal(item.name))).bytes,
        );
      } catch (error) {
        failure = error?.code ?? error?.message ?? String(error);
      }
      const permitted =
        policyInput.authorizedItems === null || policyInput.authorizedItems.includes(item.name);
      observe.check(
        `item:${item.name}`,
        permitted ? plaintext === item.value : plaintext === null && failure === "no_key",
        {
          expected: permitted ? "opens authored plaintext" : "refused",
          opened: plaintext !== null,
          ...(failure ? { code: failure } : {}),
        },
      );
    }
    observe.snapshot("after", {
      available: false,
      reason: "Baseline item-key resolver does not expose retained-key enumeration",
    });
  },
});

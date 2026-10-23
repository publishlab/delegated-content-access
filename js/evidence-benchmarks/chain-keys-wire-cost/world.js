// @ts-check
//
// The reference composition one measured case runs through: one publisher
// render, its markup delivery, and one unlock exchange between a reference
// client and a reference issuer. `run.js` asks this module for renders and
// exchanges and prints what they cost; `measure.js` holds the compression,
// normalization and counting helpers.
//
// Every byte measured here comes out of a reference path:
//
//   publisher   `core-publisher/Sealer.js` with
//               `extensions/chain-keys/core-publisher/periodFamilySupply.js`;
//               `core-publisher/issuerSupplyPlan.js` selects the supply form
//               per issuer and access group
//   delivery    `adapter-publisher/writeMarkupDelivery.js`, the two inert
//               script blocks a CDN serves inside the article HTML
//   client      `integration-client/createBrowserClient.js` over
//               `adapter-client/MarkupDeliveryReader.js`, with
//               `core-client/DcaRequestBuilder.js` for the period-key client
//               and `extensions/chain-keys/core-client/ChainKeyRequestBuilder.js`
//               with `ChainKeyCache.js` for the relay client
//   issuer      `ports/UnlockEndpoint.js` `handleDocument` over
//               `core-issuer/IssuerProcessor.js`, with the base
//               `core-issuer/IssuerEngine.js` for the period-key issuer and
//               `extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js`
//               for chain input, under `representation: 'period-keys'` or `'chain-keys'`
//
// The client's request crosses as `JSON.stringify` of the request object, the
// serialization `createBrowserClient` documents for its transport, and the
// issuer admits that same string. The response crosses as
// `JSON.stringify` of the endpoint's body, and the client reads it back parsed.

import { Sealer } from "../../core-publisher/Sealer.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { createBrowserClient } from "../../integration-client/createBrowserClient.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { requestLimits } from "../../core-shared/requestLimits.js";
import { DATA_CLASS, SEALED_CLASS } from "../../core-shared/markupPlacement.js";
import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { ChainKeyCache } from "../../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { chainKeyIssuerEngine } from "../../extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js";
import { referenceChainKeyProfile } from "../../extensions/chain-keys/referenceProfile.js";

const { subtle } = globalThis.crypto;

export const PUB = "https://www.news-site.example";
export const SIGNING_KID = "sign-2025-10";
export const KEY_ID = "2025-10";
export const NAME = "bodytext";

/**
 * A short article body. Its ciphertext is the same length in every case, so
 * it adds the same bytes to every render and moves no marginal figure.
 */
export const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

/** Two chains a day over fifteen-minute periods, `N = 48`: the chain-key test geometry. */
export const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/**
 * The supply forms, each with the delivery array `issuerSupplyPlan` takes for
 * it. `content-key-only` is the floor: a render with no period-key supply at
 * all, which carries the item content-key route alone.
 */
export const FORMS = Object.freeze({
  "content-key-only": null,
  "period-key-only": ["period-keys"],
  "period-key-plus-chain": ["period-keys", "chain-keys"],
  "chain-only": ["chain-keys"],
});

/** @param {number} fill */
const secret = (fill) => new Uint8Array(32).fill(fill);

/**
 * One issuer's key pair for the named envelope. RSA-OAEP runs at the 2048-bit
 * floor the sealed-key specification admits, with SHA-256 as the format fixes.
 *
 * @param {'ecdh-p256'|'rsa-oaep'} algorithm
 * @returns {Promise<CryptoKeyPair>}
 */
async function issuerKeyPair(algorithm) {
  if (algorithm === "ecdh-p256") {
    return /** @type {CryptoKeyPair} */ (
      await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
    );
  }
  return /** @type {CryptoKeyPair} */ (
    await subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,
      ["encrypt", "decrypt"],
    )
  );
}

/**
 * @typedef {object} CaseSpec
 * @property {keyof typeof FORMS} form
 * @property {'ecdh-p256'|'rsa-oaep'} algorithm
 * @property {number} issuers - how many issuers the render seals for
 * @property {number} groups - how many access groups the one item is wrapped under
 * @property {number} slots - the periods the render wraps under and supplies period keys
 *   for, current first
 * @property {number} chainWindows - stationary windows a chain member is supplied for
 * @property {string} at - the render instant, and the issuer's captured instant
 */

/**
 * @typedef {object} Rendered
 * @property {CaseSpec} spec
 * @property {string} markup - the delivery as the publisher adapter wrote it
 * @property {any} dcaData
 * @property {Record<string, string>} sealedContent
 * @property {{ issuerName: string, unlockUrl: string, registration: any }[]} issuers
 */

/**
 * One publisher render through the reference path. Every issuer receives the
 * same supply form for every access group. Each access group gets its own
 * canonical family generation, built fresh so its derivation work is counted
 * cold, and the same secret in every case, so two forms of one case wrap the
 * item under identical period keys.
 *
 * @param {CaseSpec} spec
 * @returns {Promise<Rendered>}
 */
export async function render(spec) {
  const signing = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const groups = Array.from({ length: spec.groups }, (unused, index) => `tier_${index + 1}`);
  const families = Object.fromEntries(
    groups.map((group, index) => [
      group,
      periodFamilyGeneration({ keyDerivationSecret: secret(7 + index), geometry: GEOMETRY }),
    ]),
  );

  const issuers = [];
  const configs = [];
  for (let index = 0; index < spec.issuers; index++) {
    const issuerName = `issuer_${index + 1}`;
    const unlockUrl = `https://unlock-${index + 1}.example.com/unlock`;
    const keys = await issuerKeyPair(spec.algorithm);
    configs.push({
      issuerName,
      keyId: KEY_ID,
      algorithm: spec.algorithm,
      publicKey: keys.publicKey,
      // The publisher may author large supply rows; the exchange below still
      // exercises each issuer route's independently configured request limit.
      limits: requestLimits({ maxBodyBytes: 1_000_000, maxEntries: 1024, maxEntriesPerGroup: 512 }),
    });
    const registration = new PublisherRegistrations([
      {
        kid: SIGNING_KID,
        publicKey: signing.publicKey,
        openingKeys: openingKeysOver(
          {
            get: (/** @type {string} */ name, /** @type {string} */ keyId) =>
              name === issuerName && keyId === KEY_ID
                ? { algorithm: spec.algorithm, privateKey: keys.privateKey }
                : undefined,
          },
          [{ issuerName, keyId: KEY_ID }],
        ),
      },
    ]).get(SIGNING_KID);
    issuers.push({ issuerName, unlockUrl, registration });
  }

  const delivery = FORMS[spec.form];
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(spec.at),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    period: { length: GEOMETRY.periodMinutes, slots: spec.slots },
    issuerSupplyPlanFor: () => ({
      contentKeyNames: [NAME],
      suppliedAccessGroups: delivery === null ? [] : groups,
      reachableContentNames: delivery === null ? [] : [NAME],
      ...(delivery === null
        ? {}
        : { periodKeyDelivery: Object.fromEntries(groups.map((group) => [group, delivery])) }),
    }),
    ...(delivery === null
      ? {}
      : {
          periodKeySupply:
            spec.form === "period-key-only"
              ? { derive: (group, t) => families[group].periodKey(group, t) }
              : periodFamilySupply({
                  families,
                  chainWindows: spec.chainWindows,
                  chainItemSlots: spec.slots,
                }),
        }),
    issuers: configs,
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: delivery === null ? [] : groups });
  const rendered = await sealer.seal();
  const markup = writeMarkupDelivery(rendered);

  return {
    spec,
    markup,
    dcaData: JSON.parse(JSON.stringify(rendered.dcaData)),
    sealedContent: { ...rendered.sealedContent },
    issuers,
  };
}

/**
 * A page root over the delivered markup string, answering the two class
 * queries `MarkupDeliveryReader` makes. It reads the string the writer
 * emitted, so the client parses what crossed rather than the render's values.
 * The writer emits each block as one `<script type="application/json">`
 * element and escapes every sequence that could end one early, so the first
 * close tag after the open tag ends the block.
 *
 * @param {string} markup
 * @param {string} origin
 */
export function rootOver(markup, origin) {
  /** @param {string} className */
  const blocks = (className) =>
    [
      ...markup.matchAll(
        new RegExp(
          `<script type="application/json" class="${className}">([\\s\\S]*?)</script>`,
          "g",
        ),
      ),
    ].map((found) => ({
      tagName: "SCRIPT",
      textContent: found[1],
      getAttribute: (/** @type {string} */ name) => (name === "type" ? "application/json" : null),
    }));
  /** @type {Record<string, object[]>} */
  const bySelector = {
    [`.${DATA_CLASS}`]: blocks(DATA_CLASS),
    [`.${SEALED_CLASS}`]: blocks(SEALED_CLASS),
  };
  return {
    location: { origin },
    querySelectorAll: (/** @type {string} */ selector) => bySelector[selector] ?? [],
  };
}

/**
 * A policy that grants period material and nothing else, `horizon` periods
 * from the issuer's current coordinate. A content key granted on the item
 * content-key route would open the item without any period key, so the policy
 * grants none.
 *
 * @param {number} horizon
 * @param {boolean} chainInput
 */
function periodOnly(horizon, chainInput) {
  return {
    decide: (/** @type {any} */ unusedClaims, /** @type {any} */ requested) => {
      void unusedClaims;
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) =>
          chainInput
            ? {
                accessGroup,
                futurePeriodCount: horizon,
                authorizePeriod: () => true,
              }
            : {
                accessGroup,
                periods: [...(requested.periodCoordinates[accessGroup] ?? [])].slice(0, horizon),
              },
        ),
      };
    },
  };
}

/**
 * The issuer a route is configured with.
 *
 *   period-key        the base issuer, `periodKeyInput` selected: it opens
 *                     the period keys the request relays
 *   chain>period-key  chain input selected, `representation: 'period-keys'`:
 *                     it returns period keys projected from chain keys
 *   chain>chain       chain input selected, `representation: 'chain-keys'`:
 *                     it returns positioned chain keys
 *
 * @typedef {'period-key'|'chain>period-key'|'chain>chain'} IssuerKind
 */

/**
 * @param {IssuerKind} kind
 * @param {number} horizon
 * @param {string} at
 * @param {Record<string, number>|undefined} limits
 * @param {string} issuerName
 */
function issuerEndpoint(kind, horizon, at, limits, issuerName) {
  const accessPolicy = periodOnly(horizon, kind !== "period-key");
  const engine =
    kind === "period-key"
      ? new IssuerEngine({ accessPolicy, operatingIssuerNames: [issuerName] })
      : chainKeyIssuerEngine({
          accessPolicy,
          operatingIssuerNames: [issuerName],
          clock: new Clock(at),
          representation: kind === "chain>chain" ? "chain-keys" : "period-keys",
        });
  const processor = new IssuerProcessor(engine, {
    ...(limits === undefined ? {} : { limits }),
    capabilityEncoders: /** @type {any} */ (engine).capabilityEncoders ?? {},
    selectedExtensions: /** @type {any} */ (engine).selectedExtensions ?? [],
    periodKeyInput: kind === "period-key",
  });
  return new UnlockEndpoint(processor);
}

/**
 * The client a route serves.
 *
 *   period-key  the base client with `relayPeriodKeys` selected
 *   relay       the chain-key relay client, `relayPeriodKeys` also
 *               selected, with a chain cache and the reference profile so
 *               it can admit and derive from a chain response
 *
 * @typedef {'period-key'|'relay'} ClientKind
 */

/**
 * @typedef {object} Exchange
 * @property {string} requestDocument - the request as it crossed
 * @property {number} status
 * @property {string|null} code - the refusal code, when the issuer refused
 * @property {string} responseDocument - the response body as it crossed
 * @property {any} body - that body, parsed
 * @property {any} application - what the client's resolver made of it
 * @property {{ kind: string }|null} origin - where the opening content key came from
 * @property {string|null} opened - the article text the client decrypted, or null
 */

/**
 * One unlock exchange for the first issuer of a render: the client builds its
 * request from the delivered markup, the issuer admits and answers that same
 * document, and the client applies the answer and opens the article. The first
 * issuer stands for any other; each issuer's exchange carries only its own
 * issuer block.
 *
 * `phases` receives each phase's name as it begins, so a caller counting
 * operations can file them under the actor that spent them.
 *
 * @param {Rendered} rendered
 * @param {{ client: ClientKind, issuer: IssuerKind, horizon: number, limits?: Record<string, number> }} route
 * @param {(phase: 'client'|'issuer') => void} [phases]
 * @returns {Promise<Exchange>}
 */
export async function exchange(rendered, route, phases = () => {}) {
  const { issuerName, unlockUrl, registration } = rendered.issuers[0];
  const endpoint = issuerEndpoint(
    route.issuer,
    route.horizon,
    rendered.spec.at,
    route.limits,
    issuerName,
  );
  const capturedAtMs = Date.parse(rendered.spec.at);

  /** @type {{ requestDocument: string, responseDocument: string, status: number, code: string|null }} */
  const crossed = { requestDocument: "", responseDocument: "", status: 0, code: null };
  const transport = {
    post: async (/** @type {string} */ unusedUrl, /** @type {object} */ request) => {
      crossed.requestDocument = JSON.stringify(request);
      phases("issuer");
      const answer = await endpoint.handleDocument(
        crossed.requestDocument,
        registration,
        {},
        capturedAtMs,
      );
      phases("client");
      crossed.status = answer.response.status;
      crossed.code = answer.code ?? null;
      crossed.responseDocument = JSON.stringify(answer.response.body);
      return {
        status: answer.response.status,
        contentType: "application/json",
        body: JSON.parse(crossed.responseDocument),
      };
    },
  };

  phases("client");
  const relay = route.client === "relay";
  // `createBrowserClient` passes every member it does not read itself on to
  // `composeClient`, which is where the relay and chain options land.
  const client = createBrowserClient(
    /** @type {any} */ ({
      root: rootOver(rendered.markup, PUB),
      issuerName,
      unlockUrl,
      transport,
      relayPeriodKeys: true,
      ...(relay
        ? {
            chainCache: new ChainKeyCache({ strategy: "retain" }),
            chainKeyProfile: referenceChainKeyProfile,
            requestBuilderFactory: (/** @type {object} */ options) =>
              new ChainKeyRequestBuilder(options),
          }
        : {}),
    }),
  );

  // `unlock` resolves the item against the response it just applied and keeps
  // the answer to itself. The resolver instance is shadowed for this one call,
  // as the chain-key test world records cache answers, so the origin of the
  // content key is read off the client's own resolution.
  /** @type {{ kind: string }|null} */
  let origin = null;
  const resolveDetailed = client.resolver.resolveDetailed.bind(client.resolver);
  client.resolver.resolveDetailed = async (/** @type {any[]} */ ...args) => {
    const resolved = await resolveDetailed(...args);
    origin = resolved.origins[0]?.origin ?? null;
    return resolved;
  };
  const answer = await client.unlock([NAME]);
  delete client.resolver.resolveDetailed;

  let opened = null;
  if (answer.status === 200) {
    // The captured view carries the content AAD the client derives; the
    // record carries none.
    const item = client.dcaData.contentItemFor(NAME);
    if (item === null) throw new Error(`the render declares no item ${NAME}`);
    const bytes = await client.opener.open({
      item,
      ciphertext: client.reader.extract(NAME),
      resolveKey: (authenticate) =>
        client.resolver.contentKeyForAuthenticatedItem(client.dcaData, NAME, authenticate),
    });
    opened = utf8Decode(bytes);
  }

  return {
    requestDocument: crossed.requestDocument,
    status: crossed.status,
    code: crossed.code,
    responseDocument: crossed.responseDocument,
    body: answer.body,
    application: answer.application,
    origin,
    opened,
  };
}

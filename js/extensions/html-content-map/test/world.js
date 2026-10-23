// @ts-check
//
// Test setup for the HTML content-map profile: one publisher that renders a
// locked HTML page through the real publisher path (`createPublisher`, then
// `writeMarkupDelivery` with embedded contentMap), and one issuer built by
// `createIssuerCore` behind a transport that counts every unlock request.
// The same world serves the browser path, the server-side path and the
// oracle, so every run sees the same locked bytes and the same issuer
// decisions.
//
// The pages are the examples of docs/spec-proposal--html-content-map.md Section 12:
// `articlePage` is the Section 12.3 multi-placement page with its seven rules,
// and `nestedTemplatePage` is the Section 12.4 template that makes
// `#main .bodytext` match three elements.

import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";

export const ORIGIN = "https://pub.example";
export const ISSUER_NAME = "map_issuer";
export const UNLOCK_URL = "https://issuer.example/unlock";
export const AT = "2026-09-29T20:10:00Z";
export const GROUP = "premium";

/** The two protected items of Section 12.3. */
export const BODYTEXT =
  "<p>The council voted 7-2 to rezone the harbour.</p>\n<p>Traders &amp; residents object.</p>";
export const FACTBOX = '<ul class="facts"><li>Vote: 7-2</li><li>Area: <b>north quay</b></li></ul>';

/** The seven rules of Section 12.3, verbatim. */
export const ARTICLE_MAP = Object.freeze({
  version: "1",
  rules: [
    { item: "bodytext", op: "fill", target: "#main .bodytext" },
    {
      item: "bodytext",
      op: "removeClass",
      target: "#main .bodytext",
      class: "locked",
    },
    { item: "bodytext", op: "removeClass", target: "#main .bodytext", class: "preview-content" },
    { item: "bodytext", op: "removeClass", target: "body", class: "blur-content" },
    { item: "bodytext", op: "remove", target: ".subscription-prompt" },
    { item: "factbox", op: "fill", target: "#factbox-inline" },
    { item: "factbox", op: "fill", target: "#factbox-aside" },
  ],
});

/**
 * The Section 12.3 page body around the carriers.
 *
 * @param {string} carriers
 * @returns {string}
 */
export function articlePage(carriers) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Harbour vote</title></head>
<body class="article blur-content">
  <div class="subscription-prompt">Subscribe to read on</div>
  <section class="main" id="main">
    <div class="bodytext locked preview-content">
      <p>The first lines of the story…</p>
    </div>
    <div id="factbox-inline"></div>
  </section>
  <aside><div id="factbox-aside"></div></aside>
  ${carriers}
</body></html>`;
}

/**
 * The Section 12.4 template: nested body elements for the same article.
 *
 * @param {string} carriers
 * @returns {string}
 */
export function nestedTemplatePage(carriers) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Harbour vote</title></head>
<body class="article blur-content">
  <div class="subscription-prompt">Subscribe to read on</div>
  <section class="main" id="main">
    <div class="bodytext">
      <div class="bodytext intro"><p>The first lines…</p></div>
      <div class="bodytext content-text"></div>
    </div>
    <div id="factbox-inline"></div>
  </section>
  <aside><div id="factbox-aside"></div></aside>
  ${carriers}
</body></html>`;
}

/**
 * A page with one plain-text slot, for `text/plain` placement.
 *
 * @param {string} carriers
 * @returns {string}
 */
export function bylinePage(carriers) {
  return `<!DOCTYPE html>
<html><head><title>Byline</title></head>
<body><p class="byline" id="byline">Byline for subscribers</p>
${carriers}
</body></html>`;
}

/** @type {Record<string, Uint8Array>} */
const PERIOD_KEYS = {};

/**
 * @param {string} accessGroup
 * @param {string} t
 * @returns {Uint8Array}
 */
function periodKeyFor(accessGroup, t) {
  const name = `${accessGroup}|${t}`;
  PERIOD_KEYS[name] ??= Uint8Array.from(
    { length: 16 },
    (_, i) => (name.length * 7 + i * 13) & 0xff,
  );
  return Uint8Array.from(PERIOD_KEYS[name]);
}

/**
 * One publisher and its issuer.
 *
 * @param {object} [options]
 * @param {string} [options.origin]
 * @param {string} [options.signingKid]
 * @param {boolean} [options.periodKeyInput] - whether the issuer reads
 *   relayed period keys
 * @param {'none'|'partial'|'complete'} [options.notDeliveredReport]
 */
export async function mapWorld({
  origin = ORIGIN,
  signingKid = "pub-sign-1",
  periodKeyInput = false,
  notDeliveredReport = "none",
} = {}) {
  const opening = await issuerKeypair();
  const signing = await signingKeypair();
  const publisher = createPublisher({
    origin,
    clock: { now: () => new Date(AT) },
    random: { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) },
    signingKeys: { [signingKid]: signing.privateKey },
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: "open-1",
        algorithm: "ecdh-p256",
        publicKey: opening.publicKey,
      },
    ],
    issuerSupplyPlanFor: (_issuer, render) => ({
      contentKeyNames: [...render.contentNames],
      suppliedAccessGroups: [...render.accessGroups],
    }),
    periodKeySupply: { derive: async (accessGroup, t) => periodKeyFor(accessGroup, t) },
    period: { length: 60, slots: 2 },
  });

  /**
   * What the issuer's policy grants: item names for content keys, and
   * whether presented period families are granted.
   *
   * @type {{ contentNames: string[]|'all', periods: boolean, retired: boolean }}
   */
  const grant = { contentNames: "all", periods: false, retired: false };
  const issuer = createIssuerCore({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: {
      decide: (_claims, requested) => ({
        contentNames:
          grant.contentNames === "all"
            ? requested.contentNames
            : requested.contentNames.filter((name) => grant.contentNames.includes(name)),
        periodGrants: grant.periods
          ? requested.accessGroups.map((accessGroup) => ({
              accessGroup,
              // This fixture deliberately grants one admitted coordinate.
              periods: [...(requested.periodCoordinates[accessGroup] ?? [])].slice(0, 1),
            }))
          : [],
      }),
    },
    periodKeyInput,
    notDeliveredReport,
  });
  const registration = {
    kid: signingKid,
    publicKey: signing.publicKey,
    openingKeys: {
      /** @param {string} issuerName @param {string} keyId */
      get(issuerName, keyId) {
        if (issuerName !== ISSUER_NAME || keyId !== "open-1") return undefined;
        return grant.retired
          ? { retired: true }
          : { algorithm: "ecdh-p256", privateKey: opening.privateKey };
      },
    },
  };

  /** @type {{ url: string, request: any, status: number }[]} */
  const unlocks = [];
  const transport = {
    /**
     * @param {string} url
     * @param {object} request
     * @returns {Promise<{ status: number, contentType: string, body: any }>}
     */
    async post(url, request) {
      const { response } = await issuer.endpoint.handleDocument(
        JSON.stringify(request),
        /** @type {any} */ (registration),
      );
      unlocks.push({ url, request: JSON.parse(JSON.stringify(request)), status: response.status });
      return { status: response.status, contentType: "application/json", body: response.body };
    },
  };

  /**
   * Render one locked page through the real publisher path. The embedded map is
   * written without admission, so a case can deliver a map the client must
   * refuse; `../adapter-publisher/writeMappedDelivery.js` is the admitting
   * publisher entry.
   *
   * @param {object} render
   * @param {string} [render.resourceId]
   * @param {{ name: string, value: string, contentType: string }[]} render.items
   * @param {object} [render.contentMap]
   * @param {(carriers: string) => string} render.page
   * @returns {Promise<{ html: string, dcaData: any, sealedContent: Record<string, string> }>}
   */
  async function publish({ resourceId = "harbour-vote", items, contentMap, page }) {
    const { dcaData, sealedContent } = await publisher.publish({
      resourceId,
      data: { section: "local" },
      items: items.map((item) => ({ ...item, accessGroups: [GROUP] })),
    });
    if (contentMap !== undefined) dcaData.contentMap = contentMap;
    const carriers = writeMarkupDelivery({ dcaData, sealedContent });
    return { html: page(carriers), dcaData, sealedContent };
  }

  /** The Section 12.3 delivery. */
  const article = () =>
    publish({
      items: [
        { name: "bodytext", value: BODYTEXT, contentType: "text/html" },
        { name: "factbox", value: FACTBOX, contentType: "text/html" },
      ],
      contentMap: ARTICLE_MAP,
      page: articlePage,
    });

  return {
    origin,
    signingKid,
    signingPublicKey: signing.publicKey,
    grant,
    transport,
    unlocks,
    publish,
    article,
  };
}

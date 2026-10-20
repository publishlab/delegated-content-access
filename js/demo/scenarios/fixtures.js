// @ts-check
//
// One story supplies the names: a paywall issuer, a news site, an hour past
// two, and five articles about a harbour. These values decide nothing. Every
// world and every test would otherwise write them out again, and one copy keeps
// a test asserting `'251023T1400'` and a test asserting `'251023T1500'` on the same
// clock.
//
// Loadable in a page, like everything under demo/scenarios/: no node imports, no
// assertions, no printing.
//
// `periodSecret` remains a byte fixture for base tests that reject the retired
// configuration member. The optional chain-key extension uses
// keyDerivationSecret. Each fixture is a call
// because a shared mutable `Uint8Array` would couple otherwise separate tests.

/** The primary issuer of the story, and the second one where a test needs two. */
export const ISSUER_NAME = "paywall_subscription_service";
export const FALLBACK_ISSUER_NAME = "paywall_fallback_service";

/** The URL each issuer answers on, plus the primary's health URL. */
export const UNLOCK_URL = "https://api.example.com/unlock";
export const HEALTH_URL = "https://api.example.com/health";
export const FALLBACK_UNLOCK_URL = "https://fallback.example.com/unlock";

/** The publisher has one host, one signing key and one issuer keypair coordinate. */
export const DOMAIN = "www.news-site.example";

/**
 * The single browser origin the publisher's renders are delivered from, and the
 * value its `resourceJWT.origin` and every BIND carry. It is canonical, so the page, the
 * HTTP Origin header and the sealed blobs spell it the same way.
 */
export const ORIGIN = "https://www.news-site.example";
export const SIGNING_KID = "sign-2025-10";
export const KEY_ID = "2025-10";
export const ALGORITHM = "ecdh-p256";

/** Twenty past two, so the hour has room on both sides of it. */
export const AT = "2025-10-23T14:20:00Z";

export const ACCESS_GROUP = "premium";
export const CONTENT_NAME = "bodytext";
export const CONTENT_TYPE = "text/html";

/**
 * The second family, beside the entitled one. A cache holding two families lets
 * a test tell per-family eviction from per-key eviction, and a render carrying
 * two makes a partial grant visible at all.
 */
export const FREE_ACCESS_GROUP = "free";

/**
 * The resourceId the spec's own examples use. `article()` derives one per label;
 * a file that builds its own render can take this one instead.
 */
export const RESOURCE_ID = "123456";

/**
 * The hour `AT` falls in and the hour after it, the two periods an hourly render
 * ships. They are spelled out rather than derived, so a test asserting them is
 * pinned to the label and not to the code that produced it.
 */
export const T_NOW = "251023T1400";
export const T_NEXT = "251023T1500";

/**
 * Five articles, enough for a story that reads one per period. Only their text
 * differs. A test checks that the plaintext that came out is the one that went
 * in, and that check needs them distinct and needs nothing else.
 */
export const ARTICLES = {
  A: "<p>The council voted 7-2 to rezone the harbour.</p>",
  B: "<p>The harbour plan goes to a second reading.</p>",
  C: "<p>Objections to the harbour plan close on Friday.</p>",
  D: "<p>The developer withdrew two of the towers.</p>",
  E: "<p>The harbour plan passed on a show of hands.</p>",
};

/**
 * Secret bytes for an optional-extension or legacy-refusal fixture, fresh each
 * call. `fill` distinguishes separate fixture values. Base publishers do not
 * accept or derive keys from this value.
 *
 * @param {number} [fill]
 * @returns {Uint8Array}
 */
export function periodSecret(fill = 7) {
  return new Uint8Array(32).fill(fill);
}

/** A publisher-retained input for the optional chain-key construction. */
export function keyDerivationSecret(fill = 7) {
  return new Uint8Array(32).fill(fill);
}

/**
 * One article as a `Publisher` renders it. It carries the bodytext most of the
 * suite is pinned to, and the resourceId is derived from the label so two labels
 * give two resources without a caller picking numbers.
 *
 * `items` are the extra items beside the bodytext. Each states its own name and
 * value, which is what tells them apart in an assertion. The rest is filled in:
 * `text/html`, and the free family rather than the entitled one. A caller asks
 * for a second item when a render has to cover more than one family, so reusing
 * the first item's family would answer nothing.
 *
 * @param {'A'|'B'|'C'|'D'|'E'} label
 * @param {object} [options]
 * @param {string} [options.resourceId]
 * @param {object} [options.data]
 * @param {{ name: string, value: string, contentType?: string, accessGroups?: string[] }[]} [options.items]
 * @returns {{ resourceId: string, data: object, items: { name: string, value: string, contentType: string, accessGroups: string[] }[] }}
 */
export function article(label, options = {}) {
  return {
    resourceId: options.resourceId ?? `12345${label.charCodeAt(0)}`,
    data: options.data ?? { section: "politics" },
    items: [
      {
        name: CONTENT_NAME,
        value: ARTICLES[label],
        contentType: CONTENT_TYPE,
        accessGroups: [ACCESS_GROUP],
      },
      ...(options.items ?? []).map((item) => ({
        contentType: CONTENT_TYPE,
        accessGroups: [FREE_ACCESS_GROUP],
        ...item,
      })),
    ],
  };
}

/**
 * The fixture article as a content-key-only publisher renders it: the
 * bodytext, and each extra item that states no groups of its own, names no
 * group, so each rides its item key alone. An extra item that names groups
 * keeps them, and a publisher with no period-key supply refuses it.
 *
 * @param {'A'|'B'|'C'|'D'|'E'} label
 * @param {Parameters<typeof article>[1]} [options]
 * @returns {ReturnType<typeof article>}
 */
export function ungroupedArticle(label, options = {}) {
  const built = article(label, {
    ...options,
    items: (options.items ?? []).map((item) => ({ accessGroups: [], ...item })),
  });
  const [bodytext, ...rest] = built.items;
  return { ...built, items: [{ ...bodytext, accessGroups: [] }, ...rest] };
}

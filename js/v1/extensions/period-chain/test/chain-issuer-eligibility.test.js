// @ts-check
//
// Which issuers each route reads a cached key under. The base exact route reads
// under the issuers the publisher sealed `periodKeys` for; the chain route reads
// under the issuers the publisher sealed `periodChainKeys` for. The two lists are
// separate because an issuer may hold one route and not the other, and an
// extension member never moves base key selection
// (docs/spec--data-format.md:284-289).
//
// A chain-only issuer under an issuer-keyed chain cache still opens its own
// retained grant (docs/spec--period-key-chains.md:961-968), and the exact cache
// never sees that issuer's name.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { keyByIssuer } from "../../../adapter-client/PeriodKeyCache.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { encrypt } from "../../../core-shared/aead.js";
import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { explicitPeriodChainClientProfile } from "../referenceProfile.js";

const PUB = "https://publisher.example";
const GROUP = "premium";
const CHAIN_ONLY = "chain_only_example";
const EXACT_ONLY = "exact_only_example";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-period-chain-v1.vectors.json", import.meta.url), "utf8"),
);
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.signature`;
}

/**
 * One render sealed under `premium` at the chain target coordinate, delivered by
 * two issuers: one carrying only the chain route and one carrying only the exact
 * route.
 *
 * @param {{ nonce: string, key: string }} wrap
 */
function page(wrap) {
  return {
    version: "1",
    resource: { origin: PUB, resourceId: "123456", renderId: "r-1" },
    resourceJWT: compactJwt({ origin: PUB, resourceId: "123456", renderId: "r-1" }),
    periodChain: GEOMETRY,
    issuerData: {
      [CHAIN_ONLY]: {
        keyId: "k1",
        unlockUrl: "https://chain.example/unlock",
        sealed: { periodChainKeys: { [GROUP]: { [TERMINAL_T]: "AAAA" } } },
      },
      [EXACT_ONLY]: {
        keyId: "k2",
        unlockUrl: "https://exact.example/unlock",
        sealed: { periodKeys: { [GROUP]: { [TARGET_T]: "AAAA" } } },
      },
    },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n",
        aad: "a",
        keys: { [GROUP]: [{ t: TARGET_T, ...wrap }] },
      },
    },
  };
}

/** The content key this render's one cached wrap opens to, under the chain leaf. */
async function wrappedUnderTheChainLeaf() {
  const contentKey = new Uint8Array(16).fill(7);
  const nonce = new Uint8Array(12).fill(4);
  const leaf = base64urlDecode(C1.leaf);
  return {
    contentKey,
    wrap: {
      nonce: base64urlEncode(nonce),
      key: base64urlEncode(await encrypt(leaf, nonce, contentKey)),
    },
  };
}

test("a chain-only issuer opens its own retained grant under an issuer-keyed chain cache", async () => {
  const { contentKey, wrap } = await wrappedUnderTheChainLeaf();
  const chainCache = new PeriodChainCache({ keyBy: keyByIssuer });
  await chainCache.put(GROUP, TERMINAL_T, base64urlDecode(C1.terminal), {
    publisher: PUB,
    issuerName: CHAIN_ONLY,
    ...GEOMETRY,
  });

  /** @type {string[][]} */
  const exactReads = [];
  const resolver = new ContentKeyResolver({
    cache: {
      put() {},
      candidatesAt(
        /** @type {string} */ _accessGroup,
        /** @type {string} */ _t,
        /** @type {any} */ context,
      ) {
        exactReads.push(context.issuerNames);
        return [];
      },
      attempted() {},
    },
    chainCache,
    periodChainProfile: explicitPeriodChainClientProfile,
  });

  assert.deepEqual(
    await resolver.contentKeyFor(new DcaData(page(wrap), { publisherOrigin: PUB }), "bodytext"),
    contentKey,
    "the chain route reads under the issuer the publisher sealed periodChainKeys for",
  );
  assert.deepEqual(
    exactReads,
    [[EXACT_ONLY]],
    "the exact cache is read under the periodKeys issuers alone",
  );
});

test("the exact route ignores an issuer whose only sealed map is the chain route", () => {
  const data = new DcaData(page({ nonce: "AAAA", key: "AAAA" }), { publisherOrigin: PUB });
  assert.deepEqual(data.issuerNamesFor(GROUP), [EXACT_ONLY]);
  assert.deepEqual(data.chainIssuerNamesFor(GROUP), [CHAIN_ONLY]);
});

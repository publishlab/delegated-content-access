// @ts-check
//
// A chain grant a response delivered stays private to that response until
// the resolver completes the response's attempt, and completion files it in
// the reusable store. A storage fault that ends the attempting operation
// still surfaces to the caller, and the grant is still filed: a later
// ordinary read opens the item without a second grant. Every resolver entry
// that takes an application ends the same way.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { encrypt } from "../../../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { Storage } from "../../../demo/actors/Storage.js";
import { contentKeyWrapNonceOctets } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-profile-chain-keys.vectors.json", import.meta.url), "utf8"),
);
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

const PUB = "https://publisher.example";
const GROUP = "premium";
const CHAIN = "chain_issuer";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const TERMINAL_T = "251023T2345";
const TARGET_T = "251023T1415";

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {unknown} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/** One chain-carrying render whose item "a" is wrapped under the C1 period key. */
async function render() {
  const renderId = "AAAAAAAAAAAAAAAAAAAAAA";
  const wrapNonce = contentKeyWrapNonceOctets({
    renderId,
    contentName: "a",
    accessGroup: GROUP,
    t: TARGET_T,
  });
  const resource = { origin: PUB, resourceId: "123456", renderId };
  return new DcaData(
    {
      version: "1",
      resource,
      resourceJWT: compactJwt(resource),
      periodGeometry: GEOMETRY,
      issuerData: [
        {
          issuerName: CHAIN,
          keyId: "k1",
          unlockUrl: "https://chain.example/unlock",
          sealed: { chainKeys: [{ accessGroup: GROUP, cutoff: TERMINAL_T, key: "AAAA" }] },
        },
      ],
      contentData: [
        {
          contentName: "a",
          contentType: "text/plain",
          nonce: base64urlEncode(new Uint8Array(12).fill(1)),
          keys: [
            {
              accessGroup: GROUP,
              period: TARGET_T,
              key: base64urlEncode(
                await encrypt(
                  base64urlDecode(C1.periodKey),
                  wrapNonce,
                  new Uint8Array(16).fill(20),
                ),
              ),
            },
          ],
        },
      ],
    },
    { publisherOrigin: PUB },
  );
}

/**
 * @type {Record<string, (resolver: ContentKeyResolver, data: DcaData, application: object) => Promise<unknown>>}
 */
const ENTRIES = {
  resolveDetailed: (resolver, data, application) =>
    resolver.resolveDetailed(data, ["a"], application),
  contentKeyFor: (resolver, data, application) => resolver.contentKeyFor(data, "a", application),
  resolveAuthenticated: (resolver, data, application) =>
    resolver.resolveAuthenticated(data, ["a"], async () => true, application),
};

for (const [name, entry] of Object.entries(ENTRIES)) {
  test(`${name} files the obtained chain grant although a storage fault ends it`, async () => {
    let failNext = false;
    const store = new Storage({
      gate: ({ op }) => {
        if (failNext && op === "keys") {
          failNext = false;
          throw Object.assign(new Error("transient storage fault"), { code: "storage_fault" });
        }
      },
    });
    const chainCache = new ChainKeyCache({ strategy: "retain" });
    const resolver = new ContentKeyResolver({
      cache: new PeriodKeyCache({ storage: store }),
      chainCache,
      chainKeyProfile: explicitChainKeyClientProfile,
    });
    const data = await render();
    const request = new ChainKeyRequestBuilder().build(data, CHAIN, ["a"]).toObject();
    const application = await resolver.applyResponse(
      data,
      CHAIN,
      {
        periodGeometry: GEOMETRY,
        keys: { chainKeys: [{ accessGroup: GROUP, cutoff: TERMINAL_T, key: C1.rootChainKey }] },
      },
      new ResponseAssociation(data, CHAIN, request),
    );
    assert.equal(application.accepted, 1);

    failNext = true;
    await assert.rejects(entry(resolver, data, application), { code: "storage_fault" });
    assert.equal(
      chainCache.entries().filter((held) => held.kind === "chain-key").length,
      1,
      "completion filed the grant in the reusable store",
    );
    const later = new ContentKeyResolver({
      cache: new PeriodKeyCache({ storage: store }),
      chainCache,
      chainKeyProfile: explicitChainKeyClientProfile,
    });
    assert.notEqual(
      await later.contentKeyFor(data, "a"),
      null,
      "a later ordinary read opens the item without a second grant",
    );
  });
}

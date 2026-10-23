// @ts-check
//
// Neutral client composition: the chain-key extension owns candidate production and
// omission owns the entry/AAD reading. Neither extension grows a second
// resolution loop.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../core-client/DcaData.js";
import { encrypt } from "../core-shared/aead.js";
import { base64urlEncode } from "../core-shared/codec.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { explicitChainKeyClientProfile } from "../extensions/chain-keys/referenceProfile.js";
import { omissionContentKeyResolverFactory } from "../extensions/content-key-seal-omission/core-client/BoundContentKeyResolver.js";
import {
  OMISSION_BIND_IDENTIFIER,
  omissionBindAad,
} from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";
import { contentKeyWrapNonceOctets } from "../test-reference/support/contentKeyWrapNonceOctets.js";

const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const GROUP = "premium";
const NAME = "bodytext";
const T = "251023T1415";
const TERMINAL_T = "251023T2345";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });

/** @param {string} renderId */
function resourceJwt(renderId) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode({ renderId })}.c2lnbmF0dXJl`;
}

test("omission AAD composes with the chain-key candidate source", async () => {
  const renderId = base64urlEncode(new Uint8Array(16).fill(1));
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: GEOMETRY,
  });
  const periodKey = await generation.periodKey(GROUP, T);
  const contentKey = new Uint8Array(16).fill(9);
  const aad = omissionBindAad({ renderId, contentName: NAME, accessGroup: GROUP, t: T });
  // The bound wrap's nonce transcript carries the same AAD it encrypts under.
  const nonce = contentKeyWrapNonceOctets({
    renderId,
    contentName: NAME,
    accessGroup: GROUP,
    t: T,
    aad,
  });
  const entry = {
    accessGroup: GROUP,
    period: T,
    key: base64urlEncode(await encrypt(periodKey, nonce, contentKey, aad)),
    bind: OMISSION_BIND_IDENTIFIER,
  };
  const terminal = await generation.chainCapability(GROUP, TERMINAL_T);
  const dcaData = new DcaData(
    {
      version: "1",
      resourceJWT: resourceJwt(renderId),
      periodGeometry: GEOMETRY,
      issuerData: [
        {
          issuerName: ISSUER,
          sealed: {
            chainKeys: [{ accessGroup: GROUP, cutoff: terminal.t, key: "carrier-a" }],
          },
        },
      ],
      contentData: [{ contentName: NAME, keys: [entry] }],
    },
    { publisherOrigin: PUB },
  );
  const chainCache = new ChainKeyCache();
  await chainCache.put(GROUP, terminal.t, terminal.key, {
    publisher: PUB,
    issuerName: ISSUER,
    ...GEOMETRY,
  });
  const resolver = omissionContentKeyResolverFactory({
    chainCache,
    chainKeyProfile: explicitChainKeyClientProfile,
  });

  const resolved = await resolver.contentKeyWithOriginFor(dcaData, NAME);
  assert.deepEqual(resolved.key, contentKey);
  assert.deepEqual(resolved.origin, {
    kind: "cached-chain-key",
    accessGroup: GROUP,
    t: T,
  });
});

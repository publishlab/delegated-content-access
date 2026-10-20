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
  const nonce = new Uint8Array(12).fill(4);
  const entry = {
    bind: OMISSION_BIND_IDENTIFIER,
    t: T,
    nonce: base64urlEncode(nonce),
    key: base64urlEncode(
      await encrypt(
        periodKey,
        nonce,
        contentKey,
        omissionBindAad({
          renderId,
          contentName: NAME,
          accessGroup: GROUP,
          t: T,
        }),
      ),
    ),
  };
  const terminal = await generation.chainCapability(GROUP, TERMINAL_T);
  const dcaData = new DcaData(
    {
      version: "1",
      resourceJWT: resourceJwt(renderId),
      periodGeometry: GEOMETRY,
      issuerData: {
        [ISSUER]: {
          sealed: {
            chainKeys: {
              [GROUP]: { [terminal.t]: "carrier-a" },
            },
          },
        },
      },
      contentData: { [NAME]: { keys: { [GROUP]: [entry] } } },
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

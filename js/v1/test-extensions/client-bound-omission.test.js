// @ts-check
//
// Neutral composition proof for two removable extensions: client-bound
// transport supplies the opaque exact-period handle, while omission supplies
// the one bound-entry interpretation. Neither extension imports its sibling.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { DcaData } from "../core-client/DcaData.js";
import { openContent } from "../core-client/openContent.js";
import { utf8Decode } from "../core-shared/codec.js";
import { Random } from "../demo/actors/Random.js";
import * as ecdhProfile from "../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { omissionContentKeyResolverFactory } from "../extensions/content-key-seal-omission/core-client/BoundContentKeyResolver.js";
import { EXTENSION_NAME } from "../extensions/content-key-seal-omission/core-shared/omissionBind.js";
import {
  ARTICLE,
  ISSUER_A,
  PUB,
  render,
  world,
} from "../extensions/content-key-seal-omission/test-lib/world.js";

const { subtle } = globalThis.crypto;

test("an omission-bound wrap opens through a client-bound exact-period handle without exporting either handle", async () => {
  const { issuerConfig, periodKeySupply, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items: ["bodytext"] },
  );
  const entry = page.contentData.bodytext.keys.premium[0];
  const periodBytes = await periodKeySupply.derive("premium", entry.t);

  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  const capability = clientBoundKeyCapability(
    {
      privateKey: pair.privateKey,
      publicKey: await subtle.exportKey("jwk", pair.publicKey),
    },
    ecdhProfile,
  );
  const transport = await ecdhProfile.seal(capability.publicKey, {
    random: new Random({ seed: 404 }),
  });
  const delivered = await transport.wrap(periodBytes);
  const opener = await capability.openDeliveredKeys({
    ...transport.transport,
    mode: "client-bound",
    method: ecdhProfile.METHOD,
  });
  const periodHandle = await opener.open(delivered, ["unwrapKey"]);
  assert.ok(periodHandle instanceof globalThis.CryptoKey);
  assert.equal(periodHandle.extractable, false);
  assert.deepEqual([...periodHandle.usages], ["unwrapKey"]);

  const cache = new PeriodKeyCache();
  await cache.put("premium", entry.t, periodHandle, { publisher: PUB });
  const resolver = omissionContentKeyResolverFactory({
    cache,
    clientBoundKeyCapability: capability,
  });
  const dcaData = new DcaData(page, { publisherOrigin: PUB });

  const originalExport = subtle.exportKey;
  let exportCalls = 0;
  subtle.exportKey = function (...args) {
    exportCalls++;
    return originalExport.apply(subtle, args);
  };
  /** @type {CryptoKey|null} */
  let contentHandle = null;
  try {
    const resolved = await resolver.contentKeyWithOriginFor(dcaData, "bodytext");
    contentHandle = /** @type {CryptoKey} */ (resolved.key);
    assert.deepEqual(resolved.origin, {
      kind: "cached-period-key",
      accessGroup: "premium",
      t: entry.t,
    });
    assert.ok(
      contentHandle instanceof globalThis.CryptoKey,
      "the bound attempt preserves the handle chain",
    );
    assert.equal(contentHandle.extractable, false);
    assert.deepEqual([...contentHandle.usages], ["decrypt"]);

    const record = page.contentData.bodytext;
    assert.equal(
      utf8Decode(
        await openContent(
          contentHandle,
          "bodytext",
          record.nonce,
          page.sealedContent.bodytext,
          record.aad,
        ),
      ),
      ARTICLE,
    );
  } finally {
    subtle.exportKey = originalExport;
  }

  assert.equal(exportCalls, 0, "the successful resolve and decrypt path exports neither handle");
  await assert.rejects(() => subtle.exportKey("raw", periodHandle));
  await assert.rejects(() => subtle.exportKey("raw", /** @type {CryptoKey} */ (contentHandle)));
});

// @ts-check
//
// The local half of the same binding. The client rebuilds the inner binding
// from the page's own unsigned renderId, so a period key filed by one unlock
// opens the bound entries of the next article without asking anyone.

import test from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { openContent } from "../../../core-client/openContent.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { decodePayload, sign } from "../../../core-shared--publisher-issuer/jwt.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import {
  BoundContentKeyResolver,
  omissionContentKeyResolverFactory,
} from "../core-client/BoundContentKeyResolver.js";
import { omissionEntryInterpretation } from "../core-client/omissionEntryInterpretation.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import {
  EXTENSION_NAME,
  OMISSION_BIND_VERSION,
  omissionBindValue,
} from "../core-shared/omissionBind.js";
import {
  ARTICLE,
  ISSUER_A,
  ISSUER_B,
  NOTE,
  PUB,
  SIGNING_KID,
  render,
  world,
} from "../test-lib/world.js";

const { subtle } = globalThis.crypto;

test("the omission interpretation owns only its marker and preserves ordinary siblings", () => {
  const context = {
    renderId: "render",
    contentName: "bodytext",
    accessGroup: "premium",
  };
  assert.deepEqual(omissionEntryInterpretation({ ...context, entry: {} }), { aad: undefined });
  assert.equal(
    omissionEntryInterpretation({ ...context, entry: { bind: "another-binding" } }),
    null,
    "an unknown marker is declined, never guessed to be ordinary",
  );
});

test("only the bound resolver opens a mixed render from a primed exact-key cache", async () => {
  const { issuerConfig, periodKeySupply, sealerConfig, signingKeys } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] }), issuerConfig(ISSUER_B)],
      }),
    ),
    { items: ["bodytext"] },
  );

  // One active issuer makes the shared contentData entry bound. The inactive
  // issuer still receives its ordinary direct content-key seal, which proves
  // this is the mixed compatibility shape rather than an all-active render.
  const entry = page.contentData.bodytext.keys.premium[0];
  assert.equal(entry.bind, OMISSION_BIND_VERSION);
  assert.equal(Object.hasOwn(page.issuerData[ISSUER_A].sealed, "contentKeys"), false);
  assert.equal(typeof page.issuerData[ISSUER_B].sealed.contentKeys.bodytext, "string");

  // Prime only the exact period coordinate. No issuer response, and in
  // particular no direct content-key answer, is applied to either resolver.
  const cache = new PeriodKeyCache();
  await cache.put("premium", entry.t, await periodKeySupply.derive("premium", entry.t), {
    publisher: PUB,
  });
  const dcaData = new DcaData(page, { publisherOrigin: PUB });

  const base = new ContentKeyResolver({ cache });
  assert.equal(
    await base.contentKeyFor(dcaData, "bodytext"),
    null,
    "base has no inner binding AAD, so the bound cache entry is an ordinary miss",
  );

  const bound = new BoundContentKeyResolver({ cache });
  assert.deepEqual(await bound.resolveDetailed(dcaData, ["bodytext"]), {
    covered: ["bodytext"],
    missing: [],
    origins: [
      {
        contentName: "bodytext",
        origin: { kind: "cached-period-key", accessGroup: "premium", t: entry.t },
      },
    ],
  });
  const contentKey = await bound.contentKeyFor(dcaData, "bodytext");
  assert.ok(contentKey, "the bound resolver rebuilds the binding and opens the same cached entry");
  assert.deepEqual(await bound.resolve(dcaData, ["bodytext"]), {
    covered: ["bodytext"],
    missing: [],
  });
  assert.deepEqual((await bound.contentKeyWithOriginFor(dcaData, "bodytext")).origin, {
    kind: "held-content-key",
  });

  const wrongBytes = base64urlDecode(/** @type {string} */ (dcaData.renderId));
  wrongBytes[0] ^= 1;
  const wrong = structuredClone(page);
  wrong.resourceJWT = await sign(
    { ...decodePayload(page.resourceJWT), renderId: base64urlEncode(wrongBytes) },
    signingKeys.privateKey,
    { kid: SIGNING_KID },
  );
  const originalDecrypt = subtle.decrypt;
  let decrypts = 0;
  subtle.decrypt = function (...args) {
    decrypts++;
    return originalDecrypt.apply(subtle, args);
  };
  try {
    assert.deepEqual(
      await bound.resolve(new DcaData(wrong, { publisherOrigin: PUB }), ["bodytext"]),
      { covered: [], missing: ["bodytext"] },
      "a well-formed local renderId mismatch is a cache miss, not a client refusal",
    );
  } finally {
    subtle.decrypt = originalDecrypt;
  }
  assert.equal(
    decrypts,
    1,
    "only the coordinate holding a cached key is attempted, and never retried without AAD",
  );

  for (const [label, mutate] of /** @type {[string, (candidate: any) => void][]} */ ([
    [
      "removed marker",
      (candidate) => {
        delete candidate.bind;
      },
    ],
    [
      "unknown marker",
      (candidate) => {
        candidate.bind = "another-binding";
      },
    ],
    [
      "changed period coordinate",
      (candidate) => {
        candidate.t = "251023T00";
      },
    ],
  ])) {
    const changed = structuredClone(page);
    mutate(changed.contentData.bodytext.keys.premium[0]);
    const changedResolver = new BoundContentKeyResolver({ cache });
    assert.deepEqual(
      await changedResolver.resolve(new DcaData(changed, { publisherOrigin: PUB }), ["bodytext"]),
      { covered: [], missing: ["bodytext"] },
      `${label} never opens through an unbound fallback`,
    );
  }

  const record = page.contentData.bodytext;
  assert.equal(
    utf8Decode(
      await openContent(
        contentKey,
        "bodytext",
        record.nonce,
        page.sealedContent.bodytext,
        record.aad,
      ),
    ),
    ARTICLE,
  );
});

test("a period key filed from one unlock opens the next article bound entry locally", async () => {
  const { issuerConfig, registration, sealerConfig } = await world();
  /** @param {string} resourceId @param {number} seed @param {string[]} items */
  const one = (resourceId, seed, items) =>
    render(
      new OmittingSealer(
        sealerConfig({
          seed,
          issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
        }),
      ),
      { resourceId, items },
    );

  const first = await one("123456", 1, ["bodytext"]);
  const second = await one("123457", 2, ["note"]);

  const cache = new PeriodKeyCache();
  const resolver = omissionContentKeyResolverFactory({ cache });

  // One unlock on the first render, answered with the period capability the
  // cached route returns.
  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(first, { publisherOrigin: PUB }),
    ISSUER_A,
    ["bodytext"],
  );
  const engine = omissionIssuerEngine({ accessPolicy: new AllowAllPolicy() });
  const result = await engine.unlock(request, registration);
  assert.ok(Object.keys(result.periodKeys.premium).length > 0, "the cached route was selected");

  const firstPage = new DcaData(first, { publisherOrigin: PUB });
  const application = await resolver.applyResponse(
    firstPage,
    ISSUER_A,
    { keys: result },
    new ResponseAssociation(firstPage, ISSUER_A, request),
  );
  await resolver.resolve(firstPage, ["bodytext"], application);

  // The second render is opened with nothing but what the cache holds.
  const page = new DcaData(second, { publisherOrigin: PUB });
  const contentKey = await resolver.contentKeyFor(page, "note");
  assert.ok(contentKey, "the cached period key opens the bound entry of a later render");

  const record = second.contentData.note;
  const plaintext = await openContent(
    contentKey,
    "note",
    record.nonce,
    second.sealedContent.note,
    record.aad,
  );
  assert.equal(utf8Decode(plaintext), NOTE);
});

test("the client and the issuer build the same binding string for one coordinate", async () => {
  const { issuerConfig, registration, sealerConfig } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
  );

  const entry = page.contentData.bodytext.keys.premium[0];
  const clientSide = omissionBindValue({
    renderId: new DcaData(page, { publisherOrigin: PUB }).renderId,
    contentName: "bodytext",
    accessGroup: "premium",
    t: entry.t,
  });
  const issuerSide = omissionBindValue({
    renderId: page.resource.renderId,
    contentName: "bodytext",
    accessGroup: "premium",
    t: entry.t,
  });

  assert.equal(clientSide, issuerSide);
  assert.equal(clientSide.startsWith("dca-seal-omission-bind-v1|"), true);

  // And the key that came out of it opens the article.
  const cache = new PeriodKeyCache();
  const resolver = new BoundContentKeyResolver({ cache });
  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    ["bodytext"],
  );
  const engine = omissionIssuerEngine({ accessPolicy: new AllowAllPolicy() });
  const result = await engine.unlock(request, registration);
  const clientPage = new DcaData(page, { publisherOrigin: PUB });
  const application = await resolver.applyResponse(
    clientPage,
    ISSUER_A,
    { keys: result },
    new ResponseAssociation(clientPage, ISSUER_A, request),
  );
  await resolver.resolve(clientPage, ["bodytext"], application);

  const record = page.contentData.bodytext;
  const contentKey = await resolver.contentKeyFor(
    new DcaData(page, { publisherOrigin: PUB }),
    "bodytext",
  );
  assert.ok(contentKey);
  assert.equal(
    utf8Decode(
      await openContent(
        contentKey,
        "bodytext",
        record.nonce,
        page.sealedContent.bodytext,
        record.aad,
      ),
    ),
    ARTICLE,
  );
});

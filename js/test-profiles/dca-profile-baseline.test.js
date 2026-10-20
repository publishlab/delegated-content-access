// @ts-check
//
// One complete baseline composition over the serialized JSON document. A real
// Sealer seals one content-key-only item to an ECDH issuer, and
// `writeJsonDelivery` turns the render into the UTF-8 octets of the data
// format's Section 6 document. Only a fresh copy of those octets crosses to the
// client side. There a `JsonDeliveryReader` reads them, `DcaData` admits the
// result, the composed client builds the request and records its association,
// the request travels to the issuer as a JSON document, and the client admits
// the issuer's answer against that association and opens the item to the
// original plaintext.
//
// Requested: dca-profile-baseline.
// Resolved: dca-profile-baseline.
//
// No HTML parser and no markup module is loaded: not `MarkupDeliveryReader`,
// `writeMarkupDelivery`, `domOver`, `queryableRoot`, `parse5`, the demo
// `ObjectDeliveryReader` or the harness `Client`. The last test walks this
// file's static imports and pins that. Period-key, compression, browser-origin
// and client-bound behavior is absent: the publisher holds no period-key
// supply, the issuer selects no period-key input, and the client relays none.
//
// Focused suites own the detail: each writer and reader refusal
// (test-reference/adapter-publisher/json-writer.test.js,
// test-reference/adapter-client/json-delivery-reader.test.js), partial results
// and denied siblings (test-reference/core-publisher/sealer-content-key-only.test.js),
// and the selected HTML form (dca-profile-html-carrier.test.js).

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The publisher and the issuer.
import { Sealer } from "../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerKeypair, signingKeypair } from "../test-reference/support/keys.js";

// The client: shippable client-role modules only.
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { createDeliveryClient } from "../integration-client/createDeliveryClient.js";
import { utf8Decode } from "../core-shared/codec.js";
import { refuses } from "../test-lib/helpers/refuses.js";

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const UNLOCK_URL = "https://api.example.com/unlock";
const AT = "2025-10-23T14:20:00Z";
const CONTENT_NAME = "bodytext";
// Non-ASCII text, so the item crosses as multi-octet UTF-8 inside the sealed
// bytes and the document crosses as UTF-8 around them.
const ARTICLE = "<p>Bystyret stemte 7–2 for å regulere havna.</p>";

/** @typedef {(requestDocument: string) => Promise<{ status: number, body: any }>} Unlock */

/**
 * One publisher and one issuer that share nothing but the issuer's public key
 * and the publisher's registration. The publisher seals one content-key-only
 * item and hands back the document's bytes; `deliver` decides which of the
 * render's ciphertexts the document carries.
 *
 * @param {{ deliver?: (sealedContent: Record<string, string>) => Record<string, string> }} [options]
 * @returns {Promise<{ bytes: Uint8Array, unlock: Unlock }>}
 */
async function world({ deliver = (sealedContent) => sealedContent } = {}) {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(CONTENT_NAME, ARTICLE, "text/html");
  const { dcaData, sealedContent } = await sealer.seal();
  const bytes = writeJsonDelivery({ dcaData, sealedContent: deliver(sealedContent) });

  const keyStore = {
    /** @param {string} issuerName @param {string} keyId */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);
  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], accessPolicy: new AllowAllPolicy() }),
    { periodKeyInput: false },
  );
  const endpoint = new UnlockEndpoint(processor);

  return {
    bytes,
    async unlock(requestDocument) {
      const { status, body } = await unlockThroughAdmission(
        processor,
        endpoint,
        requestDocument,
        registration,
      );
      // The answer crosses back as a JSON document too.
      return { status, body: JSON.parse(JSON.stringify(body)) };
    },
  };
}

/**
 * The client side of the walk. It receives the document's octets and the
 * origin its host fetched them from, and nothing else of the render.
 *
 * @param {Uint8Array} bytes
 * @param {Unlock} unlock
 */
async function clientOver(bytes, unlock) {
  const reader = new JsonDeliveryReader(bytes, { publisherOrigin: PUB });
  let request = null;
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader,
    issuerName: ISSUER_NAME,
    transport: {
      async post(url, body) {
        assert.equal(url, UNLOCK_URL);
        request = body;
        const answer = await unlock(JSON.stringify(body));
        return { ...answer, contentType: "application/json" };
      },
    },
  });
  const answer = await client.unlock([CONTENT_NAME]);
  return {
    reader,
    request,
    answer,
    application: answer.application,
    contentKey: () => client.resolver.contentKeyFor(client.dcaData, CONTENT_NAME),
    open: async () => utf8Decode((await client.open(CONTENT_NAME)).bytes),
  };
}

test(
  "the serialized JSON document opens to the original item through the real issuer",
  {
    tags: [
      "envelope/ecdh-p256/publisher",
      "envelope/ecdh-p256/issuer",
      "dca-profile-baseline/publisher/content-key-envelope",
      "dca-profile-baseline/publisher/json-delivery",
      "dca-profile-baseline/issuer/direct-result",
      "dca-profile-baseline/client/direct-admission",
      "dca-profile-baseline/client/json-delivery",
    ],
  },
  async () => {
    const { bytes, unlock } = await world();
    const document = JSON.parse(utf8Decode(bytes));
    assert.ok(Object.hasOwn(document, "contentData"), "one enclosing object: the dca-data members");
    assert.deepEqual(Object.keys(document.sealedContent), [CONTENT_NAME], "and sealedContent");
    assert.equal(document.contentData[CONTENT_NAME].keys, undefined, "no period-key route");

    const client = await clientOver(new Uint8Array(bytes), unlock);

    assert.deepEqual(Object.keys(client.request.sealed), ["contentKeys"], "no period keys relayed");
    assert.equal(client.answer.status, 200, "the issuer answered");
    assert.deepEqual(Object.keys(client.answer.body.keys), ["contentKeys"], "an item content key");
    assert.equal(client.application?.accepted, 1, "admitted against the recorded association");
    assert.deepEqual(client.application?.issues, []);
    assert.equal(await client.open(), ARTICLE, "the original plaintext");
  },
);

test(
  "a document without the item's ciphertext parses and gets its key, yet the item does not open",
  { tags: ["dca-profile-baseline/client/json-delivery"] },
  async () => {
    // Missing ciphertext is not a usable publication of that item: the format
    // defines no retrieval, so nothing on this side can supply it.
    const { bytes, unlock } = await world({ deliver: () => ({}) });

    const client = await clientOver(new Uint8Array(bytes), unlock);

    assert.equal(client.answer.status, 200);
    assert.equal(client.application?.accepted, 1);
    assert.ok(await client.contentKey(), "the client holds the item's content key");
    assert.equal(client.reader.extract(CONTENT_NAME), null, "and no ciphertext for it");
    await refuses(() => client.open(), "bad_page", "no ciphertext opens to no plaintext");
  },
);

test("the JSON entry opens a missing item and returns its content identity with the bytes", async () => {
  const { bytes, unlock } = await world();
  let calls = 0;
  const parsedReader = new JsonDeliveryReader(bytes, { publisherOrigin: PUB });
  const reader = {
    dcaData: parsedReader.dcaData,
    publisherOrigin: PUB,
    extract: (/** @type {string} */ name) => parsedReader.extract(name),
  };
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader,
    issuerName: ISSUER_NAME,
    transport: {
      async post(_url, request, context) {
        calls++;
        assert.equal(context.origin, PUB, "the captured delivery origin reaches transport");
        return { ...(await unlock(JSON.stringify(request))), contentType: "application/json" };
      },
    },
  });
  reader.publisherOrigin = "https://other.example";
  reader.dcaData.contentData[CONTENT_NAME].contentType = "text/plain";
  reader.extract = () => null;
  const first = await client.open(CONTENT_NAME);
  assert.equal(first.contentName, CONTENT_NAME);
  assert.equal(first.contentType, "text/html");
  assert.equal(utf8Decode(first.bytes), ARTICLE);
  assert.equal(utf8Decode((await client.open(CONTENT_NAME)).bytes), ARTICLE);
  assert.equal(calls, 1, "the held item key avoids a second unlock");
});

test("independent routes survive denial or silence after an ineligible conditional route", async () => {
  const { bytes, unlock } = await world();
  for (const first of ["denied", "silent"]) {
    const routes = [
      { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryOperational: false },
      { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, independent: false },
      { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, independent: true },
    ];
    let calls = 0;
    const client = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: new JsonDeliveryReader(bytes, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post(_url, request) {
          calls++;
          if (calls === 1) routes[2].independent = false;
          if (calls === 1 && first === "denied") return { status: 403, body: null };
          const answer = await unlock(JSON.stringify(request));
          if (calls === 1) answer.body.keys = {};
          return { ...answer, contentType: "application/json" };
        },
      },
    });
    const result = await client.unlockRoutes([CONTENT_NAME], routes);
    assert.equal(calls, 2, `${first}: captured independent route survived a later config mutation`);
    assert.deepEqual(
      result.attempts.map((entry) => entry.status),
      [first === "denied" ? 403 : 200, 200],
    );
    assert.deepEqual(result.missing, []);
    assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
  }
});

test("operational fallback runs only when its trusted route selects it", async () => {
  const { bytes } = await world();
  for (const retryOperational of [false, true]) {
    let calls = 0;
    const client = createDeliveryClient({
      unlockUrl: UNLOCK_URL,
      reader: new JsonDeliveryReader(bytes, { publisherOrigin: PUB }),
      issuerName: ISSUER_NAME,
      transport: {
        async post() {
          calls++;
          return { status: 503, body: null };
        },
      },
    });
    const result = await client.unlockRoutes(
      [CONTENT_NAME],
      [
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryOperational },
        { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
      ],
    );
    assert.equal(calls, retryOperational ? 2 : 1);
    assert.deepEqual(result.missing, [CONTENT_NAME]);
  }
});

test("an item-only operational retry still presents that item coordinate", async () => {
  const { bytes, unlock } = await world();
  const sent = [];
  const client = createDeliveryClient({
    unlockUrl: UNLOCK_URL,
    reader: new JsonDeliveryReader(bytes, { publisherOrigin: PUB }),
    issuerName: ISSUER_NAME,
    transport: {
      async post(_url, request) {
        sent.push(request);
        if (sent.length === 1) return { status: 503, body: null };
        return { ...(await unlock(JSON.stringify(request))), contentType: "application/json" };
      },
    },
  });
  const result = await client.unlockRoutes(
    [CONTENT_NAME],
    [
      { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL, retryOperational: true },
      { issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL },
    ],
  );
  assert.equal(sent.length, 2);
  assert.deepEqual(Object.keys(sent[1].sealed.contentKeys), [CONTENT_NAME]);
  assert.deepEqual(result.missing, []);
  assert.equal(utf8Decode((await client.openLocal(CONTENT_NAME)).bytes), ARTICLE);
});

test("this file loads no HTML parser and no markup module", () => {
  // A static walk over the import and re-export statements of this file and
  // of every relative module they name. The pattern names every module the
  // header rules out, matched on paths below `js`; a hit is a module this
  // scenario said it does not load.
  const FORBIDDEN =
    /markup|domOver|queryableRoot|parse5|ObjectDeliveryReader|test-lib\/harnesses\/client\.js/i;
  const IMPORT =
    /^\s*(?:import|export)\b[^;]*?\bfrom\s*["']([^"']+)["']|^\s*import\s*["']([^"']+)["']/gm;
  const start = fileURLToPath(import.meta.url);
  const v1 = resolve(dirname(start), "..");
  const seen = new Set([start]);
  const queue = [start];
  /** @type {string[]} */
  const bare = [];
  while (queue.length > 0) {
    const file = /** @type {string} */ (queue.pop());
    for (const [, from, bareImport] of readFileSync(file, "utf8").matchAll(IMPORT)) {
      const specifier = from ?? bareImport;
      if (!specifier.startsWith(".")) {
        bare.push(specifier);
        continue;
      }
      const target = resolve(dirname(file), specifier);
      if (!seen.has(target)) {
        seen.add(target);
        queue.push(target);
      }
    }
  }

  assert.ok(seen.size > 20, "the walk reached the publisher, issuer and client modules");
  assert.ok(
    [...seen].some((file) => relative(v1, file) === "adapter-client/JsonDeliveryReader.js"),
    "and the JSON reader among them",
  );
  assert.deepEqual(
    [...[...seen].map((file) => relative(v1, file)), ...bare].filter((path) =>
      FORBIDDEN.test(path),
    ),
    [],
    "no markup or HTML-parsing module in this file's import closure",
  );
});

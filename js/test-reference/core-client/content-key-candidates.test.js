// @ts-check
//
// Several `keys.contentKeys` records for one item are candidate keys (core
// Section 7, data format Section 2.3): the client keeps each distinct one and
// tries them under its bound, so a wrong-but-admissible record cannot hide a
// working sibling, whatever the wire order.

import test from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../core-client/DcaData.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { ContentRepresentationOpener } from "../../core-client/ContentRepresentationOpener.js";
import { createDeliveryClient } from "../../integration-client/createDeliveryClient.js";
import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { contentAadOctets } from "../support/contentAadOctets.js";

const ISSUER = "issuer_example";

/** @param {number} fill */
const bytes = (fill) => new Uint8Array(16).fill(fill);
/** @param {number} fill */
const key = (fill) => base64urlEncode(bytes(fill));

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

function deliveredPage() {
  return new DcaData(
    {
      version: "1",
      resourceJWT: compactJwt({ origin: "https://signed.example", renderId: "r-1" }),
      issuerData: [
        {
          issuerName: ISSUER,
          keyId: "k1",
          unlockUrl: "https://issuer.example/unlock",
          sealed: {},
        },
      ],
      contentData: [{ contentName: "bodytext", contentType: "text/html", nonce: "n", aad: "a" }],
    },
    { publisherOrigin: "https://publisher.example" },
  );
}

/** @param {DcaData} page */
function association(page) {
  return new ResponseAssociation(page, ISSUER, {
    version: page.version,
    issuerName: ISSUER,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(ISSUER),
    sealed: { contentKeys: [{ contentName: "bodytext", key: "AA" }] },
  });
}

/**
 * Apply one response carrying `fills` as bodytext candidates, in that order.
 * @param {number[]} fills
 */
async function applied(fills) {
  const page = deliveredPage();
  const resolver = new ContentKeyResolver();
  const application = await resolver.applyResponse(
    page,
    ISSUER,
    { keys: { contentKeys: fills.map((fill) => ({ contentName: "bodytext", key: key(fill) })) } },
    association(page),
  );
  return { page, resolver, application };
}

/** A predicate that opens the item only under the key filled with `fill`. */
const opensWith = (/** @type {number} */ fill) => async (/** @type {any} */ candidate) =>
  candidate instanceof Uint8Array && candidate.every((byte) => byte === fill);

test("a wrong-but-admissible candidate does not hide its working sibling, in either order", async () => {
  for (const fills of [
    [1, 2],
    [2, 1],
  ]) {
    const { page, resolver, application } = await applied(fills);
    assert.equal(application.accepted, 2, String(fills));
    assert.deepEqual(
      await resolver.contentKeyForAuthenticatedItem(page, "bodytext", opensWith(2)),
      bytes(2),
      String(fills),
    );
  }
});

test("the plain lookup keeps answering with the newest candidate", async () => {
  const { page, resolver } = await applied([1, 2]);
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), bytes(2));
});

test("an identical candidate is one candidate", async () => {
  const { page, resolver } = await applied([3, 3]);
  /** @type {Uint8Array[]} */
  const tried = [];
  const found = await resolver.contentKeyForAuthenticatedItem(
    page,
    "bodytext",
    async (candidate) => {
      tried.push(/** @type {Uint8Array} */ (candidate));
      return false;
    },
  );
  assert.equal(found, null);
  assert.deepEqual(tried, [bytes(3)]);
});

test("a working candidate behind four wrong ones still opens", async () => {
  // No held-candidate cap of its own: the response's raw record count already
  // bounds what one application can hold, so no failed candidate pushes a
  // working one out.
  const { page, resolver } = await applied([5, 1, 2, 3, 4]);
  /** @type {number[]} */
  const tried = [];
  const found = await resolver.contentKeyForAuthenticatedItem(
    page,
    "bodytext",
    async (candidate) => {
      tried.push(/** @type {Uint8Array} */ (candidate)[0]);
      return /** @type {Uint8Array} */ (candidate)[0] === 5;
    },
  );
  assert.deepEqual(found, bytes(5));
  assert.deepEqual(tried, [4, 3, 2, 1, 5], "newest first, down to the oldest");
});

test("an authenticated pick moves to the newest place, so the plain lookup answers with it", async () => {
  const { page, resolver } = await applied([2, 1]);
  await resolver.contentKeyForAuthenticatedItem(page, "bodytext", opensWith(2));
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), bytes(2));
});

// The openers below see a real sealed item: the article opens only under the
// key filled with 2, and the response lists that key first, so the wrong key
// filled with 1 is the newest candidate the resolver holds.
const ARTICLE = "The council voted 7-2 to rezone the harbour.";
const PUBLISHER = "https://publisher.example";

/** A delivery whose bodytext is sealed under the key filled with 2. */
async function sealedDelivery() {
  const json = {
    version: "1",
    resourceJWT: compactJwt({ origin: PUBLISHER, renderId: base64urlEncode(bytes(7)) }),
    issuerData: [
      {
        issuerName: ISSUER,
        keyId: "k1",
        sealed: { contentKeys: [{ contentName: "bodytext", key: "AA" }] },
      },
    ],
    contentData: [{ contentName: "bodytext", contentType: "text/plain" }],
  };
  const ciphertext = base64urlEncode(
    await encrypt(
      bytes(2),
      new Uint8Array(12),
      utf8Encode(ARTICLE),
      contentAadOctets(json, "bodytext"),
    ),
  );
  return { json, ciphertext };
}

/** @param {any} resolver @param {DcaData} page */
async function applyWrongNewest(resolver, page) {
  const application = await resolver.applyResponse(
    page,
    ISSUER,
    {
      keys: {
        contentKeys: [
          { contentName: "bodytext", key: key(2) },
          { contentName: "bodytext", key: key(1) },
        ],
      },
    },
    association(page),
  );
  assert.equal(application.accepted, 2);
}

test("the representation opener decodes with the candidate that authenticated", async () => {
  const { json, ciphertext } = await sealedDelivery();
  const page = new DcaData(json, { publisherOrigin: PUBLISHER });
  const resolver = new ContentKeyResolver();
  await applyWrongNewest(resolver, page);
  const item = /** @type {any} */ (page.contentItemFor("bodytext"));

  const opened = await new ContentRepresentationOpener().open({
    item,
    ciphertext,
    resolveKey: (authenticate) =>
      resolver.contentKeyForAuthenticatedItem(page, "bodytext", authenticate),
  });
  assert.equal(utf8Decode(opened), ARTICLE);
});

test("openLocal opens through a wrong newest candidate", async () => {
  const { json, ciphertext } = await sealedDelivery();
  const client = createDeliveryClient({
    reader: { dcaData: json, publisherOrigin: PUBLISHER, extract: () => ciphertext },
    issuerName: ISSUER,
    transport: {
      async post() {
        throw new Error("openLocal never posts");
      },
    },
  });
  await applyWrongNewest(client.resolver, client.dcaData);

  const opened = await client.openLocal("bodytext");
  assert.equal(utf8Decode(opened.bytes), ARTICLE);
});

// A failed candidate that the issuer delivered, or that a publisher wrap
// unwrapped from cached period or chain material, is a wrong key: the item
// fails `decrypt_failed`, as the plain lookup's answer would. A recovery
// source's derived guess that does not open is only a miss: `no_key`. The
// resolver names each candidate's origin to the predicate.
test("the resolver names a held candidate to the predicate", async () => {
  const { page, resolver } = await applied([1]);
  /** @type {unknown[]} */
  const origins = [];
  await resolver.contentKeyForAuthenticatedItem(page, "bodytext", async (_candidate, origin) => {
    origins.push(origin);
    return false;
  });
  assert.deepEqual(origins, [{ kind: "held-content-key" }]);
});

test("an open fails decrypt_failed only when a delivered or unwrapped key failed", async () => {
  const { json, ciphertext } = await sealedDelivery();
  const page = new DcaData(json, { publisherOrigin: PUBLISHER });
  const item = /** @type {any} */ (page.contentItemFor("bodytext"));
  const opener = new ContentRepresentationOpener();

  await assert.rejects(
    opener.open({
      item,
      ciphertext,
      resolveKey: async (authenticate) => {
        await authenticate(bytes(1), { kind: "held-content-key" });
        return null;
      },
    }),
    { code: "decrypt_failed" },
  );
  await assert.rejects(
    opener.open({
      item,
      ciphertext,
      resolveKey: async (authenticate) => {
        await authenticate(bytes(1), { kind: "cached-period-key" });
        return null;
      },
    }),
    { code: "decrypt_failed" },
    "a key a publisher wrap unwrapped is the item's key, so it is a wrong one",
  );
  await assert.rejects(
    opener.open({
      item,
      ciphertext,
      resolveKey: async (authenticate) => {
        await authenticate(bytes(1), { kind: "recovered-content-key" });
        await authenticate(bytes(3));
        return null;
      },
    }),
    { code: "no_key" },
    "a recovered guess, or a candidate of no named origin, that does not open is a miss",
  );
});

test("openLocal fails decrypt_failed when its only held key is wrong", async () => {
  const { json, ciphertext } = await sealedDelivery();
  const client = createDeliveryClient({
    reader: { dcaData: json, publisherOrigin: PUBLISHER, extract: () => ciphertext },
    issuerName: ISSUER,
    transport: {
      async post() {
        throw new Error("openLocal never posts");
      },
    },
  });
  await client.resolver.applyResponse(
    client.dcaData,
    ISSUER,
    { keys: { contentKeys: [{ contentName: "bodytext", key: key(1) }] } },
    association(client.dcaData),
  );
  await assert.rejects(client.openLocal("bodytext"), { code: "decrypt_failed" });
});

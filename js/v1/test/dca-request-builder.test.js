// @ts-check
//
// What the client asks one issuer for. `DcaRequestBuilder` owns the selection,
// so the assertions below pin its members, order and omissions directly.
// The client composition's `buildRequest` forwards to `DcaRequestBuilder`
// unchanged; the comparisons against it prove the composition adds no selection
// of its own, not that a second implementation independently agrees.
//
// The selection itself is where a mistake would be quiet. Sending too little
// costs a reader an article; sending an accessGroup the item is not wrapped
// under, or a period family the issuer never sealed, asks an issuer to decide
// on coordinates the page did not carry.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { subtle } from "node:crypto";

import { DcaData } from "../core-client/DcaData.js";
import { DcaRequestBuilder } from "../core-client/DcaRequestBuilder.js";
import { Client } from "../test-lib/harnesses/client.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { CONTENT_NAME, ISSUER_NAME, KEY_ID } from "../demo/scenarios/fixtures.js";

const OTHER = "other_example";
const UNLOCK_URL = "https://issuer.example/unlock";

/** One client's pair, in the shape a browser holds it. */
async function clientKeys() {
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"])
  );
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
}

/**
 * A page written out rather than rendered, so one item can sit in two groups
 * and a second issuer can hold a family the first does not.
 */
function pageData() {
  return {
    version: "1",
    resource: { origin: "https://news.example", resourceId: "123456", renderId: "r-1" },
    resourceJWT: "header.payload.signature",
    issuerData: {
      [ISSUER_NAME]: {
        keyId: KEY_ID,
        unlockUrl: UNLOCK_URL,
        sealed: {
          contentKeys: { bodytext: "bodytext-blob", premium: "premium-blob" },
          periodKeys: {
            article: { "251023T14": "a-14", "251023T15": "a-15" },
            vault: { "251023T15": "v-15" },
          },
          periodChainKeys: {
            article: { "251023T23": "ac-23", "251024T11": "ac-next-11" },
            vault: { "251023T23": "vc-23" },
          },
        },
      },
      [OTHER]: {
        keyId: "k9",
        unlockUrl: "https://other.example/unlock",
        sealed: { contentKeys: { bodytext: "other-blob" } },
      },
    },
    contentData: {
      bodytext: {
        contentType: "text/html",
        nonce: "n1",
        aad: "123456|1|bodytext",
        keys: {
          article: [{ t: "251023T14", nonce: "w-n1", key: "w1" }],
          vault: [{ t: "251023T15", nonce: "w-n2", key: "w2" }],
        },
      },
      premium: {
        contentType: "text/html",
        nonce: "n3",
        aad: "123456|1|premium",
        keys: { vault: [{ t: "251023T15", nonce: "w-n3", key: "w3" }] },
      },
    },
  };
}

/** Build one request through the component that owns the selection. */
function build(data, issuerName, needed, keys) {
  return new DcaRequestBuilder({
    relayExactPeriod: true,
    ...(keys ? { clientPublicKey: keys.publicKey } : {}),
  })
    .build(new DcaData(data), issuerName, needed)
    .toObject();
}

/**
 * The temporary compatibility entry, kept separate so it is not an oracle. The
 * delivery origin comes from the caller: this entry composes a client, and a
 * client is built where its page was delivered.
 */
function delegate(publisherOrigin, data, issuerName, needed, keys) {
  return new Client(
    keys
      ? {
          publisherOrigin,
          relayExactPeriod: true,
          clientBoundKeyCapability: { publicKey: keys.publicKey, openDeliveredKeys() {} },
        }
      : { publisherOrigin, relayExactPeriod: true },
  ).buildRequest(data, issuerName, needed);
}

describe("What the client asks one issuer for", () => {
  test("exact material is relayed only when the client selects it", () => {
    const page = new DcaData(pageData());

    const baseline = new DcaRequestBuilder().build(page, ISSUER_NAME, ["bodytext"]).toObject();
    assert.equal(Object.hasOwn(baseline.sealed, "periodKeys"), false);
    assert.deepEqual(Object.keys(baseline.sealed.contentKeys), ["bodytext"]);

    const exact = new DcaRequestBuilder({ relayExactPeriod: true })
      .build(page, ISSUER_NAME, ["bodytext"])
      .toObject();
    assert.deepEqual(Object.keys(exact.sealed.periodKeys), ["article", "vault"]);

    assert.throws(
      () => new DcaRequestBuilder(/** @type {any} */ ({ relayExactPeriod: "yes" })),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("only the requested contentNames are copied", () => {
    const built = build(pageData(), ISSUER_NAME, ["bodytext"]);

    assert.deepEqual(Object.keys(built.sealed.contentKeys), ["bodytext"]);
    assert.equal(built.sealed.contentKeys.bodytext, "bodytext-blob");

    // A name the page does not seal for this issuer carries no member,
    // rather than a member holding undefined.
    const missing = build(pageData(), ISSUER_NAME, ["no-such-item"]);
    assert.deepEqual(missing.sealed.contentKeys, {});
  });

  test("every accessGroup a requested item is wrapped under is included", () => {
    // Membership is OR: the bodytext sits in two families and a key from
    // either opens it, so both go and the issuer decides which it grants.
    const built = build(pageData(), ISSUER_NAME, ["bodytext"]);

    assert.deepEqual(Object.keys(built.sealed.periodKeys), ["article", "vault"]);

    // One item in one family asks for one family.
    const one = build(pageData(), ISSUER_NAME, ["premium"]);
    assert.deepEqual(Object.keys(one.sealed.periodKeys), ["vault"]);
  });

  test("the whole exact t map for an included group is copied, while extension carriers are not", () => {
    // The whole map goes: the client cannot tell which period the article it
    // reads next was rendered in, and the overlap key covers the boundary.
    const built = build(pageData(), ISSUER_NAME, ["bodytext"]);

    assert.deepEqual(built.sealed.periodKeys.article, { "251023T14": "a-14", "251023T15": "a-15" });
    assert.equal(Object.hasOwn(built.sealed, "periodChainKeys"), false);
    assert.equal(Object.hasOwn(built, "periodChain"), false);

    // Copied, not aliased: the request can be mutated on its way to the
    // wire without the page changing under the next build.
    const data = pageData();
    const request = new DcaRequestBuilder({ relayExactPeriod: true })
      .build(new DcaData(data), ISSUER_NAME, ["bodytext"])
      .toObject();
    request.sealed.periodKeys.article["251023T14"] = "tampered";
    assert.equal(data.issuerData[ISSUER_NAME].sealed.periodKeys.article["251023T14"], "a-14");
  });

  test("lexically invalid exact labels are not relayed and valid siblings remain", () => {
    const data = pageData();
    data.issuerData[ISSUER_NAME].sealed.periodKeys.article = {
      "251023T14": "hour",
      "251023T1415": "quarter",
      "251023T14ZZ|junk": "delimited",
      notadate: "text",
    };

    const built = build(data, ISSUER_NAME, ["bodytext"]);

    assert.deepEqual(built.sealed.periodKeys.article, {
      "251023T14": "hour",
      "251023T1415": "quarter",
    });
    assert.deepEqual(built.sealed.periodKeys.vault, { "251023T15": "v-15" });
  });

  test("a group this issuer sealed no family for carries no member", () => {
    // The page wraps the bodytext under two families; this issuer holds
    // neither. Asking it about a coordinate it never sealed would be the
    // client inventing the question.
    const built = build(pageData(), OTHER, ["bodytext"]);

    assert.equal(
      Object.hasOwn(built.sealed, "periodKeys"),
      false,
      "an empty periodKeys is no periodKeys",
    );
    assert.equal(built.sealed.contentKeys.bodytext, "other-blob");
    assert.equal(built.keyId, "k9");
  });

  test("a malformed selected block is unknown_issuer and the sibling issuer still builds", () => {
    // The format derives a request only from a block that is a non-array
    // object with a `sealed` container and string `unlockUrl` and `keyId`.
    // A page carrying one that is not asks that issuer nothing, and the
    // sibling block beside it builds its own request as it always did.
    const builder = new DcaRequestBuilder();

    for (const block of [
      [],
      "a string",
      { keyId: KEY_ID, unlockUrl: UNLOCK_URL },
      { keyId: null, unlockUrl: UNLOCK_URL, sealed: {} },
      { keyId: KEY_ID, unlockUrl: 17, sealed: {} },
      { keyId: KEY_ID, unlockUrl: UNLOCK_URL, sealed: [] },
    ]) {
      const data = pageData();
      data.issuerData[ISSUER_NAME] = /** @type {any} */ (block);
      const label = JSON.stringify(block);

      assert.throws(
        () => builder.build(new DcaData(data), ISSUER_NAME, ["bodytext"]),
        (/** @type {any} */ e) => e.code === "unknown_issuer",
        label,
      );
      assert.equal(
        build(data, OTHER, ["bodytext"]).sealed.contentKeys.bodytext,
        "other-blob",
        label,
      );
    }
  });

  test("no name the grammar refuses reaches the request", () => {
    // The maps are admitted by the view, so what the builder relays is what
    // the format admits: a rejected route map carries no member, a rejected
    // cached-wrap map selects no accessGroup, and a name the caller asks
    // about that no admitted map carries is simply absent.
    const rejectedRouteMap = pageData();
    rejectedRouteMap.issuerData[ISSUER_NAME].sealed.contentKeys = /** @type {any} */ ({
      "2bad": "blob",
      bodytext: "bodytext-blob",
    });
    const withoutRoutes = build(rejectedRouteMap, ISSUER_NAME, ["bodytext"]);
    assert.deepEqual(withoutRoutes.sealed.contentKeys, {}, "the rejected map carries no member");

    const rejectedWraps = pageData();
    rejectedWraps.contentData.bodytext.keys = /** @type {any} */ ({
      "bad|group": [{ t: "251023T14", nonce: "w-n1", key: "w1" }],
    });
    const withoutGroups = build(rejectedWraps, ISSUER_NAME, ["bodytext"]);
    assert.equal(
      Object.hasOwn(withoutGroups.sealed, "periodKeys"),
      false,
      "and selects no accessGroup",
    );
    assert.equal(
      withoutGroups.sealed.contentKeys.bodytext,
      "bodytext-blob",
      "while the item still asks",
    );

    // A name the caller hands in that the grammar refuses finds nothing in
    // an admitted map, so it carries no member either.
    const asked = build(pageData(), ISSUER_NAME, ["bad|name", "__proto__", "bodytext"]);
    assert.deepEqual(Object.keys(asked.sealed.contentKeys), ["bodytext"]);
  });

  test("the client key is offered when the client has one, and never otherwise", async () => {
    const keys = await clientKeys();

    const offered = build(pageData(), ISSUER_NAME, ["bodytext"], keys);
    assert.deepEqual(offered.clientPublicKey, keys.publicKey);

    const silent = build(pageData(), ISSUER_NAME, ["bodytext"]);
    assert.equal(Object.hasOwn(silent, "clientPublicKey"), false);
  });

  test("an issuer the page does not carry is unknown_issuer, as before", () => {
    const builder = new DcaRequestBuilder();
    const withoutIssuer = { ...pageData(), issuerData: { [ISSUER_NAME]: null } };

    for (const data of [pageData(), withoutIssuer]) {
      assert.throws(
        () => builder.build(new DcaData(data), "nobody.example", ["bodytext"]),
        (/** @type {any} */ e) => e.code === "unknown_issuer",
      );
    }

    assert.throws(
      () => builder.build(new DcaData(withoutIssuer), ISSUER_NAME, ["bodytext"]),
      (/** @type {any} */ e) => e.code === "unknown_issuer",
    );

    // A delivery the outer admission refuses is a bad page before it is a
    // question about one issuer.
    assert.throws(
      () => builder.build(new DcaData({}), ISSUER_NAME, ["bodytext"]),
      (/** @type {any} */ e) => e.code === "bad_page",
    );
  });

  test("a page is a DcaData, and an option this builder has no meaning for is refused", () => {
    assert.throws(
      () =>
        new DcaRequestBuilder().build(/** @type {any} */ (pageData()), ISSUER_NAME, ["bodytext"]),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => new DcaRequestBuilder(/** @type {any} */ ({ clientKeys: {} })),
      (/** @type {any} */ e) => e.code === "unsupported_option",
    );
  });

  test("the item inventory is never forwarded, and nothing in it reaches the issuer", () => {
    const built = build(pageData(), ISSUER_NAME, ["bodytext"]);

    assert.deepEqual(Object.keys(built), [
      "version",
      "issuerName",
      "resourceJWT",
      "keyId",
      "sealed",
    ]);
    assert.equal(Object.hasOwn(built, "contentData"), false);
    assert.equal(
      JSON.stringify(built).includes("contentType"),
      false,
      "nor anything out of a record",
    );

    // The inventory is unsigned page data. It selects which coordinates are
    // asked about and supplies no authority over them, so moving every
    // member a builder could be tempted by - including a member invented to
    // look like a grant - leaves the request it built identical.
    const edited = pageData();
    edited.contentData.bodytext.contentType = "application/json";
    edited.contentData.bodytext.aad = "anything|1|else";
    /** @type {any} */ (edited.contentData.bodytext).grant = "article";
    edited.contentData.bodytext.keys.article[0].key = "moved";
    edited.contentData.bodytext.keys.article[0].t = "251023T23";

    assert.equal(
      JSON.stringify(build(edited, ISSUER_NAME, ["bodytext"])),
      JSON.stringify(built),
      "the same request, whatever the page wrote beside the coordinates",
    );

    // It does select with the item's own group membership: an item in one
    // family asks about one family, and the second item's record does not
    // join the first item's request.
    assert.deepEqual(Object.keys(build(pageData(), ISSUER_NAME, ["premium"]).sealed.periodKeys), [
      "vault",
    ]);
  });

  test("the optional readable resource mirror does not participate in the request", () => {
    const withMirror = pageData();
    const withoutMirror = /** @type {any} */ (pageData());
    delete withoutMirror.resource;

    assert.deepEqual(
      build(withoutMirror, ISSUER_NAME, ["bodytext"]),
      build(withMirror, ISSUER_NAME, ["bodytext"]),
    );
  });

  test("the temporary buildRequest delegate returns the builder document unchanged", async () => {
    const { render } = await actorWorld();
    const rendered = await render("A");
    const origin = rendered.publisherOrigin;
    const parsed = new Client({ publisherOrigin: origin }).parse(rendered.asJson());
    const keys = await clientKeys();

    for (const needed of [[CONTENT_NAME], [], [CONTENT_NAME, "no-such-item"]]) {
      assert.equal(
        JSON.stringify(build(parsed, ISSUER_NAME, needed)),
        JSON.stringify(delegate(origin, parsed, ISSUER_NAME, needed)),
        `needed: ${JSON.stringify(needed)}`,
      );
    }

    assert.equal(
      JSON.stringify(build(parsed, ISSUER_NAME, [CONTENT_NAME], keys)),
      JSON.stringify(delegate(origin, parsed, ISSUER_NAME, [CONTENT_NAME], keys)),
      "and with a client key offered",
    );
    assert.throws(
      () =>
        delegate(origin, { ...pageData(), issuerData: { [ISSUER_NAME]: null } }, ISSUER_NAME, [
          "bodytext",
        ]),
      (/** @type {any} */ e) => e.code === "unknown_issuer",
    );
  });
});

//
// The core wire, at the places where a policy about the format decides
// something a key or a tag then acts on. Nothing here is a new mechanism; each
// test pins a rule the format states and the demo has to be shown obeying.
// Each group below says at its head which rule it is.
//
// This file does without two things, and says so rather than faking them.
// There is no DOM here, so "markup extraction" means the two artefacts
// `Sealer` already returns - `dcaData` and `sealedContent` as separate objects,
// which is exactly the format's two-element page split. The `querySelector`
// that finds them in a browser is the browser adapter's, outside the crypto.
// The issuer application selects one publisher registration by the unverified
// JWT header kid; core rechecks that exact kid and verifies the token before it
// trusts the payload. The publisher signs the exact delivery origin in the
// token, so this file has no domain-folding seam to simulate.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { decrypt, encrypt, NONCE_BYTES } from "../core-shared/aead.js";
import { base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from "../core-shared/codec.js";
import { own } from "../core-shared/wire.js";
import { ARTICLES, ISSUER_NAME } from "../demo/scenarios/fixtures.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import {
  BODYTEXT,
  PREMIUMTEXT,
  PUB,
  RESOURCE_ID,
  T_NEXT,
  T_NOW,
  world,
} from "../test-lib/fixtures/wire-policy-world.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { wrapNonceOf } from "../test-reference/support/contentKeyWrapNonceOctets.js";
import {
  contentNamesOn,
  contentRecordOf,
  issuerBlockOf,
  sealedContentByName,
  sealedContentOf,
  wrapGroupsOn,
  wrapsOf,
} from "../test-lib/helpers/inspect.js";
import { keyAt } from "../test-reference/support/namedRecords.js";

/**
 * What a JSON hop does to one object. `wire()` is the whole render; this is the
 * halves of it, which the markup delivery ships as two artefacts, and the seal
 * data a test holds on to before the page it came from is edited.
 *
 * @template T
 * @param {T} value
 * @returns {T}
 */
function hop(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * The contentKey an issuer hands back for one item, as bytes. The content-key route,
 * used here as the reference every other delivery of the same key is compared
 * against.
 *
 * @param {any} w - the world
 * @param {any} page
 * @param {string} contentName
 * @returns {Promise<Uint8Array>}
 */
async function contentKeyFor(w, page, contentName) {
  const { processor, endpoint, publisherRegistration } = w.endpointWith();
  const { status, body } = await unlockThroughAdmission(
    processor,
    endpoint,
    requestFor(page, ISSUER_NAME, [contentName]),
    publisherRegistration,
  );

  assert.equal(
    status,
    200,
    "the reference unlock has to succeed, or the comparison below means nothing",
  );
  return base64urlDecode(keyAt(body.keys.contentKeys, { contentName }));
}

describe("the content AAD is derived, never carried", () => {
  // The client rebuilds content AAD from the JWT renderId and item name. A carried `aad` member selects nothing, so an item
  // sealed under the former carried string does not open even when the record
  // carries that exact string beside it.

  test("an item sealed under its derived AAD opens; one sealed under a carried string does not", async () => {
    const w = await world();
    const { page } = await w.render();
    const contentKey = await contentKeyFor(w, page, "bodytext");
    const nonce = new Uint8Array(NONCE_BYTES);
    const former = [RESOURCE_ID, "1", "bodytext"].join("|");

    const unsealer = new Client({ publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);
    unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    await unsealer.applyResponse(dcaData, ISSUER_NAME, {
      keys: { contentKeys: [{ contentName: "bodytext", key: base64urlEncode(contentKey) }] },
    });

    /** @param {Uint8Array} aad */
    const resealed = async (aad) => {
      const copy = structuredClone(page);
      const at = copy.contentData.findIndex(
        (/** @type {any} */ record) => record.contentName === "bodytext",
      );
      copy.contentData[at] = {
        contentName: "bodytext",
        contentType: "text/html",
        nonce: base64urlEncode(nonce),
        aad: former,
      };
      const sealed = copy.sealedContent.find(
        (/** @type {any} */ record) => record.contentName === "bodytext",
      );
      sealed.content = base64urlEncode(
        await encrypt(contentKey, nonce, utf8Encode(ARTICLES.A), aad),
      );
      return copy;
    };

    const derived = await resealed(contentAadOctets(page, "bodytext"));
    const opened = await unsealer.decrypt(
      unsealer.parse(derived),
      "bodytext",
      unsealer.extract(derived, "bodytext"),
    );
    assert.equal(
      utf8Decode(opened),
      ARTICLES.A,
      "the derived transcript opens, carried aad ignored",
    );

    // Pinned to the tag rather than to "it threw": `decrypt_failed` is what
    // the client reports when GCM refuses, so a missing record or key cannot
    // pass for this control. No retry under the carried string happens.
    const carried = await resealed(utf8Encode(former));
    await assert.rejects(
      () =>
        unsealer.decrypt(
          unsealer.parse(carried),
          "bodytext",
          unsealer.extract(carried, "bodytext"),
        ),
      (/** @type {any} */ err) => err.code === "decrypt_failed",
      "the former carried transcript does not authenticate",
    );
  });
});

describe("one contentKey, two accessGroups", () => {
  // One contentKey wrapped under two accessGroups comes back byte-identical
  // from either entry - the many-to-many a pure salt derivation would remove.

  test("one contentKey wrapped under two accessGroups unwraps to identical bytes from either entry", async () => {
    const w = await world();
    const { page } = await w.render({
      items: [{ ...BODYTEXT, accessGroups: ["subscriber", "premium"] }],
    });

    assert.deepEqual(
      wrapGroupsOn(page, "bodytext"),
      ["subscriber", "premium"],
      "sealed entries under each group the item names",
    );

    // The two envelopes are different objects on the wire - a different
    // periodKey, and a nonce derived from a different accessGroup - which is
    // what makes the byte-equality below a claim about the key material rather
    // than about the bytes on the page.
    const subscriberEntry = wrapsOf(page, "bodytext", "subscriber").find(
      (/** @type {any} */ e) => e.period === T_NOW,
    );
    const premiumEntry = wrapsOf(page, "bodytext", "premium").find(
      (/** @type {any} */ e) => e.period === T_NOW,
    );
    assert.notEqual(subscriberEntry.key, premiumEntry.key);
    const subscriberNonce = wrapNonceOf(page, "bodytext", "subscriber", T_NOW);
    const premiumNonce = wrapNonceOf(page, "bodytext", "premium", T_NOW);
    assert.notDeepEqual(subscriberNonce, premiumNonce);

    const fromSubscriber = await decrypt(
      await w.periodKeySupply.derive("subscriber", T_NOW),
      subscriberNonce,
      base64urlDecode(subscriberEntry.key),
    );
    const fromPremium = await decrypt(
      await w.periodKeySupply.derive("premium", T_NOW),
      premiumNonce,
      base64urlDecode(premiumEntry.key),
    );

    assert.deepEqual(fromSubscriber, fromPremium, "one contentKey, delivered twice");
    assert.equal(fromSubscriber.length, 16);

    // And the same key again down the third delivery, the issuer's content-key route.
    // Three routes to one item, one set of bytes - the many-to-many a pure
    // salt-derived contentKey would collapse.
    assert.deepEqual(fromSubscriber, await contentKeyFor(w, page, "bodytext"));

    // The key is the same, so either route opens the article.
    for (const key of [fromSubscriber, fromPremium]) {
      const opened = await decrypt(
        key,
        new Uint8Array(12),
        base64urlDecode(sealedContentOf(page, "bodytext")),
        contentAadOctets(page, "bodytext"),
      );
      assert.equal(utf8Decode(opened), ARTICLES.A);
    }
  });
});

describe("deferred content", () => {
  // Deferred content - keys on the page with no ciphertext beside them - is
  // not an error, and the ciphertext fetched later opens under the same
  // contentKey, nonce and content AAD.

  test("deferred content is keys with no ciphertext, and the fetched bytes open under the same key, nonce and AAD", async () => {
    const w = await world();
    const { page } = await w.render({ items: [BODYTEXT, PREMIUMTEXT] });

    // The publisher ships both items' keys and only one item's ciphertext. The
    // other arrives later from a URL, and the page as delivered is the page
    // below.
    const recordAsShipped = hop(contentRecordOf(page, "premiumtext"));
    const fetchedLater = sealedContentOf(page, "premiumtext");
    page.sealedContent = page.sealedContent.filter(
      (/** @type {any} */ record) => record.contentName !== "premiumtext",
    );

    const cache = new PeriodKeyCache();
    const unsealer = new Client({ cache, publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);

    const { processor, endpoint, publisherRegistration } = w.endpointWith();
    const { body } = await unlockThroughAdmission(
      processor,
      endpoint,
      unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext", "premiumtext"]),
      publisherRegistration,
    );
    await unsealer.applyResponse(dcaData, ISSUER_NAME, body);

    // A client walking the page finds a record for a name with no element.
    // That is not an error, and nothing here throws.
    const names = contentNamesOn(dcaData);
    assert.deepEqual(names, ["bodytext", "premiumtext"]);
    assert.equal(unsealer.extract(page, "premiumtext"), null, "no element for it yet");
    assert.equal(typeof unsealer.extract(page, "bodytext"), "string");

    const { covered } = await unsealer.resolve(dcaData, names);
    assert.deepEqual(covered, names, "the key material is on the page either way");

    // The item on the page opens now.
    assert.equal(
      utf8Decode(await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"))),
      ARTICLES.A,
    );

    // The deferred one has nothing to decrypt yet, and that is a typed miss
    // rather than a crash or a wrong plaintext.
    await assert.rejects(
      () => unsealer.decrypt(dcaData, "premiumtext", unsealer.extract(page, "premiumtext")),
      (/** @type {any} */ err) => err.code === "unknown_content",
    );

    // The fetch lands. Nothing about the record was re-negotiated - it is
    // the object the page shipped - and the contentKey is the one the page's
    // own keys already resolved to.
    assert.deepEqual(contentRecordOf(dcaData, "premiumtext"), recordAsShipped);
    assert.deepEqual(
      await unsealer.contentKeyFor(dcaData, "premiumtext"),
      await contentKeyFor(w, page, "premiumtext"),
      "the deferred item keeps the key the render sealed for it",
    );

    const opened = await unsealer.decrypt(dcaData, "premiumtext", fetchedLater);
    assert.equal(utf8Decode(opened), ARTICLES.D);

    // A moved deferred item carries its wraps, but their nonces derive from the
    // item name, so under the changed name they open no key.
    const misfiled = {
      ...dcaData,
      contentData: [
        ...dcaData.contentData,
        { ...recordAsShipped, contentName: "premiumtext-other" },
      ],
    };
    await assert.rejects(
      () => unsealer.decrypt(misfiled, "premiumtext-other", fetchedLater),
      (/** @type {any} */ err) => err.code === "no_key",
      "the moved wraps open nothing under another name",
    );
    // The tag again, and not merely a rejection: the key is the one that just
    // worked, so only the AAD moved, and GCM is what says no.
    await assert.rejects(
      decrypt(
        await contentKeyFor(w, page, "premiumtext"),
        new Uint8Array(NONCE_BYTES),
        base64urlDecode(fetchedLater),
        contentAadOctets(page, "premiumtext-other"),
      ),
      "the fetched ciphertext is pinned to its own AAD, not just to some AAD",
    );

    // A carried nonce is unknown metadata and cannot retune this procedure.
    const retuned = {
      ...dcaData,
      contentData: [
        ...dcaData.contentData.filter(
          (/** @type {any} */ record) => record.contentName !== "premiumtext",
        ),
        { ...recordAsShipped, nonce: { malformed: true } },
      ],
    };
    assert.equal(
      utf8Decode(await unsealer.decrypt(retuned, "premiumtext", fetchedLater)),
      ARTICLES.D,
    );
  });
});

describe("one record per content item", () => {
  // `contentData[contentName]` is the client's whole inventory for one item:
  // the handling data it was encrypted under, and the wrapped contentKey
  // candidates under `keys` when the render offers a cached path. Both
  // delivery routes read that one record, and a render with no cached path
  // carries the record without `keys`.

  /**
   * A cache holding one family's key for the render's own period, filed under
   * the publisher the page was delivered from.
   *
   * @param {any} w - the world
   * @param {string} accessGroup
   * @returns {Promise<PeriodKeyCache>}
   */
  async function cacheHolding(w, accessGroup) {
    const cache = new PeriodKeyCache();
    await cache.put(accessGroup, T_NOW, await w.periodKeySupply.derive(accessGroup, T_NOW), {
      publisher: PUB,
    });
    return cache;
  }

  test("a cached periodKey opens the item through the record it sits in", async () => {
    const w = await world();
    const { page } = await w.render();

    const record = contentRecordOf(page, "bodytext");
    assert.deepEqual(
      Object.keys(record),
      ["contentName", "contentType", "keys"],
      "one record, in wire order",
    );
    assert.deepEqual(wrapGroupsOn(page, "bodytext"), ["premium"]);
    assert.deepEqual(
      wrapsOf(page, "bodytext", "premium").map((/** @type {any} */ e) => e.period),
      [T_NOW, T_NEXT],
    );

    const unsealer = new Client({ cache: await cacheHolding(w, "premium"), publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);

    assert.deepEqual(
      await unsealer.resolve(dcaData, ["bodytext"]),
      { covered: ["bodytext"], missing: [] },
      "the cached key unwraps a candidate out of the record",
    );
    assert.equal(
      utf8Decode(await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"))),
      ARTICLES.A,
    );
  });

  test("a content-key grant opens an item whose record also carries wrapped keys", async () => {
    // The issuer chooses which key kind it delivers, and the item does not fix
    // that choice: the page offers the cached path here, and the contentKey
    // opens the same record.
    const w = await world();
    const { page } = await w.render();
    assert.ok(contentRecordOf(page, "bodytext").keys, "the page does carry the cached path");

    const unsealer = new Client({ publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);
    unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    await unsealer.applyResponse(dcaData, ISSUER_NAME, {
      keys: {
        contentKeys: [
          {
            contentName: "bodytext",
            key: base64urlEncode(await contentKeyFor(w, page, "bodytext")),
          },
        ],
      },
    });

    assert.equal(
      utf8Decode(await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"))),
      ARTICLES.A,
    );
  });

  test("a content-key-only render carries the record without keys, and the grant opens it", async () => {
    const w = await world();
    const { page } = await w.render({ periodKeySupply: null });

    const record = contentRecordOf(page, "bodytext");
    assert.deepEqual(
      Object.keys(record),
      ["contentName", "contentType"],
      "no cached path, no keys member",
    );
    assert.equal(
      Object.hasOwn(issuerBlockOf(page, ISSUER_NAME).sealed, "periodKeys"),
      false,
      "and nothing for the issuer to grant a family with",
    );

    const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);
    unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    await unsealer.applyResponse(dcaData, ISSUER_NAME, {
      keys: {
        contentKeys: [
          {
            contentName: "bodytext",
            key: base64urlEncode(await contentKeyFor(w, page, "bodytext")),
          },
        ],
      },
    });

    assert.equal(
      utf8Decode(await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"))),
      ARTICLES.A,
    );
  });

  test("two accessGroups on one record are alternatives, and either cached family opens it", async () => {
    const w = await world();
    const { page } = await w.render({
      items: [{ ...BODYTEXT, accessGroups: ["subscriber", "premium"] }],
    });

    assert.deepEqual(wrapGroupsOn(page, "bodytext"), ["subscriber", "premium"]);

    for (const accessGroup of ["subscriber", "premium"]) {
      const unsealer = new Client({
        cache: await cacheHolding(w, accessGroup),
        publisherOrigin: PUB,
      });
      const dcaData = unsealer.parse(page);

      assert.equal(
        utf8Decode(await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"))),
        ARTICLES.A,
        `${accessGroup} on its own opens the item`,
      );
    }
  });

  test("a malformed record is a bad page for its own item, and the item beside it opens", async () => {
    const w = await world();
    const { page } = await w.render({ items: [BODYTEXT, PREMIUMTEXT] });
    const unsealer = new Client({ cache: await cacheHolding(w, "premium"), publisherOrigin: PUB });

    // Neither malformed record below is the page declaring no such item, so
    // reporting `unknown_content` would say a name the page carries is one it
    // does not: each still names bodytext, and each lost or broke a member
    // the decrypt is built from.
    for (const malformed of [
      { contentName: "bodytext", nonce: "AA" },
      { contentName: "bodytext", contentType: 7 },
    ]) {
      const dcaData = unsealer.parse(hop(page));
      const at = dcaData.contentData.findIndex(
        (/** @type {any} */ record) => record.contentName === "bodytext",
      );
      dcaData.contentData[at] = malformed;

      await assert.rejects(
        () => unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext")),
        (/** @type {any} */ err) => err.code === "bad_page",
        `${JSON.stringify(malformed)} is a bad page`,
      );
      assert.equal(
        utf8Decode(
          await unsealer.decrypt(dcaData, "premiumtext", unsealer.extract(page, "premiumtext")),
        ),
        ARTICLES.D,
        "and the sibling is not suppressed by it",
      );
    }
  });

  test("an element that is no record names no item, and every named item still opens", async () => {
    // A non-record element carries no contentName, so it declares nothing:
    // the collection keeps its named records, and the element costs neither
    // item its route.
    const w = await world();
    const { page } = await w.render({ items: [BODYTEXT, PREMIUMTEXT] });
    for (const element of ["not a record", 7, null, ["bodytext"]]) {
      const unsealer = new Client({
        cache: await cacheHolding(w, "premium"),
        publisherOrigin: PUB,
      });
      const delivered = hop(page);
      delivered.contentData.splice(1, 0, element);
      const dcaData = unsealer.parse(delivered);
      assert.equal(
        utf8Decode(
          await unsealer.decrypt(dcaData, "premiumtext", unsealer.extract(page, "premiumtext")),
        ),
        ARTICLES.D,
        JSON.stringify(element),
      );
    }
  });
});

/**
 * The markup side of the split, as this suite can honestly model it: the sealed
 * ciphertext lives in its own artefact, looked up by contentName. Here that is
 * the Sealer's own contentName-to-ciphertext map; in a browser it is the
 * `{contentName, content}` records parsed out of the `dca-sealed-content`
 * script block. The DOM is the browser adapter's and the bytes it hands over
 * are these.
 *
 * @param {object} sealedContent
 * @param {string} contentName
 * @returns {string|null}
 */
function fromSealedContentElement(sealedContent, contentName) {
  const value = own(sealedContent, contentName);
  return typeof value === "string" ? value : null;
}

describe("the JSON API variant", () => {
  // The JSON API variant is told apart by `sealedContent` being present, and
  // reaches the same plaintext bytes through the same chain.

  test("the JSON API variant is discriminated by sealedContent alone", async () => {
    const w = await world();
    const { dcaData, sealedContent, page } = await w.render({ items: [BODYTEXT, PREMIUMTEXT] });

    // The one difference between the two deliveries. The markup's dca-data
    // carries no such member, so its presence is a sufficient discriminator -
    // there is no mode field, and no version bump.
    assert.equal(Object.hasOwn(page, "sealedContent"), true);
    assert.equal(Object.hasOwn(dcaData, "sealedContent"), false);

    // And it is the only difference: strip it and the two documents are the
    // same object, member order included. Only the delivery differs; the
    // format is the same.
    const unsealer = new Client({ publisherOrigin: PUB });
    assert.equal(JSON.stringify(unsealer.parse(page)), JSON.stringify(dcaData));

    // `parse` on the markup half is a no-op, so one object reaches the crypto
    // whichever delivery it came out of.
    assert.equal(JSON.stringify(unsealer.parse(dcaData)), JSON.stringify(dcaData));

    // Same names on both sides, and the ciphertext for each is one string.
    assert.deepEqual(Object.keys(sealedContent), Object.keys(sealedContentByName(page)));
    for (const contentName of Object.keys(sealedContent)) {
      assert.equal(
        fromSealedContentElement(sealedContent, contentName),
        unsealer.extract(page, contentName),
        `${contentName} is the same ciphertext on both deliveries`,
      );
    }
  });

  test("the JSON API variant decrypts to byte-identical plaintext through the same crypto chain", async () => {
    const w = await world();
    const { dcaData, sealedContent, page } = await w.render({ items: [BODYTEXT, PREMIUMTEXT] });

    /**
     * One client, one unlock, one chain - fed by whichever extraction the
     * delivery calls for.
     *
     * @param {object} data - the dca-data half
     * @param {(contentName: string) => string|null} extract
     */
    async function readAll(data, extract) {
      const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: PUB });
      const parsed = unsealer.parse(data);
      const names = contentNamesOn(parsed);

      const { processor, endpoint, publisherRegistration } = w.endpointWith();
      const { body } = await unlockThroughAdmission(
        processor,
        endpoint,
        unsealer.buildRequest(parsed, ISSUER_NAME, names),
        publisherRegistration,
      );
      await unsealer.applyResponse(parsed, ISSUER_NAME, body);

      /** @type {Record<string, Uint8Array>} */
      const opened = {};
      for (const contentName of names) {
        opened[contentName] = await unsealer.decrypt(parsed, contentName, extract(contentName));
      }
      return opened;
    }

    const jsonReader = new Client({ publisherOrigin: PUB });
    const fromMarkup = await readAll(dcaData, (name) =>
      fromSealedContentElement(sealedContent, name),
    );
    const fromJson = await readAll(page, (name) => jsonReader.extract(page, name));

    assert.deepEqual(fromMarkup, fromJson, "byte-identical plaintext, both deliveries");
    assert.equal(utf8Decode(fromJson.bodytext), ARTICLES.A);
    assert.equal(utf8Decode(fromJson.premiumtext), ARTICLES.D);
  });
});

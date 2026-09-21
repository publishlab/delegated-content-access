//
// Every map on the wire is keyed by a name an attacker picks: contentName,
// accessGroup, issuerName. A bare `map[name]` reaches Object.prototype, so
// 'constructor' or 'toString' resolves to a function instead of missing.
// Lookups over wire-derived objects go through Object.hasOwn.
//
// The map itself is the attacker's too. A section that arrives as a string or
// an array still has member names, so a walk that does not ask whether it is a
// map reads index names as coordinates - which is the last test here.
//
// The names the sealer refuses are the other half of the same question. The
// format's identifier section makes them the consumer's business: a map keyed
// by contentName, accessGroup or issuerName is rejected whole when one member
// name fails the grammar, rather than read past that member. For every name the
// grammar admits, inherited words among them, the consumer owes a lookup that
// resolves the name as written or stays inert, and no crash on either an
// inherited or an own hazard name.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { ContentRepresentationOpener } from "../core-client/ContentRepresentationOpener.js";
import { encrypt } from "../core-shared/aead.js";
import { base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import {
  CONTENT_NAME,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  UNLOCK_URL,
} from "../demo/scenarios/fixtures.js";
import { INHERITED } from "../test-lib/fixtures/inherited-names.js";
import { makeRenderId } from "../test-lib/fixtures/renderId.js";

/** A renderId to anchor on; the value is incidental. */
const RENDER_ID = makeRenderId(3);

/** @param {object} payload */
function unsignedJwt(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "ES256", kid: KEY_ID })}.${encode(payload)}.signature`;
}

/**
 * A page shaped like the wire, with nothing under any inherited name. Hand-built
 * rather than rendered: every test below asks what a member name resolves to,
 * which needs the map's names chosen here rather than by a publisher.
 */
function page() {
  return JSON.parse(
    JSON.stringify({
      version: "1",
      resource: {
        renderId: RENDER_ID,
        origin: ORIGIN,
        issuedAt: "2025-10-23T14:00:00.000Z",
        resourceId: RESOURCE_ID,
        data: {},
      },
      resourceJWT: unsignedJwt({
        renderId: RENDER_ID,
        origin: ORIGIN,
        issuedAt: "2025-10-23T14:00:00.000Z",
        resourceId: RESOURCE_ID,
        data: {},
      }),
      contentData: {
        [CONTENT_NAME]: {
          contentType: "text/html",
          nonce: "AAAAAAAAAAAAAAAA",
          aad: `${RESOURCE_ID}|1|${CONTENT_NAME}`,
        },
      },
      issuerData: {
        [ISSUER_NAME]: {
          sealed: { contentKeys: { [CONTENT_NAME]: "AAAA" } },
          unlockUrl: UNLOCK_URL,
          keyId: KEY_ID,
        },
      },
      sealedContent: { [CONTENT_NAME]: "AAAA" },
    }),
  );
}

test("an inherited issuerName is not a configured issuer", () => {
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page());

  for (const name of INHERITED) {
    assert.throws(
      () => unsealer.buildRequest(dcaData, name, [CONTENT_NAME]),
      (err) => err.code === "unknown_issuer",
      `issuerData['${name}'] must not resolve`,
    );
  }
});

test("an inherited version or resourceJWT is not what the request carries", () => {
  const unsealer = new Client({ publisherOrigin: ORIGIN });

  // `parse` drops inherited members on its way out, so a page that reached
  // this shape came in as an object rather than through the JSON hop. The
  // fields the issuer anchors on are still read own-property here: an absent
  // version or resource has to arrive absent, not as whatever a prototype
  // says, since the issuer's answer to an incomplete request is the issuer's.
  const planted = Object.create({ version: "99", resourceJWT: page().resourceJWT });
  planted.issuerData = page().issuerData;
  planted.contentData = page().contentData;

  // The outer admission reads the same own-property way, so a page whose
  // version and resourceJWT are only on the prototype is a page carrying
  // neither, and no request is derived from it.
  assert.throws(
    () => unsealer.buildRequest(planted, ISSUER_NAME, [CONTENT_NAME]),
    (/** @type {any} */ e) => e.code === "bad_page",
  );
});

test("an inherited contentName has no sealed key to send", () => {
  const wire = page();

  for (const name of INHERITED) {
    const unsealer = new Client({ publisherOrigin: ORIGIN });
    const dcaData = unsealer.parse(wire);
    const request = unsealer.buildRequest(dcaData, ISSUER_NAME, [name]);
    assert.deepEqual(
      request.sealed.contentKeys,
      {},
      `sealed.contentKeys['${name}'] must not resolve`,
    );
  }
});

test("an inherited contentName has no sealed content to extract", () => {
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const wire = page();

  for (const name of INHERITED) {
    assert.equal(unsealer.extract(wire, name), null, `sealedContent['${name}'] must not resolve`);
  }
});

test("an inherited contentName has no record to decrypt with", async () => {
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page());

  for (const name of INHERITED) {
    assert.equal(await unsealer.contentKeyFor(dcaData, name), null);
    await assert.rejects(
      () => unsealer.decrypt(dcaData, name, "AAAA"),
      (err) => err.code === "unknown_content",
      `contentData['${name}'] must not resolve`,
    );
  }
});

test("an inherited contentName in a response does not become a key", async () => {
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page());

  // A hostile issuer answering with prototype names must not plant anything.
  unsealer.buildRequest(dcaData, ISSUER_NAME, []);
  await unsealer.applyResponse(dcaData, ISSUER_NAME, { keys: { contentKeys: {} } });

  for (const name of INHERITED) {
    assert.equal(await unsealer.contentKeyFor(dcaData, name), null);
  }
});

test("resolve reports a held content key covered, not just what the cache opens", async () => {
  // No cache here: the only material this client can hold is a content-key
  // grant for the render. `resolve` answers which items the held and cached
  // material opens, so an item whose content key is in hand is covered - a
  // resolve that consulted the cache alone would call it missing and send a
  // second walk back for a key already held.
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page());

  assert.deepEqual(
    await unsealer.resolve(dcaData, [CONTENT_NAME]),
    { covered: [], missing: [CONTENT_NAME] },
    "nothing held and nothing cached: the item needs an unlock",
  );

  // A grant that delivered a content key for this render and no period key.
  unsealer.buildRequest(dcaData, ISSUER_NAME, [CONTENT_NAME]);
  await unsealer.applyResponse(dcaData, ISSUER_NAME, {
    keys: { contentKeys: { [CONTENT_NAME]: base64urlEncode(new Uint8Array(16).fill(4)) } },
  });

  assert.deepEqual(
    await unsealer.resolve(dcaData, [CONTENT_NAME]),
    { covered: [CONTENT_NAME], missing: [] },
    "the held content key covers the item",
  );
});

describe("The consumer accepts wide", () => {
  /**
   * A page whose names the grammar admits and no sealer of ours chose. It
   * arrives anyway: the client does not choose who serves it markup, and the
   * consumer resolves what the format admits as written.
   */
  function hostilePage() {
    return JSON.parse(
      JSON.stringify({
        version: "1",
        resource: {
          renderId: "AAAAAAAAAAAA",
          origin: ORIGIN,
          issuedAt: "2025-10-23T14:00:00.000Z",
          resourceId: "123|456",
          data: {},
        },
        resourceJWT: unsignedJwt({
          renderId: "AAAAAAAAAAAA",
          origin: ORIGIN,
          issuedAt: "2025-10-23T14:00:00.000Z",
          resourceId: "123|456",
          data: {},
        }),
        contentData: {
          two: {
            contentType: "text/html",
            nonce: "AAAAAAAAAAAAAAAA",
            aad: "x",
            keys: { ten: [{ t: "251023T14", nonce: "AAAAAAAAAAAAAAAA", key: "AAAA" }] },
          },
        },
        issuerData: {
          paywall: {
            sealed: {
              contentKeys: { two: "AAAA" },
              periodKeys: { ten: { "251023T14": "AAAA" } },
            },
            unlockUrl: UNLOCK_URL,
            keyId: KEY_ID,
          },
        },
        sealedContent: { two: "AAAA" },
      }),
    );
  }

  test("a name the grammar admits is data, not a validation error", async () => {
    const unsealer = new Client({ publisherOrigin: ORIGIN });
    const page = hostilePage();
    const dcaData = unsealer.parse(page);

    // Nothing here judges an admitted name: the page's own names resolve as
    // written, whoever chose them.
    assert.equal(unsealer.extract(page, "two"), "AAAA");

    // `issuerData` is keyed by issuerName, so the name the page filed under
    // is the key the client looks up under and sends on.
    const request = unsealer.buildRequest(dcaData, "paywall", ["two"]);
    assert.equal(request.issuerName, "paywall");
    assert.deepEqual(request.sealed.contentKeys, { two: "AAAA" });
    assert.deepEqual(request.sealed.periodKeys, { ten: { "251023T14": "AAAA" } });

    const { covered, missing } = await unsealer.resolve(dcaData, ["two"]);
    assert.deepEqual(covered, []);
    assert.deepEqual(missing, ["two"]);
  });

  test("a name the grammar refuses rejects the map that carries it", () => {
    const unsealer = new Client({ publisherOrigin: ORIGIN });
    const badPage = (/** @type {any} */ err) => err.code === "bad_page";

    // One member name outside the grammar rejects the whole map, so the
    // sound sibling beside it answers nothing either. The three maps a
    // request is derived from say so where the request is derived.
    const issuers = hostilePage();
    issuers.issuerData["pay|wall"] = issuers.issuerData.paywall;
    assert.throws(
      () => unsealer.buildRequest(unsealer.parse(issuers), "paywall", ["two"]),
      badPage,
    );

    const inventory = hostilePage();
    inventory.contentData["2bad"] = inventory.contentData.two;
    assert.throws(
      () => unsealer.buildRequest(unsealer.parse(inventory), "paywall", ["two"]),
      badPage,
    );

    // The sealed-content carrier is keyed by contentName too, and the
    // reader holds it to the same rule as it reads the delivery.
    const carrier = hostilePage();
    carrier.sealedContent["2bad"] = "AAAA";
    assert.throws(() => unsealer.parse(carrier), badPage);
  });

  test("an own inherited-word coordinate survives both base request maps", () => {
    // `constructor` passes the grammar and every object also answers to it,
    // so a map that carries it as an own member is the case a plain
    // `map[name]` read cannot tell apart from the prototype's. Use it
    // independently in the two dimensions the request copies: contentName
    // and accessGroup.
    const hostile = JSON.parse(
      JSON.stringify({
        version: "1",
        resource: {
          renderId: RENDER_ID,
          origin: ORIGIN,
          issuedAt: "2025-10-23T14:00:00.000Z",
          resourceId: RESOURCE_ID,
          data: {},
        },
        resourceJWT: unsignedJwt({
          renderId: RENDER_ID,
          origin: ORIGIN,
          issuedAt: "2025-10-23T14:00:00.000Z",
          resourceId: RESOURCE_ID,
          data: {},
        }),
        contentData: {
          constructor: {
            contentType: "text/html",
            nonce: "AAAAAAAAAAAAAAAA",
            aad: "x",
            keys: {
              constructor: [{ t: "251023T14", nonce: "AAAAAAAAAAAAAAAA", key: "wrapped" }],
            },
          },
        },
        issuerData: {
          [ISSUER_NAME]: {
            sealed: {
              contentKeys: { constructor: "content-blob" },
              periodKeys: { constructor: { "251023T14": "period-blob" } },
              periodChainKeys: { constructor: { "251023T23": "chain-blob" } },
            },
            unlockUrl: UNLOCK_URL,
            keyId: KEY_ID,
          },
        },
        sealedContent: { constructor: "ciphertext" },
      }),
    );

    const unsealer = new Client({ publisherOrigin: ORIGIN });
    const request = unsealer.buildRequest(unsealer.parse(hostile), ISSUER_NAME, ["constructor"]);

    for (const map of [request.sealed.contentKeys, request.sealed.periodKeys]) {
      assert.equal(Object.hasOwn(map, "constructor"), true);
      assert.equal(Object.getPrototypeOf(map), Object.prototype);
    }

    const roundTrip = JSON.parse(JSON.stringify(request));
    assert.equal(roundTrip.sealed.contentKeys.constructor, "content-blob");
    assert.deepEqual(roundTrip.sealed.periodKeys.constructor, { "251023T14": "period-blob" });
    assert.equal(
      Object.hasOwn(roundTrip.sealed, "periodChainKeys"),
      false,
      "base never forwards an optional chain carrier",
    );
  });

  test("an inherited name off the wire is inert, not a crash", async () => {
    const page = hostilePage();

    for (const name of INHERITED) {
      const unsealer = new Client({ publisherOrigin: ORIGIN });
      const dcaData = unsealer.parse(page);
      assert.equal(unsealer.extract(page, name), null);
      assert.equal(await unsealer.contentKeyFor(dcaData, name), null);
      assert.deepEqual(unsealer.buildRequest(dcaData, "paywall", [name]).sealed.contentKeys, {});
      assert.throws(
        () => unsealer.buildRequest(dcaData, name, ["two"]),
        (err) => err.code === "unknown_issuer",
      );
    }
  });
});

describe("The generic content representation opener", () => {
  const AAD = `${RESOURCE_ID}|1|${CONTENT_NAME}`;

  /** @param {string} name @param {Uint8Array} bytes */
  function wrap(name, bytes) {
    const prefix = utf8Encode(`${name}:`);
    const out = new Uint8Array(prefix.length + bytes.length);
    out.set(prefix);
    out.set(bytes, prefix.length);
    return out;
  }

  /** @param {string} name */
  function unwrap(name) {
    const prefix = utf8Encode(`${name}:`);
    return (/** @type {Uint8Array} */ bytes) => {
      assert.deepEqual(bytes.slice(0, prefix.length), prefix, `${name} is the next outer layer`);
      return bytes.slice(prefix.length);
    };
  }

  /** @param {Uint8Array} bytes @param {string[]|undefined} contentEncodings */
  async function sealed(bytes, contentEncodings) {
    const contentKey = new Uint8Array(16).fill(7);
    const nonce = new Uint8Array(12).fill(4);
    return {
      contentKey,
      ciphertext: base64urlEncode(await encrypt(contentKey, nonce, bytes, utf8Encode(AAD))),
      record: {
        contentType: "text/html",
        nonce: base64urlEncode(nonce),
        aad: AAD,
        ...(contentEncodings === undefined ? {} : { contentEncodings }),
      },
    };
  }

  test("decoder registry admission is typed and reads only own functions", () => {
    for (const registry of [null, [], "gzip", { gzip: true }]) {
      assert.throws(
        () => new ContentRepresentationOpener(/** @type {any} */ (registry)),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
    const inherited = Object.create({ inherited: (bytes) => bytes });
    assert.ok(new ContentRepresentationOpener(inherited));
  });

  test("layers are decoded in reverse order and repetitions are preserved", async () => {
    const plaintext = utf8Encode("article");
    const layers = ["first", "second", "first"];
    let represented = plaintext;
    for (const name of layers) represented = wrap(name, represented);
    const item = await sealed(represented, layers);
    const calls = [];
    const opener = new ContentRepresentationOpener({
      first: (bytes) => {
        calls.push("first");
        return unwrap("first")(bytes);
      },
      second: (bytes) => {
        calls.push("second");
        return unwrap("second")(bytes);
      },
    });

    const opened = await opener.open({
      record: item.record,
      contentName: CONTENT_NAME,
      ciphertext: item.ciphertext,
      aad: AAD,
      resolveKey: async () => item.contentKey,
    });

    assert.deepEqual(opened, plaintext);
    assert.deepEqual(calls, ["first", "second", "first"]);
  });

  test("an unsupported layer is an item failure before key resolution, including inherited registry names", async () => {
    const item = await sealed(utf8Encode("article"), ["inherited"]);
    let resolutions = 0;
    const inherited = Object.create({ inherited: (bytes) => bytes });
    const opener = new ContentRepresentationOpener(inherited);

    await assert.rejects(
      () =>
        opener.open({
          record: item.record,
          contentName: CONTENT_NAME,
          ciphertext: item.ciphertext,
          aad: AAD,
          resolveKey: async () => {
            resolutions += 1;
            return item.contentKey;
          },
        }),
      { code: "unsupported_encoding" },
    );
    assert.equal(resolutions, 0);
  });

  test("malformed lists and decoder failures stay typed and return no partial representation", async () => {
    const item = await sealed(utf8Encode("article"), ["first", "last"]);
    let firstCalls = 0;
    const opener = new ContentRepresentationOpener({
      first: (bytes) => {
        firstCalls += 1;
        return bytes;
      },
      last: () => {
        throw new Error("decoder detail");
      },
    });
    await assert.rejects(
      () =>
        opener.open({
          record: item.record,
          contentName: CONTENT_NAME,
          ciphertext: item.ciphertext,
          aad: AAD,
          resolveKey: async () => item.contentKey,
        }),
      { code: "bad_encoding" },
    );
    assert.equal(firstCalls, 0, "an inner layer is never exposed after the outer decoder fails");

    await assert.rejects(
      () =>
        new ContentRepresentationOpener({ first: () => /** @type {any} */ ("bytes") }).open({
          record: { ...item.record, contentEncodings: ["first"] },
          contentName: CONTENT_NAME,
          ciphertext: item.ciphertext,
          aad: AAD,
          resolveKey: async () => item.contentKey,
        }),
      { code: "bad_encoding" },
    );

    await assert.rejects(
      () =>
        opener.open({
          record: { ...item.record, contentEncodings: [] },
          contentName: CONTENT_NAME,
          ciphertext: item.ciphertext,
          aad: AAD,
          resolveKey: async () => item.contentKey,
        }),
      { code: "bad_page" },
    );
  });

  test("a malformed aad is refused before key resolution", async () => {
    const item = await sealed(utf8Encode("article"), undefined);
    let resolutions = 0;
    const opener = new ContentRepresentationOpener();

    await assert.rejects(
      () =>
        opener.open({
          record: item.record,
          contentName: CONTENT_NAME,
          ciphertext: item.ciphertext,
          aad: /** @type {any} */ (undefined),
          resolveKey: async () => {
            resolutions += 1;
            return item.contentKey;
          },
        }),
      { code: "bad_page" },
    );
    assert.equal(resolutions, 0, "an unreadable item costs no key resolution");
  });

  test("authenticated decrypt completes before any decoder runs", async () => {
    const item = await sealed(wrap("first", utf8Encode("article")), ["first"]);
    let decoderCalls = 0;
    const opener = new ContentRepresentationOpener({
      first: (bytes) => {
        decoderCalls += 1;
        return unwrap("first")(bytes);
      },
    });

    await assert.rejects(
      () =>
        opener.open({
          record: item.record,
          contentName: CONTENT_NAME,
          ciphertext: item.ciphertext,
          aad: AAD,
          resolveKey: async () => new Uint8Array(16).fill(8),
        }),
      { code: "decrypt_failed" },
    );
    assert.equal(decoderCalls, 0);
  });
});

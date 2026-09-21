// @ts-check
//
// The seam where plaintext leaves the client, scanned for key material.
//
// The issuer reference gives a page three things per item -
// `(contentName, decryptedData, contentType)` - and nothing else, so a page's
// own code never touches a key. The reference hand-off harness
// `test-lib/harnesses/openAndPlace.js` passes those three values: the lines
// below record every call it made, as it made it, so both halves of the guarantee
// are assertions over that candidate hand-off rather than over a recorder this
// file wrote - the arity from the argument list the loop passed, the leak from
// the values in it. The harness is not a shipped or demo-own placement loop,
// and this test does not prove today's `PageLoad` opens content through the
// held-out target adapter; it pins the callback shape that adapter would
// receive.
//
// The scan reaches past the three values. The three values are pinned byte for
// byte a line earlier, so scanning them alone would be a scan of what the same
// test just spelled out. The two structures the demo builds and the test does
// not are scanned beside them: the `dcaData` object the client holds after the
// unlock and after every decrypt - a regression that stashed a contentKey on
// the wire object would surface there and nowhere else - and the unlock
// response body, which is the one structure that is supposed to carry keys.
//
// The scan treats every key the render is made of as a leak, computed here from
// the publisher's side rather than read out of a response: every exact
// periodKey for the (accessGroup, t) pairs the render ships, and every
// contentKey those periodKeys unwrap. A hit is any of them appearing as raw
// bytes, as any of four text spellings (base64url, standard base64, lowercase
// hex, uppercase hex), or as a live `CryptoKey` handle anywhere in the
// deep-walked structure.
//
// The suite covers both transports, because they carry different things. Direct
// transport is covered here. The client-bound companion lives with that
// extension in `extensions/client-bound-transport/test/placement-leak.test.js`,
// where handles are recognised as key material even though their bytes are
// unreadable.
//
// These tests control the scanner against planted keys. A scan that finds
// nothing is worth nothing until it has been shown to find something, so the
// same scanner runs over an argument list with a contentKey planted in it three
// ways and has to report all three. The direct-transport run carries its own
// control besides: that response body holds the keys as base64url on purpose,
// so the same scan in the same test has to light up on it and stay silent on
// everything else.
//
// One loop drives both delivery forms. `openAndPlace` takes a page that answers
// `dcaData` and `extract`, so the JSON client and `MarkupDeliveryReader` over a
// DOM drive the identical decrypt calls. That is what the parity assertions in
// the second half are: the same read run twice, once through each form, with
// the four inputs the AEAD is given compared at every step.
//
// A strict stub stands in for the DOM. Node has no document, so the markup runs
// are read through `domOver` below - the calls `MarkupDeliveryReader` makes and
// nothing else. It cuts the script block at the first `</script>` the way the
// HTML tokenizer does, so an emitter that stopped escaping that sequence fails
// here rather than passing on a repaired string.
//
// Pinned: one issuer, up and fast, no fallback, no response
// cache, the clock stands still. The wiring is `demo/scenarios/world.js`'s actor
// family; the render is handed to the `Publisher` item by item, because a scan
// wants more than one key of each kind and `fixtures.article()` ships one.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { openAndPlace } from "../test-lib/harnesses/openAndPlace.js";
import { base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from "../core-shared/codec.js";
import { isContentName } from "../core-shared/names.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { keyMaterialInPlay, leaks } from "../test-lib/helpers/keyMaterialLeaks.js";
import {
  ACCESS_GROUP,
  ARTICLES,
  CONTENT_NAME,
  CONTENT_TYPE,
  ISSUER_NAME,
  UNLOCK_URL,
} from "../demo/scenarios/fixtures.js";

const { subtle } = globalThis.crypto;

const SECOND = 1000;

/**
 * The markup delivery form for one `Page`, emitted by the writer over the page's
 * render values. The `Page` keeps no markup emitter of its own: a caller reads
 * its one wire-safe render through `asJson()` and hands the writer the dca-data
 * and the sealed content beside it, the same split the object form carries.
 *
 * @param {any} page
 * @returns {string}
 */
function markupOf(page) {
  const { sealedContent, ...dcaData } = page.asJson();
  return writeMarkupDelivery({ dcaData, sealedContent });
}

/** One resourceId across every render here, because it is what lands in the aad. */
const RESOURCE_ID = "123456";

/**
 * Two items under two families, so the scan covers more than one contentKey
 * and more than one periodKey family. `fixtures.article()` is one item under one
 * group, which would leave the scan a single key of each kind to find.
 */
const ITEMS = [
  {
    name: CONTENT_NAME,
    value: ARTICLES.A,
    contentType: CONTENT_TYPE,
    accessGroups: [ACCESS_GROUP],
  },
  {
    name: "factbox",
    value: "Harbour plan: 14 hectares, 2031.",
    contentType: "text/plain",
    accessGroups: [ACCESS_GROUP, "staff"],
  },
];

/** A colon in both name kinds at once, for the round trip below. */
const COLON_NAME = "sponsor:intro";
const COLON_GROUP = "premium:sport";
const COLON_ITEMS = [
  {
    name: COLON_NAME,
    value: "<p>Sponsored: the harbour plan, explained.</p>",
    contentType: "text/html",
    accessGroups: [COLON_GROUP],
  },
];

/**
 * One publisher, one issuer, one render. `items` is what the colon round trip
 * turns, which is a render `fixtures.article()` has no shape for and the
 * `Publisher` takes whole.
 *
 * `wire` comes back beside the page because the scan reads the render's key
 * coordinates off it, and the delivery form is the only view a `Page` hands out.
 *
 * `data` is the publisher's own metadata, turned by the escaping run: it is the
 * one part of dca-data a CMS fills with strings nobody here chose.
 *
 * @param {{ items?: any[], data?: object }} [options]
 * @returns {Promise<any>}
 */
async function world({ items = ITEMS, data = { section: "politics" } } = {}) {
  const stage = await actorWorld();

  const page = await stage.publisher.render({
    resourceId: RESOURCE_ID,
    data,
    items,
  });

  return {
    network: stage.network,
    page,
    wire: page.asJson(),
    items,
    periodKeySupply: stage.periodKeySupply,
  };
}

/**
 * One client, reading the page the way a browser does: ask the issuer for what
 * the cache cannot open, then run the reference hand-off harness
 * (`test-lib/harnesses/openAndPlace.js`) over the delivery form asked for - not a
 * shipped or demo-own placement loop. Every call it made is recorded as it was made -
 * arguments and their count, untouched.
 *
 * `dcaData` comes back with the placements because it is the client's own copy
 * of the wire after the unlock and after every decrypt, and a key held there is
 * a key on an object page code is handed whole. It is the copy the loop read,
 * which under `markup` is the one that came out of the DOM.
 *
 * The `unsealer` comes back too, holding what the unlock returned, so a test can
 * run a second read over a mutated page without paying for another unlock.
 *
 * Driven off a client composition rather than `demo/scenarios/readArticle`, which hands back
 * decoded text and error codes. The scan needs the plaintext as the bytes that
 * crossed the seam, and the client's own `dcaData` beside them - neither of them
 * survives being read as a string.
 *
 * @param {any} pageAndNetwork
 * @param {{ deliveryForm?: 'json'|'markup' }} [options]
 * @returns {Promise<any>}
 */
async function readWithPlacement({ network, page, items }, { deliveryForm = "json" } = {}) {
  const unsealer = new Client({
    cache: /** @type {any} */ (new PeriodKeyCache({})),
    publisherOrigin: "https://www.news-site.example",
  });

  const json = page.asJson();
  const dcaData = unsealer.parse(json);
  const names = items.map((/** @type {any} */ item) => item.name);

  const { missing } = await unsealer.resolve(dcaData, names);
  const request = unsealer.buildRequest(dcaData, ISSUER_NAME, missing);
  const answer = await network.post(UNLOCK_URL, request, {
    from: { who: "a reader" },
    timeout: 2 * SECOND,
    origin: "https://www.news-site.example",
  });
  assert.equal(answer.status, 200, "the honest path has to work before an absence means anything");
  await unsealer.applyResponse(dcaData, ISSUER_NAME, answer.body);

  // The two delivery forms, behind the one shape `openAndPlace` reads: the
  // markup form finds its blobs by selector, the JSON form by member name.
  // Both hand the same client the same four decrypt inputs, which is the
  // claim the parity tests below take apart.
  const readable =
    deliveryForm === "markup"
      ? new MarkupDeliveryReader(
          domOver(markupOf(page), { publisherOrigin: "https://www.news-site.example" }),
        )
      : {
          dcaData,
          extract: (/** @type {string} */ contentName) => unsealer.extract(json, contentName),
        };

  /** @type {any[][]} */
  const placements = [];
  const { placed, locked } = await openAndPlace({
    page: readable,
    unsealer,
    contentNames: names,
    place: (/** @type {any[]} */ ...args) => {
      placements.push(args);
    },
  });

  return { placements, answer, dcaData: readable.dcaData, placed, locked, unsealer, readable };
}

// ---------------------------------------------------------------------------
// The DOM this runtime has not got
// ---------------------------------------------------------------------------

/**
 * The calls `MarkupDeliveryReader` makes, over a markup string: `querySelector`
 * on a root, and `textContent` on each block it returns. Nothing else of a DOM
 * is here, and nothing needs to be - the
 * reader takes its root as an argument precisely so a runtime without a
 * document can hand it this. In a browser the same class runs over `document`.
 *
 * The script block is cut at the FIRST `</script>`, which is the tokenizer's own
 * rule and the reason `writeMarkupDelivery` escapes that sequence: markup that stopped
 * escaping it arrives here as JSON that stops short, and the reader refuses it
 * rather than this stub quietly repairing what a browser would not.
 *
 * @param {string} markup
 * @param {{ publisherOrigin?: string }} [context]
 * @returns {{ location: { origin: string }, querySelector: (selector: string) => any,
 *   querySelectorAll: (selector: string) => any[] }}
 */
function domOver(markup, context = {}) {
  const data = /<script type="application\/json" class="dca-data">([\s\S]*?)<\/script>/.exec(
    markup,
  );
  const sealed =
    /<script type="application\/json" class="dca-sealed-content">([\s\S]*?)<\/script>/.exec(markup);
  const carrier = (/** @type {RegExpExecArray|null} */ found) =>
    found === null
      ? null
      : {
          tagName: "script",
          textContent: found[1],
          getAttribute: (/** @type {string} */ name) =>
            name === "type" ? "application/json" : null,
        };

  return {
    location: { origin: context.publisherOrigin ?? "https://www.news-site.example" },
    querySelector: (/** @type {string} */ selector) => {
      if (selector === ".dca-data") return carrier(data);
      if (selector === ".dca-sealed-content") return carrier(sealed);
      return null;
    },
    querySelectorAll: (/** @type {string} */ selector) => {
      const found =
        selector === ".dca-data"
          ? carrier(data)
          : selector === ".dca-sealed-content"
            ? carrier(sealed)
            : null;
      return found === null ? [] : [found];
    },
  };
}

describe("The placement seam, direct transport", () => {
  test("the values a placement adapter is handed carry no key material, under direct transport", async () => {
    const stage = await world();
    const { placements, answer, dcaData } = await readWithPlacement(stage);

    // The honest path first: this transport hands the client raw key bytes,
    // so an absence at the seam means the client kept them and not that
    // nothing ever arrived.
    assert.equal(answer.body.transport, undefined, "direct is the bytes, not a wrapped body");
    assert.deepEqual(
      placements.map(([contentName, bytes, contentType]) => [
        contentName,
        utf8Decode(bytes),
        contentType,
      ]),
      ITEMS.map((item) => [item.name, item.value, item.contentType]),
    );

    const material = await keyMaterialInPlay(stage.wire, stage.periodKeySupply);
    assert.ok(material.length >= 6, "four periodKeys and two contentKeys at least");
    assert.deepEqual(leaks(placements, material), []);

    // The client's own copy of the wire, after the unlock and after every
    // decrypt. What the unlock handed over lives in the resolver and in
    // the periodKey cache, and this object is what page code is passed
    // whole - so a regression that parked a contentKey on it is caught here
    // and nowhere else.
    assert.deepEqual(leaks(dcaData, material), []);

    // And the control that runs on the demo's own output rather than on
    // planted values: this transport hands the keys over as base64url on
    // purpose, so the same scanner over the same material has to light up on
    // the body it just read and stay silent on everything downstream of it.
    const inTheBody = leaks(answer.body, material);
    assert.ok(
      ITEMS.every((item) =>
        inTheBody.some((line) => line.startsWith(`$.keys.contentKeys.${item.name}:`)),
      ),
      inTheBody.join("; "),
    );
    assert.ok(
      inTheBody.every((line) => line.endsWith("as text")),
      inTheBody.join("; "),
    );
  });

  test("the scan finds a contentKey planted in the placement arguments three ways", async () => {
    // The control for both transport tests. Without it a green scan could mean
    // the walk never reached the values, never recognised a handle, or never
    // knew what it was looking for.
    const stage = await world();
    const material = await keyMaterialInPlay(stage.wire, stage.periodKeySupply);
    const contentKey = /** @type {any} */ (
      material.find((entry) => entry.label.startsWith("the contentKey"))
    ).bytes;
    const handle = await subtle.importKey("raw", contentKey, { name: "AES-GCM" }, false, [
      "decrypt",
    ]);

    const planted = [
      ["bodytext", utf8Encode("<p>x</p>"), "text/html"],
      // Three shapes a careless adapter argument could carry a key in: a
      // nested string, the raw bytes, and a live handle.
      ["bodytext", { debug: { key: base64urlEncode(contentKey) } }, "text/html"],
      ["bodytext", { held: contentKey }, "text/html"],
      ["bodytext", { held: handle }, "text/html"],
    ];

    const found = leaks(planted, material);
    assert.equal(found.length, 3, found.join("; "));
    assert.ok(found.some((line) => line.endsWith("as text")));
    assert.ok(found.some((line) => line.endsWith("as bytes")));
    assert.ok(found.some((line) => line.includes("CryptoKey handle")));
  });

  test("the placement callback takes exactly (contentName, decryptedData, contentType)", async () => {
    // The whole read, through the markup form and the reference hand-off
    // harness (`test-lib/harnesses/openAndPlace.js`), not a shipped placement
    // loop: what is asserted here is the argument list `openAndPlace`
    // passed, not one this file declared. It does not prove today's
    // `PageLoad` opens content through the held-out target adapter.
    const stage = await world();
    const { placements, placed, locked, dcaData } = await readWithPlacement(stage, {
      deliveryForm: "markup",
    });

    assert.deepEqual(
      placed,
      ITEMS.map((item) => item.name),
    );
    assert.deepEqual(locked, []);
    assert.equal(placements.length, ITEMS.length, "once per opened item");
    for (const args of placements) {
      assert.equal(
        args.length,
        3,
        "three arguments and no fourth - a page is handed no key to hold",
      );
    }

    assert.deepEqual(
      placements.map(([contentName, decryptedData, contentType]) => [
        contentName,
        utf8Decode(decryptedData),
        contentType,
      ]),
      ITEMS.map((item) => [item.name, item.value, item.contentType]),
    );
    for (const [, decryptedData] of placements) {
      assert.ok(decryptedData instanceof Uint8Array, "plaintext bytes, not a handle to open");
    }

    // And the scan the two runs above make, pointed at the same arguments -
    // the ones the reference hand-off harness (`test-lib/harnesses/openAndPlace.js`)
    // passed.
    const material = await keyMaterialInPlay(stage.wire, stage.periodKeySupply);
    assert.deepEqual(leaks(placements, material), []);
    assert.deepEqual(leaks(dcaData, material), []);
  });

  test("a deferred item crosses no key-bearing surface and opens when its ciphertext arrives separately", async () => {
    const stage = await world();
    const deferredName = "factbox";
    const unsealer = new Client({
      cache: /** @type {any} */ (new PeriodKeyCache({})),
      publisherOrigin: "https://www.news-site.example",
    });
    const json = stage.page.asJson();
    const dcaData = unsealer.parse(json);
    const names = ITEMS.map((item) => item.name);
    const { missing } = await unsealer.resolve(dcaData, names);
    const request = unsealer.buildRequest(dcaData, ISSUER_NAME, missing);
    const answer = await stage.network.post(UNLOCK_URL, request, {
      from: { who: "a reader" },
      timeout: 2 * SECOND,
      origin: "https://www.news-site.example",
    });
    assert.equal(answer.status, 200);
    await unsealer.applyResponse(dcaData, ISSUER_NAME, answer.body);

    const deferred = {
      dcaData,
      extract: (contentName) =>
        contentName === deferredName ? null : unsealer.extract(json, contentName),
    };
    /** @type {any[][]} */
    const placements = [];
    const { placed, locked } = await openAndPlace({
      page: deferred,
      unsealer,
      contentNames: names,
      place: (...args) => {
        placements.push(args);
      },
    });

    assert.deepEqual(placed, [CONTENT_NAME]);
    assert.deepEqual(locked, [{ contentName: deferredName, error: "unknown_content" }]);
    const material = await keyMaterialInPlay(stage.wire, stage.periodKeySupply);
    assert.deepEqual(leaks(placements, material), []);
    assert.deepEqual(
      leaks({ dcaData, fetchedCiphertext: stage.wire.sealedContent[deferredName] }, material),
      [],
    );

    const fetched = stage.wire.sealedContent[deferredName];
    assert.equal(
      utf8Decode(await unsealer.decrypt(dcaData, deferredName, fetched)),
      ITEMS.find((item) => item.name === deferredName).value,
      "the key held from the unlock opens the ciphertext delivered after the page",
    );
  });
});

describe("Extraction, and what reaches the crypto", () => {
  test("JSON-API extraction hands the crypto the sealer bytes untouched", async () => {
    const { page, wire } = await world();
    const unsealer = new Client({ publisherOrigin: "https://www.news-site.example" });

    const json = page.asJson();
    const dcaData = unsealer.parse(json);
    const contentName = ITEMS[0].name;

    // The four inputs a decrypt is made of, taken through the extraction
    // path and compared against the delivery form the publisher shipped.
    // This demo can hold the byte-transparency half of that guarantee: a
    // markup extractor arriving later has one pinned set of inputs to be
    // identical to.
    const record = dcaData.contentData[contentName];

    assert.deepEqual(
      base64urlDecode(/** @type {string} */ (unsealer.extract(json, contentName))),
      base64urlDecode(wire.sealedContent[contentName]),
      "ciphertext bytes",
    );
    assert.deepEqual(
      base64urlDecode(record.nonce),
      base64urlDecode(wire.contentData[contentName].nonce),
      "nonce",
    );
    assert.deepEqual(
      utf8Encode(record.aad),
      utf8Encode(wire.contentData[contentName].aad),
      "aad, as the bytes that go into the AEAD rather than the string beside it",
    );
    assert.equal(record.aad, `${RESOURCE_ID}|1|${contentName}`);

    // The key lookup coordinates: which groups the item is wrapped under, in
    // which periods, and the wrapped bytes at each. A reordering here picks
    // a different key with nothing else changed, which is why they are
    // pinned beside the ciphertext.
    assert.deepEqual(dcaData.contentData[contentName].keys, wire.contentData[contentName].keys);
    assert.deepEqual(Object.keys(dcaData.contentData[contentName].keys), ITEMS[0].accessGroups);
    assert.equal(dcaData.resource.renderId, wire.resource.renderId);
  });

  test("markup extraction and JSON-API extraction yield identical decrypt inputs", async () => {
    const { page, wire } = await world();
    const unsealer = new Client({ publisherOrigin: "https://www.news-site.example" });

    const json = page.asJson();
    const fromJson = unsealer.parse(json);
    const fromMarkup = new MarkupDeliveryReader(
      domOver(markupOf(page), { publisherOrigin: "https://www.news-site.example" }),
    );

    // The whole of dca-data, member order included. The two forms differ by
    // where the ciphertext sits and by nothing else, so an issuer reading
    // the JSON and a browser reading the markup are reading one render.
    assert.deepEqual(fromMarkup.dcaData, fromJson);
    assert.equal(
      JSON.stringify(fromMarkup.dcaData),
      JSON.stringify(fromJson),
      "down to the member order",
    );

    for (const item of ITEMS) {
      const contentName = item.name;
      const fromSelector = fromMarkup.extract(contentName);

      // The four inputs a decrypt is made of, through both paths and
      // against the delivery form the publisher shipped.
      assert.equal(
        fromSelector,
        unsealer.extract(json, contentName),
        `ciphertext for ${contentName}`,
      );
      assert.deepEqual(
        base64urlDecode(/** @type {string} */ (fromSelector)),
        base64urlDecode(wire.sealedContent[contentName]),
        "the sealer bytes",
      );

      const record = fromMarkup.dcaData.contentData[contentName];
      assert.deepEqual(
        base64urlDecode(record.nonce),
        base64urlDecode(wire.contentData[contentName].nonce),
        "nonce",
      );
      assert.deepEqual(
        utf8Encode(record.aad),
        utf8Encode(wire.contentData[contentName].aad),
        "aad, as the bytes that go into the AEAD rather than the string beside it",
      );

      // Which groups, in which order: a reordering here picks a different
      // key with nothing else changed.
      assert.deepEqual(
        fromMarkup.dcaData.contentData[contentName].keys,
        wire.contentData[contentName].keys,
      );
      assert.deepEqual(
        Object.keys(fromMarkup.dcaData.contentData[contentName].keys),
        item.accessGroups,
      );
    }

    // And through to the plaintext: the same read run twice over one render,
    // once per delivery form, ending at the same recorded placement calls.
    const stage = await world();
    const viaJson = await readWithPlacement(stage, { deliveryForm: "json" });
    const viaMarkup = await readWithPlacement(stage, { deliveryForm: "markup" });
    assert.deepEqual(viaMarkup.placements, viaJson.placements);
    assert.deepEqual(viaMarkup.placed, viaJson.placed);
  });

  test("one changed ciphertext byte in the markup refuses, and places nothing", async () => {
    // The control for the parity above: without it, both sides reading one
    // render could be comparing something to itself. A byte changed in the
    // emitted markup has to come back through the same extraction as a
    // different ciphertext and die at the tag - and the placement callback
    // must not be called for it, because a page that placed an unopened item
    // would be rendering an empty article as an unlocked one.
    const stage = await world();
    const { unsealer } = await readWithPlacement(stage, { deliveryForm: "markup" });

    const markup = markupOf(stage.page);
    const contentName = ITEMS[0].name;
    const ciphertext = /** @type {string} */ (
      new MarkupDeliveryReader(
        domOver(markup, { publisherOrigin: "https://www.news-site.example" }),
      ).extract(contentName)
    );
    const changed = (ciphertext[0] === "A" ? "B" : "A") + ciphertext.slice(1);
    const mutated = new MarkupDeliveryReader(
      domOver(markup.replace(ciphertext, changed), {
        publisherOrigin: "https://www.news-site.example",
      }),
    );

    assert.equal(mutated.extract(contentName), changed);
    assert.notEqual(changed, ciphertext);

    /** @type {any[][]} */
    const placements = [];
    const { placed, locked } = await openAndPlace({
      page: mutated,
      unsealer,
      contentNames: [contentName],
      place: (/** @type {any[]} */ ...args) => {
        placements.push(args);
      },
    });

    assert.deepEqual(placements, []);
    assert.deepEqual(placed, []);
    assert.deepEqual(locked, [{ contentName, error: "decrypt_failed" }]);
  });

  test("a script-closing sequence in publisher metadata leaves the dca-data block intact", async () => {
    // `resource.data` is whatever the CMS put there and it reaches the JSON
    // verbatim, so the two sequences that end a script block early are not
    // hypothetical: `</script` ends it outright, and `<!--` opens the states
    // where a later `<script` makes the element's own closing tag stop
    // ending it.
    const closing = "</script><img src=x onerror=alert(1)>";
    const commented = "<!--<script>";
    const { page } = await world({ data: { section: closing, note: commented } });
    const markup = markupOf(page);

    const block = markup.slice(markup.indexOf(">") + 1, markup.indexOf("</script>"));
    assert.equal(block.includes("</script"), false, "nothing in the JSON ends the block");
    assert.equal(block.includes("<!--"), false, "and nothing in it opens the escaped states");
    assert.equal(
      /** @type {RegExpMatchArray} */ (markup.match(/<\/script/gi)).length,
      2,
      "two closing tags, the emitter's own two",
    );

    // And no consumer has to know it happened: the rewrite is to JSON's own
    // escape for the character, so what comes back through the DOM is the
    // string the publisher wrote and the two delivery forms still agree.
    const read = new MarkupDeliveryReader(
      domOver(markup, { publisherOrigin: "https://www.news-site.example" }),
    );
    assert.equal(read.dcaData.resource.data.section, closing);
    assert.equal(read.dcaData.resource.data.note, commented);
    assert.deepEqual(
      read.dcaData,
      new Client({ publisherOrigin: "https://www.news-site.example" }).parse(page.asJson()),
    );
  });

  test("a contentName with a colon round-trips as a JSON key, as the aad and into a selector", async () => {
    const stage = await world({ items: COLON_ITEMS });
    const json = stage.wire;

    // Member position, after the JSON round trip every `Page` puts a render
    // through: the name that comes back is the name that went in - in
    // contentData, in sealedContent, and as the accessGroup key beneath
    // it, where the colon remains part of the exact group coordinate.
    assert.deepEqual(Object.keys(json.contentData), [COLON_NAME]);
    assert.deepEqual(Object.keys(json.sealedContent), [COLON_NAME]);
    assert.deepEqual(Object.keys(json.contentData[COLON_NAME].keys), [COLON_GROUP]);

    // And in the aad, where the AEAD authenticates it: a colon rewritten
    // anywhere between the publisher and the client is a decrypt failure and
    // not a cosmetic difference.
    assert.equal(json.contentData[COLON_NAME].aad, `${RESOURCE_ID}|1|${COLON_NAME}`);

    // The whole read driven through the colon name - unlock, unwrap, decrypt
    // - ending at the three values a placement adapter would be handed.
    const { placements } = await readWithPlacement(stage);
    assert.deepEqual(
      placements.map(([contentName, bytes, contentType]) => [
        contentName,
        utf8Decode(bytes),
        contentType,
      ]),
      COLON_ITEMS.map((item) => [item.name, item.value, item.contentType]),
    );

    // And in the sealed-content carrier, where the name is a JSON member
    // name the way a client looks one up by member name: the colon
    // needs no escape there, and the characters that would break the
    // carrier - a quote closing the member name, a backslash opening an
    // escape - are the ones the grammar refuses.
    const carrier = JSON.stringify({ [COLON_NAME]: "QUJD" });
    assert.equal(carrier, '{"sponsor:intro":"QUJD"}');
    assert.equal(JSON.parse(carrier)[COLON_NAME], "QUJD");
    for (const hostile of ['sponsor"intro', "sponsor\\intro", 'a":"b']) {
      assert.equal(isContentName(hostile), false, hostile);
    }
  });
});

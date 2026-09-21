// @ts-check
//
// The object delivery reader, and the claim this file makes about it: a client
// driven over the object form and one driven over the markup form read the same
// render. The two readers find their data differently (a member lookup here, a
// selector there), and every later step takes their two answers as given, so a
// difference between them would move what a page opens without touching
// anything that looks like the client walk.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { ObjectDeliveryReader } from "../demo/support/ObjectDeliveryReader.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { CONTENT_NAME } from "../demo/scenarios/fixtures.js";
import { INHERITED } from "../test-lib/fixtures/inherited-names.js";

const PUBLISHER_ORIGIN = "https://publisher.example";

/**
 * The smallest thing that answers `querySelector` the way
 * `MarkupDeliveryReader` asks: the two inert JSON script blocks, `.dca-data` and
 * `.dca-sealed-content`. Written here rather than taken from a DOM, because
 * these tests are about the pair agreeing.
 */
function markupOver(page) {
  const { sealedContent = {}, ...dcaData } = page;
  const carrier = (value) => ({
    tagName: "script",
    textContent: JSON.stringify(value),
    getAttribute: (name) => (name === "type" ? "application/json" : null),
  });

  return {
    location: { origin: PUBLISHER_ORIGIN },
    querySelectorAll(selector) {
      if (selector === ".dca-data") return [carrier(dcaData)];
      if (selector === ".dca-sealed-content") return [carrier(sealedContent)];
      return [];
    },
  };
}

describe("The object delivery, read back", () => {
  test("the data comes back without the ciphertext beside it", async () => {
    const { render } = await actorWorld();
    const delivered = (await render("A")).asJson();

    const page = new ObjectDeliveryReader(delivered, { publisherOrigin: PUBLISHER_ORIGIN });

    assert.equal(Object.hasOwn(page.dcaData, "sealedContent"), false, "the blobs are not dca-data");
    assert.equal(page.dcaData.version, delivered.version);
    assert.deepEqual(page.dcaData.resource, delivered.resource);
    assert.equal(page.extract(CONTENT_NAME), delivered.sealedContent[CONTENT_NAME]);
  });

  test("a string delivery and the object it parses to read alike", async () => {
    const { render } = await actorWorld();
    const delivered = (await render("A")).asJson();

    const fromObject = new ObjectDeliveryReader(delivered, { publisherOrigin: PUBLISHER_ORIGIN });
    const fromText = new ObjectDeliveryReader(JSON.stringify(delivered), {
      publisherOrigin: PUBLISHER_ORIGIN,
    });

    assert.deepEqual(fromText.dcaData, fromObject.dcaData);
    assert.equal(fromText.extract(CONTENT_NAME), fromObject.extract(CONTENT_NAME));
  });

  test("an unknown name is a miss, and never an inherited member", () => {
    const page = new ObjectDeliveryReader(
      { sealedContent: { bodytext: "AAAA" } },
      { publisherOrigin: PUBLISHER_ORIGIN },
    );

    assert.equal(page.extract("bodytext"), "AAAA");
    assert.equal(page.extract("no-such-item"), null);
    for (const name of INHERITED) {
      assert.equal(page.extract(name), null, `sealedContent['${name}'] must not resolve`);
    }

    // A page carrying no blobs at all answers the same miss: deferred
    // content is a URL fetch, not an error here.
    assert.equal(
      new ObjectDeliveryReader({}, { publisherOrigin: PUBLISHER_ORIGIN }).extract("bodytext"),
      null,
    );

    // And a member that is not a string is not ciphertext.
    assert.equal(
      new ObjectDeliveryReader(
        { sealedContent: { bodytext: 17 } },
        { publisherOrigin: PUBLISHER_ORIGIN },
      ).extract("bodytext"),
      null,
    );
  });

  test("a delivery that is not a page is refused", () => {
    for (const delivery of [null, 42, "null"]) {
      assert.throws(
        () =>
          new ObjectDeliveryReader(/** @type {any} */ (delivery), {
            publisherOrigin: PUBLISHER_ORIGIN,
          }),
        (/** @type {any} */ e) => e.code === "bad_page",
      );
    }
  });

  test("an enclosing array and a sealedContent that is no map are structural failures", () => {
    // The object form's own rules: an enclosing array fails the delivery,
    // and a present `sealedContent` that is not a non-array object is a
    // carrier the delivery said it had and did not.
    for (const delivery of [
      [],
      [{ version: "1" }],
      { sealedContent: [] },
      { sealedContent: 42 },
      {
        sealedContent: "QUJD",
      },
    ]) {
      assert.throws(
        () =>
          new ObjectDeliveryReader(/** @type {any} */ (delivery), {
            publisherOrigin: PUBLISHER_ORIGIN,
          }),
        (/** @type {any} */ e) => e.code === "bad_page",
        JSON.stringify(delivery),
      );
    }

    // A string delivery reaches the same rules through its parse.
    assert.throws(
      () => new ObjectDeliveryReader("[]", { publisherOrigin: PUBLISHER_ORIGIN }),
      (/** @type {any} */ e) => e.code === "bad_page",
    );
  });

  test("an inherited sealedContent is absent, and no member of it is ciphertext", () => {
    // The native-object consumer reads `sealedContent` as an own member, so
    // a prototype carrying one supplies no ciphertext and leaves no member
    // on the data beside it.
    const inherited = Object.create({ sealedContent: { bodytext: "QUJD" } });
    inherited.version = "1";
    const page = new ObjectDeliveryReader(inherited, { publisherOrigin: PUBLISHER_ORIGIN });

    assert.equal(
      page.extract("bodytext"),
      null,
      "a prototype value is not this delivery's ciphertext",
    );
    assert.equal(
      Object.hasOwn(page.dcaData, "sealedContent"),
      false,
      "and it is no member of the data either",
    );
    assert.equal(page.dcaData.version, "1", "while the own members answer");
  });

  test("the two delivery forms answer the same page", async () => {
    const { render } = await actorWorld();
    const delivered = (await render("A")).asJson();

    const object = new ObjectDeliveryReader(delivered, { publisherOrigin: PUBLISHER_ORIGIN });
    const markup = new MarkupDeliveryReader(markupOver(delivered));

    assert.deepEqual(
      markup.dcaData,
      object.dcaData,
      "the same dca-data, whichever form carried it",
    );
    for (const name of Object.keys(delivered.sealedContent)) {
      assert.equal(markup.extract(name), object.extract(name), `the same ciphertext for ${name}`);
    }
    assert.equal(
      markup.extract("no-such-item"),
      object.extract("no-such-item"),
      "and the same miss",
    );
  });

  test("the two delivery forms refuse the same carrier and share the same misses", () => {
    // One member name outside the grammar rejects the carrier, in both
    // delivery forms and with the same code.
    const rejected = { sealedContent: { "bad|name": "QUJD", bodytext: "QUJD" } };
    for (const build of [
      () => new ObjectDeliveryReader(rejected, { publisherOrigin: PUBLISHER_ORIGIN }),
      () => new MarkupDeliveryReader(markupOver(rejected)),
    ]) {
      assert.throws(build, (/** @type {any} */ e) => e.code === "bad_page");
    }

    // Over an admitted carrier the two answer the same misses.
    const delivered = { sealedContent: { bodytext: 17 } };
    const readers = [
      new ObjectDeliveryReader(delivered, { publisherOrigin: PUBLISHER_ORIGIN }),
      new MarkupDeliveryReader(markupOver(delivered)),
    ];

    for (const reader of readers) {
      assert.equal(reader.extract("bad|name"), null, "a grammar-illegal lookup is a miss");
      assert.equal(reader.extract(""), null, "an otherwise invalid string name is a miss");
      assert.equal(
        reader.extract(/** @type {any} */ (null)),
        null,
        "null is not coerced to a name",
      );
      assert.equal(
        reader.extract(/** @type {any} */ (42)),
        null,
        "a number is not coerced to a name",
      );
      assert.equal(reader.extract("absent"), null, "an absent member is a miss");
      assert.equal(reader.extract("constructor"), null, "an inherited member is a miss");
      assert.equal(reader.extract("bodytext"), null, "a present non-string is not ciphertext");
    }
  });
});

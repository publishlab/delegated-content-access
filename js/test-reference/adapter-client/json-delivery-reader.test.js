// @ts-check
//
// The baseline delivery reader on its own: each constructor refusal, one code
// each, and what `extract` answers. `JsonDeliveryReader` reads the serialized
// UTF-8 document of the data format's object delivery, as `writeJsonDelivery`
// emits it, with the publisher origin the host supplies beside it. A real render
// through the issuer is in `test-profiles/dca-profile-baseline.test.js`.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { JsonDeliveryReader } from "../../adapter-client/JsonDeliveryReader.js";
import { writeJsonDelivery } from "../../adapter-publisher/writeJsonDelivery.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { INHERITED } from "../../test-lib/fixtures/inherited-names.js";

const PUB = "https://www.news-site.example";
const CONTEXT = Object.freeze({ publisherOrigin: PUB });
const DCA_DATA = Object.freeze({
  version: "1",
  contentData: [{ contentName: "bodytext" }, { contentName: "premiumtext" }],
  resource: { data: { section: "politics" } },
});

/** @param {string} json */
const bytesOf = (json) => new TextEncoder().encode(json);

/** @param {string} json */
const readerOf = (json) => new JsonDeliveryReader(bytesOf(json), CONTEXT);

describe("The JSON delivery reader, the argument refusals", () => {
  test("bytes that are not a Uint8Array are a config refusal, a string included", async () => {
    // A JavaScript type guard (PORTING.md, Bytes): a port that holds bytes in
    // a binary string need not tell text apart from bytes here.
    const json = '{"version":"1"}';
    for (const bytes of [json, bytesOf(json).buffer, [...bytesOf(json)], null, undefined]) {
      await refuses(
        () => new JsonDeliveryReader(/** @type {any} */ (bytes), CONTEXT),
        { code: "bad_config", message: /bytes/ },
        `a ${bytes === null ? "null" : typeof bytes} delivery`,
      );
    }
  });

  test("a missing context or one without a canonical origin is a config refusal", async () => {
    const bytes = bytesOf('{"version":"1"}');
    for (const context of [
      undefined,
      null,
      {},
      { publisherOrigin: "" },
      { publisherOrigin: "null" },
      { publisherOrigin: `${PUB}/` },
      { publisherOrigin: `${PUB}/article` },
      { publisherOrigin: "HTTPS://WWW.NEWS-SITE.EXAMPLE" },
      { publisherOrigin: "ftp://news-site.example" },
    ]) {
      await refuses(
        () => new JsonDeliveryReader(bytes, /** @type {any} */ (context)),
        "bad_config",
        `a context of ${JSON.stringify(context)}`,
      );
    }
  });

  test("a context member other than publisherOrigin is refused by name", async () => {
    await refuses(
      () =>
        new JsonDeliveryReader(
          bytesOf('{"version":"1"}'),
          /** @type {any} */ ({ publisherOrigin: PUB, url: `${PUB}/article` }),
        ),
      { code: "unsupported_option", message: /url/ },
      "an unknown context member",
    );
  });
});

describe("The JSON delivery reader, the document refusals", () => {
  test("malformed UTF-8 is a page refusal, even inside a string", async () => {
    for (const bytes of [
      Uint8Array.of(0x7b, 0x22, 0x76, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d), // {"v":"<ff>"}
      Uint8Array.of(0x7b, 0x22, 0x76, 0x22, 0x3a, 0x22, 0xc3, 0x22, 0x7d), // a cut sequence
      Uint8Array.of(0x7b, 0x22, 0x76, 0x22, 0x3a, 0x22, 0xed, 0xa0, 0x80, 0x22, 0x7d), // a surrogate
    ]) {
      await refuses(
        () => new JsonDeliveryReader(bytes, CONTEXT),
        "bad_page",
        `the octets ${Buffer.from(bytes).toString("hex")}`,
      );
    }
  });

  test("a repeated or misplaced BOM, or malformed input after it, refuses the page", async () => {
    for (const bytes of [
      bytesOf('\uFEFF\uFEFF{"version":"1"}'),
      bytesOf(' \uFEFF{"version":"1"}'),
      Uint8Array.of(0xef, 0xbb, 0xbf, 0xff),
      bytesOf("\uFEFF"),
      bytesOf('\uFEFF{"version":'),
      bytesOf("\uFEFF[]"),
      // Each differs from the BOM `EF BB BF` in one octet and is no BOM.
      Uint8Array.of(0xe2, 0xbb, 0xbf, ...bytesOf("{}")),
      Uint8Array.of(0xef, 0xbc, 0xbf, ...bytesOf("{}")),
      Uint8Array.of(0xef, 0xbb, 0xbe, ...bytesOf("{}")),
    ]) {
      await refuses(
        () => new JsonDeliveryReader(bytes, CONTEXT),
        "bad_page",
        "an invalid BOM document",
      );
    }
  });

  test("empty input and text that is not JSON are page refusals", async () => {
    for (const json of ["", " ", '{"version": "1", "reso', "{version:1}", '{"a":1} {"b":2}']) {
      await refuses(() => readerOf(json), "bad_page", `the text ${JSON.stringify(json)}`);
    }
  });

  test("a document that is not a non-array object is a page refusal", async () => {
    for (const json of ["42", '"a string"', "null", "true", "[]", '[{"version":"1"}]']) {
      await refuses(
        () => readerOf(json),
        { code: "bad_page", message: /not an object/ },
        `a document of ${json}`,
      );
    }
  });

  test("a present sealedContent that is not an array is a page refusal", async () => {
    for (const value of ["null", "{}", '{"bodytext":"QUJD"}', '"QUJD"', "42", "true"]) {
      await refuses(
        () => readerOf(`{"version":"1","sealedContent":${value}}`),
        { code: "bad_page", message: /sealedContent/ },
        `a sealedContent of ${value}`,
      );
    }
  });

  test("a sealedContent record whose contentName is outside the grammar refuses the whole document", async () => {
    for (const name of ["bad name", "", "1bodytext", "a".repeat(65), 7, null]) {
      await refuses(
        () =>
          readerOf(
            `{"version":"1","sealedContent":[{"contentName":"bodytext","content":"QUJD"},` +
              `{"contentName":${JSON.stringify(name)},"content":"QUJD"}]}`,
          ),
        { code: "bad_page", message: /grammar/ },
        `a carrier record named ${JSON.stringify(name)}`,
      );
    }
    await refuses(
      () => readerOf('{"version":"1","sealedContent":[{"content":"QUJD"}]}'),
      { code: "bad_page", message: /grammar/ },
      "a carrier record with no contentName",
    );
  });

  test("a sealedContent element that is not a record supplies nothing, and its siblings read", () => {
    const reader = readerOf(
      '{"version":"1","sealedContent":[null,"QUJD",["bodytext","WFla"],' +
        '{"contentName":"bodytext","content":"QUJD"},42]}',
    );
    assert.equal(reader.extract("bodytext"), "QUJD");
  });

  test("the markup form's bytes are a page refusal", async () => {
    // The HTML carrier is another profile's form. A client that reads JSON
    // finds no JSON document in it.
    const markup = writeMarkupDelivery({
      dcaData: { ...DCA_DATA },
      sealedContent: { bodytext: "QUJD" },
    });

    await refuses(() => readerOf(markup), "bad_page", "markup is not the JSON document");
  });
});

describe("The JSON delivery reader, what it answers", () => {
  test("the writer's bytes read back: dcaData without sealedContent, and each ciphertext", () => {
    const sealedContent = { bodytext: "QUJD", premiumtext: "WFla" };
    const reader = new JsonDeliveryReader(
      writeJsonDelivery({ dcaData: DCA_DATA, sealedContent }),
      CONTEXT,
    );

    assert.deepEqual(reader.dcaData, DCA_DATA);
    assert.equal(Object.hasOwn(reader.dcaData, "sealedContent"), false, "split off dcaData");
    assert.equal(reader.publisherOrigin, PUB);
    assert.equal(reader.extract("bodytext"), "QUJD");
    assert.equal(reader.extract("premiumtext"), "WFla");
  });

  test("one initial UTF-8 BOM preserves the document and ciphertext answers", () => {
    const document = writeJsonDelivery({
      dcaData: { ...DCA_DATA, description: "\uFEFFinside string" },
      sealedContent: { bodytext: "QUJD", premiumtext: "WFla" },
    });
    const ordinary = new JsonDeliveryReader(document, CONTEXT);
    for (const whitespace of ["", " \r\n\t"]) {
      const bytes = Uint8Array.of(0xef, 0xbb, 0xbf, ...bytesOf(whitespace), ...document);
      const reader = new JsonDeliveryReader(bytes, CONTEXT);
      assert.deepEqual(reader.dcaData, ordinary.dcaData);
      assert.equal(reader.dcaData.description, "\uFEFFinside string");
      assert.equal(reader.publisherOrigin, ordinary.publisherOrigin);
      for (const name of ["bodytext", "premiumtext", "othertext"]) {
        assert.equal(reader.extract(name), ordinary.extract(name));
      }
      bytes.fill(0x20);
      assert.deepEqual(reader.dcaData, ordinary.dcaData, "the reader still snapshots its input");
    }
  });

  test("a deferred item, a missing carrier and an unknown name are all null", () => {
    const deferred = new JsonDeliveryReader(
      writeJsonDelivery({ dcaData: DCA_DATA, sealedContent: { bodytext: "QUJD" } }),
      CONTEXT,
    );
    assert.equal(deferred.extract("premiumtext"), null, "declared in contentData, not carried");
    assert.equal(deferred.extract("othertext"), null, "not declared at all");

    const none = readerOf('{"version":"1"}');
    assert.equal(none.extract("bodytext"), null, "a document with no sealedContent member");
  });

  test("a content that is not a string supplies no ciphertext, and its siblings still read", () => {
    const reader = readerOf(
      '{"version":"1","sealedContent":[{"contentName":"bodytext","content":"QUJD"},' +
        '{"contentName":"a","content":42},{"contentName":"b","content":null},' +
        '{"contentName":"c","content":{"x":"QUJD"}},{"contentName":"d","content":["QUJD"]},' +
        '{"contentName":"e"}]}',
    );

    assert.equal(reader.extract("bodytext"), "QUJD");
    for (const name of ["a", "b", "c", "d", "e"]) assert.equal(reader.extract(name), null, name);
  });

  test("records resolve by contentName in any order, and the last whole record for one name wins", () => {
    const records = [
      { contentName: "bodytext", content: "QUJD" },
      { contentName: "premiumtext", content: "WFla" },
    ];
    for (const sealedContent of [records, [...records].reverse()]) {
      const reader = readerOf(JSON.stringify({ version: "1", sealedContent }));
      assert.equal(reader.extract("bodytext"), "QUJD");
      assert.equal(reader.extract("premiumtext"), "WFla");
    }

    const replaced = readerOf(
      '{"version":"1","sealedContent":[{"contentName":"bodytext","content":"WFla"},' +
        '{"contentName":"bodytext","content":"QUJD"}]}',
    );
    assert.equal(replaced.extract("bodytext"), "QUJD");

    // Replacement, not merging: a later record without a usable content
    // leaves the item without ciphertext rather than falling back.
    const unusable = readerOf(
      '{"version":"1","sealedContent":[{"contentName":"bodytext","content":"QUJD"},' +
        '{"contentName":"bodytext","content":7}]}',
    );
    assert.equal(unusable.extract("bodytext"), null);
  });

  test("extract reads own members only, and a name outside the grammar is null", () => {
    const reader = readerOf(
      '{"version":"1","sealedContent":[{"contentName":"bodytext","content":"QUJD"}]}',
    );

    for (const name of [...INHERITED, "__proto__", "bad name", ""]) {
      assert.equal(reader.extract(name), null, name);
    }

    // An inherited string is the case the string check alone would let through,
    // so the test puts one on the prototype for the length of one read.
    Object.defineProperty(Object.prototype, "premiumtext", { value: "WFla", configurable: true });
    try {
      assert.equal(reader.extract("premiumtext"), null, "an inherited ciphertext is absent");
    } finally {
      delete (/** @type {any} */ (Object.prototype).premiumtext);
    }
  });

  test("a top-level `__proto__` member stays an own member of dcaData", () => {
    const reader = readerOf('{"version":"1","__proto__":{"polluted":true}}');

    assert.equal(Object.hasOwn(reader.dcaData, "__proto__"), true);
    assert.equal(Object.getPrototypeOf(reader.dcaData), Object.prototype);
    assert.equal(/** @type {any} */ (reader.dcaData).polluted, undefined);
  });

  test("of two members with one name, the last is the one read", () => {
    const reader = readerOf(
      '{"version":"0","version":"1","sealedContent":[{"contentName":"bodytext",' +
        '"content":"WFla","content":"QUJD"}]}',
    );

    assert.equal(reader.dcaData.version, "1");
    assert.equal(reader.extract("bodytext"), "QUJD");
  });

  test("the reader checks no dca-data member: that is DcaData's admission", () => {
    const reader = readerOf('{"version":"vX","sealedContent":[]}');

    assert.deepEqual(reader.dcaData, { version: "vX" });
  });

  test("the bytes are read once: a later change to them changes no answer", () => {
    const bytes = writeJsonDelivery({ dcaData: DCA_DATA, sealedContent: { bodytext: "QUJD" } });
    const reader = new JsonDeliveryReader(bytes, CONTEXT);
    bytes.fill(0x20);

    assert.deepEqual(reader.dcaData, DCA_DATA);
    assert.equal(reader.extract("bodytext"), "QUJD");
  });
});

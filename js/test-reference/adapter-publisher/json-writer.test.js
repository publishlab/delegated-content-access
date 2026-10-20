// @ts-check
//
// The baseline delivery writer on its own: the bytes it emits and each refusal,
// one code each. `writeJsonDelivery` takes the pair a Sealer returns and emits
// the serialized document of the data format's object delivery. The round trip
// through `JsonDeliveryReader` is in `test-reference/adapter-client/json-delivery-reader.test.js`,
// and a real render through the issuer is in `test-profiles/dca-profile-baseline.test.js`.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { writeJsonDelivery } from "../../adapter-publisher/writeJsonDelivery.js";
import { refuses } from "../../test-lib/helpers/refuses.js";

const DCA_DATA = Object.freeze({ version: "1", resource: { data: { section: "politics" } } });
const SEALED = Object.freeze({ bodytext: "QUJD" });

/** @param {Uint8Array} bytes */
const text = (bytes) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);

describe("The JSON delivery writer, the document it emits", () => {
  test("the bytes are the UTF-8 of one object: the dcaData members, then sealedContent", () => {
    const bytes = writeJsonDelivery({ dcaData: DCA_DATA, sealedContent: SEALED });

    assert.ok(bytes instanceof Uint8Array, "the interchange form is bytes");
    assert.equal(text(bytes), JSON.stringify({ ...DCA_DATA, sealedContent: SEALED }));
    assert.equal(bytes[0], 0x7b, "the first octet is `{`: no byte order mark");
  });

  test("non-ASCII text is UTF-8, and markup sequences are written as they are", () => {
    // The JSON form is no script block, so nothing in it is rewritten for HTML.
    const data = "Blåbær </script><!-- \u{1f600}";
    const bytes = writeJsonDelivery({
      dcaData: { version: "1", resource: { data } },
      sealedContent: {},
    });

    assert.equal(JSON.parse(text(bytes)).resource.data, data);
    assert.ok(text(bytes).includes("</script><!--"), "no \\u003c rewrite in the JSON form");
    assert.ok(Buffer.from(bytes).includes(Buffer.from([0xc3, 0xa5])), "å is its two UTF-8 octets");
  });

  test("an empty sealedContent is written as an empty member, not left out", () => {
    const bytes = writeJsonDelivery({ dcaData: { version: "1" }, sealedContent: {} });

    assert.equal(text(bytes), '{"version":"1","sealedContent":{}}');
  });

  test("each call returns new bytes and the writer keeps nothing between calls", () => {
    const first = writeJsonDelivery({ dcaData: DCA_DATA, sealedContent: SEALED });
    const second = writeJsonDelivery({ dcaData: DCA_DATA, sealedContent: SEALED });

    assert.notEqual(first, second);
    first.fill(0);
    assert.equal(text(second), JSON.stringify({ ...DCA_DATA, sealedContent: SEALED }));
  });

  test("an own `__proto__` member of dcaData stays an own member of the document", () => {
    const dcaData = JSON.parse('{"version":"1","__proto__":{"x":1}}');
    const document = JSON.parse(text(writeJsonDelivery({ dcaData, sealedContent: {} })));

    assert.equal(Object.hasOwn(document, "__proto__"), true);
    assert.deepEqual(document["__proto__"], { x: 1 });
  });

  test("an inherited sealedContent or ciphertext is not a member, so it is not written", () => {
    const dcaData = Object.assign(Object.create({ sealedContent: { bodytext: "WFla" } }), {
      version: "1",
    });
    const sealedContent = Object.assign(Object.create({ premiumtext: "WFla" }), SEALED);

    assert.equal(
      text(writeJsonDelivery({ dcaData, sealedContent })),
      '{"version":"1","sealedContent":{"bodytext":"QUJD"}}',
    );
  });
});

describe("The JSON delivery writer, refusals", () => {
  test("a render that is not a record is a config refusal", async () => {
    for (const render of [null, undefined, 42, "a string", []]) {
      await refuses(
        () => writeJsonDelivery(/** @type {any} */ (render)),
        "bad_config",
        `a render of ${JSON.stringify(render)}`,
      );
    }
  });

  test("a render member the writer does not take is refused by name", async () => {
    await refuses(
      () =>
        writeJsonDelivery(/** @type {any} */ ({ dcaData: DCA_DATA, sealedContent: {}, page: 1 })),
      { code: "unsupported_option", message: /page/ },
      "an unknown render member",
    );
  });

  test("a missing or non-object dcaData is a config refusal", async () => {
    for (const dcaData of [undefined, null, "{}", 42, []]) {
      await refuses(
        () => writeJsonDelivery(/** @type {any} */ ({ dcaData, sealedContent: {} })),
        { code: "bad_config", message: /dcaData/ },
        `a dcaData of ${JSON.stringify(dcaData)}`,
      );
    }
  });

  test("a missing or non-object sealedContent is a config refusal", async () => {
    for (const sealedContent of [undefined, null, "QUJD", 42, ["QUJD"]]) {
      await refuses(
        () => writeJsonDelivery(/** @type {any} */ ({ dcaData: DCA_DATA, sealedContent })),
        { code: "bad_config", message: /sealedContent/ },
        `a sealedContent of ${JSON.stringify(sealedContent)}`,
      );
    }
  });

  test("a dcaData that already has its own sealedContent member is a config refusal", async () => {
    await refuses(
      () =>
        writeJsonDelivery({
          dcaData: { version: "1", sealedContent: { bodytext: "WFla" } },
          sealedContent: SEALED,
        }),
      { code: "bad_config", message: /already carries/ },
      "two ciphertext maps for one document",
    );
  });

  test("a sealedContent member name outside the contentName grammar is a name refusal", async () => {
    for (const sealedContent of [
      { 'bad"name': "QUJD" },
      { "</script>": "QUJD" },
      { "": "QUJD" },
      { ["a".repeat(65)]: "QUJD" },
      JSON.parse('{"__proto__":"QUJD"}'),
    ]) {
      await refuses(
        () => writeJsonDelivery({ dcaData: DCA_DATA, sealedContent }),
        "bad_name",
        `a carrier keyed ${JSON.stringify(Object.keys(sealedContent))}`,
      );
    }
  });

  test("a ciphertext that is not canonical base64url is a name refusal", async () => {
    // Padding, a standard-base64 character, nonzero unused trailing bits, a
    // character outside both alphabets, and a value that is no string.
    for (const ciphertext of ["QUJD=", "QU+D", "QUJ", "QU<D", 42, null]) {
      await refuses(
        () =>
          writeJsonDelivery({
            dcaData: DCA_DATA,
            sealedContent: /** @type {any} */ ({ bodytext: ciphertext }),
          }),
        { code: "bad_name", message: /base64url/ },
        `a ciphertext of ${JSON.stringify(ciphertext)}`,
      );
    }
  });

  test("a value JSON.stringify cannot serialize is a config refusal", async () => {
    /** @type {any} */
    const cycle = { version: "1" };
    cycle.self = cycle;
    for (const [label, dcaData] of [
      ["a bigint", { version: "1", n: 1n }],
      ["a cycle", cycle],
    ]) {
      await refuses(
        () => writeJsonDelivery({ dcaData: /** @type {object} */ (dcaData), sealedContent: {} }),
        { code: "bad_config", message: /JSON cannot represent/ },
        /** @type {string} */ (label),
      );
    }
  });
});

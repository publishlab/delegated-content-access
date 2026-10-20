// @ts-check
//
// Standalone markup-delivery writer behavior. The writer-to-reader interaction
// proof remains in markup-placement.test.js.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import {
  inertJsonScript,
  writeMarkupDelivery,
} from "../../adapter-publisher/writeMarkupDelivery.js";
import { DATA_CLASS, SEALED_CLASS } from "../../core-shared/markupPlacement.js";
import { isContentName } from "../../core-shared/names.js";
import { actorWorld } from "../../demo/scenarios/world.js";
import { CONTENT_NAME } from "../../demo/scenarios/fixtures.js";

/**
 * One render, split the way the writer takes it: dca-data and the sealed content
 * beside it, as `asJson()` hands them over with the ciphertext under a member.
 *
 * @param {any} page
 * @returns {{ dcaData: any, sealedContent: Record<string, string> }}
 */
function renderValues(page) {
  const { sealedContent, ...dcaData } = page.asJson();
  return { dcaData, sealedContent };
}

/**
 * The text of the sealed-content block, between its own opening and closing
 * tags - what a reader hands to `JSON.parse`.
 *
 * @param {string} markup
 * @returns {string}
 */
function sealedBlockText(markup) {
  const block =
    /<script type="application\/json" class="dca-sealed-content">([\s\S]*?)<\/script>/.exec(markup);
  assert.ok(block, "the markup carries a sealed-content script block");
  return block[1];
}

/** The dca-data JSON text, after the writer's script-safe rewrite. */
function dataBlockText(markup) {
  const block = /<script type="application\/json" class="dca-data">([\s\S]*?)<\/script>/.exec(
    markup,
  );
  assert.ok(block, "the markup carries a dca-data script block");
  return block[1];
}

/** A deterministic finite IEEE-754 sample that crosses a PHP double unchanged. */
function finiteIeee754Samples() {
  const view = new DataView(new ArrayBuffer(8));
  const samples = [
    -0,
    0,
    Number.MIN_VALUE,
    -Number.MIN_VALUE,
    1e-7,
    1e-6,
    1e-5,
    1e20,
    1e21,
    -1e21,
    Number.MAX_VALUE,
    -Number.MAX_VALUE,
    9007199254740991,
    0.30000000000000004,
    NaN,
    Infinity,
    -Infinity,
  ];
  for (let index = 0; index < 4096; index += 1) {
    const exponent = (index * 7919) % 2047;
    const sign = (index & 1) === 0 ? 0 : 0x80000000;
    const fractionHigh = (index * 2654435761) & 0xfffff;
    const fractionLow = (index * 2246822519) >>> 0;
    view.setUint32(0, sign | (exponent << 20) | fractionHigh, false);
    view.setUint32(4, fractionLow, false);
    samples.push(view.getFloat64(0, false));
  }
  return samples;
}

describe("The markup delivery writer", () => {
  test("the emitted markup carries the two inert JSON script blocks the reader queries", async () => {
    const { render } = await actorWorld();
    const { dcaData, sealedContent } = renderValues(await render("A"));
    const markup = writeMarkupDelivery({ dcaData, sealedContent });

    // The writer built its elements out of the shared tokens, so the markup
    // carries exactly what the reader's selectors go looking for.
    assert.ok(
      markup.includes(`<script type="application/json" class="${DATA_CLASS}">`),
      "the data block is an inert JSON script",
    );
    assert.ok(
      markup.includes(`<script type="application/json" class="${SEALED_CLASS}">`),
      "so is the sealed-content block",
    );

    // And nothing of the retired carrier: no template, no per-item div, no
    // name attribute. The name is a JSON member now.
    assert.equal(markup.includes("<template"), false, "no template fragment");
    assert.equal(markup.includes("<div"), false, "no per-item div");
    assert.equal(markup.includes("data-dca-content-name"), false, "no name attribute");
  });

  test("the sealed-content block is one JSON object of contentName to ciphertext", async () => {
    const { render } = await actorWorld();
    const { dcaData, sealedContent } = renderValues(await render("A"));
    const markup = writeMarkupDelivery({ dcaData, sealedContent });

    const parsed = JSON.parse(sealedBlockText(markup));
    assert.deepEqual(parsed, sealedContent, "every item, byte for byte");
    assert.equal(Array.isArray(parsed), false, "an object, never an array");
    assert.ok(Object.hasOwn(parsed, CONTENT_NAME), "the item is filed under its own name");
  });

  test("the emission is exact: two blocks, the sealed JSON on its own line", () => {
    const markup = writeMarkupDelivery({
      dcaData: { version: "1" },
      sealedContent: { bodytext: "QUJD", premiumtext: "REVG" },
    });

    assert.equal(
      markup,
      [
        '<script type="application/json" class="dca-data">{"version":"1"}</script>',
        '<script type="application/json" class="dca-sealed-content">',
        '{"bodytext":"QUJD","premiumtext":"REVG"}',
        "</script>",
      ].join("\n"),
    );
  });

  test("the data block keeps JSON.stringify number spelling and ordinary marker-named members", () => {
    const dcaData = {
      version: "1",
      $undef: "ordinary data, not bridge undefined",
      $sym: "ordinary data, not bridge symbol",
      samples: finiteIeee754Samples(),
    };
    const markup = writeMarkupDelivery({ dcaData, sealedContent: {} });

    assert.equal(dataBlockText(markup), JSON.stringify(dcaData));
  });

  test("the data block quotes ordered index names and preserves every sparse-array hole", () => {
    const leading = [];
    leading[1] = "one";
    const interior = ["zero"];
    interior[2] = "two";
    const trailing = ["zero"];
    trailing.length = 3;
    const allHoles = new Array(3);
    const dcaData = {
      4294967295: "ordinary after indexes",
      2: "two",
      "01": "leading-zero ordinary",
      1: "one",
      4294967294: "last index",
      sparse: { leading, interior, trailing, allHoles },
    };
    const markup = writeMarkupDelivery({ dcaData, sealedContent: {} });

    assert.equal(
      dataBlockText(markup),
      '{"1":"one","2":"two","4294967294":"last index","4294967295":"ordinary after indexes","01":"leading-zero ordinary","sparse":{"leading":[null,"one"],"interior":["zero",null,"two"],"trailing":["zero",null,null],"allHoles":[null,null,null]}}',
    );
  });

  test("the writer emits an empty object when every item is deferred", () => {
    const markup = writeMarkupDelivery({ dcaData: { version: "1" }, sealedContent: {} });

    assert.equal(sealedBlockText(markup), "\n{}\n", "an empty carrier, not an absent one");
    assert.deepEqual(JSON.parse(sealedBlockText(markup)), {});
  });

  test("dca-data is an object, never an array-shaped carrier", () => {
    assert.throws(
      () => writeMarkupDelivery({ dcaData: [], sealedContent: {} }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });

  test("a contentName outside the grammar is refused at emission, not written into the JSON", () => {
    for (const contentName of ['bad"name', "bad\\name", "</script>", "bad|name", ""]) {
      assert.throws(
        () =>
          writeMarkupDelivery({
            dcaData: { version: "1" },
            sealedContent: { [contentName]: "QUJD" },
          }),
        (/** @type {any} */ e) => e.code === "bad_name",
        `a name of ${JSON.stringify(contentName)} never reaches the markup`,
      );
    }
  });

  test("a ciphertext outside canonical base64url is refused at emission, not written into the JSON", () => {
    for (const ciphertext of [
      "QUJD</script><img src=x onerror=alert(1)>",
      'QUJD"}',
      "<!--<script>",
      "QUJD_-",
      "REVG-_",
      "A",
      "QQ=",
      "QR",
    ]) {
      assert.throws(
        () =>
          writeMarkupDelivery({ dcaData: { version: "1" }, sealedContent: { body: ciphertext } }),
        (/** @type {any} */ e) => e.code === "bad_name",
        `a ciphertext carrying ${JSON.stringify(ciphertext)} never reaches the markup`,
      );
    }

    // Canonical values in every permitted length class, empty included,
    // stay byte-identical.
    const emitted = writeMarkupDelivery({
      dcaData: { version: "1" },
      sealedContent: {
        empty: "",
        onebyte: "QQ",
        twobytes: "AAA",
        fullquantum: "QUJD",
        urlalphabet: "QUJD_w",
      },
    });
    assert.deepEqual(JSON.parse(sealedBlockText(emitted)), {
      empty: "",
      onebyte: "QQ",
      twobytes: "AAA",
      fullquantum: "QUJD",
      urlalphabet: "QUJD_w",
    });
  });

  test("a non-string ciphertext is refused rather than serialized as its JSON type", () => {
    for (const ciphertext of [null, 42, {}, [], undefined, true]) {
      assert.throws(
        () =>
          writeMarkupDelivery({
            dcaData: { version: "1" },
            sealedContent: { body: /** @type {any} */ (ciphertext) },
          }),
        (/** @type {any} */ e) => e.code === "bad_name",
        `a ciphertext of ${JSON.stringify(ciphertext) ?? "undefined"} is not a sealed blob`,
      );
    }
  });

  test("nothing the two accepted alphabets admit can end the sealed script block", () => {
    // The block is inert because of what may go into it, with no rewrite
    // afterwards: an element in script-data state ends at `</script` and at
    // nothing else, and `<` is the character that starts it. Neither alphabet
    // carries one, so the check below is what the safety rests on.
    for (let code = 0; code < 0x2500; code += 1) {
      const character = String.fromCodePoint(code);

      // The name grammar, asked through the shared oracle both sides use.
      if (isContentName(`a${character}`)) {
        assert.equal(
          character,
          character.replace("<", ""),
          `a name may not carry ${JSON.stringify(character)}`,
        );
      }

      // The ciphertext alphabet, asked through the writer itself: the
      // prefix plus one character is a complete canonical quantum, so a
      // character it accepts reaches the block.
      let accepted = true;
      try {
        writeMarkupDelivery({
          dcaData: { version: "1" },
          sealedContent: { body: `QUJ${character}` },
        });
      } catch {
        accepted = false;
      }
      if (accepted) {
        assert.equal(
          character,
          character.replace("<", ""),
          `a ciphertext may not carry ${JSON.stringify(character)}`,
        );
      }
    }

    // And on a real render, the only terminator in the whole emission is
    // the one closing each of the two blocks.
    const markup = writeMarkupDelivery({
      dcaData: { version: "1" },
      sealedContent: { "sponsor:intro": "QUJD", body_text: "REVG-w" },
    });
    assert.equal(/** @type {RegExpMatchArray} */ (markup.match(/<\/script[\s/>]/gi)).length, 2);
  });

  test("the writer takes dcaData and sealedContent and refuses any other member", () => {
    // An optional carrier, such as the proposed content map, is written by its
    // own extension, so a caller still handing one to the base writer hears
    // about it instead of getting a page without it.
    for (const member of ["contentMap", "carriers", "page"]) {
      assert.throws(
        () =>
          writeMarkupDelivery(
            /** @type {any} */ ({ dcaData: { version: "1" }, sealedContent: {}, [member]: {} }),
          ),
        (/** @type {any} */ e) => e.code === "unsupported_option",
        `a ${member} member is refused`,
      );
    }
  });

  test("the markup writer refuses an array of sealed content", () => {
    assert.throws(
      () =>
        writeMarkupDelivery(/** @type {any} */ ({ dcaData: { version: "1" }, sealedContent: [] })),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("unrepresentable render data is a typed configuration refusal", () => {
    const cyclic = {};
    cyclic.self = cyclic;
    for (const dcaData of [
      { value: 1n },
      cyclic,
      {
        toJSON() {
          return undefined;
        },
      },
    ]) {
      assert.throws(() => writeMarkupDelivery({ dcaData, sealedContent: {} }), {
        code: "bad_config",
      });
    }
    for (const render of ["bad", [1], null]) {
      assert.throws(() => writeMarkupDelivery(render), { code: "bad_config" });
    }
  });

  test("the writer refuses a render it cannot emit", () => {
    assert.throws(
      () => writeMarkupDelivery({ sealedContent: {} }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
    assert.throws(
      () => writeMarkupDelivery({ dcaData: { version: "1" } }),
      (/** @type {any} */ e) => e.code === "bad_config",
    );
  });
});

describe("The inert JSON script block", () => {
  test("it writes one application/json script element with the class and the JSON", () => {
    assert.equal(
      inertJsonScript("x-carrier", { version: "1", list: [1, "two"] }),
      '<script type="application/json" class="x-carrier">{"version":"1","list":[1,"two"]}</script>',
    );
  });

  test("text that could end or re-open the script element is escaped and parses back", () => {
    const value = { target: '[data-slot="</script><!--x"]', upper: "</SCRIPT>" };
    const block = inertJsonScript("x-carrier", value);
    const text = /** @type {RegExpExecArray} */ (
      /^<script type="application\/json" class="x-carrier">([\s\S]*)<\/script>$/.exec(block)
    )[1];
    assert.equal(/<\/script/i.test(text), false, "no terminator inside the block");
    assert.equal(text.includes("<!--"), false, "no escaped-state opener inside the block");
    assert.deepEqual(JSON.parse(text), value);
  });

  test("a class outside the ident grammar never reaches the markup", () => {
    for (const className of ['a"b', "a b", "a>b", "", "1a", "--", "a&b"]) {
      assert.throws(
        () => inertJsonScript(className, {}),
        (/** @type {any} */ e) => e.code === "bad_config",
        `a class of ${JSON.stringify(className)} is refused`,
      );
    }
  });

  test("the two base carrier tokens stay with the writer that checks their contents", () => {
    for (const className of [DATA_CLASS, SEALED_CLASS]) {
      assert.throws(
        () => inertJsonScript(className, {}),
        (/** @type {any} */ e) => e.code === "bad_config",
        `${className} is written only by writeMarkupDelivery`,
      );
    }
  });

  test("a value JSON cannot represent is refused rather than written as nothing", () => {
    const cycle = {};
    Object.assign(cycle, { cycle });
    for (const value of [undefined, () => 1, Symbol("s"), 1n, cycle]) {
      assert.throws(
        () => inertJsonScript("x-carrier", /** @type {any} */ (value)),
        (/** @type {any} */ e) => e.code === "bad_config",
      );
    }
  });
});

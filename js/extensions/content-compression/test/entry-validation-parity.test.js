// @ts-check
//
// `CompressingSealer.content()` re-implements base `Sealer.content()`'s
// entry-time validation, because the adapter has to refuse a call before it
// buffers it and base only sees the call at seal(). Two copies of one rule set
// drift. Each case here makes one refusing call on both sealers and asserts a
// single code from both, so the copy is pinned by behaviour rather than by
// text, line markers or a commit stamp.

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Encode } from "../../../core-shared/codec.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { composePublisherConfig } from "../../../core-publisher/publisherComposition.js";
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { encode as gzipEncode } from "../core-shared--client-publisher/gzipCodec.js";
import { ARTICLE, GROUP, ISSUER, SIDEBAR, world } from "./world.js";

/** @param {string} code */
const coded = (code) => (/** @type {any} */ error) => error?.code === code;

/** @returns {{ bytes: Uint8Array, contentType: any, contentEncodings: string[] }} */
function descriptor(contentType = "text/html") {
  return { bytes: utf8Encode(ARTICLE), contentType, contentEncodings: [] };
}

/** @type {{ what: string, code: string, call: (sealer: any) => void }[]} */
const CASES = [
  {
    what: "a content name repeated in one render",
    code: "bad_config",
    call: (sealer) => {
      sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: [GROUP] });
      sealer.content("bodytext", SIDEBAR, "text/html", { accessGroups: [GROUP] });
    },
  },
  {
    what: "a content name base refuses on the wire",
    code: "bad_name",
    call: (sealer) => sealer.content("body|text", ARTICLE, "text/html", { accessGroups: [GROUP] }),
  },
  {
    what: "options that are not an object",
    code: "bad_config",
    call: (sealer) => sealer.content("bodytext", ARTICLE, "text/html", "premium"),
  },
  {
    what: "an accessGroups value that is not a list",
    code: "bad_config",
    call: (sealer) => sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: GROUP }),
  },
  {
    what: "a legacy call carrying no content type",
    code: "bad_config",
    call: (sealer) => sealer.content("bodytext", ARTICLE, undefined, { accessGroups: [GROUP] }),
  },
  {
    what: "a missing content type before a malformed accessGroup",
    code: "bad_config",
    call: (sealer) =>
      sealer.content("bodytext", ARTICLE, undefined, { accessGroups: ["pre|mium"] }),
  },
  {
    what: "an accessGroup base refuses on the wire",
    code: "bad_name",
    call: (sealer) =>
      sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: ["pre|mium"] }),
  },
  {
    what: "a descriptor carrying no contentType",
    code: "bad_config",
    call: (sealer) =>
      sealer.content(
        "bodytext",
        { bytes: utf8Encode(ARTICLE), contentEncodings: [] },
        { accessGroups: [GROUP] },
      ),
  },
  {
    what: "a descriptor with a fourth argument beside it",
    code: "bad_config",
    call: (sealer) => sealer.content("bodytext", descriptor(), { accessGroups: [GROUP] }, {}),
  },
  {
    what: "a descriptor member base does not carry",
    code: "unsupported_option",
    call: (sealer) =>
      sealer.content("bodytext", { ...descriptor(), compressed: true }, { accessGroups: [GROUP] }),
  },
];

/**
 * @param {any} sealer
 * @param {(sealer: any) => void} call
 * @returns {string} the refusal code, or how the call ended instead
 */
function refusalOf(sealer, call) {
  sealer.resource("123456", { section: "politics" });
  try {
    call(sealer);
    return "accepted";
  } catch (error) {
    return /** @type {any} */ (error).code ?? "untyped";
  }
}

for (const { what, code, call } of CASES) {
  test(`base and the adapter refuse ${what} with the same code`, async () => {
    const { sealerConfig } = await world();

    assert.deepEqual(
      [
        refusalOf(new Sealer(sealerConfig()), call),
        refusalOf(new CompressingSealer(sealerConfig()), call),
      ],
      [code, code],
    );
  });
}

/**
 * @param {() => unknown} call
 * @returns {{ code: string, message: string }|"accepted"}
 */
function outcomeOf(call) {
  try {
    call();
    return "accepted";
  } catch (error) {
    return { code: /** @type {any} */ (error).code, message: /** @type {any} */ (error).message };
  }
}

test("base and the adapter admit an ungrouped item beside a grouped one under a period-key supply", async () => {
  // Groups are optional per item. Under a supply each sealer takes an item
  // with omitted or empty groups, seals it with no `keys` member, and still
  // wraps the grouped item beside it.
  for (const [label, options] of [
    ["omitted", {}],
    ["empty", { accessGroups: [] }],
  ]) {
    const { sealerConfig } = await world();
    for (const sealer of [new Sealer(sealerConfig()), new CompressingSealer(sealerConfig())]) {
      const kind = `${sealer.constructor.name}, ${label} groups`;
      sealer.resource("123456", { section: "politics" });
      sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: [GROUP] });
      assert.equal(sealer.content("sidebar", SIDEBAR, "text/html", options), sealer, kind);
      const { dcaData } = await sealer.seal();
      assert.equal(Object.hasOwn(dcaData.contentData.sidebar, "keys"), false, kind);
      assert.deepEqual(Object.keys(dcaData.contentData.bodytext.keys), [GROUP], kind);
      assert.deepEqual(
        Object.keys(dcaData.issuerData[ISSUER].sealed.contentKeys),
        ["bodytext", "sidebar"],
        kind,
      );
    }
  }
});

test("base and the adapter refuse a named group without a period-key supply alike, before any codec work", async () => {
  // A sealer with no supply could only drop the wraps a group asks for, so
  // both refuse the call that names one, with one code and one message. The
  // adapter refuses at content(), before its gzip codec runs. A malformed
  // group name still meets the name check first, as in base.
  const { sealerConfig } = await world();
  const { periodKeySupply: _supply, ...withoutSupply } = sealerConfig();
  let encodes = 0;
  const gzip = {
    /** @param {Uint8Array} bytes */
    encode: async (bytes) => {
      encodes += 1;
      return gzipEncode(bytes);
    },
  };

  for (const [label, groups, expected] of [
    [
      "a named group",
      [GROUP],
      {
        code: "bad_config",
        message:
          'content "bodytext" names accessGroups, and this publisher holds no periodKeySupply to wrap under',
      },
    ],
    ["a malformed group", ["pre|mium"], undefined],
  ]) {
    const outcomes = [
      new Sealer(withoutSupply),
      new CompressingSealer(withoutSupply, { gzip }),
    ].map((sealer) => {
      sealer.resource("123456", { section: "politics" });
      return outcomeOf(() =>
        sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: groups }),
      );
    });
    assert.deepEqual(outcomes[1], outcomes[0], /** @type {string} */ (label));
    if (expected) assert.deepEqual(outcomes[0], expected, /** @type {string} */ (label));
    else
      assert.equal(
        /** @type {any} */ (outcomes[0]).code,
        "bad_name",
        /** @type {string} */ (label),
      );
  }

  // An ungrouped item still seals on the adapter without a supply, so the
  // refusal above is about the group and not about the configuration.
  const adapter = new CompressingSealer(withoutSupply, { gzip });
  adapter.resource("123456", { section: "politics" });
  adapter.content("bodytext", ARTICLE, "text/html", {});
  assert.equal(encodes, 0, "every refusal came before the codec");
  const { dcaData } = await adapter.seal();
  assert.equal(Object.hasOwn(dcaData.contentData.bodytext, "keys"), false);
  assert.equal(encodes, 1);
});

test("the adapter refuses its descriptor-only contentEncoding option instead of silently ignoring it", async () => {
  const { sealerConfig } = await world();
  const call = (sealer) =>
    sealer.content("bodytext", descriptor(), { accessGroups: [GROUP], contentEncoding: "gzip" });

  assert.deepEqual(
    [
      refusalOf(new Sealer(sealerConfig()), call),
      refusalOf(new CompressingSealer(sealerConfig()), call),
    ],
    ["accepted", "unsupported_option"],
  );
});

/**
 * A contribution that declares one per-item option and copies it onto the
 * item's record, so a render shows which options reached base.
 */
const TAGGING = Object.freeze({
  name: "item-tag-probe",
  itemOptionMembers: ["itemTag"],
  itemPreparation: {
    routes: () => [],
    /** @param {{ items: readonly any[] }} context */
    prepare: async ({ items }) => ({
      contentRecords: Object.fromEntries(
        items
          .filter((item) => Object.hasOwn(item.options, "itemTag"))
          .map((item) => [item.name, { itemTag: item.options.itemTag }]),
      ),
    }),
  },
});

/** @param {any} sealerConfig */
function tagged(sealerConfig) {
  return composePublisherConfig(sealerConfig, TAGGING).config;
}

test("base and the adapter carry a declared item option to the render on every adapter path", async () => {
  const { sealerConfig } = await world();
  /** @type {Record<string, any>} */
  const records = {};
  for (const sealer of [
    new Sealer(tagged(sealerConfig())),
    new CompressingSealer(tagged(sealerConfig())),
  ]) {
    const kind = sealer.constructor.name;
    const compressing = sealer instanceof CompressingSealer;
    const late = { section: "news" };
    sealer.resource("123456", { section: "politics" });
    // Compressed on the adapter, ordinary bytes on base.
    sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: [GROUP], itemTag: late });
    // The adapter's identity path and a descriptor both pass base the item as given.
    sealer.content("sidebar", SIDEBAR, "text/html", {
      accessGroups: [GROUP],
      itemTag: ["side", 2],
      ...(compressing ? { contentEncoding: "identity" } : {}),
    });
    sealer.content("figure", descriptor(), { accessGroups: [GROUP], itemTag: null });
    sealer.content("caption", SIDEBAR, "text/html", { accessGroups: [GROUP] });
    // The option was copied at content(); a later change reaches no render.
    late.section = "changed";
    const { dcaData } = await sealer.seal();
    records[kind] = Object.fromEntries(
      Object.entries(dcaData.contentData).map(([name, record]) => [
        name,
        { itemTag: record.itemTag, encodings: record.contentEncodings },
      ]),
    );
  }
  assert.deepEqual(records.CompressingSealer, {
    bodytext: { itemTag: { section: "news" }, encodings: ["gzip"] },
    sidebar: { itemTag: ["side", 2], encodings: undefined },
    figure: { itemTag: null, encodings: undefined },
    caption: { itemTag: undefined, encodings: ["gzip"] },
  });
  assert.deepEqual(records.Sealer, {
    bodytext: { itemTag: { section: "news" }, encodings: undefined },
    sidebar: { itemTag: ["side", 2], encodings: undefined },
    figure: { itemTag: null, encodings: undefined },
    caption: { itemTag: undefined, encodings: undefined },
  });
});

test("base and the adapter refuse a declared item option that is not plain JSON with the same code", async () => {
  const { sealerConfig } = await world();
  const call = (/** @type {any} */ sealer) =>
    sealer.content("bodytext", ARTICLE, "text/html", {
      accessGroups: [GROUP],
      itemTag: { at: new Date(0) },
    });

  assert.deepEqual(
    [
      refusalOf(new Sealer(tagged(sealerConfig())), call),
      refusalOf(new CompressingSealer(tagged(sealerConfig())), call),
    ],
    ["bad_config", "bad_config"],
  );
});

test("the adapter refuses an item option no selected contribution declared", async () => {
  // Base copies only declared options and passes over the rest; the adapter
  // refuses the rest, so a misspelled or unselected option fails at the call
  // instead of sealing an item without the route it asked for.
  const { sealerConfig } = await world();
  for (const [label, config, options] of [
    ["no contribution", sealerConfig(), { accessGroups: [GROUP], itemTag: "a" }],
    ["a misspelled option", tagged(sealerConfig()), { accessGroups: [GROUP], itemTags: "a" }],
  ]) {
    for (const value of [ARTICLE, descriptor()]) {
      const sealer = new CompressingSealer(config);
      sealer.resource("123456", { section: "politics" });
      const call =
        typeof value === "string"
          ? () => sealer.content("bodytext", value, "text/html", options)
          : () => sealer.content("bodytext", value, options);
      assert.throws(call, coded("unsupported_option"), /** @type {string} */ (label));
    }
  }
});

// Three intentional divergences remain. The extension refuses its own
// contentEncoding option beside an already-represented descriptor, where base
// does not interpret that option. The adapter refuses an item option no
// selected contribution declared, where base passes over it. After seal(), base
// takes another content() call and this buffering adapter does not;
// render-round-trip.test.js pins the latter under 'a sealed adapter takes no
// more content'.

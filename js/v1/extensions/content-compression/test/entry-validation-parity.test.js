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
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { ARTICLE, GROUP, SIDEBAR, world } from "./world.js";

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
    what: "an item with no accessGroup under a period-key supply",
    code: "bad_config",
    call: (sealer) => sealer.content("bodytext", ARTICLE, "text/html", {}),
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

// Two intentional divergences remain. The extension refuses its own
// contentEncoding option beside an already-represented descriptor, where base
// does not interpret that option. After seal(), base takes another content()
// call and this buffering adapter does not; render-round-trip.test.js pins the
// latter under 'a sealed adapter takes no more content'.

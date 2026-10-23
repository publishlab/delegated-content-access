// @ts-check
import test from "node:test";
import assert from "node:assert/strict";

import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { contentRecordOf } from "../../../test-lib/helpers/inspect.js";
import { world } from "./world.js";

/** @param {string[]} contentEncodings */
const prepared = (contentEncodings) => ({
  bytes: new Uint8Array([1, 2, 3]),
  contentType: "application/example",
  contentEncodings,
});

test("default publisher refuses unsupported prepared sequences before codec work", async () => {
  const { sealerConfig } = await world();
  let encodes = 0;
  const sealer = new CompressingSealer(sealerConfig(), {
    gzip: {
      encode: async (bytes) => {
        encodes++;
        return bytes;
      },
    },
  });
  for (const sequence of [["zstd"], ["gzip", "gzip"], ["gzip", "zstd"]]) {
    assert.throws(() => sealer.content("bodytext", prepared(sequence)), {
      code: "unsupported_encoding",
    });
  }
  assert.equal(encodes, 0);
});

test("configured prepared sequence matches the complete ordered list without invoking a codec", async () => {
  const { sealerConfig } = await world();
  const sequences = [["gzip", "zstd"]];
  let encodes = 0;
  const sealer = new CompressingSealer(sealerConfig(), {
    supportedEncodingSequences: sequences,
    gzip: {
      encode: async (bytes) => {
        encodes++;
        return bytes;
      },
    },
  });
  sequences[0].reverse();
  sequences.push(["other"]);
  for (const sequence of [["zstd", "gzip"], ["gzip"], ["gzip", "zstd", "zstd"], ["other"]]) {
    assert.throws(() => sealer.content("bodytext", prepared(sequence)), {
      code: "unsupported_encoding",
    });
  }
  sealer.resource("article", {});
  sealer.content("bodytext", prepared(["gzip", "zstd"]));
  const render = await sealer.seal();
  assert.deepEqual(contentRecordOf(render.dcaData, "bodytext").contentEncodings, ["gzip", "zstd"]);
  assert.equal(
    encodes,
    0,
    "acceptance declares deployment support without implementing or inspecting those codecs",
  );
});

test("baseline sequence selection refuses default raw gzip and permits explicit identity", async () => {
  const { sealerConfig } = await world();
  let encodes = 0;
  const sealer = new CompressingSealer(sealerConfig(), {
    supportedEncodingSequences: [[]],
    gzip: {
      encode: async (bytes) => {
        encodes++;
        return bytes;
      },
    },
  });
  sealer.resource("article", {});
  assert.throws(() => sealer.content("bodytext", "text", "text/plain"), {
    code: "unsupported_encoding",
  });
  assert.throws(() => sealer.content("bodytext", prepared(["gzip"])), {
    code: "unsupported_encoding",
  });
  sealer.content("bodytext", "text", "text/plain", { contentEncoding: "identity" });
  sealer.content("sidebar", prepared([]));
  const render = await sealer.seal();
  assert.equal(contentRecordOf(render.dcaData, "bodytext").contentEncodings, undefined);
  assert.equal(contentRecordOf(render.dcaData, "sidebar").contentEncodings, undefined);
  assert.equal(encodes, 0);
});

test("a wider prepared selection cannot implicitly downgrade raw gzip to identity", async () => {
  const { sealerConfig } = await world();
  const sealer = new CompressingSealer(sealerConfig(), {
    supportedEncodingSequences: [["gzip", "zstd"]],
  });
  assert.throws(() => sealer.content("bodytext", "text", "text/plain"), {
    code: "unsupported_encoding",
  });
  assert.throws(
    () => sealer.content("bodytext", "text", "text/plain", { contentEncoding: "identity" }),
    { code: "unsupported_encoding" },
  );
});

test("malformed supported sequence configuration is refused at construction", async () => {
  const { sealerConfig } = await world();
  for (const value of [
    null,
    {},
    "gzip",
    [],
    ["gzip"],
    [null],
    [[""]],
    [[3]],
    new Array(1),
    [new Array(1)],
  ]) {
    assert.throws(
      () =>
        new CompressingSealer(sealerConfig(), {
          supportedEncodingSequences: /** @type {any} */ (value),
        }),
      { code: "bad_config" },
    );
  }
});

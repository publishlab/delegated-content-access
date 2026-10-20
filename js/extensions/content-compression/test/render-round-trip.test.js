// @ts-check
//
// A compressed render, opened. The publisher compresses each item on its own
// and writes the encoding into the item's record; the client resolves the
// content key the ordinary way and decodes after the authenticated decrypt.

import test from "node:test";
import assert from "node:assert/strict";

import { utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import { syntheticArticle } from "../../../tools/synthetic-html.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { decode, encode } from "../core-shared--client-publisher/gzipCodec.js";
import { openEncodedContent } from "../core-client/openEncodedContent.js";
import {
  ARTICLE,
  GROUP,
  SIDEBAR,
  contentKeyOf,
  ephemeralPool,
  itemOf,
  render,
  world,
} from "./world.js";

/**
 * @param {any} wire
 * @param {string} contentName
 * @param {any} periodKeySupply
 * @param {object} [extra]
 */
function open(wire, contentName, periodKeySupply, extra = {}) {
  return openEncodedContent({
    item: itemOf(wire, contentName),
    ciphertext: wire.sealedContent[contentName],
    resolveKey: () => contentKeyOf(wire, contentName, periodKeySupply),
    ...extra,
  });
}

test("the publisher refuses a codec that returns two gzip members", async () => {
  const { sealerConfig } = await world();
  const gzip = {
    encode: async (bytes) => {
      const member = await encode(bytes);
      const joined = new Uint8Array(member.length * 2);
      joined.set(member);
      joined.set(member, member.length);
      return joined;
    },
  };
  const sealer = new CompressingSealer(sealerConfig(), { gzip });
  sealer.resource("123456", { section: "politics" });
  sealer.content("bodytext", ARTICLE, "text/html");
  await assert.rejects(() => sealer.seal(), { code: "bad_encoding" });
});

test("a codec cannot change item bytes, and a corrected retry still opens both original items", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  let corrupt = true;
  const sealer = new CompressingSealer(sealerConfig(), {
    gzip: {
      encode: async (bytes) => {
        const output = bytes.slice();
        if (corrupt) output[0] ^= 1;
        return encode(output);
      },
    },
  });
  sealer
    .resource("123456", { section: "politics" })
    .content("bodytext", ARTICLE, "text/html", { accessGroups: [GROUP] })
    .content("sidebar", SIDEBAR, "text/html", { accessGroups: [GROUP] });
  await assert.rejects(() => sealer.seal(), { code: "bad_encoding" });
  corrupt = false;
  const sealed = await sealer.seal();
  const wire = JSON.parse(
    JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
  );
  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
  assert.equal(utf8Decode(await open(wire, "sidebar", periodKeySupply)), SIDEBAR);
});

test("the default opener refuses a published two-member gzip item", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const first = await encode(utf8Encode(ARTICLE));
  const second = await encode(utf8Encode("<p>APPENDED</p>"));
  const bytes = new Uint8Array(first.length + second.length);
  bytes.set(first);
  bytes.set(second, first.length);
  const wire = await render(new Sealer(sealerConfig()), [
    {
      name: "bodytext",
      value: { bytes, contentType: "text/html", contentEncodings: ["gzip"] },
    },
  ]);
  await assert.rejects(() => open(wire, "bodytext", periodKeySupply), {
    code: "bad_encoding",
  });
});

test("a short body round trips through gzip", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const wire = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: ARTICLE },
  ]);

  assert.deepEqual(wire.contentData.bodytext.contentEncodings, ["gzip"]);
  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
});

test("a 30 KB synthetic body round trips through gzip", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const body = syntheticArticle({ bytes: 30_000, seed: 3 });
  assert.ok(body.length > 25_000, `the generator produced ${body.length} bytes`);

  const wire = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: body },
  ]);

  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), body);
});

test("an item named identity carries no encoding member and opens undecoded", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const wire = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: ARTICLE },
    { name: "sidebar", value: SIDEBAR, options: { contentEncoding: "identity" } },
  ]);

  assert.equal(Object.hasOwn(wire.contentData.sidebar, "contentEncodings"), false);
  assert.equal(utf8Decode(await open(wire, "sidebar", periodKeySupply)), SIDEBAR);
  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
});

test("a legacy call with no content type is refused at that call, and the render carries on", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const sealer = new CompressingSealer(sealerConfig());
  sealer.resource("123456", { section: "politics" });

  // The shared representation normalizer refuses this at entry, so the bad
  // call does not poison the adapter's buffered render.
  assert.throws(() => sealer.content("bodytext", ARTICLE, undefined, { accessGroups: [GROUP] }), {
    code: "bad_config",
  });

  sealer.content("sidebar", SIDEBAR, "text/html", { accessGroups: [GROUP] });
  const sealed = await sealer.seal();
  const wire = JSON.parse(
    JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
  );

  assert.deepEqual(Object.keys(wire.contentData), ["sidebar"]);
  assert.equal(utf8Decode(await open(wire, "sidebar", periodKeySupply)), SIDEBAR);
});

test("bytes handed to content() round trip and can be mutated afterwards", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const bytes = utf8Encode(ARTICLE);

  const sealer = new CompressingSealer(sealerConfig());
  sealer
    .resource("123456", { section: "politics" })
    .content("bodytext", bytes, "text/html", { accessGroups: [GROUP] })
    .content("sidebar", SIDEBAR, "text/html", { accessGroups: [GROUP] });
  bytes.fill(0x41);
  const sealed = await sealer.seal();
  const wire = JSON.parse(
    JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
  );

  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
  assert.equal(utf8Decode(await open(wire, "sidebar", periodKeySupply)), SIDEBAR);
});

test("a sealed adapter takes no more content, and a second seal carries the same items", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const sealer = new CompressingSealer(sealerConfig());
  sealer
    .resource("123456", { section: "politics" })
    .content("bodytext", ARTICLE, "text/html", { accessGroups: [GROUP] })
    .content("sidebar", SIDEBAR, "text/html", { accessGroups: [GROUP] });

  const first = await sealer.seal();

  assert.throws(() => sealer.content("extra", ARTICLE, "text/html", { accessGroups: [GROUP] }), {
    code: "bad_config",
  });

  // The second seal delegates to the held base sealer, which already holds
  // what the first seal handed it: the same names, one gzip layer each,
  // compressed once. Base draws a fresh renderId and fresh nonces per seal,
  // so the two renders carry the same items without being byte-equal.
  const second = await sealer.seal();
  assert.deepEqual(Object.keys(second.dcaData.contentData), Object.keys(first.dcaData.contentData));
  assert.deepEqual(second.dcaData.contentData.bodytext.contentEncodings, ["gzip"]);
  assert.deepEqual(second.dcaData.contentData.sidebar.contentEncodings, ["gzip"]);
  assert.deepEqual(second.dcaData.resource.data, first.dcaData.resource.data);

  const wire = JSON.parse(
    JSON.stringify({ ...second.dcaData, sealedContent: second.sealedContent }),
  );
  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
});

test("simultaneous seals share one compression pass and both produce a render", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  let encodes = 0;
  const sealer = new CompressingSealer(sealerConfig(), {
    gzip: {
      encode: async (bytes) => {
        encodes += 1;
        await Promise.resolve();
        return encode(bytes);
      },
    },
  });
  sealer
    .resource("123456", { section: "politics" })
    .content("bodytext", ARTICLE, "text/html", { accessGroups: [GROUP] })
    .content("sidebar", SIDEBAR, "text/html", { accessGroups: [GROUP] });

  const [first, second] = await Promise.all([sealer.seal(), sealer.seal()]);

  assert.equal(encodes, 2, "each item is compressed once, not once per concurrent caller");
  for (const sealed of [first, second]) {
    const wire = JSON.parse(
      JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
    );
    assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
    assert.equal(utf8Decode(await open(wire, "sidebar", periodKeySupply)), SIDEBAR);
  }
});

test("the sealed gzip item is shorter than the same item sealed plain", async () => {
  const { sealerConfig } = await world();
  const body = syntheticArticle({ bytes: 30_000, seed: 5 });

  const compressed = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: body },
  ]);
  const plain = await render(new Sealer(sealerConfig()), [{ name: "bodytext", value: body }]);

  const gzipLength = compressed.sealedContent.bodytext.length;
  const plainLength = plain.sealedContent.bodytext.length;
  assert.ok(gzipLength * 2 < plainLength, `${gzipLength} against ${plainLength}`);
});

test("each item is compressed on its own, so one item cannot shrink on another", async () => {
  const { sealerConfig } = await world();
  const body = syntheticArticle({ bytes: 8000, seed: 11 });

  const alone = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: body },
  ]);
  const beside = await render(new CompressingSealer(sealerConfig()), [
    { name: "sidebar", value: body },
    { name: "bodytext", value: body },
  ]);

  assert.equal(beside.sealedContent.bodytext.length, alone.sealedContent.bodytext.length);
  assert.equal(beside.sealedContent.sidebar.length, alone.sealedContent.bodytext.length);
});

test("the injected gzip is what compresses, and the record still says gzip", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  let asked = 0;
  const gzip = {
    encode: (/** @type {Uint8Array} */ bytes) => {
      asked += 1;
      return encode(bytes);
    },
    decode,
  };

  const wire = await render(new CompressingSealer(sealerConfig(), { gzip }), [
    { name: "bodytext", value: ARTICLE },
  ]);

  assert.equal(asked, 1, "the default was not reached behind the injected one");
  assert.deepEqual(wire.contentData.bodytext.contentEncodings, ["gzip"]);
  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
});

test("runtime gzip and an already-gzipped descriptor delegate equivalent bytes and metadata to base", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const providers = await ephemeralPool();
  const compressedBytes = await encode(utf8Encode(ARTICLE));

  const runtime = await render(
    new CompressingSealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    [{ name: "bodytext", value: ARTICLE }],
  );
  const prepared = await render(new Sealer(sealerConfig({ ephemeralKeyPairs: providers() })), [
    {
      name: "bodytext",
      value: {
        bytes: compressedBytes,
        contentType: "text/html",
        contentEncodings: ["gzip"],
      },
    },
  ]);

  const { resourceJWT: runtimeJwt, ...runtimeRest } = runtime;
  const { resourceJWT: preparedJwt, ...preparedRest } = prepared;
  assert.equal(JSON.stringify(preparedRest), JSON.stringify(runtimeRest));
  assert.equal(
    preparedJwt.split(".").slice(0, 2).join("."),
    runtimeJwt.split(".").slice(0, 2).join("."),
  );
  assert.equal(
    utf8Decode(await open(prepared, "bodytext", periodKeySupply)),
    ARTICLE,
    "the client decrypts the supplied representation before reversing gzip",
  );
});

test("a descriptor handed to the adapter is delegated to base unchanged", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const providers = await ephemeralPool();
  const compressedBytes = await encode(utf8Encode(ARTICLE));
  const prepared = () => ({
    name: "bodytext",
    value: {
      bytes: Uint8Array.from(compressedBytes),
      contentType: "text/html",
      contentEncodings: ["gzip"],
    },
  });

  // Descriptor bytes are already represented bytes, so the adapter adds no
  // layer of its own: both renders below are the same render.
  const throughAdapter = await render(
    new CompressingSealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    [prepared()],
  );
  const throughBase = await render(new Sealer(sealerConfig({ ephemeralKeyPairs: providers() })), [
    prepared(),
  ]);

  assert.deepEqual(throughAdapter.contentData.bodytext.contentEncodings, ["gzip"]);

  // The signature is left out for the reason identity-parity.test.js states:
  // ECDSA draws its own nonce inside WebCrypto, so this compares the payload.
  const { resourceJWT: adapterJwt, ...adapterRest } = throughAdapter;
  const { resourceJWT: baseJwt, ...baseRest } = throughBase;
  assert.equal(JSON.stringify(adapterRest), JSON.stringify(baseRest));
  assert.equal(
    adapterJwt.split(".").slice(0, 2).join("."),
    baseJwt.split(".").slice(0, 2).join("."),
  );

  assert.equal(utf8Decode(await open(throughAdapter, "bodytext", periodKeySupply)), ARTICLE);
});

test("base trusts descriptor bytes and a mismatched declaration fails only at client decode", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const wire = await render(new Sealer(sealerConfig()), [
    {
      name: "bodytext",
      value: {
        bytes: utf8Encode(ARTICLE),
        contentType: "text/html",
        contentEncodings: ["gzip"],
      },
    },
  ]);

  await assert.rejects(() => open(wire, "bodytext", periodKeySupply), { code: "bad_encoding" });
});

test("an encoding this extension does not write is refused at the call that named it", async () => {
  const { sealerConfig } = await world();
  const sealer = new CompressingSealer(sealerConfig());

  assert.throws(
    () =>
      sealer.content("bodytext", ARTICLE, "text/html", {
        accessGroups: ["premium"],
        contentEncoding: "br",
      }),
    { code: "unsupported_option" },
  );
  sealer.content("bodytext", ARTICLE, "text/html", {
    accessGroups: ["premium"],
    contentEncoding: "gzip",
  });
});

test("a gzip option beside a descriptor is refused at the call that named it", async () => {
  const { sealerConfig } = await world();
  const sealer = new CompressingSealer(sealerConfig());
  const prepared = {
    bytes: await encode(utf8Encode(ARTICLE)),
    contentType: "text/html",
    contentEncodings: ["gzip"],
  };

  assert.throws(
    () => sealer.content("bodytext", prepared, { accessGroups: [GROUP], contentEncoding: "gzip" }),
    {
      code: "unsupported_option",
    },
  );
});

test("an identity option beside a descriptor is refused at the call that named it", async () => {
  const { sealerConfig } = await world();
  const sealer = new CompressingSealer(sealerConfig());
  const prepared = {
    bytes: await encode(utf8Encode(ARTICLE)),
    contentType: "text/html",
    contentEncodings: ["gzip"],
  };

  assert.throws(
    () =>
      sealer.content("bodytext", prepared, { accessGroups: [GROUP], contentEncoding: "identity" }),
    {
      code: "unsupported_option",
    },
  );
});

test("a descriptor call carrying only accessGroups is accepted", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const sealer = new CompressingSealer(sealerConfig());
  sealer.resource("123456", { section: "politics" });
  sealer.content(
    "bodytext",
    {
      bytes: await encode(utf8Encode(ARTICLE)),
      contentType: "text/html",
      contentEncodings: ["gzip"],
    },
    { accessGroups: [GROUP] },
  );

  const sealed = await sealer.seal();
  const wire = JSON.parse(
    JSON.stringify({ ...sealed.dcaData, sealedContent: sealed.sealedContent }),
  );
  assert.deepEqual(wire.contentData.bodytext.contentEncodings, ["gzip"]);
  assert.equal(utf8Decode(await open(wire, "bodytext", periodKeySupply)), ARTICLE);
});

test("a client without gzip refuses the gzip item and opens the identity item beside it", async () => {
  const { sealerConfig, periodKeySupply } = await world();
  const wire = await render(new CompressingSealer(sealerConfig()), [
    { name: "bodytext", value: ARTICLE },
    { name: "sidebar", value: SIDEBAR, options: { contentEncoding: "identity" } },
  ]);

  let resolved = 0;
  const counting = {
    derive: (/** @type {string} */ accessGroup, /** @type {string} */ t) => {
      resolved += 1;
      return periodKeySupply.derive(accessGroup, t);
    },
  };

  await assert.rejects(() => open(wire, "bodytext", counting, { gzip: null }), {
    code: "unsupported_encoding",
  });
  assert.equal(resolved, 0, "the refused item cost no key resolution");

  assert.equal(utf8Decode(await open(wire, "sidebar", counting, { gzip: null })), SIDEBAR);
  assert.equal(resolved, 1);
});

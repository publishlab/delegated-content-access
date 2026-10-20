// @ts-check
//
// With every item named `identity`, the render this sealer produces is base's
// render, byte for byte, and that equality is what keeps this extension
// optional. Same seeds, same ephemeral keypairs, same period-key supply, and
// the two sealers walk the same coordinates in the same order.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { ARTICLE, SIDEBAR, ephemeralPool, render, world } from "./world.js";

/** @param {string} token @returns {string} the compact JWT's header and payload */
function payloadOf(token) {
  return token.split(".").slice(0, 2).join(".");
}

const IDENTITY_ITEMS = [
  { name: "bodytext", value: ARTICLE, options: { contentEncoding: "identity" } },
  { name: "sidebar", value: SIDEBAR, options: { contentEncoding: "identity" } },
];

test("an identity render equals the base render, byte for byte", async () => {
  const { sealerConfig } = await world();
  const providers = await ephemeralPool();

  const base = await render(
    new Sealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    IDENTITY_ITEMS,
  );
  const composed = await render(
    new CompressingSealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    IDENTITY_ITEMS,
  );

  // Every byte but the signature. ECDSA draws its own nonce inside WebCrypto,
  // which the injected `random` does not reach, so two signatures over one
  // payload differ by construction. The payload under them is compared
  // instead, decoded from the token both renders carry.
  const { resourceJWT: baseJwt, ...baseRest } = base;
  const { resourceJWT: composedJwt, ...composedRest } = composed;
  assert.equal(JSON.stringify(composedRest), JSON.stringify(baseRest));
  assert.equal(payloadOf(composedJwt), payloadOf(baseJwt));
});

test("a compressed render differs from the base render only in the two members it owns", async () => {
  const { sealerConfig } = await world();
  const providers = await ephemeralPool();

  const base = await render(new Sealer(sealerConfig({ ephemeralKeyPairs: providers() })), [
    { name: "bodytext", value: ARTICLE },
  ]);
  const composed = await render(
    new CompressingSealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    [{ name: "bodytext", value: ARTICLE }],
  );

  assert.notEqual(composed.sealedContent.bodytext, base.sealedContent.bodytext);
  assert.deepEqual(composed.contentData.bodytext.contentEncodings, ["gzip"]);

  const { contentEncodings, ...rest } = composed.contentData.bodytext;
  assert.deepEqual(contentEncodings, ["gzip"]);
  assert.deepEqual(rest, base.contentData.bodytext);
  assert.deepEqual(composed.resource, base.resource);
  assert.equal(payloadOf(composed.resourceJWT), payloadOf(base.resourceJWT));
  assert.deepEqual(composed.issuerData, base.issuerData);
});

test("a bytes value and the string it decodes to seal the same", async () => {
  const { sealerConfig } = await world();
  const providers = await ephemeralPool();

  const fromString = await render(
    new CompressingSealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    [{ name: "bodytext", value: ARTICLE }],
  );
  const fromBytes = await render(
    new CompressingSealer(sealerConfig({ ephemeralKeyPairs: providers() })),
    [{ name: "bodytext", value: new TextEncoder().encode(ARTICLE) }],
  );

  const { resourceJWT: stringJwt, ...stringRest } = fromString;
  const { resourceJWT: bytesJwt, ...bytesRest } = fromBytes;
  assert.equal(JSON.stringify(bytesRest), JSON.stringify(stringRest));
  assert.equal(payloadOf(bytesJwt), payloadOf(stringJwt));
});

test("a configuration base refuses is refused here, for base reasons", async () => {
  const { sealerConfig } = await world();

  assert.throws(() => new CompressingSealer({ ...sealerConfig(), nonsense: true }), {
    code: "unsupported_option",
  });
  assert.throws(
    () =>
      new CompressingSealer(sealerConfig(), { gzip: /** @type {any} */ ({ decode: (b) => b }) }),
    {
      code: "bad_config",
    },
  );
  assert.throws(() => new CompressingSealer(sealerConfig(), { gzip: /** @type {any} */ (null) }), {
    code: "bad_config",
  });
});

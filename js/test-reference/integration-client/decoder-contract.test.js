// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { composeClient } from "../../integration-client/composeClient.js";
import { ContentRepresentationOpener } from "../../core-client/ContentRepresentationOpener.js";
import { DEFAULT_CONTENT_ENCODING_LIMITS } from "../../core-client/contentEncodings.js";
import { DcaData } from "../../core-client/DcaData.js";
import { encrypt } from "../../core-shared/aead.js";
import { base64urlEncode } from "../../core-shared/codec.js";

test("public client composition accepts a budget-required decoder and forwards its bound", async () => {
  /** @type {number[]} */
  const budgets = [];
  /** @param {Uint8Array} bytes @param {{ maxOutputBytes: number }} budget */
  const decode = (bytes, budget) => {
    budgets.push(budget.maxOutputBytes);
    assert.equal(bytes[0], 1);
    return bytes.subarray(1, 1 + budget.maxOutputBytes);
  };
  const decoders = { custom: decode };
  // Both public contracts must accept a decoder whose second parameter is required.
  const composed = composeClient({ contentDecoders: decoders });
  const standalone = new ContentRepresentationOpener(decoders);
  const nonce = new Uint8Array(12).fill(3);
  const key = new Uint8Array(16).fill(7);
  const page = new DcaData({
    version: "1",
    resourceJWT:
      "eyJhbGciOiJFUzI1NiJ9.eyJyZW5kZXJJZCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.c2lnbmF0dXJl",
    contentData: {
      bodytext: {
        contentType: "text/plain",
        contentEncodings: ["custom"],
        nonce: base64urlEncode(nonce),
      },
    },
    issuerData: { issuer: { keyId: "opening", sealed: { contentKeys: {} } } },
  });
  const item = page.contentItemFor("bodytext");
  assert.ok(item);
  const plaintext = new TextEncoder().encode("bounded content");
  const ciphertext = base64urlEncode(
    await encrypt(key, new Uint8Array(12), new Uint8Array([1, ...plaintext]), item.contentAad),
  );
  for (const opener of [composed.opener, standalone]) {
    assert.deepEqual(
      await opener.open({ item, ciphertext, resolveKey: async () => key }),
      plaintext,
    );
  }
  assert.deepEqual(budgets, [
    DEFAULT_CONTENT_ENCODING_LIMITS.maxOutputBytes,
    DEFAULT_CONTENT_ENCODING_LIMITS.maxOutputBytes,
  ]);
});

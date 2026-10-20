// @ts-check
// Replay the baseline issuer's content-key ECDH envelope without loading the
// mixed content-key-and-period-key render fixture it was extracted from.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { base64urlDecode, base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { open } from "../core-shared--publisher-issuer/keySealing.js";
import { refuses } from "../test-lib/helpers/refuses.js";

const directory = fileURLToPath(
  new URL("../../verification/vectors/v1/baseline/ecdh-p256-envelope-open/", import.meta.url),
);
const manifest = JSON.parse(readFileSync(`${directory}set.json`, "utf8"));

// P-256 field prime and curve constant b (SEC 2, secp256r1); a is -3.
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/**
 * Whether the uncompressed point satisfies y^2 = x^3 - 3x + b mod p. A
 * right-length 0x04 point can still be off the curve; only the equation shows it.
 * @param {Uint8Array} point - 65 octets, 0x04 || x || y
 */
function onP256(point) {
  const coordinate = (/** @type {Uint8Array} */ bytes) =>
    BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  const x = coordinate(point.subarray(1, 33));
  const y = coordinate(point.subarray(33, 65));
  const mod = (/** @type {bigint} */ value) => ((value % P256_P) + P256_P) % P256_P;
  return mod(y * y) === mod(x * x * x - 3n * x + P256_B);
}
const names = readdirSync(directory)
  .filter((name) => name.endsWith(".json") && name !== "set.json")
  .sort();

test("the baseline ECDH package declares the carrier-open projection", () => {
  assert.equal(manifest.set, "ecdh-p256-envelope-open");
  assert.deepEqual(manifest.formatProofs?.["ecdh-p256-envelope-open/v1"], {
    proofBoundary: "carrier",
    operation: "open",
    projection: "content-key",
  });
  assert.deepEqual(
    names,
    [
      "open-ecdh-p256-compressed.json",
      "open-ecdh-p256-hybrid.json",
      "open-ecdh-p256-leading-zero.json",
      "open-ecdh-p256-off-curve.json",
      "open-ecdh-p256.json",
    ],
    "every package member is replayed",
  );
});

for (const name of names) {
  test(`${name}: the recorded envelope follows its binding and point form`, async () => {
    const vector = JSON.parse(readFileSync(`${directory}${name}`, "utf8"));
    assert.equal(vector.vectorFormat, "ecdh-p256-envelope-open/v1");
    const { input, expected } = vector;
    assert.equal(input.algorithm, "ecdh-p256");
    assert.equal(
      expected.bind,
      `dca-bind-key-envelope|c|${input.binding.renderId}|${input.binding.contentName}`,
    );

    const refusal = expected.error !== undefined;
    assert.deepEqual(
      Object.keys(expected).sort(),
      refusal ? ["bind", "blob", "error"] : ["bind", "blob"],
      "a record cannot claim both a refusal and a successful output",
    );
    const blob = base64urlDecode(expected.blob);
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      input.recipientPrivateKeyJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );

    if (refusal) {
      assert.equal(expected.error, "unseal_failed");
      if (name === "open-ecdh-p256-hybrid.json") {
        const positive = JSON.parse(readFileSync(`${directory}open-ecdh-p256.json`, "utf8"));
        const positiveBlob = base64urlDecode(positive.expected.blob);
        assert.equal(blob.length, 109);
        assert.equal(blob[0], 6, "the valid even-y point uses the hybrid marker");
        assert.equal(positiveBlob[64] & 1, 0, "the recorded point has even y parity");
        assert.deepEqual(blob.subarray(1), positiveBlob.subarray(1));
      } else if (name === "open-ecdh-p256-off-curve.json") {
        assert.equal(blob.length, 109);
        assert.equal(blob[0], 4, "the invalid point still uses uncompressed form");
        const positive = JSON.parse(readFileSync(`${directory}open-ecdh-p256.json`, "utf8"));
        assert.equal(
          onP256(base64urlDecode(positive.expected.blob).subarray(0, 65)),
          true,
          "control: the recorded valid point satisfies the curve equation",
        );
        assert.equal(onP256(blob.subarray(0, 65)), false, "the recorded point is off P-256");
      } else if (name === "open-ecdh-p256-compressed.json") {
        const positive = JSON.parse(readFileSync(`${directory}open-ecdh-p256.json`, "utf8"));
        const positiveBlob = base64urlDecode(positive.expected.blob);
        assert.equal(blob.length, 77, "33-byte compressed point plus the original 44-byte tail");
        assert.equal(blob[0], 2, "the compressed point encodes even y parity");
        assert.deepEqual(blob.subarray(1, 33), positiveBlob.subarray(1, 33));
        assert.deepEqual(blob.subarray(33), positiveBlob.subarray(65));
      }

      await refuses(
        () => open(expected.blob, privateKey, "ecdh-p256", { binding: input.binding }),
        expected.error,
        `${name} is refused at the issuer envelope boundary`,
      );
      return;
    }

    assert.deepEqual(Object.keys(expected).sort(), ["bind", "blob"]);
    assert.equal(blob.length, 109, "65-byte point, 12-byte nonce, 16-byte key and tag");
    assert.equal(blob[0], 4, "the ephemeral point uses uncompressed P-256 form");
    const ephemeral = await crypto.subtle.importKey(
      "raw",
      blob.subarray(0, 65),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedX = await crypto.subtle.deriveBits(
      { name: "ECDH", public: ephemeral },
      privateKey,
      256,
    );
    const sharedXBytes = new Uint8Array(sharedX);
    assert.equal(sharedXBytes.length, 32, "the agreement retains the P-256 field width");
    if (name === "open-ecdh-p256-leading-zero.json") {
      assert.equal(sharedXBytes[0], 0, "this recorded envelope has a leading-zero agreement");
    }
    const aes = await crypto.subtle.importKey("raw", sharedX, "AES-GCM", false, ["decrypt"]);
    const operation = (additionalData) =>
      crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: blob.subarray(65, 77),
          additionalData: utf8Encode(additionalData),
          tagLength: 128,
        },
        aes,
        blob.subarray(77),
      );
    const raw = await operation(expected.bind);
    assert.equal(base64urlEncode(new Uint8Array(raw)), input.contentKeyBase64url);
    await assert.rejects(operation(`${expected.bind}-other`), "a changed coordinate fails the tag");

    assert.equal(
      base64urlEncode(
        await open(expected.blob, privateKey, "ecdh-p256", { binding: input.binding }),
      ),
      input.contentKeyBase64url,
      "the reference issuer agrees with the independent WebCrypto replay",
    );
  });
}

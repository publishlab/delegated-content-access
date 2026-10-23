import assert from "node:assert/strict";
import { test } from "node:test";
import { createECDH, createDecipheriv, webcrypto } from "node:crypto";
import { generateEcdhKeyPair, exportRawKey } from "../../../core-shared/cryptoProvider.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { bindValue } from "../../../core-shared--publisher-issuer/bind.js";
import {
  seal as stockSeal,
  open as stockOpen,
} from "../../../core-shared--publisher-issuer/keySealing.js";
import { NONCE_FREE_ENVELOPE, seal, open } from "../core-shared--publisher-issuer/envelope.js";
import {
  nonceFreeEnvelopeKeySealing,
  nonceFreeEnvelopePublisherContribution,
} from "../core-publisher/keySealing.js";
import {
  openNonceFreeEnvelope,
  nonceFreeEnvelopeIssuerContribution,
} from "../core-issuer/procedure.js";
import { envelopeBehavior } from "../../../test-lib/suites/envelope-behavior.js";

const binding = { renderId: "AAECAwQFBgcICQoLDA0ODw", contentName: "bodytext" };
const aad = utf8Encode(bindValue(binding));
const payload = Uint8Array.from({ length: 16 }, (_, i) => i * 17);
const adapter = {
  createRecipient: generateEcdhKeyPair,
  seal: (bytes, recipient, coordinate) =>
    nonceFreeEnvelopeKeySealing.seal(bytes, recipient.publicKey, "ecdh-p256", {
      envelope: NONCE_FREE_ENVELOPE,
      binding: coordinate,
    }),
  open: (blob, recipient, coordinate) =>
    openNonceFreeEnvelope(blob, recipient, utf8Encode(bindValue(coordinate))),
};
envelopeBehavior(adapter);

test("independent literal transcript: scalar 1 sender, scalar 2 recipient, zero nonce", async () => {
  // Recorded with node:crypto createECDH/createCipheriv, outside WebCrypto/base helpers.
  // Public test keys only; not credentials. The transcript fixes BIND and ciphertext.
  const point = Buffer.from(
    "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
    "hex",
  );
  const privateKey = await webcrypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: point.subarray(1, 33).toString("base64url"),
      y: point.subarray(33).toString("base64url"),
      d: Buffer.from("02".padStart(64, "0"), "hex").toString("base64url"),
    },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const blob =
    "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfUthIn7QIU4eFOsUXFeHAdcj3I8QIjTVdoSIa240gt8qQ";
  assert.equal(
    Buffer.from(blob, "base64url").subarray(65).toString("hex"),
    "2d8489fb4085387853ac51715e1c075c8f723c4088d355da1221adb8d20b7ca9",
  );
  assert.deepEqual(await openNonceFreeEnvelope(blob, { privateKey }, aad), payload);
});

test("generated seal independently opens with node:crypto, and each seal has a fresh point", async () => {
  const recipient = createECDH("prime256v1");
  recipient.generateKeys();
  const publicKey = await webcrypto.subtle.importKey(
    "raw",
    recipient.getPublicKey(),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const blobs = await Promise.all(Array.from({ length: 8 }, () => seal(payload, publicKey, aad)));
  assert.equal(
    new Set(blobs.map((blob) => Buffer.from(blob.subarray(0, 65)).toString("hex"))).size,
    8,
  );
  for (const blob of blobs) {
    assert.equal(blob.length, 97);
    assert.equal(base64urlEncode(blob).length, 130);
    const key = recipient.computeSecret(blob.subarray(0, 65));
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.alloc(12));
    decipher.setAAD(aad);
    decipher.setAuthTag(blob.subarray(81));
    assert.deepEqual(
      new Uint8Array(Buffer.concat([decipher.update(blob.subarray(65, 81)), decipher.final()])),
      payload,
    );
  }
});

test("corruption, malformed point and carrier width fail closed", async () => {
  const recipient = await generateEcdhKeyPair();
  const blob = await seal(payload, recipient.publicKey, aad);
  for (const offset of [0, 20, 65, 96]) {
    const changed = blob.slice();
    changed[offset] ^= 1;
    await assert.rejects(open(changed, recipient.privateKey, aad), { code: "unseal_failed" });
  }
  for (const invalid of [blob.subarray(1), new Uint8Array(98), new Uint8Array(109)]) {
    await assert.rejects(open(invalid, recipient.privateKey, aad), { code: "unseal_failed" });
  }
  for (const invalid of ["%%%", "", base64urlEncode(blob) + "="]) {
    await assert.rejects(openNonceFreeEnvelope(invalid, recipient, aad), { code: "unseal_failed" });
  }
});

test("prototype and adopted core interoperate without a carried-nonce fallback", async () => {
  const recipient = await generateEcdhKeyPair();
  const options = {
    binding,
    random: { bytes: (n) => webcrypto.getRandomValues(new Uint8Array(n)) },
  };
  const ordinary = await nonceFreeEnvelopeKeySealing.seal(
    payload,
    recipient.publicKey,
    "ecdh-p256",
    options,
  );
  assert.equal(Buffer.from(ordinary, "base64url").length, 97);
  assert.deepEqual(await stockOpen(ordinary, recipient.privateKey, "ecdh-p256", options), payload);
  assert.deepEqual(await openNonceFreeEnvelope(ordinary, recipient, aad), payload);
  const experimental = await adapter.seal(payload, recipient, binding);
  assert.deepEqual(
    await stockOpen(experimental, recipient.privateKey, "ecdh-p256", options),
    payload,
  );
  const stock = await stockSeal(payload, recipient.publicKey, "ecdh-p256", options);
  assert.equal(Buffer.from(stock, "base64url").length, 97);
  // A correctly placed former nonce cannot turn the old layout into a fallback.
  const current = Buffer.from(stock, "base64url");
  const former = base64urlEncode(
    Buffer.concat([current.subarray(0, 65), Buffer.alloc(12), current.subarray(65)]),
  );
  await assert.rejects(stockOpen(former, recipient.privateKey, "ecdh-p256", options), {
    code: "unseal_failed",
  });
  await assert.rejects(openNonceFreeEnvelope(former, recipient, aad), { code: "unseal_failed" });
  const contribution = nonceFreeEnvelopeIssuerContribution();
  assert.equal(contribution.envelopeProcedures[NONCE_FREE_ENVELOPE].open, openNonceFreeEnvelope);
  assert.deepEqual(contribution.envelopeProcedures[NONCE_FREE_ENVELOPE].keyAlgorithms, [
    "ecdh-p256",
  ]);
  assert.equal(nonceFreeEnvelopePublisherContribution().keySealing, nonceFreeEnvelopeKeySealing);
});

test("captured payload and BIND survive caller mutation during async sealing", async () => {
  const recipient = await generateEcdhKeyPair();
  const bytes = payload.slice();
  const mutableAad = aad.slice();
  const pending = seal(bytes, recipient.publicKey, mutableAad);
  bytes.fill(0);
  mutableAad.fill(0);
  assert.deepEqual(await open(await pending, recipient.privateKey, aad), payload);
});

test("payload, binding and deterministic-pair injection are refused", async () => {
  const recipient = await generateEcdhKeyPair();
  for (const size of [0, 15, 17, 32])
    await assert.rejects(seal(new Uint8Array(size), recipient.publicKey, aad), { code: "bad_key" });
  await assert.rejects(seal(payload, recipient.publicKey, new Uint8Array()), {
    code: "binding_failed",
  });
  await assert.rejects(
    nonceFreeEnvelopeKeySealing.seal(payload, recipient.publicKey, "ecdh-p256", {
      envelope: NONCE_FREE_ENVELOPE,
      binding,
      ephemeralKeyPair: recipient,
    }),
    { code: "unsupported_option" },
  );
  await assert.rejects(
    nonceFreeEnvelopeKeySealing.seal(payload, recipient.publicKey, "ecdh-p256", {
      envelope: "unknown",
      binding,
    }),
    { code: "bad_config" },
  );
  const point = new Uint8Array(await exportRawKey(recipient.publicKey));
  assert.equal(point.length, 65);
});

test("Buffer inputs are copied before sealing and opening await", async () => {
  const recipient = await generateEcdhKeyPair();
  const bytes = Buffer.from(payload);
  const mutableAad = Buffer.from(aad);
  const sealing = seal(bytes, recipient.publicKey, mutableAad);
  bytes.fill(0);
  mutableAad.fill(0);
  const blob = await sealing;
  assert.deepEqual(await open(blob, recipient.privateKey, aad), payload);

  const mutableBlob = Buffer.from(blob);
  const openingAad = Buffer.from(aad);
  const opening = open(mutableBlob, recipient.privateKey, openingAad);
  mutableBlob.fill(0);
  openingAad.fill(0);
  assert.deepEqual(await opening, payload);
});

// Historical component comparison of the superseded signing-input AAD,
// full-token candidate and old carried string. These controls are independent
// of the current production render/name AAD. The full-token transcript and the carried string are
// historical controls built here. These are raw-AEAD tests: the layout fixture
// uses an opaque token-shaped string, and the signature comparison uses DCA's
// ES256 JWT signing helper.
import test from "node:test";
import assert from "node:assert/strict";

import {
  tokenRepresentationAad,
  signingInputRepresentationAad,
} from "../implementation/tokenRepresentationAad.js";
import { oldCarriedAad } from "../test-lib/oldFormat.js";
import { encrypt, decrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import { base64urlEncode, utf8Encode, utf8Decode } from "../../../core-shared/codec.js";
import { sign, verify } from "../../../core-shared--publisher-issuer/jwt.js";
import { RENDER_ID_BYTES } from "../../../core-shared--publisher-issuer/bind.js";

const key = new Uint8Array(16).fill(0x25);
const nonceFor = (marker) => new Uint8Array(NONCE_BYTES).fill(marker);
const plaintext = utf8Encode("a protected representation");

/** Canonical 22-character renderId test coordinate from exactly 16 bytes. */
const makeRenderId = (byte) => base64urlEncode(new Uint8Array(RENDER_ID_BYTES).fill(byte));

function delivery() {
  return {
    resourceJWT: "a.b.c",
    contentData: {
      bodytext: { contentType: "text/é", contentEncodings: ["gzip", "br"] },
      other: { contentType: "text/é", contentEncodings: ["gzip", "br"] },
    },
  };
}

test("historical full-token candidate matches its independently recorded octets", () => {
  const expectedHex =
    "6463612d62696e642d636f6e74656e742d726570726573656e746174696f6e2d763100" +
    "00000005612e622e6300000008626f64797465787400000007746578742fc3a9" +
    "0000000200000004677a6970000000026272";
  assert.equal(
    Buffer.from(tokenRepresentationAad(delivery(), "bodytext")).toString("hex"),
    expectedHex,
  );
  const withoutMirror = delivery();
  withoutMirror.resource = { resourceId: "wrong", origin: "https://wrong.example" };
  assert.equal(
    Buffer.from(tokenRepresentationAad(withoutMirror, "bodytext")).toString("hex"),
    expectedHex,
  );
});

test("the historical signing-input transcript matches its renamed-domain record", () => {
  // The candidate's recorded octets, kept byte for byte.
  const candidateHex =
    "6463612d62696e642d636f6e74656e742d7369676e696e672d696e7075742d763100" +
    "00000003612e6200000008626f64797465787400000007746578742fc3a9" +
    "0000000200000004677a6970000000026272";
  // "dca-bind-content-signing-input-v1" 0x00, the candidate domain
  const candidateDomainHex = "6463612d62696e642d636f6e74656e742d7369676e696e672d696e7075742d763100";
  // "dca-bind-content" 0x00, the historical signing-input domain
  const historicalDomainHex = "6463612d62696e642d636f6e74656e7400";
  assert.ok(candidateHex.startsWith(candidateDomainHex));
  assert.equal(
    Buffer.from(signingInputRepresentationAad(delivery(), "bodytext")).toString("hex"),
    historicalDomainHex + candidateHex.slice(candidateDomainHex.length),
    "the historical comparator builds the recorded fields after the renamed domain",
  );
});

test("valid ES256 signature-only refresh preserves historical signing-input AAD but changes full-token AAD", async () => {
  const keys = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const resource = {
    renderId: makeRenderId(0x11),
    origin: "https://www.news-site.example",
    issuedAt: "2025-10-23T14:20:00Z",
    resourceId: "123456",
    data: { section: "politics" },
  };
  const first = await sign(resource, keys.privateKey, { kid: "sign-2025-10" });
  let refreshed = first;
  for (let attempt = 0; attempt < 16 && refreshed === first; attempt++) {
    refreshed = await sign(resource, keys.privateKey, { kid: "sign-2025-10" });
  }
  assert.notEqual(
    refreshed,
    first,
    "ES256 produced a distinct valid signature for unchanged signed bytes",
  );
  assert.equal(first.split(".").slice(0, 2).join("."), refreshed.split(".").slice(0, 2).join("."));
  assert.notEqual(first.split(".")[2], refreshed.split(".")[2]);
  assert.deepEqual(await verify(first, keys.publicKey), resource);
  assert.deepEqual(await verify(refreshed, keys.publicKey), resource);

  const earlier = delivery();
  earlier.resourceJWT = first;
  const later = delivery();
  later.resourceJWT = refreshed;
  const signingNonce = nonceFor(0x42);
  const fullNonce = nonceFor(0x43);
  const signingCiphertext = await encrypt(
    key,
    signingNonce,
    plaintext,
    signingInputRepresentationAad(earlier, "bodytext"),
  );
  const fullCiphertext = await encrypt(
    key,
    fullNonce,
    plaintext,
    tokenRepresentationAad(earlier, "bodytext"),
  );
  assert.equal(
    utf8Decode(
      await decrypt(
        key,
        signingNonce,
        signingCiphertext,
        signingInputRepresentationAad(later, "bodytext"),
      ),
    ),
    "a protected representation",
    "the same signed header and claims leave the historical signing-input content AAD unchanged",
  );
  await assert.rejects(
    decrypt(key, fullNonce, fullCiphertext, tokenRepresentationAad(later, "bodytext")),
    "full-token coupling would require resealing despite identical verified claims",
  );

  const changedClaims = delivery();
  changedClaims.resourceJWT = await sign(
    { ...resource, renderId: makeRenderId(0x12) },
    keys.privateKey,
    { kid: "sign-2025-10" },
  );
  assert.equal(
    (await verify(changedClaims.resourceJWT, keys.publicKey)).renderId,
    makeRenderId(0x12),
  );
  await assert.rejects(
    decrypt(
      key,
      signingNonce,
      signingCiphertext,
      signingInputRepresentationAad(changedClaims, "bodytext"),
    ),
    "changing signed render claims changes the signing input and refuses the old seal",
  );

  const changedHeader = delivery();
  changedHeader.resourceJWT = await sign(resource, keys.privateKey, { kid: "sign-2025-11" });
  assert.deepEqual(await verify(changedHeader.resourceJWT, keys.publicKey), resource);
  await assert.rejects(
    decrypt(
      key,
      signingNonce,
      signingCiphertext,
      signingInputRepresentationAad(changedHeader, "bodytext"),
    ),
    "changing the protected kid also changes the signing input",
  );

  const signingInput = first.split(".").slice(0, 2).join(".");
  const invalidSignature = delivery();
  invalidSignature.resourceJWT = `${signingInput}.${base64urlEncode(new Uint8Array(64))}`;
  await assert.rejects(verify(invalidSignature.resourceJWT, keys.publicKey));
  assert.equal(
    utf8Decode(
      await decrypt(
        key,
        signingNonce,
        signingCiphertext,
        signingInputRepresentationAad(invalidSignature, "bodytext"),
      ),
    ),
    "a protected representation",
    "a retained key can still open the same signed-input bytes without client-side JWT verification",
  );
  await assert.rejects(
    decrypt(key, fullNonce, fullCiphertext, tokenRepresentationAad(invalidSignature, "bodytext")),
    "the full-token variant detects signature-segment corruption without verifying it",
  );
});

test("historical signing-input extraction rejects malformed compact-token spelling", () => {
  for (const token of ["a.b", "a.b.c.d", "a..c", "a.b.c=", "a.b.c+"]) {
    const malformed = delivery();
    malformed.resourceJWT = token;
    assert.throws(() => signingInputRepresentationAad(malformed, "bodytext"), TypeError);
  }
});

test("historical signing-input and full-token transcripts reject changes to signed input or selected handling fields", async () => {
  for (const [candidate, aadFor, nonce] of [
    ["full token", tokenRepresentationAad, nonceFor(0x44)],
    ["historical signing input", signingInputRepresentationAad, nonceFor(0x45)],
  ]) {
    const original = delivery();
    const aad = aadFor(original, "bodytext");
    const ciphertext = await encrypt(key, nonce, plaintext, aad);
    assert.equal(
      utf8Decode(await decrypt(key, nonce, ciphertext, aad)),
      "a protected representation",
    );

    for (const [label, change, name] of [
      [
        "signed payload",
        (d) => {
          d.resourceJWT = "a.c.d";
        },
        "bodytext",
      ],
      ["content name", () => {}, "other"],
      [
        "type",
        (d) => {
          d.contentData.bodytext.contentType = "text/html";
        },
        "bodytext",
      ],
      [
        "encoding order",
        (d) => {
          d.contentData.bodytext.contentEncodings = ["br", "gzip"];
        },
        "bodytext",
      ],
      [
        "encoding omission",
        (d) => {
          delete d.contentData.bodytext.contentEncodings;
        },
        "bodytext",
      ],
    ]) {
      const changed = delivery();
      change(changed);
      await assert.rejects(
        decrypt(key, nonce, ciphertext, aadFor(changed, name)),
        `${candidate}: ${label} must fail authentication with the same key and ciphertext`,
      );
    }
  }
});

test("historical full-token candidate retransmits unchanged token but refuses any token-byte change", async () => {
  const old = delivery();
  const nonce = nonceFor(0x46);
  const ciphertext = await encrypt(key, nonce, plaintext, tokenRepresentationAad(old, "bodytext"));
  const retransmitted = JSON.parse(JSON.stringify(old));
  assert.equal(
    utf8Decode(
      await decrypt(key, nonce, ciphertext, tokenRepresentationAad(retransmitted, "bodytext")),
    ),
    "a protected representation",
  );
  retransmitted.resourceJWT = "a.b.d";
  await assert.rejects(
    decrypt(key, nonce, ciphertext, tokenRepresentationAad(retransmitted, "bodytext")),
  );
  // The candidate's proposed new-render/key/envelope duty is an authoring rule;
  // this primitive test establishes only the changed-AAD opening failure.
});

test("old-format control: the carried AAD did not authenticate type or encoding metadata", async () => {
  const carried = utf8Encode(oldCarriedAad("article", "bodytext"));
  const nonce = nonceFor(0x47);
  const ciphertext = await encrypt(key, nonce, plaintext, carried);
  const changed = delivery();
  changed.contentData.bodytext.contentType = "application/javascript";
  changed.contentData.bodytext.contentEncodings = ["br"];
  assert.equal(
    utf8Decode(await decrypt(key, nonce, ciphertext, carried)),
    "a protected representation",
    "the same old carried AAD opens after unbound metadata changes",
  );
  const historicalNonce = nonceFor(0x48);
  const historicalCiphertext = await encrypt(
    key,
    historicalNonce,
    plaintext,
    signingInputRepresentationAad(delivery(), "bodytext"),
  );
  await assert.rejects(
    decrypt(
      key,
      historicalNonce,
      historicalCiphertext,
      signingInputRepresentationAad(changed, "bodytext"),
    ),
    "the historical signing-input AAD binds those fields, so the same change refuses the seal",
  );
  assert.notDeepEqual(
    tokenRepresentationAad(changed, "bodytext"),
    tokenRepresentationAad(delivery(), "bodytext"),
    "the full-token candidate also changed authentication input for those fields",
  );
  // This is a raw-AEAD comparison, not a host decoder or code-execution test.
});

test("absent encodings differ from malformed encodings", () => {
  const absent = delivery();
  delete absent.contentData.bodytext.contentEncodings;
  assert.ok(tokenRepresentationAad(absent, "bodytext").length > 0);
  const sparse = Array(3);
  sparse[0] = "gzip";
  sparse[2] = "br";
  for (const bad of [[], [""], sparse, "gzip", ["gzip", 3]]) {
    const malformed = delivery();
    malformed.contentData.bodytext.contentEncodings = bad;
    assert.throws(() => tokenRepresentationAad(malformed, "bodytext"));
  }
  const unpaired = delivery();
  unpaired.contentData.bodytext.contentType = "text/\uD800";
  assert.throws(() => tokenRepresentationAad(unpaired, "bodytext"));
});

// @ts-check
//
// Repository-tooling coverage. The generator composes base, variant, and
// optional-extension vector writers, so this is not a base reference suite.
//
// The generator cannot seed WebCrypto's ECDSA nonce. It instead retains a
// prior fixture signature only when that exact signing input still verifies.

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { sign, verify } from "../core-shared--publisher-issuer/jwt.js";
import { bindValue } from "../core-shared--publisher-issuer/bind.js";
import { seal as coreSeal, open as coreOpen } from "../core-shared--publisher-issuer/keySealing.js";
import { base64urlDecode, utf8Decode } from "../core-shared/codec.js";
import {
  makeBoundCarrierVector,
  makeProtocolFixtureManifest,
  makeV1SetManifest,
  retainRecordedSignature,
} from "../tools/make-vectors.js";
import { CHECKSUM_FILE, writeChecksums } from "../tools/checksums.js";
import { sealingWith } from "../tools/vector-fixtures/keySealingWith.js";
import { deterministicEcdhFixtureSealing } from "../tools/vector-fixtures/deterministicEcdhSealing.js";
import { syntheticArticle, textOf } from "../tools/synthetic-html.js";
import { unbannedBindValue } from "../tools/vector-fixtures/unbannedSealing.js";

const { subtle } = globalThis.crypto;

const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

test("deterministic ECDH sealing refuses a missing ephemeral fixture", async () => {
  const issuer = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const fixtureSealing = deterministicEcdhFixtureSealing(() => undefined);
  await assert.rejects(
    async () =>
      fixtureSealing.seal(new Uint8Array(16), issuer.publicKey, "ECDH-P256", {
        binding: { renderId: "AAAAAAAAAAAAAAAAAAAAAA", contentName: "bodytext" },
        random: { bytes: (length) => new Uint8Array(length) },
      }),
    /no recorded ephemeral keypair/,
  );
});

test("synthetic HTML rejects inherited renderer names", () => {
  assert.throws(() => syntheticArticle({ bytes: 64, form: /** @type {any} */ ("constructor") }), {
    message: "unknown form constructor",
  });
});

test("textOf decodes each entity once", () => {
  assert.equal(textOf("&amp;lt; &#38;lt; &lt;"), "&lt; &lt; <");
});

test("the delimiter-bypass fixture refuses unsupported period-chain coordinates", () => {
  assert.throws(
    () =>
      unbannedBindValue({
        renderId: "AAAAAAAAAAAAAAAAAAAAAA",
        accessGroup: "premium",
        suppliedT: "251023T23",
        chainsPerDay: 4,
        periodMinutes: 360,
        periodChain: true,
      }),
    /supports content and exact-period coordinates only/,
  );
});

test("alternate-binding sealing equals core when given the core binding", async () => {
  const alternate = sealingWith(bindValue);
  const key = new Uint8Array(16).fill(0x5a);
  const binding = {
    renderId: "AAAAAAAAAAAAAAAAAAAAAA",
    accessGroup: "premium",
    t: "251023T14",
  };
  const issuerEcdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const ephemeral = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const nonceSource = { bytes: (length) => new Uint8Array(length).fill(0xa5) };

  const options = { binding, random: nonceSource, ephemeralKeyPair: ephemeral };
  const coreBlob = await coreSeal(key, issuerEcdh.publicKey, "ECDH-P256", options);
  const alternateBlob = await alternate.seal(key, issuerEcdh.publicKey, "ECDH-P256", options);
  assert.equal(alternateBlob, coreBlob, "ECDH-P256 seal bytes");
  assert.deepEqual(
    await alternate.unseal(coreBlob, issuerEcdh.privateKey, "ECDH-P256", { binding }),
    key,
    "ECDH-P256 tool open of core blob",
  );

  const issuerRsa = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["encrypt", "decrypt"],
  );
  const coreRsaBlob = await coreSeal(key, issuerRsa.publicKey, "RSA-OAEP", { binding });
  const alternateRsaBlob = await alternate.seal(key, issuerRsa.publicKey, "RSA-OAEP", { binding });
  assert.deepEqual(
    await alternate.unseal(coreRsaBlob, issuerRsa.privateKey, "RSA-OAEP", { binding }),
    key,
    "tool opens the randomized core RSA blob",
  );
  assert.deepEqual(
    await coreOpen(alternateRsaBlob, issuerRsa.privateKey, "RSA-OAEP", { binding }),
    key,
    "core opens the randomized tool RSA blob",
  );
});

test("alternate-binding sealing reads the same 2048-bit modulus floor core reads", async () => {
  // One normative rule for the floor has two implementations here. Both refuse
  // the same narrow modulus, so a caller that seals with core and opens with
  // this one meets the floor on either side.
  const alternate = sealingWith(bindValue);
  const key = new Uint8Array(16).fill(0x5a);
  const binding = { renderId: "AAAAAAAAAAAAAAAAAAAAAA", contentName: "bodytext" };
  const narrow = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["encrypt", "decrypt"],
  );

  /** @type {[string, () => Promise<unknown>][]} */
  const calls = [
    ["core seal", () => coreSeal(key, narrow.publicKey, "RSA-OAEP", { binding })],
    ["tool seal", () => alternate.seal(key, narrow.publicKey, "RSA-OAEP", { binding })],
    ["core open", () => coreOpen("x", narrow.privateKey, "RSA-OAEP", { binding })],
    ["tool open", () => alternate.unseal("x", narrow.privateKey, "RSA-OAEP", { binding })],
  ];
  for (const [label, run] of calls) {
    await assert.rejects(run, (error) => {
      assert.equal(
        /** @type {any} */ (error).code,
        "bad_config",
        `${label}: a narrow modulus is the issuer's own configuration fault`,
      );
      assert.match(
        /** @type {Error} */ (error).message,
        /2048/,
        `${label}: the message names the floor`,
      );
      return true;
    });
  }
});

test("the base vector set manifest declares the set, its phase and its format proofs", () => {
  assert.deepEqual(makeV1SetManifest("devel"), {
    set: "v1",
    phase: "devel",
    formatProofs: {
      3: {
        proofBoundary: "carrier",
        operation: "open",
        projection: "recovered-binding-and-key",
      },
    },
  });
});

test("the protocol fixture manifest exactly classifies its payload files", async () => {
  const dir = fileURLToPath(
    new URL("../../../verification/fixtures/protocol-v1/", import.meta.url),
  );
  const manifest = JSON.parse(readFileSync(`${dir}manifest.json`, "utf8"));
  assert.equal(manifest.schema, "dca-protocol-fixture-manifest/v1");
  assert.equal(manifest.protocol, "dca");
  assert.equal(manifest.version, "1");
  assert.equal(manifest.stability, "draft");
  assert.deepEqual(
    Object.keys(manifest).sort(),
    ["files", "protocol", "schema", "stability", "version"],
    "the package declares its schema, its identity and its file inventory",
  );

  const paths = manifest.files.map(({ path }) => path);
  const payloadFiles = readdirSync(dir)
    .filter((file) => file.endsWith(".json") && file !== "manifest.json")
    .sort();
  assert.deepEqual(paths, [...paths].sort(), "manifest membership is stable by path");
  assert.deepEqual(paths, payloadFiles, "every JSON payload is declared exactly once");
  assert.equal(new Set(paths).size, paths.length, "no fixture path is declared twice");

  const consumerCounts = { "base-contract": 0, reference: 0 };
  for (const entry of manifest.files) {
    const fixture = JSON.parse(readFileSync(`${dir}${entry.path}`, "utf8"));
    assert.equal(
      entry.vectorFormat,
      fixture.vectorFormat,
      `${entry.path}: declared format matches bytes`,
    );
    assert.ok(
      ["1", "2"].includes(entry.vectorFormat),
      `${entry.path}: fixture format is owned here`,
    );
    assert.equal(entry.consumers.length, 1, `${entry.path}: one current assertion owner`);
    assert.ok(Object.hasOwn(consumerCounts, entry.consumers[0]), `${entry.path}: known consumer`);
    consumerCounts[entry.consumers[0]]++;
    if (entry.vectorFormat === "1") {
      for (const content of fixture.input.content) {
        const projection = fixture.expected.contentOpen[content.name];
        assert.equal(
          utf8Decode(base64urlDecode(projection.aadBase64url)),
          fixture.expected.dcaData.contentData[content.name].aad,
          `${entry.path}: content aad projection matches the wire source`,
        );
        assert.equal(
          utf8Decode(base64urlDecode(projection.valueBase64url)),
          content.value,
          `${entry.path}: content value projection matches the publisher input`,
        );
        assert.equal(
          Object.hasOwn(fixture.expected.dcaData.contentData[content.name], "aadBase64url"),
          false,
          `${entry.path}: the byte projection is not a wire member`,
        );
      }
    }
  }
  assert.deepEqual(consumerCounts, {
    "base-contract": 22,
    reference: 2,
  });
  assert.deepEqual(
    [...new Set(manifest.files.flatMap((entry) => Object.keys(entry)))].sort(),
    ["consumers", "path", "vectorFormat"],
    "a file entry gives its path, its format and the consumer that asserts over it",
  );

  const regenerated = makeProtocolFixtureManifest(
    manifest.files.map((entry) => ({
      file: entry.path,
      vector: { vectorFormat: entry.vectorFormat },
    })),
  );
  assert.deepEqual(
    regenerated,
    manifest,
    "the generator owns the manifest shape and classification",
  );

  const checksumLines = readFileSync(`${dir}${CHECKSUM_FILE}`, "utf8").trim().split("\n");
  assert.equal(checksumLines.length, payloadFiles.length, "one checksum per declared payload");
  for (const [index, file] of payloadFiles.entries()) {
    const digest = await subtle.digest("SHA-256", readFileSync(`${dir}${file}`));
    const hex = [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    assert.equal(checksumLines[index], `${hex}  ${file}`, `${file}: checksum covers exact bytes`);
  }
});

test("fixture generation cannot silently promote a new file into the base contract", () => {
  assert.throws(
    () =>
      makeProtocolFixtureManifest([{ file: "new-behavior.json", vector: { vectorFormat: "2" } }]),
    /has no reviewed consumer/,
  );
});

test("the vector generator retains only a valid signature over the same encoded signing input", async () => {
  const keyPair = await subtle.generateKey(ECDSA_P256, true, ["sign", "verify"]);
  const prior = await sign({ marker: "recorded" }, keyPair.privateKey, { kid: "fixture" });
  const candidate = await sign({ marker: "recorded" }, keyPair.privateKey, { kid: "fixture" });

  const retained = await retainRecordedSignature(candidate, prior, keyPair.publicKey);
  assert.equal(
    retained,
    prior,
    "a valid prior signature holds the same encoded header and payload",
  );
  assert.deepEqual(await verify(retained, keyPair.publicKey), { marker: "recorded" });

  const changedInput = await sign({ marker: "changed" }, keyPair.privateKey, { kid: "fixture" });
  assert.equal(
    await retainRecordedSignature(changedInput, prior, keyPair.publicKey),
    changedInput,
    "a different payload must receive the signature this run produced",
  );

  const otherKeyPair = await subtle.generateKey(ECDSA_P256, true, ["sign", "verify"]);
  assert.equal(
    await retainRecordedSignature(candidate, prior, otherKeyPair.publicKey),
    candidate,
    "a signature under an older public key is never retained",
  );

  const [header, payload, signature] = prior.split(".");
  const invalidPrior = `${header}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  assert.equal(
    await retainRecordedSignature(candidate, invalidPrior, keyPair.publicKey),
    candidate,
    "a damaged prior signature is never retained",
  );
  assert.equal(
    await retainRecordedSignature(candidate, undefined, keyPair.publicKey),
    candidate,
    "the first generation has no prior signature to retain",
  );
});

test("bound-carrier regeneration repairs deterministic blobs and their checksum", async () => {
  const dir = `${mkdtempSync(join(tmpdir(), "dca-bound-vector-"))}/`;
  try {
    const generated = await makeBoundCarrierVector();
    assert.match(generated.dir, /v1-alt--bind-on-renderId-and-slot/);

    const write = async (vector) => {
      writeFileSync(`${dir}${generated.file}`, `${JSON.stringify(vector, null, 2)}\n`);
      await writeChecksums(dir);
    };
    await write(generated.vector);
    const expectedBytes = readFileSync(`${dir}${generated.file}`, "utf8");
    const expectedSums = readFileSync(`${dir}${CHECKSUM_FILE}`, "utf8");

    const tampered = structuredClone(generated.vector);
    const blob = tampered.expected.ecdh.contentBlob;
    tampered.expected.ecdh.contentBlob = `${blob.startsWith("A") ? "B" : "A"}${blob.slice(1)}`;
    await write(tampered);
    assert.notEqual(readFileSync(`${dir}${generated.file}`, "utf8"), expectedBytes);
    assert.notEqual(readFileSync(`${dir}${CHECKSUM_FILE}`, "utf8"), expectedSums);

    await write((await makeBoundCarrierVector()).vector);
    assert.equal(readFileSync(`${dir}${generated.file}`, "utf8"), expectedBytes);
    assert.equal(readFileSync(`${dir}${CHECKSUM_FILE}`, "utf8"), expectedSums);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

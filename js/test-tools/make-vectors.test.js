// @ts-check
//
// Repository-tooling coverage. The generator composes base, variant, and
// optional-extension vector writers, so this is not a base reference suite.
//
// The generator cannot seed WebCrypto's ECDSA nonce. It instead retains a
// prior fixture signature only when that exact signing input still verifies.

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { sign, verify } from "../core-shared--publisher-issuer/jwt.js";
import { bindValue } from "../core-shared--publisher-issuer/bind.js";
import { seal as coreSeal, open as coreOpen } from "../core-shared--publisher-issuer/keySealing.js";
import { base64urlDecode, utf8Decode } from "../core-shared/codec.js";
import {
  assertFixturePackageWritable,
  driftFrom,
  FIXTURE_PACKAGES,
  makeBoundCarrierVector,
  makeOpenNegativeVectors,
  makeProtocolFixtureManifest,
  makeRsaOaepSetManifest,
  retainRecordedSignature,
} from "../tools/make-vectors.js";
import { CHECKSUM_FILE, writeChecksums } from "../tools/checksums.js";
import { sealingWith } from "../tools/vector-fixtures/keySealingWith.js";
import { deterministicEcdhFixtureSealing } from "../tools/vector-fixtures/deterministicEcdhSealing.js";
import { discoverFixturePackageRoots } from "./claim-index.js";
import { syntheticArticle, textOf } from "../tools/synthetic-html.js";
import { unbannedBindValue } from "../tools/vector-fixtures/unbannedSealing.js";
// The generator check compares with the production transcript; the replay in
// test-vectors/vectors.test.js checks the same bytes against a hand-built one.
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { contentAad } from "../core-shared--client-publisher/contentAad.js";

const { subtle } = globalThis.crypto;

const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

test("deterministic ECDH sealing refuses a missing ephemeral fixture", async () => {
  const issuer = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const fixtureSealing = deterministicEcdhFixtureSealing(() => undefined);
  await assert.rejects(
    async () =>
      fixtureSealing.seal(new Uint8Array(16), issuer.publicKey, "ecdh-p256", {
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

test("the delimiter-bypass fixture refuses unsupported chain-key coordinates", () => {
  assert.throws(
    () =>
      unbannedBindValue({
        renderId: "AAAAAAAAAAAAAAAAAAAAAA",
        accessGroup: "premium",
        suppliedT: "251023T2300",
        chainsPerDay: 4,
        periodMinutes: 360,
        chainKey: true,
      }),
    /supports content and period-key coordinates only/,
  );
});

test("alternate-binding sealing equals core when given the core binding", async () => {
  const alternate = sealingWith(bindValue);
  const key = new Uint8Array(16).fill(0x5a);
  const binding = {
    renderId: "AAAAAAAAAAAAAAAAAAAAAA",
    accessGroup: "premium",
    t: "251023T1400",
  };
  const issuerEcdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const ephemeral = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const nonceSource = { bytes: (length) => new Uint8Array(length).fill(0xa5) };

  const options = { binding, random: nonceSource, ephemeralKeyPair: ephemeral };
  const coreBlob = await coreSeal(key, issuerEcdh.publicKey, "ecdh-p256", options);
  const alternateBlob = await alternate.seal(key, issuerEcdh.publicKey, "ecdh-p256", options);
  assert.equal(alternateBlob, coreBlob, "ECDH-P256 seal bytes");
  assert.deepEqual(
    await alternate.unseal(coreBlob, issuerEcdh.privateKey, "ecdh-p256", { binding }),
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
  const coreRsaBlob = await coreSeal(key, issuerRsa.publicKey, "rsa-oaep", { binding });
  const alternateRsaBlob = await alternate.seal(key, issuerRsa.publicKey, "rsa-oaep", { binding });
  assert.deepEqual(
    await alternate.unseal(coreRsaBlob, issuerRsa.privateKey, "rsa-oaep", { binding }),
    key,
    "tool opens the randomized core RSA blob",
  );
  assert.deepEqual(
    await coreOpen(alternateRsaBlob, issuerRsa.privateKey, "rsa-oaep", { binding }),
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
    ["core seal", () => coreSeal(key, narrow.publicKey, "rsa-oaep", { binding })],
    ["tool seal", () => alternate.seal(key, narrow.publicKey, "rsa-oaep", { binding })],
    ["core open", () => coreOpen("x", narrow.privateKey, "rsa-oaep", { binding })],
    ["tool open", () => alternate.unseal("x", narrow.privateKey, "rsa-oaep", { binding })],
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

test("the RSA-OAEP package manifest declares the set, its phase and its format proofs", () => {
  assert.deepEqual(makeRsaOaepSetManifest("devel"), {
    set: "rsa-oaep-envelope-open",
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

test("the RSA-OAEP generator owns both recorded negative opens with refusal-shaped expectations", () => {
  const negatives = makeOpenNegativeVectors();
  assert.deepEqual(negatives.map(({ file }) => file).sort(), [
    "open-rsa-oaep-long-tail.json",
    "open-rsa-oaep-prefix-confusion.json",
  ]);
  for (const { vector } of negatives) {
    assert.equal(vector.vectorFormat, "3");
    assert.equal(vector.input.binding.contentName, "premium");
    assert.deepEqual(Object.keys(vector.expected).sort(), ["bind", "blob", "error"]);
    assert.equal(vector.expected.error, "unseal_failed");
  }
});

/** The three protocol fixture packages, what each holds and which tier asserts from it. */
const PROTOCOL_FIXTURE_PACKAGES = [
  {
    id: "fixtures/v1/baseline/issuer-admission",
    payloads: 17,
    formats: ["2"],
    consumers: { "base-contract": 17 },
  },
  {
    id: "fixtures/v1/profiles/dca-profile-period-keys/issuer-admission",
    payloads: 7,
    formats: ["1", "2"],
    consumers: { "base-contract": 7 },
  },
  {
    id: "fixtures/v1/reference/protocol-regressions",
    payloads: 6,
    formats: ["2", "sealer-factory-refusal-v2", "sealer-factory-v3"],
    consumers: { reference: 6 },
  },
];

/** @param {string} id */
const fixturePackageDir = (id) =>
  fileURLToPath(new URL(`../../verification/${id}/`, import.meta.url));

/** @param {string} dir */
const payloadFilesIn = (dir) =>
  readdirSync(dir)
    .filter((file) => file.endsWith(".json") && file !== "manifest.json")
    .sort();

test("every fixture package on disk is one the generator or a recorder owns", () => {
  const fixtureRoot = fileURLToPath(new URL("../../verification/fixtures/", import.meta.url));
  assert.deepEqual(
    discoverFixturePackageRoots(fixtureRoot).sort(),
    [
      "fixtures/v1/baseline/issuer-admission",
      "fixtures/v1/profiles/dca-profile-chain-keys/geometry-admission",
      "fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix",
      "fixtures/v1/profiles/dca-profile-period-keys/issuer-admission",
      "fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition",
      "fixtures/v1/reference/protocol-regressions",
    ],
    "every fixture package needs an explicit consumer and replay owner",
  );
  assert.deepEqual(
    FIXTURE_PACKAGES,
    PROTOCOL_FIXTURE_PACKAGES.map(({ id }) => id),
    "the generator writes exactly the three protocol fixture packages",
  );
});

test("the three protocol fixture packages split the 30 payloads without overlap", () => {
  const payloads = PROTOCOL_FIXTURE_PACKAGES.flatMap(({ id }) =>
    payloadFilesIn(fixturePackageDir(id)),
  );
  assert.equal(payloads.length, 30, "17 baseline, 7 period-key and 6 reference payloads");
  assert.equal(new Set(payloads).size, payloads.length, "no payload sits in two packages");
});

for (const expected of PROTOCOL_FIXTURE_PACKAGES) {
  test(`${expected.id}: the manifest exactly classifies its payload files`, async () => {
    const dir = fixturePackageDir(expected.id);
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
    const payloadFiles = payloadFilesIn(dir);
    assert.deepEqual(paths, [...paths].sort(), "manifest membership is stable by path");
    assert.deepEqual(paths, payloadFiles, "every JSON payload is declared exactly once");
    assert.equal(new Set(paths).size, paths.length, "no fixture path is declared twice");
    assert.equal(paths.length, expected.payloads, "the package holds its reviewed members");

    /** @type {Record<string, number>} */
    const consumerCounts = {};
    const formats = new Set();
    for (const entry of manifest.files) {
      const fixture = JSON.parse(readFileSync(`${dir}${entry.path}`, "utf8"));
      assert.equal(
        entry.vectorFormat,
        fixture.vectorFormat,
        `${entry.path}: declared format matches bytes`,
      );
      formats.add(entry.vectorFormat);
      assert.equal(entry.consumers.length, 1, `${entry.path}: one current assertion owner`);
      consumerCounts[entry.consumers[0]] = (consumerCounts[entry.consumers[0]] ?? 0) + 1;
      if (entry.vectorFormat === "1") {
        for (const content of fixture.input.content) {
          const projection = fixture.expected.contentOpen[content.name];
          assert.deepEqual(
            base64urlDecode(projection.aadBase64url),
            contentAad({
              renderId: decodeCompactJwt(fixture.expected.dcaData.resourceJWT)?.payload?.renderId,
              contentName: content.name,
            }),
            `${entry.path}: content aad projection is the content AAD the wire derives`,
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
    assert.deepEqual([...formats].sort(), expected.formats, "the package holds only its formats");
    assert.deepEqual(consumerCounts, expected.consumers);
    assert.deepEqual(
      [...new Set(manifest.files.flatMap((entry) => Object.keys(entry)))].sort(),
      ["consumers", "path", "vectorFormat"],
      "a file entry gives its path, its format and the consumer that asserts over it",
    );

    const regenerated = makeProtocolFixtureManifest(
      expected.id,
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
}

test("fixture generation cannot silently promote a new file into the base contract", () => {
  const [baseline, periodKeys] = FIXTURE_PACKAGES;
  assert.throws(
    () =>
      makeProtocolFixtureManifest(baseline, [
        { file: "new-behavior.json", vector: { vectorFormat: "2" } },
      ]),
    /has no reviewed consumer/,
  );
  // seal-ecdh.json is a reviewed member, but of the period-key package.
  assert.throws(
    () =>
      makeProtocolFixtureManifest(baseline, [
        { file: "seal-ecdh.json", vector: { vectorFormat: "1" } },
      ]),
    /seal-ecdh\.json: generated fixture belongs to fixtures\/v1\/profiles\/dca-profile-period-keys\/issuer-admission/,
  );
  assert.throws(
    () => makeProtocolFixtureManifest(periodKeys, []),
    /fixtures\/v1\/profiles\/dca-profile-period-keys\/issuer-admission: generated fixture inventory differs/,
  );
  assert.throws(
    () => makeProtocolFixtureManifest("fixtures/protocol-v1", []),
    /unknown protocol fixture package fixtures\/protocol-v1/,
  );
});

test("a frozen protocol fixture package refuses a regeneration and names itself", () => {
  const dir = `${mkdtempSync(join(tmpdir(), "dca-frozen-fixtures-"))}/`;
  try {
    for (const id of FIXTURE_PACKAGES) {
      rmSync(`${dir}manifest.json`, { force: true });
      assert.doesNotThrow(
        () => assertFixturePackageWritable(id, dir),
        "a package without a manifest is draft",
      );
      writeFileSync(`${dir}manifest.json`, JSON.stringify({ stability: "draft" }));
      assert.doesNotThrow(() => assertFixturePackageWritable(id, dir));
      writeFileSync(`${dir}manifest.json`, JSON.stringify({ stability: "frozen" }));
      assert.throws(
        () => assertFixturePackageWritable(id, dir),
        (error) =>
          error instanceof Error &&
          error.message.startsWith(`${id} is frozen, and this run would overwrite it.`),
      );
      writeFileSync(`${dir}manifest.json`, JSON.stringify({ stability: "stable" }));
      assert.throws(
        () => assertFixturePackageWritable(id, dir),
        (error) =>
          error instanceof Error &&
          error.message === `${id} has unsupported fixture stability "stable"`,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
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
    assert.match(generated.dir, /v1\/experiments\/bind-on-renderId-and-slot/);

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

test("the drift check names each generated file that differs, is missing or is left over", () => {
  const dir = `${mkdtempSync(join(tmpdir(), "dca-vector-drift-"))}/`;
  try {
    writeFileSync(`${dir}same.json`, "{}\n");
    writeFileSync(`${dir}changed.json`, '{"cases":1}\n');
    writeFileSync(`${dir}left-over.json`, "{}\n");
    writeFileSync(`${dir}manifest.json`, "{}\n");
    writeFileSync(`${dir}${CHECKSUM_FILE}`, "old sums\n");
    const outputs = new Map([
      [`${dir}same.json`, "{}\n"],
      [`${dir}changed.json`, '{"cases":2}\n'],
      [`${dir}new.json`, "{}\n"],
      [`${dir}${CHECKSUM_FILE}`, "new sums\n"],
    ]);

    assert.deepEqual(driftFrom(outputs, [dir]), [
      { path: `${dir}${CHECKSUM_FILE}`, kind: "differs" },
      { path: `${dir}changed.json`, kind: "differs" },
      { path: `${dir}left-over.json`, kind: "left over" },
      { path: `${dir}new.json`, kind: "missing" },
    ]);
    assert.deepEqual(
      driftFrom(new Map([[`${dir}same.json`, "{}\n"]]), []),
      [],
      "a file equal to its generation is no drift, and only an owned directory has left-overs",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the committed fixtures and vector sets are what a fresh generation writes", () => {
  // A record whose generator input changed without a regeneration still
  // matches its sums, so only a fresh generation shows the drift.
  const run = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("../tools/make-vectors.js", import.meta.url)), "--check"],
    { encoding: "utf8" },
  );
  assert.equal(run.status, 0, `${run.stdout}${run.stderr}`);
  assert.match(run.stdout, /match a fresh generation/);
});

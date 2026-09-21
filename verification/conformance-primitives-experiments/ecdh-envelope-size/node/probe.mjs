#!/usr/bin/env node
// Node probe. Reads `_shared/fixture.json` inputs, seals and opens the three
// envelope profiles through WebCrypto and writes observations as JSON on
// stdout. It reads no expectation and assigns no verdict.
//
// `--record` is the one exception, and it still assigns no verdict: it writes
// this run's observations into the fixture's `expected` block, leaving `inputs`
// byte for byte as it was, so `_shared/compare.mjs` has a recorded answer to
// hold every runtime against. It refuses to record a run in which a profile
// went unanswered.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import process from "node:process";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "..", "_shared", "fixture.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const { inputs } = fixture;

const args = process.argv.slice(2);
const recording = args.includes("--record");
const unknown = args.filter((a) => a !== "--record");
if (unknown.length > 0) {
  console.error(`probe.mjs takes --record or nothing, got: ${unknown[0]}`);
  process.exit(2);
}

const subtle = globalThis.crypto.subtle;
const EC = { name: "ECDH", namedCurve: "P-256" };
const TAG_BYTES = 16;

const unhex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const hex = (b) => Buffer.from(b).toString("hex");
const b64url = (b) => Buffer.from(b).toString("base64url");
const utf8 = (s) => Buffer.from(s, "utf8");

// The two SubjectPublicKeyInfo shells for a P-256 point: id-ecPublicKey with
// prime256v1, then a BIT STRING holding the 65-byte or 33-byte point.
const SPKI_65 = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
const SPKI_33 = unhex("3039301306072a8648ce3d020106082a8648ce3d030107032200");

function spki(point) {
  const shell = point.length === 33 ? SPKI_33 : SPKI_65;
  const der = new Uint8Array(shell.length + point.length);
  der.set(shell, 0);
  der.set(point, shell.length);
  return der;
}

async function importPointRaw(point) {
  return subtle.importKey("raw", point, EC, false, []);
}

async function importPointSpki(point) {
  return subtle.importKey("spki", spki(point), EC, false, []);
}

// Compressed points go through the runtime's own import in both modes. Nothing
// here decompresses a point or touches field arithmetic.
let compressedImportMode = "unsupported";
async function importPoint(point) {
  if (point.length === 65) return importPointRaw(point);
  if (compressedImportMode === "native") return importPointRaw(point);
  if (compressedImportMode === "container-assisted") return importPointSpki(point);
  throw new Error("compressed point import is unsupported here");
}

async function detectCompressedImport() {
  const point = unhex(inputs.ephemeral.publicCompressedHex);
  try {
    await importPointRaw(point);
    compressedImportMode = "native";
    return;
  } catch {
    /* fall through to the container */
  }
  try {
    await importPointSpki(point);
    compressedImportMode = "container-assisted";
  } catch {
    compressedImportMode = "unsupported";
  }
}

function privateKey(pkcs8Hex) {
  return subtle.importKey("pkcs8", unhex(pkcs8Hex), EC, false, ["deriveBits"]);
}

async function agree(point, pkcs8Hex) {
  const pub = await importPoint(point);
  const priv = await privateKey(pkcs8Hex);
  return new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
}

async function hkdf(secret, info, byteLength) {
  const base = await subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) },
    base,
    byteLength * 8,
  );
  return new Uint8Array(bits);
}

async function seal(keyBytes, nonce, plaintext, aad) {
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(
    await subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: utf8(aad), tagLength: TAG_BYTES * 8 },
      key,
      plaintext,
    ),
  );
}

async function open(keyBytes, nonce, ciphertext, aad) {
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(
    await subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: utf8(aad), tagLength: TAG_BYTES * 8 },
      key,
      ciphertext,
    ),
  );
}

// One profile switch, shared by the three shapes: how wide the carried point
// is, and whether the key and nonce come from the fixture or from HKDF.
const PROFILES = {
  "control-109": { pointHex: "publicUncompressedHex", derived: false },
  "hkdf-97": { pointHex: "publicUncompressedHex", derived: true },
  "hkdf-compressed-65": { pointHex: "publicCompressedHex", derived: true },
};

async function material(profile, point, bind) {
  const shared = await agree(point, inputs.issuer.privatePkcs8Hex);
  if (!PROFILES[profile].derived) {
    return { key: shared, nonce: unhex(inputs.controlNonceHex) };
  }
  return {
    key: await hkdf(shared, inputs.hkdf.keyInfoPrefix + bind, inputs.hkdf.keyBytes),
    nonce: await hkdf(shared, inputs.hkdf.nonceInfoPrefix + bind, inputs.hkdf.nonceBytes),
  };
}

// The publisher side agrees with the issuer public point under the fixed
// ephemeral private key, so every runtime seals the same bytes.
async function sealingMaterial(profile, bind) {
  const shared = await agree(
    unhex(inputs.issuer.publicUncompressedHex),
    inputs.ephemeral.privatePkcs8Hex,
  );
  if (!PROFILES[profile].derived) {
    return { key: shared, nonce: unhex(inputs.controlNonceHex) };
  }
  return {
    key: await hkdf(shared, inputs.hkdf.keyInfoPrefix + bind, inputs.hkdf.keyBytes),
    nonce: await hkdf(shared, inputs.hkdf.nonceInfoPrefix + bind, inputs.hkdf.nonceBytes),
  };
}

function envelope(profile, point, nonce, ciphertext) {
  const parts = PROFILES[profile].derived ? [point, ciphertext] : [point, nonce, ciphertext];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function split(profile, bytes) {
  const pointBytes = profile === "hkdf-compressed-65" ? 33 : 65;
  const point = bytes.subarray(0, pointBytes);
  if (PROFILES[profile].derived) {
    return { point, nonce: null, ciphertext: bytes.subarray(pointBytes) };
  }
  return {
    point,
    nonce: bytes.subarray(pointBytes, pointBytes + 12),
    ciphertext: bytes.subarray(pointBytes + 12),
  };
}

// The probe reports every negative case as one word. The experiment is looking
// for a released key, so the probe reports which of the two outcomes happened and
// nothing about the cause.
async function openEnvelope(profile, bytes, bind) {
  const { point, nonce, ciphertext } = split(profile, bytes);
  const { key, nonce: derivedNonce } = await material(profile, point, bind);
  return open(key, nonce ?? derivedNonce, ciphertext, bind);
}

async function releases(profile, bytes, bind) {
  try {
    const opened = await openEnvelope(profile, bytes, bind);
    return opened.length > 0 ? "key-released" : "no-key";
  } catch {
    return "no-key";
  }
}

async function runProfile(profile) {
  const bind = inputs.bind.value;
  const pointHex = inputs.ephemeral[PROFILES[profile].pointHex];
  const point = unhex(pointHex);

  if (point.length === 33 && compressedImportMode === "unsupported") {
    return { status: "unsupported", reason: "no compressed-point import through the runtime" };
  }

  const { key, nonce } = await sealingMaterial(profile, bind);
  const ciphertext = await seal(key, nonce, unhex(inputs.dcaKeyHex), bind);
  const bytes = envelope(profile, point, nonce, ciphertext);

  const flipped = Uint8Array.from(bytes);
  flipped[flipped.length - TAG_BYTES - 1] ^= 0x01;

  const offCurve = Uint8Array.from(bytes);
  const badPoint = unhex(
    point.length === 33 ? inputs.offCurvePoints.compressedHex : inputs.offCurvePoints.uncompressedHex,
  );
  offCurve.set(badPoint, 0);

  // A compressed x below p whose curve equation has no square root mod p. Only
  // a 33-byte point carries that case, so the wider profiles report `n/a`.
  let nonResiduePoint = "n/a";
  if (point.length === 33) {
    const nonResidue = Uint8Array.from(bytes);
    nonResidue.set(unhex(inputs.offCurvePoints.compressedNonResidueHex), 0);
    nonResiduePoint = await releases(profile, nonResidue, bind);
  }

  let openedKeyHex = null;
  try {
    openedKeyHex = hex(await openEnvelope(profile, bytes, bind));
  } catch (error) {
    openedKeyHex = `open-failed: ${error.name}`;
  }

  return {
    status: "answered",
    envelopeHex: hex(bytes),
    derivedKeyHex: hex(key),
    derivedNonceHex: hex(nonce),
    envelopeBase64url: b64url(bytes),
    decodedBytes: bytes.length,
    base64urlChars: b64url(bytes).length,
    pointBytes: point.length,
    openedKeyHex,
    wrongBind: await releases(profile, bytes, inputs.otherBind.value),
    flippedCiphertext: await releases(profile, flipped, bind),
    invalidPoint: await releases(profile, offCurve, bind),
    nonResiduePoint,
  };
}

async function derivedPair(pkcs8Hex, bind) {
  const shared = await agree(unhex(inputs.issuer.publicUncompressedHex), pkcs8Hex);
  return {
    keyHex: hex(await hkdf(shared, inputs.hkdf.keyInfoPrefix + bind, inputs.hkdf.keyBytes)),
    nonceHex: hex(await hkdf(shared, inputs.hkdf.nonceInfoPrefix + bind, inputs.hkdf.nonceBytes)),
  };
}

async function reuse() {
  const bind = inputs.bind.value;
  return {
    sameEphemeralSameBind: await derivedPair(inputs.ephemeral.privatePkcs8Hex, bind),
    sameEphemeralSameBindRepeat: await derivedPair(inputs.ephemeral.privatePkcs8Hex, bind),
    sameEphemeralOtherBind: await derivedPair(inputs.ephemeral.privatePkcs8Hex, inputs.otherBind.value),
    freshEphemeralSameBind: await derivedPair(inputs.ephemeralFresh.privatePkcs8Hex, bind),
  };
}

await detectCompressedImport();

const observations = {
  runtime: "node",
  runtimeVersion: process.version,
  cryptoProvider: `OpenSSL ${process.versions.openssl}`,
  compressedPointImport: compressedImportMode,
  profiles: {},
  ephemeralReuse: {},
};

for (const profile of Object.keys(PROFILES)) {
  observations.profiles[profile] = await runProfile(profile);
}
const pairs = await reuse();
for (const profile of Object.keys(PROFILES)) {
  if (PROFILES[profile].derived) observations.ephemeralReuse[profile] = pairs;
}

// The recorded block carries every field a profile reports, plus the three
// derived pairs, and nothing the probe did not just compute.
function recordedExpectation() {
  const profiles = {};
  for (const [profile, observed] of Object.entries(observations.profiles)) {
    if (observed.status !== "answered") {
      console.error(`--record needs every profile answered; ${profile} is ${observed.status}`);
      process.exit(2);
    }
    const { status, ...fields } = observed;
    profiles[profile] = fields;
  }
  const pairs = Object.values(observations.ephemeralReuse)[0];
  if (!pairs) {
    console.error("--record needs the ephemeral-reuse pairs, and this run reported none");
    process.exit(2);
  }
  return {
    note: "Recorded by node/probe.mjs --record. Every runtime is held against these bytes.",
    recordedBy: observations.runtime,
    profiles,
    ephemeralReuse: {
      sameEphemeralSameBind: pairs.sameEphemeralSameBind,
      sameEphemeralOtherBind: pairs.sameEphemeralOtherBind,
      freshEphemeralSameBind: pairs.freshEphemeralSameBind,
    },
  };
}

if (recording) {
  fixture.expected = recordedExpectation();
  writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
  console.error(`recorded the expected block into ${fixturePath}`);
} else {
  process.stdout.write(`${JSON.stringify(observations, null, 2)}\n`);
}

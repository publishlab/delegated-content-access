#!/usr/bin/env node
// Records the DCA compact-ECDH vectors in ../test/vectors/dca-compact-ecdh.json.
//
// The Node cases are sealed by this extension's own code through its testing
// facility, from fixed ikm values, so they are reproducible but not
// independent. Independence comes from a second implementation reading them:
// with `--go-result <file>`, this script merges that implementation's report
// and marks, per case, exactly which recorded fields it checked, and adds the
// envelopes it sealed for Node to open. Without the flag, every case records
// an empty `goChecked` list. The Go checker is not included here; `--go-result`
// imports an externally supplied report. Without it, this recorder reproduces
// the Node cases without the recorded independent-check evidence.
//
//   node tools/record-dca-vectors.mjs [--go-result <file>]
//   npx prettier --write test/vectors/dca-compact-ecdh.json
//
// The ephemeral ikm values are searched in order, from counter 0, until each
// case's condition holds: an even and an odd Y for each payload width, and an
// ECDH x-coordinate whose first octet is zero.

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

import { utf8Encode } from "../../../core-shared/codec.js";
import { INFO, open } from "../core-shared--publisher-issuer/envelope.js";
import {
  deriveKeyPair,
  sealEnvelopeWithEphemeral,
} from "../core-shared--publisher-issuer/testing/deterministicHpke.js";

const OUT = new URL("../test/vectors/dca-compact-ecdh.json", import.meta.url);

const ISSUER_LABEL = "dca-compact-ecdh vector issuer";
const EPHEMERAL_LABEL = "dca-compact-ecdh vector ephemeral ";

/** @param {Uint8Array} value */
const hex = (value) => Buffer.from(value).toString("hex");
/** @param {string} label */
const ikmFor = (label) => Uint8Array.from(createHash("sha256").update(label).digest());

const RENDER_ID = "AAECAwQFBgcICQoLDA0ODw";
const KEY16 = Uint8Array.from(Buffer.from("00112233445566778899aabbccddeeff", "hex"));
const SEED32 = Uint8Array.from(
  Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"),
);

/**
 * The cases, each with the condition its ephemeral must meet. The AADs follow
 * the BIND grammar of docs/spec--sealed-key-envelopes.md Section 3. The
 * 32-octet AADs stand in for a composing mechanism's binding; this profile
 * treats the AAD as opaque octets.
 */
const CASES = [
  {
    id: "content-key-even",
    payload: KEY16,
    aad: `dca-bind-key-envelope|c|${RENDER_ID}|bodytext`,
    when: (/** @type {any} */ s) => s.blob[0] === 0x02 && s.dh[0] !== 0,
  },
  {
    id: "content-key-odd",
    payload: KEY16,
    aad: `dca-bind-key-envelope|c|${RENDER_ID}|bodytext`,
    when: (/** @type {any} */ s) => s.blob[0] === 0x03 && s.dh[0] !== 0,
  },
  {
    id: "period-key-dh-leading-zero",
    payload: KEY16,
    aad: `dca-bind-key-envelope|p|${RENDER_ID}|premium|261016T0900`,
    when: (/** @type {any} */ s) => s.dh[0] === 0,
  },
  {
    id: "seed-even",
    payload: SEED32,
    aad: `dca-bind-key-envelope|c|${RENDER_ID}|seedexample`,
    when: (/** @type {any} */ s) => s.blob[0] === 0x02 && s.dh[0] !== 0,
  },
  {
    id: "seed-odd",
    payload: SEED32,
    aad: `dca-bind-key-envelope|c|${RENDER_ID}|seedexample`,
    when: (/** @type {any} */ s) => s.blob[0] === 0x03 && s.dh[0] !== 0,
  },
];

function goResult() {
  const at = process.argv.indexOf("--go-result");
  if (at === -1) return null;
  const file = process.argv[at + 1];
  if (!file) throw new Error("--go-result needs a file");
  return JSON.parse(readFileSync(file, "utf8"));
}

async function main() {
  const go = goResult();
  const issuerIkm = ikmFor(ISSUER_LABEL);
  const issuer = await deriveKeyPair(issuerIkm);

  const cases = [];
  let counter = 0;
  for (const spec of CASES) {
    const aad = utf8Encode(spec.aad);
    for (; ; counter++) {
      const ikmE = ikmFor(EPHEMERAL_LABEL + counter);
      const ephemeral = await deriveKeyPair(ikmE);
      const sealed = await sealEnvelopeWithEphemeral(
        ephemeral,
        spec.payload,
        issuer.publicKey,
        aad,
      );
      if (!spec.when(sealed)) continue;
      const opened = await open(sealed.blob, issuer, aad, spec.payload.length);
      if (hex(opened) !== hex(spec.payload)) throw new Error(`${spec.id} did not open`);
      const goCase = go?.cases?.[spec.id];
      if (go && goCase?.failed?.length) {
        throw new Error(`Go refused ${spec.id}: ${goCase.failed.join(", ")}`);
      }
      cases.push({
        id: spec.id,
        ephemeralLabel: EPHEMERAL_LABEL + counter,
        ikmE: hex(ikmE),
        skEm: hex(ephemeral.skBytes),
        enc: hex(sealed.enc),
        dh: hex(sealed.dh),
        sharedSecret: hex(sealed.sharedSecret),
        key: hex(sealed.key),
        baseNonce: hex(sealed.baseNonce),
        payload: hex(spec.payload),
        aadText: spec.aad,
        aad: hex(aad),
        ciphertext: hex(sealed.ciphertext),
        blob: hex(sealed.blob),
        blobBase64url: Buffer.from(sealed.blob).toString("base64url"),
        goChecked: goCase?.checked ?? [],
      });
      counter++;
      break;
    }
  }

  const document = {
    profile: "dca-profile-compact-ecdh",
    specification: "docs/spec-profile--compact-ecdh.md",
    provenance: {
      recorder:
        "js/extensions/compact-ecdh/tools/record-dca-vectors.mjs, sealing through this " +
        "extension's testing facility; ikm values are SHA-256 of the UTF-8 labels given",
      independentCheck: go
        ? `${go.implementation}: goChecked lists, per case, the fields that implementation ` +
          "checked on its own, one name per check; it never checks sharedSecret, which " +
          "crypto/hpke does not expose; goSealed holds envelopes it sealed"
        : "none recorded",
      goCheckedMeaning: {
        skRm: "Go DeriveKeyPair from ikmR gives this private key",
        pkRm: "Go DeriveKeyPair from ikmR gives this public key",
        skEm: "Go DeriveKeyPair from ikmE gives this private key",
        enc: "Go DeriveKeyPair from ikmE gives this public key",
        "blob[0:33]": "Go crypto/elliptic compresses enc to these bytes",
        "blob[33:]": "the blob tail equals the recorded ciphertext",
        "decompressed-enc": "Go crypto/elliptic decompresses blob[0:33] to enc",
        dh: "Go crypto/ecdh gives this x-coordinate from both sides",
        "ciphertext-opens":
          "Go crypto/hpke opens the ciphertext under the decompressed enc, the issuer key, " +
          "info and aad, to payload",
        "key-and-nonce-reproduce":
          "Go AES-256-GCM under key and baseNonce at sequence zero reproduces the ciphertext",
        "flipped-prefix-refused": "Go crypto/hpke refuses the other point with the same x",
      },
    },
    info: hex(INFO),
    infoText: "dca-derivation-compact-ecdh",
    issuer: {
      label: ISSUER_LABEL,
      ikmR: hex(issuerIkm),
      skRm: hex(issuer.skBytes),
      pkRm: hex(issuer.pkBytes),
      goChecked: go?.issuer?.checked ?? [],
    },
    cases,
    goSealed: go?.sealed ?? [],
  };
  writeFileSync(OUT, JSON.stringify(document, null, 2) + "\n");
  console.error(
    `wrote ${cases.length} cases, ${document.goSealed.length} Go-sealed, last counter ${counter - 1}`,
  );
}

await main();

#!/usr/bin/env node
// Regenerates the canonical chain-key construction vectors directly from their
// retained inputs. It deliberately does not import the extension implementation.

import { readFileSync, writeFileSync } from "node:fs";

const file = new URL("../test/fixtures/dca-profile-chain-keys.vectors.json", import.meta.url);
// The profile identifier the set is recorded for, and the `constructionId`
// octets inside every context. They are different identities:
// the first names the profile, the second enters every derivation.
const profile = "dca-profile-chain-keys";
const constructionId = "dca-construction-chain-keys";
const chainKeyBytes = 16;
const keyDerivationSecretBytes = 32;
const encoder = new TextEncoder();

/** @param {string} value */
function decodeHex(value) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new Error(`not hex: ${JSON.stringify(value)}`);
  return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
}

/** @param {Uint8Array} value */
function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

/** @param {string} value */
function unbase64url(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

/** @param {number} value */
function u16(value) {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value);
  return bytes;
}

/** @param {number} value */
function u32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

/** @param {Uint8Array[]} parts */
function join(parts) {
  const bytes = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}

/** @param {number} domain @param {any} row @param {number} position */
function context(domain, row, position) {
  const group = encoder.encode(row.accessGroup);
  return join([
    Uint8Array.of(domain),
    u16(encoder.encode(constructionId).length),
    encoder.encode(constructionId),
    u16(group.length),
    group,
    u16(row.chainsPerDay),
    u16(row.periodMinutes),
    u32(row.windowStart),
    u16(position),
  ]);
}

/** @param {Uint8Array} ikm @param {Uint8Array} info @param {number} bytes */
async function hkdf(ikm, info, bytes) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info },
      key,
      bytes * 8,
    ),
  );
}

/** @param {string} label @param {any} row */
function coordinateFor(label, row) {
  const minutes =
    Date.parse(
      `20${label.slice(0, 2)}-${label.slice(2, 4)}-${label.slice(4, 6)}T${label.slice(7, 9)}:${label.slice(9, 11)}Z`,
    ) / 60_000;
  const windowMinutes = 1440 / row.chainsPerDay;
  const windowStart = minutes - (minutes % windowMinutes);
  return {
    windowStart,
    position: (minutes - windowStart) / row.periodMinutes,
    N: windowMinutes / row.periodMinutes,
  };
}

/** @param {any} row @param {number} position */
async function chainKeyAt(row, position) {
  const secret = decodeHex(row.secretHex);
  if (secret.length !== keyDerivationSecretBytes)
    throw new Error(`${row.id}: key-derivation-secret width`);
  let chainKey = await hkdf(secret, context(0x01, row, row.N - 1), chainKeyBytes);
  for (let at = row.N - 2; at >= position; at--)
    chainKey = await hkdf(chainKey, context(0x02, row, at), chainKeyBytes);
  return chainKey;
}

/** @param {any} row */
async function regenerateCase(row) {
  const chainKeys = [];
  for (let position = 0; position < row.N; position++)
    chainKeys.push(await chainKeyAt(row, position));
  const periodKeys = await Promise.all(
    chainKeys.map((chainKey, position) =>
      hkdf(chainKey, context(0x03, row, position), chainKeyBytes),
    ),
  );
  const terminal = chainKeys.at(-1);
  const cutoffChainKeys = Object.fromEntries(
    await Promise.all(
      Object.keys(row.cutoffChainKeys ?? {}).map(async (label) => {
        const coordinate = coordinateFor(label, row);
        return [label, base64url(await chainKeyAt({ ...row, ...coordinate }, coordinate.position))];
      }),
    ),
  );
  const hex = (value) => Buffer.from(value).toString("hex");
  const regenerated = {
    ...row,
    expansion: periodKeys.map(base64url),
    leafInfoHex: hex(context(0x03, row, row.position)),
    rootInfoHex: hex(context(0x01, row, row.N - 1)),
    stepInfoHex: hex(context(0x02, row, row.N - 2)),
    periodKey: base64url(periodKeys[row.position]),
    chainKeyAfterOneStep: base64url(chainKeys[row.N - 2]),
    rootChainKey: base64url(terminal),
  };
  if (Object.hasOwn(row, "cutoffChainKeys")) regenerated.cutoffChainKeys = cutoffChainKeys;
  return regenerated;
}

/** @param {any} side */
async function separationPeriodKey(side) {
  const row = { ...side, id: "separation" };
  const chainKey = await chainKeyAt(row, row.position);
  return base64url(await hkdf(chainKey, context(0x03, row, row.position), chainKeyBytes));
}

const document = JSON.parse(readFileSync(file, "utf8"));
const former = document.status === "current-32" ? structuredClone(document) : null;
const cases = await Promise.all(document.cases.map(regenerateCase));
const separation = await Promise.all(
  document.separation
    .filter((row) => row.a.construction === constructionId && row.b.construction === constructionId)
    .map(async (row) => ({
      ...row,
      periodKeyA: await separationPeriodKey(row.a),
      periodKeyB: await separationPeriodKey(row.b),
    })),
);

if (former !== null) {
  for (const row of cases) {
    const previous = former.cases.find((candidate) => candidate.id === row.id);
    if (
      base64url(unbase64url(previous.rootChainKey).slice(0, chainKeyBytes)) !== row.rootChainKey
    ) {
      throw new Error(`${row.id}: Root prefix relation changed`);
    }
    if (
      row.chainKeyAfterOneStep ===
        base64url(unbase64url(previous.chainKeyAfterOneStep).slice(0, chainKeyBytes)) ||
      row.periodKey === base64url(unbase64url(previous.periodKey).slice(0, chainKeyBytes))
    ) {
      throw new Error(`${row.id}: Step/Leaf unexpectedly retained their old prefix`);
    }
  }
}

Object.assign(document, {
  cases,
  constructionIdentity: constructionId,
  generatedBy:
    "node extensions/chain-keys/tools/regenerate-canonical-vectors.mjs; direct WebCrypto HKDF-SHA-256 generator with the dca-construction-chain-keys contexts and 32-byte key-derivation secret. Re-running this command is deterministic.",
  generationSource:
    "This generator rebuilds every context and derives every Root, Step and Leaf without importing the extension implementation.",
  profile,
  replacement:
    "Canonical v1 set under the construction identifier dca-construction-chain-keys. Every Root, Step and Leaf context carries that identifier, and this generator derives every value in the set; none was copied from another set.",
  semanticWidths: {
    chainKey: 16,
    contentKey: 16,
    keyDerivationSecret: 32,
    periodKey: 16,
    periodKeyWrapAlgorithm: "AES-128-GCM",
  },
  separation,
  setIdentity: profile,
  status: "canonical-16",
});

writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`);

#!/usr/bin/env node
// Regenerates the frozen canonical period-chain vectors directly from their
// retained inputs. It deliberately does not import the extension implementation.

import { readFileSync, writeFileSync } from "node:fs";

const file = new URL("../test/fixtures/dca-period-chain-v1.vectors.json", import.meta.url);
const construction = "dca-period-chain-v1";
const stateBytes = 16;
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
    u16(construction.length),
    encoder.encode(construction),
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

/** @param {number} minutes */
function labelAt(minutes) {
  const date = new Date(minutes * 60_000);
  const part = (value) => String(value).padStart(2, "0");
  return (
    `${part(date.getUTCFullYear() % 100)}${part(date.getUTCMonth() + 1)}${part(date.getUTCDate())}` +
    `T${part(date.getUTCHours())}${part(date.getUTCMinutes())}`
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
async function stateAt(row, position) {
  const secret = decodeHex(row.secretHex);
  if (secret.length !== keyDerivationSecretBytes)
    throw new Error(`${row.id}: key-derivation-secret width`);
  let state = await hkdf(secret, context(0x01, row, row.N - 1), stateBytes);
  for (let at = row.N - 2; at >= position; at--)
    state = await hkdf(state, context(0x02, row, at), stateBytes);
  return state;
}

/** @param {any} row */
async function regenerateCase(row) {
  const states = [];
  for (let position = 0; position < row.N; position++) states.push(await stateAt(row, position));
  const leaves = await Promise.all(
    states.map((state, position) => hkdf(state, context(0x03, row, position), stateBytes)),
  );
  const terminal = states.at(-1);
  const cutoffStates = Object.fromEntries(
    await Promise.all(
      Object.keys(row.cutoffStates ?? {}).map(async (label) => {
        const coordinate = coordinateFor(label, row);
        return [label, base64url(await stateAt({ ...row, ...coordinate }, coordinate.position))];
      }),
    ),
  );
  const regenerated = {
    ...row,
    expansion: leaves.map(base64url),
    leaf: base64url(leaves[row.position]),
    stateAfterOneStep: base64url(states[row.N - 2]),
    terminal: base64url(terminal),
  };
  if (Object.hasOwn(row, "cutoffStates")) regenerated.cutoffStates = cutoffStates;
  return regenerated;
}

/** @param {any} side */
async function separationLeaf(side) {
  const row = { ...side, id: "separation" };
  const state = await stateAt(row, row.position);
  return base64url(await hkdf(state, context(0x03, row, row.position), stateBytes));
}

const document = JSON.parse(readFileSync(file, "utf8"));
const former = document.status === "current-32" ? structuredClone(document) : null;
const cases = await Promise.all(document.cases.map(regenerateCase));
const separation = await Promise.all(
  document.separation
    .filter((row) => row.a.profile === construction && row.b.profile === construction)
    .map(async (row) => ({
      ...row,
      leafA: await separationLeaf(row.a),
      leafB: await separationLeaf(row.b),
    })),
);

if (former !== null) {
  for (const row of cases) {
    const previous = former.cases.find((candidate) => candidate.id === row.id);
    if (base64url(unbase64url(previous.terminal).slice(0, stateBytes)) !== row.terminal) {
      throw new Error(`${row.id}: Root prefix relation changed`);
    }
    if (
      row.stateAfterOneStep ===
        base64url(unbase64url(previous.stateAfterOneStep).slice(0, stateBytes)) ||
      row.leaf === base64url(unbase64url(previous.leaf).slice(0, stateBytes))
    ) {
      throw new Error(`${row.id}: Step/Leaf unexpectedly retained their old prefix`);
    }
  }
}

Object.assign(document, {
  cases,
  generatedBy:
    "node extensions/period-chain/tools/regenerate-canonical-vectors.mjs; direct WebCrypto HKDF-SHA-256 generator with the retained dca-period-chain-v1 contexts and 32-byte key-derivation secret. Re-running this command is deterministic.",
  generationSource:
    "This generator rebuilds every context and derives every Root, Step and Leaf without importing the extension implementation.",
  replacement:
    "Canonical v1 set: Root is the first 16 bytes of the former 32-byte Root because its identifier and Root inputs are unchanged. Step and Leaf are recomputed from the shortened state and deliberately differ from their former 32-byte values. The retired differently identified construction was domain-separated and its bytes were not copied.",
  semanticWidths: {
    chainState: 16,
    contentKey: 16,
    exactLeaf: 16,
    exactWrapAlgorithm: "AES-128-GCM",
    keyDerivationSecret: 32,
  },
  separation,
  status: "canonical-16",
});

writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`);

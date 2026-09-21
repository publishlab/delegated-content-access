// @ts-check
//
// Writes the SHA256SUMS file a vector or fixture set carries, from the bytes on disk.
//
// Consumers take the set as the contract, so they have to be able to check
// "these are the bytes" where no replayer runs: no JSON parser, no Node, no
// PHP. This writes plain `sha256sum` format, so changing into any generated set
// and running `sha256sum -c SHA256SUMS` checks the bytes. Argon2 ships the same
// pair, a `.shasum` per KAT plus a check-sums script.
//
// The generator calls this after every write. A devel set may change when its
// inputs change; an unchanged regeneration writes the same bytes and sums. A
// devel match tells you the bytes are the ones the generator last wrote. The
// generator refuses a frozen fixture directory or stable vector set before any
// of this, so its sums file covers hand edits and bad merges rather than regeneration.
//
// This leaves metadata out: set.json records a vector set's phase and
// manifest.json records fixture stability. A reader must not mistake either
// metadata change for a tampered payload.
//
// `node:fs` stays in tooling and tests. Browser-facing core, port and demo actor
// modules run without it; the hashing operation itself uses WebCrypto.

import { readdirSync, readFileSync, writeFileSync } from "node:fs";

/** The name every set uses, and the file `sha256sum -c` reads. */
export const CHECKSUM_FILE = "SHA256SUMS";

/**
 * set.json and manifest.json describe the set; the generated payload bytes live
 * in the other files.
 */
const SET_METADATA = new Set(["set.json", "manifest.json"]);

/**
 * The set's vectors, in name order, so two runs write the same file.
 *
 * @param {string} dir
 * @returns {string[]}
 */
export function vectorFilesIn(dir) {
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json") && !SET_METADATA.has(name))
    .sort();
}

/**
 * `sha256sum`'s own line format: lowercase hex, two spaces, the bare file
 * name. Two spaces means text mode there; this reads and hashes the bytes the
 * same way either way, and the format lets a tool that knows nothing about this
 * tree check the file.
 *
 * @param {string} dir  with a trailing slash
 * @returns {Promise<string[]>} the vector names hashed
 */
export async function writeChecksums(dir) {
  const files = vectorFilesIn(dir);
  const lines = [];

  for (const file of files) {
    const digest = await crypto.subtle.digest("SHA-256", readFileSync(dir + file));
    const hex = [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    lines.push(`${hex}  ${file}`);
  }

  writeFileSync(dir + CHECKSUM_FILE, `${lines.join("\n")}\n`);
  return files;
}

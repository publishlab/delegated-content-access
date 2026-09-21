// @ts-check
//
// This module measures what one article body costs on the wire once it is sealed, in
// each of the three compression profiles.
//
// `run-synthetic.js` and `run-downloads.js` import it, pass one prepared form at a
// time, and print the rows it returns.
//
// A form is `html` for the fragment of a bodytext field, `txt` for the same body as
// readable text, or `json` for a structured body. Each form produces one row per
// profile:
//
//   base             the ciphertext is the sealed form as it stands
//   extension gzip   the form is gzipped at level 9, then sealed
//   extension br     the form is compressed with Brotli, then sealed
//
// Columns, all in bytes:
//
//   plain     the form as this module received it, the same in all three rows of a form
//   cipher    the ciphertext, the sealed input plus the 16-byte tag
//   wire      that ciphertext as one base64url string, what the publisher writes into
//             the `dca-sealed-content` block
//   wire gz   gzip level 9 of that string, the way transport gzip compresses it
//   wire br   Brotli at its default quality over the same string
//
// The wire columns count the bytes sent over the network. base64url carries six bits
// per byte, so a transport codec still compresses a string of random ciphertext, and
// the base row shows by how much.
//
// Each sample gets its own table, indented under a line naming it, with one dated
// header line above them all. Every cell is padded to its column's width across all
// the tables, so the raw markdown reads as fixed-width text without a renderer and the
// columns line up from one sample to the next.
//
// Counts are grouped in threes with a space. On the two extension rows every count
// after `plain` is followed by its share of the base row's count in the same column,
// so `10 232 (25%)` under `wire` is a quarter of the base row's wire bytes. `plain`
// stays bare, because the three rows of a form share one input.
//
// Sealing goes through `core-shared/aead.js`, the call `core-publisher/Sealer.js` makes
// for a content item, with a fresh random 16-byte key and 12-byte nonce and an aad of
// the same `resourceId | version | contentName` shape, so these numbers come out of the
// reference implementation's own sealing path.
//
// Ciphertext length is input plus tag, and base64url of a fixed length is fixed too, so
// those columns are exact and a rerun reports them again. Compressing a fresh
// ciphertext varies: a different random key gives different bytes and moves gzip and
// Brotli by a byte or two. So each row seals `RUNS` times and reports the median for
// `wire gz` and `wire br`, as
// `extensions/content-key-seal-omission/test-lib/measure.js` does for its gzip column.

import { brotliCompressSync, gzipSync } from "node:zlib";

import { encrypt, NONCE_BYTES } from "../../core-shared/aead.js";
import { AAD_DELIMITER } from "../../core-shared--client-publisher/names.js";

/** How many seals go into each row's compressed-wire median. */
const RUNS = 5;

/** The dca-data format version `Sealer` writes into a content aad. */
const VERSION = "1";

/** The canonical AES-128 content key width `Sealer` seals a content item under. */
const KEY_BYTES = 16;

/**
 * One row of the table.
 *
 * @typedef {object} Row
 * @property {string} sample
 * @property {string} form
 * @property {string} profile
 * @property {number} plain
 * @property {number} cipher
 * @property {number} wire
 * @property {number} wireGz
 * @property {number} wireBr
 */

/**
 * The middle of an odd number of readings.
 *
 * @param {number[]} values
 * @returns {number}
 */
function median(values) {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}

/**
 * One content item's ciphertext, sealed the way `Sealer.seal()` does.
 *
 * @param {Uint8Array} plaintext
 * @param {string} resourceId
 * @param {string} contentName
 * @returns {Promise<Uint8Array>}
 */
async function sealed(plaintext, resourceId, contentName) {
  const key = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const aad = [resourceId, VERSION, contentName].join(AAD_DELIMITER);
  return encrypt(key, nonce, plaintext, new TextEncoder().encode(aad));
}

/**
 * Measure one prepared form of one article body: three profiles.
 *
 * @param {object} sample
 * @param {string} sample.label - what the rows are named after
 * @param {string} sample.form - `html`, `txt` or `json`
 * @param {string} sample.bytes - the body in that form
 * @returns {Promise<Row[]>}
 */
export async function measureSample({ label, form, bytes }) {
  /** @type {Row[]} */
  const rows = [];
  const plain = Buffer.from(bytes, "utf8");

  const profiles = [
    { name: "base", bytes: plain },
    { name: "extension gzip", bytes: gzipSync(plain, { level: 9 }) },
    { name: "extension br", bytes: brotliCompressSync(plain) },
  ];

  for (const profile of profiles) {
    /** @type {number[]} */
    const wireGz = [];
    /** @type {number[]} */
    const wireBr = [];
    let cipher = 0;
    let wire = 0;

    for (let run = 0; run < RUNS; run += 1) {
      const ciphertext = await sealed(profile.bytes, label, `body-${form}`);
      const carried = Buffer.from(ciphertext).toString("base64url");
      cipher = ciphertext.length;
      wire = carried.length;
      wireGz.push(gzipSync(carried, { level: 9 }).length);
      wireBr.push(brotliCompressSync(carried).length);
    }

    rows.push({
      sample: label,
      form,
      profile: profile.name,
      plain: plain.length,
      cipher,
      wire,
      wireGz: median(wireGz),
      wireBr: median(wireBr),
    });
  }

  return rows;
}

/** How far each table is indented, under the line naming its sample. */
const INDENT = "    ";

/** The byte columns compared against the base row, in the order they are printed. */
const SHARED_COLUMNS = /** @type {const} */ (["cipher", "wire", "wireGz", "wireBr"]);

/**
 * @param {number} count
 * @returns {string} digits grouped in threes, `30 720`
 */
function grouped(count) {
  return String(count).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
}

/**
 * @param {number} count
 * @param {number} [against] - the base row's count in the same column
 * @returns {string}
 */
function cell(count, against) {
  if (against === undefined) return grouped(count);
  return `${grouped(count)} (${Math.round((count / against) * 100)}%)`;
}

/**
 * The markdown table, under a header line giving the date, the Node version and the
 * codec settings, so a table pasted into a design document still shows when and on what
 * it was measured. Each extension row is compared against the base row of its own
 * sample and form.
 *
 * @param {Row[]} rows
 * @returns {string}
 */
export function table(rows) {
  const when = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Oslo",
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date());

  /** @type {Map<string, Row>} */
  const bases = new Map();
  for (const row of rows) {
    if (row.profile === "base") bases.set(`${row.sample}/${row.form}`, row);
  }

  /** @type {Map<string, string[][]>} */
  const samples = new Map();
  for (const row of rows) {
    const base = row.profile === "base" ? undefined : bases.get(`${row.sample}/${row.form}`);
    const cells = [
      row.form,
      row.profile,
      grouped(row.plain),
      ...SHARED_COLUMNS.map((column) => cell(row[column], base?.[column])),
    ];
    samples.set(row.sample, [...(samples.get(row.sample) ?? []), cells]);
  }

  const header = ["form", "profile", "plain", "cipher", "wire", "wire gz", "wire br"];
  const widths = header.map((name, column) =>
    Math.max(name.length, 3, ...[...samples.values()].flat().map((cells) => cells[column].length)),
  );

  /**
   * @param {string[]} cells
   * @param {string} [fill] - what the padding is made of
   * @returns {string}
   */
  const line = (cells, fill = " ") =>
    `${INDENT}| ${cells.map((text, column) => text.padEnd(widths[column], fill)).join(" | ")} |`;

  const headerLine = line(header);
  const rule = line(
    widths.map(() => "---"),
    "-",
  );

  /** @type {string[]} */
  const out = [
    `Measured ${when} Oslo, Node ${process.version}, gzip level 9, Brotli default quality.`,
    "",
  ];

  for (const [sample, body] of samples) {
    out.push(sample, "", headerLine, rule, ...body.map((cells) => line(cells)), "");
  }

  return out.join("\n");
}

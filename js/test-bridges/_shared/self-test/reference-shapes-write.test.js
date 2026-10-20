import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { SHAPES_FILE, referenceShapes } from "../reference-shapes-write.mjs";

/**
 * Reads the shapes of `source`, written as `fixture.js` in a temporary tree
 * with its own config, and returns that module's entry.
 *
 * @param {string} source
 */
function shapesOf(source) {
  return modulesOf(source)["fixture.js"] ?? {};
}

/** @param {string} source @param {Record<string, string>} [extra] */
function modulesOf(source, extra = {}) {
  const directory = mkdtempSync(join(tmpdir(), "dca-reference-shapes-"));
  try {
    writeFileSync(
      join(directory, "jsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          allowJs: true,
          checkJs: true,
          noEmit: true,
          target: "ES2024",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          lib: ["ES2024", "DOM"],
        },
        include: ["**/*.js"],
      }),
    );
    writeFileSync(join(directory, "fixture.js"), source);
    for (const [name, contents] of Object.entries(extra)) {
      const path = join(directory, name);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, contents);
    }
    return referenceShapes(join(directory, "jsconfig.json")).modules;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const opaque = "return /** @type {any} */ (undefined);";

test("bytes and strings keep apart, through promises and aliases", () => {
  assert.deepEqual(
    shapesOf(`
/** @typedef {Uint8Array} Octets */
/** @returns {Uint8Array} */ export function bytes() { ${opaque} }
/** @returns {string} */ export function text() { ${opaque} }
/** @returns {Promise<Octets>} */ export async function later() { ${opaque} }
/** @param {string} value @returns {Uint8Array} */
export const arrow = (value) => new TextEncoder().encode(value);
`),
    {
      arrow: "Uint8Array",
      bytes: "Uint8Array",
      later: "Uint8Array",
      text: "string",
    },
  );
});

test("records and lists keep apart: Readonly, intersections, optional members, index signatures, arrays and tuples", () => {
  assert.deepEqual(
    shapesOf(`
/** @typedef {{ key: Uint8Array, name: string, count: number, note?: string }} Entry */
/** @returns {Readonly<Entry>} */ export function entry() { ${opaque} }
/** @returns {{ key: Uint8Array } & { name: string }} */ export function joined() { ${opaque} }
/** @returns {Record<string, Uint8Array>} */ export function keyed() { ${opaque} }
/** @returns {{ [name: string]: string[] }} */ export function indexed() { ${opaque} }
/** @returns {readonly Uint8Array[]} */ export function many() { ${opaque} }
/** @returns {[Uint8Array, string, number]} */ export function pair() { ${opaque} }
/** @returns {Array<{ blob: Uint8Array }>} */ export function nested() { ${opaque} }
/** @returns {{}} */ export function empty() { ${opaque} }
`),
    {
      empty: { record: {} },
      entry: {
        record: {
          key: "Uint8Array",
          name: "string",
          note: { anyOf: ["string", "undefined"] },
        },
      },
      indexed: { record: {}, values: { list: "string" } },
      joined: { record: { key: "Uint8Array", name: "string" } },
      keyed: { record: {}, values: "Uint8Array" },
      many: { list: "Uint8Array" },
      nested: { list: { record: { blob: "Uint8Array" } } },
      pair: { tuple: ["Uint8Array", "string", "value"] },
    },
  );
});

test("null and undefined keep apart", () => {
  assert.deepEqual(
    shapesOf(`
/** @returns {string | undefined} */ export function maybe() { ${opaque} }
/** @returns {Uint8Array | null} */ export function nullable() { ${opaque} }
/** @returns {undefined} */ export function nothing() { ${opaque} }
/** @returns {void} */ export function none() {}
/** @returns {{ at?: number }} */ export function optional() { ${opaque} }
`),
    {
      maybe: { anyOf: ["string", "undefined"] },
      none: "undefined",
      nothing: "undefined",
      nullable: { anyOf: ["Uint8Array", "null"] },
      optional: { record: { at: { anyOf: ["undefined", "value"] } } },
    },
  );
});

test("a union whose records share a literal member keys each branch by it", () => {
  assert.deepEqual(
    shapesOf(`
/** @returns {{ kind: "list", items: string[] } | { kind: "map", items: Record<string, string> }} */
export function named() { ${opaque} }
/** @returns {{ ok: true, value: Uint8Array } | { ok: false, reason: string } | undefined} */
export function flagged() { ${opaque} }
/** @returns {{ a: Uint8Array } | { b: string }} */
export function loose() { ${opaque} }
`),
    {
      flagged: {
        anyOf: [
          "undefined",
          {
            discriminant: "ok",
            cases: {
              false: { record: { reason: "string" } },
              true: { record: { value: "Uint8Array" } },
            },
          },
        ],
      },
      loose: { anyOf: [{ record: { a: "Uint8Array" } }, { record: { b: "string" } }] },
      named: {
        discriminant: "kind",
        cases: {
          '"list"': { record: { items: { list: "string" } } },
          '"map"': { record: { items: { record: {}, values: "string" } } },
        },
      },
    },
  );
});

test("exports the reference type leaves open stay unmarked", () => {
  assert.deepEqual(
    shapesOf(`
/** @template T @param {T} value @returns {T} */ export function same(value) { return value; }
/** @returns {any} */ export function anything() { ${opaque} }
/** @returns {unknown} */ export function unknowable() { ${opaque} }
/** @returns {string | any} */ export function widened() { ${opaque} }
/** @returns {number} */ export function count() { return 1; }
/** @returns {Date} */ export function when() { return new Date(); }
/** @returns {Map<string, string>} */ export function map() { return new Map(); }
/** @returns {CryptoKey} */ export function key() { ${opaque} }
export function undocumented() { return new Uint8Array(); }
export const VALUE = new Uint8Array();
export class Thing {}
`),
    {},
  );
});

test("the shapes list modules, exports and members in sorted order", () => {
  const shapes = shapesOf(`
/** @returns {{ b: string, a: Uint8Array }} */ export function zeta() { ${opaque} }
/** @returns {string} */ export function alpha() { ${opaque} }
`);
  assert.deepEqual(Object.keys(shapes), ["alpha", "zeta"]);
  assert.deepEqual(Object.keys(/** @type {any} */ (shapes.zeta).record), ["a", "b"]);
});

test("the committed shapes match the reference's JSDoc types", () => {
  const stale =
    "reference-shapes.json is stale; from js/ run node test-bridges/_shared/reference-shapes-write.mjs";
  const committed = JSON.parse(readFileSync(SHAPES_FILE, "utf8"));
  const current = referenceShapes();
  assert.deepEqual(committed, current, stale);
  assert.equal(JSON.stringify(committed), JSON.stringify(current), stale);
});

test("ordinary reference shapes do not depend on optional experiment modules", () => {
  const source =
    "/** @returns {Uint8Array} */ export function bytes() { return new Uint8Array(); }";
  assert.deepEqual(
    modulesOf(source, {
      "experiments/candidate/implementation/provider.js":
        "/** @returns {string} */ export function experiment() { return 'candidate'; }",
    }),
    modulesOf(source),
    "removing experiments must leave ordinary reference shapes unchanged",
  );
});

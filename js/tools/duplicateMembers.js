// @ts-check
//
// A standalone experimental duplicate-member lint/test utility, built as a tokenizer.
//
// The scan reads the raw text, because a parser never hands back the duplicate. RFC
// 8259 says member names SHOULD be unique, and every parser in reach (JSON.parse, PHP
// json_decode, Python json) keeps the last occurrence and hands back an object that
// cannot express the duplicate, so the duplicate is gone from the parsed value.
// `verification/fixtures/v1/reference/protocol-regressions/reject-duplicate-member-name.json` holds that
// shape: one member name repeated inside `sealed.contentKeys`, the two occurrences
// holding blobs the publisher sealed at two different coordinates.
//
// The scan catches a publisher bug. The publisher seals each blob under one coordinate,
// and the issuer rebuilds that coordinate from the renderId in the verified resource and
// the name it read the blob under, in the one pass, so a label and a key cannot come
// apart: whichever occurrence a parser keeps, a name yields its own key or no key. A
// duplicate member breaks something else instead: two conformant runtimes read one
// document as two different requests.
// That is a publisher bug in rendered output and a support case in production, which is
// why this sits on the publisher's side and off the issuer's path.
//
// The scan tracks which object encloses each name. DCA reuses member names across
// sibling objects on purpose: every wrap record carries `nonce`, `t` and `key`, every
// content item carries `contentType`, and a contentName reappears as an accessGroup name
// one level down. A scan that only counts names reports every one of those as a
// duplicate. On the v1 render fixture that is eleven names, all false, none of them a
// duplicate member anywhere. A publisher switches off a check that noisy, and the real
// duplicate then gets through.
//
// `flatNameScan` is that name-only version, sharing this file's token walk so the only
// difference between the two answers is whether the scan consults the containing object.
// It measures what the cheap version costs.
//
// The scan walks the grammar far enough to tell member names from values and to know
// what object encloses them. It decodes strings while walking but retains only
// member names. It refuses text it cannot walk, because reporting "no duplicates"
// on text the walk failed on is worse than no scan.
//
// This reference runs it only from its test tier. A publisher may run the pure utility
// over rendered output in CI or a browser build, and that deployment wiring sits outside
// this repository's reference path. Scanning a `.dca-data` string needs no `node:fs` and
// no Node globals.

import { dcaError } from "../core-shared/errors.js";

/**
 * @typedef {object} Member
 * @property {string} name - the member name, unescaped
 * @property {string} parent - path of the object holding it, for a reader
 * @property {number} parentId - which object holds it, for the tally. Paths
 *   cannot do that job: `{"a": {"x": 1}, "a": {"x": 2}}` gives both inner
 *   objects the path `$.a`, and grouping by path would count their two `x`
 *   members as a duplicate, a false positive created by the duplicate the scan
 *   is looking for.
 * @property {string} path - path of the member itself
 * @property {number} index - offset of the name's opening quote in the text
 */

/**
 * @typedef {object} Duplicate
 * @property {string} name
 * @property {string} parent - the one object where the name repeats
 * @property {number} index - offset of the repeating occurrence
 * @property {number} occurrence - 2 for the first repeat, 3 for the next
 */

/** A name that reads back as itself in a path; anything else gets quoted. */
const PLAIN_NAME = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

/** JSON numbers, whole grammar, so a malformed one ends the scan with an error. */
const NUMBER = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;

const ESCAPES = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/**
 * @param {string} message
 * @param {number} at
 * @returns {Error}
 */
function scanError(message, at) {
  return dcaError("duplicate_scan_failed", `${message} at offset ${at}`);
}

/**
 * @param {string} parent
 * @param {string} name
 * @returns {string}
 */
function childPath(parent, name) {
  return PLAIN_NAME.test(name) ? `${parent}.${name}` : `${parent}[${JSON.stringify(name)}]`;
}

/**
 * @param {string} text
 * @param {number} i
 * @returns {number}
 */
function skipWhitespace(text, i) {
  while (
    i < text.length &&
    (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")
  )
    i += 1;
  return i;
}

/**
 * A JSON string, unescaped. The scan compares names after unescaping: an escaped spelling
 * and a literal one are the same member name, and a scan comparing the raw spans
 * would call them two names and miss the duplicate.
 *
 * @param {string} text
 * @param {number} start - offset of the opening quote
 * @returns {{ value: string, next: number }}
 */
function readString(text, start) {
  let i = start + 1;
  let value = "";

  for (;;) {
    if (i >= text.length) throw scanError("unterminated string", start);
    const ch = text[i];

    if (ch === '"') return { value, next: i + 1 };

    if (ch === "\\") {
      const code = text[i + 1];
      if (code === "u") {
        const hex = text.slice(i + 2, i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw scanError("bad \\u escape", i);
        // By code unit, so a surrogate pair reassembles on its own.
        value += String.fromCharCode(parseInt(hex, 16));
        i += 6;
        continue;
      }
      const mapped = /** @type {any} */ (ESCAPES)[code];
      if (mapped === undefined) throw scanError(`bad escape \\${code}`, i);
      value += mapped;
      i += 2;
      continue;
    }

    // RFC 8259: a string carries control characters only as escapes.
    if (ch < " ") throw scanError("raw control character in string", i);

    value += ch;
    i += 1;
  }
}

/**
 * @typedef {object} Walk
 * @property {Member[]} members - every member name, in document order
 * @property {number} objects - how many objects have been opened; readObject uses
 *   the count at the moment an object opens as that object's id
 */

/**
 * @param {string} text
 * @param {number} start
 * @param {string} path
 * @param {Walk} walk
 * @returns {number} the offset just past this value
 */
function readValue(text, start, path, walk) {
  const i = skipWhitespace(text, start);
  if (i >= text.length) throw scanError("value expected", i);
  const ch = text[i];

  if (ch === "{") return readObject(text, i, path, walk);
  if (ch === "[") return readArray(text, i, path, walk);
  if (ch === '"') return readString(text, i).next;

  for (const literal of ["true", "false", "null"]) {
    if (text.startsWith(literal, i)) return i + literal.length;
  }

  const number = NUMBER.exec(text.slice(i));
  if (number) return i + number[0].length;

  throw scanError(`value expected, got ${JSON.stringify(text.slice(i, i + 8))}`, i);
}

/**
 * @param {string} text
 * @param {number} start - offset of `{`
 * @param {string} path
 * @param {Walk} walk
 * @returns {number}
 */
function readObject(text, start, path, walk) {
  const parentId = walk.objects;
  walk.objects += 1;

  let i = skipWhitespace(text, start + 1);
  if (text[i] === "}") return i + 1;

  for (;;) {
    i = skipWhitespace(text, i);
    if (text[i] !== '"') throw scanError("member name expected", i);

    const nameAt = i;
    const { value: name, next } = readString(text, i);
    walk.members.push({ name, parent: path, parentId, path: childPath(path, name), index: nameAt });

    i = skipWhitespace(text, next);
    if (text[i] !== ":") throw scanError('":" expected after member name', i);

    i = readValue(text, i + 1, childPath(path, name), walk);
    i = skipWhitespace(text, i);

    if (text[i] === ",") {
      i += 1;
      continue;
    }
    if (text[i] === "}") return i + 1;
    throw scanError('"," or "}" expected', i);
  }
}

/**
 * @param {string} text
 * @param {number} start - offset of `[`
 * @param {string} path
 * @param {Walk} walk
 * @returns {number}
 */
function readArray(text, start, path, walk) {
  let i = skipWhitespace(text, start + 1);
  if (text[i] === "]") return i + 1;

  for (let element = 0; ; element += 1) {
    i = readValue(text, i, `${path}[${element}]`, walk);
    i = skipWhitespace(text, i);

    if (text[i] === ",") {
      i += 1;
      continue;
    }
    if (text[i] === "]") return i + 1;
    throw scanError('"," or "]" expected', i);
  }
}

/**
 * Every member name in the document, in the order it appears, each carrying the
 * object that holds it. Both scans below read this one walk, so their answers differ
 * only in whether they consult `parent`.
 *
 * @param {string} text - JSON source, as it sits in the markup
 * @returns {Member[]}
 * @throws {import('../core-shared/errors.js').DcaError} on text it cannot walk
 */
export function memberNames(text) {
  if (typeof text !== "string") throw scanError("the scan reads text, not a parsed value", 0);

  /** @type {Walk} */
  const walk = { members: [], objects: 0 };
  const end = skipWhitespace(text, readValue(text, 0, "$", walk));
  if (end !== text.length) throw scanError("trailing input after the document", end);
  return walk.members;
}

/**
 * The scan reports a member name that repeats inside one object.
 *
 * The tally keys on the object instance. The `parentId` note on `Member` says why a
 * path cannot key it.
 *
 * A `Map` holds the tally rather than an object literal: on a plain object
 * `seen['__proto__'] = 1` writes no own property, so a duplicate `__proto__` would
 * report clean.
 *
 * @param {string} text
 * @returns {Duplicate[]} empty when every object's names are unique
 */
export function scanDuplicateMembers(text) {
  /** @type {Map<number, Map<string, number>>} */
  const seen = new Map();
  /** @type {Duplicate[]} */
  const duplicates = [];

  for (const { name, parent, parentId, index } of memberNames(text)) {
    let names = seen.get(parentId);
    if (names === undefined) {
      names = new Map();
      seen.set(parentId, names);
    }
    const occurrence = (names.get(name) ?? 0) + 1;
    names.set(name, occurrence);
    if (occurrence > 1) duplicates.push({ name, parent, index, occurrence });
  }

  return duplicates;
}

/**
 * The name-only scan, for measurement only: the same names, counted without their
 * parent. It reports every name DCA reuses across sibling objects.
 *
 * @param {string} text
 * @returns {{ name: string, count: number }[]} names seen more than once anywhere
 */
export function flatNameScan(text) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const { name } of memberNames(text)) counts.set(name, (counts.get(name) ?? 0) + 1);

  return [...counts].filter(([, count]) => count > 1).map(([name, count]) => ({ name, count }));
}

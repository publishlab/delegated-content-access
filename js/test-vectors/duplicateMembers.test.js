//
// tools/duplicateMembers - a standalone experimental lint/test utility that
// cannot work by parsing. The reference runtime does not invoke it.
// Every parser in reach keeps the last occurrence of a repeated member name and
// hands back a value the duplicate cannot be read out of, so the check runs on
// text and so do these tests: real render vectors, the reject vector built
// around one record that carries `key` twice, and a duplicate injected deep
// inside an honest render.
//
// These tests also measure what the cheap version of the same check would cost.
// DCA reuses member names across sibling objects on purpose, so a scan that only
// counts names calls every one of those a duplicate; `flatNameScan` is here to
// be counted, not to be used.
//
// Every attack below comes with the honest path beside it, so a test that
// passed because nothing worked at all would be visible.
//
// Reading the vectors needs the filesystem, which core, ports and actors never
// touch. This is a test file, so `node:fs` is at hand here the way `node:test`
// is.
//
// Nothing here stands up a world: the subject is a walk over text, so
// `demo/scenarios/` has nothing it needs.
//
// These cases pin duplicate-member handling at the public parser boundary.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { memberNames, scanDuplicateMembers, flatNameScan } from "../tools/duplicateMembers.js";

// The render vectors, seal-ecdh.json among them, sit in the period-key
// package; the duplicate-member attack is a reference regression.
const RENDER_DIR = fileURLToPath(
  new URL(
    "../../verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-admission/",
    import.meta.url,
  ),
);
const REGRESSION_DIR = fileURLToPath(
  new URL("../../verification/fixtures/v1/reference/protocol-regressions/", import.meta.url),
);

describe("The duplicate-member tokenizer", () => {
  // A pre-parse duplicate check is cheap in Python (object_pairs_hook) and a
  // token walk in Go, while a raw-text scan in JS/PHP is unsound: DCA reuses
  // member names across sibling objects on purpose, so a scan that only counts
  // names drowns in false positives. The tokenizer is tools/duplicateMembers.js;
  // what follows feeds it real renders and a real attack.
  //
  // The v1 fixture is a two-item render that names its one issuer once. Every
  // collection is an array of records, so its block repeats six names, each
  // once per record: `contentName`, `contentType` and `keys` in the item
  // records and the sealed content-key records, `accessGroup`, `period` and
  // `key` in every wrap and sealed key record. Wrap records carry no `nonce`,
  // which derives from the wrap's coordinate, and item records no `aad`. The
  // count is asserted below.

  /** The render vectors, which carry a real `dcaData` block each. */
  function renderVectors() {
    return readdirSync(RENDER_DIR)
      .filter((file) => file.endsWith(".json") && file !== "manifest.json")
      .sort()
      .map((file) => ({ file, vector: JSON.parse(readFileSync(RENDER_DIR + file, "utf8")) }))
      .filter(({ vector }) => vector.vectorFormat === "1");
  }

  test("the nesting-aware scan finds no duplicate member in any real render", async () => {
    const vectors = renderVectors();
    assert.ok(vectors.length >= 1, "the render vectors were found");

    for (const { file, vector } of vectors) {
      // Both serializations, because the answer must not depend on how the
      // block was printed into the markup.
      for (const text of [
        JSON.stringify(vector.expected.dcaData),
        JSON.stringify(vector.expected.dcaData, null, 2),
      ]) {
        assert.deepEqual(scanDuplicateMembers(text), [], `${file} is clean`);
      }
    }
  });

  test("the flat name scan calls six names duplicates on the same block, and every one is false", async () => {
    const { vector } = renderVectors().find(({ file }) => file === "seal-ecdh.json") ?? {};
    assert.ok(vector, "the canonical render vector");
    const text = JSON.stringify(vector.expected.dcaData, null, 2);

    const flat = flatNameScan(text);
    assert.equal(flat.length, 6, "six names repeat somewhere in the document");
    assert.deepEqual(
      flat.map(({ name }) => name).sort(),
      ["accessGroup", "contentName", "contentType", "key", "keys", "period"],
      "the names DCA reuses on purpose - the identity and key fields of every " +
        "record in a collection",
    );

    // Where the false positives come from, made explicit: `key` appears ten
    // times, in ten different records, and no record holds two of them.
    const keys = memberNames(text).filter(({ name }) => name === "key");
    assert.equal(keys.length, 10);
    assert.equal(new Set(keys.map(({ parent }) => parent)).size, 10, "ten parents, one key each");

    // And the same document again, with the nesting taken into account.
    assert.deepEqual(scanDuplicateMembers(text), [], "zero duplicates - all six were false");

    // The count is a snapshot of a fixture, so it is worth knowing it is not a
    // fluke of the walk: the same names come out under either serialization.
    assert.equal(flatNameScan(JSON.stringify(vector.expected.dcaData)).length, 6);
  });

  test("the scan catches the duplicate the reject vector is built around, at its exact path", async () => {
    const vector = JSON.parse(
      readFileSync(REGRESSION_DIR + "reject-duplicate-member-name.json", "utf8"),
    );

    // The vector is built around `rawBody`: one bodytext record carrying `key`
    // twice, which no parsed value can express. It is scanned as the string it
    // is, because a re-serialization would have destroyed it first.
    assert.equal(typeof vector.rawBody, "string");

    const duplicates = scanDuplicateMembers(vector.rawBody);
    assert.equal(duplicates.length, 1, "one duplicate, and the scan says which");
    assert.equal(duplicates[0].name, "key");
    assert.equal(
      duplicates[0].parent,
      "$.sealed.contentKeys[0]",
      "the one record the attack is inside",
    );
    assert.equal(duplicates[0].occurrence, 2);

    // The evidence really is gone after a parse, which is why the check runs on
    // text: the same body round-tripped through JSON.parse scans clean, and
    // the one record keeps its last `key` and no trace of the first.
    const record = JSON.parse(vector.rawBody).sealed.contentKeys;
    assert.equal(record.length, 1, "still one record, not two rival ones");
    assert.deepEqual(Object.keys(record[0]), ["contentName", "key"]);
    const written = vector.rawBody.match(
      /\{"contentName":\s*"bodytext"((?:,\s*"key":\s*"[^"]+")+)\s*\}/,
    );
    assert.ok(written, "the bodytext record carries only key members after its name");
    const occurrences = [...written[1].matchAll(/"key":\s*"([^"]+)"/g)].map((m) => m[1]);
    assert.equal(occurrences.length, 2);
    assert.equal(record[0].key, occurrences[1], "the parser keeps the last field");
    const parsed = JSON.stringify(JSON.parse(vector.rawBody), null, 2);
    assert.deepEqual(scanDuplicateMembers(parsed), [], "last-wins left one member and no trace");

    // Rejecting the duplicate is the other conformant reading, and the vector
    // records it beside the last-field answer.
    assert.deepEqual(
      vector.expected.alsoConformant.map((/** @type {any} */ entry) => entry.code),
      ["invalid_json"],
    );

    // And the honest body it was cut from is clean, so the finding above is the
    // attack rather than the scanner objecting to unlock requests.
    const honest = JSON.parse(readFileSync(RENDER_DIR + "seal-ecdh.json", "utf8"));
    assert.deepEqual(scanDuplicateMembers(JSON.stringify(honest.expected.dcaData, null, 2)), []);
  });

  test("a duplicate injected into a render is caught wherever it sits, and only there", async () => {
    const { vector } = renderVectors().find(({ file }) => file === "seal-ecdh.json") ?? {};
    assert.ok(vector, "the canonical render vector");
    const clean = JSON.stringify(vector.expected.dcaData, null, 2);

    // Deep inside a wrap record, at the far end of the document from where a
    // top-level scan would be looking, and the place a second `period` member
    // would decide which periodKey a client unwraps with. The first match in
    // the text is bodytext's first wrap record.
    const attacked = clean.replace(
      '"period": "251023T1400",\n          "key"',
      '"period": "251023T1400",\n          "period": "251023T1500",\n          "key"',
    );
    assert.notEqual(attacked, clean, "the injection landed");

    const duplicates = scanDuplicateMembers(attacked);
    assert.equal(duplicates.length, 1);
    assert.equal(duplicates[0].name, "period");
    assert.equal(duplicates[0].parent, "$.contentData[0].keys[0]", "inside one wrap record");

    // "And only there", spelled out. The render carries eight records with one
    // `period` each, four wrap records and four sealed period-key records;
    // after the injection nine `period` members sit across those same eight
    // records, so exactly one record holds two of them and the other seven are
    // untouched. A scan that widened its idea of "one object" (grouping by
    // path, say, or by name) would land on a different parent count here.
    const periods = memberNames(attacked).filter(({ name }) => name === "period");
    assert.equal(periods.length, 9, "the eight records' own period members, plus the injected one");
    assert.equal(
      new Set(periods.map(({ parentId }) => parentId)).size,
      8,
      "nine members, eight records: one holds the duplicate, seven hold one each",
    );
  });

  test("a duplicate is a duplicate however it is spelled, and __proto__ is not a blind spot", async () => {
    // Escaping. `"a"` and `"a"` are one member name in JSON, so a scan
    // comparing raw spans would report two names and miss the collision, which
    // is exactly the differential an attacker would reach for once the obvious
    // form is checked.
    assert.deepEqual(
      scanDuplicateMembers('{"contentKeys": {"bodytext": "A", "\\u0062odytext": "B"}}').map(
        ({ name, parent }) => ({ name, parent }),
      ),
      [{ name: "bodytext", parent: "$.contentKeys" }],
    );
    assert.deepEqual(
      scanDuplicateMembers('{"a": 1, "b": 2}'),
      [],
      "and two names are still two names",
    );

    // The prototype hazard applies to the checker itself: a scanner tallying
    // names in a plain object would write
    // `seen['__proto__']` to no own property and report clean on the one name
    // where a missed duplicate is worth the most.
    const duplicates = scanDuplicateMembers('{"__proto__": {"a": 1}, "__proto__": {"a": 2}}');
    assert.equal(duplicates.length, 1);
    assert.equal(duplicates[0].name, "__proto__");
    assert.deepEqual(scanDuplicateMembers('{"__proto__": 1, "constructor": 2, "toString": 3}'), []);

    // Same name, different parents, one level apart: the shape DCA emits on
    // purpose, and the one a flat scan cannot tell from the attack above.
    assert.deepEqual(scanDuplicateMembers('{"locked-data": {"locked-data": [{"t": "1"}]}}'), []);
    assert.deepEqual(flatNameScan('{"locked-data": {"locked-data": [{"t": "1"}]}}'), [
      { name: "locked-data", count: 2 },
    ]);
  });

  test("the scan refuses text it cannot walk rather than reporting it clean", async () => {
    // A scanner that swallows what it does not understand answers "no
    // duplicates" for a document it never read, which is the one answer a
    // security check must never give by accident.
    for (const bad of [
      '{"a": }',
      '{"a" 1}',
      '{"a": 1,}',
      '{"a": 1} trailing',
      '{"a": "unterminated}',
      '{"a": 01}',
      "{'a': 1}",
      '{"a": 1',
      "[1, 2",
      '{"a": tru}',
      '{"a": "\\x41"}',
    ]) {
      assert.throws(
        () => scanDuplicateMembers(bad),
        (/** @type {any} */ err) => err.code === "duplicate_scan_failed",
        `expected a stated refusal for ${bad}`,
      );
    }

    // A parsed value is not text, and being handed one is a caller mistake
    // worth naming: it is how the check silently stops running.
    assert.throws(
      () => scanDuplicateMembers(/** @type {any} */ ({ a: 1 })),
      (/** @type {any} */ err) => err.code === "duplicate_scan_failed",
    );

    // The controls: JSON the scan must accept, including the value kinds a
    // dca-data block does not happen to use.
    for (const good of [
      "{}",
      "[]",
      "null",
      "0",
      "-1.5e10",
      '"text"',
      '{"a": [{"b": [true, false, null]}]}',
    ]) {
      assert.deepEqual(scanDuplicateMembers(good), [], good);
    }
  });
});

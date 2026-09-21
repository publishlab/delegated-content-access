//
// tools/duplicateMembers - a standalone experimental lint/test utility that
// cannot work by parsing. The reference runtime does not invoke it.
// Every parser in reach keeps the last occurrence of a repeated member name and
// hands back a value the duplicate cannot be read out of, so the check runs on
// text and so do these tests: real render vectors, the reject vector built
// around one repeated `bodytext`, and a duplicate injected deep inside an
// honest render.
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

const FIXTURE_DIR = fileURLToPath(
  new URL("../../../verification/fixtures/protocol-v1/", import.meta.url),
);

describe("The duplicate-member tokenizer", () => {
  // A pre-parse duplicate check is cheap in Python (object_pairs_hook) and a
  // token walk in Go, while a raw-text scan in JS/PHP is unsound: DCA reuses
  // member names across sibling objects on purpose, so a scan that only counts
  // names drowns in false positives. The tokenizer is tools/duplicateMembers.js;
  // what follows feeds it real renders and a real attack.
  //
  // The canonical dca-data block has 14 repeated names (nonce x9, t x6, key x6,
  // one `keys` per item record, and the content and group names). The v1 fixture
  // is a two-item render where the spec's block has three, and it names its one
  // issuer once, so it yields 11: the same names, one content item's worth fewer
  // and no repeated issuerName. The actual count is asserted below; the delta is
  // the fixture, not a disagreement about the finding.

  /** The render vectors, which carry a real `dcaData` block each. */
  function renderVectors() {
    return readdirSync(FIXTURE_DIR)
      .filter((file) => file.endsWith(".json") && file !== "manifest.json")
      .sort()
      .map((file) => ({ file, vector: JSON.parse(readFileSync(FIXTURE_DIR + file, "utf8")) }))
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

  test("the flat name scan calls eleven names duplicates on the same block, and every one is false", async () => {
    const { vector } = renderVectors().find(({ file }) => file === "seal-ecdh.json") ?? {};
    assert.ok(vector, "the canonical render vector");
    const text = JSON.stringify(vector.expected.dcaData, null, 2);

    const flat = flatNameScan(text);
    assert.equal(flat.length, 11, "eleven names repeat somewhere in the document");
    assert.deepEqual(
      flat.map(({ name }) => name).sort(),
      [
        "251023T14",
        "251023T15",
        "aad",
        "bodytext",
        "contentType",
        "key",
        "keys",
        "locked-data",
        "nonce",
        "premium",
        "t",
      ],
      "the names DCA reuses on purpose - wrap records, item records, content " +
        "items, and a contentName that is also an accessGroup",
    );

    // Where the false positives come from, made explicit: `nonce` appears six
    // times, in six different objects, and no object holds two of them.
    const nonces = memberNames(text).filter(({ name }) => name === "nonce");
    assert.equal(nonces.length, 6);
    assert.equal(
      new Set(nonces.map(({ parent }) => parent)).size,
      6,
      "six parents, one nonce each",
    );

    // And the same document again, with the nesting taken into account.
    assert.deepEqual(scanDuplicateMembers(text), [], "zero duplicates - all eleven were false");

    // The count is a snapshot of a fixture, so it is worth knowing it is not a
    // fluke of the walk: the same names come out under either serialization.
    assert.equal(flatNameScan(JSON.stringify(vector.expected.dcaData)).length, 11);
  });

  test("the scan catches the duplicate the reject vector is built around, at its exact path", async () => {
    const vector = JSON.parse(
      readFileSync(FIXTURE_DIR + "reject-duplicate-member-name.json", "utf8"),
    );

    // The vector is built around `rawBody`: a body carrying `bodytext` twice
    // inside one object, which no parsed value can express. It is scanned as
    // the string it is, because a re-serialization would have destroyed it
    // first.
    assert.equal(typeof vector.rawBody, "string");

    const duplicates = scanDuplicateMembers(vector.rawBody);
    assert.equal(duplicates.length, 1, "one duplicate, and the scan says which");
    assert.equal(duplicates[0].name, "bodytext");
    assert.equal(duplicates[0].parent, "$.sealed.contentKeys", "the object the attack is inside");
    assert.equal(duplicates[0].occurrence, 2);

    // The evidence really is gone after a parse, which is why the check runs on
    // text: the same body round-tripped through JSON.parse scans clean.
    const parsed = JSON.stringify(JSON.parse(vector.rawBody), null, 2);
    assert.deepEqual(scanDuplicateMembers(parsed), [], "last-wins left one member and no trace");

    // And the honest body it was cut from is clean, so the finding above is the
    // attack rather than the scanner objecting to unlock requests.
    const honest = JSON.parse(readFileSync(FIXTURE_DIR + "seal-ecdh.json", "utf8"));
    assert.deepEqual(scanDuplicateMembers(JSON.stringify(honest.expected.dcaData, null, 2)), []);
  });

  test("a duplicate injected into a render is caught wherever it sits, and only there", async () => {
    const { vector } = renderVectors().find(({ file }) => file === "seal-ecdh.json") ?? {};
    assert.ok(vector, "the canonical render vector");
    const clean = JSON.stringify(vector.expected.dcaData, null, 2);

    // Deep inside a wrap record, at the far end of the document from where a
    // top-level scan would be looking, and the place a second `key` member
    // would decide which contentKey a client unwraps.
    const attacked = clean.replace(
      '"t": "251023T14",\n            "nonce"',
      '"t": "251023T14",\n            "t": "251023T15",\n            "nonce"',
    );
    assert.notEqual(attacked, clean, "the injection landed");

    const duplicates = scanDuplicateMembers(attacked);
    assert.equal(duplicates.length, 1);
    assert.equal(duplicates[0].name, "t");
    assert.equal(
      duplicates[0].parent,
      "$.contentData.bodytext.keys.premium[0]",
      "inside one wrap record",
    );

    // "And only there", spelled out. The render carries four wrap records with
    // one `t` each; after the injection five `t` members sit across those same
    // four records, so exactly one record holds two of them and the other three
    // are untouched. A scan that widened its idea of "one object" (grouping by
    // path, say, where the two `[0]` records of two different contentNames read
    // alike) would land on a different parent count here.
    const ts = memberNames(attacked).filter(({ name }) => name === "t");
    assert.equal(ts.length, 5, "the four records' own t members, plus the injected one");
    assert.equal(
      new Set(ts.map(({ parentId }) => parentId)).size,
      4,
      "five members, four records: one holds the duplicate, three hold one each",
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

import test from "node:test";
import assert from "node:assert/strict";

import { convertAnswer, loadReferenceShapes, returnShape } from "../reference-shapes.mjs";

const bytes = (/** @type {string} */ text) => new TextEncoder().encode(text);

test("an empty list becomes an empty record where the reference type is a record", () => {
  assert.deepEqual(convertAnswer({ record: {} }, []), {});
  assert.deepEqual(convertAnswer({ record: {}, values: "string" }, []), {});
  assert.deepEqual(convertAnswer({ record: { inner: { record: {} } } }, { inner: [] }), {
    inner: {},
  });
});

test("a string becomes the same UTF-8 bytes where the reference type is Uint8Array", () => {
  assert.deepEqual(convertAnswer("Uint8Array", "é"), bytes("é"));
  assert.deepEqual(convertAnswer({ list: "Uint8Array" }, ["a", "b"]), [bytes("a"), bytes("b")]);
  assert.deepEqual(convertAnswer({ record: {}, values: "Uint8Array" }, { k: "v" }), {
    k: bytes("v"),
  });
  assert.deepEqual(convertAnswer({ tuple: ["Uint8Array", "string"] }, ["a", "b"]), [
    bytes("a"),
    "b",
  ]);
});

test("null becomes undefined where the reference type admits undefined and not null", () => {
  assert.equal(convertAnswer("undefined", null), undefined);
  assert.deepEqual(
    convertAnswer({ record: { at: { anyOf: ["undefined", "value"] } } }, { at: null }),
    { at: undefined },
  );
  assert.equal(convertAnswer({ anyOf: ["null", "undefined"] }, null), null);
  assert.equal(convertAnswer({ anyOf: ["null", "string"] }, null), null);
  assert.equal(convertAnswer("value", null), null);
});

test("a value a union admits passes unchanged", () => {
  const either = { anyOf: [{ list: "string" }, { record: {} }] };
  assert.deepEqual(convertAnswer(either, []), []);
  assert.equal(convertAnswer({ anyOf: ["Uint8Array", "string"] }, "a"), "a");
  assert.equal(convertAnswer({ anyOf: ["string", "undefined"] }, "a"), "a");
  assert.deepEqual(convertAnswer({ list: "string" }, []), []);
  assert.equal(convertAnswer("any", null), null);
  assert.deepEqual(convertAnswer(undefined, []), []);
});

test("a record under a union of records without a discriminant passes unchanged", () => {
  const loose = { anyOf: [{ record: { a: "Uint8Array" } }, { record: { b: "string" } }] };
  assert.deepEqual(convertAnswer(loose, { a: "x" }), { a: "x" });
});

test("a discriminated union picks its branch from the answer before converting inside it", () => {
  const shape = {
    discriminant: "kind",
    cases: {
      '"list"': { record: { items: { list: "string" } } },
      '"map"': { record: { items: { record: {}, values: "string" } } },
    },
  };
  assert.deepEqual(convertAnswer(shape, { kind: "map", items: [] }), { kind: "map", items: {} });
  assert.deepEqual(convertAnswer(shape, { kind: "list", items: [] }), { kind: "list", items: [] });
  assert.deepEqual(convertAnswer(shape, { kind: "other", items: [] }), {
    kind: "other",
    items: [],
  });
  const flagged = {
    anyOf: [
      "undefined",
      {
        discriminant: "ok",
        cases: { false: { record: {} }, true: { record: { value: "Uint8Array" } } },
      },
    ],
  };
  assert.deepEqual(convertAnswer(flagged, { ok: true, value: "a" }), {
    ok: true,
    value: bytes("a"),
  });
  assert.equal(convertAnswer(flagged, null), undefined);
});

test("a value that contradicts the reference type passes unchanged", () => {
  assert.equal(convertAnswer("Uint8Array", 5), 5);
  assert.equal(convertAnswer({ record: {} }, "x"), "x");
  assert.deepEqual(convertAnswer({ record: {} }, [1]), [1]);
  assert.deepEqual(convertAnswer("string", bytes("a")), bytes("a"));
  assert.equal(convertAnswer("string", null), null);
});

test("a position the test target declared is never converted, and a disagreement is refused", () => {
  assert.throws(
    () => convertAnswer({ record: {} }, [], [{ at: [], type: "list" }]),
    /the test target declares list at the result, where the reference type admits record/,
  );
  assert.throws(
    () =>
      convertAnswer({ record: { items: { record: {} } } }, { items: [] }, [
        { at: ["items"], type: "list" },
      ]),
    /declares list at items, where the reference type admits record/,
  );
  assert.throws(
    () => convertAnswer({ list: "string" }, [bytes("a")], [{ at: [0], type: "Uint8Array" }]),
    /declares Uint8Array at \[0\], where the reference type admits string/,
  );
  assert.deepEqual(
    convertAnswer({ anyOf: [{ list: "string" }, { record: {} }] }, [], [{ at: [], type: "list" }]),
    [],
  );
  assert.deepEqual(convertAnswer({ record: {} }, {}, [{ at: [], type: "record" }]), {});
  assert.deepEqual(convertAnswer("any", [], [{ at: [], type: "list" }]), []);
  // A declared record still has undeclared members the reference type reads.
  assert.deepEqual(
    convertAnswer({ record: { key: "Uint8Array" } }, { key: "k" }, [{ at: [], type: "record" }]),
    { key: bytes("k") },
  );
});

test("an answer declared whole is never converted, and a position the reference type does not admit is refused", () => {
  assert.throws(
    () => convertAnswer({ record: {} }, [], "all"),
    /the test target declares list at the result, where the reference type admits record/,
  );
  assert.throws(
    () => convertAnswer({ record: { key: "Uint8Array" } }, { key: "k" }, "all"),
    /declares string at key, where the reference type admits Uint8Array/,
  );
  assert.throws(
    () => convertAnswer({ anyOf: ["undefined", "value"] }, null, "all"),
    /declares null at the result, where the reference type admits undefined or value/,
  );
  assert.throws(
    () => convertAnswer({ tuple: ["string"] }, [5], "all"),
    /declares number at \[0\], where the reference type admits string/,
  );
  const typed = { key: bytes("k"), items: [], note: undefined };
  assert.deepEqual(
    convertAnswer(
      {
        record: {
          key: "Uint8Array",
          items: { anyOf: [{ list: "string" }, { record: {} }] },
          note: { anyOf: ["string", "undefined"] },
        },
      },
      typed,
      "all",
    ),
    typed,
  );
});

test("a declaration that does not match the answer's own value is a bridge error", () => {
  assert.throws(
    () => convertAnswer({ record: {} }, {}, [{ at: [], type: "list" }]),
    /bridge response declares list at the result, where the answer holds record/,
  );
  assert.throws(
    () => convertAnswer({ record: {} }, {}, [{ at: ["missing"], type: "list" }]),
    /bridge response declares list at missing, where the answer holds undefined/,
  );
});

test("the committed shapes name each export by its reference module", () => {
  const shapes = loadReferenceShapes();
  assert.equal(returnShape(shapes, "core-shared/codec.js", "base64urlDecode"), "Uint8Array");
  assert.equal(returnShape(shapes, "core-shared/codec.js", "missing"), undefined);
  assert.equal(returnShape(shapes, "missing.js", "base64urlDecode"), undefined);
});

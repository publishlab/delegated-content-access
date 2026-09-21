// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { survivorRows } from "./mutation-survivors.js";

const report = {
  files: {
    "core-shared/codec.js": {
      source: 'const a = 1;\nif (x > 0) throw new Error("bad x");\n',
      mutants: [
        {
          mutatorName: "EqualityOperator",
          replacement: "x >= 0",
          status: "Survived",
          location: { start: { line: 2, column: 5 }, end: { line: 2, column: 10 } },
        },
        {
          mutatorName: "StringLiteral",
          replacement: '""',
          status: "Killed",
          location: { start: { line: 2, column: 28 }, end: { line: 2, column: 35 } },
        },
        {
          mutatorName: "StringLiteral",
          replacement: '""',
          status: "NoCoverage",
          location: { start: { line: 2, column: 28 }, end: { line: 2, column: 35 } },
        },
      ],
    },
  },
};

test("a survivor row carries the file, place, mutator, original text and replacement", () => {
  assert.deepEqual(survivorRows(report)[0], [
    "core-shared/codec.js",
    "2:5",
    "Survived",
    "EqualityOperator",
    "x > 0",
    "x >= 0",
  ]);
});

test("killed mutants stay out and uncovered ones stay in", () => {
  assert.deepEqual(
    survivorRows(report).map((row) => row[2]),
    ["Survived", "NoCoverage"],
  );
});

test("tabs and newlines in source text cannot break a row", () => {
  const multiline = {
    files: {
      "f.js": {
        source: "a(\n\tb)",
        mutants: [
          {
            mutatorName: "BlockStatement",
            replacement: "{}",
            status: "Survived",
            location: { start: { line: 1, column: 1 }, end: { line: 2, column: 4 } },
          },
        ],
      },
    },
  };
  assert.equal(survivorRows(multiline)[0][4], "a(\\n\\tb)");
});

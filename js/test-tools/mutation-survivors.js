// @ts-check
// Reads a StrykerJS JSON report and prints one tab-separated row per mutant
// that no test killed: file, line:column, status, mutator, the original source
// text and its replacement. The full report also carries every killed mutant
// and the source of each file, which a reader classifying survivors does not need.
//
//   node test-tools/mutation-survivors.js [reports/mutation/mutation.json]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const UNKILLED = new Set(["Survived", "NoCoverage"]);

/** @param {string} text */
function oneLine(text) {
  return text.replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll("\t", "\\t");
}

/**
 * Stryker lines and columns count from 1, and the end column points one past
 * the last character.
 * @param {string} source
 * @param {{start: {line: number, column: number}, end: {line: number, column: number}}} location
 */
function originalText(source, location) {
  const lines = source.split("\n");
  const { start, end } = location;
  if (start.line === end.line) {
    return lines[start.line - 1].slice(start.column - 1, end.column - 1);
  }
  return [
    lines[start.line - 1].slice(start.column - 1),
    ...lines.slice(start.line, end.line - 1),
    lines[end.line - 1].slice(0, end.column - 1),
  ].join("\n");
}

/**
 * @param {{files: Record<string, {source: string, mutants: Array<{mutatorName: string,
 *   replacement?: string, status: string, location: any}>}>}} report
 * @returns {string[][]}
 */
export function survivorRows(report) {
  const rows = [];
  for (const [file, { source, mutants }] of Object.entries(report.files)) {
    for (const mutant of mutants) {
      if (!UNKILLED.has(mutant.status)) continue;
      const { start } = mutant.location;
      rows.push([
        file,
        `${start.line}:${start.column}`,
        mutant.status,
        mutant.mutatorName,
        oneLine(originalText(source, mutant.location)),
        oneLine(mutant.replacement ?? ""),
      ]);
    }
  }
  return rows;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = process.argv[2] ?? "reports/mutation/mutation.json";
  const report = JSON.parse(readFileSync(path, "utf8"));
  console.log(["file", "at", "status", "mutator", "original", "replacement"].join("\t"));
  for (const row of survivorRows(report)) console.log(row.join("\t"));
}

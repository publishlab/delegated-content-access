// @ts-check
//
// This script is the benchmark's main run: synthetic bodies, no network and no files,
// so a rerun repeats the table apart from its two median columns.
//
// Run it from the repository root, with no arguments:
//
//     node js/evidence-benchmarks/compression-before-sealing/run-synthetic.js
//
// The neutral synthetic fixture renders every size below in every form, and each string
// goes straight into `measure.js`, so each form is measured at its own length.
// `measure.js` describes the columns.

import { syntheticArticle } from "../../tools/synthetic-html.js";
import { measureSample, table } from "./measure.js";

/** The body sizes measured, small to large. */
const SIZES = [3072, 10240, 30720];

/** The forms a body is measured in. */
const FORMS = /** @type {const} */ (["html", "txt", "json"]);

/** @type {import('./measure.js').Row[]} */
const rows = [];

for (const bytes of SIZES) {
  const label = `synthetic-${Math.round(bytes / 1024)}kb`;
  for (const form of FORMS) {
    rows.push(...(await measureSample({ label, form, bytes: syntheticArticle({ bytes, form }) })));
  }
}

process.stdout.write(table(rows));

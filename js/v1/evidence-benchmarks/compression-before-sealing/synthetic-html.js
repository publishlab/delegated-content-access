// @ts-check
//
// This CLI prints the deterministic synthetic article fixture, for reading it by hand.
// The generator itself lives under `tools/`, so the gated tests that use it depend only
// on `tools/` and not on this benchmark directory.

import { pathToFileURL } from "node:url";
import { syntheticArticle } from "../../tools/synthetic-html.js";

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const bytes = Number(process.argv[2] ?? 10240);
  const form = /** @type {'html'|'txt'|'json'} */ (process.argv[3] ?? "html");
  const seed = Number(process.argv[4] ?? 1);
  if (
    !Number.isFinite(bytes) ||
    bytes < 64 ||
    !["html", "txt", "json"].includes(form) ||
    !Number.isFinite(seed)
  ) {
    process.stderr.write(
      "usage: node evidence-benchmarks/compression-before-sealing/synthetic-html.js [bytes] [html|txt|json] [seed]\n",
    );
    process.exit(2);
  }
  process.stdout.write(syntheticArticle({ bytes, form, seed }));
}

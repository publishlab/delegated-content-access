// @ts-check
// Development host composition: chromium.js serves this browser URL mount from
// the local v1 tree. Runtime graph callers receive no mapping or exemption.
import assert from "node:assert/strict";
import { posix } from "node:path";
import { developmentImportEdgesOf } from "./sourceGraph.js";

function browserMountSpecifier(rel, specifier) {
  const mount = "/__js/";
  if (rel !== "extensions/html-content-map/test/chromium.js" || !specifier.startsWith(mount))
    return specifier;
  const target = posix.normalize(specifier.slice(mount.length));
  assert.ok(
    !target.startsWith("../") && !target.startsWith("/"),
    "browser development mount must stay inside v1",
  );
  const relative = posix.relative(posix.dirname(rel), target);
  return relative.startsWith(".") ? relative : `./${relative}`;
}

export function developmentEdgesOf(rel, root) {
  return developmentImportEdgesOf(rel, root, browserMountSpecifier);
}

// @ts-check
import { readdirSync, statSync } from "node:fs";

/** Expand literal .js paths and direct-child *.js patterns relative to root.
 * No recursive or implicit patterns. Shared files are selected once.
 * @param {{layers: Record<string, {paths: string[]}>}} manifest
 * @param {URL} root
 * @returns {string[]}
 */
export function copyManifestFiles(manifest, root) {
  const files = new Set();
  for (const layer of Object.values(manifest.layers)) {
    for (const path of layer.paths) {
      if (!/^(?:[A-Za-z0-9_-]+\/)*(?:\*|[A-Za-z0-9_.-]+)\.js$/.test(path)) {
        throw new Error(`unsupported copy path: ${path}`);
      }
      if (path.endsWith("/*.js")) {
        const directory = path.slice(0, -4);
        for (const entry of readdirSync(new URL(directory, root), { withFileTypes: true })) {
          if (entry.isFile() && entry.name.endsWith(".js")) files.add(directory + entry.name);
        }
      } else {
        if (!statSync(new URL(path, root)).isFile()) throw new Error(`not a copy file: ${path}`);
        files.add(path);
      }
    }
  }
  return [...files].sort();
}

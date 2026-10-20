// @ts-check

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, relative, resolve, sep } from "node:path";

const SCHEMA = "dca-protocol-fixture-manifest/v1";
const CONSUMERS = new Set(["base-contract", "reference"]);

/**
 * Select exact fixture files from checked-in package manifests.
 *
 * @param {string} verificationRoot
 * @param {string[]} fixtureSets
 * @param {string} consumer
 * @param {string[]} formats
 * @returns {string[]}
 */
export function selectFixtureFiles(verificationRoot, fixtureSets, consumer, formats) {
  if (!Array.isArray(fixtureSets) || fixtureSets.length === 0) {
    throw new Error("fixtureSets must name at least one fixture package");
  }
  if (!CONSUMERS.has(consumer))
    throw new Error(`unknown fixture consumer ${JSON.stringify(consumer)}`);
  if (
    !Array.isArray(formats) ||
    formats.length === 0 ||
    formats.some((format) => typeof format !== "string")
  ) {
    throw new Error("fixtureFormats must be a non-empty string array");
  }

  const selectedFormats = new Set(formats);
  if (selectedFormats.size !== formats.length)
    throw new Error("fixtureFormats contains a duplicate");
  const selected = [];
  const selectedPaths = new Set();
  const packagePaths = new Set();

  for (const fixtureSet of fixtureSets) {
    if (typeof fixtureSet !== "string" || fixtureSet.length === 0) {
      throw new Error("fixtureSets entries must be non-empty strings");
    }
    const fixtureSetPath = resolve(verificationRoot, fixtureSet);
    const fromVerification = relative(verificationRoot, fixtureSetPath);
    if (
      fromVerification === ".." ||
      fromVerification.startsWith(`..${sep}`) ||
      resolve(fixtureSetPath) === resolve(verificationRoot)
    ) {
      throw new Error(
        `fixture package escapes the verification root: ${JSON.stringify(fixtureSet)}`,
      );
    }
    if (packagePaths.has(fixtureSetPath))
      throw new Error(`duplicate fixture package ${JSON.stringify(fixtureSet)}`);
    packagePaths.add(fixtureSetPath);

    const manifestPath = resolve(fixtureSetPath, "manifest.json");
    if (!existsSync(manifestPath)) throw new Error(`missing fixture manifest ${manifestPath}`);
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest?.schema !== SCHEMA || manifest.protocol !== "dca" || manifest.version !== "1") {
      throw new Error(`unsupported fixture manifest in ${fixtureSetPath}`);
    }
    if (!["draft", "frozen"].includes(manifest.stability) || !Array.isArray(manifest.files)) {
      throw new Error(`malformed fixture manifest in ${fixtureSetPath}`);
    }

    const declaredPaths = [];
    const declared = new Set();
    for (const entry of manifest.files) {
      const path = entry?.path;
      if (
        typeof path !== "string" ||
        path.length === 0 ||
        basename(path) !== path ||
        !path.endsWith(".json")
      ) {
        throw new Error(`fixture manifest has unsafe path ${JSON.stringify(path)}`);
      }
      if (declared.has(path)) throw new Error(`fixture manifest repeats ${JSON.stringify(path)}`);
      declared.add(path);
      declaredPaths.push(path);
      if (typeof entry.vectorFormat !== "string") {
        throw new Error(`${path}: fixture manifest has no string vectorFormat`);
      }
      if (
        !Array.isArray(entry.consumers) ||
        entry.consumers.length === 0 ||
        new Set(entry.consumers).size !== entry.consumers.length ||
        entry.consumers.some((name) => !CONSUMERS.has(name))
      ) {
        throw new Error(`${path}: fixture manifest has invalid consumers`);
      }

      const fixtureFile = resolve(fixtureSetPath, path);
      const fixture = JSON.parse(readFileSync(fixtureFile, "utf8"));
      if (fixture.vectorFormat !== entry.vectorFormat) {
        throw new Error(`${path}: fixture bytes differ from their declared vectorFormat`);
      }
      if (!entry.consumers.includes(consumer) || !selectedFormats.has(entry.vectorFormat)) continue;
      if (selectedPaths.has(fixtureFile)) throw new Error(`fixture selected twice: ${fixtureFile}`);
      selectedPaths.add(fixtureFile);
      selected.push(fixtureFile);
    }

    const payloadPaths = readdirSync(fixtureSetPath)
      .filter((path) => path.endsWith(".json") && path !== "manifest.json")
      .sort();
    if (JSON.stringify(declaredPaths) !== JSON.stringify([...declaredPaths].sort())) {
      throw new Error(`fixture manifest paths are not sorted in ${fixtureSetPath}`);
    }
    if (JSON.stringify(declaredPaths) !== JSON.stringify(payloadPaths)) {
      throw new Error(
        `fixture manifest membership differs from JSON payloads in ${fixtureSetPath}`,
      );
    }
  }
  return selected;
}

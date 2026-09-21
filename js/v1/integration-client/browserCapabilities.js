// @ts-check
//
// The platform APIs a client composition reads while its modules load.
// `core-shared/codec.js` constructs a `TextEncoder` and a `TextDecoder` at
// module evaluation and calls `atob` and `btoa`, and
// `core-shared/cryptoProvider.js` reads `globalThis.crypto.subtle` at module
// evaluation. On a platform short of one of those, the import throws before any
// composition code runs, and the host sees a `TypeError` from a file it did not
// write. A caller runs this probe first, while nothing but `core-shared/errors.js`
// has been loaded, and then imports the composition.
//
// `core-shared/errors.js` is the one module this probe imports: it declares a
// class and two functions, imports nothing itself, and reads no global, so
// loading it says nothing about the platform. A host that wants the refusal
// before any other module evaluates therefore imports this file alone, in a
// first script, and calls `requireBrowserCapabilities()` there.

import { dcaError } from "../core-shared/errors.js";

/**
 * Each name, and how a caller reads the API behind it off the platform object.
 * `crypto.subtle` is listed beside `crypto` because a page served over plain
 * HTTP gets a `crypto` object with no `subtle` on it.
 *
 * @type {[string, (platform: any) => boolean][]}
 */
const CAPABILITIES = [
  ["crypto", (platform) => typeof platform?.crypto === "object" && platform.crypto !== null],
  ["crypto.subtle", (platform) => typeof platform?.crypto?.subtle === "object"],
  ["TextEncoder", (platform) => typeof platform?.TextEncoder === "function"],
  ["TextDecoder", (platform) => typeof platform?.TextDecoder === "function"],
  ["atob", (platform) => typeof platform?.atob === "function"],
  ["btoa", (platform) => typeof platform?.btoa === "function"],
];

/**
 * The names this platform does not carry, in the order above. A platform with
 * no `crypto` at all lacks `crypto.subtle` too, and both names are reported.
 *
 * @param {any} [platform] - the object the APIs are read off, `globalThis` in a
 *   browser and a stand-in object in a test
 * @returns {string[]}
 */
export function missingBrowserCapabilities(platform = globalThis) {
  return CAPABILITIES.filter(([, present]) => !present(platform)).map(([name]) => name);
}

/**
 * Throw `unsupported_platform` naming every API this platform does not carry.
 * An `unsupported_platform` code names a runtime gap, not a host mistake: the
 * host copied this source to a runtime that answers no `btoa`, and no option
 * changes that.
 *
 * @param {any} [platform]
 * @returns {void}
 */
export function requireBrowserCapabilities(platform = globalThis) {
  const missing = missingBrowserCapabilities(platform);
  if (missing.length === 0) return;
  throw dcaError("unsupported_platform", `this platform does not carry ${missing.join(", ")}`);
}

// @ts-check

// The JSON-only seam shared by Page construction and the simulated Network.
// Keeping the check out of Network lets a Page reject values JSON would
// silently mangle without pulling the actor world into a delivery value.

import { dcaError } from "../../core-shared/errors.js";

/**
 * @param {any} value
 * @param {string} path
 * @param {Set<object>} seen
 * @returns {void}
 */
function walk(value, path, seen) {
  const where = path || "the payload";

  if (value === null) return;
  const type = typeof value;
  if (type === "string" || type === "boolean") return;
  if (type === "number") {
    if (!Number.isFinite(value)) {
      throw dcaError("unsafe_payload", `${where} is ${value}, which JSON has no way to carry`);
    }
    return;
  }
  if (type !== "object") {
    const named = type === "undefined" ? "a member that is not there" : `a ${type}`;
    throw dcaError("unsafe_payload", `${where} is ${named}, which cannot cross the wire`);
  }

  const prototype = Object.getPrototypeOf(value);
  const plain = Array.isArray(value) || prototype === Object.prototype || prototype === null;
  if (!plain) {
    const kind = value?.constructor?.name ?? "an object of some class";
    throw dcaError(
      "unsafe_payload",
      `${where} is a ${kind}; only JSON primitives, plain objects and arrays cross the wire`,
    );
  }

  if (seen.has(value)) {
    throw dcaError("unsafe_payload", `${where} points back at something that holds it`);
  }
  seen.add(value);

  if (Array.isArray(value)) {
    value.forEach((entry, index) => walk(entry, `${path}[${index}]`, seen));
  } else {
    for (const name of Object.keys(value)) {
      walk(value[name], path ? `${path}.${name}` : name, seen);
    }
  }

  seen.delete(value);
}

/**
 * @param {any} payload
 * @returns {void}
 */
export function assertWireSafe(payload) {
  walk(payload, "", new Set());
}

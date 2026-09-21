// @ts-check
// Sibling to base source: js/v1/core-shared--publisher-issuer/bind.js
//
// Candidate BIND semantics for the authority a key represents. Render identity
// is deliberately absent: a period capability is reusable across renders.
// This is a runnable variation, not a frozen wire grammar.

import { dcaError } from "../../../core-shared/errors.js";

export const BIND_VERSION = "dca-bind-authority-proof";
export const BIND_DELIMITER = "|";

/**
 * @typedef {object} Binding
 * @property {string} publisher
 * @property {string} [resourceId]
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t]
 * @property {boolean} [periodChain]
 */

/** @param {unknown} value @param {string} field */
function bindable(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw dcaError("binding_failed", `${field} is not a non-empty string`);
  }
  if (value.includes(BIND_DELIMITER)) {
    throw dcaError("binding_failed", `${field} contains the BIND delimiter`);
  }
  return value;
}

/**
 * @param {Binding} binding
 * @returns {string[]}
 */
export function bindFields(binding) {
  if (binding === null || typeof binding !== "object") {
    throw dcaError("binding_failed", "a binding is an object naming one authority");
  }

  const publisher = bindable(binding.publisher, "publisher");
  const content = binding.resourceId !== undefined || binding.contentName !== undefined;
  const period = binding.accessGroup !== undefined || binding.t !== undefined;

  if (content && period) {
    throw dcaError(
      "binding_failed",
      "a binding names content authority or period authority, never both",
    );
  }
  if (content) {
    if (binding.resourceId === undefined || binding.contentName === undefined) {
      throw dcaError("binding_failed", "content authority needs resourceId and contentName");
    }
    if (binding.periodChain !== undefined) {
      throw dcaError("binding_failed", "content authority has no period-chain kind");
    }
    return [
      BIND_VERSION,
      "c",
      publisher,
      bindable(binding.resourceId, "resourceId"),
      bindable(binding.contentName, "contentName"),
    ];
  }
  if (period) {
    if (binding.accessGroup === undefined || binding.t === undefined) {
      throw dcaError("binding_failed", "period authority needs accessGroup and t");
    }
    if (binding.periodChain !== undefined && typeof binding.periodChain !== "boolean") {
      throw dcaError("binding_failed", "periodChain is a boolean");
    }
    return [
      BIND_VERSION,
      binding.periodChain === true ? "pc" : "p",
      publisher,
      bindable(binding.accessGroup, "accessGroup"),
      bindable(binding.t, "t"),
    ];
  }
  throw dcaError("binding_failed", "a binding names content or period authority");
}

/** @param {Binding} binding */
export function bindValue(binding) {
  return bindFields(binding).join(BIND_DELIMITER);
}

// @ts-check
//
// One error type that carries a `code`. The port's only job is to map those
// codes to status, so the code has to survive the throw as data rather than as
// a message a reader has to parse.

export class DcaError extends Error {
  /**
   * @param {string} code - stable identifier, also what the port maps on
   * @param {string} message - for a human reading a stack trace
   */
  constructor(code, message) {
    super(message);
    this.name = "DcaError";
    this.code = code;
  }
}

/**
 * @param {string} code
 * @param {string} message
 * @returns {DcaError}
 */
export function dcaError(code, message) {
  return new DcaError(code, message);
}

/**
 * Core currently defines no per-coordinate withheld codes. Family availability
 * is a `notDelivered` reason, never an error entry or a default retry signal.
 */
export const WITHHELD_CODES = {};

/**
 * These codes mark a call failure that carries no information about an
 * issuer's access decision. Both the browser walk and the fallback health gate
 * treat these as unavailable and may continue. Refusals are deliberately left
 * out of this shared set.
 */
/** @type {ReadonlySet<unknown>} */
const TRANSPORT_FAILURE_CODES = new Set(["offline", "timeout", "no_route"]);

/** @param {unknown} code */
export function isTransportFailureCode(code) {
  return TRANSPORT_FAILURE_CODES.has(code);
}

/** Opaque transport outcome supplies no conditional-retry authority.
 * @param {unknown} code @returns {boolean}
 */
export function isIndeterminateTransportCode(code) {
  return code === "indeterminate_transport";
}

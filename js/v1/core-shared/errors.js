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
 * A response carries these codes in its `errors` map to report a
 * per-coordinate decision: the issuer opened what arrived and withheld it.
 * These codes do not report a blob that would not open. These are named here,
 * in one place, because the issuer step that emits one and the client walk
 * that stops on one have to agree on the vocabulary: a code added on one side but not the other would
 * either be reported and never stopped on, or stopped on and never reported.
 * Both build off this object, so adding a code here once adds it to both.
 *
 * The HTTP status (400) carries a wire-level refusal such as `bad_client_key`,
 * and a 200 `errors` map does not, so it is left out of this object on
 * purpose. The walk ends fail-closed on it through the status branch, not
 * through a withheld code.
 *
 * `noCurrentPeriod`: a fallback grants the current period only, and no period
 * an accessGroup presented has started. Emitted by `trimToCurrentPeriod`.
 */
export const WITHHELD_CODES = {
  noCurrentPeriod: "no_current_period",
};

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

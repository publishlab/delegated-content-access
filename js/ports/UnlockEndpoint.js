// @ts-check

// Default HTTP-shaped adapter around issuer core. It maps semantic DCA results
// to `{ status, body }` and fills in refusal detail from the `errorDetail` setting
// fixed at construction. The issuer core holds the verification, policy, unsealing and
// parsing; on the application path the issuer application admits through the injected
// processor before its cache lookup, then passes this port an already-admitted request
// on a miss. The raw-document compatibility entry (`handleDocument`) also admits through
// that same injected processor.

/** @import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js" */
import { dcaError } from "../core-shared/errors.js";

/** @typedef {import('../core-issuer/IssuerProcessor.js').DcaResult} DcaResult */

/** @type {Map<string, number>} */
const STATUS = new Map([
  ["invalid_json", 400],
  ["too_many_entries", 400],
  ["body_too_large", 413],
  ["unknown_key", 503],
  ["out_of_scope_issuer", 400],
  ["policy_unavailable", 503],
  ["bad_version", 400],
  ["bad_jwt", 400],
  ["bad_alg", 400],
  ["bad_signature", 400],
  ["unknown_publisher_key", 400],
  ["binding_failed", 400],
  ["request_mismatch", 400],
  ["unsupported_option", 400],
  ["client_key_required", 400],
  ["bad_client_key", 400],
  ["denied", 401],
]);

/** The error a uniform issuer returns for every refusal, whatever the cause. */
const UNIFORM_ERROR = "rejected";

const DETAILS = ["code", "uniform"];
const OPTIONS = ["errorDetail"];

/**
 * The common body for protocol and host admission refusals.
 *
 * @param {string} code
 * @param {'code'|'uniform'} errorDetail
 * @param {object} [detail] - included only when the configured detail mode is `code`
 * @returns {object}
 */
export function refusalBody(code, errorDetail, detail = {}) {
  return errorDetail === "uniform" ? { error: UNIFORM_ERROR } : { error: code, ...detail };
}

export class UnlockEndpoint {
  /** @type {IssuerProcessor} */
  #processor;

  /** @type {'code'|'uniform'} */
  #errorDetail;

  /**
   * @param {IssuerProcessor} processor - the issuer application constructs it and
   *   gives it the admission caps through the processor's own `limits`; `errorDetail`
   *   is this port's only option.
   * @param {object} [options]
   * @param {'code'|'uniform'} [options.errorDetail]
   */
  constructor(processor, options = {}) {
    if (typeof processor?.admit !== "function" || typeof processor?.processMiss !== "function") {
      throw dcaError(
        "bad_config",
        "UnlockEndpoint needs an IssuerProcessor to admit and process through",
      );
    }

    const config = options ?? {};
    for (const name of Object.keys(config)) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `UnlockEndpoint has no ${name} yet, and will not pretend to`,
        );
      }
    }

    const errorDetail = config.errorDetail ?? "code";
    if (!DETAILS.includes(errorDetail)) {
      throw dcaError(
        "unsupported_option",
        `${JSON.stringify(errorDetail)} is not a refusal detail`,
      );
    }

    this.#processor = processor;
    this.#errorDetail = /** @type {'code'|'uniform'} */ (errorDetail);
  }

  /** Browser host refusals use the same configured disclosure as core refusals. */
  /** @param {string} code */
  admissionRefusalBody(code) {
    return refusalBody(code, this.#errorDetail);
  }

  /**
   * The in-process result the application observes. `response` crosses the wire.
   * `code` names the refusal the core reported, even where the body carries only
   * `rejected`, so the application can count and log it. Only `response` is ever
   * put on the transport.
   *
   * @param {DcaResult} result
   * @returns {{ response: { status: number, body: object }, policyData: any, code: string|undefined }}
   */
  #toHttp(result) {
    if (result.kind === "success") {
      return {
        response: { status: 200, body: result.document },
        policyData: result.policyData,
        code: undefined,
      };
    }

    const status = STATUS.get(result.code) ?? 500;
    return {
      response: { status, body: refusalBody(result.code, this.#errorDetail) },
      policyData: undefined,
      code: result.code,
    };
  }

  /**
   * Map a structural-admission refusal to the wire. The issuer application admits
   * before its cache lookup; when admission fails it passes the failure here, so the
   * status map and the refusal wording stay in this one file.
   *
   * @param {DcaResult} result - a failure the processor's `admit` returned
   * @returns {{ response: { status: number, body: object }, policyData: any, code: string|undefined }}
   */
  refusal(result) {
    // `admit` never reports a refusal as a success, so a host that passes a success
    // here has wired the port wrong. `#toHttp` would map that success to 200 and
    // deliver the document it carries, so `refusal` throws instead.
    if (result?.kind === "success") {
      throw dcaError(
        "bad_config",
        "UnlockEndpoint.refusal takes an admission failure, not a success",
      );
    }
    return this.#toHttp(result);
  }

  /**
   * Miss-processing boundary for the issuer application and controlled
   * in-process hosts. The caller admits the request through the processor before
   * this call, and that single admission stands: the port processes the miss and
   * maps the result.
   *
   * @param {import('../core-issuer/IssuerProcessor.js').IssuerInvocation} invocation -
   *   one host-owned context for an already-admitted request
   * @returns {Promise<{ response: { status: number, body: object }, policyData: any, code: string|undefined }>}
   */
  async handleRequest(invocation) {
    return this.#toHttp(await this.#processor.processMiss(invocation));
  }

  /**
   * Raw-document compatibility boundary for a real host or a portable contract
   * bridge. It admits through the injected processor and, on admission,
   * processes the miss. The measured-before-parse byte cap runs here because
   * the processor owns it on the raw-document admission path.
   *
   * @param {string} requestDocument
   * @param {import('../core-issuer/IssuerEngine.js').PublisherRegistration} registration
   * @param {{ principal?: any, context?: any }} [policyInput]
   * @param {number} [capturedAtMs] - finite host-captured epoch milliseconds
   * @returns {Promise<{ response: { status: number, body: object }, policyData: any, code: string|undefined }>}
   */
  async handleDocument(requestDocument, registration, policyInput = {}, capturedAtMs) {
    const admission = this.#processor.admit(requestDocument);
    if (admission.kind !== "admitted") return this.#toHttp(admission);
    return this.handleRequest({
      request: admission.request,
      registration,
      policyInput,
      capturedAtMs,
    });
  }
}

// @ts-check

// This class holds one DCA request document, and both the client and the
// issuer use it. The client builds one with `fromParts` and posts
// `toObject()`. The issuer parses that string into the same class and
// verifies, decides and unseals against it.
//
// Building or parsing produces one stable object for protocol code to inspect.
// Neither step authenticates the request or makes malformed fields valid. The
// engine still performs verification.

import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";

/**
 * A read-only view of one parsed, still-untrusted request.
 *
 * The class reads the fixed fields and checks the containers in one place,
 * which catches implementation mistakes. It does not authenticate the request,
 * authorize access, or make any value trusted. Publisher authenticity is
 * established later by signature verification; the issuer's policy decides
 * access.
 */
export class DcaRequest {
  #document;

  /**
   * Wrap one parsed but still untrusted request representation.
   *
   * @param {unknown} document
   */
  constructor(document) {
    this.#document = document;
  }

  /**
   * Builds a request on the client side. Member order and omission rules
   * match what a request has always carried. When the client cannot fill an
   * optional member, it omits that member, because JSON cannot hold a member
   * whose value is undefined. The issuer, not this client, decides what an
   * incomplete request means.
   *
   * @param {object} parts
   * @param {unknown} parts.version
   * @param {unknown} parts.issuerName
   * @param {unknown} [parts.resourceJWT] - carried only when it is a string
   * @param {unknown} [parts.keyId] - carried only when it is a string
   * @param {Record<string, string>} [parts.contentKeys]
   * @param {Record<string, Record<string, string>>} [parts.periodKeys]
   * @param {unknown} [parts.clientPublicKey] - offered, never demanded
   * @returns {DcaRequest}
   */
  static fromParts(parts) {
    if (parts === null || typeof parts !== "object") {
      throw dcaError("bad_config", "a DCA request is built from a parts object");
    }

    const periodKeys = parts.periodKeys ?? {};
    /** @type {any} */
    const document = {
      version: parts.version,
      issuerName: parts.issuerName,
      ...(typeof parts.resourceJWT === "string" ? { resourceJWT: parts.resourceJWT } : {}),
      ...(typeof parts.keyId === "string" ? { keyId: parts.keyId } : {}),
      sealed: { contentKeys: parts.contentKeys ?? {} },
    };
    if (Object.keys(periodKeys).length > 0) document.sealed.periodKeys = periodKeys;
    if (parts.clientPublicKey !== undefined) document.clientPublicKey = parts.clientPublicKey;

    return new DcaRequest(document);
  }

  /** @returns {unknown} */
  get version() {
    return own(this.#document, "version");
  }

  /** @returns {unknown} */
  get issuerName() {
    return own(this.#document, "issuerName");
  }

  /** @returns {unknown} */
  get keyId() {
    return own(this.#document, "keyId");
  }

  /** @returns {unknown} */
  get resourceJWT() {
    return own(this.#document, "resourceJWT");
  }

  /**
   * What this client can do, offered as an option. Its presence does
   * not ask for client-bound delivery and does not change what the issuer
   * verifies, decides or unseals; an issuer may still answer directly.
   *
   * @returns {unknown}
   */
  get clientPublicKey() {
    return own(this.#document, "clientPublicKey");
  }

  /** @returns {unknown} */
  get sealed() {
    return own(this.#document, "sealed");
  }

  /**
   * @param {'contentKeys'|'periodKeys'|'periodChainKeys'} name
   * @returns {Record<string, unknown>|undefined}
   */
  #sealedMapFor(name) {
    const value = own(this.sealed, name);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : undefined;
  }

  /** @returns {Record<string, unknown>|undefined} */
  get sealedContentKeys() {
    return this.#sealedMapFor("contentKeys");
  }

  /** @returns {Record<string, unknown>|undefined} */
  get sealedPeriodKeys() {
    return this.#sealedMapFor("periodKeys");
  }

  /** @returns {Record<string, unknown>|undefined} */
  get sealedPeriodChainKeys() {
    return this.#sealedMapFor("periodChainKeys");
  }

  /**
   * Returns the document itself, for a caller that has to serialise it, hash
   * it, or key a cache on it. It returns the same object this request was
   * built or parsed from, so unknown members and member order stay as they
   * arrived.
   *
   * @returns {any}
   */
  toObject() {
    return this.#document;
  }
}

/**
 * Parse the document once. Callers must keep and use this returned
 * representation for verification, policy, and unsealing.
 *
 * @param {string} document
 * @returns {DcaRequest}
 */
export function parseDcaRequest(document) {
  if (typeof document !== "string") {
    throw dcaError("bad_config", "a DCA request document is a raw JSON string");
  }

  let parsed;
  try {
    parsed = JSON.parse(document);
  } catch {
    throw dcaError("invalid_json", "the DCA request document is not valid JSON");
  }
  return new DcaRequest(parsed);
}

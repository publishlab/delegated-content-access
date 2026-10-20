// @ts-check

import { dcaError } from "../core-shared/errors.js";
import { isAccessGroup, isContentName } from "../core-shared/names.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { own } from "../core-shared/wire.js";
import { DcaData } from "./DcaData.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";

/** @param {unknown} value @returns {value is object} */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** @param {unknown} value @returns {any} */
function frozenClone(value) {
  if (Array.isArray(value)) {
    /** @type {any[]} */
    const clone = [];
    for (let index = 0; index < value.length; index++) {
      if (!Object.hasOwn(value, index)) continue;
      Object.defineProperty(clone, index, {
        value: frozenClone(own(value, String(index))),
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    Object.defineProperty(clone, "length", { value: value.length, writable: false });
    return Object.freeze(clone);
  }
  if (!record(value)) return value;
  const clone = {};
  for (const name of Object.keys(value)) {
    Object.defineProperty(clone, name, {
      value: frozenClone(own(value, name)),
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(clone);
}

/** Immutable evidence of the exact request associated with one response. */
export class ResponseAssociation {
  #issuerName;
  #delivery;
  #page;
  #request;
  #acceptDirectResponse;

  /**
   * @param {DcaData} page
   * @param {string} issuerName
   * @param {DcaRequest|object} request
   * @param {{ acceptDirectResponse?: boolean }} [endpoint] - trusted endpoint agreement
   */
  constructor(page, issuerName, request, endpoint = {}) {
    if (!(page instanceof DcaData)) {
      throw dcaError("bad_config", "a response association needs a DcaData page");
    }
    const document = request instanceof DcaRequest ? request.toObject() : request;
    if (!record(document)) {
      throw dcaError("bad_config", "a response association needs the request document sent");
    }
    if (
      endpoint.acceptDirectResponse !== undefined &&
      typeof endpoint.acceptDirectResponse !== "boolean"
    ) {
      throw dcaError("bad_config", "an endpoint's acceptDirectResponse is boolean");
    }
    if (
      own(document, "issuerName") !== issuerName ||
      own(document, "version") !== page.version ||
      own(document, "resourceJWT") !== page.resourceJWT ||
      own(document, "keyId") !== page.keyIdFor(issuerName) ||
      own(document, "envelope") !== page.envelopeFor(issuerName)
    ) {
      throw dcaError("bad_config", "a response association must match its page and issuer");
    }
    this.#issuerName = issuerName;
    this.#delivery = page.toObject();
    this.#page = Object.freeze({
      version: page.version,
      resourceJWT: page.resourceJWT,
      renderId: page.renderId,
      keyId: page.keyIdFor(issuerName),
      envelope: page.envelopeFor(issuerName),
      publisherOrigin: page.publisherOrigin,
    });
    this.#request = frozenClone(document);
    // An offer does not itself authorize direct fallback. A request with no
    // client-bound offer retains the baseline default; an offered method needs
    // an explicit endpoint agreement before key material in direct
    // representation is admitted.
    this.#acceptDirectResponse =
      endpoint.acceptDirectResponse ?? own(document, "clientPublicKey") === undefined;
    Object.freeze(this);
  }

  /** @param {DcaData} page @param {string} issuerName */
  matches(page, issuerName) {
    if (
      !(page instanceof DcaData) ||
      issuerName !== this.#issuerName ||
      page.toObject() !== this.#delivery
    )
      return false;
    try {
      return (
        page.version === this.#page.version &&
        page.resourceJWT === this.#page.resourceJWT &&
        page.renderId === this.#page.renderId &&
        page.keyIdFor(issuerName) === this.#page.keyId &&
        page.envelopeFor(issuerName) === this.#page.envelope &&
        page.publisherOrigin === this.#page.publisherOrigin
      );
    } catch {
      return false;
    }
  }

  get request() {
    return this.#request;
  }

  get acceptDirectResponse() {
    return this.#acceptDirectResponse;
  }

  /** The one client-bound method the immutable request offered, if any. */
  get offeredClientBoundMethod() {
    const publicKey = own(this.#request, "clientPublicKey");
    if (!record(publicKey)) return null;
    if (own(publicKey, "kty") === "EC" && own(publicKey, "crv") === "P-256") {
      return "ECDH-P256";
    }
    return own(publicKey, "kty") === "RSA" ? "RSA-OAEP" : null;
  }

  /** @param {string} contentName */
  presentsContent(contentName) {
    return (
      isContentName(contentName) &&
      Object.hasOwn(own(own(this.#request, "sealed"), "contentKeys") ?? {}, contentName)
    );
  }

  /** @param {string} accessGroup @param {string} t */
  presentsPeriodKey(accessGroup, t) {
    return (
      isAccessGroup(accessGroup) &&
      isPeriodKeyLabel(t) &&
      Object.hasOwn(own(own(own(this.#request, "sealed"), "periodKeys"), accessGroup) ?? {}, t)
    );
  }

  /** @param {string} accessGroup @param {string} t */
  presentsChainKey(accessGroup, t) {
    return Object.hasOwn(own(own(own(this.#request, "sealed"), "chainKeys"), accessGroup) ?? {}, t);
  }
}

// @ts-check
//
// The client composition, without the network: the wiring `demo/actors/PageLoad`
// performs, factored so a unit test drives the client flow directly against the
// units the mixed `Unsealer` dissolved into. It reads the object delivery form
// through `demo/support/ObjectDeliveryReader` (parse/extract) and takes the
// rest from `integration-client/composeClient`, which builds the same request
// builder, key resolver and representation opener a page load runs on, plus the
// injected client-bound capability's opening half. A Client built with no
// `cache` now reads and writes an in-memory `PeriodKeyCache` that
// `composeClient` builds for it, where it formerly resolved nothing from cache.
//
// This is test support rather than a component: `PageLoad` is the real demo
// composition, and adds the network walk, breaker and observations on top. This
// directory holds the assert side of the suite; nothing here is collected as a
// test file.
//
// The `{ publisherOrigin, cache, clientBoundKeyCapability }` config and its
// option-refusal mirror what the browser hands a load, so a test reads the same
// as the flow it stands in for: a client with no keypair asks for nothing but
// direct, and a clock has nowhere to enter because no client call takes a
// moment. The delivery origin is required, because the browser reads one off
// the page it loaded and no test client may invent one. A client that filed its
// period keys under an origin nothing was delivered from would partition the
// cache by a coordinate no page has.

import { DcaData } from "../../core-client/DcaData.js";
import { ResponseAssociation } from "../../core-client/ResponseAssociation.js";
import { composeClient } from "../../integration-client/composeClient.js";
import { dcaError } from "../../core-shared/errors.js";
import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";
import { own } from "../../core-shared/wire.js";
import { ObjectDeliveryReader } from "../../demo/support/ObjectDeliveryReader.js";
const OPTIONS = [
  "publisherOrigin",
  "cache",
  "chainCache",
  "periodChainProfile",
  "clientBoundKeyCapability",
  "acceptDirectFallback",
  "persistRawPeriodKeys",
  "relayExactPeriod",
  "requestBuilderFactory",
  "contentDecoders",
];

export class Client {
  /** @type {import('../../core-client/ContentKeyResolver.js').ContentKeyResolver} */
  #resolver;
  /** @type {{ build: Function }} */
  #builder;
  /** @type {import('../../core-client/ContentRepresentationOpener.js').ContentRepresentationOpener} */
  #opener;
  #publisherOrigin;
  /** @type {WeakMap<object, Map<string, ResponseAssociation>>} */
  #responseAssociations = new WeakMap();

  /**
   * @param {object} config
   * @param {string} config.publisherOrigin - the canonical origin this page
   *   was delivered from, required for the same reason `Page` and
   *   `ObjectDeliveryReader` require it: nothing here may invent one
   * @param {any} [config.cache]
   * @param {any} [config.chainCache]
   * @param {any} [config.periodChainProfile]
   *   client resolves under, as a browser is configured with one
   * @param {{ publicKey: JsonWebKey, openDeliveredKeys: Function }} [config.clientBoundKeyCapability]
   * @param {boolean} [config.acceptDirectFallback]
   * @param {boolean} [config.persistRawPeriodKeys]
   * @param {boolean} [config.relayExactPeriod]
   * @param {(options: object) => { build: Function }} [config.requestBuilderFactory]
   * @param {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [config.contentDecoders]
   */
  constructor(config = /** @type {any} */ ({})) {
    // The empty default is here so `new Client()` reaches the refusal below
    // and says what is missing, rather than dying on a property read.
    for (const name of Object.keys(config)) {
      if (!OPTIONS.includes(name)) {
        throw dcaError("unsupported_option", `Client has no ${name} yet, and will not pretend to`);
      }
    }

    const publisherOrigin = normalizePublisherOrigin(config.publisherOrigin);
    if (publisherOrigin === null) {
      throw dcaError(
        "bad_config",
        "a Client needs its canonical publisherOrigin as delivery context",
      );
    }
    this.#publisherOrigin = publisherOrigin;

    const { resolver, builder, opener } = composeClient({
      ...(config.cache === undefined ? {} : { cache: config.cache }),
      ...(config.chainCache === undefined ? {} : { chainCache: config.chainCache }),
      ...(config.periodChainProfile === undefined
        ? {}
        : { periodChainProfile: config.periodChainProfile }),
      ...(config.clientBoundKeyCapability === undefined
        ? {}
        : { clientBoundKeyCapability: config.clientBoundKeyCapability }),
      ...(config.acceptDirectFallback === undefined
        ? {}
        : { acceptDirectFallback: config.acceptDirectFallback }),
      ...(config.persistRawPeriodKeys === undefined
        ? {}
        : { persistRawPeriodKeys: config.persistRawPeriodKeys }),
      // This test harness historically models the exact-period client used by
      // its focused suites. Production composition defaults the same option
      // off; a baseline-focused test can select that state explicitly here.
      relayExactPeriod: config.relayExactPeriod ?? true,
      ...(config.requestBuilderFactory === undefined
        ? {}
        : { requestBuilderFactory: config.requestBuilderFactory }),
      ...(config.contentDecoders === undefined ? {} : { contentDecoders: config.contentDecoders }),
    });
    this.#resolver = /** @type {any} */ (resolver);
    this.#builder = builder;
    this.#opener = opener;
  }

  /**
   * dca-data out of the object delivery form.
   *
   * @param {object|string} page
   * @returns {object} dcaData
   */
  parse(page) {
    return new ObjectDeliveryReader(page, { publisherOrigin: this.#publisherOrigin }).dcaData;
  }

  /**
   * The sealed ciphertext for one item, or null when the page does not carry
   * it - deferred content is a URL fetch, and an unknown name is a miss.
   *
   * @param {object} page
   * @param {string} contentName
   * @returns {string|null} base64url ciphertext
   */
  extract(page, contentName) {
    const value = own(own(page, "sealedContent"), contentName);
    return typeof value === "string" ? value : null;
  }

  /**
   * The wire-shaped request for one issuer, as the client would post it.
   *
   * @param {object} dcaData
   * @param {string} issuerName
   * @param {string[]} needed
   * @returns {any}
   */
  buildRequest(dcaData, issuerName, needed) {
    const page = new DcaData(dcaData, { publisherOrigin: this.#publisherOrigin });
    const delivery = page.toObject();
    let outstanding = this.#responseAssociations.get(delivery);
    if (outstanding?.has(issuerName)) {
      throw dcaError("bad_config", "a Client cannot replace an outstanding response association");
    }
    const request = this.#builder.build(page, issuerName, needed);
    if (outstanding === undefined) {
      outstanding = new Map();
      this.#responseAssociations.set(delivery, outstanding);
    }
    outstanding.set(issuerName, new ResponseAssociation(page, issuerName, request));
    return request.toObject();
  }

  /**
   * @param {object} dcaData
   * @param {string[]} contentNames
   * @param {object[]} responseAttempt - optional response application report
   * @returns {Promise<{ covered: string[], missing: string[] }>}
   */
  resolve(dcaData, contentNames, ...responseAttempt) {
    return this.#resolver.resolve(
      new DcaData(dcaData, { publisherOrigin: this.#publisherOrigin }),
      contentNames,
      ...responseAttempt,
    );
  }

  /**
   * @param {object} dcaData
   * @param {string} issuerName
   * @param {object} response
   * @param {object[]} requestContext - optional request document retained by a focused test
   * @returns {Promise<{ accepted: number, errors: object[], issues: object[] }>}
   */
  async applyResponse(dcaData, issuerName, response, ...requestContext) {
    const page = new DcaData(dcaData, { publisherOrigin: this.#publisherOrigin });
    const supplied = requestContext[0];
    let association;
    if (supplied instanceof ResponseAssociation) {
      association = supplied;
    } else if (supplied !== undefined) {
      association = new ResponseAssociation(page, issuerName, supplied);
    } else {
      const outstanding = this.#responseAssociations.get(page.toObject());
      association = outstanding?.get(issuerName);
      outstanding?.delete(issuerName);
      if (outstanding?.size === 0) this.#responseAssociations.delete(page.toObject());
    }
    const application = await this.#resolver.applyResponse(page, issuerName, response, association);
    // Mirror the production load: a response's private exact capabilities
    // are tried immediately, then promoted or discarded by that attempt.
    await this.#resolver.resolve(page, page.contentNames(), application);
    return application;
  }

  /**
   * @param {object} dcaData
   * @param {string} contentName
   * @returns {Promise<Uint8Array|CryptoKey|null>}
   */
  contentKeyFor(dcaData, contentName) {
    return this.#resolver.contentKeyFor(
      new DcaData(dcaData, { publisherOrigin: this.#publisherOrigin }),
      contentName,
    );
  }

  /**
   * The open path: the key resolution the resolver owns, then the decode-and-
   * open tail `openContent` owns. The aad is the page's on this composition,
   * and a page that mangled it is a bad page. A variant that derives its own
   * aad overrides `aadFor`.
   *
   * @param {object} dcaData
   * @param {string} contentName
   * @param {string|null} ciphertext - base64url, from `extract`
   * @returns {Promise<Uint8Array>} plaintext bytes; contentType is in the record
   */
  async decrypt(dcaData, contentName, ciphertext) {
    // Through the view rather than a walk of its own, so the record rules
    // this composition opens under are the ones `PageLoad` opens under.
    const record = new DcaData(dcaData, { publisherOrigin: this.#publisherOrigin }).contentDataFor(
      contentName,
    );
    if (!record) {
      throw dcaError("unknown_content", `the page declares no content item "${contentName}"`);
    }
    if (typeof ciphertext !== "string") {
      throw dcaError("unknown_content", `no ciphertext for "${contentName}"`);
    }

    return this.#opener.open({
      record,
      contentName,
      ciphertext,
      aad: this.aadFor(dcaData, contentName, record),
      resolveKey: () => this.contentKeyFor(dcaData, contentName),
    });
  }

  /**
   * Where the aad comes from. The base composition reads it off the record
   * beside the ciphertext; a variant that binds content its own way overrides
   * this and openContent's guards stay shared.
   *
   * @param {object} dcaData
   * @param {string} contentName
   * @param {any} record
   * @returns {string}
   */
  aadFor(dcaData, contentName, record) {
    return own(record, "aad");
  }
}

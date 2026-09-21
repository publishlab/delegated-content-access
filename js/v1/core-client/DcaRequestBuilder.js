// @ts-check

// Builds the request the client sends to one issuer. It reads a page through
// `DcaData`, selects the key material that issuer can open, and returns a
// `DcaRequest`.
//
// It does not inspect the cache, contact an issuer, apply a response or unwrap
// anything. The caller settles what is already cached before it asks this:
// `needed` is the contentNames the client could not resolve itself, and
// sending fewer is always correct because the issuer answers whatever it
// receives.
//
// `DcaData` admits the page this reads. It holds the outer object, the
// selected issuer block and each route map to the shape the format states, so
// this refuses an unusable issuer block with `unknown_issuer`. `DcaData` also
// admits identifier-keyed maps, so this relays only what the format admits: a
// rejected route map carries no member into the request, a rejected
// cached-wrap map selects no accessGroup, and a name the caller asks about
// that no admitted map carries stays absent and is not looked up some other
// way.
//
// `build` always sends the baseline contentKeys for the needed items. When
// trusted client configuration selects exact-period relay, it also sends the
// sealed periodKeys for every accessGroup those items are wrapped under. The
// issuer decides which presented coordinate it grants, and a client that gets
// periodKeys never needs the contentKey.
// Optional carrier members are added by their selected request composition;
// base does not forward one merely because the page carries it.
//
// For an included group, the builder sends the whole carried period family
// instead of one `t`, because the client cannot tell which period the article
// it reads next was rendered in, and the overlap key covers the boundary.

import { dcaError } from "../core-shared/errors.js";
import { isExactPeriodLabel } from "../core-shared/periodLabels.js";
import { setOwn } from "../core-shared/wire.js";
import { DcaData } from "./DcaData.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";

const OPTIONS = ["clientPublicKey", "relayExactPeriod"];

export class DcaRequestBuilder {
  /** @type {unknown} */
  #clientPublicKey;

  /** @type {boolean} */
  #relayExactPeriod;

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey] - the exported public half of
   *   the client's transport pair, already a JWK because a request is a
   *   payload and exporting one would make building it asynchronous. If it
   *   is left out, this client offers no client-bound transport.
   * @param {boolean} [config.relayExactPeriod] - whether this client has
   *   selected the exact-period profile for its request projection
   */
  constructor(config = {}) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `DcaRequestBuilder has no ${name} yet, and will not pretend to`,
        );
      }
    }
    if (config?.relayExactPeriod !== undefined && typeof config.relayExactPeriod !== "boolean") {
      throw dcaError("bad_config", "relayExactPeriod is boolean");
    }
    this.#clientPublicKey = config?.clientPublicKey;
    this.#relayExactPeriod = config?.relayExactPeriod ?? false;
  }

  /**
   * @param {DcaData} page
   * @param {string} issuerName
   * @param {string[]} needed - contentNames the client could not resolve
   * @returns {DcaRequest}
   */
  build(page, issuerName, needed) {
    if (!(page instanceof DcaData)) {
      throw dcaError("bad_config", "a request is built from a DcaData; construct one first");
    }
    if (!page.hasIssuer(issuerName)) {
      throw dcaError("unknown_issuer", `the page carries no issuer "${issuerName}"`);
    }

    /** @type {Record<string, string>} */
    const contentKeys = {};
    /** @type {Record<string, Record<string, string>>} */
    const periodKeys = {};
    for (const contentName of needed) {
      const blob = page.sealedContentKeyFor(issuerName, contentName);
      if (typeof blob === "string") setOwn(contentKeys, contentName, blob);

      for (const accessGroup of this.#relayExactPeriod ? page.accessGroupsFor(contentName) : []) {
        const periods = page.sealedPeriodKeysFor(issuerName, accessGroup);
        if (periods !== null && typeof periods === "object") {
          const admitted = Object.fromEntries(
            Object.entries(/** @type {any} */ (periods)).filter(
              ([t, blob]) => isExactPeriodLabel(t) && typeof blob === "string",
            ),
          );
          if (Object.keys(admitted).length > 0) setOwn(periodKeys, accessGroup, admitted);
        }
      }
    }

    // The builder forwards the envelope as it arrived. The client cannot
    // check it because it has no publisher key, and it does not need to. The
    // envelope gives the issuer evidence that the resource claims came from
    // the publisher, and it carries the renderId that the blobs beside it are
    // bound to. The issuer decides what an incomplete request means, so a
    // page carrying no envelope or no keyId sends no member in its place.
    return DcaRequest.fromParts({
      version: page.version,
      issuerName,
      resourceJWT: page.resourceJWT,
      keyId: page.keyIdFor(issuerName),
      contentKeys,
      periodKeys,

      // The client offers this key and does not demand its use. An issuer
      // with no client-bound mode ignores it; an issuer pinned to
      // client-bound has nothing to wrap to without it.
      clientPublicKey: this.#clientPublicKey,
    });
  }
}

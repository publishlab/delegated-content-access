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
// selected issuer block and each route collection to the shape the format
// states, so this refuses an unusable issuer block with `unknown_issuer`.
// `DcaData` also admits the identity fields of each collection, so this relays
// only what the format admits: a rejected route collection carries no record
// into the request, a rejected cached-wrap collection selects no accessGroup,
// and a name the caller asks about that no admitted record carries stays
// absent and is not looked up some other way. Several records at one
// coordinate are candidate alternatives, and the builder relays every one
// whose key is canonical.
//
// `build` always sends the baseline contentKeys for the needed items. When
// trusted client configuration selects period-key relay, it also sends the
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
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { own } from "../core-shared/wire.js";
import { DcaData } from "./DcaData.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";

const OPTIONS = ["clientPublicKey", "relayPeriodKeys"];

export class DcaRequestBuilder {
  /** @type {unknown} */
  #clientPublicKey;

  /** @type {boolean} */
  #relayPeriodKeys;

  /**
   * @param {object} [config]
   * @param {unknown} [config.clientPublicKey] - the exported public half of
   *   the client's transport pair, already a JWK because a request is a
   *   payload and exporting one would make building it asynchronous. If it
   *   is left out, this client offers no client-bound transport.
   * @param {boolean} [config.relayPeriodKeys] - whether this client has
   *   selected the period-key profile for its request projection
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
    if (config?.relayPeriodKeys !== undefined && typeof config.relayPeriodKeys !== "boolean") {
      throw dcaError("bad_config", "relayPeriodKeys is boolean");
    }
    this.#clientPublicKey = config?.clientPublicKey;
    this.#relayPeriodKeys = config?.relayPeriodKeys ?? false;
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

    /** @type {{ contentName: string, key: string }[]} */
    const contentKeys = [];
    /** @type {{ accessGroup: string, period: string, key: string }[]} */
    const periodKeys = [];
    // An item or group named twice by the caller or by the page is relayed
    // once; its several candidate records are all relayed, each once.
    const relayedItems = new Set();
    const relayedGroups = new Set();
    for (const contentName of needed) {
      if (relayedItems.has(contentName)) continue;
      relayedItems.add(contentName);
      for (const key of page.sealedContentKeysFor(issuerName, contentName)) {
        if (typeof key === "string" && binaryStringBytes(key) !== null)
          contentKeys.push({ contentName, key });
      }

      for (const accessGroup of this.#relayPeriodKeys ? page.accessGroupsFor(contentName) : []) {
        if (relayedGroups.has(accessGroup)) continue;
        relayedGroups.add(accessGroup);
        for (const record of page.sealedPeriodKeysFor(issuerName, accessGroup) ?? []) {
          const period = own(record, "period");
          const key = own(record, "key");
          if (
            typeof period === "string" &&
            isPeriodKeyLabel(period) &&
            typeof key === "string" &&
            binaryStringBytes(key) !== null
          )
            periodKeys.push({ accessGroup, period, key });
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
      // Taken from the same block as keyId: the issuer opens these blobs with
      // the procedure this member names, so it must describe this block.
      envelope: page.envelopeFor(issuerName),
      contentKeys,
      periodKeys,

      // The client offers this key and does not demand its use. An issuer
      // with no client-bound mode ignores it; an issuer pinned to
      // client-bound has nothing to wrap to without it.
      clientPublicKey: this.#clientPublicKey,
    });
  }
}

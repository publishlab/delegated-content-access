// @ts-check
//
// Compatibility adapter for the omission client's selected entry reading and
// for the items its requests present through bound candidates, so a returned
// key or error for one of them is solicited. Candidate ordering, response
// application, detailed origins, and the single wrap attempt all remain
// base-owned in `ContentKeyResolver`.

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { dcaError } from "../../../core-shared/errors.js";
import { omissionEntryInterpretation } from "./omissionEntryInterpretation.js";
import { omissionPresentedContentNames } from "./OmissionRequestBuilder.js";

const OPTIONS = [
  "cache",
  "chainCache",
  "chainKeyProfile",
  "clientBoundKeyCapability",
  "acceptDirectFallback",
  "persistRawPeriodKeys",
  "periodKeyResponseCoordinate",
  "responseSections",
  "recoverySources",
];

/**
 * The base resolver options this composition passes through. It sets
 * `entryInterpretation` and `presentedContentNames` itself, so a caller's copy
 * of either is refused rather than silently replaced.
 *
 * @typedef {Pick<
 *   NonNullable<ConstructorParameters<typeof ContentKeyResolver>[0]>,
 *   | "cache"
 *   | "chainCache"
 *   | "chainKeyProfile"
 *   | "clientBoundKeyCapability"
 *   | "acceptDirectFallback"
 *   | "persistRawPeriodKeys"
 *   | "periodKeyResponseCoordinate"
 *   | "responseSections"
 *   | "recoverySources"
 * >} OmissionResolverOptions
 */

/**
 * Factory form for Browser's resolver composition seam.
 *
 * @param {OmissionResolverOptions} [options]
 * @returns {ContentKeyResolver}
 */
export function omissionContentKeyResolverFactory(options = {}) {
  for (const name of Object.keys(options ?? {})) {
    if (!OPTIONS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `the omission resolver has no ${name} yet, and will not pretend to`,
      );
    }
  }
  return new ContentKeyResolver({
    ...options,
    entryInterpretation: omissionEntryInterpretation,
    presentedContentNames: omissionPresentedContentNames,
  });
}

export class BoundContentKeyResolver {
  /** @type {ContentKeyResolver} */
  #resolver;

  /** @param {OmissionResolverOptions} [config] */
  constructor(config = {}) {
    this.#resolver = omissionContentKeyResolverFactory(config);
  }

  /** Validate recursive reset support in the selected retaining owners.
   * @returns {void}
   */
  assertReaderContextReset() {
    return this.#resolver.assertReaderContextReset();
  }

  /** Retire and clear the underlying resolver's reader context.
   * @returns {Promise<void>}
   */
  clearReaderContext() {
    return this.#resolver.clearReaderContext();
  }

  /** @param {Parameters<ContentKeyResolver["applyResponse"]>} args */
  applyResponse(...args) {
    return this.#resolver.applyResponse(...args);
  }

  /** @param {Parameters<ContentKeyResolver["resolveDetailed"]>} args */
  resolveDetailed(...args) {
    return this.#resolver.resolveDetailed(...args);
  }

  /** @param {Parameters<ContentKeyResolver["contentKeyWithOriginFor"]>} args */
  contentKeyWithOriginFor(...args) {
    return this.#resolver.contentKeyWithOriginFor(...args);
  }

  /** @param {Parameters<ContentKeyResolver["resolve"]>} args */
  resolve(...args) {
    return this.#resolver.resolve(...args);
  }

  /** @param {Parameters<ContentKeyResolver["contentKeyFor"]>} args */
  contentKeyFor(...args) {
    return this.#resolver.contentKeyFor(...args);
  }

  // A route walk selects keys only after they authenticate the item's sealed
  // bytes. The arguments, including the response application that carries its
  // lease, pass through unchanged so the base resolver keeps their admission.

  /** @param {Parameters<ContentKeyResolver["resolveAuthenticated"]>} args */
  resolveAuthenticated(...args) {
    return this.#resolver.resolveAuthenticated(...args);
  }

  /** @param {Parameters<ContentKeyResolver["contentKeyForAuthenticatedItem"]>} args */
  contentKeyForAuthenticatedItem(...args) {
    return this.#resolver.contentKeyForAuthenticatedItem(...args);
  }
}

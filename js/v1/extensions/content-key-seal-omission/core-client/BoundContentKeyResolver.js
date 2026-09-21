// @ts-check
//
// Compatibility adapter for the omission client's selected entry reading.
// Candidate ordering, response application, detailed origins, and the single
// wrap attempt all remain base-owned in `ContentKeyResolver`.

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { dcaError } from "../../../core-shared/errors.js";
import { omissionEntryInterpretation } from "./omissionEntryInterpretation.js";

const OPTIONS = [
  "cache",
  "chainCache",
  "periodChainProfile",
  "clientBoundKeyCapability",
  "acceptDirectFallback",
  "persistRawPeriodKeys",
];

/**
 * Factory form for Browser's resolver composition seam.
 *
 * @param {object} [options]
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
  return new ContentKeyResolver({ ...options, entryInterpretation: omissionEntryInterpretation });
}

export class BoundContentKeyResolver {
  /** @type {ContentKeyResolver} */
  #resolver;

  /** @param {object} [config] */
  constructor(config = {}) {
    this.#resolver = omissionContentKeyResolverFactory(config);
  }

  applyResponse(...args) {
    return this.#resolver.applyResponse(...args);
  }

  resolveDetailed(...args) {
    return this.#resolver.resolveDetailed(...args);
  }

  contentKeyWithOriginFor(...args) {
    return this.#resolver.contentKeyWithOriginFor(...args);
  }

  resolve(...args) {
    return this.#resolver.resolve(...args);
  }

  contentKeyFor(...args) {
    return this.#resolver.contentKeyFor(...args);
  }
}

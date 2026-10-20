// @ts-check
//
// The accessGroup-only row changes the value the shared sealed-section fixture
// commits to, and nothing in its hostile-carrier walk. Content names resolve
// through the issuer's own table; period entries are already keyed by group.
// This deliberately omits renderId, key kind and t, so the shared relabel
// suite can spend each missing dimension.

import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { sealedSectionWith } from "../../../test-lib/harnesses/sealedSection.js";
import * as boundSealing from "./keySealing.js";

/**
 * @param {any} accessGroupOf
 * @param {string} contentName
 * @returns {string}
 */
function tierOf(accessGroupOf, contentName) {
  const accessGroup = own(accessGroupOf, contentName);
  if (typeof accessGroup !== "string" || accessGroup.length === 0) {
    throw dcaError("bad_config", `no accessGroup is recorded for content "${contentName}"`);
  }
  return accessGroup;
}

/** @param {any} value @param {string} coordinate */
function wireBlobOf(value, coordinate) {
  if (typeof value !== "string") {
    throw dcaError("binding_failed", `the sealed value at ${coordinate} is not a wire string`);
  }
  return value;
}

const section = sealedSectionWith({
  defaultKeySealing: boundSealing,
  blobOf: wireBlobOf,
  boundDescription: "access tier it was presented under",
  binding: {
    sealContent: ({ config, contentName }) => ({
      accessGroup: tierOf(config.accessGroupOf, contentName),
    }),
    sealPeriod: ({ accessGroup }) => ({ accessGroup }),
    openContent: ({ config, contentName }) => ({
      accessGroup: tierOf(config.accessGroupOf, contentName),
    }),
    openPeriod: ({ accessGroup }) => ({ accessGroup }),
  },
});

export const { sealSection, unsealSection } = section;

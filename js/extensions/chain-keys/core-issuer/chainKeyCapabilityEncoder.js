// @ts-check

// This module projects one typed chain capability. The source carries the
// resolved geometry it authenticated and used. The encoder preserves that pair
// as internal composition metadata; the wire response uses its associated
// request context. The chain-key width comes
// from the construction profile the route was composed on, so an encoder is
// made for one profile and then checks the entries it is handed against that
// profile.

import { base64urlDecode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import { MAX_CHAIN_MEMBERS_PER_FAMILY } from "../../../core-shared/geometryBounds.js";
import {
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
  chainKeyCoordinate,
  settleChainGeometry,
  validateChainKeyAccessGroup,
} from "../core-shared/chainKeyConstruction.js";

/**
 * Makes an encoder for one named construction profile. This call refuses an
 * unknown name at composition, before any response reaches the encoder.
 *
 * @param {string} [construction] - absent is `dca-construction-chain-keys`
 * @returns {(record: any) => object}
 */
export function chainKeyCapabilityEncoderFor(construction = CHAIN_KEY_CONSTRUCTION) {
  const { chainKeyBytes } = chainKeyConstructionProfile(construction);
  return (record) => encodeChainCapability(record, chainKeyBytes);
}

/**
 * @param {any} record
 * @param {number} chainKeyBytes - the chain-key width of the selected profile
 */
function encodeChainCapability(record, chainKeyBytes) {
  if (
    record === null ||
    typeof record !== "object" ||
    record.kind !== "chain-keys" ||
    typeof record.accessGroup !== "string" ||
    record.entries === null ||
    typeof record.entries !== "object" ||
    Array.isArray(record.entries)
  ) {
    throw dcaError(
      "bad_config",
      "a frozen chain capability has kind, accessGroup, and encoded entries",
    );
  }
  validateChainKeyAccessGroup(record.accessGroup);
  const geometry = settleChainGeometry(record.interpretation?.geometry ?? {});
  const selections = record.interpretation?.selections;
  if (
    !Array.isArray(selections) ||
    selections.length === 0 ||
    selections.length > MAX_CHAIN_MEMBERS_PER_FAMILY
  ) {
    throw dcaError(
      "bad_config",
      "a frozen chain capability carries its bounded resolved selections",
    );
  }

  const cutoffs = new Set();
  const windows = new Set();
  for (const selection of selections) {
    if (
      selection === null ||
      typeof selection !== "object" ||
      typeof selection.suppliedT !== "string" ||
      typeof selection.cutoffT !== "string"
    ) {
      throw dcaError(
        "bad_config",
        "a frozen chain selection names its supplied and cutoff coordinates",
      );
    }
    const supplied = chainKeyCoordinate(selection.suppliedT, geometry);
    const cutoff = chainKeyCoordinate(selection.cutoffT, geometry);
    if (
      supplied.windowStart !== cutoff.windowStart ||
      supplied.position < cutoff.position ||
      windows.has(cutoff.windowStart) ||
      cutoffs.has(selection.cutoffT)
    ) {
      throw dcaError("bad_config", "a frozen chain selection is one backward cutoff per window");
    }
    windows.add(cutoff.windowStart);
    cutoffs.add(selection.cutoffT);
  }

  const names = Object.keys(record.entries);
  if (
    names.length === 0 ||
    names.length > MAX_CHAIN_MEMBERS_PER_FAMILY ||
    names.some((cutoffT) => !cutoffs.has(cutoffT))
  ) {
    throw dcaError("bad_config", "a frozen chain response contains only selected cutoff entries");
  }
  for (const cutoffT of names) {
    if (typeof record.entries[cutoffT] !== "string") {
      throw dcaError("bad_config", "a frozen chain response entry is base64url key material");
    }
    let bytes;
    try {
      bytes = base64urlDecode(record.entries[cutoffT]);
    } catch {
      throw dcaError("bad_config", "a frozen chain response entry is base64url key material");
    }
    if (bytes.length !== chainKeyBytes) {
      throw dcaError(
        "bad_config",
        `a chain response entry of this profile is ${chainKeyBytes} key bytes`,
      );
    }
  }

  return {
    section: "chainKeys",
    accessGroup: record.accessGroup,
    entries: record.entries,
    periodGeometry: {
      chainsPerDay: geometry.chainsPerDay,
      periodMinutes: geometry.periodMinutes,
    },
  };
}

/**
 * The encoder for the profile a route uses when it names none. It stays a plain
 * function for every caller that installs it directly.
 */
export const chainKeyCapabilityEncoder = chainKeyCapabilityEncoderFor(CHAIN_KEY_CONSTRUCTION);

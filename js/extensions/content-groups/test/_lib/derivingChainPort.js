// Stock generation with optional seed-reference observation for lifecycle assertions.
import { periodFamilyGeneration as familyGeneration } from "../../../chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { CHAIN } from "./chainPort.js";

export const DERIVING_CHAIN = Object.freeze({ ...CHAIN, familyGeneration });

/**
 * The deriving port, recording every seed it is handed. A seed handle passes
 * its kept copy to `familyGeneration` itself, so a test sees that copy's bytes
 * after the handle is disposed without a production getter.
 */
export function recordingChain() {
  /** @type {Uint8Array[]} */
  const secrets = [];
  const chain = Object.freeze({
    ...DERIVING_CHAIN,
    /** @param {{ keyDerivationSecret: Uint8Array, geometry: any }} input */
    familyGeneration(input) {
      secrets.push(input.keyDerivationSecret);
      return familyGeneration(input);
    },
  });
  return { chain, secrets };
}

/** Whether every recorded seed copy is all zeros, and there was at least one. */
export function allZeroed(/** @type {Uint8Array[]} */ secrets) {
  return secrets.length > 0 && secrets.every((secret) => secret.every((byte) => byte === 0));
}

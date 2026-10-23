// @ts-check
//
// The two sides of a named issuerData record's sealed material: sealing one
// render's key material for one issuer, and the issuer opening the coordinates
// it granted. This diagnostic harness uses slot-indexed local tables
// (`contentKeys[contentName]` and `periodKeys[accessGroup][t]`); they are not
// serialized delivery collections. A relabel moves one local member.
//
// This harness walks the issuer side itself instead of calling into
// `core-issuer/IssuerEngine`. It varies two answers the engine settled the other
// way, and each one is an attack surface worth being able to run.
//
// This harness runs the soundness condition as code. The binding holds because
// the slot in the value and the slot the access decision was made on are the
// same string from the same place: the request member name. There is no second
// label for an attacker to move independently. The engine has no seam here and
// none belongs there; `slotFrom` makes that condition switchable: `key` stands
// for the sound issuer, `wrapper` for the implementer who read the slot off a
// field beside the blob, and the second one hands over keys it denied. The
// wrapper shape stands for any request field an issuer might reach for instead
// of the name it decided on, and no wire carries it.
//
// The harness refuses the whole request when an unseal fails. The engine answers
// a blob that did not open with an error record beside a 200, which is what a
// benign key rollover is owed: the rest of the request is opened and the reader
// loses one item. A relabel arrives as the same failure, so that answer also
// tells an attacker which coordinate they got wrong, one blob at a time.
// Refusing the whole request is the other side of that trade: treat any binding
// failure as suspected tampering, and answer nothing. It costs the rollover its
// partial answer. Both are defensible and the engine picked one, so the other is
// run here.
//
// Everything else is the engine's: verified renderId in, own-property lookups
// throughout, the decision applied before any blob is opened.

import { base64urlEncode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";
import { own } from "../../core-shared/wire.js";
import * as boundSealing from "../../core-shared--publisher-issuer/keySealing.js";

/**
 * Core's module as this harness's KeySealing: core exports the opening side as
 * `open`, and this interface names it `unseal`, so the default binds one to the
 * other. A variant may inject another pair through the same seam.
 */
const coreSealing = { seal: boundSealing.seal, unseal: boundSealing.open };

/**
 * The seal/unseal pair to run through. Core's by default; variant tests may
 * pass another pair to run the same walk over a different construction.
 *
 * @typedef {object} KeySealing
 * @property {(keyBytes: Uint8Array, publicKey: CryptoKey, algorithm: string, options: any) => Promise<string>} [seal]
 * @property {(blob: string, privateKey: CryptoKey, algorithm: string, options: any) => Promise<Uint8Array>} [unseal]
 */

/**
 * The per-algorithm options both modules take. `ephemeralKeyPair` is ECDH only
 * and both refuse it for RSA-OAEP rather than ignore it.
 *
 * @param {string} algorithm
 * @param {any} options
 * @returns {any}
 */
function forAlgorithm(algorithm, options) {
  if (algorithm !== "rsa-oaep") return options;

  const { ephemeralKeyPair, ...rest } = options;
  return rest;
}

/**
 * The blob out of whatever the request carried at a coordinate. A string is the
 * wire; an object is the wrapper the unsound issuer below reads its slot from,
 * and its blob is opened either way, so the two configurations differ in one
 * thing only: where the slot came from.
 *
 * @param {any} value
 * @returns {string}
 */
function blobOf(value) {
  const blob = typeof value === "string" ? value : own(value, "blob");
  if (typeof blob !== "string") {
    throw dcaError("binding_failed", "the sealed value at this coordinate is not a wire string");
  }
  return blob;
}

/**
 * The one difference an alternate binding needs to supply. The section walk,
 * algorithm handling and refusal surface stay in this test harness; only the
 * value each carrier commits to is variable. This is deliberately test-only:
 * production core keeps its fixed BIND grammar.
 *
 * @typedef {object} SectionBinding
 * @property {(context: { config: any, contentName: string }) => any} sealContent
 * @property {(context: { config: any, accessGroup: string, t: string }) => any} sealPeriod
 * @property {(context: { config: any, contentName: string, value: any }) => any} openContent
 * @property {(context: { config: any, accessGroup: string, t: string, value: any }) => any} openPeriod
 */

const renderCoordinateBinding = {
  sealContent: ({ config, contentName }) => ({ renderId: config.renderId, contentName }),
  sealPeriod: ({ config, accessGroup, t }) => ({ renderId: config.renderId, accessGroup, t }),
  openContent: ({ config, contentName, value }) => ({
    renderId: config.renderId,
    contentName: config.slotFrom === "wrapper" ? own(value, "contentName") : contentName,
  }),
  openPeriod: ({ config, accessGroup, t, value }) => ({
    renderId: config.renderId,
    ...(config.slotFrom === "wrapper"
      ? { accessGroup: own(value, "accessGroup"), t: own(value, "t") }
      : { accessGroup, t }),
  }),
};

/**
 * @param {any} config
 */
function checkCoreUnsealOptions(config) {
  const slotFrom = config.slotFrom ?? "key";
  if (slotFrom !== "key" && slotFrom !== "wrapper") {
    throw dcaError(
      "bad_config",
      `a slot comes from the request key or from a wrapper field, not "${slotFrom}"`,
    );
  }
}

/**
 * Build a sealed-section fixture over one binding construction. This permits a
 * comparison row to alter the binding without copying the hostile-carrier walk.
 *
 * @param {object} options
 * @param {SectionBinding} options.binding
 * @param {KeySealing} [options.defaultKeySealing]
 * @param {(value: any, coordinate: string) => string} [options.blobOf]
 * @param {(config: any) => void} [options.checkUnsealOptions]
 * @param {string} [options.boundDescription] - text after "bound to the" in a refusal
 */
export function sealedSectionWith({
  binding,
  defaultKeySealing = coreSealing,
  blobOf: sectionBlobOf = blobOf,
  checkUnsealOptions = () => {},
  boundDescription = "coordinate it was presented at",
}) {
  for (const name of ["sealContent", "sealPeriod", "openContent", "openPeriod"]) {
    if (typeof binding?.[name] !== "function")
      throw new TypeError(`sealedSectionWith needs binding.${name}()`);
  }

  /** @param {any} config */
  const sealSection = async (config) => {
    const {
      contentKeys = {},
      periodKeys = {},
      publicKey,
      algorithm,
      random,
      ephemeralKeyPairs,
      keySealing = defaultKeySealing,
    } = config;
    const seal = keySealing.seal;
    if (typeof seal !== "function") {
      throw dcaError(
        "bad_config",
        "a keySealing is a module with a seal(keyBytes, publicKey, algorithm, options)",
      );
    }

    /** @type {Record<string, string>} */
    const sealedContentKeys = {};
    for (const [contentName, keyBytes] of Object.entries(contentKeys)) {
      sealedContentKeys[contentName] = await seal(
        keyBytes,
        publicKey,
        algorithm,
        forAlgorithm(algorithm, {
          random,
          ephemeralKeyPair: ephemeralKeyPairs?.({ contentName }),
          binding: binding.sealContent({ config, contentName }),
        }),
      );
    }

    /** @type {Record<string, Record<string, string>>} */
    const sealedPeriodKeys = {};
    for (const [accessGroup, byPeriod] of Object.entries(periodKeys)) {
      /** @type {Record<string, string>} */
      const periods = {};
      for (const [t, keyBytes] of Object.entries(byPeriod)) {
        periods[t] = await seal(
          keyBytes,
          publicKey,
          algorithm,
          forAlgorithm(algorithm, {
            random,
            ephemeralKeyPair: ephemeralKeyPairs?.({ accessGroup, t }),
            binding: binding.sealPeriod({ config, accessGroup, t }),
          }),
        );
      }
      sealedPeriodKeys[accessGroup] = periods;
    }
    return { contentKeys: sealedContentKeys, periodKeys: sealedPeriodKeys };
  };

  /** @param {any} config */
  const unsealSection = async (config) => {
    const { sealed, privateKey, algorithm, granted, keySealing = defaultKeySealing } = config;
    const unseal = keySealing.unseal;
    if (typeof unseal !== "function") {
      throw dcaError(
        "bad_config",
        "a keySealing is a module with an unseal(blob, privateKey, algorithm, options)",
      );
    }
    checkUnsealOptions(config);

    const presentedContent = own(sealed, "contentKeys") ?? {};
    const presentedPeriods = own(sealed, "periodKeys") ?? {};
    const contentNames =
      granted?.contentNames ??
      (typeof presentedContent === "object" ? Object.keys(presentedContent) : []);
    const accessGroups =
      granted?.accessGroups ??
      (typeof presentedPeriods === "object" ? Object.keys(presentedPeriods) : []);

    const open = async (value, coordinate, bound) => {
      const blob = sectionBlobOf(value, coordinate);
      try {
        return base64urlEncode(
          await unseal(
            blob,
            privateKey,
            algorithm,
            forAlgorithm(algorithm, {
              binding: bound,
            }),
          ),
        );
      } catch (cause) {
        throw dcaError(
          "binding_failed",
          `sealed.${coordinate} did not open bound to the ${boundDescription}: ` +
            (cause instanceof Error ? cause.message : "unseal failed"),
        );
      }
    };

    /** @type {Record<string, string>} */
    const contentKeys = {};
    for (const contentName of contentNames) {
      const value = own(presentedContent, contentName);
      if (value === undefined) continue;
      contentKeys[contentName] = await open(
        value,
        `contentKeys.${contentName}`,
        binding.openContent({ config, contentName, value }),
      );
    }

    /** @type {Record<string, Record<string, string>>} */
    const periodKeys = {};
    for (const accessGroup of accessGroups) {
      const byPeriod = own(presentedPeriods, accessGroup);
      if (byPeriod === null || typeof byPeriod !== "object") continue;
      /** @type {Record<string, string>} */
      const opened = {};
      for (const t of Object.keys(byPeriod)) {
        const value = byPeriod[t];
        opened[t] = await open(
          value,
          `periodKeys.${accessGroup}.${t}`,
          binding.openPeriod({ config, accessGroup, t, value }),
        );
      }
      if (Object.keys(opened).length > 0) periodKeys[accessGroup] = opened;
    }
    return { contentKeys, periodKeys };
  };

  return { sealSection, unsealSection };
}

const coreSection = sealedSectionWith({
  binding: renderCoordinateBinding,
  checkUnsealOptions: checkCoreUnsealOptions,
});

export const { sealSection, unsealSection } = coreSection;

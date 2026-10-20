// @ts-check
//
// The chain-key construction profiles shared by their publisher and issuer
// compositions. Base period keys remain opaque and do not import this module.
//
// The construction `dca-construction-chain-keys` derives 16-byte chain keys and 16-byte
// period keys. The spec writes the chain key at position i as `C[i]`; a chain
// key here is always one such positioned key. The construction identifier sits
// inside every ROOT, STEP and LEAF context; it is not a wire-selectable width
// profile.

import { utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import {
  inspectPeriodGeometryBounds,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_POSITIONS_PER_WINDOW,
  PERIOD_GEOMETRY_MINUTES_PER_DAY,
} from "../../../core-shared/geometryBounds.js";

const { subtle } = globalThis.crypto;

/**
 * The optional chain-key profile's identifier, the sibling of
 * `PERIOD_KEY_PROFILE`. Callers that mean the profile, for example in a
 * catalogue or a list of requested profiles, use this constant.
 */
export const CHAIN_KEY_PROFILE = "dca-profile-chain-keys";

/**
 * The name that selects the chain-key construction in this module's registry.
 * Callers pass it to `chainKeyConstructionProfile` and `chainKeyDerivations`;
 * it is not a wire member.
 */
export const CHAIN_KEY_CONSTRUCTION = "dca-construction-chain-keys";

/**
 * The `constructionId` octets inside every Root, Step and Leaf context.
 *
 * `CHAIN_KEY_PROFILE` names the optional profile. `CHAIN_KEY_CONSTRUCTION`
 * selects the construction in the registry, and this value enters every
 * derivation. Only this value reaches derived bytes: changing it makes a new
 * construction with new derived bytes, while renaming the profile or the
 * selector leaves derived bytes alone.
 */
export const CHAIN_KEY_CONSTRUCTION_ID = "dca-construction-chain-keys";

/** Retained extension exports for callers that consume the profile bounds. */
export { MAX_CHAIN_MEMBERS_PER_FAMILY, MAX_CHAIN_MEMBERS_PER_MESSAGE, MAX_POSITIONS_PER_WINDOW };
export const MAX_RIVAL_CHAIN_CANDIDATES = 4;
export const MAX_RIVAL_PERIOD_KEY_CANDIDATES = 4;

const MS_PER_MINUTE = 60_000;
const KEY_DERIVATION_SECRET_BYTES = 32;

/**
 * One `dca-construction-chain-keys` chain key is exactly this wide. The construction
 * fixes the width, and it is exported so a caller holding opened material can
 * check it before deriving from it.
 */
export const CHAIN_KEY_BYTES = 16;
const LABEL_LENGTH = 11;
const LABEL = /^(\d{2})(\d{2})(\d{2})T(\d{2})(\d{2})$/;
const ROOT = 0x01;
const STEP = 0x02;
const LEAF = 0x03;
const EMPTY_SALT = new Uint8Array(0);
const GEOMETRY_OPTIONS = ["chainsPerDay", "periodMinutes"];
const SETTLED_GEOMETRIES = new WeakSet();
const ACCESS_GROUP = /^[a-zA-Z][a-zA-Z0-9_:-]*$/;
const MAX_ACCESS_GROUP_LENGTH = 64;

/** @param {unknown} value */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @typedef {object} ChainGeometry
 * @property {number} chainsPerDay
 * @property {number} periodMinutes
 * @property {number} windowMinutes
 * @property {number} positionsPerWindow
 */

/**
 * @typedef {object} ChainCoordinate
 * @property {string} t
 * @property {number} windowStart
 * @property {number} position
 * @property {string} startT
 * @property {string} terminalT
 */

/** @param {number} value */
function pad(value) {
  return String(value).padStart(2, "0");
}

/** The profile's fixed eleven-character spelling for an epoch minute. @param {number} minutes */
export function chainKeyLabelAt(minutes) {
  if (!Number.isSafeInteger(minutes)) {
    throw dcaError("bad_config", "a chain-key label needs a whole epoch minute");
  }
  const date = new Date(minutes * MS_PER_MINUTE);
  if (
    !Number.isFinite(date.getTime()) ||
    date.getUTCFullYear() < 2000 ||
    date.getUTCFullYear() > 2099
  ) {
    throw dcaError("bad_config", "a chain-key label is inside the profile years 2000 through 2099");
  }
  return (
    `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}`
  );
}

/** The access-group wire grammar the construction binds into its contexts. @param {unknown} value */
export function validateChainKeyAccessGroup(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ACCESS_GROUP_LENGTH ||
    !ACCESS_GROUP.test(value)
  ) {
    throw dcaError(
      "bad_name",
      "a chain-key accessGroup follows the base 64-character name grammar",
    );
  }
  return value;
}

/**
 * Validate and snapshot the complete wire geometry pair. There is no default.
 *
 * @param {unknown} geometry
 * @returns {ChainGeometry}
 */
export function settleChainGeometry(geometry) {
  if (geometry === null || typeof geometry !== "object" || Array.isArray(geometry)) {
    throw dcaError(
      "bad_config",
      "a period-family generation needs its complete { chainsPerDay, periodMinutes }",
    );
  }
  for (const name of Object.keys(geometry)) {
    if (!GEOMETRY_OPTIONS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `chain geometry is the complete pair { chainsPerDay, periodMinutes } and has no ${name}`,
      );
    }
  }

  const { chainsPerDay, periodMinutes } = /** @type {any} */ (geometry);
  const bounds = inspectPeriodGeometryBounds(chainsPerDay, periodMinutes);
  if (bounds.kind === "invalidChainsPerDay") {
    throw dcaError(
      "bad_config",
      `chainsPerDay is a positive divisor of ${PERIOD_GEOMETRY_MINUTES_PER_DAY}, got ${String(chainsPerDay)}`,
    );
  }
  if (bounds.kind === "invalidPeriodMinutes") {
    throw dcaError(
      "bad_config",
      `periodMinutes is a positive divisor of ${bounds.windowMinutes}, got ${String(periodMinutes)}`,
    );
  }
  if (bounds.kind === "tooManyPositions") {
    throw dcaError(
      "bad_config",
      `a chain window holds at most ${MAX_POSITIONS_PER_WINDOW} positions, this geometry asks for ${bounds.positionsPerWindow}`,
    );
  }
  const { windowMinutes, positionsPerWindow } = bounds;
  const settled = Object.freeze({ chainsPerDay, periodMinutes, windowMinutes, positionsPerWindow });
  SETTLED_GEOMETRIES.add(settled);
  return settled;
}

/** Whether the root value cannot supply a complete valid chain pair.
 * @param {unknown} context
 * @returns {boolean}
 */
export function invalidChainGeometry(context) {
  try {
    settleChainGeometry(context);
    return false;
  } catch {
    return true;
  }
}

/** Resolve the one complete root chain pair for a named family.
 * An invalid, absent, partial or legacy overridden pair resolves no chain.
 * @param {unknown} context
 * @param {string} accessGroup
 * @returns {ChainGeometry|null}
 */
export function resolveChainGeometry(context, accessGroup) {
  validateChainKeyAccessGroup(accessGroup);
  if (!record(context)) return null;
  try {
    return settleChainGeometry(context);
  } catch {
    return null;
  }
}

/** @param {ChainGeometry} geometry */
function settledGeometry(geometry) {
  if (geometry !== null && typeof geometry === "object" && SETTLED_GEOMETRIES.has(geometry))
    return geometry;
  return settleChainGeometry(geometry);
}

/**
 * Map one fixed profile label onto its explicit geometry.
 *
 * @param {unknown} t
 * @param {ChainGeometry} geometry
 * @returns {ChainCoordinate}
 */
export function chainKeyCoordinate(t, geometry) {
  const settled = settledGeometry(geometry);
  if (typeof t !== "string") {
    throw dcaError(
      "bad_config",
      `a chain-key coordinate is ${LABEL_LENGTH} characters of YYMMDDTHHMM, got type ${typeof t}`,
    );
  }
  if (t.length !== LABEL_LENGTH) {
    throw dcaError(
      "bad_config",
      `a chain-key coordinate is ${LABEL_LENGTH} characters of YYMMDDTHHMM, got ${JSON.stringify(t)}`,
    );
  }
  const parts = LABEL.exec(t);
  if (!parts)
    throw dcaError("bad_config", `chain-key coordinate ${JSON.stringify(t)} is not YYMMDDTHHMM`);

  const year = 2000 + Number(parts[1]);
  const month = Number(parts[2]);
  const day = Number(parts[3]);
  const hour = Number(parts[4]);
  const minute = Number(parts[5]);
  const at = Date.UTC(year, month - 1, day, hour, minute);
  const date = new Date(at);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute
  ) {
    throw dcaError(
      "bad_config",
      `chain-key coordinate ${JSON.stringify(t)} is not a UTC calendar minute`,
    );
  }
  const minutes = at / MS_PER_MINUTE;
  if (minutes % settled.periodMinutes !== 0) {
    throw dcaError(
      "bad_config",
      `chain-key coordinate ${JSON.stringify(t)} is off the ${settled.periodMinutes}-minute family grid`,
    );
  }
  const windowStart = minutes - (minutes % settled.windowMinutes);
  return Object.freeze({
    t,
    windowStart,
    position: (minutes - windowStart) / settled.periodMinutes,
    startT: chainKeyLabelAt(windowStart),
    terminalT: chainKeyLabelAt(
      windowStart + (settled.positionsPerWindow - 1) * settled.periodMinutes,
    ),
  });
}

/**
 * The context bytes one derivation runs over. The construction identifier is
 * the one the selected profile fixes, so a profile cannot derive under another
 * profile's transcript.
 *
 * @param {ConstructionProfile} profile
 * @param {number} domain
 * @param {string} accessGroup
 * @param {ChainGeometry} geometry
 * @param {number} windowStart
 * @param {number} position
 */
function context(profile, domain, accessGroup, geometry, windowStart, position) {
  const construction = utf8Encode(profile.constructionId);
  const group = utf8Encode(accessGroup);
  const bytes = new Uint8Array(1 + 2 + construction.length + 2 + group.length + 2 + 2 + 4 + 2);
  const view = new DataView(bytes.buffer);
  let at = 0;
  bytes[at] = domain;
  at += 1;
  view.setUint16(at, construction.length);
  at += 2;
  bytes.set(construction, at);
  at += construction.length;
  view.setUint16(at, group.length);
  at += 2;
  bytes.set(group, at);
  at += group.length;
  view.setUint16(at, geometry.chainsPerDay);
  at += 2;
  view.setUint16(at, geometry.periodMinutes);
  at += 2;
  view.setUint32(at, windowStart);
  at += 4;
  view.setUint16(at, position);
  return bytes;
}

/**
 * @param {ConstructionProfile} profile
 * @param {Uint8Array} ikm
 * @param {Uint8Array} info
 * @param {number} bytes - the HKDF output width
 */
async function hkdf(profile, ikm, info, bytes) {
  try {
    const material = await subtle.importKey("raw", Uint8Array.from(ikm), "HKDF", false, [
      "deriveBits",
    ]);
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: EMPTY_SALT, info: Uint8Array.from(info) },
      material,
      bytes * 8,
    );
    return new Uint8Array(bits);
  } catch (cause) {
    const error = dcaError("bad_key", `the ${profile.constructionId} derivation failed`);
    error.cause = cause;
    throw error;
  }
}

/** @param {Uint8Array} chainKey @param {number} width - the caller's own chain-key width */
function suppliedChainKey(chainKey, width) {
  if (!(chainKey instanceof Uint8Array) || chainKey.length !== width) {
    throw dcaError("bad_config", `a supplied chain key has exactly ${width} bytes`);
  }
  return Uint8Array.from(chainKey);
}

/**
 * The derivations and chain-key admission of one construction profile, closed
 * over that profile.
 *
 * The profile fixes its construction identifier, chain-key width and the
 * period-key width of the period-key profile it names. The context layout,
 * domain separation, coordinate rules and 32-byte key-derivation secret are part
 * of that selected construction. The closure passes its fixed chain-key width to
 * `suppliedChainKey`, so every other width is refused rather than padded,
 * truncated or retried.
 *
 * @param {ConstructionProfile} profile
 */
function derivations(profile) {
  const width = profile.chainKeyBytes;
  const periodKeyWidth = 16;
  /** @type {(domain: number, accessGroup: string, geometry: ChainGeometry, windowStart: number, position: number) => Uint8Array} */
  const at = (domain, accessGroup, geometry, windowStart, position) =>
    context(profile, domain, accessGroup, geometry, windowStart, position);
  /**
   * Derive the root chain key at the window terminal from one independently
   * provisioned key-derivation secret.
   *
   * @param {{ keyDerivationSecret: Uint8Array, accessGroup: string, terminalT: string, geometry: ChainGeometry }} input
   */
  async function rootChainKey(input) {
    if (input !== null && typeof input === "object" && Object.hasOwn(input, "secret")) {
      throw dcaError(
        "unsupported_option",
        "the retained publisher input is keyDerivationSecret, not secret",
      );
    }
    const { keyDerivationSecret, accessGroup, terminalT, geometry } = input;
    if (
      !(keyDerivationSecret instanceof Uint8Array) ||
      keyDerivationSecret.length !== KEY_DERIVATION_SECRET_BYTES
    ) {
      throw dcaError(
        "bad_config",
        `a period-family generation holds exactly ${KEY_DERIVATION_SECRET_BYTES} key-derivation-secret bytes`,
      );
    }
    const settled = settledGeometry(geometry);
    const group = validateChainKeyAccessGroup(accessGroup);
    const coordinate = chainKeyCoordinate(terminalT, settled);
    if (coordinate.position !== settled.positionsPerWindow - 1) {
      throw dcaError("bad_config", "a root chain key is derived at its window terminal");
    }
    return hkdf(
      profile,
      Uint8Array.from(keyDerivationSecret),
      at(ROOT, group, settled, coordinate.windowStart, coordinate.position),
      width,
    );
  }

  /**
   * Move one supplied chain key backward to an explicit target coordinate.
   * Callers that accept a supplied chain key should prefer the bounded expansion
   * below.
   *
   * @param {{ chainKey: Uint8Array, accessGroup: string, suppliedT: string, targetT: string,
   *   geometry: ChainGeometry }} input
   */
  async function chainKeyFromChainKey({ chainKey, accessGroup, suppliedT, targetT, geometry }) {
    const settled = settledGeometry(geometry);
    const group = validateChainKeyAccessGroup(accessGroup);
    let current = suppliedChainKey(chainKey, width);
    const supplied = chainKeyCoordinate(suppliedT, settled);
    const target = chainKeyCoordinate(targetT, settled);
    if (supplied.windowStart !== target.windowStart || target.position > supplied.position) {
      throw dcaError(
        "bad_config",
        "a supplied chain key reaches only its own window through its cutoff",
      );
    }
    for (let position = supplied.position - 1; position >= target.position; position--) {
      current = await hkdf(
        profile,
        current,
        at(STEP, group, settled, target.windowStart, position),
        width,
      );
    }
    return current;
  }

  /** @param {{ chainKey: Uint8Array, accessGroup: string, t: string, geometry: ChainGeometry }} input */
  async function periodKeyFromChainKey({ chainKey, accessGroup, t, geometry }) {
    const settled = settledGeometry(geometry);
    const group = validateChainKeyAccessGroup(accessGroup);
    const coordinate = chainKeyCoordinate(t, settled);
    return hkdf(
      profile,
      suppliedChainKey(chainKey, width),
      at(LEAF, group, settled, coordinate.windowStart, coordinate.position),
      periodKeyWidth,
    );
  }

  /**
   * Project one supplied chain key over the contiguous start-through-cutoff
   * range in its own window. It walks backward once and returns copied period-key
   * bytes.
   *
   * @param {{ chainKey: Uint8Array, accessGroup: string, suppliedT: string, cutoffT: string,
   *   geometry: ChainGeometry }} input
   * @returns {Promise<ReadonlyArray<{ t: string, position: number, key: Uint8Array }>>}
   */
  async function periodKeysFromChainKey({ chainKey, accessGroup, suppliedT, cutoffT, geometry }) {
    const settled = settledGeometry(geometry);
    const group = validateChainKeyAccessGroup(accessGroup);
    const supplied = chainKeyCoordinate(suppliedT, settled);
    const cutoff = chainKeyCoordinate(cutoffT, settled);
    if (supplied.windowStart !== cutoff.windowStart || cutoff.position > supplied.position) {
      throw dcaError(
        "bad_config",
        "a supplied chain key reaches only its own window through its cutoff",
      );
    }
    let current = suppliedChainKey(chainKey, width);
    const periodKeys = [];
    for (let position = supplied.position; position >= 0; position--) {
      if (position < supplied.position) {
        current = await hkdf(
          profile,
          current,
          at(STEP, group, settled, supplied.windowStart, position),
          width,
        );
      }
      if (position <= cutoff.position) {
        const t = chainKeyLabelAt(supplied.windowStart + position * settled.periodMinutes);
        const key = await hkdf(
          profile,
          current,
          at(LEAF, group, settled, supplied.windowStart, position),
          periodKeyWidth,
        );
        periodKeys.push(Object.freeze({ t, position, key: Uint8Array.from(key) }));
      }
    }
    return Object.freeze(periodKeys.reverse());
  }

  return { rootChainKey, chainKeyFromChainKey, periodKeyFromChainKey, periodKeysFromChainKey };
}

/**
 * One selectable construction profile.
 *
 * @typedef {object} ConstructionProfile
 * @property {string} name - the profile identifier the profile is selected by.
 *   It is not a wire member.
 * @property {string} constructionId - the identifier inside every context
 * @property {number} chainKeyBytes - one positioned chain key's width
 */

/**
 * One profile and the derivations closed over it, built once at load.
 *
 * @param {string} name
 * @param {string} constructionId
 * @param {number} chainKeyBytes
 */
function registered(name, constructionId, chainKeyBytes) {
  const profile = Object.freeze({
    name,
    constructionId,
    chainKeyBytes,
  });
  return { profile, derivations: derivations(profile) };
}

/** @type {Record<string, ReturnType<typeof registered>>} */
const CONSTRUCTION_PROFILES = {
  [CHAIN_KEY_CONSTRUCTION]: registered(
    CHAIN_KEY_CONSTRUCTION,
    CHAIN_KEY_CONSTRUCTION_ID,
    CHAIN_KEY_BYTES,
  ),
};

/** @param {string} name */
function selected(name) {
  if (typeof name !== "string" || !Object.hasOwn(CONSTRUCTION_PROFILES, name)) {
    throw dcaError(
      "unsupported_option",
      `there is no chain-key construction profile ${JSON.stringify(name)}; the profiles are ` +
        `${Object.keys(CONSTRUCTION_PROFILES).join(" and ")}`,
    );
  }
  return CONSTRUCTION_PROFILES[name];
}

/**
 * The named construction profile and its widths. An unknown name is refused, so
 * a deployment that misspells its profile fails closed at selection rather than
 * deriving under whichever profile happened to be the default.
 *
 * @param {string} name
 * @returns {ConstructionProfile}
 */
export function chainKeyConstructionProfile(name) {
  return selected(name).profile;
}

/**
 * The four derivations of the named profile: `rootChainKey`, `chainKeyFromChainKey`,
 * `periodKeyFromChainKey` and `periodKeysFromChainKey`. Naming the profile is all a caller
 * does to select a width, and the closures it gets back carry that width.
 *
 * @param {string} name
 */
export function chainKeyDerivations(name) {
  return selected(name).derivations;
}

const current = chainKeyDerivations(CHAIN_KEY_CONSTRUCTION);

export const rootChainKey = current.rootChainKey;
export const chainKeyFromChainKey = current.chainKeyFromChainKey;
export const periodKeyFromChainKey = current.periodKeyFromChainKey;
export const periodKeysFromChainKey = current.periodKeysFromChainKey;

// The five operations below are the direct canonical primitive surface. Their
// input objects deliberately carry the complete coordinates a neutral bridge
// can receive: no bridge has to assemble a label, terminal position, or
// supplied/target pair around a more general projection primitive.

/** @param {number} windowStart @param {ChainGeometry} geometry @param {number} position */
function primitiveLabel(windowStart, geometry, position) {
  if (!Number.isSafeInteger(windowStart) || windowStart < 0 || windowStart > 0xffff_ffff) {
    throw dcaError("bad_config", "a chain-key primitive windowStart is an unsigned 32-bit minute");
  }
  if (!Number.isSafeInteger(position) || position < 0 || position >= geometry.positionsPerWindow) {
    throw dcaError("bad_config", "a chain-key primitive position is inside its geometry window");
  }
  const t = chainKeyLabelAt(windowStart + position * geometry.periodMinutes);
  const coordinate = chainKeyCoordinate(t, geometry);
  if (coordinate.windowStart !== windowStart || coordinate.position !== position) {
    throw dcaError(
      "bad_config",
      "a chain-key primitive windowStart and position round-trip through one canonical coordinate",
    );
  }
  return t;
}

/** Map one canonical label to its window and position without exposing a projection.
 * @param {{ t: string, chainsPerDay: number, periodMinutes: number }} input
 */
export function chainKeyCoordinatePrimitive({ t, chainsPerDay, periodMinutes }) {
  const coordinate = chainKeyCoordinate(t, settleChainGeometry({ chainsPerDay, periodMinutes }));
  return Object.freeze({ windowStart: coordinate.windowStart, position: coordinate.position });
}

/** Map one canonical window and position to its one label.
 * @param {{ windowStart: number, position: number, chainsPerDay: number, periodMinutes: number }} input
 */
export function chainKeyLabelPrimitive({ windowStart, position, chainsPerDay, periodMinutes }) {
  return primitiveLabel(
    windowStart,
    settleChainGeometry({ chainsPerDay, periodMinutes }),
    position,
  );
}

/** Derive one root chain key at the terminal position of a supplied window.
 * @param {{ keyDerivationSecret: Uint8Array, accessGroup: string, chainsPerDay: number, periodMinutes: number, windowStart: number }} input
 */
export async function chainKeyRootPrimitive({
  keyDerivationSecret,
  accessGroup,
  chainsPerDay,
  periodMinutes,
  windowStart,
}) {
  const geometry = settleChainGeometry({ chainsPerDay, periodMinutes });
  return current.rootChainKey({
    keyDerivationSecret,
    accessGroup,
    terminalT: primitiveLabel(windowStart, geometry, geometry.positionsPerWindow - 1),
    geometry,
  });
}

/** Derive exactly one preceding chain key; unlike chainKeyFromChainKey, this never walks.
 * @param {{ chainKey: Uint8Array, accessGroup: string, chainsPerDay: number, periodMinutes: number, windowStart: number, position: number }} input
 */
export async function chainKeyStepPrimitive({
  chainKey,
  accessGroup,
  chainsPerDay,
  periodMinutes,
  windowStart,
  position,
}) {
  const geometry = settleChainGeometry({ chainsPerDay, periodMinutes });
  if (
    !Number.isSafeInteger(position) ||
    position < 0 ||
    position >= geometry.positionsPerWindow - 1
  ) {
    throw dcaError(
      "bad_config",
      "one chain-key Step has an input chain key at the following position",
    );
  }
  // Validate the coordinate's representable profile range before deriving;
  // the output position binds this one Step, and no supplied label is inferred.
  primitiveLabel(windowStart, geometry, position);
  return hkdf(
    selected(CHAIN_KEY_CONSTRUCTION).profile,
    suppliedChainKey(chainKey, CHAIN_KEY_BYTES),
    context(
      selected(CHAIN_KEY_CONSTRUCTION).profile,
      STEP,
      validateChainKeyAccessGroup(accessGroup),
      geometry,
      windowStart,
      position,
    ),
    CHAIN_KEY_BYTES,
  );
}

/** Derive one period key with the Leaf derivation from the chain key at the supplied position.
 * @param {{ chainKey: Uint8Array, accessGroup: string, chainsPerDay: number, periodMinutes: number, windowStart: number, position: number }} input
 */
export async function chainKeyLeafPrimitive({
  chainKey,
  accessGroup,
  chainsPerDay,
  periodMinutes,
  windowStart,
  position,
}) {
  const geometry = settleChainGeometry({ chainsPerDay, periodMinutes });
  primitiveLabel(windowStart, geometry, position);
  const profile = selected(CHAIN_KEY_CONSTRUCTION).profile;
  return hkdf(
    profile,
    suppliedChainKey(chainKey, CHAIN_KEY_BYTES),
    context(
      profile,
      LEAF,
      validateChainKeyAccessGroup(accessGroup),
      geometry,
      windowStart,
      position,
    ),
    16,
  );
}

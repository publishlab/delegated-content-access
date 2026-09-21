// @ts-check
//
// The period-chain construction profiles shared by their publisher and issuer
// compositions. Base period keys remain opaque and do not import this module.
//
// `dca-period-chain-v1` carries 16-byte states and 16-byte exact leaves. Its
// construction identifier sits inside every ROOT, STEP and LEAF context; it is
// not a wire-selectable width profile.

import { utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import {
  inspectPeriodGeometryBounds,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_POSITIONS_PER_WINDOW,
  PERIOD_GEOMETRY_MINUTES_PER_DAY,
} from "../../../core-shared/geometryBounds.js";
import { own } from "../../../core-shared/wire.js";

const { subtle } = globalThis.crypto;

/** The canonical KDF construction identifier. It is not a wire selector. */
export const PERIOD_CHAIN_CONSTRUCTION = "dca-period-chain-v1";

/** Retained extension exports for callers that consume the profile bounds. */
export { MAX_CHAIN_MEMBERS_PER_FAMILY, MAX_CHAIN_MEMBERS_PER_MESSAGE, MAX_POSITIONS_PER_WINDOW };
export const MAX_RIVAL_CHAIN_CANDIDATES = 4;
export const MAX_RIVAL_EXACT_CANDIDATES = 4;

const MS_PER_MINUTE = 60_000;
const KEY_DERIVATION_SECRET_BYTES = 32;

/**
 * One `dca-period-chain-v1` chain state is exactly this wide. That profile
 * fixes the width, and it is exported so a caller holding opened material can
 * check it before deriving from it.
 */
export const PERIOD_CHAIN_STATE_BYTES = 16;
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

/** The profile's fixed eleven-character spelling for an epoch minute. */
export function periodChainLabelAt(minutes) {
  if (!Number.isSafeInteger(minutes)) {
    throw dcaError("bad_config", "a period-chain label needs a whole epoch minute");
  }
  const date = new Date(minutes * MS_PER_MINUTE);
  if (
    !Number.isFinite(date.getTime()) ||
    date.getUTCFullYear() < 2000 ||
    date.getUTCFullYear() > 2099
  ) {
    throw dcaError(
      "bad_config",
      "a period-chain label is inside the profile years 2000 through 2099",
    );
  }
  return (
    `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}`
  );
}

/** The access-group wire grammar the construction binds into its contexts. */
export function validatePeriodChainAccessGroup(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ACCESS_GROUP_LENGTH ||
    !ACCESS_GROUP.test(value)
  ) {
    throw dcaError(
      "bad_name",
      "a period-chain accessGroup follows the base 64-character name grammar",
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
export function settlePeriodChainGeometry(geometry) {
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
        `period-chain geometry is the complete pair { chainsPerDay, periodMinutes } and has no ${name}`,
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

/**
 * Resolve one family's whole-pair wire geometry. An own family override is
 * decisive, including when malformed; values never merge across scopes.
 *
 * @param {unknown} context
 * @param {string} accessGroup
 * @returns {ChainGeometry|null}
 */
export function resolvePeriodChainGeometry(context, accessGroup) {
  if (!record(context)) return null;
  const groups = own(context, "accessGroups");
  if (groups !== undefined && !record(groups)) return null;

  const overridden = record(groups) && Object.hasOwn(groups, accessGroup);
  const candidate = overridden
    ? own(groups, accessGroup)
    : {
        chainsPerDay: own(context, "chainsPerDay"),
        periodMinutes: own(context, "periodMinutes"),
      };
  if (
    !record(candidate) ||
    !Object.hasOwn(candidate, "chainsPerDay") ||
    !Object.hasOwn(candidate, "periodMinutes")
  )
    return null;
  try {
    return settlePeriodChainGeometry(candidate);
  } catch {
    return null;
  }
}

/** @param {ChainGeometry} geometry */
function settledGeometry(geometry) {
  if (geometry !== null && typeof geometry === "object" && SETTLED_GEOMETRIES.has(geometry))
    return geometry;
  return settlePeriodChainGeometry(geometry);
}

/**
 * Map one fixed profile label onto its explicit geometry.
 *
 * @param {unknown} t
 * @param {ChainGeometry} geometry
 * @returns {ChainCoordinate}
 */
export function periodChainCoordinate(t, geometry) {
  const settled = settledGeometry(geometry);
  if (typeof t !== "string") {
    throw dcaError(
      "bad_config",
      `a period-chain coordinate is ${LABEL_LENGTH} characters of YYMMDDTHHMM, got type ${typeof t}`,
    );
  }
  if (t.length !== LABEL_LENGTH) {
    throw dcaError(
      "bad_config",
      `a period-chain coordinate is ${LABEL_LENGTH} characters of YYMMDDTHHMM, got ${JSON.stringify(t)}`,
    );
  }
  const parts = LABEL.exec(t);
  if (!parts)
    throw dcaError("bad_config", `period-chain coordinate ${JSON.stringify(t)} is not YYMMDDTHHMM`);

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
      `period-chain coordinate ${JSON.stringify(t)} is not a UTC calendar minute`,
    );
  }
  const minutes = at / MS_PER_MINUTE;
  if (minutes % settled.periodMinutes !== 0) {
    throw dcaError(
      "bad_config",
      `period-chain coordinate ${JSON.stringify(t)} is off the ${settled.periodMinutes}-minute family grid`,
    );
  }
  const windowStart = minutes - (minutes % settled.windowMinutes);
  return Object.freeze({
    t,
    windowStart,
    position: (minutes - windowStart) / settled.periodMinutes,
    startT: periodChainLabelAt(windowStart),
    terminalT: periodChainLabelAt(
      windowStart + (settled.positionsPerWindow - 1) * settled.periodMinutes,
    ),
  });
}

/**
 * The context bytes one derivation runs over. The construction identifier comes
 * from the selected profile, so a profile cannot derive under another profile's
 * transcript.
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
    const material = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: EMPTY_SALT, info },
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

/** @param {Uint8Array} state @param {number} width - the caller's own state width */
function suppliedState(state, width) {
  if (!(state instanceof Uint8Array) || state.length !== width) {
    throw dcaError("bad_config", `a supplied period-chain state has exactly ${width} bytes`);
  }
  return Uint8Array.from(state);
}

/**
 * The derivations and state admission of one construction profile, closed over
 * that profile.
 *
 * The profile fixes its construction identifier, state width and the exact-leaf
 * width of the exact profile it names. The context layout, domain separation,
 * coordinate rules and 32-byte key-derivation secret are part of that selected
 * construction. The closure passes its fixed state width to `suppliedState`, so
 * every other width is refused rather than padded, truncated or retried.
 *
 * @param {ConstructionProfile} profile
 */
function derivations(profile) {
  const width = profile.stateBytes;
  const leafWidth = 16;
  const at = (domain, accessGroup, geometry, windowStart, position) =>
    context(profile, domain, accessGroup, geometry, windowStart, position);
  /**
   * Derive the terminal state from one independently provisioned key-derivation secret.
   *
   * @param {{ keyDerivationSecret: Uint8Array, accessGroup: string, terminalT: string, geometry: ChainGeometry }} input
   */
  async function terminalState(input) {
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
    const group = validatePeriodChainAccessGroup(accessGroup);
    const coordinate = periodChainCoordinate(terminalT, settled);
    if (coordinate.position !== settled.positionsPerWindow - 1) {
      throw dcaError("bad_config", "a period-chain root is derived at its window terminal");
    }
    return hkdf(
      profile,
      Uint8Array.from(keyDerivationSecret),
      at(ROOT, group, settled, coordinate.windowStart, coordinate.position),
      width,
    );
  }

  /**
   * Move one supplied chain state backward to an explicit target coordinate.
   * Callers that accept supplied state should prefer the bounded expansion below.
   *
   * @param {{ state: Uint8Array, accessGroup: string, suppliedT: string, targetT: string,
   *   geometry: ChainGeometry }} input
   */
  async function stateFromState({ state, accessGroup, suppliedT, targetT, geometry }) {
    const settled = settledGeometry(geometry);
    const group = validatePeriodChainAccessGroup(accessGroup);
    let current = suppliedState(state, width);
    const supplied = periodChainCoordinate(suppliedT, settled);
    const target = periodChainCoordinate(targetT, settled);
    if (supplied.windowStart !== target.windowStart || target.position > supplied.position) {
      throw dcaError(
        "bad_config",
        "a supplied period-chain state reaches only its own window through its cutoff",
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

  /** @param {{ state: Uint8Array, accessGroup: string, t: string, geometry: ChainGeometry }} input */
  async function leafFromState({ state, accessGroup, t, geometry }) {
    const settled = settledGeometry(geometry);
    const group = validatePeriodChainAccessGroup(accessGroup);
    const coordinate = periodChainCoordinate(t, settled);
    return hkdf(
      profile,
      suppliedState(state, width),
      at(LEAF, group, settled, coordinate.windowStart, coordinate.position),
      leafWidth,
    );
  }

  /**
   * Project one supplied state over the contiguous start-through-cutoff range in
   * its own window. It walks backward once and returns copied leaf bytes.
   *
   * @param {{ state: Uint8Array, accessGroup: string, suppliedT: string, cutoffT: string,
   *   geometry: ChainGeometry }} input
   * @returns {Promise<ReadonlyArray<{ t: string, position: number, key: Uint8Array }>>}
   */
  async function expansionFromState({ state, accessGroup, suppliedT, cutoffT, geometry }) {
    const settled = settledGeometry(geometry);
    const group = validatePeriodChainAccessGroup(accessGroup);
    const supplied = periodChainCoordinate(suppliedT, settled);
    const cutoff = periodChainCoordinate(cutoffT, settled);
    if (supplied.windowStart !== cutoff.windowStart || cutoff.position > supplied.position) {
      throw dcaError(
        "bad_config",
        "a supplied period-chain state reaches only its own window through its cutoff",
      );
    }
    let current = suppliedState(state, width);
    const leaves = [];
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
        const t = periodChainLabelAt(supplied.windowStart + position * settled.periodMinutes);
        const key = await hkdf(
          profile,
          current,
          at(LEAF, group, settled, supplied.windowStart, position),
          leafWidth,
        );
        leaves.push(Object.freeze({ t, position, key: Uint8Array.from(key) }));
      }
    }
    return Object.freeze(leaves.reverse());
  }

  return { terminalState, stateFromState, leafFromState, expansionFromState };
}

/**
 * One selectable construction profile.
 *
 * @typedef {object} ConstructionProfile
 * @property {string} constructionId - the identifier inside every context, and
 *   the name the profile is selected by. It is not a wire member.
 * @property {number} stateBytes - one positioned chain state's width
 */

/**
 * One profile and the derivations closed over it, built once at load.
 *
 * @param {string} constructionId
 * @param {number} stateBytes
 */
function registered(constructionId, stateBytes) {
  const profile = Object.freeze({
    constructionId,
    stateBytes,
  });
  return { profile, derivations: derivations(profile) };
}

const CONSTRUCTION_PROFILES = {
  [PERIOD_CHAIN_CONSTRUCTION]: registered(PERIOD_CHAIN_CONSTRUCTION, PERIOD_CHAIN_STATE_BYTES),
};

/** @param {string} name */
function selected(name) {
  if (typeof name !== "string" || !Object.hasOwn(CONSTRUCTION_PROFILES, name)) {
    throw dcaError(
      "unsupported_option",
      `there is no period-chain construction profile ${JSON.stringify(name)}; the profiles are ` +
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
export function periodChainConstructionProfile(name) {
  return selected(name).profile;
}

/**
 * The four derivations of the named profile: `terminalState`, `stateFromState`,
 * `leafFromState` and `expansionFromState`. Naming the profile is all a caller
 * does to select a width, and the closures it gets back carry that width.
 *
 * @param {string} name
 */
export function periodChainDerivations(name) {
  return selected(name).derivations;
}

const current = periodChainDerivations(PERIOD_CHAIN_CONSTRUCTION);

export const periodChainTerminalState = current.terminalState;
export const periodChainStateFromState = current.stateFromState;
export const periodChainLeafFromState = current.leafFromState;
export const periodChainExpansionFromState = current.expansionFromState;

// The five operations below are the direct canonical primitive surface. Their
// input objects deliberately carry the complete coordinates a neutral bridge
// can receive: no bridge has to assemble a label, terminal position, or
// supplied/target pair around a more general projection primitive.

/** @param {number} windowStart @param {ChainGeometry} geometry @param {number} position */
function primitiveLabel(windowStart, geometry, position) {
  if (!Number.isSafeInteger(windowStart) || windowStart < 0 || windowStart > 0xffff_ffff) {
    throw dcaError(
      "bad_config",
      "a period-chain primitive windowStart is an unsigned 32-bit minute",
    );
  }
  if (!Number.isSafeInteger(position) || position < 0 || position >= geometry.positionsPerWindow) {
    throw dcaError("bad_config", "a period-chain primitive position is inside its geometry window");
  }
  const t = periodChainLabelAt(windowStart + position * geometry.periodMinutes);
  const coordinate = periodChainCoordinate(t, geometry);
  if (coordinate.windowStart !== windowStart || coordinate.position !== position) {
    throw dcaError(
      "bad_config",
      "a period-chain primitive windowStart and position round-trip through one canonical coordinate",
    );
  }
  return t;
}

/** Map one canonical label to its window and position without exposing a projection. */
export function periodChainCoordinatePrimitive({ t, chainsPerDay, periodMinutes }) {
  const coordinate = periodChainCoordinate(
    t,
    settlePeriodChainGeometry({ chainsPerDay, periodMinutes }),
  );
  return Object.freeze({ windowStart: coordinate.windowStart, position: coordinate.position });
}

/** Map one canonical window and position to its one label. */
export function periodChainLabelPrimitive({ windowStart, position, chainsPerDay, periodMinutes }) {
  return primitiveLabel(
    windowStart,
    settlePeriodChainGeometry({ chainsPerDay, periodMinutes }),
    position,
  );
}

/** Derive one terminal Root state at the terminal position of a supplied window. */
export async function periodChainRootPrimitive({
  keyDerivationSecret,
  accessGroup,
  chainsPerDay,
  periodMinutes,
  windowStart,
}) {
  const geometry = settlePeriodChainGeometry({ chainsPerDay, periodMinutes });
  return current.terminalState({
    keyDerivationSecret,
    accessGroup,
    terminalT: primitiveLabel(windowStart, geometry, geometry.positionsPerWindow - 1),
    geometry,
  });
}

/** Derive exactly one preceding state; unlike stateFromState, this never walks. */
export async function periodChainStepPrimitive({
  state,
  accessGroup,
  chainsPerDay,
  periodMinutes,
  windowStart,
  position,
}) {
  const geometry = settlePeriodChainGeometry({ chainsPerDay, periodMinutes });
  if (
    !Number.isSafeInteger(position) ||
    position < 0 ||
    position >= geometry.positionsPerWindow - 1
  ) {
    throw dcaError(
      "bad_config",
      "one period-chain Step has an input state at the following position",
    );
  }
  // Validate the coordinate's representable profile range before deriving;
  // the output position binds this one Step, and no supplied label is inferred.
  primitiveLabel(windowStart, geometry, position);
  return hkdf(
    selected(PERIOD_CHAIN_CONSTRUCTION).profile,
    suppliedState(state, PERIOD_CHAIN_STATE_BYTES),
    context(
      selected(PERIOD_CHAIN_CONSTRUCTION).profile,
      STEP,
      validatePeriodChainAccessGroup(accessGroup),
      geometry,
      windowStart,
      position,
    ),
    PERIOD_CHAIN_STATE_BYTES,
  );
}

/** Derive one exact Leaf key from the state at the supplied position. */
export async function periodChainLeafPrimitive({
  state,
  accessGroup,
  chainsPerDay,
  periodMinutes,
  windowStart,
  position,
}) {
  const geometry = settlePeriodChainGeometry({ chainsPerDay, periodMinutes });
  primitiveLabel(windowStart, geometry, position);
  const profile = selected(PERIOD_CHAIN_CONSTRUCTION).profile;
  return hkdf(
    profile,
    suppliedState(state, PERIOD_CHAIN_STATE_BYTES),
    context(
      profile,
      LEAF,
      validatePeriodChainAccessGroup(accessGroup),
      geometry,
      windowStart,
      position,
    ),
    16,
  );
}

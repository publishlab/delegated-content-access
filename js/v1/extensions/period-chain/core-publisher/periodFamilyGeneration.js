// @ts-check
//
// The publisher side of the period-chain construction.
//
// One handle is one immutable derivation generation: an independently
// provisioned key-derivation secret, one named construction profile, and one
// complete geometry. The route selects the profile for this generation; the profile decides the
// state and leaf widths as well as the identifier inside every context; a
// generation naming none is on `dca-period-chain-v1`. Its
// key-derivation-secret bytes are copied and its geometry snapshotted at
// construction, so a caller that later mutates the buffer or config gets
// the same bytes out of this handle as before. Replacing the key-derivation
// secret creates a new handle; the old one keeps deriving its generation's bytes.
//
// The logical family adds the access group named at each call. One handle may
// therefore serve several access-group families under the same retained-input
// generation; their Root contexts remain distinct.
// No family identifier and no generation identifier enter the construction or
// leave this module: the root context carries the construction identifier, the
// access group, the complete geometry, the window start and the terminal
// position, and nothing else. See `spec--period-key-chains.md`, Canonical
// construction.
//
// Geometry is explicit. Nothing here reads a collection of `t` values to work
// out how a day is divided; every requested label is validated against the
// geometry this handle was built with, and a label off that grid is refused
// rather than rounded onto it. Labels are the profile's fixed eleven-character
// `YYMMDDTHHMM`, which is why the base `formatT` is not reused: base spells an
// hourly period in nine characters, and this profile has one spelling.

import { dcaError } from "../../../core-shared/errors.js";
import { MAX_POSITIONS_PER_WINDOW } from "../../../core-shared/geometryBounds.js";
import { validateAccessGroup } from "../../../core-shared/names.js";
import {
  PERIOD_CHAIN_CONSTRUCTION,
  periodChainConstructionProfile,
  periodChainCoordinate,
  periodChainDerivations,
  periodChainLabelAt,
  settlePeriodChainGeometry,
} from "../core-shared/periodChainConstruction.js";

/** @typedef {import('../core-shared/periodChainConstruction.js').ChainCoordinate} ChainCoordinate */

export { MAX_POSITIONS_PER_WINDOW, PERIOD_CHAIN_CONSTRUCTION };

const SECRET_BYTES = 32;

const OPTIONS = ["keyDerivationSecret", "geometry", "cache", "construction"];

/**
 * One immutable derivation generation, serving the access-group family named
 * at each operation.
 *
 * @param {object} config
 * @param {Uint8Array} config.keyDerivationSecret - the independently
 *   provisioned 32-byte publisher key-derivation secret, copied on the way in
 * @param {{ chainsPerDay: number, periodMinutes: number }} config.geometry - the
 *   complete wire pair
 * @param {boolean} [config.cache] - retain derived state and leaves for reuse
 *   across calls. The cache is disposable: the retained key-derivation secret
 *   and geometry regenerate every entry, and the same bytes come out with it off.
 * @param {string} [config.construction] - the construction profile this
 *   generation derives under. Naming none is `dca-period-chain-v1`, so every
 *   caller that selected nothing keeps the bytes it had.
 */
export function periodFamilyGeneration(config = /** @type {any} */ ({})) {
  for (const name of Object.keys(config ?? {})) {
    if (!OPTIONS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `a period-family generation has no ${name} yet, and will not pretend to`,
      );
    }
  }

  const {
    keyDerivationSecret,
    geometry,
    cache = true,
    construction = PERIOD_CHAIN_CONSTRUCTION,
  } = config ?? {};
  // The profile is named before anything is derived. It decides the whole width
  // selection below, and an unknown name is refused here.
  const profile = periodChainConstructionProfile(construction);
  const {
    terminalState: derivedTerminalState,
    stateFromState: derivedStateFromState,
    leafFromState: derivedLeafFromState,
  } = periodChainDerivations(profile.constructionId);
  if (!(keyDerivationSecret instanceof Uint8Array) || keyDerivationSecret.length !== SECRET_BYTES) {
    throw dcaError(
      "bad_config",
      `a period-family generation holds exactly ${SECRET_BYTES} key-derivation-secret bytes`,
    );
  }
  if (typeof cache !== "boolean") {
    throw dcaError(
      "bad_config",
      "a period-family generation caches or it does not; cache is a boolean",
    );
  }

  // The generation snapshot. Nothing below reads `config`, `keyDerivationSecret` or
  // `geometry` again, so mutating any of them afterwards changes nothing.
  const retainedInput = Uint8Array.from(keyDerivationSecret);
  const settled = settlePeriodChainGeometry(geometry);

  /**
   * Derived state and leaves, partitioned by construction, geometry, access
   * group and window; position keys the maps inside one window. Generation
   * and family need no key of their own; each derivation generation handle
   * has its own cache. A rival retained-input generation is a different
   * handle with a different cache.
   *
   * @type {Map<string, { states: Map<number, Uint8Array>, leaves: Map<number, Uint8Array> }>}
   */
  const retained = new Map();

  /** @returns {{ states: Map<number, Uint8Array>, leaves: Map<number, Uint8Array> }} */
  function room(accessGroup, windowStart) {
    if (!cache) return { states: new Map(), leaves: new Map() };
    const key = [
      profile.constructionId,
      settled.chainsPerDay,
      settled.periodMinutes,
      accessGroup,
      windowStart,
    ].join("\0");
    let held = retained.get(key);
    if (!held) {
      held = { states: new Map(), leaves: new Map() };
      retained.set(key, held);
    }
    return held;
  }

  /**
   * The positioned state `S[position]`, walking backward from the nearest
   * state already retained above it, or the terminal when there is none, and
   * keeping every state the walk passes. One position costs one step, so an
   * expansion of a whole window walks it once.
   *
   * @param {string} accessGroup
   * @param {number} windowStart
   * @param {number} position
   * @param {{ states: Map<number, Uint8Array> }} held
   * @returns {Promise<Uint8Array>}
   */
  async function stateAt(accessGroup, windowStart, position, held) {
    const known = held.states.get(position);
    if (known) return known;

    const terminal = settled.positionsPerWindow - 1;
    let from = terminal;
    for (const at of held.states.keys()) {
      if (at >= position && at < from) from = at;
    }

    let state = held.states.get(from);
    if (!state) {
      state = await derivedTerminalState({
        keyDerivationSecret: retainedInput,
        accessGroup,
        terminalT: periodChainLabelAt(windowStart + terminal * settled.periodMinutes),
        geometry: settled,
      });
      held.states.set(terminal, state);
      from = terminal;
    }
    for (let at = from - 1; at >= position; at--) {
      state = await derivedStateFromState({
        state,
        accessGroup,
        suppliedT: periodChainLabelAt(windowStart + (at + 1) * settled.periodMinutes),
        targetT: periodChainLabelAt(windowStart + at * settled.periodMinutes),
        geometry: settled,
      });
      held.states.set(at, state);
    }
    return state;
  }

  /**
   * @param {string} accessGroup
   * @param {number} windowStart
   * @param {number} position
   * @param {{ states: Map<number, Uint8Array>, leaves: Map<number, Uint8Array> }} held
   * @returns {Promise<Uint8Array>}
   */
  async function leafAt(accessGroup, windowStart, position, held) {
    const known = held.leaves.get(position);
    if (known) return known;
    const state = await stateAt(accessGroup, windowStart, position, held);
    const leaf = await derivedLeafFromState({
      state,
      accessGroup,
      t: periodChainLabelAt(windowStart + position * settled.periodMinutes),
      geometry: settled,
    });
    held.leaves.set(position, leaf);
    return leaf;
  }

  return Object.freeze({
    geometry: settled,

    /**
     * The construction profile this generation is one generation of: its
     * identifier, its state width and the base exact profile its leaves
     * have. A composition planning around this handle reads the widths off
     * it rather than restating them.
     */
    constructionProfile: profile,

    /**
     * Where a label sits under this handle's geometry.
     *
     * @param {string} t
     * @returns {ChainCoordinate}
     */
    coordinateFor(t) {
      return periodChainCoordinate(t, settled);
    },

    /**
     * The canonical exact leaf at one coordinate: the bytes a render wraps
     * its content keys under, and the bytes an exact recipient receives.
     *
     * @param {string} accessGroup
     * @param {string} t
     * @returns {Promise<Uint8Array>}
     */
    async periodKey(accessGroup, t) {
      const group = validateAccessGroup(accessGroup);
      const at = periodChainCoordinate(t, settled);
      const held = room(group, at.windowStart);
      return Uint8Array.from(await leafAt(group, at.windowStart, at.position, held));
    },

    /**
     * The positioned chain capability at one coordinate: the state a
     * publisher supplies to an issuer, which is the window's terminal when
     * `t` is the terminal label and a lower cutoff otherwise. It reaches
     * its own leaf and every earlier position in the same window, and
     * nothing later or outside it.
     *
     * @param {string} accessGroup
     * @param {string} t
     * @returns {Promise<{ t: string, windowStart: number, position: number, key: Uint8Array }>}
     */
    async chainCapability(accessGroup, t) {
      const group = validateAccessGroup(accessGroup);
      const at = periodChainCoordinate(t, settled);
      const held = room(group, at.windowStart);
      return Object.freeze({
        t: at.t,
        windowStart: at.windowStart,
        position: at.position,
        key: Uint8Array.from(await stateAt(group, at.windowStart, at.position, held)),
      });
    },

    /**
     * Every canonical leaf the capability at `t` reaches: the window start
     * through `t`, in coordinate order. One backward walk derives each leaf
     * from the state retained at its position.
     *
     * @param {string} accessGroup
     * @param {string} t
     * @returns {Promise<{ t: string, position: number, key: Uint8Array }[]>}
     */
    async expansion(accessGroup, t) {
      const group = validateAccessGroup(accessGroup);
      const at = periodChainCoordinate(t, settled);
      const held = room(group, at.windowStart);

      const leaves = [];
      for (let position = at.position; position >= 0; position--) {
        leaves.push(
          Object.freeze({
            t: periodChainLabelAt(at.windowStart + position * settled.periodMinutes),
            position,
            key: Uint8Array.from(await leafAt(group, at.windowStart, position, held)),
          }),
        );
      }
      return Object.freeze(leaves.reverse());
    },
  });
}

/**
 * The base publisher's view of one generation: exact derivation and nothing
 * else. The `Sealer` takes a `derive(accessGroup, t)` and assigns no
 * derivation meaning to the bytes it gets back, so the chain operations stay
 * behind the extension composition that holds the handle itself.
 *
 * @param {{ periodKey: (accessGroup: string, t: string) => Promise<Uint8Array> }} generation
 * @returns {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }}
 */
export function exactPeriodKeySupplyFor(generation) {
  if (typeof generation?.periodKey !== "function") {
    throw dcaError(
      "bad_config",
      "an exact period-key supply is made over a period-family generation",
    );
  }
  return Object.freeze({
    derive: (accessGroup, t) => generation.periodKey(accessGroup, t),
  });
}

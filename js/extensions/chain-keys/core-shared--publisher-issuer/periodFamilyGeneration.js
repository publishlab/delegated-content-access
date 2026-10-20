// @ts-check
//
// Secret-backed chain-key family derivation shared by publisher and issuer.
//
// One handle is one immutable derivation generation: an independently
// provisioned key-derivation secret for one publisher namespace, one named construction profile, and one
// complete geometry. The route selects the profile for this generation; the profile decides the
// chain-key and period-key widths as well as the identifier inside every context; a
// generation naming none is on `dca-construction-chain-keys`. Its
// key-derivation-secret bytes are copied and its geometry snapshotted at
// construction, so a caller that later mutates the buffer or config gets
// the same bytes out of this handle as before. Replacing the key-derivation
// secret creates a new handle; the old one keeps deriving its generation's bytes.
// The caller provisions namespace separation. This handle does not turn an
// unscoped master secret into publisher-specific material from an origin.
//
// The logical family adds the access group named at each call. One handle may
// therefore serve several access-group families under the same retained-input
// generation; their Root contexts remain distinct.
// No family identifier and no generation identifier enter the construction or
// leave this module: the root context carries the construction identifier, the
// access group, the complete geometry, the window start and the terminal
// position, and nothing else. See `spec-profile--chain-keys.md`, Canonical
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
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
  chainKeyCoordinate,
  chainKeyDerivations,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../core-shared/chainKeyConstruction.js";

/** @typedef {import('../core-shared/chainKeyConstruction.js').ChainCoordinate} ChainCoordinate */

export { MAX_POSITIONS_PER_WINDOW, CHAIN_KEY_CONSTRUCTION };

const SECRET_BYTES = 32;

const OPTIONS = ["keyDerivationSecret", "geometry", "cache", "construction"];

/**
 * One immutable derivation generation, serving the access-group family named
 * at each operation.
 *
 * @param {object} config
 * @param {Uint8Array} config.keyDerivationSecret - the independently
 *   provisioned 32-byte key-derivation secret, copied on the way in
 * @param {{ chainsPerDay: number, periodMinutes: number }} config.geometry - the
 *   complete wire pair
 * @param {boolean} [config.cache] - retain derived chain keys and period keys for reuse
 *   across calls. The cache is disposable: the retained key-derivation secret
 *   and geometry regenerate every entry, and the same bytes come out with it off.
 * @param {string} [config.construction] - the construction profile this
 *   generation derives under. Naming none is `dca-construction-chain-keys`, so every
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
    construction = CHAIN_KEY_CONSTRUCTION,
  } = config ?? {};
  // The profile is named before anything is derived. It decides the whole width
  // selection below, and an unknown name is refused here.
  const profile = chainKeyConstructionProfile(construction);
  const {
    rootChainKey: derivedRootChainKey,
    chainKeyFromChainKey: derivedChainKeyFromChainKey,
    periodKeyFromChainKey: derivedPeriodKeyFromChainKey,
  } = chainKeyDerivations(profile.name);
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
  const settled = settleChainGeometry(geometry);

  /**
   * Derived chain keys and period keys, partitioned by construction, geometry, access
   * group and window; position keys the maps inside one window. Generation
   * and family need no key of their own; each derivation generation handle
   * has its own cache. A rival retained-input generation is a different
   * handle with a different cache.
   *
   * @type {Map<string, { chainKeys: Map<number, Uint8Array>, periodKeys: Map<number, Uint8Array> }>}
   */
  const retained = new Map();

  /**
   * @param {string} accessGroup
   * @param {number} windowStart
   * @returns {{ chainKeys: Map<number, Uint8Array>, periodKeys: Map<number, Uint8Array> }}
   */
  function room(accessGroup, windowStart) {
    if (!cache) return { chainKeys: new Map(), periodKeys: new Map() };
    const key = [
      profile.constructionId,
      settled.chainsPerDay,
      settled.periodMinutes,
      accessGroup,
      windowStart,
    ].join("\0");
    let held = retained.get(key);
    if (!held) {
      held = { chainKeys: new Map(), periodKeys: new Map() };
      retained.set(key, held);
    }
    return held;
  }

  /**
   * The positioned chain key `C[position]`, walking backward from the nearest
   * chain key already retained above it, or the root chain key at the terminal
   * when there is none, and keeping every chain key the walk passes. One
   * position costs one step, so an expansion of a whole window walks it once.
   *
   * @param {string} accessGroup
   * @param {number} windowStart
   * @param {number} position
   * @param {{ chainKeys: Map<number, Uint8Array> }} held
   * @returns {Promise<Uint8Array>}
   */
  async function chainKeyAt(accessGroup, windowStart, position, held) {
    const known = held.chainKeys.get(position);
    if (known) return known;

    const terminal = settled.positionsPerWindow - 1;
    let from = terminal;
    for (const at of held.chainKeys.keys()) {
      if (at >= position && at < from) from = at;
    }

    let chainKey = held.chainKeys.get(from);
    if (!chainKey) {
      chainKey = await derivedRootChainKey({
        keyDerivationSecret: retainedInput,
        accessGroup,
        terminalT: chainKeyLabelAt(windowStart + terminal * settled.periodMinutes),
        geometry: settled,
      });
      held.chainKeys.set(terminal, chainKey);
      from = terminal;
    }
    for (let at = from - 1; at >= position; at--) {
      chainKey = await derivedChainKeyFromChainKey({
        chainKey,
        accessGroup,
        suppliedT: chainKeyLabelAt(windowStart + (at + 1) * settled.periodMinutes),
        targetT: chainKeyLabelAt(windowStart + at * settled.periodMinutes),
        geometry: settled,
      });
      held.chainKeys.set(at, chainKey);
    }
    return chainKey;
  }

  /**
   * @param {string} accessGroup
   * @param {number} windowStart
   * @param {number} position
   * @param {{ chainKeys: Map<number, Uint8Array>, periodKeys: Map<number, Uint8Array> }} held
   * @returns {Promise<Uint8Array>}
   */
  async function periodKeyAt(accessGroup, windowStart, position, held) {
    const known = held.periodKeys.get(position);
    if (known) return known;
    const chainKey = await chainKeyAt(accessGroup, windowStart, position, held);
    const periodKey = await derivedPeriodKeyFromChainKey({
      chainKey,
      accessGroup,
      t: chainKeyLabelAt(windowStart + position * settled.periodMinutes),
      geometry: settled,
    });
    held.periodKeys.set(position, periodKey);
    return periodKey;
  }

  return Object.freeze({
    geometry: settled,

    /**
     * The construction profile this generation is one generation of: its
     * identifier and its chain-key width; its period keys have the base period-key
     * width. A composition planning around this handle reads the widths off
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
      return chainKeyCoordinate(t, settled);
    },

    /**
     * The canonical period key at one coordinate: the bytes a render wraps
     * its content keys under, and the bytes a period-key recipient receives.
     *
     * @param {string} accessGroup
     * @param {string} t
     * @returns {Promise<Uint8Array>}
     */
    async periodKey(accessGroup, t) {
      const group = validateAccessGroup(accessGroup);
      const at = chainKeyCoordinate(t, settled);
      const held = room(group, at.windowStart);
      return Uint8Array.from(await periodKeyAt(group, at.windowStart, at.position, held));
    },

    /**
     * The positioned chain capability at one coordinate: the chain key a
     * publisher supplies to an issuer, which is the window's terminal when
     * `t` is the terminal label and a lower cutoff otherwise. It reaches
     * its own period key and every earlier position in the same window, and
     * nothing later or outside it.
     *
     * @param {string} accessGroup
     * @param {string} t
     * @returns {Promise<{ t: string, windowStart: number, position: number, key: Uint8Array }>}
     */
    async chainCapability(accessGroup, t) {
      const group = validateAccessGroup(accessGroup);
      const at = chainKeyCoordinate(t, settled);
      const held = room(group, at.windowStart);
      return Object.freeze({
        t: at.t,
        windowStart: at.windowStart,
        position: at.position,
        key: Uint8Array.from(await chainKeyAt(group, at.windowStart, at.position, held)),
      });
    },

    /**
     * Every canonical period key the capability at `t` reaches: the window start
     * through `t`, in coordinate order. One backward walk derives each period key
     * from the chain key retained at its position.
     *
     * @param {string} accessGroup
     * @param {string} t
     * @returns {Promise<readonly Readonly<{ t: string, position: number, key: Uint8Array }>[]>}
     */
    async expansion(accessGroup, t) {
      const group = validateAccessGroup(accessGroup);
      const at = chainKeyCoordinate(t, settled);
      const held = room(group, at.windowStart);

      const periodKeys = [];
      for (let position = at.position; position >= 0; position--) {
        periodKeys.push(
          Object.freeze({
            t: chainKeyLabelAt(at.windowStart + position * settled.periodMinutes),
            position,
            key: Uint8Array.from(await periodKeyAt(group, at.windowStart, position, held)),
          }),
        );
      }
      return Object.freeze(periodKeys.reverse());
    },
  });
}

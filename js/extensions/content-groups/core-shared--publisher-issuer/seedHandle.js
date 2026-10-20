// @ts-check
// Secret-backed content-name/window handles are needed by publisher and issuer only.
import { validateAccessGroup } from "../../../core-shared/names.js";
import {
  chainKeyCoordinate,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../../chain-keys/core-shared/chainKeyConstruction.js";
import { periodFamilyGeneration } from "../../chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import {
  checkedGeometry,
  checkedPeriod,
  checkedWindow,
  keyBytes,
} from "../core-shared/construction.js";

/**
 * Stock construction; an explicit replacement can observe or substitute its operations.
 * @type {Readonly<{coordinate: typeof chainKeyCoordinate, labelAt: typeof chainKeyLabelAt,
 *   settleGeometry: typeof settleChainGeometry, familyGeneration: typeof periodFamilyGeneration}>}
 */
export const STOCK_CHAIN = Object.freeze({
  coordinate: chainKeyCoordinate,
  labelAt: chainKeyLabelAt,
  settleGeometry: settleChainGeometry,
  familyGeneration: periodFamilyGeneration,
});

/**
 * @param {Uint8Array} seed
 * @param {any} geometry
 * @param {string} label
 * @param {any} [chain]
 * @returns {Readonly<{windowStart: string,
 *   periodKey: (group: string, t: string) => Promise<Uint8Array>,
 *   chainKey: (group: string, t: string) => Promise<{t: string, windowStart: number, position: number, key: Uint8Array}>,
 *   dispose: () => void}>}
 */
export function seedHandle(seed, geometry, label, chain = STOCK_CHAIN) {
  const kept = keyBytes(seed, 32, "window seed");
  const g = checkedGeometry(geometry, chain);
  const start = checkedWindow(label, g, chain);
  const stock = chain.familyGeneration({ keyDerivationSecret: kept, geometry: g });
  let disposed = false;
  /** @param {string} t */
  const within = (t) => {
    if (disposed) throw new Error("seed handle is disposed");
    const at = checkedPeriod(t, g, chain);
    if (at.windowStart !== start.windowStart) throw new Error("coordinate outside seed window");
    return at;
  };
  return Object.freeze({
    windowStart: start.startT,
    /** @param {string} group @param {string} t */
    async periodKey(group, t) {
      validateAccessGroup(group);
      within(t);
      return stock.periodKey(group, t);
    },
    /** @param {string} group @param {string} t */
    async chainKey(group, t) {
      validateAccessGroup(group);
      within(t);
      return stock.chainCapability(group, t);
    },
    /** Zero the handle's copy of the seed; the handle derives nothing after. */
    dispose() {
      disposed = true;
      kept.fill(0);
    },
  });
}

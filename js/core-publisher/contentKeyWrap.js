// @ts-check
//
// How one render writes `contentData[contentName].keys`. That member is emitted
// once and every issuer of the render reads the same entries, so each render,
// not each issuer, decides the aad a wrap is made under and the shape of its
// entry.
//
// A strategy is asked for the aad at a coordinate, and then for the entry that
// coordinate's wrap is written as. It draws nothing, holds nothing and is never
// handed a key: the nonce, the period key and the content key stay with the
// Sealer, so a strategy cannot move key material anywhere.

import { dcaError } from "../core-shared/errors.js";

/**
 * The coordinate of one wrap, as a strategy's aad call receives it.
 *
 * @typedef {object} ContentKeyWrapCoordinate
 * @property {string} renderId
 * @property {string} contentName
 * @property {string} accessGroup
 * @property {string} t
 */

/**
 * One finished wrap, as a strategy's entry call receives it. `nonce` and `key`
 * are base64url, as on the wire.
 *
 * @typedef {object} ContentKeyWrap
 * @property {string} t
 * @property {string} nonce
 * @property {string} key
 */

/**
 * @typedef {object} ContentKeyWrapStrategy
 * @property {(coordinate: ContentKeyWrapCoordinate) => Uint8Array|undefined} aad
 * @property {(wrap: ContentKeyWrap) => object} entry
 */

/**
 * The strategy a render uses when it is not told otherwise. It uses no aad,
 * because the period key is already specific to its access group, and it writes
 * the entry the format describes. It is the v1 representation, and every
 * recorded vector carries it.
 *
 * @type {ContentKeyWrapStrategy}
 */
export const ordinaryContentKeyWrap = {
  aad: () => undefined,
  entry: ({ t, nonce, key }) => ({ t, nonce, key }),
};

/**
 * A strategy's two calls, read off it on arrival and stored next to the
 * strategy itself, so a plan can name the strategy this render selected.
 *
 * @typedef {object} CheckedContentKeyWrap
 * @property {ContentKeyWrapStrategy} strategy - as it arrived, for the plans
 * @property {(coordinate: ContentKeyWrapCoordinate) => Uint8Array|undefined} aad
 * @property {(wrap: ContentKeyWrap) => object} entry
 */

/** The entry members the shared `contentData[name].keys` traversal reads. */
const ENTRY_MEMBERS = ["t", "nonce", "key"];

/**
 * Checks the strategy a render will use, where it arrives. An absent strategy
 * selects the ordinary wrap; a supplied strategy must answer both calls. The
 * two representations differ by one member on an entry.
 *
 * This function reads both calls here and keeps them, so a render wraps with
 * the strategy selected for it. If a member were replaced after the render
 * started, the render would write a second representation beside the entries
 * already written, and `contentData[contentName].keys` is emitted once for
 * every issuer to read.
 *
 * @param {unknown} strategy
 * @returns {CheckedContentKeyWrap}
 */
export function checkedContentKeyWrap(strategy) {
  const candidate = /** @type {any} */ (strategy === undefined ? ordinaryContentKeyWrap : strategy);
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    typeof candidate.aad !== "function" ||
    typeof candidate.entry !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "a contentKeyWrapStrategy is an object with aad(coordinate) and entry(wrap)",
    );
  }
  const { aad, entry } = candidate;

  return Object.freeze({
    strategy: candidate,
    aad: (coordinate) => aad.call(candidate, coordinate),
    entry: (wrap) => checkedEntry(entry.call(candidate, wrap)),
  });
}

/**
 * Checks one entry a strategy wrote. The entry must be an object with the
 * members every reader of `contentData[name].keys` walks. Any other members
 * belong to the strategy, and base reads none of them.
 *
 * @param {unknown} entry
 * @returns {object}
 */
function checkedEntry(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw dcaError("bad_config", "a contentKeyWrapStrategy writes each entry as an object");
  }
  for (const member of ENTRY_MEMBERS) {
    if (typeof (/** @type {any} */ (entry)[member]) !== "string") {
      throw dcaError("bad_config", `a content-key entry carries ${member}, and this one does not`);
    }
  }
  return entry;
}

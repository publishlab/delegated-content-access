// @ts-check

// This file defines one eviction contract for both logical client pools. The callback receives
// only coordinates and bookkeeping, never key bytes or CryptoKey handles.

const SIX_HOURS = 6 * 60 * 60 * 1000;
const LABEL = /^(\d{2})(\d{2})(\d{2})T(\d{2})(\d{2})?$/;

/**
 * @typedef {object} EvictionEntry
 * @property {'independent'|'chain'} pool
 * @property {string} t
 * @property {'period-key'|'chain-key'} kind
 */

/**
 * The reference default: retain a key coordinate until it is six hours behind
 * the host's clock. A future coordinate therefore stays; an unreadable
 * coordinate is evicted: retaining one that no future read can interpret would
 * let a time-bounded reference pool grow without bound.
 *
 * @param {EvictionEntry} entry
 * @param {{ now: Date }} context
 * @returns {boolean} true when the cache should evict it
 */
export function evictAfterSixHours(entry, { now }) {
  const parts = LABEL.exec(entry.t);
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) return false;
  if (!parts) return true;
  const at = Date.UTC(
    2000 + Number(parts[1]),
    Number(parts[2]) - 1,
    Number(parts[3]),
    Number(parts[4]),
    parts[5] === undefined ? 0 : Number(parts[5]),
  );
  const parsed = new Date(at);
  if (
    parsed.getUTCFullYear() !== 2000 + Number(parts[1]) ||
    parsed.getUTCMonth() !== Number(parts[2]) - 1 ||
    parsed.getUTCDate() !== Number(parts[3]) ||
    parsed.getUTCHours() !== Number(parts[4]) ||
    parsed.getUTCMinutes() !== (parts[5] === undefined ? 0 : Number(parts[5]))
  )
    return true;
  return now.getTime() - at >= SIX_HOURS;
}

// @ts-check
//
// This module exposes the ordinary period-key cache as one resolver
// candidate source. For each authored wrap, it asks the cache only for the
// rivals retained at that wrap's byte-identical exact coordinate.

import { dcaError } from "../core-shared/errors.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { own } from "../core-shared/wire.js";

const MAX_RIVALS_PER_WRAP = 4;
const MAX_TRIALS_PER_RESOLUTION = 64;

// One realm's ordinary filings, including local chain derivations. Persistent
// cache readers advance past observed stamps; this supplies no cross-tab lock.
let nextFiling = 0;
/** @param {number} order
 * @returns {void}
 */
export function observePeriodFilingOrder(order) {
  if (!Number.isSafeInteger(order) || order < 0)
    throw dcaError("bad_storage", "the period-key filing order is a nonnegative safe integer");
  nextFiling = Math.max(nextFiling, order);
}
/** @returns {number} */
export function nextPeriodFilingOrder() {
  if (nextFiling === Number.MAX_SAFE_INTEGER)
    throw dcaError("bad_storage", "the period-key cache filing order is exhausted");
  return ++nextFiling;
}

/** @param {Uint8Array|CryptoKey} a @param {Uint8Array|CryptoKey} b */
function samePeriodKey(a, b) {
  return (
    a === b ||
    (a instanceof Uint8Array &&
      b instanceof Uint8Array &&
      a.length === b.length &&
      a.every((byte, index) => byte === b[index]))
  );
}

/** Shared finite trials and duplicate suppression across ordinary/chain views.
 * @param {{ remaining: number, seen?: Map<any, (Uint8Array|CryptoKey)[]> }} budget
 * @param {any} entry @param {Uint8Array|CryptoKey} key
 * @returns {boolean}
 */
export function takePeriodCandidate(budget, entry, key) {
  if (budget.remaining <= 0) return false;
  budget.seen ??= new Map();
  const seen = budget.seen.get(entry) ?? [];
  if (seen.some((held) => samePeriodKey(held, key))) return false;
  seen.push(key);
  budget.seen.set(entry, seen);
  budget.remaining--;
  return true;
}

/** The period keys this budget already spent on one wrap, in trial order.
 * A later source reads them to tell a memo it may skip from one never offered.
 * @param {{ seen?: Map<any, (Uint8Array|CryptoKey)[]> }} budget
 * @param {any} entry
 * @returns {(Uint8Array|CryptoKey)[]}
 */
export function triedPeriodKeys(budget, entry) {
  return [...(budget.seen?.get(entry) ?? [])];
}

/**
 * @param {{ candidatesAt: Function, candidateEntriesAt?: Function, attempted: Function }|null} cache
 * @param {{ candidatesAt: Function, candidateEntriesAt?: Function, attempted: Function }|null} [additional]
 * @returns {{ attempts: (context: any) => AsyncGenerator<any> }}
 */
export function periodKeyCandidateSource(cache, additional = null) {
  const caches = [cache, additional].filter((view) => view !== null);
  if (
    caches.length === 0 ||
    caches.some(
      (view) => typeof view?.candidatesAt !== "function" || typeof view?.attempted !== "function",
    )
  ) {
    throw dcaError(
      "bad_config",
      "a period-key candidate source needs candidatesAt and attempted cache methods",
    );
  }

  if (caches.length > 1 && caches.some((view) => typeof view?.candidateEntriesAt !== "function"))
    throw dcaError("bad_config", "composed ordinary period views need shared filing metadata");

  return Object.freeze({
    /**
     * @param {{ accessGroup: string, entries: any[], publisher?: string,
     *   issuerNames: string[], lease?: object,
     *   budget?: { remaining: number } }} context
     */
    async *attempts({
      accessGroup,
      entries,
      publisher,
      issuerNames,
      lease,
      budget = { remaining: MAX_TRIALS_PER_RESOLUTION },
    }) {
      for (const entry of entries) {
        if (budget.remaining <= 0) return;
        const t = own(entry, "t");
        if (!isPeriodKeyLabel(t)) continue;
        const context = { publisher, issuerNames, lease };
        const views = await Promise.all(
          caches.map(async (view) => {
            if (typeof view?.candidateEntriesAt === "function")
              return {
                candidates: await view.candidateEntriesAt(accessGroup, t, context),
              };
            const keys = /** @type {(Uint8Array|CryptoKey)[]} */ (
              await /** @type {any} */ (view).candidatesAt(accessGroup, t, context)
            );
            return {
              candidates: keys.map((key, index) => ({ key, pending: false, order: -index })),
            };
          }),
        );
        const nonempty = views.filter((view) => view.candidates.length > 0);
        const candidates = nonempty.flatMap((view) => view.candidates);
        candidates.sort((a, b) => Number(b.pending) - Number(a.pending) || b.order - a.order);
        /** @type {(Uint8Array|CryptoKey)[]} */
        const selected = [];
        for (const candidate of candidates) {
          if (selected.some((key) => samePeriodKey(key, candidate.key))) continue;
          selected.push(candidate.key);
          if (selected.length === MAX_RIVALS_PER_WRAP) break;
        }
        for (const periodKey of selected) {
          if (!takePeriodCandidate(budget, entry, periodKey)) continue;
          yield {
            entry,
            periodKey,
            origin: { kind: "cached-period-key", accessGroup, t },
          };
        }
      }
    },
  });
}

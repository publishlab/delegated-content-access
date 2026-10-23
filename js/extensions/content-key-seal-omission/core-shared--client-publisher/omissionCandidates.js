// @ts-check
// The same bound wraps reach the client request and the publisher's request-size
// check. Callers supply their own admitted view of each item's wrap families.
// A candidate forwards no nonce: the issuer derives it from the verified render
// and the candidate's coordinate, so a carried `nonce` on an entry stays behind.
import { own } from "../../../core-shared/wire.js";
import { isBoundEntry } from "../core-shared/omissionBind.js";

/**
 * @typedef {{ contentName: string, accessGroup: string, period: unknown, key: unknown, bind: unknown }} BoundCandidate
 */

/**
 * The `boundCandidates` records for these content names: one record per bound
 * wrap entry, carrying the content name, the access group and the period it
 * was read at. Each entry is the client's view of a wrap record, which names
 * its period label `t`.
 * @param {string[]} contentNames
 * @param {(name: string) => Iterable<[string, any[]]>} entriesFor - access group
 *   to that item's wrap entries
 * @returns {BoundCandidate[]}
 */
export function omissionBoundCandidates(contentNames, entriesFor) {
  /** @type {BoundCandidate[]} */
  const candidates = [];
  for (const contentName of contentNames) {
    for (const [accessGroup, entries] of entriesFor(contentName)) {
      for (const entry of entries) {
        if (!isBoundEntry(entry)) continue;
        candidates.push({
          contentName,
          accessGroup,
          period: own(entry, "t"),
          key: own(entry, "key"),
          bind: own(entry, "bind"),
        });
      }
    }
  }
  return candidates;
}

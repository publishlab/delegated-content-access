// @ts-check
// The same bound wraps reach the client request and the publisher's request-size
// check. Callers supply their own admitted view of each item's wrap families.
import { own, setOwn } from "../../../core-shared/wire.js";
import { isBoundEntry } from "../core-shared/omissionBind.js";

/**
 * @param {string[]} contentNames
 * @param {(name: string) => Iterable<[string, any[]]>} entriesFor
 * @returns {Record<string, any[]>}
 */
export function omissionBoundCandidates(contentNames, entriesFor) {
  /** @type {Record<string, any[]>} */
  const result = {};
  for (const contentName of contentNames) {
    const candidates = [];
    for (const [accessGroup, entries] of entriesFor(contentName)) {
      for (const entry of entries) {
        if (!isBoundEntry(entry)) continue;
        candidates.push({
          accessGroup,
          t: own(entry, "t"),
          nonce: own(entry, "nonce"),
          key: own(entry, "key"),
          bind: own(entry, "bind"),
        });
      }
    }
    if (candidates.length > 0) setOwn(result, contentName, candidates);
  }
  return result;
}

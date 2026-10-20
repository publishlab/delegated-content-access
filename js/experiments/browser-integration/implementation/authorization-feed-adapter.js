// @ts-check
// Example application adapter for an asynchronous authorization-feed API.
import { createContextSource } from "./context-source.js";

/**
 * Adapt an API that asynchronously reads a lease after each feed notification.
 * A monotonically increasing read generation prevents a late lookup from
 * replacing the state obtained from a newer notification.
 * This example treats a successful, non-overlapping read of the same account
 * and key handles as positive continuity confirmation. Its upstream feed must
 * not reuse that pair after an actual context replacement. Failed or
 * overlapping reads cannot confirm continuity and retire prior work.
 *
 * @param {{readAuthorizationLease: () => Promise<AuthorizationLease | null>, onLeaseChange: (listener: () => void) => () => void}} feed
 */
export function adaptAuthorizationFeed(feed) {
  const source = createContextSource({
    sequence: 0,
    contextKnown: false,
    contextRevision: "authorization-feed-0",
  });
  let sequence = 0;
  let revision = 0;
  let readGeneration = 0;
  let readPending = false;
  let continuityUncertain = false;
  let disposed = false;
  /** @type {AuthorizationLease | null} */
  let current = null;
  /** @type {{accountHandle: string, keyHandle: string} | null} */
  let association = null;

  async function refresh() {
    if (disposed) return;
    // A second notification before the prior read settles leaves a gap in
    // which an intermediate association could have existed.
    if (readPending) continuityUncertain = true;
    const generation = ++readGeneration;
    readPending = true;
    // A change notification makes the previous lease uncertain immediately.
    // Keep its association so a later confirmed matching lease may resume
    // suspended work; an actual association change gets a new revision below.
    current = null;
    sequence += 1;
    source.publish({
      sequence,
      contextKnown: false,
      contextRevision: `authorization-feed-${revision}`,
    });
    /** @type {AuthorizationLease | null} */
    let lease;
    try {
      lease = await feed.readAuthorizationLease();
    } catch {
      if (generation === readGeneration) {
        readPending = false;
        continuityUncertain = true;
      }
      // An unavailable read leaves context unknown. A later matching value
      // cannot prove continuity through this unresolved notification.
      return;
    }
    if (generation !== readGeneration) return;
    readPending = false;
    const nextAssociation =
      lease &&
      typeof lease.accountHandle === "string" &&
      lease.accountHandle !== "" &&
      typeof lease.keyHandle === "string" &&
      lease.keyHandle !== "" &&
      typeof lease.bearer === "string" &&
      lease.bearer !== ""
        ? { accountHandle: lease.accountHandle, keyHandle: lease.keyHandle }
        : null;
    if (
      continuityUncertain ||
      (nextAssociation === null) !== (association === null) ||
      (nextAssociation !== null &&
        association !== null &&
        (nextAssociation.accountHandle !== association.accountHandle ||
          nextAssociation.keyHandle !== association.keyHandle))
    ) {
      revision += 1;
    }
    continuityUncertain = false;
    association = nextAssociation;
    current =
      nextAssociation === null || lease === null
        ? null
        : Object.freeze({
            accountHandle: nextAssociation.accountHandle,
            keyHandle: nextAssociation.keyHandle,
            bearer: lease.bearer,
          });
    sequence += 1;
    source.publish({
      sequence,
      contextKnown: current !== null,
      contextRevision: `authorization-feed-${revision}`,
    });
  }

  const stop = feed.onLeaseChange(() => {
    void refresh();
  });
  const ready = refresh();

  return Object.freeze({
    provider: source.provider,
    ready,
    /** Application-only access to this adapter's lease representation. */
    currentLease() {
      return current;
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      readGeneration += 1;
      readPending = false;
      stop();
      current = null;
      source.end();
    },
  });
}

/** @typedef {{accountHandle: string, keyHandle: string, bearer: string}} AuthorizationLease */

// @ts-check
// Example application adapter for an event-based session API.
import { createContextSource } from "./context-source.js";

/**
 * Adapt an API that emits a complete current session when it changes.
 * This module owns the translation from that API's account and bearer fields
 * into the optional context source; it does not authorize DCA requests.
 *
 * @param {{onSessionChange: (listener: (session: SessionEventValue | null) => void) => () => void}} sessions
 */
export function adaptSessionEvents(sessions) {
  const source = createContextSource({
    sequence: 0,
    contextKnown: false,
    contextRevision: "event-session-0",
  });
  let sequence = 0;
  let revision = 0;
  let disposed = false;
  /** @type {SessionEventValue | null} */
  let current = null;
  /** @type {{accountRef: string, credentialRef: string} | null} */
  let association = null;

  const stop = sessions.onSessionChange((session) => {
    if (disposed) return;
    const nextAssociation =
      session &&
      typeof session.accountRef === "string" &&
      session.accountRef !== "" &&
      typeof session.credentialRef === "string" &&
      session.credentialRef !== "" &&
      typeof session.bearerToken === "string" &&
      session.bearerToken !== ""
        ? { accountRef: session.accountRef, credentialRef: session.credentialRef }
        : null;
    if (
      (nextAssociation === null) !== (association === null) ||
      (nextAssociation !== null &&
        association !== null &&
        (nextAssociation.accountRef !== association.accountRef ||
          nextAssociation.credentialRef !== association.credentialRef))
    ) {
      revision += 1;
    }
    association = nextAssociation;
    current =
      nextAssociation === null || session === null
        ? null
        : Object.freeze({
            accountRef: nextAssociation.accountRef,
            credentialRef: nextAssociation.credentialRef,
            bearerToken: session.bearerToken,
          });
    sequence += 1;
    source.publish({
      sequence,
      contextKnown: current !== null,
      contextRevision: `event-session-${revision}`,
    });
  });

  return Object.freeze({
    provider: source.provider,
    /** Application-only credential read, paired with the current event state. */
    readBearerCredential() {
      return current ? `Bearer ${current.bearerToken}` : null;
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      stop();
      current = null;
      source.end();
    },
  });
}

/** @typedef {{accountRef: string, credentialRef: string, bearerToken: string}} SessionEventValue */

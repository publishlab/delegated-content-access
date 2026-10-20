// @ts-check
// Checked menu participant. The host calls view on timer/resume and invokes an
// action directly from the click; account hints never authorize a DCA request.

/**
 * @param {import("../implementation/account-source.js").AccountProvider} provider
 * @param {() => number} [now]
 */
export function createAccountMenu(provider, now = () => Date.now()) {
  /** @type {import("../implementation/account-source.js").AccountSnapshot | null} */
  let current = null;
  let live = true;
  const stop = provider.subscribe((snapshot) => {
    if (!live || (current !== null && snapshot.sequence <= current.sequence)) return;
    current = snapshot;
  });
  function view() {
    const time = now();
    const fresh =
      live &&
      current !== null &&
      Number.isFinite(time) &&
      time >= current.observedAt &&
      time < current.validUntil;
    return {
      signedIn: fresh && current !== null ? current.signedIn : "unknown",
      actionReady: {
        signIn: !!(
          fresh &&
          current !== null &&
          current.actionReady.signIn &&
          typeof provider.actions.signIn === "function"
        ),
        signOut: !!(
          fresh &&
          current !== null &&
          current.actionReady.signOut &&
          typeof provider.actions.signOut === "function"
        ),
        openAccount: !!(
          fresh &&
          current !== null &&
          current.actionReady.openAccount &&
          typeof provider.actions.openAccount === "function"
        ),
      },
    };
  }
  return {
    view,
    /** @param {import("../implementation/account-source.js").AccountAction} action @returns {Promise<import("../implementation/account-source.js").ActionOutcome>} */
    invoke(action) {
      const method = provider.actions[action];
      if (!view().actionReady[action] || typeof method !== "function")
        return Promise.resolve("unsupported");
      try {
        const result = method(); // Initiate inside the click, without a queued hop.
        return Promise.resolve(result).then(
          (value) =>
            value === "started" || value === "unsupported" || value === "failed" ? value : "failed",
          () => "failed",
        );
      } catch {
        return Promise.resolve("failed");
      }
    },
    dispose() {
      if (!live) return;
      live = false;
      current = null;
      stop();
    },
  };
}

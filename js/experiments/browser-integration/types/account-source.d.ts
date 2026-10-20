export type AccountAction = "signIn" | "signOut" | "openAccount";
export type ActionOutcome = "started" | "unsupported" | "failed";
export type ActionReadiness = {
  signIn: boolean;
  signOut: boolean;
  openAccount: boolean;
};
export type AccountSnapshot = {
  sequence: number;
  observedAt: number;
  validUntil: number;
  signedIn: "yes" | "no" | "unknown";
  actionReady: ActionReadiness;
};
export type AccountActions = Partial<Record<AccountAction, () => Promise<ActionOutcome>>>;
export type AccountInitiators = Partial<
  Record<AccountAction, () => ActionOutcome | Promise<ActionOutcome>>
>;
export type AccountListener = (snapshot: AccountSnapshot, stop: () => void) => void;
export type AccountProvider = {
  subscribe: (listener: AccountListener) => () => void;
  actions: AccountActions;
};
/**
 * The adapter supplies original times and sequence; late replay never refreshes
 * them. Calling an action starts the upstream function synchronously, before
 * returning its promise, so a popup-sensitive click keeps its activation.
 *
 * @param {AccountSnapshot} initial
 * @param {AccountInitiators} [actions]
 * @returns {{provider: AccountProvider, publish: (snapshot: AccountSnapshot) => boolean, end: () => void}}
 */
export declare function createAccountSource(
  initial: AccountSnapshot,
  actions?: AccountInitiators,
): {
  provider: AccountProvider;
  publish: (snapshot: AccountSnapshot) => boolean;
  end: () => void;
};
/**
 * Explicit adapter mapping for the deployment guide's local optional hint.
 * It creates no source association, context revision or entitlement.
 * @param {{state: "signed-in" | "signed-out" | "unknown", observedAt: number, validUntil: number}} account
 * @param {number} sequence
 * @param {ActionReadiness} actionReady
 * @returns {AccountSnapshot}
 */
export declare function accountFromLocal(
  account: {
    state: "signed-in" | "signed-out" | "unknown";
    observedAt: number;
    validUntil: number;
  },
  sequence: number,
  actionReady: ActionReadiness,
): AccountSnapshot;

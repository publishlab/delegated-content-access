// An independently authored static participant, checked against emitted types.
import type { ClientRegistry, RegistryKey } from "../types/registry.js";
import type { ContentHandler, ContentInput } from "../types/content-handler.js";
import type { ContextSnapshot, ContextSourceProvider } from "../types/context-source.js";
import type { AccountAction, AccountSnapshot, AccountProvider } from "../types/account-source.js";

const articleKey: RegistryKey = {
  interface: "dca.content-handler",
  major: 1,
  name: "article",
};

// @ts-expect-error registry major versions are numeric
const wrongKey: RegistryKey = { interface: "dca.content-handler", major: "1", name: "article" };

const knownContext: ContextSnapshot = {
  sequence: 1,
  contextKnown: true,
  contextRevision: "session-generation",
};

// @ts-expect-error a context snapshot requires an explicit revision
const wrongSnapshot: ContextSnapshot = { sequence: 2, contextKnown: false };

const account: AccountSnapshot = {
  sequence: 1,
  observedAt: 1_800_000_000_000,
  validUntil: 1_800_000_060_000,
  signedIn: "unknown",
  actionReady: { signIn: true, signOut: false, openAccount: false },
};

/** @param {ContentInput} input */
function renderArticle({ value, commit }: ContentInput) {
  if (typeof value !== "string") return { status: "refused", reason: "not_text" } as const;
  const target = document.querySelector("article");
  if (target === null) return { status: "refused", reason: "no_target" } as const;
  return commit(() => {
    target.replaceChildren(document.createTextNode(value));
  })
    ? ({ status: "handled" } as const)
    : ({ status: "refused", reason: "stale" } as const);
}

const wrongCallback: ContentHandler = {
  connect: () => ({
    // @ts-expect-error callback status is the closed handled/refused/failed set
    handleContent: async () => ({ article: { status: "applied" } }),
    dispose() {},
  }),
};

/** @ts-expect-error arbitrary operations are not account actions */
const wrongAction: AccountAction = "refreshSession";

export function installParticipant(
  registry: ClientRegistry,
  context: ContextSourceProvider,
  accountProvider: AccountProvider,
  handler: ContentHandler,
  isEligible: () => boolean,
) {
  const remove = registry.register(articleKey, handler);
  const stopContext = context.subscribe((snapshot) => {
    if (snapshot.contextKnown) void snapshot.contextRevision;
  });
  let hint: AccountSnapshot | null = null;
  const stopAccount = accountProvider.subscribe((snapshot) => {
    hint = snapshot;
  });
  function signInFromClick() {
    const now = Date.now();
    if (
      hint === null ||
      now < hint.observedAt ||
      now >= hint.validUntil ||
      !hint.actionReady.signIn
    )
      return Promise.resolve("unsupported" as const);
    return accountProvider.actions.signIn?.() ?? Promise.resolve("unsupported" as const);
  }
  const selected = registry.lookup<ContentHandler>(articleKey);
  const connection = selected?.connect({
    delivery: { contentData: { article: { contentType: "text/html" } } },
    isEligible,
    values: { article: "strictUTF8" },
    targets: { article: renderArticle },
  });
  return { remove, stopContext, stopAccount, connection, signInFromClick };
}

void knownContext;
void account;
void wrongKey;
void wrongSnapshot;
void wrongCallback;
void wrongAction;

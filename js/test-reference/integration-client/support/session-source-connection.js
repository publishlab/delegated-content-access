// A small application-side lifecycle fixture. It exercises the selected
// context source and presenter boundary without executing an informative guide.
export function connectSessionSource(source, makeClient, openItemMap, placeNow) {
  let current = null;
  let lastSequence = -1;
  let disposed = false;

  function retire() {
    if (current) current.live = false;
    current = null;
  }

  async function unlockAndPresent(ctx) {
    await ctx.client.unlock(["bodytext"]);
    if (!ctx.live || current !== ctx) return;
    const opened = await openItemMap(ctx.client);
    if (!ctx.live || current !== ctx) return;
    placeNow(opened); // final guard and synchronous side effect in one turn
  }

  const unsubscribe = source.subscribe((snapshot) => {
    if (disposed || snapshot.sequence <= lastSequence) return;
    lastSequence = snapshot.sequence;
    if (!snapshot.contextKnown) {
      retire();
      return;
    }
    if (current && current.revision === snapshot.contextRevision) return;
    retire(); // before the successor owns this presenter
    const ctx = { client: makeClient(), revision: snapshot.contextRevision, live: true };
    current = ctx;
    void unlockAndPresent(ctx).catch((error) => {
      if (ctx.live && current === ctx) console.error(error);
    });
  });

  return () => {
    if (disposed) return;
    disposed = true;
    retire();
    unsubscribe();
  };
}

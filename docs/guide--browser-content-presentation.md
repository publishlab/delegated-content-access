# Placing protected article content

Status: Informative Draft

This guide covers publisher-owned browser placement and the optional
[HTML content-map candidate](spec-proposal--html-content-map.md). The browser
[content-handler contract](spec-proposal--browser-integration.md#5-content-handler)
and the HTML map are proposals. The reference
implements both for evaluation.
This guide adds no baseline requirement. The [browser integration guide](guide--browser-integration.md)
covers component discovery and session wiring.

## Choose the placement owner

For an ordinary article, the content owner selects the handler that renders opened
content. Use the site's existing renderer, or a rendering library supplied by its
CMS, issuer or another chosen vendor. Supplying keys and supplying rendering code
are separate roles, even when one vendor supplies both.

The application gives that handler opened content and a captured article destination.
The handler applies the site's HTML policy, updates its DOM or framework state, and
reports completion. It can then activate publisher-selected article behavior.
Neither an issuer response nor a field inside opened content selects executable code.

A `contentMap` gives an independent client enough information to reconstruct the
protected article slots without the owner's rendering scripts. A browser can explicitly
select the map renderer too, where its host can maintain stable targets. Merely shipping
a map does not execute it. Choose one placement owner for each destination; do not run
both renderers or silently switch to the map after the chosen handler refuses.

| Integration | Placement owner | What the map adds |
| --- | --- | --- |
| Ordinary publisher page | Owner-selected content handler | Optional independent reconstruction of the same article. |
| Framework-managed article | Handler updates the framework's state or uses its rendering API | An independent HTML representation; no outside writer takes over framework nodes. |
| Browser explicitly using the reference map renderer | Retained browser map session | Fixed-target HTML/plain-text placement and explicit continuation. |
| Independent service terminating DCA | Its selected map implementation | Article reconstruction without loading publisher scripts. |

## Handoff between client and presenter

Use the direct connection shown in
[one article, wired directly](guide--browser-integration.md#one-article-wired-directly).
The configured callback receives the item name, required media type, opened value and
a guarded commit operation. Content names belong to the captured delivery; `bodytext`
is not a page-wide destination name. Content descriptions and schemas are unnecessary
for ordinary HTML placement.

The integration captures the article and output lifetime before awaiting key acquisition.
Navigation, article replacement or a change in the owning context ends that lifetime
before the destination is reused. The callback checks eligibility at the actual effect,
including after its own asynchronous work. A successful unlock alone is not successful
placement. The [core lifetime rule](spec--core-protocol.md#221-logical-client-contexts-and-pending-work)
also applies when using a vendor's renderer. A remounted destination starts a new output
lifetime and needs disposal and a fresh connection;
[browser-integration Section 4.3](spec-proposal--browser-integration.md#43-association-replacement-and-end)
owns retirement and successor association.

For a complete article body, replace the teaser's children with the full opened body.
Do not append the full body to the teaser: teasers may already contain part of that
body, may be rewritten, or may omit embedded elements. Keep the enclosing article slot
stable. Remove its lock state and outside subscription prompt only after its required
content has been placed successfully.

## Author a map with the template

Generate rules beside the template that owns the destinations. Prefer a unique ID or
stable `data-*` marker to a broad class shared by nested article elements. Every rule
must match exactly one target in the locked document. Missing destinations are authoring
errors, not an instruction to choose the first match.

This publisher-composition example uses an existing reference-publisher result `render` and the
same full body string that was sealed as `bodytext`. The import path is relative to
this guide's repository directory; an application bundles the corresponding module.

```js
import { writeMappedDelivery } from "../js/extensions/html-content-map/adapter-publisher/writeMappedDelivery.js";

const contentMap = {
  version: "1",
  rules: [
    { item: "bodytext", op: "fill", target: "#article-body" },
    { item: "bodytext", op: "removeClass", target: "#article-body", class: "locked" },
    { item: "bodytext", op: "remove", target: "#article-subscribe" },
  ],
};

const html = writeMappedDelivery({
  dcaData: render.dcaData,
  sealedContent: render.sealedContent,
  contentMap,
  items: { bodytext: fullBodyHtml },
  page: carriers => `<!doctype html>
<html><head><meta charset="utf-8"><title>Example article</title></head>
<body>
  <article><div id="article-body" class="locked"><p>Public teaser.</p></div></article>
  <aside id="article-subscribe">Subscribe to read the article.</aside>
  ${carriers}
</body></html>`,
});
```

The `bodytext` record in `render.dcaData.contentData` has `contentType` `text/html`; the map has no type
table. `writeMappedDelivery` embeds it in the existing `dca-data` JSON and returns the
page after checking the rules, targets and author-time placement. Its `items` argument
contains author-time text, never a second plaintext delivery carrier. Only the public
teaser and encrypted content belong in the locked response. A publisher in another
language emits the same member and checks its actual rendered page.

A prompt inside the body slot disappears through `fill`; omit a separate `remove`
rule for it. A lock class on an ancestor can have its own `removeClass` rule. Optional
factboxes use separate items and slots, allowing one to remain locked while the body
opens. One item can fill several disjoint slots. A shared gate that depends on several
items opening together needs application handling; the map has no conditional program.

Targets in templates, shadow roots or parsing-sensitive table/select contexts are not
covered by this candidate. Put a whole rendered table inside a supported block slot,
or keep the site's custom handler for that case. The map is HTML/plain-text placement,
not a JSON-path language, a component renderer or a generic DOM patch language.

## Use the reference map renderer explicitly

For a browser host choosing map placement, the document must use UTF-8. The
reference checks the browser's selected `document.characterSet`; it does not refetch
already-decoded HTML to inspect its original bytes. Source-reading adapters perform
strict UTF-8 byte validation.

For explicit browser map placement:

```js
import { createBrowserMapSession } from "../js/extensions/html-content-map/integration-client/reconstructBrowserPage.js";

const placement = createBrowserMapSession({
  document,
  isEligible: () => articleContext.live, // captured article and owning context
  ...trustedClientOptions, // issuer, transport and context-scoped client setup
});
const first = await placement.run();
// Report first.report and retain placement for this eligible article/context.
```

After a new grant in the same eligible context, call `placement.run()` again to retry
still-locked items; add no automatic retry loop. A retained session refuses changed or
replaced targets rather than looking them up again, and a failed session needs a fresh
locked delivery. The required `isEligible` is checked again after asynchronous work and
at each placement effect; it must describe the captured context, not whichever context
is current later. The
[extension README](../js/extensions/html-content-map/README.md#explicit-reconstruction)
documents `run()`, `snapshot()`, `dispose()` and the server entry `createHtmlGateway`.

The reference checks the whole serialized document and element identities for external
changes. That is intentionally conservative: unrelated DOM activity such as an ad refresh
can also make a browser map run stale. For a dynamic page, use the owner's
handler as the ordinary renderer and exercise the map on the independently fetched
locked document. Do not broaden live-page ownership merely to make the map test pass.

## Completion, activation and serving

The map reports `complete` only after every mapped item and rule succeeds. `partial`
means remaining items are locked, with their teasers and prompts intact; it does not
assert why the issuer supplied no key. A defective item or placement failure is
`failed`, and is not a reconstructed result. The browser content handler uses its own
per-item `handled`, `refused`, `failed` and `stale` outcomes; do not treat those as
issuer entitlement decisions or confuse them with the map report.

Article markup may contain images, links and embeds. Filling that markup does not
prove that lazy loading, consent-gated embeds, analytics or other widgets have been
activated. The browser owner supplies those lifecycle hooks and observes its CSP and
Trusted Types policy. The independent map claim covers the declared slot content and
lock/prompt effects, not equivalent JavaScript execution or every interactive feature.

Keep the source URL and report with exported HTML. Relative URLs must retain their
meaning. A partial export is a terminal snapshot; retained DCA carriers must not cause
a browser initializer to unlock and place the body again. A host serving reconstructed
HTML chooses its output mode, script behavior and response-cache policy explicitly.
The map engine does not sanitize arbitrary pages or supply a general URL rewriter.

## Placement cases to exercise on an article integration

Use actual rendered templates and compare the protected body with the publisher's
intended full body. Include an ordinary article, an image/embedded-content article,
a layout with lock classes and an outside prompt, and an optional independently gated
factbox. Include mobile layouts, an empty teaser and nested body containers.
Check denied and partial grants, repeated completion notifications, navigation
while opening is pending, and missing or duplicate target markers.

Run the owner-selected browser handler and the independent map client against the
same sealed delivery. Compare body content and lock/prompt effects separately from
activation behavior. A map defect must not be mistaken for an issuer denial, and a
page must not acquire two placement owners. Start with templates whose
rendering contract is known, retaining the existing handler for unsupported layouts.

Record the template and actual selected handler, browser effects, independent
output and known limits. Preserve inline images, body ordering and relative-URL
meaning; later grants should place only still-locked items. The reference map's
whole-document stale check may be too conservative for unrelated DOM churn.
Measure article-size/repeated-placement costs against existing page budgets
before adding machinery. JSON paths, append, arbitrary attributes, script
execution, shadow-root traversal and a general template language are not part
of this candidate. The integrating application owner selects deployment validation;
the specification maintainers decide promotion separately.

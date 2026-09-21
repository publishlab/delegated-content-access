# Browser opened-content presentation sketch

Status: Informative Draft

This guide illustrates one possible JavaScript handoff. It makes the actor
boundary concrete, but it is not a proposal, selected interface, DCA profile,
normative browser API, or compatibility commitment.

## Purpose

DCA ends content opening with authenticated, decoded bytes. A publisher still
has to decide where those bytes belong in its page, how their representation
is rendered, and whether trusted page behavior runs afterward. The publisher
models the content and owns those decisions; an issuer-supplied or independent
client script should not guess them from selectors or issuer responses.

The handoff sits after DCA opening and before application rendering:

```text
Publisher render
  names and seals content as "bodytext_full"
                    |
                    v
DCA browser client                     Issuer
  reads the delivery
  sends an unlock request ----------> authenticates and decides access
  admits the response <-------------- returns granted key capability
  resolves the content key
  authenticates, decrypts and decodes the item
                    |
                    | { version, contentName, contentType, bytes, signal }
                    v
Publisher presentation callback
  maps "bodytext_full" to publisher-owned targets and rendering
  optionally runs publisher-registered activation code
```

Each actor stops where another actor already owns the decision. The issuer
does not select page targets or presentation behavior. The DCA client does not
interpret the application meaning of item names or execute opened content. The
publisher callback does not participate in authentication, entitlement, key
selection, or cryptography; it receives the result only after those operations
succeed.

The illustrated boundary uses one publisher-supplied presentation object:

```text
presentation.version = "1"
presentation.presentOpenedContent(item) -> void | Promise<void>
```

The caller always awaits `presentOpenedContent(...)`; a synchronous presenter
may return nothing. Return or promise fulfilment means the publisher finished
its presentation work. Throwing or rejecting means presentation failed; it
does not retroactively change the issuer decision or make the content
unopened.

## Callback record

| Member | Meaning |
| --- | --- |
| `version` | The callback-record version, currently the string `"1"`. |
| `contentName` | The admitted DCA item name, such as `bodytext_full`. The publisher maps it to application meaning and targets. |
| `contentType` | Publisher handling metadata. DCA v1 does not cryptographically authenticate this member, so the publisher must allow only the types configured for that content name. |
| `bytes` | A fresh `Uint8Array` containing the opened and representation-decoded item. The presenter may copy it and must not use mutation to communicate with the client. |
| `signal` | An `AbortSignal` for page disposal, navigation, or replacement. A presenter should stop before changing the page when it observes an aborted signal. |

The illustrated callback record does not include content keys, reusable period
capability, raw issuer responses, reader identity, an entitlement assertion,
selectors, callback names, or a separately interpreted script-source field.
The `bytes` remain opened content even when publisher code deliberately chooses
to treat them as executable input.

## Illustrated composition: explicit injection

When the publisher starts a client built to evaluate this sketch, it passes
the presentation object directly:

```js
startClient({ presentation });
```

`startClient` is illustrative; the current reference `createBrowserClient()`
does not yet accept a presentation option. Today its host calls the presenter
after `opener.open()`, as the exact-period integration guide demonstrates.
Explicit injection is one possible later composition because it makes
ownership and testing clear. In either illustrated composition, the client
calls the object only after it has successfully opened the item:

```js
await presentation.presentOpenedContent({
  version: "1",
  contentName,
  contentType,
  bytes: Uint8Array.from(openedBytes),
  signal,
});
```

## Illustrated independent-script discovery

When a publisher page and an independently loaded client script cannot share a
constructor call, this sketch uses a versioned same-realm discovery key:

```js
const presentationKey = Symbol.for("delegated-content-access.presentation.v1");
```

The publisher refuses a duplicate registration and installs the same
presentation object before loading or starting the client script:

```js
if (Object.prototype.hasOwnProperty.call(globalThis, presentationKey)) {
  throw new Error("A DCA presentation object is already registered");
}
Object.defineProperty(globalThis, presentationKey, {
  value: presentation,
  configurable: true,
});
```

An application that replaces its presenter first stops its client work,
aborts outstanding presentation signals, deletes this configurable property,
and then registers the replacement. It does not overwrite a live presenter.

The client reads it, requires `version === "1"` and a callable
`presentOpenedContent`, and otherwise reports that the page supplies no
supported presenter. It must not silently choose a DOM target or fall back to
executing opened markup.

The global symbol is discovery, not a security boundary. Every script in the
same JavaScript realm can discover, call, replace, or observe page objects
subject to ordinary platform controls. A publisher that does not trust an
issuer-supplied script with page privileges must not load it into that page
realm.

## Publisher mapping example

The publisher keeps target selection and rendering in its own code:

```js
const articleTarget = document.querySelector("[data-article-body]");
if (!articleTarget) throw new Error("The publisher page carries no article-body target");

const operations = new Map([
  [
    "bodytext_full",
    {
      contentType: "text/html",
      target: articleTarget,
      render: renderArticleFragment,
      activate: activateArticle,
    },
  ],
]);

const presentation = Object.freeze({
  version: "1",
  async presentOpenedContent({ version, contentName, contentType, bytes, signal }) {
    if (version !== "1") throw new Error("Unsupported presentation record version");
    if (!(bytes instanceof Uint8Array)) throw new Error("Opened content must be bytes");
    if (!(signal instanceof AbortSignal)) throw new Error("Presentation needs an AbortSignal");

    const operation = operations.get(contentName);
    if (!operation) throw new Error(`No publisher placement for ${contentName}`);
    if (contentType !== operation.contentType) throw new Error("Unexpected content type");
    if (signal.aborted) return;

    await operation.render(operation.target, bytes, { signal });
    if (!signal.aborted) await operation.activate?.(operation.target, { signal });
  },
});
```

One item may update one target, several targets, a framework store, or no DOM
at all. Repeating presentation should have publisher-defined replacement or
idempotence behavior; the client does not infer it.

## Rendering and activation

Opening proves that the bytes match the protected item; it does not decide how
the browser should interpret them. The publisher presenter may insert text,
parse and schema-check JSON, create an admitted `Blob`, sanitize and place an
HTML fragment, or update a framework component.

Rendering and activation should remain separate inside publisher code. The
ordinary pattern is to place content and then call a publisher-registered
activation function such as `activateArticle`. Opened content does not name a
callback and the client does not recreate script elements, evaluate source, or
bypass CSP.

A publisher may deliberately treat an opened item as executable code inside
its own presenter. Doing so grants that item page-script authority and makes
CSP, Trusted Types, module loading, lifecycle, and failure behavior the
publisher's responsibility. This sketch carries bytes to that decision; it
does not standardize or enable code execution by default.

## Open question: independent-script namespace

The callback shape does not require one discovery mechanism when the publisher
can inject the presentation object directly. Independently loaded scripts do
need an agreed name. This draft currently illustrates:

```js
Symbol.for("delegated-content-access.presentation.v1")
```

A conventional, inspectable alternative is:

```js
globalThis.DelegatedContentAccess.presentation.v1
```

The named global is easier for implementers and browser tooling to discover,
but it reserves a public string namespace and needs exact rules for creating
parent objects without overwriting another integration. The symbol avoids a
plain global property name but is less familiar and still provides no security
boundary. Before settling the fallback, test both with a publisher-controlled
page and an independently loaded client script. Whichever form is selected
must define the exact name, version lookup, registration order, collision
refusal, replacement lifecycle, and missing-presenter failure. Explicit
injection is the simpler illustrated baseline and uses the same presentation
object either way; whether it should be preferred remains open.

## Relationship to DCA

Presentation occurs after key acquisition, response admission, content-key
resolution, authenticated content opening, and representation decoding. It
does not alter DCA messages, access decisions, profiles, cryptographic
transcripts, or cache reach.

The [exact-period integration guide](guide--integration--exact-period.md#opened-bytes-and-page-presentation)
shows the operation that produces the callback inputs. The underlying design
questions and the possible future content-slot convention remain exploratory.
A future profile is justified only if independent publishers and clients need
common markup discovery or observable placement behavior beyond this callback.

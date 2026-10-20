# Recipient grant

Status: reference for a selected optional profile; implementation evidence,
not protocol authority

This extension implements `dca-profile-recipient-grant-unlock`. An accountless
recipient holds a signed bearer grant and presents it to one trusted issuer.
The issuer returns item content keys for the current render and nothing
broader.

The common signed form uses a compact `dca-share+jwt` token. A publisher,
issuer or configured delegate can mint it after the host authorizes the exact
scope. `signedGrant.js` supplies `mintSignedRecipientGrant`,
`verifySignedRecipientGrant` and `createSignedGrantStore`. The store plugs into
`createRecipientGrantIssuer`'s `grants.get` seam, preserving verified-render
admission before credential lookup. Opaque issuer-held references remain an
explicit local store choice; they do not establish signed-format conformance.
The host selects that store before lookup. Do not compose a failed signed lookup
with an opaque-store fallback such as `(await signed.get(r)) ?? opaque.get(r)`; an invalid
signed grant refuses that attempt.

## Authority

- [`spec-profile--recipient-grant-unlock.md`](../../../docs/spec-profile--recipient-grant-unlock.md)
  is the binding: presentation, issuer admission and result, client
  admission, and the conformance boundary in §6.
- [`spec--profiles.md`](../../../docs/spec--profiles.md) §8 selects the
  profile. It depends on the complete `dca-profile-baseline` profile; a
  browser caller also selects `dca-profile-browser-origin`.

Where this code and the specifications disagree, the specifications decide.

## Entrypoints

- `issuer.js` exports `createRecipientGrantIssuer(config, ...contributions)`. The host supplies
  the issuer identity, a grant store with `get(reference, {nowMs})` and its access
  policy. The result has `unlock(input)`, which takes the raw
  request, the publisher registration and the `Authorization` field value,
  and `browserHttp(preflightOrigin)`, which composes browser HTTP admission
  and CORS with the same endpoint. Optional `errorDetail: "uniform"` hides grant and DCA request
  refusal codes behind `rejected`; the default `"code"` preserves specific codes. HTTP method, malformed/missing Origin and
  preflight refusals retain the browser adapter's own responses.
  - The issuer forwards each contribution, such as `compactEcdhIssuerContribution()`, to base `createIssuerCore`.
    A contribution carries `name` and `envelopeProcedures` and nothing else. The issuer refuses any other member,
    such as a response section source or an extension coordinate, with `bad_config` at construction, so a
    contribution adds a way to open the permitted item keys and never another grant mechanism.
  - With compact ECDH, one opening-key entry with `envelopes: ["ecdh-p256", "compact-ecdh"]` serves both an
    ordinary and a compact-selected render; each answer holds only the granted item content keys.
- `client.js` exports `createRecipientGrantBrowserClient(config)`. The host
  supplies the current render, a trusted issuer selection (`issuerName`,
  `unlockUrl`, `publisherOrigin`, `resourceId`), the bearer reference and
  Fetch. It returns a base browser client whose `unlock` is limited to this
  attempt.
  - The client keeps its bearer reference for its whole life. `clearReaderContext()` drops the retained item keys
    and retires pending work, but a later `unlock` on the same client presents the same grant again. A new reader
    needs a new recipient client, built with that reader's own reference.
- `browserHost.js` exports `createRecipientGrantBrowserHost(config)`. The host
  injects a trusted issuer and Fetch, then captures a direct grant, an injected
  reader result or one query value (default `share`). It removes a captured
  query value with injected History, keeps the grant in this adapter instance
  until the host's required finite `retainUntil` deadline or an earlier
  unverified compact-token `exp`,
  and attempts only names still unresolved after ordinary access. Clearing or
  expiring the grant retires pending unlock and open results. Navigation and
  reload retention remain host policy.

The signed grant uses ES256 as the required public-key algorithm. HS256 is
available only with an explicitly onboarded HMAC key of at least 256 bits.
Trusted entries are scoped by public publisher identity and `kid`, then bind
the registration, sharing purpose, algorithm, required issuing authority,
allowed names and maximum lifetime. The issuer maps the authenticated grant
record to the verified publisher registration and resource before opening a
key. A logical audience is enforced when present; hosts serving multiple
applications require one through `requireAudience`. The same publisher token
can serve independently configured issuer routes without naming their hosts.
The host's `authorize` callback is the minting permission boundary: it must
check editorial, promotional, issuer-reader or delegated authority before
returning bounded claims. The helper always supplies a fresh random 128-bit
`jti`; authorized claims cannot set it. Revocation is an issuer-local callback.
All token times use integer seconds and exact admission boundaries. The issuer
passes one trusted captured instant as `grants.get(reference, {nowMs})`, and the
signed store uses that instant for signature-claim time admission as well as the
issuer's record-validity checks. An opaque store may ignore the extra argument;
its returned record is still checked at that captured instant. Direct signed
verification accepts the same optional third argument. Explicit instants must
be finite numbers; there is no skew allowance. A token issued after the captured
instant remains invalid even if the store's own clock has advanced. Each onboarded
key supplies its authority even when token `iss` is absent; revocation receives
that trusted entry.
The minter writes the required `typ`, `alg` and `kid` header members.
Verification accepts additional noncritical metadata but refuses `crit`,
`b64`, `jwk`, `jku` and `x5u`.

## What is implemented

- Presentation: the client sends one `Authorization: Bearer` field with
  `credentials: "omit"` and `redirect: "error"`, only to the configured
  endpoint, and refuses a render outside the configured publisher and
  resource. A refusal ends the attempt; it never retries with another issuer
  or credential.
- Issuer admission: the issuer verifies the publisher registration, the
  signed envelopes and, for a browser request, the signed origin before it
  looks up the grant. It then checks purpose, issuer, registration,
  resource, validity window and revocation.
- Issuer result: base issuer core decides under a policy scoped to the
  intersection of granted names, presented items and current host policy.
  It returns item content keys only; a request carrying period or chain
  material, or a result carrying either, is refused.
- Client result refusal: a response with `periodKeys`, `chainKeys`,
  `periodGeometry` or legacy `chainGeometry` fails with `bad_response` before
  any key is kept. Base
  response association still applies.

The issuer uses base `createIssuerCore` and `BrowserUnlockHttp`; the client
uses base `createBrowserClient` with its `resolverFactory` and transport
seams. Neither copies base code. The client passes
`clientBoundKeyCapability` through to base; no test here opens a
client-bound result.

A host placing an opaque bearer in a query must percent-encode the query value,
for example with `URL.searchParams.set("share", reference)` or `encodeURIComponent`.
`%2B` recovers a literal `+`; an unescaped `+` is decoded as a space by
`URLSearchParams` and cannot preserve that credential. Base64url is another
producer choice, not an additional restriction on valid bearer credentials.

The JS implementation supports direct bearer presentation. Optional issuer
session exchange and a PHP/CMS producer require separate host contracts and
are not claimed here. Removing the query value after arrival cannot erase it
from the initial server request, previews or upstream logs.

## What is not implemented

Per `spec--profiles.md` §8 and the binding's §6, this profile and this code
leave out:

- a grant issuance endpoint or share UI;
- a mandatory public link format; the adapter's query carrier is an optional
  host choice;
- issuer storage for the optional opaque form;
- a use-count rule;
- an immediate revocation distribution protocol.

## Tests

Run from `js/`:

```sh
node --test extensions/recipient-grant/test/*.test.js
node --test test-profiles/dca-profile-recipient-grant-unlock.test.js
node --test test-extensions/recipient-grant-compact-ecdh.test.js
```

The extension tests cover ES256 and optional HS256, issuer admission and
scope, browser carrier handling, redirects and result refusal. The signed
composition test opens original bytes through two independently configured
issuers and on a later render with changed content under the same item name.

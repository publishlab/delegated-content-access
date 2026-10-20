# DCA JavaScript reference

This tree holds the DCA reference implementation, written in plain JavaScript and
covering the protocol end to end.

Run commands from the repository root. Examples use explicit `js/` paths
unless a section specifies the package directory.

## Implementation and integration

- [Actor copy manifests](README.md#publisher-client-and-issuer-artifacts) - the runtime directories to copy for each actor:
  [publisher](copy-manifest--publisher.json), [issuer](copy-manifest--issuer.json), [client](copy-manifest--client.json)
- [js/extensions/](extensions/README.md) - optional capabilities and their composition boundaries
- [js/PORTING.md](PORTING.md) - contracts and behavior for implementations in other languages
- [js/demo/](demo/README.md) - example actors and runnable demonstrations

## Tests, experiments and verification

- [js/test-lib/README.md](test-lib/README.md) - test-only library code: reusable suites plus named adapters, harnesses, fixtures and helpers
- [js/test/README.md](test/README.md) - reference tests and shared-invariant rules
- [js/test-extensions/README.md](test-extensions/README.md) - selected-extension composition test routing
- [js/test-vectors/](test-vectors/) - recorded fixture and vector replays, excluded from the public gate
- [js/experiments/README.md](experiments/README.md) - the JavaScript experiments directory: executable proofs using alternate implementations, tests and unpromoted suites
- [js/evidence-benchmarks/README.md](evidence-benchmarks/README.md) - hand-run byte measurements the design documents cite
- [js/evidence-platform-tests/README.md](evidence-platform-tests/README.md) - hand-run empirical tests of runtime and host behavior
- [verification/conformance-primitives/](../verification/conformance-primitives/README.md) - cross-runtime operation-bridge
  conformance, its lanes, contract and entry points
- [verification/conformance-primitives-experiments/](../verification/conformance-primitives-experiments/README.md) - hand-run cross-runtime
  evidence for proposed or rejected constructions, outside the gate
- [verification/vectors/](../verification/vectors/) - versioned wire vectors for any implementation to replay,
  the `sets.txt` manifest listing which sets a full run walks, and where the runtimes disagree

The reference demonstrates a complete unlock exchange. A publisher seals content and signs the
render. An issuer verifies that one signed resource and reads the renderId out
of it. From that renderId the issuer rebuilds the render and the coordinate each
blob is bound to, then opens the blob there, over ECDH P-256 or RSA-OAEP, and
the client decrypts. A genuine blob presented at a coordinate where it was not
sealed fails the unseal, and the issuer reports it as one entry in `errors`
beside a 200. A key rollover produces that same 200 and that same entry, since
the issuer cannot tell those apart. Its periodKeys are derived,
shipped, cached and trial-unwrapped, so the second article of a period costs no
unlock.

An issuer can stop answering. A breaker per issuer url takes a failing issuer
out of the walk. A fallback issuer grants only after its own health probe finds
the primary down, and the client reuses that probe result for a TTL rather than
probing again on every request.

The integrity checks always run first, and an access policy the integrator
supplies then decides who may read what. A naive policy runs beside a strict one
on the same render, and the naive issuer hands back the article the strict
issuer holds back. The naive policy and the demo's emergency window exist to
show the mechanics; do not deploy either. Two issuers answer one page differently.
A shared period key can open matching items across their routes. Issuer-scoped
cache partitions control the reference client's lookup, not the key's
cryptographic reach. Keys travel direct or under the selected client-bound
transport. Response caches must preserve that transport's client-key and
authorization partitions; caching does not require direct transport.
Three things rotate: the issuer
keypair, the publisher signing key and the periodSecret. All three run against
markup that predates them, and the issuer answers a retired keyId with
200-with-errors and a keyId it never held with 400.

An integrator can also configure what the endpoint discloses, and what it
refuses before it reads anything:

- one uniform refusal body in place of the coded default
- a byte cap ahead of the JSON parse
- entry caps ahead of the engine
- an auth gate ahead of the health probe, the transport agreement and every signature

The auth gate is why an unidentified caller costs no asymmetric operation. All
of it is off unless configured.

`sh js/check` from the repository root runs the public JavaScript
package gate and forwards to the
package's pinned pnpm. Its stages are lint, formatting, the
admitted checked-JavaScript slice, source boundaries, vector-free JavaScript
reference behavior and the experiment tier. It runs no vector checks, repository vector
tooling, portable contract tests or cross-runtime conformance. Those are separately
selected commands. The gate neither requires PHP nor installs any conformance
toolchain, and its lint, formatting and checked-JavaScript stages run the
package's own devDependencies. Install those with
`corepack pnpm@10.23.0 --dir js install --frozen-lockfile --ignore-scripts`
and install the [browser prerequisite](#browser-prerequisite) before running the gate.

`sh js/check` is the repository entry point. It exits 0 when every
gated stage held, 1 when a gated stage failed, and 2 when the run was partial
and verified less than intended. This check covers the named JavaScript
stages; passing it does not establish full DCA conformance. The
[independent evidence documentation](../verification/README.md) describes
separately selected checks.

Cross-runtime conformance is opt-in and entirely separate from `check`. Its
[README](../verification/conformance-primitives/README.md) owns the current bridge model, lane layout,
corpus cases, toolchain behavior and commands. Keep
those details there rather than duplicating them in this overview.

The JavaScript reference suite's skip count depends on the environment; each
skip carries its reason in the test output. `markup-placement.test.js` checks that
`writeMarkupDelivery()` and `js/adapter-client/MarkupDeliveryReader.js`
agree through a small stub DOM.

A `contentName` carrying a colon - `sponsor:intro` under `premium:sport` -
seals, ships and decrypts here. `leak-checks.test.js` runs it from the JSON
member name through the aad to the selector.

`js/demo/browser/index.html` runs the same scenario the tests assert over.
Run `python3 -m http.server --directory js 8000`, then open
`http://localhost:8000/demo/browser/`. `js/experiments/` holds experiments
that displace a core module. The binding experiments retain alternatives to
the selected coordinate-bound seal: an earlier unbound seal under which the
same relabel succeeds, and whole-request refusal where core answers per item.

The binding variants sit under `js/experiments/`, in `_implementation/<shape>/` when more
than one experiment runs one and in `<experiment>/implementation/` otherwise. Each
module opens with a header giving what its shape reproduces, on which kind of
sealed blob, what that stops and what it leaves open against the shipped
binding, and that header is where the shape is written down. The comparison entry points under
`js/experiments/<experiment>/test/` run each move through both bindings on one request, so when a
move succeeds under one binding and is refused under another, the difference
comes from the binding and not from how each implementation was written.
Where one behavioral requirement is deliberately
registered against more than one implementation target, define a selected
requirement under `js/test-lib/suites/` and an unpromoted requirement under
`js/experiments/<experiment>/test-lib/suites/`; a variant must not carry a rewritten copy of that
shared requirement. Target-local characterization may remain separately named.
The experiments and test-lib READMEs own that boundary.

The six protocol fixture packages under `verification/fixtures/v1/` hold recorded
whole-protocol inputs used by the portable base contracts and the explicit
JavaScript vector tier. Each manifest names which consumer owns assertions over
each file. `verification/vectors/v1/`
holds base protocol evidence for any runtime to replay.
The six fixture packages are baseline issuer admission, period-key issuer
admission and issuer-client composition, chain-key geometry admission and
issuer-client prefix, and reference protocol regressions. Their specialized
recorders are `js/tools/record-period-key-composition.js`,
`record-chain-keys-geometry-admission.js` and `record-chain-keys-prefix.js`.
Regenerate both with
`node js/tools/make-vectors.js`, run from the repository root.
An unchanged regeneration is byte-stable: it retains a recorded ES256 signature
only when its exact header and payload are unchanged and the signature verifies
under the current public JWK. With `--check` the generator writes nothing and
fails when a checked-in file differs from a fresh generation; `pnpm test` runs
that check. The recorded BIND alternative lives under
`verification/vectors/v1/experiments/bind-on-renderId-and-slot/`. The
chain-key primitives and client-bound delivery packages live under
`verification/vectors/v1/profiles/dca-profile-*/`; neither changes the base vector
formats. Every set is selected by its path in `verification/vectors/sets.txt`.
The ECDH-P256 profile
injects its ephemeral pair and nonce so seal and open are reproducible; the
RSA-OAEP profile records open only because OAEP sealing is randomized. A fresh
runtime seal still draws a new ES256 `k`, so replayers compare header and
payload and verify the signature rather than comparing it.

Every vector set and the neutral fixture package carry `SHA256SUMS` beside
their payloads. `sh verification/vectors/check-sums.sh` checks a set against
it, with no JSON parser, no Node and no PHP. A bare `sha256sum -c SHA256SUMS`
checks one directory's recorded hashes; the script also walks every declared
set, checks its declaration and prints its phase, because a match means different
things either side of a freeze: on a devel set the bytes are the ones
`make-vectors.js` last wrote, and an unchanged run writes identical sums; on a
stable set they are frozen, so a mismatch is a hand edit or a bad merge.
`make-vectors.js` stops with an error instead of writing into a stable set.

`verification/conformance-primitives/` carries its own literal corpus of
stock-library cases and reads nothing here.

Those same packages hold the current recorded renders and
refusal inputs. The renderId refusals separately cover a 17-byte value and a
22-character value that decodes
to 16 bytes but has non-zero unused trailing bits, so width and canonical
base64url spelling are both replayed before private-key reach. The algorithm
substitutions - `alg: none`, and the same payload MAC'd under the publisher's
own public key - catch an issuer that pins the key and bytes but reads the
algorithm off the header. The bound-carrier fixture uses `vectorFormat` 4: it
records two deterministic ECDH seals, their coordinate refusals, and a recorded
RSA-OAEP open under the variant's binding grammar.

## Browser prerequisite

The gate requires Node 22.22.2, pnpm 10.23.0 and headless Chromium with its
runtime libraries. Browser tests are part of the required reference and
experiment stages; without the executable, the gate exits 2 because required
evidence could not run.

The harnesses use `DCA_ORACLE_BROWSER` when it names an existing executable.
Otherwise, when that variable is unset or empty, they look under
`~/.cache/puppeteer/chrome-headless-shell/` for the Linux x64
`chrome-headless-shell` executable. They do not search PATH. A nonempty override
that names a missing file does not fall back to the cache.

For Linux x64, install the browser in the harness's default cache with:

```sh
corepack pnpm@10.23.0 dlx @puppeteer/browsers@3.2.2 install chrome-headless-shell@152.0.7977.75 --path "$HOME/.cache/puppeteer"
```

The command downloads the browser; install the system runtime packages listed in
`deb.deps` or `rpm.deps` beside the downloaded executable for your Linux distribution.
On other platforms, set `DCA_ORACLE_BROWSER` to the executable path printed by the
install command. `DCA_ORACLE_BROWSER_LIBS` can name a directory containing extra
libraries. When unset, the harness uses `~/.cache/chrome-libs` if it exists. The
harness prepends the selected directory's `lib/x86_64-linux-gnu`,
`usr/lib/x86_64-linux-gnu` and `lib64` subdirectories to `LD_LIBRARY_PATH` and
uses its `etc/fonts` as `FONTCONFIG_PATH`. If the selected directory does not
exist, the browser uses the inherited environment and system libraries.
A failed browser launch fails the browser check.

## Runtime

The base slices are plain ESM with no dependencies and no build step. The
package, [`package.json`](package.json), declares one runtime dependency,
`parse5`, for the adapters of the proposed
[HTML content-map extension](extensions/html-content-map/README.md);
no base slice imports it. The base slices use WebCrypto only: `crypto.subtle`,
plain objects, `TextEncoder`/`TextDecoder`. No
Node imports, no `Buffer`, so the identical files run under `node --test` and
under `<script type="module">`. `node:test` appears only in test files, and
`node:child_process` only in the one that spans two runtimes. Types come from
JSDoc with `// @ts-check`, so there is nothing to compile.

That is a property of the checked-in reference, not a deployment restriction.
An extracted role is static ESM with a public entry, and an implementer may
bundle it with their integration code into an artifact that keeps none of the
reference tree's internal filenames or paths.

The browser page uses `crypto.subtle`; serve it from the web root documented
above.

## Actor integration and package reference

Reusable publisher, issuer and client implementations live here as plain
JavaScript modules. Start with the role integration entries and copy manifests
below; optional capabilities live under `extensions/`.

## Run one baseline exchange

From this directory:

```sh
node example--baseline-exchange.js
```

The [runnable example](example--baseline-exchange.js) uses only the public role
entries and JSON adapters. It generates fresh local keys, publishes `bodytext`,
serializes the delivery and both unlock messages, verifies the publisher at the
issuer, and opens the genuine plaintext twice with one issuer request. Its
in-process transport is a wiring example, not an HTTP server or browser-origin
binding. The [smoke test](test-reference/integration-client/baseline-example.test.js)
runs the same example.

| Host input          | Owner and purpose in the example                                                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Signing private key | Publisher signs the resource claims; issuer registration holds its verification key.                                         |
| Opening private key | Issuer holds it under the selected registration and issuer/keyId pair; publisher receives only its public key.               |
| Registration        | Issuer host selects the trusted publisher, verification key and scoped opening-key lookup.                                   |
| Reader and policy   | Issuer host supplies the authenticated principal and explicitly permits this reader/article. No request field grants access. |
| Issuer route        | Client host selects the trusted unlock URL and transport.                                                                    |
| Time and randomness | Publisher host supplies the clock and cryptographic random bytes; the example fixes time and generates fresh randomness.     |

Replace these local example inputs with deployment-owned configuration and
caller authentication. Select optional capabilities separately using the
[extension role entries](extensions/README.md).

### Inspect one acquisition attempt

`open(name)` acquires a missing key and then opens locally. Its `no_key` error
alone does not distinguish denial from an unavailable issuer. If the UI needs
that distinction, make the attempt explicit using an existing configured client:

```js
const attempt = await client.unlock(["bodytext"]);
// Inspect attempt.status, attempt.skipped and attempt.application locally.
// A skipped attempt has no HTTP status. A transport failure may reject instead.
const opened = await client.openLocal("bodytext");
// Hand opened.bytes and opened.contentType to the application's handler.
```

Handle `openLocal()` failure and transport exceptions in the host UI. A 503 or
an indeterminate transport outcome is not authoritative entitlement denial;
interpret a completed refusal under the selected issuer/binding contract.
Do not call `unlock()` again merely to diagnose a failed `open()`: that is a
second acquisition attempt. `openLocal()` makes no issuer request, and can
succeed with retained capability even when this attempt supplies no new key.

## Runtime directories

| Directory                                                              | Purpose                                                  |
| ---------------------------------------------------------------------- | -------------------------------------------------------- |
| `integration-publisher/`, `integration-issuer/`, `integration-client/` | Host-facing actor entry points and composition           |
| `core-publisher/`, `core-issuer/`, `core-client/`                      | Actor protocol behavior                                  |
| `adapter-publisher/`, `adapter-issuer/`, `adapter-client/`             | Delivery, transport and storage adapters                 |
| `core-shared/`, `core-shared--*/`, `ports/`                            | Shared primitives, contracts and host ports              |
| [extensions/](extensions/README.md)                                    | Optional capabilities, selected separately               |
| [demo/](demo/README.md)                                                | Example applications; excluded from actor runtime copies |

Use the [publisher](copy-manifest--publisher.json),
[issuer](copy-manifest--issuer.json) or [client](copy-manifest--client.json)
copy manifest for the exact runtime directory selection. The manifests select paths explicitly under `layers.core.paths`,
`layers.adapters.paths` and `layers.integration.paths`, with one path per line.
Paths are relative to `root`. A literal selects one file; `directory/*.js`
selects direct JavaScript children without recursion. No wildcard is implicit;
recursive patterns are not supported. The full actor copy is the union, with
overlapping files selected once; preserve relative paths. Layer names identify the
source responsibility, not independent deployment packages: integration uses
lower layers, and selecting core alone leaves host composition to you. Issuer
`ports/` belongs to the integration layer.
[PORTING.md](PORTING.md) describes the contracts for ports to other languages.
Test, evidence and experiment directories are described [later](#where-files-go).

Recorded keys, ciphertexts and fixtures used by this tree are generated test
material. They are not production keys or deployment configuration.

## Publisher, client and issuer artifacts

Publisher, client and issuer are peer source roles. Client and issuer code runs
in separate deployment and trust boundaries even when one team owns both.
Shared modules are included in each relevant output, so the sharing happens in
the source; at runtime each role holds its own copy.

Each role has a supported source-copy entry under `integration-publisher/`,
`integration-client/` or `integration-issuer/`. This tree provides no build
command, package export or generated bundle.
`reference.mjs` exports a test-facing surface and includes test support, so it
is not a deployment entry. Each role's copy manifest selects its supported
consumer slice, and the boundary check verifies its source closure.

```text
publisher
  core-shared/
  core-publisher/
  core-shared--client-publisher/
  core-shared--publisher-issuer/
  adapter-publisher/
  integration-publisher/

client
  core-shared/
  core-client/
  core-shared--client-issuer/
  core-shared--client-publisher/
  adapter-client/
  integration-client/

issuer
  core-shared/
  core-issuer/
  core-shared--client-issuer/
  core-shared--publisher-issuer/
  ports/
  adapter-issuer/
  integration-issuer/
```

A publisher integration selects the publisher core and supplies its render,
signing and key inputs. A client integration selects the client core and any
client adapters it needs, then supplies page reading, issuer transport, storage,
startup and content placement. An issuer integration selects the issuer core and its server
adapters or ports, then supplies HTTP handling, authentication, publisher
registration and keys, policy and state. Optional source is selected after the
base slice using the same role directories under
[`extensions/<name>/`](extensions/README.md). Teams choose their own bundler
and host composition; do not ship demo, test, evidence, tool or variant modules
as role code.

[`createPublisher.js`](integration-publisher/createPublisher.js) constructs a
fresh Sealer per `publish({resourceId, data, items})` and returns
`{dcaData, sealedContent}`. Its required host inputs include the origin,
clock, entropy, signing keys, issuer list and per-render issuer supply plan.
Optional compositions may supply `keySealing` and a render-wide
`contentKeyWrapStrategy` together with their matching supply planner. The entry
validates these through the Sealer and imports no extension; selecting an
implementation prototype does not make it an adopted protocol profile.

The supported composition call is `createPublisher(baseConfig, ...contributions)`.
A selected extension supplies a named contribution; core refuses two owners
of one seam before render work. For example, with host-selected contribution
objects:

```js
const publisher = createPublisher(baseConfig, wrapContribution, supplyContribution);
const render = await publisher.publish({ resourceId, data, items });
```

`core-publisher/publisherComposition.js::composePublisherConfig` returns frozen
`{ config, owners, plannerOrder }`. The `plannerOrder` list records wrapper
contribution names; the last listed wrapper is outermost. Composition copies
and freezes the issuer list and records, signing-key map, period options and
issuer limits. CryptoKeys and collaborators retain identity. The full port
contract is in [PORTING.md](PORTING.md#role-integration-operations).

[`copy-manifest--publisher.json`](copy-manifest--publisher.json) includes the
publisher adapter. The baseline delivery form is the serialized UTF-8 JSON
document of [data format Section 6](../docs/spec--data-format.md): a
publisher host calls `writeJsonDelivery(render)` for its bytes, and a client
reads them with `JsonDeliveryReader` and the publisher origin its host
supplies. Markup is the `dca-profile-html-carrier` profile's form: a markup host
calls `writeMarkupDelivery(render)`, and a client reads the page with
`MarkupDeliveryReader`.
[`createIssuerCore.js`](integration-issuer/createIssuerCore.js) composes the
engine, processor and endpoint with an explicit `accessPolicy`; enabling
period-key relay input is the host's independent `periodKeyInput` choice.
Explicit `periodCapabilitySource`, `contentKeySource`, capability encoders and
selected-extension input allow optional compositions through the same entry.
A complete extension engine may instead be injected as `engine`; it owns its
policy and engine options, and the processor selections it declares apply
unless the host names its own; a host selection that drops a declared entry
refuses construction. The entry imports no extension.
`createBrowserIssuer({core, registrationForKid, preflight, admitCaller, clock})`
composes the browser HTTP adapter for direct responses. Its host supplies raw
JSON and the observed Origin from the trusted HTTP boundary. Reusable
`admitBrowserRequest` provides the same admission order for hosts that own
response transforms or transactional metering. It freezes the parsed request,
selects registration and verifies publisher claims and Origin before policy or
opening. The engine independently verifies again when called. The host still
supplies authentication, registration, opening keys and policy. For
cookie-backed browser sessions, the client Fetch transport uses
`credentials: "include"` and the issuer composition enables `credentials: true`.
For bearer sessions, the transport uses `credentials: "omit"` and the issuer
enables `authorization: true`. [`copy-manifest--issuer.json`](copy-manifest--issuer.json)
includes the optional reference HTTP adapter beside the entry. Both manifests
copy every direct `.js` file in their named directories at one pinned commit.

[`integration-client/`](integration-client/) is the composition tier over the
client core and its adapters. `createDeliveryClient.js` takes a delivery reader
and host transport; `createBrowserClient.js` supplies the HTML reader for a page
root. Both provide `open(contentName)`, which obtains any missing key from the
configured issuer and returns `{contentName, contentType, bytes}`, and
`openLocal(contentName)` for retained capability only. `open()` reports any
keyless result as `no_key`; a host that needs to distinguish a denial from an
outage reads the attempt returned by `unlock()` before presenting a message.
`composeClient.js` builds
the cache, resolver, request builder and content opener a client keeps.
[`copy-manifest--client.json`](copy-manifest--client.json) names the directories
a consumer copies at a pinned repository revision. It selects every `.js` file
directly in those directories, not their subdirectories, extensions, demo or
tests. Record the commit you copied from; `git -C <checkout> rev-parse HEAD`
names it, and the manifest pins nothing on its own. Keep the six directory names
and their common parent; the modules import each other relatively across them.
The "client copy slice" cases in `test-base/import-boundary.test.js`
hold the manifest against the tree and the entry's permitted imports; you write
a copy check of your own: re-derive the slice from the manifest, compare each
file with the source at the revision you recorded, and fail on a file that
differs, is missing or is no longer named. Source copy is
the current boundary because the one known JavaScript consumer already uses
it, while a package or generated bundle would add a second release boundary
without serving another consumer or deployment format.

`createBrowserClient` is synchronous and uses static imports. The standard
browser globals its dependencies read must therefore exist before the entry is
imported; a host that needs a named pre-import capability report imports
`browserCapabilities.js` first. The host supplies one `issuerName`, a transport
and its trusted `unlockUrl` for acquisition. No URL is carried in the article.
A carried `unlockUrl` is ignored regardless of its type. The entry refuses an
invalid configured endpoint at construction with `bad_config`; HTTPS without
credentials or a fragment is required, except selected loopback development
HTTP. Missing endpoint configuration refuses acquisition before any request;
held capability still opens locally. The publisher must also have supplied
usable sealed material for that issuer: local configuration cannot create a
route for an absent issuer. Trusted ordered routes use `unlockRoutes`.
Without a
supplied cache, the composition creates a `PeriodKeyCache` backed by an in-memory Map. It accepts no `clock` option: a
host that needs clock-based eviction builds and supplies a cache with its clock
and eviction policy. A host that wants period keys to survive a reload passes
`storage` and `cacheNamespace` through this entry. Extensions remain
explicit option values and factories. One `unlock` call addresses one issuer.
It returns `{status, body, application}` after an HTTP exchange, or
`{skipped: 'no-eligible-route', application: null}` if no eligible coordinates
remain; a skip sends no request and has no HTTP status/body.
`unlockRoutes(contentNames, routes)` executes a trusted host-selected route
order. `retryUnavailable` covers still-needed families explicitly reported
unavailable; `retryOperational` covers a classified operational transport
failure or observable `5xx`. Both default off. An indeterminate Fetch result
never permits conditional fallback; a separately configured `independent` attempt
remains permitted.
The result is `{missing, attempts, failed}`. `failed` contains `{name, code}`
for known malformed item records or unsupported representations; failed items
are excluded from issuer requests, and valid siblings continue. `missing`
contains valid items that still lack an authenticating capability. Each
visited route adds one `attempts` record with a finite `outcome` token that
[PORTING.md](PORTING.md#role-integration-operations) lists; `answered` is
not plaintext success. Storage,
configuration, global delivery and unexpected faults remain visible.
The workflow recomputes missing items and filters
conditional requests to eligible families. Hosts own route selection, circuit
breaking, logical context lifetime, cache isolation and presentation eligibility.
Use the awaited reader-context reset below when retiring a reader on the same
configured client. Changed transport or publisher configuration needs a newly
configured client and appropriately scoped stores.

Ordinary `open(name)` preflights its requested item before its own cache/key
lookup or acquisition. Unsupported or malformed items throw their existing
item error before this call sends a request; preflight runs no decoder.
`openLocal(name)` runs the same preflight before its key lookup, so an item
with malformed handling metadata or ciphertext gives `bad_page` there too, whether or
not a key is held. This is
the reference integration ordering. Standalone `unlock` and independently
scheduled acquisitions remain separate; it promises no protocol-wide absence
of acquisition, metering or issuer observations.

A JSON host's item-opening call is:

```js
import { JsonDeliveryReader } from "./adapter-client/JsonDeliveryReader.js";
import { createDeliveryClient } from "./integration-client/createDeliveryClient.js";

const client = createDeliveryClient({
  reader: new JsonDeliveryReader(deliveryBytes, { publisherOrigin }),
  issuerName,
  unlockUrl,
  transport,
});
const { contentName, contentType, bytes } = await client.open("bodytext");
```

Here `deliveryBytes`, `publisherOrigin`, `issuerName`, `unlockUrl` and `transport` come from
the host. `unlockUrl` is trusted host configuration for that issuer, not a value read from the delivery
bytes; without it, an `open()` that needs acquisition refuses `bad_config`. Use `createFetchTransport` from
`adapter-client/fetchTransport.js` for a browser
Fetch port, with explicit credentials and acquisition cancellation settings.
The transport implements `post(url, request, {origin})` and returns
`{status, contentType, body}` with the response JSON parsed when an HTTP response
is observed. Locally attributable outages may reject with `code` equal to
`offline`, `timeout` or `no_route`. `timeout` applies only to a deadline
known to fire before the request was sent. A Fetch TypeError, opaqueredirect
or post-send deadline has an unknown HTTP outcome and must be tagged
`indeterminate_transport`; it does not authorize conditional fallback. The
tag works on an injected host
error without local DcaError identity. An independently selected route remains
permitted; unexpected untagged programming errors propagate and end this
walk. The host decides
whether and where the opened bytes may be presented.

For composition examples, start with the demonstration
[`Publisher`](demo/actors/Publisher.js),
[`Browser`](demo/actors/Browser.js) and
[`IssuerServer`](demo/actors/IssuerServer.js). They show where policies, keys,
state and transport are supplied, but they are examples rather than deployment
APIs. Reusable host-facing pieces live under `adapter-*` and [`ports/`](ports/).

### How profile selection reaches role code

Profile names are resolved at an integration or deployment boundary. That
boundary turns the resolved profile duties into narrow role configuration;
lower-level protocol code then handles concrete capabilities, carriers and
transforms instead of repeatedly branching on profile identifiers. Wire-member
presence alone does not select optional behavior.

Examples in this reference are:

- Period-key selection supplies the publisher with `periodKeySupply` and an
  issuer supply plan, enables client request relay with `relayPeriodKeys`, and
  enables issuer input processing with `periodKeyInput`. The cache and
  content-key resolver then handle period keys without reading a profile name.
- Content-representation selection produces an ordered `contentEncodings`
  list and supplies matching client decoders. The opener authenticates and
  decrypts before applying those transforms in reverse order.
- Chain-key selection composes publisher supply planning, a chain request
  builder, an issuer capability source and the applicable client cache or
  derivation behavior. Those injected components own the chain algorithms and
  the chain keys they hold; base period-key processing does not acquire chain
  branches.
- Client-bound custody supplies a client capability object and an issuer
  delivery profile. The response representation confirms what was selected;
  the key consumer does not infer custody from a publisher envelope.

A boolean is suitable for one narrow role duty such as relaying or accepting
period-key input. A profile that adds algorithms, state or a new
representation uses an injected component with the operations that duty needs.
Each checked-in scenario under [`test-profiles/`](test-profiles/) proves that
its independently configured roles form one complete path. The
[coverage index](test-profiles/README.md#coverage-index) distinguishes canonical,
partial and missing profile evidence.

## Checks and tests

Run these commands from the repository root. Each command names the `js`
package explicitly, then names whose implementation it tests and whether it
selects optional behavior.

The explicit `corepack pnpm@10.23.0` matches this package's `packageManager`
pin. Update both together when the package changes pnpm versions; relying on a
different root-level pnpm can fail before it reads the nested package pin.

| Intent                                                                                | Command                                                                                       |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Type-check the currently admitted JavaScript source slice                             | `corepack pnpm@10.23.0 --dir js run check:types`                                              |
| Check source boundaries and extension removability                                    | `corepack pnpm@10.23.0 --dir js run check:boundaries`                                         |
| Test the base JavaScript reference behavior                                           | `corepack pnpm@10.23.0 --dir js run test:reference:base`                                      |
| Test content compression only                                                         | `corepack pnpm@10.23.0 --dir js run test:reference:extension:content-compression`             |
| Test chain keys only                                                                  | `corepack pnpm@10.23.0 --dir js run test:reference:extension:chain-keys`                      |
| Test client-bound transport only                                                      | `corepack pnpm@10.23.0 --dir js run test:reference:extension:client-bound-transport`          |
| Test combinations of optional extensions                                              | `corepack pnpm@10.23.0 --dir js run test:reference:compositions`                              |
| [Test checked-in canonical profile scenarios](test-profiles/README.md#coverage-index) | `corepack pnpm@10.23.0 --dir js run test:reference:profiles`                                  |
| Test recorded fixtures and vectors                                                    | `corepack pnpm@10.23.0 --dir js run test:reference:vectors`                                   |
| Test all vector-free JavaScript reference behavior                                    | `corepack pnpm@10.23.0 --dir js run test:reference:public`                                    |
| Test portable contracts against the inventory-selected bindings                       | `corepack pnpm@10.23.0 --dir js run test:contract`                                            |
| Test every base target declared by one supplied binding                               | `corepack pnpm@10.23.0 --dir js run test:contract:base -- <binding-relative-to-js>`           |
| Test the checked-in reference binding's base targets                                  | `corepack pnpm@10.23.0 --dir js run test:contract:reference:base`                             |
| Test one target against supplied bindings                                             | `corepack pnpm@10.23.0 --dir js run test:contract:<target> -- <binding-relative-to-js> [...]` |
| Test repository vector tooling                                                        | `corepack pnpm@10.23.0 --dir js run test:tools`                                               |
| Test every checked-in experiment                                                      | `corepack pnpm@10.23.0 --dir js run test:experiments`                                         |
| Run the default local gate                                                            | `corepack pnpm@10.23.0 --dir js test`                                                         |
| Run the gate's behavior half without the portable contracts                           | `corepack pnpm@10.23.0 --dir js run test:unit`                                                |
| Run the default gate plus experiments                                                 | `corepack pnpm@10.23.0 --dir js run test:all`                                                 |
| Run the default gate in a single process                                              | `corepack pnpm@10.23.0 --dir js run test:single-process`                                      |

The package's `test` script (`corepack pnpm@10.23.0 --dir js test`) runs `test:unit` and then
`test:contract`. `test:unit` hands Node one glob over
the package, so it runs every `*.test.js` file outside `experiments/` and `test-contract/`:
source boundary checks, all reference behavior including the explicit vector tier, extension
and composition tests, and repository tooling tests. `test:contract` adds the local
portable-contract bindings. Neither runs experiments; `test:all` adds them. The
vector-free public selector is used by the public gate's `run-gate.js`. Neither command runs
cross-runtime conformance.

The [scoped profile evidence index](../verification/claim-index/README.md)
records role-specific support declarations and eight JavaScript scenarios with
exact test identities and selections. `claim:evidence` runs the referenced test
files; `claim:all` observes every test admitted by `test:unit` while keeping
evidence bound to those exact scenario/test selectors. Both report package
integrity separately from role evidence. These commands do not run the
stock-library comparison under `verification/conformance-primitives/`; that
independent suite has its own inventory and result. Current records are
catalogue-bounded and incomplete, not full normative conformance claims.
Run `claim:evidence` and `claim:all` with Node 24.19 or newer; the ordinary
Node 22 package gate does not run them.

`corepack pnpm@10.23.0 --dir js test` stops at the first command that exits non-zero, so a red
or incomplete `test:unit` leaves the portable contracts unrun in that
invocation. After fixing, run
`corepack pnpm@10.23.0 --dir js run test:contract`, or run
`corepack pnpm@10.23.0 --dir js run check`, which reports every stage whatever an earlier
stage did.

The `test` script runs the discovered test files in parallel, one process per
file, across however many cores the host has. On this host that is the faster
mode: 2026-09-20, `corepack pnpm@10.23.0 --dir js test` ran in 5.6s and the single-process run
in 11.7s, because per-file mode parallelises across cores. Use
`corepack pnpm@10.23.0 --dir js run test:single-process`
(`--experimental-test-isolation=none`) where that parallelism does not pay: a
host with few cores, or debugging state that leaks between test files. Node
sends no per-file summary in that mode, so the `test` script prints no
slowest-file list there.

## Checks

| Command                                       | Runs                                                                                                                                |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `corepack pnpm@10.23.0 --dir js lint`         | ESLint over every JavaScript file in `js` except `.stryker-tmp` and `node_modules`, the two directories `eslint.config.js` ignores. |
| `corepack pnpm@10.23.0 --dir js typecheck`    | The admitted checked-JavaScript slice, the same run as `check:types`.                                                               |
| `corepack pnpm@10.23.0 --dir js test`         | The default local gate: boundaries, contracts, reference behavior, tooling.                                                         |
| `corepack pnpm@10.23.0 --dir js run check`    | The public gate: lint, format, types, boundaries, vector-free reference behavior, experiments.                                      |
| `corepack pnpm@10.23.0 --dir js format:check` | Prettier, no writes; fails on any file `corepack pnpm@10.23.0 --dir js format` would rewrite.                                       |

`corepack pnpm@10.23.0 --dir js run check` runs `test-tools/run-gate.js`, which exits 0 when every stage
held, 1 when a stage failed and 2 when a stage ran partially. `sh js/check`
forwards to it.

The checked-JavaScript slice covers only the files `jsconfig.json` admits; the
section below says how to read that list.

## Runtime by directory

`core-*`, `adapter-*`, `integration-*`, `ports`, `demo` and every extension `core-*` directory
are runtime-neutral: WebCrypto and the shared web APIs, no Node or DOM globals.
`eslint.config.js` enforces that split through per-directory globals, and it carves out one
exception: `demo/browser/page.js` is the one DOM file. `tools`, `evidence-benchmarks`,
`evidence-platform-tests`, `experiments`, extension tests and tools, and every `test*` tree run
on Node's test runner. A `process` in neutral code or a `document` outside the browser file fails
`corepack pnpm@10.23.0 --dir js lint`.

## Checked-JavaScript scope

`corepack pnpm@10.23.0 --dir js run check:types` checks types statically; it does not replace a
behavioral test. The `include` list in `jsconfig.json` is the exact scope: `tsc` checks a file when a glob
or path in that list names it. Read the list for the current set; this README keeps no copy of it.

- The list admits every file under the top-level `core-*`, `adapter-*` and `ports` directories by glob.
- It names the other admitted files, such as role integration entry points, extension modules, bridge modules,
  test tools and experiment modules, one path or one directory glob at a time.

New files enter only after the expanded set is green.

At the WebCrypto boundary, `cryptoProvider.js` copies `Uint8Array` or
`ArrayBuffer` input into an ArrayBuffer-backed snapshot; shared-backed views
therefore do not cross into the DOM `BufferSource` contract. A file the
`jsconfig.json` list does not name, such as a remaining demo or extension file, a test, test support, a tool,
a benchmark or another experiment, stays off the admitted list. `tsc` reaches one
only when an admitted file imports it; the rest is existing type debt, not
silently checked code.

`corepack pnpm@10.23.0 --dir js test` uses exit 0 for complete agreement, exit 1 for a
completed check that disagreed, and exit 2 when proof marked todo remains, or
when the run matched no test file at all. A run that carries both a failure and
a todo exits 1: exit 2 says the run proved less than intended, not that
something disagreed. A named lane below the `test` script is a plain
`node --test` command and reports Node's own 0 or 1, so a todo inside one
reaches a developer on the next full run.
`corepack pnpm@10.23.0 --dir js run check` runs
every stage whatever an earlier stage reported, and exits 2 when a stage did
not complete.

Contract selectors never prepend a local implementation. The binding paths
after `--` give the complete selected implementation set. See
`test-contract/README.md` for the binding shape and target rules.

## Where files go

| File proves                                                                 | Directory                                                                                   |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Repository source boundaries or extension-absent barrel loading             | `test-base/`                                                                                |
| Repository tooling that composes several capability families                | `test-tools/`                                                                               |
| One source module's reference behavior, including cases selected for a port | `test-reference/<target>/`                                                                  |
| Cross-cutting JavaScript reference behavior                                 | `test/`                                                                                     |
| Recorded fixtures and vectors                                               | `test-vectors/`                                                                             |
| Portable behavior through an implementation binding                         | `test-contract/`                                                                            |
| Reusable JavaScript reference-test support                                  | `test-lib/`; `test-reference/support/` when a `test-reference/core-shared/` test imports it |
| One optional extension                                                      | `extensions/<name>/test/`                                                                   |
| Two or more optional extensions                                             | `test-extensions/`                                                                          |
| One complete scenario for a named protocol profile                          | `test-profiles/`                                                                            |
| Alternate or deliberately deviant behavior                                  | `experiments/<experiment>/test/`                                                            |
| Measured cost of a wire or content choice, hand-run, never gated            | `evidence-benchmarks/<name>/`                                                               |
| Empirical runtime or host behavior, hand-run, never gated                   | `evidence-platform-tests/`                                                                  |

Platform evidence tests execute assertions over runtime and host behavior. They
run by hand, sit outside the npm test lanes, and stand as evidence about a host
rather than as a claim about DCA correctness.

Place a test by ownership, not by which source it happens to import. A base
test may prove an injection seam with a local stub. A test whose behavior disappears with an
extension belongs to that extension, including normal integration with required
sibling implementations. Shared interactions without a primary feature owner
belong in `test-extensions/`. Runtime extension dependencies follow role rules
and must be acyclic; core remains extension-independent. Owned tests and bench
scenarios may import siblings without changing ownership.

## Browser denied-unlock cache

`createBrowserClient` installs a bounded ten-minute denial cache. It suppresses
an equivalent request only after a clean, admitted `notDelivered` report explicitly
denies every presented family. Missing keys, partial answers, ordinary HTTP
refusals and transport failures do not create hints. The default cache is in
memory; inject one shared instance and host storage to retain hints across loads.
`createDeliveryClient` has no automatic denial cache.

```js
import { DeniedUnlockCache } from "./adapter-client/DeniedUnlockCache.js";

const denialCache = new DeniedUnlockCache({
  context: session.accessContextId, // host-owned opaque identifier, no credentials
  storage: sessionStorage,
  namespace: "news-access",
  durationMs: 10 * 60_000,
});
const client = createBrowserClient({ ...browserConfig, denialCache });

// The issuer's session service explicitly knows the CURRENT reader has no access.
// The service discards callbacks from retired sessions before invoking this.
// This suppresses new articles too, only for this publisher and issuer route.
session.onNoAccess(async () => {
  await denialCache.denyContext({
    publisherOrigin: "https://news.example",
    issuerName: "exampleIssuer",
    unlockUrl: "https://issuer.example/unlock",
  });
});

// An entitlement refresh can keep delivered keys.
await client.clearAccessDecisions();

// On logout/account switch, stop old session callbacks and new client work first.
await client.clearReaderContext();
// After successful cleanup, install the successor authentication/context.
denialCache.setContext(nextSession.accessContextId);
```

The issuer selects `notDeliveredReport: "complete"` when it wants complete family
denials to be observable as `200` results. That report is optional on the wire.
Automatic hints include the exact render and requested material; they do not infer
that a reader denied one article is denied every article. `denyContext` is the
trusted issuer integration's explicit broader no-access decision; it suppresses
all requests for that publisher/issuer/endpoint in the current context, for this
cache's configured duration. Login/logout/access-change handling clears both
kinds of hint. An old pending declaration cannot refill a changed context.
Pass `denialCache: false`
to disable browser suppression. A host may inject a structural collaborator
implementing `capture`, `deny`, `denyContext`, `invalidate` and `setContext`; no
subclass is required. Hints contain fingerprints and deadlines, no keys,
credentials or response bodies. After a storage fault the instance uses memory
only; the host still invalidates every live instance on access-context changes.
Session callbacks must belong to the currently captured context. Discard a late
previous-session no-access notification before calling `denyContext`; the method
cannot determine the ownership of an event the host has already misattributed.

## Browser reader-context lifecycle

Both methods are available even with `denialCache: false`:

| Method                                | Clears                                                                     | Preserves                                                                       |
| ------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `await client.clearAccessDecisions()` | Denial hints and pending denial recordings                                 | Delivered item, period and chain capabilities; configured transport/backoff     |
| `await client.clearReaderContext()`   | Those decisions, retained keys, derived keys and response/opening sessions | Publisher/transport configuration and the configured recipient wrapping keypair |

Decision clearing sends no request. An already pending valid grant may still
arrive and be retained. Full reset synchronously retires the old generation when
called, before its promise is awaited. Old operations cannot return plaintext,
file grants, promote pending material or continue route fallback into the new
context. Retirement checks reject with local error code `context_retired`. Calls during cleanup
also reject. Start successor work after reset fulfills, or after acknowledging
the hint-only failure described below. Reset does
not wait for an old network request or cryptographic operation to finish.

The stock resolver, period cache and selected chain cache each clear their own
retained state. Persistent period-cache cleanup drains issued store operations, reads included,
and removes only that instance's namespace. A store operation that never settles
holds reset pending and keeps new work blocked. Every selected cleanup runs even if another
fails. A key/resolver cleanup failure rejects reset and permanently detaches this client
from access work; another reset cannot silently claim success. Resolve the
retention/storage failure and use a newly constructed client with a safe namespace.
If only decision cleanup fails, full reset rejects local
`access_decisions_clear_failed`, with the original thrown value as `cause`, after
all cleanup settles. Keys have cleared and access work may continue; this does
not claim the scheduling owner cleared. Repair or replace that owner before
relying on cleared decisions. A fresh client alone does not repair a reused
faulted `DeniedUnlockCache`: replace that cache too (and use the successor
access-context identifier). The stock cache retires local hints even when
persistence fails; arbitrary custom hooks may fail before doing so.
`clearAccessDecisions()` still reports the original fault directly. The denial
cache's strict lifecycle clear also reports a previous persistence failure; its
older `invalidate()` and `setContext()` methods remain best-effort scheduling
operations.

Browser construction requires a custom resolver to implement
`clearReaderContext(): Promise<void>`, recursively clearing its retaining owners.
Custom period and chain caches need the same method. Calling it must retire old
work synchronously; completion means old effects cannot reappear and durable
cleanup has succeeded. Custom denial collaborators must invalidate pending
recordings and surface cleanup faults through `clearAccessDecisions()` (or their
`invalidate()` fallback). A custom custody capability or chain profile that
retains delivered state must implement `clearReaderContext()` too; configured
stateless capabilities need no empty hook. Lower-level delivery construction
retains its existing opt-in denial behavior and does not require reset support
until full reset is requested. A lower-level full reset without key/resolver reset support
rejects `bad_config` and detaches the client after retiring the old generation.
Hosts that intend to reset can call a stock resolver's
`assertReaderContextReset()` at construction; arbitrary custom resolvers need no
assertion method. Browser construction checks the public caches it composed
and trusts a custom resolver's recursive duty for additional hidden owners.

Reset is local lifecycle management. It cannot revoke keys or plaintext already
copied outside the client, destroy application-owned keypairs, clear other client
instances or synchronize shared stores across tabs. Discard sibling cache
instances over a persistent namespace before reusing it: their later writes or
reconciliation can restore old material. Host transports must honor the
[HTTP binding's no-store rule](../docs/spec--http-binding.md) and must not share
pending requests or retained responses across authenticated reader contexts.
Identical POST bodies do not identify the same authenticated reader. The host retires old session
callbacks, coordinates those instances and namespaces, updates authentication,
and checks eligibility at the actual presentation boundary, including plaintext
returned before reset but not yet displayed. Failure of
`clearAccessDecisions()` preserves grants and does not detach access work.

## Source layout and releases

The package, actor directories, tests and tooling share this unversioned `js/`
root. Git release tags identify complete snapshots of code, specifications,
examples and tests. Maintained release lines and next-major development use
separate Git branches when needed. Package versions and supported DCA protocol
versions are independent: a new package major version may still implement DCA v1.
Protocol-versioned fixtures and vectors retain their version directories.

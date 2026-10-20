# Portable implementation test bridge

The **bridge** connects the unchanged JS test driver to a test target, but it
does not include the test target itself:

```text
JS test driver
  → bridge JS values
  → ┌───────────── bridge ─────────────┐
    │ serialize to bridge values (JSON) │
    │ transport as JSON                 │
    │ target adapter                    │
    │ materialize target-language data  │
    └───────────────────────────────────┘
  → test target (implementation under test)
```

Return values and errors travel back through the same bridge in reverse. The
terms, the value domain and the modes are defined in
[CONTRACT.md](_shared/CONTRACT.md#vocabulary).

The test driver selects fixtures, keeps expected values, makes assertions, and
owns the verdict. A target adapter only returns observations or a typed
refusal.

This is a best-effort coverage amplifier beside an implementation's native
tests. Overlay is the normal mode: its routes show partial external coverage.
Strict is evidence for one declared slice, never a claim that a whole test
target conforms. A test target that throws fails closed in both modes.
Overlay uses the reference before dispatch when the bridge cannot carry an
input. When the test target answered but the bridge cannot carry the answer
back, the call fails in both modes.

No bridge binds a DCA issuer or publisher contract; the role contracts are in
[js/test-contract/](../test-contract/).

## Choose a bridge

Each directory here without a leading `_` is a bridge, and its name is the
`DCA_BRIDGE` value:

- `js`: a JavaScript test target, named by `DCA_TARGET_ROOT`.
- `js-loopback`: the reference itself through the JS bridge. It checks the
  bridge, not an implementation.
- `php`: a PHP test target, named by `DCA_TARGET_ROOT`.

`_shared/` holds the driver, the runner, the named selections and
[CONTRACT.md](_shared/CONTRACT.md); you reach it through `pnpm test:bridge`.
This level holds only what a user needs to pick a bridge and start. Everything
else goes into `_shared/`.

## Runtime path

An unchanged Node test calls a generated import proxy, which uses
`ProcessBinding`, a Node worker thread, and one persistent adapter child process
over stdin/stdout to reach the test target:

```text
unchanged Node test → generated import proxy → ProcessBinding
  → Node worker thread → persistent adapter child process → test target
```

There is no HTTP, socket, or FIFO. Frames are a 4-byte unsigned big-endian
length followed by UTF-8 JSON. Each Node test process starts one adapter child.
Because unchanged synchronous exports must stay synchronous, the main test
thread waits with `SharedArrayBuffer` and `Atomics` while the worker owns the
asynchronous child-process I/O. The js-loopback child is Node loading the
reference implementation; the PHP child is `php adapter.php`.

## Run a bridge

From `js`, `pnpm test:bridge` takes a named selection or one test path
relative to `js`:

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-core
DCA_BRIDGE=js-loopback pnpm test:bridge test-reference/core-shared/geometry-bounds.test.js
```

It refuses without `DCA_BRIDGE`. Relative `DCA_BRIDGE` and `DCA_TARGET_ROOT`
paths resolve from the directory you ran pnpm in. The bridge finds the port
only through `DCA_TARGET_ROOT`; it names no repository and guesses no path. `public` in place of a
selection runs the package's `test:reference:public` tests through the
bridge. On 2026-09-23, 826 of its 1366 cases passed through `js-loopback`
and two were skipped. Most of the 538 failures are calls that return what the
bridge cannot carry back, such as a `CryptoKey` pair or a record holding
functions, or that change their argument. Some call a handle proxy's member
with an argument the bridge cannot carry, which has no reference fallback, or
hand a proxy to reference code that expects the reference class. The others
depend on function identity, a frozen result, a patched `crypto.subtle` or a
settled-geometry identity check, which no process bridge carries.

A direct Node run keeps every ordinary Node selector. Import the bridge module
itself:

```sh
node --import=./test-bridges/js-loopback/bridge.mjs \
  --test test-reference/core-shared/geometry-bounds.test.js
```

## Test your own implementation

There are three ways in. The shipped bridges are the templates.

- A JavaScript implementation uses the shipped JS bridge as it is. Point
  `DCA_TARGET_ROOT` at your modules, or at a directory of re-export files that
  maps the reference's module paths and export names onto yours, as
  [js/README.md](js/README.md) shows:

  ```sh
  DCA_BRIDGE=js DCA_TARGET_ROOT=/path/to/shim pnpm test:bridge portable-core
  ```

  To keep the root in a file, copy `js-loopback/bridge.mjs` as
  [js/README.md](js/README.md#checking-the-bridge-itself) describes.

- A PHP implementation uses the shipped PHP bridge as it is. Mark your classes
  with the `Dca\Porting\SourceModule`, `Dca\Porting\SourceExport` and
  `Dca\Porting\ReturnType` attributes, or with your own attributes named in
  the settings [php/README.md](php/README.md) describes, then point the bridge
  at the directory that holds them:

  ```sh
  DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php \
    DCA_TARGET_NAMESPACE='Your\Namespace' pnpm test:bridge portable-core
  ```

- An implementation in another language copies `js/` or `php/`. Point the
  copy's `../_shared/` imports at this directory, give `defineBridge` your
  adapter, and set `DCA_BRIDGE` to the path of the copied `bridge.mjs`:

  ```sh
  DCA_BRIDGE=/path/to/your/bridge.mjs pnpm test:bridge portable-core
  ```

  A compiled adapter gives `defineBridge` a `command` and no `adapter` path.
  `adapterCwd` sets the directory the adapter starts in, the current directory
  by default. `targetRoot` names your implementation's tree, which the adapter
  receives as `DCA_TARGET_ROOT`; it has no default. Your adapter speaks the
  protocol in [CONTRACT.md](_shared/CONTRACT.md).

## Portable selections

A named selection in `js/test-bridges/_shared/selections/` is a driver-owned,
language-neutral floor. Bridge-compatible cases register through one
test-local group binding, for example
`const portableCoreTest = portableTest("portable-core")`. Its versioned JSON
manifest names the containing unchanged test files, expected case count and
reference module exports that must be called externally. It may also list
[input mappings](_shared/CONTRACT.md#input-mappings): an argument that holds
an instance of a reference class crosses as that instance's data. The runner selects by
that group, forces strict routing and records a temporary transcript when
needed. A Node test reporter, `_shared/run-reporter.mjs`, counts each selected
file's cases as passed, failed, cancelled, skipped or TODO. The runner rejects
any case that did not pass, a passed count that differs from the manifest, a
run that left no case report, a reference fallback, an uncarried result, an
unmet required route and a selected test file with no external call. Test
titles and assertions remain ordinary Node tests. A passing run ends with a summary such
as `portable-core: N selected tests passed; required exports X/Y called`.

A selection whose name ends in `-dynamic` holds the cases of its partner whose
input a typed port cannot receive: a value whose JSON kind contradicts the type
the reference's JSDoc declares for the parameter, or a record member the
declared type does not have. A parameter declared `unknown` takes any value.
PHP runs both selections of a pair. A typed port runs the selections its API
can receive and need not run a `-dynamic` one.

`portable-core` covers finite scalar and record values, dense lists, bytes,
explicit instants, deterministic pure functions, and stock cryptography where
the unchanged test uses materializable data. It excludes callbacks, identity
and sparse-object behavior, browser objects, DOM or HTTP, actor composition,
and unknown native key handles. Where a case also passes a value the bridge
does not carry, such as `undefined`, `NaN`, an invalid `Date` or a `Symbol`,
or asserts a JavaScript error name, a portable twin beside it runs the rest,
and the direct case keeps them all.

`portable-core-dynamic` runs the cases of those files whose input contradicts
the declared type: a `formatT` date that is `null`, a string or a record, a
`currentT` label list holding a value that is not a string, a stated AEAD width
of `"16"` or `null`, a `null` binding for `bindValue`, and a period-key
profile name that is a number or `null`. The name, origin and binary-string
checks declare `unknown`, so their non-string cases stay in `portable-core`.

The portable AEAD cases round-trip through the test target or refuse a key,
a stated width or a carrier of the wrong width, so they prove the call path
and those checks, not AEAD correctness. The known-answer cases in
[verification/conformance-primitives/](../../verification/conformance-primitives/)
prove that. A self-test gives the unchanged geometry test a deliberately wrong
test target and requires the strict run to fail.

Run it from `js`:

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-core
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-core
DCA_BRIDGE=js-loopback pnpm test:bridge portable-core-dynamic
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-core-dynamic
```

The first command is a strict bridge-path proof. The second makes missing PHP
coverage visible as a failed required route; it does not remove a portable
test because one test target has not mapped that export yet.

`portable-publisher` is the first role-owned selection. It runs the unchanged,
stateless `planSiteResources` cases against the selected test target. The selection
excludes a source-layout assertion and the JavaScript-runtime assertions
about frozen identity, unsupported objects and sparse arrays; none can provide
evidence about another implementation through the declared bridge values.
Run the same driver-owned cases against two test targets from `js`:

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-publisher
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-publisher
```

`js-loopback` passes these cases with no reference fallback. Another
adapter runs the same selection and must meet the same manifest, count and
required export. This proves parity for the
selected stateless publisher-planning boundary, not stateful sealing or the
whole publisher role.

`portable-issuer` runs direct cases of the issuer's two pre-key request
checks, `checkVersion` and `checkEnvelopes`, without an engine or processor.
Both take a `DcaRequest`, so the manifest maps that argument: the request
crosses as its `toObject()` document, which the `js` adapter rebuilds into the
test target's own `DcaRequest` and the `php` adapter hands a port as a
record. `publisherFor` stays out: its registration holds a function and a
`Map`, and it returns that registration by identity, none of which the bridge
carries. Cases that build `IssuerEngine` or `IssuerProcessor` stay with the
issuer contracts in [js/test-contract/](../test-contract/).

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-issuer
```

`portable-object-core` runs two cases of
`test-reference/core-shared/dca-request.test.js`. The first parses a request
document with `parseDcaRequest` and reads it back with `toObject`. The request
object stays in the test target and the test holds a
[handle proxy](_shared/CONTRACT.md#object-handles), so both calls run in the
test target, and the manifest requires both: the export and the `DcaRequest`
member. The second is the portable twin of the parse refusal of a document
that is not JSON. `portable-object-core-dynamic` runs the other half, a
document that is a record where `parseDcaRequest` declares a string. The
direct case also refuses `DcaRequest.fromParts(null)`, the client's builder,
which runs in the reference, so that half stays in the direct run. The file's other cases build
requests with reference code or read getters, which a handle proxy does not
carry; they run only in a direct run.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-object-core
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-object-core
DCA_BRIDGE=js-loopback pnpm test:bridge portable-object-core-dynamic
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-object-core-dynamic
```

A self-test gives the cases a JavaScript test target whose document comes back
reordered, and one in PHP whose document drops the member nobody named; the
strict run fails on the test's own assertion in both. Neither target refuses
anything, so the twin fails beside it.

`portable-sealer-origin` runs five cases of
`test-reference/core-publisher/sealer-origin.test.js`. Each asks the reference
test factory `sealerForRender` in `core-publisher/testing/sealerFactory.js` for
a Sealer, with plain setup: the origin, the signing key ID, the issuer record,
a fixed instant, one random byte stream and known PEM test keys. The test
target maps that export in its own testing module and builds its own Sealer
from the setup, and the test holds a handle; `resource`, `content` and `seal` then run on that object. The first
case compares the signed `resourceJWT` origin with the one it configured, and
the issuer block's `keyId` with the configured key. The
second builds two Sealers in one adapter session, interleaves their calls and
checks that each render carries only its own instant, draws and content. The
next two render once per admitted origin besides the default one and check
that the Sealer signs it as given: three canonical IPv6 literals, and three
http origins on a localhost host under the development profile. The last
renders the default https origin with the development profile off and on,
and checks that both renders sign it. The manifest requires the factory and
the three members. The file's other tests
build publishers with reference code and run only in a direct run.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-origin
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-origin
```

`portable-sealer-period-keys` runs the period-key wire case of
`test-reference/adapter-client/periodkeys.test.js` through the same factory.
Its setup adds a fixed key for each of the two periods the render wraps under.
The case checks every value the render draws at its offset in the stream: the
render id, both wrap nonces, the content key each wrap
opens to, and the envelope nonces, up to the stream's last byte. The test then
opens each issuer envelope with the known issuer private key, using Node's
WebCrypto rather than a reference module: the content-key one must hold the
drawn content key, and each period one its fixed period key. The origin
selection's two-render case opens its content-key envelopes the same way. The
manifest requires the factory and the same three members.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-period-keys
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-period-keys
```

A self-test gives the cases a JavaScript factory that configures another
origin, and the strict run fails on the test's own assertion.

`portable-sealer-refusals` runs the refusal cases of
`test-reference/core-publisher/sealer-origin.test.js`,
`test-reference/core-publisher/sealer-options.test.js` and
`test-reference/core-publisher/sealer-factory.test.js` through the same
factory. Each builds on the origin case's plain setup with a member or two
changed, and may call members on the Sealer handle. It then asserts the DCA
error code the port refused with, plus the message where the case names one.
An adapter refusal or a bridge failure carries another code, so it fails
the case. The cases cover a missing or non-canonical origin, http outside the
development profile, a content type left out, descriptors the Sealer cannot
seal, and `seal` before a resource or a content item. They also cover issuer
and signing-key refusals, and the factory's own: a read past the end of the
random stream, a period the fixed keys do not list, and a key document that
is not the expected PEM. A fixed period key of the wrong width is refused by
the Sealer. The key-document cases pin the code alone, because the ports word
those messages differently. Cases whose input is a JavaScript function or a
sparse array stay in the direct run.

`portable-sealer-refusals-dynamic` runs the refusal cases of
`sealer-options.test.js` and `sealer-factory.test.js` whose input a typed port
cannot receive. They cover a setup, issuer or descriptor member the declared
record does not have, and a content value, content type, access-group list or
descriptor member of another JSON kind. They also cover a list where a random
stream or fixed period keys are declared, a record where a hook, a wrap
strategy or the planner function is declared, a clock or random source in
the setup, and PEM text where a native key is declared. The factory refuses a
supply or a key beside its test counterpart on the member being there and
reads none of it, so those cases give an empty record and PEM text where the
direct cases give a function and native keys. No case here seals, so the
manifest requires the factory and `content` alone.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-refusals
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-refusals
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-refusals-dynamic
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-refusals-dynamic
```

`portable-sealer-issuers` runs the mixed-issuer case of
`test-reference/core-publisher/sealer-composition.test.js` through the same
factory. It renders one page with two items twice from the same stream: first
with the ECDH issuer alone, then with an RSA-OAEP issuer after it. The shared
content entries and ciphertexts must match, and the issuer blocks must follow
the configured order. The case checks every value the render draws at its
offset in the stream, and opens each wrap and each ECDH envelope as the
period-key case does. An RSA-OAEP envelope draws nothing from the stream, so
the case cannot pin its bytes. It checks the 342-character width and opens
each envelope with the known RSA private key through Node's WebCrypto. The
plaintext must be exactly the BIND followed by the drawn content key or the
fixed period key. Apart from the descriptor cases below, the file's other
tests build their Sealers with reference code and run only in a direct run.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-issuers
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-issuers
```

`portable-sealer-descriptors` runs three content-representation cases of
`test-reference/core-publisher/sealer-composition.test.js` through the same
factory. Each renders the origin case's item twice on one stream: once as the
string, and once as its UTF-8 bytes, as a descriptor whose bytes carry three
declared layers, or as a descriptor with none. Bytes seal what the string
seals. The layered descriptor puts its layers on the wire in order, repeat
included, and base seals its bytes unchanged. The descriptor with no layers
renders what the string renders, with no `contentEncodings` member. A render
draws a fresh ECDH ephemeral key, so the cases compare each envelope's nonce
and the key it opens to rather than its bytes. The direct cases also change
the bytes and the layer list after `content()`; a bridge copies the arguments
at the call, so that half runs only in a direct run.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-descriptors
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-descriptors
```

`portable-sealer-runtime` runs one case of
`test-reference/core-publisher/sealer-factory.test.js`: a setup with no fixed
instant and no random stream, so the test target's factory builds its
runtime clock and secure random source. It keeps the test key documents.
Two renders must be stamped within a second of this host's clock readings
around them, and must draw different render ids and content keys. Content
encryption uses the implicit fixed zero nonce and draws no content nonce.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-sealer-runtime
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-sealer-runtime
```

`portable-key-sealing-refusals-dynamic` runs the portable twins of the
refusal cases of `test-reference/core-shared/keySealing.test.js`. A
`CryptoKey` does not cross to a synchronous PHP member, so each twin passes
`null` for the issuer key, and each refusal fires before `seal` or `open`
reads the key. `null` contradicts the declared `CryptoKey`, so the twins sit
in a `-dynamic` selection and no typed one. They cover a `kdf` or
`payloadBytes` option, a seal with no binding, a third algorithm, an
RSA-OAEP ephemeral key pair, a renderId one byte too wide, a content name
past the BIND field bound, and a payload that is a list, a number, or 15 or
17 octets. The direct payload case also refuses a 16-character string, which
a port that holds bytes in its string type takes as its octets
([PORTING.md](../PORTING.md#bytes)). The cases that need a real key stay in
the direct run.

```sh
DCA_BRIDGE=js-loopback pnpm test:bridge portable-key-sealing-refusals-dynamic
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/php pnpm test:bridge portable-key-sealing-refusals-dynamic
```

A selection may also route `new X` for a class it lists under
[`constructors`](_shared/CONTRACT.md#construct-an-object-of-a-claimed-class):
the test target builds the object from the constructor's arguments and the
test holds a handle proxy. No committed selection uses it yet.

The runner preserves streamed Node output and finishes with its exit status.
With `DCA_TIMING=1`, it also prints elapsed wall time.

`DCA_BRIDGE_MODE` selects `overlay` (the default) or `strict` for a direct
selector; a named selection always runs strict.
[CONTRACT.md](_shared/CONTRACT.md#modes) defines each mode.

## Adapter process contract

[CONTRACT.md](_shared/CONTRACT.md) is the language-neutral protocol: framing, startup
inputs, requests, value serialization, refusals, modes and evidence. The PHP
adapter's native type and reflection mappings are in
[php/README.md](php/README.md).

Each shipped adapter's `self-test/bridge-values.test.js` runs
[`_shared/bridge-values/`](_shared/bridge-values/suite.mjs) against a native
fixture in its `self-test/fixtures/`: every value type the adapter lists in
`valueTypes` must cross, be used and come back. A copied adapter adds the same
entry and fixture; `suite.mjs` says what the fixture's `identity`, `inspect`
and `transform` return.

## Optional logs and diagnostics

`DCA_LOG_DIR` names a caller-owned parent
directory. The runner creates one unique UTC run directory below it, for
example `run--20260922T143012Z--js-loopback--1234`, writes `run.json`, and
gives every worker unique transcript shards in that directory.
`run.json` records the command and selector, UTC start and finish, elapsed time,
exit status, bridge and mode, and the shard inventory. A named selection's run
directory also holds `case-counts.json`, the reporter's counts per test file
beside Node's run summary. A direct bridge import also creates an equivalent
process-scoped directory beneath this parent.

Transcripts record capability discovery, exact requests and responses,
infrastructure events and routes. The final record says the binding was
disposed; the verdict is the exit status in `run.json`. Transcripts may contain public
test fixtures including test keys; do not use production credentials. The
adapter never writes them. With `DCA_LOG_DIR` unset, the bridge creates no log
directories or files and skips transcript serialization.

`DCA_TIMING=1` enables per-call timing. When a log directory is present, each
worker writes a timing shard there; without one, it writes one concise timing
record to stderr. `DCA_TIMING=0` or an unset value avoids per-call timing work.

Set `DCA_DEBUG=1` for concise lifecycle, route, dispatch, and teardown lines on
stderr. `DCA_DEBUG=0` or an unset value is quiet; any other value is refused.
Debugging does not enable file logging.

# JavaScript reference and test entry points

Run these commands from the repository root. Each command names the `js/v1`
package explicitly, then names whose implementation it tests and whether it
selects optional behavior.

The explicit `corepack pnpm@10.23.0` matches this package's `packageManager`
pin. Update both together when the package changes pnpm versions; relying on a
different root-level pnpm can fail before it reads the nested package pin.

Recorded keys, ciphertexts and fixtures used by this tree are generated test
material. They are not production keys or deployment configuration.

## Publisher, client and issuer artifacts

Publisher, client and issuer are peer source roles. Client and issuer code runs
in separate deployment and trust boundaries even when one team owns both.
Shared modules are included in each relevant output, so the sharing happens in
the source; at runtime each role holds its own copy.

The client has one supported source-copy entry under `integration-client/`.
Publisher and issuer remain role source without deployment entries, and this
tree provides no build command, package export or generated bundle.
`reference.mjs` exports a test-facing surface and includes test support, so it
is not a deployment entry. The boundary check identifies which source belongs
to each role; only the client manifest below selects a supported consumer
slice.

```text
publisher
  core-shared/
  core-publisher/
  core-shared--client-publisher/
  core-shared--publisher-issuer/

client
  core-shared/
  core-client/
  core-shared--client-issuer/
  core-shared--client-publisher/

issuer
  core-shared/
  core-issuer/
  core-shared--client-issuer/
  core-shared--publisher-issuer/
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

[`integration-client/`](integration-client/) is the composition tier over the
client core and its adapters: `createBrowserClient.js` reads one page root,
addresses one issuer and takes the host's transport, and `composeClient.js`
builds the cache, resolver, request builder and content opener a client keeps.
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
`browserCapabilities.js` first. The host supplies one `issuerName` and a
transport, while the page supplies that issuer's unlock URL unless the host
overrides it. Without a supplied cache, the composition creates a
`PeriodKeyCache` backed by an in-memory Map. It accepts no `clock` option: a
host that needs clock-based eviction builds and supplies a cache with its clock
and eviction policy. A host that wants period keys to survive a reload passes
`storage` and `cacheNamespace` through this entry. Extensions remain
explicit option values and factories. One `unlock` call addresses one issuer;
route ordering, retries and circuit breaking stay with the host or demo actor,
and so does deciding what a reader sees for a status other than 200.

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

- Exact period selection supplies the publisher with `periodKeySupply` and an
  issuer supply plan, enables client request relay with `relayExactPeriod`, and
  enables issuer input processing with `exactPeriodInput`. The cache and
  content-key resolver then handle ordinary exact capabilities without reading
  a profile name.
- Content-representation selection produces an ordered `contentEncodings`
  list and supplies matching client decoders. The opener authenticates and
  decrypts before applying those transforms in reverse order.
- Period-chain selection composes publisher supply planning, a chain request
  builder, an issuer capability source and the applicable client cache or
  derivation behavior. Those injected components own chain algorithms and
  state; base exact-key processing does not acquire chain branches.
- Client-bound custody supplies a client capability object and an issuer
  delivery profile. The response representation confirms what was selected;
  the key consumer does not infer custody from a publisher envelope.

A boolean is suitable for one narrow role duty such as relaying or accepting
exact-period input. A profile that adds algorithms, state or a new
representation uses an injected component with the operations that duty needs.
Each checked-in scenario under [`test-profiles/`](test-profiles/) proves that
its independently configured roles form one complete path. The
[coverage index](test-profiles/README.md#coverage-index) distinguishes canonical,
partial and missing profile evidence.

| Intent | Command |
| --- | --- |
| Type-check the currently admitted JavaScript source slice | `corepack pnpm@10.23.0 --dir js/v1 run check:types` |
| Check source boundaries and extension removability | `corepack pnpm@10.23.0 --dir js/v1 run check:boundaries` |
| Test the base JavaScript reference behavior | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:base` |
| Test content compression only | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:extension:content-compression` |
| Test period-chain only | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:extension:period-chain` |
| Test client-bound transport only | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:extension:client-bound-transport` |
| Test combinations of optional extensions | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:compositions` |
| Test checked-in canonical profile scenarios (currently exact-period) | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:profiles` |
| Test recorded fixtures and vectors | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:vectors` |
| Test all vector-free JavaScript reference behavior | `corepack pnpm@10.23.0 --dir js/v1 run test:reference:public` |
| Test portable contracts against the inventory-selected bindings | `corepack pnpm@10.23.0 --dir js/v1 run test:contract` |
| Test every base target declared by one supplied binding | `corepack pnpm@10.23.0 --dir js/v1 run test:contract:base -- <binding-relative-to-js/v1>` |
| Test the checked-in reference binding's base targets | `corepack pnpm@10.23.0 --dir js/v1 run test:contract:reference:base` |
| Test one target against supplied bindings | `corepack pnpm@10.23.0 --dir js/v1 run test:contract:<target> -- <binding-relative-to-js/v1> [...]` |
| Test repository vector tooling | `corepack pnpm@10.23.0 --dir js/v1 run test:tools` |
| Test every checked-in experiment | `corepack pnpm@10.23.0 --dir js/v1 run test:experiments` |
| Run the default local gate | `corepack pnpm@10.23.0 --dir js/v1 test` |
| Run the gate's behavior half without the portable contracts | `corepack pnpm@10.23.0 --dir js/v1 run test:unit` |
| Run the default gate plus experiments | `corepack pnpm@10.23.0 --dir js/v1 run test:all` |
| Run the default gate in a single process | `corepack pnpm@10.23.0 --dir js/v1 run test:single-process` |

The package's `test` script (`corepack pnpm@10.23.0 --dir js/v1 test`) runs `test:unit` and then
`test:contract`. `test:unit` hands Node one glob over
the package, so it runs every `*.test.js` file outside `experiments/` and `test-contract/`:
source boundary checks, all reference behavior including the explicit vector tier, extension
and composition tests, and repository tooling tests. `test:contract` adds the local
portable-contract bindings. Neither runs experiments; `test:all` adds them. The
vector-free public selector is used by the public gate's `run-gate.js`. Neither command runs
cross-runtime conformance.

`corepack pnpm@10.23.0 --dir js/v1 test` stops at the first command that exits non-zero, so a red
or incomplete `test:unit` leaves the portable contracts unrun in that
invocation. After fixing, run
`corepack pnpm@10.23.0 --dir js/v1 run test:contract`, or run
`corepack pnpm@10.23.0 --dir js/v1 run check`, which reports every stage whatever an earlier
stage did.

The `test` script runs the discovered test files in parallel, one process per
file, across however many cores the host has. On this host that is the faster
mode: 2026-09-20, `corepack pnpm@10.23.0 --dir js/v1 test` ran in 5.6s and the single-process run
in 11.7s, because per-file mode parallelises across cores. Use
`corepack pnpm@10.23.0 --dir js/v1 run test:single-process`
(`--experimental-test-isolation=none`) where that parallelism does not pay: a
host with few cores, or debugging state that leaks between test files. Node
sends no per-file summary in that mode, so the `test` script prints no
slowest-file list there.

## Checks

| Command | Runs |
| --- | --- |
| `corepack pnpm@10.23.0 --dir js/v1 lint` | ESLint over the source it currently covers; `eslint.config.js` names the files still excluded. |
| `corepack pnpm@10.23.0 --dir js/v1 typecheck` | The admitted checked-JavaScript slice, the same run as `check:types`. |
| `corepack pnpm@10.23.0 --dir js/v1 test` | The default local gate: boundaries, contracts, reference behavior, tooling. |
| `corepack pnpm@10.23.0 --dir js/v1 run check` | The public gate: lint, format, types, boundaries, vector-free reference behavior, experiments. |
| `corepack pnpm@10.23.0 --dir js/v1 format:check` | Prettier, no writes; fails on any file `corepack pnpm@10.23.0 --dir js/v1 format` would rewrite. |

`corepack pnpm@10.23.0 --dir js/v1 run check` runs `test-tools/run-gate.js`, which exits 0 when every stage
held, 1 when a stage failed and 2 when a stage ran partially. `sh js/check`
forwards to it.

The checked-JavaScript slice covers only the files admitted by `jsconfig.json`;
it does not cover every file under `core-*`, `adapter-*` and `ports`.

## Runtime by directory

`core-*`, `adapter-*`, `ports` and `demo` are runtime-neutral: WebCrypto and the shared web
APIs, no Node or DOM globals. `eslint.config.js` enforces that split through per-directory
globals, and it carves out one exception: `demo/browser/page.js` is the one DOM file. `tools`,
`evidence-benchmarks`, `evidence-platform-tests`, `experiments`, extension tests and tools, and
every `test*` tree run on Node's test runner. A `process` in neutral code or a `document` outside
the browser file fails `corepack pnpm@10.23.0 --dir js/v1 lint`.

## Checked-JavaScript scope

`corepack pnpm@10.23.0 --dir js/v1 run check:types` checks types statically; it does not replace a
behavioral test. `jsconfig.json` names the admitted files explicitly. The first
slice covers:

- the reusable `core-shared` value, admission, geometry, markup-placement and
  AEAD/WebCrypto-provider utilities
- every crypto-free pairwise protocol module
- the publisher configuration
- issuer-supply planning and checked site-resource planner boundary
- the publisher `Sealer` and content-representation boundary
- the independent delivery/HTTP/eviction adapters

New files enter only after the expanded set is green.

At the WebCrypto boundary, `cryptoProvider.js` copies `Uint8Array` or
`ArrayBuffer` input into an ArrayBuffer-backed snapshot; shared-backed views
therefore do not cross into the DOM `BufferSource` contract. Role cores,
remaining adapters, ports, demo, extensions, tests, tools, benchmarks and
experiments remain outside this first slice as existing type debt, not silently
checked code. The deferred synthetic simulator does not exist yet and is not
part of this checked boundary.

`corepack pnpm@10.23.0 --dir js/v1 test` uses exit 0 for complete agreement, exit 1 for a
completed check that disagreed, and exit 2 when proof marked todo remains, or
when the run matched no test file at all. A run that carries both a failure and
a todo exits 1: exit 2 says the run proved less than intended, not that
something disagreed. A named lane below the `test` script is a plain
`node --test` command and reports Node's own 0 or 1, so a todo inside one
reaches a developer on the next full run.
`corepack pnpm@10.23.0 --dir js/v1 run check` runs
every stage whatever an earlier stage reported, and exits 2 when a stage did
not complete.

Contract selectors never prepend a local implementation. The binding paths
after `--` give the complete selected implementation set. See
`test-contract/README.md` for the binding shape and target rules.

## Where files go

| File proves | Directory |
| --- | --- |
| Repository source boundaries or extension-absent barrel loading | `test-base/` |
| Repository tooling that composes several capability families | `test-tools/` |
| Base JavaScript reference behavior | `test/`, `test-reference/<target>/` |
| Recorded fixtures and vectors | `test-vectors/` |
| Portable behavior through an implementation binding | `test-contract/` |
| Reusable JavaScript reference-test support | `test-lib/` |
| One optional extension | `extensions/<name>/test/` |
| Two or more optional extensions | `test-extensions/` |
| One complete scenario for a named protocol profile | `test-profiles/` |
| Alternate or deliberately deviant behavior | `experiments/<experiment>/test/` |
| Measured cost of a wire or content choice, hand-run, never gated | `evidence-benchmarks/<name>/` |
| Empirical runtime or host behavior, hand-run, never gated | `evidence-platform-tests/` |

Platform evidence tests execute assertions over runtime and host behavior. They
run by hand, sit outside the npm test lanes, and stand as evidence about a host
rather than as a claim about DCA correctness.

Place a test by ownership, not by which source it happens to import. A base
test may prove an injection seam with a local stub. A test whose behavior disappears with an
extension belongs to that extension. A test requiring sibling extensions
belongs in `test-extensions/` so neither extension depends on the other.

# Scenario bench

Run real publisher, issuer and client code for one resource or an explicitly
selected retained-reader workload, then inspect
the actual wire data, sizes, work, timings and retained client material.
This benchmark is an offline Node development tool, with no new dependencies. It does
not replace correctness or security tests and makes no conformance claim.
Content groups remain proposal code; reporting their profile identifier does
not adopt the proposal.

From `js/evidence-benchmarks/scenario-bench/`:

```sh
node cli.js --scenario scenarios/item.js --out /tmp/item-bench
node cli.js --scenario scenarios/chain-keys/groups.js --out /tmp/chains-bench
node cli.js --scenario scenarios/content-groups/groups.js --out /tmp/groups-bench
```

Each invocation defaults to one genuine full execution with fresh keys, no
warmup, two groups for the group cases, hourly periods, two source windows,
a render at 12:20 UTC and an issuer horizon through T18. A resource may have
several named items. Output directories must be fresh; ordinary runs never
overwrite tracked captures or previous results.

## Compare period keys and chains with content groups

For a matched publisher → issuer → client comparison, start with the
[saved comparison and reproduction guide](COMPARISON.md).
It records inputs, byte counts and checks that authorized content opens.
A fresh run with `--out` saves that run's exact wire payloads.
Content-group results remain proposal evidence; the dense ordinary case raises
message capacity beyond the current profile bound and is labelled experimental.

## CLI

Named arguments only; paths resolve from the invoking working directory.

| Option                                      | Meaning                                                                                                                                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--scenario MODULE`                         | Required local module exporting `scenario`; loading it executes local code.                                                                                                                  |
| `--input FILE` or `--input -`               | One JSON input object from disk or stdin; omitted fields use documented scenario defaults.                                                                                                   |
| `--scope publisher\|publisher-issuer\|full` | Stages to execute; default `full`. Missing stages are unmeasured.                                                                                                                            |
| `--runs N`, `--warmup N`                    | Independent measured samples (default 1) and fresh diagnostic warmups (default 0). Warmup artifacts remain in `warmupSamples`, excluded from summary statistics.                             |
| `--time-steps`                              | Collect available named construction timings, in addition to role timings.                                                                                                                   |
| `--count-crypto`                            | Count attempted WebCrypto calls in a dedicated isolated Node worker per sample.                                                                                                              |
| `--format text\|json`                       | Stdout presentation; default text. Diagnostics go to stderr.                                                                                                                                 |
| `--show SECTION,...` or `all`               | Select report sections for stdout. Text defaults to sizes/checks; JSON defaults to all.                                                                                                      |
| `--detail summary\|breakdown\|full`         | Text presentation detail; no change to execution.                                                                                                                                            |
| `--out DIRECTORY`                           | Save full `report.json` and each sample's exact wire messages under `sample-N/capture-NAME/`.                                                                                                |
| `--save NAME=FILE`                          | Export a section, `report`, or singular `delivery`, `dca-data`, `request`, `response` wire JSON. Repeat to save several. Capture exports require one run/one message; use `--out` otherwise. |

Sections are `setup`, `samples`, `captures`, `sizes`, `work`, `timings`, `cache`,
`checks`, and `summary`. `--save` destinations must be outside `--out`.
Selected views never rerun the scenario, omit verification, or enable observations
that were not collected. Failed required checks produce a nonzero exit, even
when hidden by the selected view. Available artifacts and failure checks remain
in the full report. Invocation errors also exit unsuccessfully.

```sh
cat /tmp/article.json | node cli.js \
  --scenario scenarios/content-groups/groups.js \
  --input - --format json --show sizes,cache --out /tmp/article-bench

node cli.js --scenario scenarios/item.js \
  --scope publisher --save dca-data=/tmp/item-data.json
```

The retained-reader scenario below supplies a bounded multi-resource workload
through the same CLI and engine. There is no generic sweep CLI, production
session API or time simulation framework. Independent comparison callers invoke
the engine again with fresh state.

## Inputs

The baseline item case accepts:

```json
{
  "publisher": {
    "resourceId": "article-17",
    "items": [{ "name": "bodytext", "value": "Saved article text", "contentType": "text/plain" }]
  },
  "issuer": { "authorizedItems": ["bodytext"] }
}
```

`authorizedItems: null` grants all requested authored items; an explicit list
selects the permitted items. The publisher also accepts `origin`, `data` and
an ISO `at` instant. Baseline `client` currently has no overrides. The baseline
resolver does not expose retained item-key enumeration; its cache observations
say unavailable rather than estimating a key count.

The two matched group cases accept:

```json
{
  "publisher": {
    "groups": 3,
    "groupVocabulary": 1000,
    "periodGeometry": { "chainsPerDay": 2, "periodMinutes": 60 },
    "sourceWindows": 2,
    "at": "2026-10-14T23:59:00Z",
    "items": [
      {
        "name": "bodytext",
        "value": "Saved body",
        "contentType": "text/plain",
        "groups": ["group0000", "group0002"]
      },
      {
        "name": "sidebar",
        "value": "Saved sidebar",
        "contentType": "text/plain",
        "groups": ["group0001"]
      }
    ]
  },
  "issuer": { "horizon": 6, "authorizedGroups": ["group0000"] },
  "client": { "initialCache": false, "routeProbes": true, "observeCache": true }
}
```

Group names are `group0000`, `group0001`, etc. `groups` controls generated item
membership; `groupVocabulary` controls the available names. Explicit item groups
replace generated memberships. The report records the resolved items, used
groups and authorization separately; unused vocabulary names generate no keys.
`horizon` is a future **period offset**, not hours for arbitrary geometry.
The fixture policy authorizes the complete prefix reach of chain keys for the
listed groups. Changing geometry does not silently change this into a different
entitlement policy. `sourceWindows` is 1 or 2; the default is 2. `itemPeriods`
selects ordinary-chain item-wrap alternatives (default 1).

The composed `scenarios/chain-keys/compact-ecdh.js` case accepts
`publisher.variant: "compact-ecdh"` and selects it by default. The ordinary
extension-owned entry refuses that variant without the injected composition.
It changes the actual envelope assembly and requested profile closure together.
Content groups do not accept that variant; their seed envelopes use their own
construction. Unknown overrides fail.

The ordinary runtime defaults to 16 chain source members per issuer message.
With two windows, more than eight groups exceed that capacity. For a deliberate
larger experiment, set `publisher.maxChainMembersPerMessage` explicitly:

```json
{
  "publisher": {
    "groups": 100,
    "groupVocabulary": 100,
    "maxChainMembersPerMessage": 200
  },
  "client": { "routeProbes": false }
}
```

The ordinary scenario provisions this capacity across its real publisher,
issuer, request builder and response profile. The positive safe integer is
trusted configuration, never a wire field or an authorization grant. Its
effective value and whether it exceeds the current specification's fixed
maximum of 16 appear in the report. Such a run measures an explicit experiment;
it does not claim conformance to the unchanged profile bound. Content-group
cases use their own bounds and refuse this ordinary-only input. Neither case
silently reduces group count, switches to item-key supply or opens only the
first alternative to manufacture success.

## Callable engine and scenario ownership

```js
import { runBench } from "./runBench.js";
import { scenario } from "./scenarios/content-groups/groups.js";

const report = await runBench({
  scenario,
  input: { publisher: { groups: 2 } },
  measurement: { scope: "full", runs: 1, warmup: 0 },
});
```

Core cases and genuinely shared workload/exchange ingredients live in
`scenarios/`. Extension scenarios live under `scenarios/<extension>/`
and may compose required siblings directly. The content-group
entry composes real chain/cache implementations there; the chain-owned compact
entry selects compact envelope contributions without adding a compact runtime
dependency to ordinary chain cases. Installed sibling sources are explicit
development prerequisites. The generic runner imports no extension. Each
runnable entry stands alone and exports:

```js
export const scenario = {
  id: "example",
  requestedProfiles: ["dca-profile-baseline"], // or a function of resolved input
  defaults: {/* public input defaults */},
  resolveInput(overrides) {
    /* validate, resolve once, return JSON input */
  },
  async execute({ input, observe, scope }) {
    /* assemble actual roles */
  },
};
```

Without `resolveInput`, the engine merges known default fields recursively and
refuses unknown overrides. Resolve workload generation before role timings;
each sample receives a clone of the same logical input. Fresh role instances,
caches and protocol randomness belong inside `execute`. Keep keys and secrets
out of reportable input. Importing a public case must not import test fixtures.

`observe.time(name, fn, {nested, step})`, `capture(name, document, {text,
status, partitions})`, `check(name, passed, details)`, `count(name, amount)` and
`snapshot(name, value)` collect observations. `step: true` is opt-in via
`timeSteps`; `nested` labels containment independently. Explicit capture text
must parse to the supplied document. Partition strings must concatenate to the
exact captured text. Scenarios own expected access/opening outcomes; a scenario
with no verification never reports success.

Crypto counting additionally needs `scenarioUrl` naming the actual module's
unmodified, frozen scenario export (`Object.freeze({...})`) and JSON-compatible input. Callable-only anonymous
or modified scenarios cannot be serialized into a worker. Module imports are
setup; sampled operations must happen inside `execute`. Workers instrument only
their own WebCrypto methods, restore them in `finally`, and return counts, never
key arguments. These are attempted operations, not proof of algorithm correctness.

## Reading the report

The text payload view (`--show captures`) presents separate objects keyed by
`markup.dca-data`, `markup.dca-sealed-content`, `json.request` and `json.response`.
The size summary uses the same labels. These are presentation labels for the
carrier payloads, not extra wire members. Their sizes exclude HTML script tags
and markup escaping; the current scenarios execute JSON delivery. Raw JSON
reports and saved captures retain that exact transport evidence, including the
combined JSON delivery. A single displayed artifact can instead use its label
as a heading and show only its payload.

- `setup` records effective public inputs, requested/resolved protocol profiles,
  measurement settings, Node runtime, source revision and dirty-tree status.
  Profiles missing from the current catalogue require explicit finite scenario
  `profileDeclarations` with catalogued parents, specification reference and
  proposal/working-draft status. These are reported as partial catalogue coverage;
  they do not extend the normative catalogue or create a conformance claim.
- `samples` preserves every measured execution. Top-level observations refer
  to the first sample; `summary` reports distributions across measured samples.
  Each physical render has its own artifacts and fresh randomness.
- `captures` retains parsed objects and exact JSON text. Multiple messages with
  one name remain ordered arrays. Absent stages or cache-hit responses have
  an unavailable reason, never an invented zero-byte document.
- `sizes` reports UTF-8 JSON and gzip level 9 bytes. `dcaData` excludes encrypted
  content; delivery and ciphertext accounting are separately named. Raw byte
  partitions reconcile to the total. Independently gzipped partitions are
  **not additive** and do not explain the complete document's gzip size.
- `timings` uses monotonic milliseconds, separating setup, role work,
  serialization/validation and compression/accounting. Client duration may
  enclose issuer duration. Nested steps must not be added to their enclosing
  duration. Instrumented timings are labelled; no fixed speed thresholds apply.
  Optional crypto counters separate `setup`, `primary`, `probes` and `unscoped`
  phases; `cryptoTotal` includes all phases. Probe and nested setup timing names
  carry prefixes. The `total` serialization/compression metrics include all phases.
- `cache["trusted-reference-limits"]` records the ordinary-chain scenario's configured
  request/cache limits and explicit message capacity as configuration metadata,
  not a passed behavioral check.
- `cache.before/after` observes real caches and a string store's UTF-8 storage
  key/value bytes. A stored family can hold several keys. Retained chain keys,
  memoized period keys and persisted entries have separate counts. This is not
  heap size or browser quota. `entries()` can run normal eviction; the case
  fixes its clock and observes outside role timings. No cache key bytes are exported.
  `client.observeCache: false` skips cache enumeration and storage measurement;
  access checks still run. Its unavailable snapshots do not assert retention counts.
- `checks` records plaintext equality, expected refusal, route isolation and
  retained-state checks. Route probes use separate clients/caches and named
  observations, without warming the primary measured exchange.

`initialCache: true` obtains the fixture grant in separately identified setup,
then measures the resource using its actual held keys. If no unlock is needed,
there is no primary request/response capture. Setup calls are not disguised as
measured zero-cost acquisition.

## Development acceptance

Add a scenario in a profile/extension's first working slice. Later behavior
changes rerun affected scenarios and retain the report/artifact location with
the change's return. Use the common runner and real role seams. Ordinary tests
remain independently required and should not depend on benchmark reports.
An extension does not need a registry entry: document its explicit module path.

Focused acceptance from `js/evidence-benchmarks/scenario-bench/`:

```sh
sh check
node --test ../../test-tools/profile-catalogue.test.js ../../test-base/import-boundary.test.js
```

`sh check` runs every benchmark test, the five admitted tool modules'
checked-JavaScript types, lint and formatting. Its installed tools come from
`js/node_modules/`; it adds no package dependencies.

The historical [benchmark tools](../README.md) retain
specialized operation, compression and research comparisons. Automatic sweeps,
broader retention/expiry workloads, comparative tables, CMS input mapping
and visual playback remain separate consumers or later work.

## Retained reader across articles and windows

The ordinary chain extension also owns a Node retained-reader workload:

```sh
node cli.js --scenario scenarios/chain-keys/retained-reader.js --time-steps --count-crypto --out /tmp/retained-reader
```

Each independent sample creates one real publisher and issuer, plus reader-owned
period/chain caches backed by an in-memory string store. Each article gets its
own delivery client sharing those caches. No production session API is added.
The default workload renders article one and article two in the same hourly
period, reopens article one's saved ciphertext, requests an unauthorized group,
renders article three after midnight in the next chain window, then advances
past the six-hour retention threshold and explicitly cleans up. The ordinary
16-member capacity applies; larger-capacity experiments stay in `groups.js`.

Inputs are `publisher` and `issuer` options from the ordinary group case,
`representation: "chain-keys"` (default) or `"period-keys"`, and ordered `steps`:

```json
{
  "representation": "period-keys",
  "steps": [
    {
      "id": "first",
      "at": "2026-10-14T23:20:00Z",
      "resourceId": "article-one",
      "expectedUnlocks": 1
    },
    {
      "id": "second",
      "at": "2026-10-14T23:30:00Z",
      "resourceId": "article-two",
      "expectedUnlocks": 0
    },
    { "id": "saved", "at": "2026-10-14T23:40:00Z", "reopen": "first", "expectedUnlocks": 0 },
    {
      "id": "next-window",
      "at": "2026-10-15T00:20:00Z",
      "resourceId": "article-three",
      "expectedUnlocks": 1
    },
    { "id": "expiry", "at": "2026-10-15T06:30:00Z", "cleanup": true }
  ]
}
```

Step IDs are distinct artifact-safe names; UTC instants cannot go backwards.
Each step selects one fresh `resourceId`, earlier render ID to `reopen`, or
`cleanup: true`. Fresh renders use the same authored items/configuration; saved
rereads do not publish again. `requestNames` can select authored items; by default
the workload requests policy-permitted names and checks every item locally.
The default denied step explicitly requests `restricted`, which belongs only
to unauthorized `group0001`; expected refusal remains a required check.
`expectedUnlocks` optionally asserts zero or one real endpoint call for a step.
Custom workloads must supply expectations appropriate to their geometry, grant
horizon and times. The built-in expectations describe the default hourly case;
geometry or entitlement changes can intentionally fail them and require matching
custom steps. Only `full` execution scope is supported.

Both output modes currently consume real chain publisher supply. Selecting
`period-keys` measures issuer projection to period keys and independent-cache
reuse; it does not claim an independently composed period-only publisher case.
No grants are manufactured by the workload. Actual responses, plaintext recovery
and local refusal are checked through the real integrations.

Captures/timings/checks carry step prefixes, such as `first:delivery`,
`first:request` and `next-window:client`. Saved rereads have no new delivery;
cache hits have no new request/response. `cache` preserves each step's clock
advance, pre-unlock and post-opening observations. Clock-advance snapshots read
only serialized storage and cannot trigger eviction. Subsequent `entries()`
observations run the real six-hour coordinate policy: chain-cache enumeration
can evict memory while its old serialized record remains. Cleanup records that
intermediate state, then calls each cache's `reconcile()` and measures storage
again. Moving the clock alone is never reported as completed eviction.
`rawKeyBytesFromFixed16OctetEntries` multiplies enumerated retained entries by the
v1 fixed 16-octet width, including memoized period keys; serialized key/value
bytes are measured separately. Identifiers and counters are retained; key bytes
are never included in the report.

Finally, the workload retires every delivery client with `clearReaderContext()`
and clears both reader-owned caches even after execution failure. The teardown
snapshot and required check verify empty memory and storage. Every sample and
warmup starts independently; existing one-resource scenarios keep their fresh
runtime behavior.

Direct observations are wire messages/UTF-8 and gzip sizes, unlock calls,
construction counters, optional attempted crypto calls, timings, enumerated
retention and actual string-store bytes. There is no traffic projection,
browser quota, database-size or heap estimate in this view.

Further views remain owned by scenario-bench maintainers: select a browser-backed
adapter view only for an actual browser storage/transport question; select
per-resource authoring or fresh-vs-saved workload expansion for a named comparison;
select a calculator/projection consumer only with explicit traffic, encoding and
overhead assumptions. Fold specialized supply/bounds/compression comparisons in
only when their workload can answer a concrete resource-exchange question.
The evidence-benchmark comparison guides continue to own the retained specialized
runner inventory. No universal simulator or protocol-capacity change is pending
as part of this delivery.

## Private checks

Install the reference package's pinned development dependencies under `js/`; this package reuses those executables and adds no installed dependencies. From this directory, run `sh check` (tests, checked JavaScript, lint and formatting), or `sh check tests`, `sh check types`, `sh check lint`, `sh check format` separately. The benchmark check is runnable independently of the public reference gate.

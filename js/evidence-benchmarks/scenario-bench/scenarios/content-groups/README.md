# content-groups scenario measurements

## Scenario bench

For a current full-client measurement, from `js/evidence-benchmarks/scenario-bench/`:

```sh
node cli.js --scenario scenarios/content-groups/groups.js --out /tmp/content-group-bench
```

`groups.js` here exports the runnable scenario and owns its
real chain-key/cache composition. It requires the installed `chain-keys`
implementation for the measured composition; missing support fails explicitly.
The [common bench guide](../../README.md) documents
1/2/10/100-group inputs, sparse vocabularies, saved/mixed items, partial grants,
initial caches and midnight-crossing grants. The case verifies the actual
composed client, each connector route, granted cutoffs and retained key/storage
counts. Proposal status remains explicit; measurements do not adopt this profile.
The [retained historical wire sizes](../../../../extensions/content-groups/README.md#wire-sizes)
keep their original provenance and narrower manual-opening verification.

### Compare the 100/100 membership case

This is the dense-membership "worst case" used for comparison: 100 group names
across the publication, and one resource whose single item belongs to all 100.
The issuer authorizes all 100. It is not the maximum workload supported by the
extension. Both cases use the same content, hourly periods, two source windows,
a T12 render, a grant through T18 and a cold client. Each performs a real unlock
and verifies that the returned keys open the authored content.

Run from `js/evidence-benchmarks/scenario-bench/`. A fresh temporary directory keeps inputs and captures together:

```sh
dca_bench_dir=$(mktemp -d "${TMPDIR:-/tmp}/dca-bench-100.XXXXXX")

cat > "$dca_bench_dir/content-groups-input.json" <<'JSON'
{
  "publisher": { "groups": 100, "groupVocabulary": 100 },
  "client": { "routeProbes": false }
}
JSON

cat > "$dca_bench_dir/ordinary-input.json" <<'JSON'
{
  "publisher": {
    "groups": 100,
    "groupVocabulary": 100,
    "maxChainMembersPerMessage": 200
  },
  "client": { "routeProbes": false }
}
JSON

# Content-group seeds and connectors.
node cli.js \
  --scenario scenarios/content-groups/groups.js \
  --input "$dca_bench_dir/content-groups-input.json" \
  --out "$dca_bench_dir/content-groups"

# Ordinary period-key wraps and period-key plus chain-key issuer supply.
node cli.js \
  --scenario scenarios/chain-keys/groups.js \
  --input "$dca_bench_dir/ordinary-input.json" \
  --out "$dca_bench_dir/ordinary"
```

To also compare the ordinary construction with compact ECDH envelopes:

```sh
node cli.js \
  --scenario scenarios/chain-keys/compact-ecdh.js \
  --input "$dca_bench_dir/ordinary-input.json" \
  --out "$dca_bench_dir/ordinary-compact-ecdh"
```

The ordinary cases explicitly provision 200 source members: 100 groups times
two windows. Their normal capacity remains 16; this override exceeds the
current chain-key specification's fixed message bound and is reported as an
experiment with matching implementations. It does not amend that profile.
Content groups uses its own limits and does not take this ordinary-only option.

Compare the printed JSON and gzip-level-9 byte rows for `markup.dca-data`,
`markup.dca-sealed-content`, `json.request` and `json.response`. The markup labels
identify separate JSON payloads; their sizes exclude HTML script tags and
markup escaping. Sum those four rows for the exchange payload total. Do not
also add combined JSON delivery, which contains the same metadata and content.
Compression is measured separately for each payload; fresh randomness can
change compressed sizes between runs.

Add `--show captures,sizes` to print the separately keyed payloads as well as
their sizes. Each output directory contains `report.json` and exact wire
captures under `sample-1/capture-*/1.json`. `routeProbes: false` keeps this
comparison to the primary exchange; plaintext-opening and grant/cache checks
still run. Omit that override to additionally verify every individual route.

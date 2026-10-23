# chain-keys scenario measurements

## Scenario bench

From `js/evidence-benchmarks/scenario-bench/`, run one real resource through publisher, issuer and composed client:

```sh
node cli.js --scenario scenarios/chain-keys/groups.js --out /tmp/chain-bench
```

The [common bench guide](../../README.md) documents saved
article inputs, geometry/grants, initial caches, the chain-owned `scenarios/chain-keys/compact-ecdh.js`
composition and
report interpretation. Authored period and chain alternatives are independently
probed. The default uses two groups and two source windows; more than eight
groups with that window count exceeds the default 16 source-member capacity
and yields a failed check, without changing the workload or falling back.
For a deliberate 100-group comparison, pass
`publisher: { groups: 100, maxChainMembersPerMessage: 200 }`. The scenario
provisions the real publisher, issuer, relay, admission profile and caches
with matching finite capacity and reports the override. This exceeds the
current specification's 16-member bound; it is measurement with matching
implementations, not a change to that specification or its default.

Outside the bench, the publisher's issuer entry and chain request builder,
carrier readers, issuer source/engine and profile factories expose the same
trusted `maxChainMembersPerMessage` option. The profile factories take it in
their optional second configuration argument. Use the existing
`ChainKeyCache.maxMembersPerMessage` for cache admission, and configure request
byte/entry budgets independently. No carried field can increase these limits.

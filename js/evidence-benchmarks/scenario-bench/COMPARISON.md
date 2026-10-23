# Period keys and chains versus content groups

One fresh publisher → issuer → client exchange per row, captured on 23 October
2026 with the inputs in [comparison-results.json](comparison-results.json).
All four executions passed their five opening, coordinate and cache checks.
Sizes are UTF-8 bytes; gzip level 9 compresses each payload separately.

| Groups | Construction         | Delivery metadata raw / gzip | Encrypted content raw / gzip | Request raw / gzip | Response raw / gzip | Total raw / gzip |
| -----: | -------------------- | ---------------------------: | ---------------------------: | -----------------: | ------------------: | ---------------: |
|      2 | Period keys + chains |                2,079 / 1,302 |                    107 / 127 |      1,776 / 1,125 |           205 / 156 |    4,167 / 2,710 |
|      2 | Content groups       |                  1,310 / 885 |                    107 / 127 |        1,151 / 774 |           264 / 173 |    2,832 / 1,959 |
|    100 | Period keys + chains |              68,033 / 35,117 |                    107 / 127 |    62,928 / 31,616 |       8,241 / 2,203 | 139,309 / 69,063 |
|    100 | Content groups       |                7,092 / 2,943 |                    107 / 127 |        2,327 / 997 |      10,162 / 2,241 |   19,688 / 6,308 |

The ordinary path spends more on supplied per-group sealed material. Content
groups shares supplied seeds across the item's groups and adds connectors; its
returned chain records carry the item name as well as the group. The response
alone is therefore not the complete comparison.

Both constructions use one item with the same content, hourly periods, two
source windows, a T12 render, authorization through T18, all listed groups
granted and a cold client. The table adds metadata, encrypted content, request
and response once each; it excludes HTTP headers, HTML script tags and escaping.
It does not also add combined JSON delivery, which would count the same data twice.

**Capacity boundary:** the 2-group case uses ordinary default limits. The dense
100-group ordinary case explicitly sets `maxChainMembersPerMessage: 200` for
100 groups × two windows, exceeding the current chain profile's fixed 16-member
bound. It is an experiment using matching implementations, not a conforming
100-group baseline. Content groups uses its own specified limits.

Content groups remains a Proposal. Matching this exchange does not equalize
issuer custody: the content-group seeds allow derivation for the supplied
content name and window across articles. Broader vocabulary, sparse membership,
partial grants, multiple items and retained reads can change the tradeoff.

Fresh ECDH keys and signatures vary, so gzip byte counts are observations from
one sample per case, not deterministic constants or statistical estimates.
Run multiple samples for a distribution. These measurements use the current
named-record layout, nested `requested` selections and nonce-free ordinary/seed envelopes; older saved tables
may use another draft and must not be mixed without matching their wire format.

## Reproduce

Install the development dependencies from `js/`, then run from this directory.
The [dense comparison recipe](scenarios/content-groups/README.md#compare-the-100100-membership-case)
gives both commands and capacity settings. For the 2-group rows use
`publisher.groups: 2`, `publisher.groupVocabulary: 2` and no capacity override.
The JSON file preserves each row's input; all use `client.routeProbes: false`.
Use `--runs N` to gather several genuine samples. Each output directory keeps
its full report and exact payload captures.

The [main benchmark guide](README.md) documents sparse groups, workloads,
timings, work counters and retained-reader scenarios.

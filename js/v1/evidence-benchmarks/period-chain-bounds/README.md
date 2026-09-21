# Period-chain bounds

[`spec--period-key-chains.md`](../../../../docs/spec--period-key-chains.md)
**Bounds** names five fixed peer-visible period-chain limits. The benchmark
also compares one and four locally retained rival chain candidates; the
profile does not fix that setting.
This measures the operations those limits bound, each at the ceiling it names, on the real construction,
issuer projection and client derivation paths rather than on a substitute hash loop.

Two numbers describe each operation. The spec models the HKDF count as `2N - 1` per expansion and
`maxRivalChainCandidates x (2N - 1)` per wrap. That count does not move between runs, and a bound on
derivation work limits it and nothing else. Wall time moves with the host, so each row gives a median with
its spread beside it.

Measured 2026-09-13, one container on a shared host:

```text
Node v22.22.2, Intel(R) Core(TM) Ultra 7 155H, 22 logical CPUs visible.
linux 7.0.0-31-generic, a container on a shared host: wall times are indicative.

1. N = 288 terminal construction from the family root, cold
   periodFamilyGeneration({ cache: false }).chainCapability at 251023T2355
   0.15 ms median (0.06 min, 0.28 max, 11 runs after 2 discarded), 1 HKDF

2. Full 288-leaf projection of one member, periodChainExpansionFromState
   17.52 ms median (15.97 min, 23.42 max, 11 runs after 2 discarded), 575 HKDF for 288 leaves

3a. Client walk from the 251023T2355 cutoff back to 251023T0000, 1 rival chain candidate
   PeriodChainCache.candidates answered 1
   7.16 ms median (6.30 min, 9.48 max, 11 runs after 2 discarded), 288 HKDF, 288 per candidate

3b. Client walk from the 251023T2355 cutoff back to 251023T0000, 4 rival chain candidates
   PeriodChainCache.candidates answered 4
   32.72 ms median (30.48 min, 38.10 max, 11 runs after 2 discarded), 1 152 HKDF, 288 per candidate

4. One message at the 16-member ceiling: 8 families of 2, 16 chain members
   request document 3 761 UTF-8 bytes
   default IssuerProcessor limits: failure too_many_entries
   explicit maxEntries 17: admitted, endpoint answered 200
   16.46 ms median (13.86 min, 18.47 max, 11 runs after 2 discarded)
   response body 746 UTF-8 bytes, 16 leaves

5. One 512-leaf exact response through UnlockEndpoint.handleRequest, 3 families asked, admission admitted
   status 200, 512 leaves in premium, archive
   errors member absent
   33.87 ms median (30.82 min, 38.91 max, 5 runs after 2 discarded)
   response body 20 034 JSON characters, 20 034 UTF-8 bytes

6. The same three families as direct chain state, representation: 'chain'
   status 200, 3 chain members in 3 families
   1.91 ms median (1.58 min, 2.84 max, 11 runs after 2 discarded)
   response body 372 UTF-8 bytes
```

Reading the rows. In row 1 the run derives the terminal and stops there, so that single HKDF is the whole
cost of reaching a window's top from the family root; rows 2 and 3 measure the walk down from there. Row 2
measures one full expansion, `2N - 1` derivations at `N = 288`, the figure the spec names and what the
issuer pays to open and project one member. In row 3 the client asks for one coordinate at the far end of
the window rather than for every leaf in it, so it derives 288 per candidate, 287 backward steps and one
leaf; four rivals multiply that and nothing else. Row 4 measures a message at the 16-member ceiling, eight
independently rooted current/next families with two distinct window terminals each, which
`periodFamilySupply` produces at `chainWindows: 2`. Row 5 measures the exact response at its ceiling; its
body is all ASCII, so its JSON characters and its UTF-8 bytes come to the same count. In row 6 the issuer
answers the same three families as chain state instead, and the whole document is 372 bytes because one
cutoff state replaces every leaf it reaches.

The run needs no network, writes no file, and asserts nothing. It stays out of every test lane, because
`package.json` does not name it. Run it from the repository root:

```sh
node js/v1/evidence-benchmarks/period-chain-bounds/run.js
```

Rerunning reproduces the counts and the byte sizes exactly; the wall times move with the host.

## What these numbers say about the selected values

The measurements are engineering evidence for the fixed v1 profile, not a latency SLA.

`maxPositionsPerWindow`, 288. A full window costs 575 HKDF to project and 288 per client candidate to walk.
The 288 ceiling covers one chain per day with five-minute periods (`1/5`) and five chains per day with
one-minute periods (`5/1`) alike; both geometries produce 288 positions.

`maxChainMembersPerFamily`, 2. Two members express the current/next independently rooted window shape.
Expanding a full family costs at most 1,150 HKDF invocations.

`maxChainMembersPerMessage`, 16. Eight two-member families produce a 3,761-byte request here and bound full
issuer expansion at 9,200 HKDF invocations. The reference port's default `maxEntries: 16` is intentionally
stricter once ordinary base entries accompany the chain collection; with an explicit finite
`maxEntries: 17` the processor admits this benchmark's 16 members plus its one content-key entry.

`maxExactLeavesPerFamily`, 288. This is independently declared even though it numerically equals the
geometry bound. It lets one family return a whole maximum window of leaves; expanding those in full costs
575 HKDF.

`maxExactLeavesPerResponse`, 512. A canonical-width response at the ceiling is 20,034 UTF-8 bytes here. The
value is not a multiple of 288,
so the second family in row 5 is answered with the 224 leaves that were left rather than with a whole
window, and the third is answered with nothing.

`maxRivalChainCandidates`, measured at 1 and 4. **Fails to distinguish as a peer-visible value, and the
measurement supports classifying it as local retention policy.** Four candidates cost 1 152 HKDF against 288 for
one, exactly linear, and no byte on the wire changes with the number. The client picks how many rivals it
retains and pays for its own choice.

`maxRivalExactCandidates`, not fixed by the profile. **Not measured.** No row above exercises expanded-leaf
retention. It counts as local retention policy by the same argument as the chain rival bound rather than on
evidence gathered here.

`MAX_MEMOIZED_LEAVES`, 288 in `extensions/period-chain/core-client/PeriodChainCache.js`, is local retention
policy on the same footing: the file says so itself, a host overrides it through `maxMemoLeaves`, and it is
deliberately not a row of the Bounds table. It is not measured here either.

## Two asymmetries the measurement ran into

The reference clamps at the exact-leaf ceilings and refuses at the member ceilings. It refuses a third
member in one family and a seventeenth in one message with named messages, which the carrier-reader and
sealer-composition cases pin. A family asked for 289 leaves is answered with 288, and no API anywhere
produces a 289th leaf for one family. So `extensions/period-chain/test/exact-leaf-bounds.test.js` asserts a
clamp at those edges rather than a refusal.

The response says nothing about the leaves the issuer withheld at the 512 ceiling. In row 5 the run asked
three identically provisioned families whose issuer policies each supplied 600 leaves and got back 512, in two
families, with the third
absent from `keys.periodKeys` and no `errors` member in the document at all. The third family's
`unavailable` answer drops it from the response without a per-item error, so a client reading that response
cannot tell a family that was refused from one the issuer dropped at the ceiling. The behavior is recorded,
not changed.

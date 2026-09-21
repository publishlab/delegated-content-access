# Proposal: state the period-chain label mapping as integer arithmetic

Status: Proposal
Target: [spec--period-key-chains.md Section 7.3](spec--period-key-chains.md#coordinate-labels)

This document has no protocol authority. If the editors accept it, they move
its requirements into the target and remove this proposal file.

## Introduction

Section 7.3 defines the coordinate label `YYMMDDTHHMM` and maps it to the
construction coordinate through `M`, "minutes since 1970-01-01T00:00Z of the
labeled instant", and through `format`, its inverse. The section leaves both
conversions to the implementer, and most implementers will reach for their
platform's date library.

This proposal writes both conversions as integer arithmetic over `M`, so every
implementation computes the same label on every platform without a calendar
library.

## Motivation

Two parties map labels independently. The publisher formats every label it
emits. A chain-route issuer rounds its own captured instant down to the period
grid ([Section 13.1](spec--period-key-chains.md#chain-route-periodcount))
and looks up supplied members keyed by the label `suppliedT`
([Section 12.1](spec--period-key-chains.md#document-member)). The two
parties may come from different vendors and run on different platforms.

Date libraries answer differently by default:

- An issuer whose runtime formats in `Europe/Oslo` looks for `251023T1615`
  where the publisher wrote `251023T1415`. The issuer finds a gap at its current
  coordinate and grants nothing, or it grants a horizon shifted by two hours.
- Several runtimes read the two-digit year `99` as 1999. The profile defines it
  as 2099.
- Some runtimes reject `250431T0000`; others roll it forward to 1 May.

None of these failures names its cause. The reader sees locked content.

Integer arithmetic removes the defaults. The mapping needs division and
remainder on non-negative integers and nothing else.

## Proposed text

All divisions below are integer divisions on non-negative integers, and `%` is
the remainder.

Label to minute count, for the fields `YY`, `MM`, `DD`, `HH`, `mm` read as
decimal integers:

```text
y    = 2000 + YY
if MM <= 2: y = y - 1
era  = y / 400
yoe  = y - era × 400
mp   = (MM + 9) % 12
doy  = (153 × mp + 2) / 5 + DD - 1
doe  = yoe × 365 + yoe / 4 - yoe / 100 + doy
days = era × 146097 + doe - 719468
M    = days × 1440 + HH × 60 + mm
```

Minute count to label:

```text
days = M / 1440
rem  = M % 1440
z    = days + 719468
era  = z / 146097
doe  = z - era × 146097
yoe  = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
y    = yoe + era × 400
doy  = doe - (365 × yoe + yoe / 4 - yoe / 100)
mp   = (5 × doy + 2) / 153
DD   = doy - (153 × mp + 2) / 5 + 1
MM   = mp + 3 if mp < 10, otherwise mp - 9
if MM <= 2: y = y + 1
YY   = y % 100,  HH = rem / 60,  mm = rem % 60
```

Each label field is written zero-padded to two digits. A formatter MUST refuse
an `M` whose year falls outside 2000 through 2099.

The real-calendar test needs no table of month lengths: a label passes when
the field ranges hold and formatting its own `M` spells the same eleven
characters. `250431T0000` maps to an `M` that formats as `250501T0000`, so it
fails.

An implementation that starts from a Unix timestamp in seconds computes
`M = seconds / 60` and never constructs a date value.

## Worked examples

Label to coordinate, with `windowStart` and `position` from the existing
Section 7.3 mapping:

| `t` | `chainsPerDay` | `periodMinutes` | `M` | `windowStart` | `position` |
|---|---|---|---|---|---|
| `000101T0000` | 2 | 15 | 15778080 | 15778080 | 0 |
| `251023T1415` | 2 | 15 | 29353815 | 29353680 | 9 |
| `251023T1400` | 2 | 60 | 29353800 | 29353680 | 2 |
| `251023T2345` | 2 | 15 | 29354385 | 29353680 | 47 |
| `251024T0000` | 2 | 15 | 29354400 | 29354400 | 0 |
| `991231T2359` | | | 68374079 | | |

Each row reads in both directions: the label maps to the coordinate, and
`label(windowStart, position)` spells the label. The largest supported `M`,
68374079, fits the `u32` `windowStart` encoding of
[Section 6.4](spec--period-key-chains.md#context-encoding).

The arithmetic above was checked against a calendar library for every day from
2000-01-01 through 2099-12-31 on 2026-09-17.

## Compatibility

The proposal changes no label, no coordinate and no derived key. It replaces a
definition by reference to the calendar with the arithmetic that definition
already implies.

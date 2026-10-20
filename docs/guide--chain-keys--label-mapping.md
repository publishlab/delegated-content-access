# Chain-key label mapping

Status: Informative Draft

This guide gives an optional integer-arithmetic recipe for the label mapping in
[chain keys Section 7.3](spec-profile--chain-keys.md#coordinate-labels).
That specification defines the labels and coordinates. A correctly configured
calendar library is equally suitable; implementations need not use this algorithm.

## Calendar and compact labels

DCA uses Gregorian calendar dates and UTC. See
[RFC 3339 Section 4.1](https://www.rfc-editor.org/rfc/rfc3339.html#section-4.1)
for UTC and [Section 5.7](https://www.rfc-editor.org/rfc/rfc3339.html#section-5.7)
for valid calendar dates, including leap-year handling.

The compact DCA label `YYMMDDTHHMM` is not an RFC 3339 timestamp.
For example, `251023T1415` denotes the same minute as `2025-10-23T14:15:00Z`.
DCA fixes the year to `2000 + YY`, implies UTC, and uses minute precision.
RFC 3339 instead uses four-digit years, separators, seconds and an explicit offset
([Section 5.6](https://www.rfc-editor.org/rfc/rfc3339.html#section-5.6)).

When using a calendar library, select UTC explicitly, expand the year before
parsing, and reject invalid dates rather than accepting normalization. For
example, `250431T0000` is invalid; it does not denote 1 May.
Apply the chain profile's period-grid check separately from calendar validation.

## Integer conversion recipe

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

Each label field is written zero-padded to two digits. Under the profile, a formatter refuses
an `M` whose year falls outside 2000 through 2099.

First check the fixed eleven-character syntax and the field ranges in Section 7.3.
The real-calendar test then needs no table of month lengths: a label passes when
the field ranges hold and formatting its own `M` spells the same eleven
characters. `250431T0000` maps to an `M` that formats as `250501T0000`, so it
fails.

An implementation that starts from a Unix timestamp in seconds computes
`M = seconds / 60` using integer division for a non-negative timestamp and
never constructs a date value. Check that the result is within the supported
2000 through 2099 range before formatting.

## Worked examples

Label to coordinate, with `windowStart` and `position` from the existing
Section 7.3 mapping:

| `t`           | `chainsPerDay` | `periodMinutes` | `M`      | `windowStart` | `position` |
| ------------- | -------------- | --------------- | -------- | ------------- | ---------- |
| `000101T0000` | 2              | 15              | 15778080 | 15778080      | 0          |
| `251023T1415` | 2              | 15              | 29353815 | 29353680      | 9          |
| `251023T1400` | 2              | 60              | 29353800 | 29353680      | 2          |
| `251023T2345` | 2              | 15              | 29354385 | 29353680      | 47         |
| `251024T0000` | 2              | 15              | 29354400 | 29354400      | 0          |
| `991231T2359` |                |                 | 68374079 |               |            |

Every label and `M` pair reads in both directions. Where geometry is shown,
`label(windowStart, position)` also spells the label. The largest supported `M`,
68374079, fits the `u32` `windowStart` encoding of
[Section 6.4](spec-profile--chain-keys.md#context-encoding).

The arithmetic above was checked against a calendar library at 00:00, 14:15
and 23:59 on every day from 2000-01-01 through 2099-12-31: 109,575
conversions and inverse conversions agreed.

## Protocol effect

This recipe changes no label, coordinate or derived key. The calendar semantics,
label spelling and grid rules remain defined by the chain-key profile.

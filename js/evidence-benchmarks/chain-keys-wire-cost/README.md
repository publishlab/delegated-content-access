# Chain-key wire cost

This executable benchmark measures the reference publisher delivery and one client-to-issuer exchange for four supply forms: `content-key-only`, `period-key-only`, `period-key-plus-chain` and `chain-only`. It uses the [chain-key profile](../../../docs/spec-profile--chain-keys.md) with one shared top-level `periodGeometry`: the derive-only period adapter used here omits geometry, while the selected chain family plan carries the exact `{periodMinutes, chainsPerDay}` pair. A chain family plan may retain that pair even when its issuer supply selects only ordinary period keys. There are no family geometry overrides.

The content-key-only floor has an independently sealed item content key and no supplied access groups. All other forms wrap the same item under the same periods, so comparing their delivery sizes isolates the period/chain supply. Chain-only delivery also retains the item content-key route where configured. The benchmark covers ECDH-P256 and RSA-OAEP envelopes, one or two issuers, one or three groups, one or two supplied windows, and one through 48 wrapped or authorized periods.

## Measured result

Historical capture recorded 2026-10-16 with omitted period-only geometry and no response geometry echo.
It predates the implicit content-nonce adoption: these delivery totals include the former
per-item nonce field and are not current wire totals.
Sizes are raw / gzip / Brotli bytes. Compression uses normalized random carriers; this capture used
`--bytes`, so it does not establish a fresh genuine-render spread.

| One issuer, one group, two wrapped periods in one window | ECDH-P256 delivery | RSA-OAEP delivery |
| --- | ---: | ---: |
| Content-key-only floor | 1,137 / 813 / 722 | 1,333 / 967 / 871 |
| Period-key-only | 1,707 / 1,200 / 1,092 | 2,295 / 1,657 / 1,544 |
| Period-key-plus-chain | 1,950 / 1,360 / 1,253 | 2,734 / 1,968 / 1,847 |
| Chain-only | 1,598 / 1,117 / 1,017 | 1,990 / 1,426 / 1,309 |

Chain-only saves 109 raw / 75 Brotli bytes with ECDH and 305 raw / 235 Brotli bytes with RSA
in this case. With one supplied member in either form, chain-only costs 54 raw bytes more because
only it carries the geometry pair. Period-only becomes larger at two wrapped periods within one
window and three across two windows in the measured raw and compressed series. One wrapped period
adds 99 raw bytes per group; one sealed member adds 163 ECDH or 359 RSA bytes.

The focused ECDH period-key request is 989 / 779 / 743 bytes, versus chain-only relay
943 / 721 / 685. The two-period response is 131 / 131 / 112; the one-chain response is
91 / 99 / 87. At a 48-period horizon, the period response is 1,925 / 1,077 / 980 and
the two-window chain response is 130 / 128 / 106. The client pays up to 28 HKDF calls
in the measured window to derive the article period from the returned cutoff.

A fixed two-wrap/two-window chain delivery is 1,761 / 1,242 / 1,140 bytes in the horizon series;
a period-only render wrapping under 48 periods is 13,759 / 8,918 / 8,581. Those are different
wrapping schedules, not 48 wraps in the chain article. Multiplying the focused Brotli gap by
100 million responses gives 7.5 GB (ECDH) or 23.5 GB (RSA) of DCA script-block bytes;
this is not a measured whole-page transfer saving.

## Method and checks

`run.js` composes real renders and exchanges from `world.js`; it does not hand-build delivery, requests or responses. The publisher uses `Sealer` and `periodFamilySupply`; `writeMarkupDelivery` serializes both DCA script blocks. `createBrowserClient` reads that markup and builds the period-key or chain-relay request. `UnlockEndpoint.handleDocument` admits the serialized request and uses either base period-key input or chain input configured for period-key projection or chain-key output. The client applies the serialized response and opens the encrypted item. The one-window cached-only second wrap across an edge is accepted when another item-key route supplies that second period.

Before printing, the run checks the exact delivery members, shared geometry shape, relayed carrier, response representation, decoded article, refusal status and key-opening/HKDF counts. The expected refusals are a period-key client receiving no period member from chain-only delivery (`401 denied`) and the default issuer limit of four relayed period keys per family (`400 too_many_entries`). The broad publisher rows use explicit trusted publisher request limits, while a long period-key exchange raises the issuer's own default limit to 64. The period-key-only rows use a derive-only adapter over the same canonical generation, so matching coordinates retain identical key bytes without advertising a chain family plan. Chain forms use periodFamilySupply with explicit `chainItemSlots: spec.slots`
to preserve the stated like-for-like wrapping schedules. The separate T0
comparison below exercises the new omitted-option default.

The geometry is 15-minute periods and two 12-hour stationary windows per day. One 51-byte `bodytext` is encrypted in each render. Gzip uses level 9; Brotli uses Node's defaults. Raw counts are UTF-8 bytes. Seeded render identifiers and content keys repeat; current item encryption derives its nonce implicitly, while other seeded nonces repeat; ECDH ephemeral keys, RSA-OAEP seals and ES256 signatures remain random. `measure.js` replaces only those random carriers with equal-width SHA-256 counter-mode material for deterministic compressed comparisons. The full run also samples seven genuine renders per focused form; the historical recorded result above uses --bytes and makes no new spread claim. Cryptographic work is counted through `crypto.subtle`, not timed.

Run from the repository root:

```sh
node js/evidence-benchmarks/chain-keys-wire-cost/run.js
node js/evidence-benchmarks/chain-keys-wire-cost/run.js --bytes > a.txt
node js/evidence-benchmarks/chain-keys-wire-cost/run.js --bytes > b.txt
diff a.txt b.txt
```

`--bytes` skips the genuine-render spread, so its output repeats exactly on an unchanged tree. The run needs no network and writes no file. It measures direct issuer responses, not client-bound responses, whole HTML pages, other geometries or wall time.

## T0 item policy: saved genuine output

Historical capture recorded 2026-10-17 by `node js/evidence-benchmarks/chain-keys-wire-cost/t0.js`.
These saved documents predate implicit content nonces and retain their original bytes.
The table describes that capture, not a fresh run of the current implementation.
The [saved documents and measurements](t0-artifacts/measurements.json) compare the
omitted `chainItemSlots` default against explicit `chainItemSlots: 2`. Both use
hourly periods, two independent 12-hour source windows, a render at 11:59, and
issuer authorization for the current period through T+6 (seven hourly positions).
The actual response returns independently calculated 11:00 and 17:00 cutoffs.
Each measured item opens to its authored plaintext through the real exchange.

| Item groups / configured universe | Metadata default / two wraps, raw | Raw saving | Metadata default / two wraps, gzip | Gzip saving | One response raw / gzip, either policy |
| --- | ---: | ---: | ---: | ---: | ---: |
| One / one | 1,235 / 1,334 | 99 (7.42%) | 906 / 964 | 58 (6.02%) | 131 / 129 |
| Two / two | 1,682 / 1,880 | 198 (10.53%) | 1,202 / 1,312 | 110 (8.38%) | 220 / 183 |
| One / four (sparse) | 1,235 / 1,334 | 99 (7.42%) | 907 / 962 | 55 (5.72%) | 131 / 129 |

Metadata is compact `JSON.stringify` of the actual page delivery without
`sealedContent`; content ciphertext is excluded. The files retain actual
cryptographic carriers and the exact request and response, with no normalization.
Gzip uses level 9. Raw savings are 99 bytes per removed item wrap in these cases;
compressed values are this capture, and change with random seals and signatures.
The response saving is zero bytes (0%) in every case: the independent window
supply and granted cutoff keys are unchanged. The sparse case checks that no
unreferenced group appears in item wraps, source supply or returned keys.
Rerunning `t0.js` replaces only `t0-artifacts/` with a new genuine capture.


### Current implementation raw-byte check

A separate 2026-10-19 check composed the same six cases through the current real
publisher, issuer and client, opened every item, and compared compact metadata
with the saved capture. It did not replace the saved documents. Removing the
per-item nonce field reduces each metadata document by 27 raw bytes:

| Item groups / configured universe | Current metadata default / two wraps, raw | Raw saving |
| --- | ---: | ---: |
| One / one | 1,208 / 1,307 | 99 |
| Two / two | 1,655 / 1,853 | 198 |
| One / four (sparse) | 1,208 / 1,307 | 99 |

This check establishes raw metadata counts only. It does not update the historical
gzip results, response measurements or normalized broad benchmark table. For a
new retained genuine capture, deliberately rerun `t0.js` and review the resulting
artifact changes; do not combine its random compressed sizes with the old capture.

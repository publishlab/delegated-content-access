# Chain geometry JSON number admission

This passive package preserves the raw JSON spellings `2`, `2.0` and `2e0`
for `chainsPerDay`, and `60`, `60.0` and `6e1` for `periodMinutes`.
[Chain keys §12.1](../../../../../../docs/spec-profile--chain-keys.md#document-member)
admits positive JSON integers by mathematical value, independent of spelling.
[Chain windows](../../../../../../docs/spec-profile--chain-keys.md#windows)
then give `windowMinutes = 1440 / 2 = 720` and
`positionsPerWindow = 720 / 60 = 12`, within the
[288-position bound](../../../../../../docs/spec-profile--chain-keys.md#bounds).
Fractional values and numeric strings in either member are refused.

`inputs.json` is deliberately raw text: parsing and reserializing it would
erase the admission property. Its nine cases exercise each member separately.
`expected.json` contains hand-specified expectations from those requirements,
not values obtained from the JavaScript implementation. `observations.json`
records the actual `settleChainGeometry` results after JSON parsing.
The recorder refuses to write observations that disagree with expectations.
No particular refusal code or message is required by this package.

`manifest.json` declares the exact three payload members and their hashes,
consumers and provenance. `SHA256SUMS` covers those payload bytes. This README
and the manifest are required metadata; their contents are not payload hashes.
The directory holds exactly these six files and imports or executes nothing.

From the repository root:

```sh
node js/tools/record-chain-keys-geometry-admission.js
node js/tools/record-chain-keys-geometry-admission.js --check
node --test js/test-tools/record-chain-keys-geometry-admission.test.js js/test-vectors/chain-keys-geometry-admission.test.js
```

The dedicated recorder writes only this package's five generated files and
keeps the original source commit when payloads are unchanged. It never writes
this README, construction vectors or the mixed protocol fixture package.
`--check` writes nothing. Exit 0 means exact membership, payload hashes and
fresh recording agree; exit 1 reports drift, membership or checksum findings;
exit 2 means the check could not read its package or could not run. Recording
refuses a frozen package. Freezing changes lifecycle metadata, not inputs or
specification-derived expectations.

`js/test-vectors/chain-keys-geometry-admission.test.js` reads the raw
inputs, then replays them through the existing domain admission routine and
compares with the independently specified expectations and recorded results.
The recorder self-test exercises damaged copies and regeneration. This recorded-fixture replay
lives in the vector/replay tier; it does not claim a composition of multiple
optional extensions.

This is JavaScript domain evidence for the original geometry-number spelling
obligation. It adds no primitive-corpus operation, issuer exchange, capability
grant, independent implementation, whole-profile pilot or claim-completeness
assertion. The operative profile identifier is `dca-profile-chain-keys`.


## Recording provenance after specification consolidation

The manifest's `sourceCommit` records the original geometry observations.
Later specification changes updated authority references in `expected.json`
and their checksums; inputs, mathematical expectations and observations did not
change. The current expected-file metadata therefore differs from the original
recording's authority strings. `--check` requires the current authority references.

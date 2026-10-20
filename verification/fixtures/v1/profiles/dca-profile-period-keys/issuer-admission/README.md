# Period-key issuer-admission fixtures

This package holds the recorded render `seal-ecdh.json`, format `1`, and six
recorded unlock requests, format `2`, cut from it. The render seals two
content items for one ECDH P-256 issuer, both as content keys and as
period keys for two access groups and two periods. A replay seals its `input`
and compares the result with `expected`.

The six requests belong here because their observation needs period
keys. Three put a delimiter or an inadmissible identifier in an access group.
Three expect the period keys answered beside a partial content-key result: a
relabeled blob, a blob from another render and an unknown contentName. A
`periodKeys` section that a request carries but no observation reads is no
reason to place it here.

Several readers use this package:

- The portable base contracts select it beside the
  [baseline issuer-admission package](../../../baseline/issuer-admission/README.md).
  Both targets in `js/test-contract/contract-targets.json` name the two
  packages in `fixtureSets`.
- `js/test-vectors/vectors.test.js` replays every file, with the other two
  protocol fixture packages. The reject vectors of all three name
  `seal-ecdh` in `derivedFrom`.
- `js/test-vectors/issuer-endpoint-port.test.js` and
  `js/test-vectors/duplicateMembers.test.js` read `seal-ecdh.json`.

`js/tools/make-vectors.js` writes this package; from `js/`,
`node tools/make-vectors.js --check` fails when the files differ from a fresh
generation.

`manifest.json` declares exact membership, the format of each file and the
test tier that asserts from it. Every entry here names `base-contract`.

`SHA256SUMS` covers every JSON payload and excludes the manifest.

`stability: draft` means the generator may rewrite this package as the draft
protocol changes; do not create fixture revision numbers during that period.

Setting `stability` to `frozen` makes this package immutable, and the
generator then refuses to write over it. After that, a compatible adopted
change publishes a separate fixture revision. A wire-incompatible change
belongs to a new protocol version, not a fixture revision.

# Reference protocol regressions

This package holds six records that only the JavaScript reference tier
asserts from. No portable contract target selects it.

- `reject-duplicate-member-name.json` and `reject-prototype-name.json` are
  unlock requests, format `2`, cut from the render `seal-ecdh.json` in the
  [period-key issuer-admission package](../../profiles/dca-profile-period-keys/issuer-admission/README.md).
  The first repeats a member name inside `sealed.contentKeys`; the second
  carries contentNames that are inherited member names in JavaScript.
- `seal-factory-content-key-only.json`, `seal-factory-period-keys.json` and
  `seal-factory-mixed-issuers.json` are Sealer factory records, format
  `sealer-factory-v3`, and `seal-factory-refusals.json` is a refusal record,
  format `sealer-factory-refusal-v2`.

The Sealer factory records, format `sealer-factory-v3`, are for ports to
replay in their own native tests, with no bridge. Three renders are recorded:
content keys only, sealed for two periods, and two items for an ECDH issuer and an
RSA-OAEP issuer. RSA-OAEP envelopes are opened, never pinned. Bytes and
instants are the tagged values of the test bridge frames, at any depth, and
calls are data. The refusal record, format `sealer-factory-refusal-v2`, holds
the refusals that cross a bridge, each with its expected DCA error code. The
records can be read directly by a port and replayed in its own test suite.
`consumers` names only the test tier in this repository that asserts from a file,
so these records select `reference`, for the JavaScript
reference replay. A port that replays them adds no manifest entry.

Three JavaScript tests read this package:

- `js/test-vectors/vectors.test.js` replays every file, with the other two
  protocol fixture packages.
- `js/test-vectors/sealer-factory-records.test.js` replays the four
  factory records it selects from `manifest.json`.
- `js/test-vectors/duplicateMembers.test.js` scans
  `reject-duplicate-member-name.json`.

`js/tools/make-vectors.js` writes this package; from `js/`,
`node tools/make-vectors.js --check` fails when the files differ from a fresh
generation.

`manifest.json` declares exact membership, the format of each file and the
test tier that asserts from it. Every entry here names `reference`.

`SHA256SUMS` covers every JSON payload and excludes the manifest.

`stability: draft` means the generator may rewrite this package as the draft
protocol changes; do not create fixture revision numbers during that period.

Setting `stability` to `frozen` makes this package immutable, and the
generator then refuses to write over it. After that, a compatible adopted
change publishes a separate fixture revision. A wire-incompatible change
belongs to a new protocol version, not a fixture revision.

# Baseline issuer-admission fixtures

This package holds 17 recorded unlock requests, format `2`, that a DCA v1
issuer must not answer as asked under any profile. They forge, substitute or
tamper the signed resource, put a delimiter or an inadmissible identifier in
a contentName, leave out or misspell the renderId, carry a claim the format
does not admit, or ask for no coordinate at all. No observation here needs
an access group or period keys.

Each request is cut from the render `seal-ecdh.json` and names it in
`derivedFrom`. That render sits in the
[period-key issuer-admission package](../../profiles/dca-profile-period-keys/issuer-admission/README.md),
so a replay loads both packages together.

Two tiers read this package:

- The portable base contracts select it beside the period-key package. Both
  targets in `js/test-contract/contract-targets.json` name the two packages
  in `fixtureSets`.
- `js/test-vectors/vectors.test.js` replays it through the JavaScript
  reference issuer, with the other two protocol fixture packages.

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


## Assertion scope

The reference endpoint replay uses an allowing policy for eligible untouched
coordinates, and checks successful siblings where a case supplies them. A
blanket denial is not a valid substitute for the recorded admission behavior.
`privateKeyReached` counts key-store access, not actual cryptographic opening
or authorization correctness. These are component/endpoint observations, not
captured HTTP response headers.

Portable base contracts here describe the selected reference issuer-port API,
not a universal baseline-protocol diagnostic vocabulary. Exact reference error
strings or API status assertions preserve that API's compatibility contract.
An independent protocol-conformance replay asserts the normative refusal class,
scope and ordering, and asserts an exact diagnostic only when the selected
specification fixes it.

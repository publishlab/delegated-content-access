# Shared test fixtures

This directory holds recorded inputs shared by more than one test tier. The
tiers that read them hold their own assertions, and the recorded vector sets
live under [`../vectors/`](../vectors/README.md).

Each versioned package includes a manifest stating exact membership and whether
portable base contracts or reference tests assert from each file.

A manifest's `provenance.sourceCommit` identifies the source-repository revision
used for its original recording; the public repository does not carry that
commit. Package READMEs describe later authority-reference metadata updates
where applicable. Current package checks validate the current recorded files.

The JavaScript package moved from `js/v1/` to `js/`. Manifest `recorder` and
`sourceScenario` paths use the current layout; at a recorded `sourceCommit`
from before that move, resolve a `js/...` path as `js/v1/...`. The source commit
continues to identify the original recording, not the later path-only edit.

This subtree is passive recorded data. It imports and executes nothing; each
consumer names the package and files it reads through its own manifest or test
configuration. The conformance-primitives corpus does not read these fixtures.

`js/tools/make-vectors.js` writes three packages of whole-protocol renders
and unlock requests, each with a `dca-protocol-fixture-manifest/v1` manifest
and its own `SHA256SUMS`:

- `v1/baseline/issuer-admission/` holds 17 unlock requests that the portable
  base contracts assert from under every profile.
- `v1/profiles/dca-profile-period-keys/issuer-admission/` holds the render
  `seal-ecdh.json` and six unlock requests whose observations need period
  keys. The portable base contracts select it beside the baseline
  package.
- `v1/reference/protocol-regressions/` holds two unlock-request regressions
  and four Sealer factory records that only the JavaScript reference asserts
  from.

The [claim-index pilot](../claim-index/README.md) lists all three as
`unmapped`.

The `v1/profiles/dca-profile-period-keys/issuer-client-composition/` package
records one period key story under `dca-profile-period-keys`: a partial grant, the
kept period key reused on the next render, and a 401 for the ungranted next
period with nothing cached or opened. Its own recorder writes and checks it:
`node js/tools/record-period-key-composition.js --check` from the
repository root checks membership, checksums and a fresh recording;
`verification/vectors/check-sums.sh` does not walk it.
`js/test-vectors/period-key-composition.test.js` replays it through the
real JavaScript issuer and client and holds the assertions. It is `draft`,
and every claim decision that could use it is incomplete. The directories
that hold packages, such as `v1/`, `v1/baseline/` and `v1/profiles/`, are path
segments and not packages.

The `v1/profiles/dca-profile-chain-keys/geometry-admission/` package preserves
integer-valued JSON number spellings and fractional/string refusals. Its
recorder checks membership, checksums and independent expected window/position
math; `js/test-vectors/chain-keys-geometry-admission.test.js` replays the
raw JSON through the JavaScript geometry admission boundary. Run
`node js/tools/record-chain-keys-geometry-admission.js --check` from the
repository root. It remains `unmapped` for role duties: domain admission alone
does not establish a publisher, issuer or client profile claim.
See its [package README](v1/profiles/dca-profile-chain-keys/geometry-admission/README.md).

The `v1/profiles/dca-profile-chain-keys/issuer-client-prefix/` package records
one chain-key result whose ten-position backward prefix opens ten items from
one issuer exchange. Later same-window and adjacent-window items remain
unopened from that retained key, with no new unlock. Its dedicated recorder,
`node js/tools/record-chain-keys-prefix.js --check` from the repository
root, verifies exact membership, checksums and regeneration; its JavaScript
replay is `js/test-vectors/chain-keys-prefix.test.js`. The claim index
selects it only for the chain-output pilot's four issuer/client duties. It
uses recorded publisher renders and frozen construction values; this is
JavaScript regression and provenance evidence, with every claim incomplete.
The live profile test separately owns grant and response-admission refusals.
See the [prefix package README](v1/profiles/dca-profile-chain-keys/issuer-client-prefix/README.md).

Start with
[`v1/baseline/issuer-admission/README.md`](v1/baseline/issuer-admission/README.md) or
[`v1/profiles/dca-profile-period-keys/issuer-client-composition/README.md`](v1/profiles/dca-profile-period-keys/issuer-client-composition/README.md).

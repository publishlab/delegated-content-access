# DCA JavaScript reference

This tree holds the DCA reference implementation, written in plain JavaScript and
covering the protocol end to end.

Run commands from the repository root. Examples use explicit `js/` and
`js/v1/` paths rather than requiring a package-directory `cd`.

- [verification/conformance-primitives/](../verification/conformance-primitives/README.md) - cross-runtime operation-bridge
  conformance, its lanes, contract and entry points
- [verification/conformance-primitives-experiments/](../verification/conformance-primitives-experiments/README.md) - hand-run cross-runtime
  evidence for proposed or rejected constructions, outside the gate
- [js/v1/](v1/) - the JavaScript reference implementation
- [js/v1/test-lib/README.md](v1/test-lib/README.md) - test-only library code: reusable suites plus named adapters, harnesses, fixtures and helpers
- [js/v1/test/README.md](v1/test/README.md) - reference tests and shared-invariant rules
- [js/v1/test-extensions/README.md](v1/test-extensions/README.md) - selected-extension composition test routing
- [js/v1/test-vectors/](v1/test-vectors/) - recorded fixture and vector replays, excluded from the public gate
- [js/v1/experiments/README.md](v1/experiments/README.md) - the JavaScript experiments directory: executable proofs using alternate implementations, tests and unpromoted suites
- [js/v1/evidence-benchmarks/README.md](v1/evidence-benchmarks/README.md) - hand-run byte measurements the design documents cite
- [js/v1/evidence-platform-tests/README.md](v1/evidence-platform-tests/README.md) - hand-run empirical tests of runtime and host behavior
- [verification/vectors/](../verification/vectors/) - versioned wire vectors for any implementation to replay,
  the `sets.txt` manifest listing which sets a full run walks, and where the runtimes disagree

The reference demonstrates a complete unlock exchange. A publisher seals content and signs the
render. An issuer verifies that one signed resource and reads the renderId out
of it. From that renderId the issuer rebuilds the render and the coordinate each
blob is bound to, then opens the blob there, over ECDH P-256 or RSA-OAEP, and
the client decrypts. A genuine blob presented at a coordinate where it was not
sealed fails the unseal, and the issuer reports it as one entry in `errors`
beside a 200. A key rollover produces that same 200 and that same entry, since
the issuer cannot tell those apart. Its periodKeys are derived,
shipped, cached and trial-unwrapped, so the second article of a period costs no
unlock.

An issuer can stop answering. A breaker per issuer url takes a failing issuer
out of the walk. A fallback issuer grants only after its own health probe finds
the primary down, and the client reuses that probe result for a TTL rather than
probing again on every request.

The integrity checks always run first, and an access policy the integrator
supplies then decides who may read what. A naive policy runs beside a strict one
on the same render, and the naive issuer hands back the article the strict
issuer holds back. The naive policy and the demo's emergency window exist to
show the mechanics; do not deploy either. Two issuers answer one page differently, and a periodKey one
of them granted opens the other's article unless the client's cache is keyed by
issuer. Keys travel direct or wrapped to one client's non-extractable keypair,
and a response cache forces direct. Three things rotate: the issuer
keypair, the publisher signing key and the periodSecret. All three run against
markup that predates them, and the issuer answers a retired keyId with
200-with-errors and a keyId it never held with 400.

An integrator can also configure what the endpoint discloses, and what it
refuses before it reads anything:

- one uniform refusal body in place of the coded default
- a byte cap ahead of the JSON parse
- entry caps ahead of the engine
- an auth gate ahead of the health probe, the transport agreement and every signature

The auth gate is why an unidentified caller costs no asymmetric operation. All
of it is off unless configured.

`sh js/check` runs the public Node-only repository gate and forwards to the
package's pinned pnpm. Its stages are lint, formatting, the
admitted checked-JavaScript slice, source boundaries, vector-free JavaScript
reference behavior and the experiment tier. It runs no vector checks, repository vector
tooling, portable contract tests or cross-runtime conformance. Those are separately
selected commands. The gate neither requires PHP nor installs any conformance
toolchain, and its lint, formatting and checked-JavaScript stages run the
package's own devDependencies, so a checkout completes it once `js/v1` has been
installed with
`corepack pnpm@10.23.0 --dir js/v1 install --frozen-lockfile --ignore-scripts`.

`sh js/check` is this tree's public check entrypoint. It exits 0 when every
gated stage held, 1 when a gated stage failed, and 2 when the run was partial
and verified less than intended.

Cross-runtime conformance is opt-in and entirely separate from `check`. Its
[README](../verification/conformance-primitives/README.md) owns the current bridge model, lane layout,
corpus cases, toolchain behavior and commands. Keep
those details there rather than duplicating them in this overview.

The JavaScript reference suite's skip count depends on the environment; each
skip carries its reason in the test output. `markup-placement.test.js` checks that
`writeMarkupDelivery()` and `js/v1/adapter-client/MarkupDeliveryReader.js`
agree through a small stub DOM.

A `contentName` carrying a colon - `sponsor:intro` under `premium:sport` -
seals, ships and decrypts here. `leak-checks.test.js` runs it from the JSON
member name through the aad to the selector.

`js/v1/demo/browser/index.html` runs the same scenario the tests assert over.
Run `python3 -m http.server --directory js/v1 8000`, then open
`http://localhost:8000/demo/browser/`. `js/v1/experiments/` holds experiments
that displace a core module. The binding experiments retain alternatives to
the selected coordinate-bound seal: an earlier unbound seal under which the
same relabel succeeds, and whole-request refusal where core answers per item.

The binding variants sit under `js/v1/experiments/`, in `_implementation/<shape>/` when more
than one experiment runs one and in `<experiment>/implementation/` otherwise. Each
module opens with a header giving what its shape reproduces, on which kind of
sealed blob, what that stops and what it leaves open against the shipped
binding, and that header is where the shape is written down. The comparison entry points under
`js/v1/experiments/<experiment>/test/` run each move through both bindings on one request, so when a
move succeeds under one binding and is refused under another, the difference
comes from the binding and not from how each implementation was written.
Where one behavioral requirement is deliberately
registered against more than one implementation target, define a selected
requirement under `js/v1/test-lib/suites/` and an unpromoted requirement under
`js/v1/experiments/<experiment>/test-lib/suites/`; a variant must not carry a rewritten copy of that
shared requirement. Target-local characterization may remain separately named.
The experiments and test-lib READMEs own that boundary.

`verification/fixtures/protocol-v1/` holds recorded whole-protocol inputs used by the
portable base contracts and the explicit JavaScript vector tier. Its manifest
names which consumer owns assertions over each file. `verification/vectors/v1/`
holds base protocol evidence for any runtime to replay.
Regenerate both with
`node js/v1/tools/make-vectors.js`, run from the repository root.
An unchanged regeneration is byte-stable: it retains a recorded ES256 signature
only when its exact header and payload are unchanged and the signature verifies
under the current public JWK. The sets beside it under `verification/vectors/v1-alt--*/`
hold focused or alternative fixtures. Sets under `verification/vectors/v1-profile--*/`
hold separately versioned extension contracts, including client-bound delivery
profiles and period-chain primitive bytes; neither changes the
base vector formats, and each replays under the name it carries in
`verification/vectors/sets.txt`. The ECDH-P256 profile
injects its ephemeral pair and nonce so seal and open are reproducible; the
RSA-OAEP profile records open only because OAEP sealing is randomized. A fresh
runtime seal still draws a new ES256 `k`, so replayers compare header and
payload and verify the signature rather than comparing it.

Every vector set and the neutral fixture package carry `SHA256SUMS` beside
their payloads. `sh verification/vectors/check-sums.sh` checks a set against
it, with no JSON parser, no Node and no PHP. A bare `sha256sum -c SHA256SUMS`
checks one directory's recorded hashes; the script also walks every declared
set, checks its declaration and prints its phase, because a match means different
things either side of a freeze: on a devel set the bytes are the ones
`make-vectors.js` last wrote, and an unchanged run writes identical sums; on a
stable set they are frozen, so a mismatch is a hand edit or a bad merge.
`make-vectors.js` stops with an error instead of writing into a stable set.

`verification/conformance-primitives/` carries its own literal corpus of
stock-library cases and reads nothing here.

That same `verification/fixtures/protocol-v1/` package holds the current recorded renders and
refusal inputs. The renderId refusals separately cover a 17-byte value and a
22-character value that decodes
to 16 bytes but has non-zero unused trailing bits, so width and canonical
base64url spelling are both replayed before private-key reach. The algorithm
substitutions - `alg: none`, and the same payload MAC'd under the publisher's
own public key - catch an issuer that pins the key and bytes but reads the
algorithm off the header. The bound-carrier fixture uses `vectorFormat` 4: it
records two deterministic ECDH seals, their coordinate refusals, and a recorded
RSA-OAEP open under the variant's binding grammar.

## Runtime

The reference is plain ESM with no dependencies and no build step. It uses
WebCrypto only: `crypto.subtle`, plain objects, `TextEncoder`/`TextDecoder`. No
Node imports, no `Buffer`, so the identical files run under `node --test` and
under `<script type="module">`. `node:test` appears only in test files, and
`node:child_process` only in the one that spans two runtimes. Types come from
JSDoc with `// @ts-check`, so there is nothing to compile.

That is a property of the checked-in reference, not a deployment restriction.
An extracted role is static ESM with a public entry, and an implementer may
bundle it with their integration code into an artifact that keeps none of the
reference tree's internal filenames or paths.

The browser page uses `crypto.subtle`; serve it from the web root documented
above.

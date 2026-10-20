# Chain-key issuer and client prefix composition

This package records one chain-key story under `dca-profile-chain-keys`. The
publisher supplies chain keys only: each render carries one sealed chain key
and wraps its item at its own period coordinate, with no item content key and
no period-key member. One browser reads thirteen renders against one
issuer whose clock stays at 2025-10-23 14:20 UTC, under the `2/15` geometry:

1. The client reads the 14:15 item. The issuer's policy answers a forward
   horizon of zero future periods. The independently authorized article
   target selects the chain key at
   `251023T1415`, position 9 of the window that starts at 12:00.
2. The client opens each item from 12:00 through 14:00 from that retained
   chain key. It makes no further issuer call.
3. The client tries the items at `251023T1430` (later in the same window),
   `251023T1145` (the preceding window) and `251024T0000` (the next window)
   without an unlock. Each stays missing and unopened, and what the client
   retains does not change. These are absence of reach, not grant refusals: the
   issuer is not asked again, so its clock and policy cannot answer them.

The optional future horizon names no coordinates. The independently selected
cutoff chain key reaches all ten coordinates from the window start through
the cutoff. The issuer's recorded period policy authorizes every position in that prefix
([spec-profile--chain-keys.md §13.1](../../../../../../docs/spec-profile--chain-keys.md#chain-route-periodcount));
the client never learns the horizon.

`js/test-vectors/chain-keys-prefix.test.js` replays the recorded markup
through the real JavaScript issuer and client, set up from `inputs.json`
alone, and holds every assertion. A second test checks the recorded bytes with
stock WebCrypto HKDF-SHA-256 and AES-GCM, apart from the reference: the Leaf
context bytes, every prefix period key and every prefix item's plaintext. This
directory is data: it imports and executes nothing.

- `inputs.json` holds the issuer and client setup: the fixed clock, issuer
  keypair, publisher registration, geometry, supply plan, the issuer's
  decisions in call order and the client's reads in order.
- `renders.json` holds each render's markup delivery, signed token, wrapped
  coordinate and supplied chain label.
- `exchange.json` holds the one unlock request the client posted and the
  issuer's answer.
- `expected.json` holds the facts the replay asserts: the witness, the
  response form, the policy horizon, each prefix coordinate's period key
  and plaintext, each out-of-reach coordinate with its kind of refusal, and
  the one issuer exchange. It then holds what each read observed.

The exchange is recorded below HTTP: status and JSON body are retained, not
actual response headers. Replay supplies the in-memory JSON transport. These
records do not establish HTTP Content-Type admission or browser behavior.

The cutoff key, the prefix period keys and the Leaf context bytes in
`expected.json` come from case `c1` of the frozen
[construction vectors][vectors], written by a generator that does not import the extension. The recorder
refuses to write a story that disagrees with them. Each out-of-reach entry also
carries the period key its item was wrapped under, as a control that the item
is openable; the `251023T1430` period key comes from the same frozen case, the
other two from the recorder's own publisher generation.

`manifest.json` declares the members with their sha256, the consumers, the
provenance and the limitations. `SHA256SUMS` repeats the payload sums in
`sha256sum -c` form. This README is a required member and is not hashed.

Record or check from the repository root:

```
node js/tools/record-chain-keys-prefix.js
node js/tools/record-chain-keys-prefix.js --check
```

`--check` writes nothing. It exits 0 only when the directory holds exactly
the declared members, each member matches its sha256, and a fresh recording
writes the same text for every generated file. It exits 1 when one of those
does not hold and 2 when it cannot read the package. The package check and
the replay test are separate: the check proves these are the bytes the
recorder writes, the replay proves the issuer and client still behave as
recorded. `js/test-tools/record-chain-keys-prefix.test.js` tests the check
itself on damaged copies of this package.

`stability: draft` means the recorder may rewrite this package as the draft
changes. A frozen package is never rewritten; a change after a freeze is a
new package revision.

The keys here are published test keys. The ES256 signatures are retained
values: a regeneration keeps a recorded signature only after it verifies over
the same header and payload.

Limitations: every claim decision is incomplete. The package is regression and
provenance evidence for the JavaScript issuer and client, not independent
conformance. It does not replay the publisher: the renders are recorded input.
It covers one geometry, one window and one cutoff, one issuer, direct
transport and ECDH-P256 envelopes only, and no client-bound transport, rival
generation, policy refusal or response-admission refusal; the
[profile scenario](../../../../../../js/test-profiles/dca-profile-chain-keys.test.js)
covers the last two live.

[vectors]: ../../../../../../js/extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json

# Period-key issuer and client composition

This package records one period key story under `dca-profile-period-keys`, with
the publisher supplying period-key envelopes and item wraps only: no item
content key and no chain key. One browser reads three renders against one
issuer:

1. Render A offers the current and the next period. The issuer grants only
   the current one. The client opens A and keeps that one period key.
2. Render B, at the same instant, opens from the kept period key. The client
   makes no issuer call.
3. An hour later, render C needs the next period. The issuer grants nothing
   and answers 401. The client caches nothing and opens nothing.

`js/test-vectors/period-key-composition.test.js` replays the recorded
markup through the real JavaScript issuer and client, set up from
`inputs.json` alone, and holds every assertion. This directory is data: it
imports and executes nothing.

- `inputs.json` holds the issuer and client setup: clock, issuer keypair,
  publisher registration, the period keys and the issuer's decisions in call
  order.
- `renders.json` holds each render's markup delivery and its signed token.
- `exchange.json` holds each unlock request the client posted and the
  issuer's answer.
- `expected.json` holds what each step observed: text, item error, unlock
  result, what the issuer's policy was asked, the cached period keys and the
  counters.

The exchange is recorded below HTTP: status and JSON body are retained, not
actual response headers. The replay supplies its in-memory JSON transport;
this package does not check HTTP Content-Type admission. Its PageLoad story
uses `denied` for the final 401 attempt. That is a story observation, not a
route API token: an issuer that answers a denial still counts as `answered`
at that API boundary.

`manifest.json` declares the members with their sha256, the consumers, the
provenance and the limitations. `SHA256SUMS` repeats the payload sums in
`sha256sum -c` form. This README is a required member and is not hashed.

Record or check from the repository root:

```
node js/tools/record-period-key-composition.js
node js/tools/record-period-key-composition.js --check
```

`--check` writes nothing. It exits 0 only when the directory holds exactly
the declared members, each member matches its sha256, and a fresh recording
writes the same text for every generated file. It exits 1 when one of those
does not hold and 2 when it cannot read the package. The package check and
the replay test are separate: the check proves these are the bytes the
recorder writes, the replay proves the issuer and client still behave as
recorded. `js/test-tools/record-period-key-composition.test.js` tests the
check itself on damaged copies of this package.

`stability: draft` means the recorder may rewrite this package as the draft
changes. A frozen package is never rewritten; a change after a freeze is a
new package revision.

The keys here are published test keys. The ES256 signatures are retained
values: a regeneration keeps a recorded signature only after it verifies over
the same header and payload.

Limitations: every claim decision is incomplete. The package proves the
period-key-only supply path through the real JavaScript issuer and client. It
does not replay the publisher, and it covers no chain keys, no
client-bound transport, no second issuer and no independent conformance.

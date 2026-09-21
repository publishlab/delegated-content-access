# Content aad derived on the client

The client fills content names such as `bodytext` and `locked-data` and rebuilds
the content aad from the resource id, version and content name instead of
reading the aad field shipped beside the ciphertext. Its own
`implementation/contentAad.js` holds the derivation, and
`test-lib/harnesses/DerivingUnsealer.js` extends the standard reference client
so only the aad source differs. `comparison.test.js` checks four things in order:
whether the client derives the aad the publisher shipped on every checked-in
protocol fixture, whether a page whose shipped aad is wrong for every item still goes
end to end through an untouched issuer, whether the derived binding fails the
way the shipped one does when its inputs move, and what it costs to ignore the
field. The selected assertions run to completion.

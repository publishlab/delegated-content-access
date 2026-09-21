# BIND anchored on renderId and slot

Each control here removes one piece of the shipped binding, and the tests show
what then opens. Its own `implementation/` holds the three controls: `bind.js`, the
delimiter-less join that core rejected, which lets `premium1` open under a `premium`
grant; `unboundSealing.js`, the seal as it stood before the binding; and
`naiveSealing.js` over that join. `comparison.test.js` runs each control
against the shipped `bind.js` and `keySealing.js` on both carriers, asserting
the wire width of each. `bind-self-test.test.js` replays the checked-in
`verification/vectors/v1-alt--bind-on-renderId-and-slot/bind-blobs.json` through the
standard `bindSelfTest` harness and separates a concrete binding mistake from
request tampering. Both entry points run their complete selected assertions
to completion.

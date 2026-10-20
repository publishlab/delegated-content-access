# Period BIND over publisher authority

This experiment compares the shipped render-scoped envelope BIND with a
candidate binding over publisher, `accessGroup`, canonical period label and key
kind. The candidate omits `renderId`. Moving a period-key or chain-key envelope
between two renders under the same publisher authority opens under the candidate
and fails under the shipped BIND. Both carriers are exercised. The delivered
period capability can already be reused across matching renders; this test
concerns reuse of the publisher-to-issuer **sealed envelope**, not a newly
demonstrated need for client key reuse.

The publisher-change case deliberately reuses one issuer opening keyset and a
colliding `renderId` across two publisher names. It isolates the primitive BIND
field: the candidate refuses the relabel, while the shipped BIND accepts the
same bytes at that primitive boundary. It is not a valid isolation design for
mutually untrusted publishers. The current security model requires separate
opening keysets for them; issuer registration, signature and policy admission
are outside this suite.

The candidate also omits chain geometry. These cases hold geometry fixed, so
they cannot establish safe chain-envelope substitution across geometry or show
that this candidate can replace the complete chain-key BIND. Period labels use
the current `YYMMDDTHHMM` spelling; the chain control uses the same supplied
label with an explicit fixed geometry. The candidate is an experimental
construction, not a selected protocol change or a complete migration plan.

`comparison.test.js` runs the candidate from
[`_implementation/bind-on-authority/`](../_implementation/bind-on-authority/),
while `control.test.js` runs the shipped
`core-shared--publisher-issuer/keySealing.js`. Both run
`test-lib/suites/period-binding-authority.js` unchanged and classify every
observed outcome by name. `retained-render` separately runs the candidate's
`keySealing.js`.

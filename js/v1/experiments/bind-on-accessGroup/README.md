# Sealed value bound to the accessGroup alone

The publisher seals a content key with a binding built from the accessGroup
`premium` alone, no renderId. A reader in `premium` moves that blob into another
render, or swaps it for another item's, and the issuer rebuilds the same
`premium` string either way, so it opens the moved blob anyway. The tests record
which of the shipped relabels the issuer still refuses under this binding and
which it opens. It uses
[`_implementation/bind-on-accessGroup/`](../_implementation/bind-on-accessGroup/),
which `retained-render` also runs. `comparison.test.js` runs the shipped
relabel requirement from `test-lib/suites/binding-relabel.js` against it. It
records the relabels this construction opens as expected divergences while
retaining the shipped refusal assertions and first proving each moved key is
usable.
`characterization.test.js` covers this implementation on its own: the bound
value, refusal codes, and the wire coordinate named when a content value is
malformed.

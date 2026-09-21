# Reader retaining an old render

A reader keeps render `abc123` open after the publisher has issued `xyz789`,
and presents a value sealed for the old render at the new render. The shipped
keySealing rebuilds the binding with `xyz789` and refuses; under the other two
bindings, which carry no render coordinate, the issuer opens the moved value.
One suite, `test-lib/suites/retained-render.js`, runs against three bindings,
and each entry point supplies the key sealing it runs with.
`render-coordinate.test.js` runs the control, the shipped
`core-shared--publisher-issuer/keySealing.js`, and pins its refusal of the
moved value.
`scope-coordinate.test.js` runs
[`_implementation/bind-on-accessGroup/`](../_implementation/bind-on-accessGroup/)
and `authority-by-kind.test.js` runs
[`_implementation/bind-on-authority/`](../_implementation/bind-on-authority/),
the two bindings that carry no render coordinate. All three run the complete
suite; the suite states the outcome each binding reproduces.

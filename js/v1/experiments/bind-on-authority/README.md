# Period BIND over publisher authority

The publisher seals a period key with a binding over publisher, accessGroup
`premium`, period and key kind, and leaves the render out. A reader moves that
blob from render `abc123` to render `xyz789`. The candidate opens it, on both
the exact and the chain kind; the shipped keySealing refuses it. It uses
[`_implementation/bind-on-authority/`](../_implementation/bind-on-authority/);
`retained-render` runs the same `keySealing.js`. Both entry points drive
`test-lib/suites/period-binding-authority.js` and pin every outcome by name:
`comparison.test.js` runs the candidate and `control.test.js` runs the shipped
`core-shared--publisher-issuer/keySealing.js`. Each side runs the complete
shared requirement.

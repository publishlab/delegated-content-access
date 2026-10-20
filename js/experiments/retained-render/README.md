# Reader retaining an old render

This experiment compares envelope BIND coordinates when an old publisher-sealed
period-key blob is presented under a newer render. Current BIND includes the
signed render ID and refuses that move. Two historical alternative bindings
omit the render coordinate and open the moved blob. The same original period
key is sealed in both renders so the comparison isolates BIND; this is allowed
period-key reuse at one publisher, access group and period coordinate.

The retained article's period-key content-key wrap uses **no AAD**, as current
v1 specifies. The suite seals its content under a fixed local string,
`article-old|1|premiumtext`, in the carried format v1 used before 2026-10-15;
content AAD is not a coordinate this experiment compares. The test first
opens that saved article at its honest old coordinate. It then tests only the
moved issuer envelope at the admitted hourly label `251023T1400`. The suite
calls envelope sealing and opening directly; it does not exercise an issuer's
period-label admission or policy. An envelope refusal does not revoke a period
key already delivered to a reader: that reader can still open retained
ciphertext and matching wraps within its capability reach.

`render-coordinate.test.js` uses the current sealed-envelope implementation;
`scope-coordinate.test.js` and `authority-by-kind.test.js` use historical
alternatives. ECDH-P256 and RSA-OAEP each run the same suite. The green tests
characterize acceptance or refusal by those constructions; they do not adopt
an alternative or claim the old article becomes inaccessible after a denial.

Run from `js/`:

```sh
node --test --test-reporter=spec experiments/retained-render/test/*.test.js
```

The focused run on 2026-10-11 passed 9 tests with no skips or TODOs.

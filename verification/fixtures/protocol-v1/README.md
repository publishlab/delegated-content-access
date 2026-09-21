# Protocol v1 fixtures

These recorded renders and unlock requests are shared test inputs. Each tier
that reads them holds the assertions it makes from them.

`manifest.json` declares exact membership, format, and which test tier currently
asserts from each file. Portable base contracts select `base-contract`;
reference tests covering JavaScript-only or historical behavior select
`reference`.

`SHA256SUMS` covers every JSON payload and excludes the manifest.

`stability: draft` means this is the one mutable fixture package for the
current draft protocol. The generator may rewrite it as the draft changes; do
not create fixture revision numbers during that period.

Setting `stability` to `frozen` makes this package the immutable v1 baseline.
After that, a compatible adopted change publishes a separate fixture revision.
It does not overwrite the frozen package. A wire-incompatible change belongs
to a new protocol version, not a fixture revision.

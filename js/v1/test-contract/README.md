# Portable contract selectors

These tests exercise an explicitly supplied implementation binding. They do
not import the JavaScript reference implementation unless the selected binding
does so.

Run every base target a binding declares:

```sh
npm run test:contract:base -- path/to/binding.js
```

Run one target against one or more bindings:

```sh
npm run test:contract:issuer-endpoint -- path/to/binding.js
npm run test:contract:issuer-core -- path/to/binding.js
```

The paths are relative to `js/v1/`. Every binding comes from the command line.
`npm run test:contract:reference:base` explicitly selects the combined local
reference binding. `npm run test:contract` adds runner validation and the
separately named endpoint fixture binding.

A binding is an ESM module exporting `dcaTestBinding.targets`. Each own target
name selects a closed entry in `contract-targets.json`. Its declaration names
the supported versions, delivery modes, contract profiles and observations,
plus the target's driver. The base selector runs only the base targets a
binding declares, leaves any other declared name to a later selector, and
fails if the binding declares no base target. Each target README documents its
driver boundary.

Optional extensions have no portable contracts yet. Their reference tests
remain under `extensions/<name>/test/`.

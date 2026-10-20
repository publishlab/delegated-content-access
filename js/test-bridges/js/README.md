# JavaScript target adapter

This adapter lets unchanged Node tests call a JavaScript test target through
the generic [test-bridge contract](../_shared/CONTRACT.md). It runs the target in a
separate Node process, so a call crosses the same process boundary and value
serializer as a call to a PHP or compiled target.

## Start coordinates

`DCA_TARGET_ROOT` names the target root. It is trusted process configuration,
never test request data.

The adapter looks up each module by the reference path the test imports. A
test that imports `core-shared/geometryBounds.js` makes the adapter import
`core-shared/geometryBounds.js` below the target root. Every function export
of that module, and every export whose value the bridge can carry, becomes a
member under its export name. The driver routes a reference function export
to the member with the same name. An exported class, other than an error
class, becomes a claimed class: an object of it that a call returns crosses
as a [handle](../_shared/CONTRACT.md#object-handles), and each method its
instances have, own or inherited, is a member the test's proxy calls. A constant always comes from the reference,
so a test that only reads constants does not test your code. A path outside
the root is refused.

A target does not have to mirror the reference's layout. A small directory of
re-export files can map reference paths and names onto your own modules:

```js
// /path/to/shim/core-shared/geometryBounds.js
export * from "../../your-dca/geometry.js";
export { checkGeometry as inspectPeriodGeometryBounds } from "../../your-dca/geometry.js";
```

```sh
DCA_BRIDGE=js DCA_BRIDGE_MODE=strict DCA_TARGET_ROOT=/path/to/shim \
  pnpm test:bridge test-reference/core-shared/geometry-bounds.test.js
```

Run from `js`. In strict mode a call to a function the shim lacks fails
with `strict bridge run: <module>#<export> is not claimed by the test target`;
in overlay it runs on the reference, and the transcript does not record it.
Classes and constants the shim lacks load from the reference in both modes. A named selection such as
`portable-core` fails on each required export the shim does not claim, so run
one to see what is still unmapped.

## Checking the bridge itself

This bridge refuses to start without `DCA_TARGET_ROOT`, and the adapter
refuses without a root too. [`../js-loopback/bridge.mjs`](../js-loopback/bridge.mjs)
names `js` as the target root, so the adapter loads the reference modules
and the tests run the reference against itself across the process boundary.
That run checks the bridge: values cross, the proxy routes claimed exports,
and the transcript records the calls. It tests no implementation other than
the reference.

To keep your target root in a file, copy `js-loopback/bridge.mjs`, point its
`../_shared/` and `../js/` imports at this checkout, change `targetRoot` and
`id`, and set `DCA_BRIDGE` to the copy's path. The `id` labels debug lines and
transcripts.

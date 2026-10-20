# JavaScript demonstration layer

`js` is the reference package. This `demo/` directory inside it holds the
demonstration layer: code only the example deployment uses.

Put code here only when it models or presents the example deployment:

- `actors/` holds stateful publisher, issuer, browser and infrastructure actors;
- `scenarios/` holds code that builds worlds and changes their public state
  over time;
- `support/` holds demo-only values, policies and composition helpers;
- `browser/` holds the page that runs a scenario interactively.

Protocol behavior belongs in `core-*`. Reusable delivery, storage and transport
choices belong in `adapter-*`; host-facing entry points belong in
`integration-*/`; `ports/` holds explicit contracts and endpoint bindings.
Tests and variant proofs use their own trees.

Judge placement by one test: behavior an implementer could reuse without
adopting the demonstration world does not belong here. Demo actors
may compose reusable components, but reusable components never import the demo.

## HTTP evidence boundary

The simulated `Network` supports unlock POSTs and health probes. It does not
simulate OPTIONS or browser CORS enforcement. Preflight behavior is tested
directly in `test-reference/adapter-issuer/browser-unlock-http.test.js`, relative
to `js/`. Real-host and browser evidence is separate; passing a demo story
does not establish proxy handling, raw HTTP-header admission or a real preflight.

The simulation passes the captured serialized request to issuer admission.
Byte counts describe those messages; the simulation does not establish that
a production HTTP host preserves request bytes or applies the HTTP binding
correctly.

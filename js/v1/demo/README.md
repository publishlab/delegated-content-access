# JavaScript demonstration layer

`js/v1` is the reference package. This `demo/` directory inside it holds the
demonstration layer: code only the example deployment uses.

Put code here only when it models or presents the example deployment:

- `actors/` holds stateful publisher, issuer, browser and infrastructure actors;
- `scenarios/` holds code that builds worlds and changes their public state
  over time;
- `support/` holds demo-only values, policies and composition helpers;
- `browser/` holds the page that runs a scenario interactively.

Protocol behavior belongs in `core-*`. Reusable delivery, storage and transport
choices belong in `adapter-*`; host-facing entry points belong in `ports/`.
Tests and variant proofs use their own trees.

Judge placement by one test: behavior an implementer could reuse without
adopting the demonstration world does not belong here. Demo actors
may compose reusable components, but reusable components never import the demo.

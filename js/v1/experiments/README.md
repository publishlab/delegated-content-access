# JavaScript experiments

`experiments/` sits beside the framework it exercises so an experiment can
reuse test-only suites and harnesses without entering standard runtime code.
The directory holds alternate implementations, their tests and unpromoted
suites.

Each experiment proves its claim by running. It may show that a construction
works, fails, or produces a particular harmful result. Green means the stated outcome
was reproduced, not that the construction is approved. Removing this directory must
not break standard runtime code, reference tests or reference vector generation.
The combined vector generator has no dependency on it.

Experiments cover:

- alternative constructions being compared;
- proposed base requirements or protocol extensions;
- deliberately insufficient constructions that reproduce an attack or loss
  of authority; and
- rejected or historical behavior worth retaining as executable evidence.

A green run means every entry reproduced its stated outcomes. Rejected
constructions have two forms: one may keep the shipped shared assertion with a
todo status, and the gate pins its exact failure count; another may positively
characterize the harmful answer it returns, so that repairing the construction
turns the characterization red. A construction green under the shipped
assertions is a candidate, not evidence of a rejected weakness.

```text
experiments/
  README.md
  reference.mjs         the one file an outside bridge imports
  _implementation/      alternate implementations two or more experiments use
    <alternate-implementation>/
  _shared/              everything else that belongs to no single experiment
    test/               the experiments directory's own tests
  <experiment>/
    README.md           what it asks, its status and a dated result
    implementation/     alternate implementations only this experiment uses
    test-lib/           suites and harnesses only this experiment uses
    test/               its entry points, named for the kind of proof
```

One experiment is one directory. Its README states the outcome the test run
reproduces for it. The test command runs `experiments/*/test/*.test.js`, which
covers every experiment and [`_shared/test/`](_shared/test/) alike. An
experiment imports its own files, [`_implementation/`](_implementation/),
[`_shared/`](_shared/) and the standard runtime, never another experiment. An
alternate implementation never imports another. Anything a second experiment
needs moves up to the matching underscore directory, and an alternate
implementation moves as a whole directory. Move an experiment elsewhere without
the underscore directories it imports and it fails at load.

Inside an experiment each directory holds one kind of file. An alternate
implementation holds alternate protocol or domain behavior, the code a test
swaps in for standard behavior; it holds no entry point, fixture, adapter or
suite. A
`test-lib/suites/` file owns cases, assertions and completeness checks, and a
`test-lib/harnesses/` file adapts alternate behavior to a suite. Only
`test/` holds executable `.test.js` entry points, each one an explicitly
selected comparison or characterization, and an expected-failure profile there
names the cases this construction fails, so the entry point keeps every shared
case in place and as written. The hostile-carrier mechanics that the standard
vector generator shares stay with `../tools/vector-fixtures/`, as test
construction rather than as an alternate implementation.

Run every experiment from `js/v1/`:

```sh
pnpm run test:experiments
```

`pnpm test` runs the standard reference and contract suites and leaves this
directory alone; `pnpm run test:all` runs both tiers, and stops before this one
when `pnpm test` reported a failure or an incomplete run. A single entry point runs
on its own path, for example:

```sh
node --test --test-reporter=spec experiments/bind-on-accessGroup/test/comparison.test.js
```

Promotion removes the experiment prefix:

- `experiments/<name>/test/<entry>.test.js` becomes `test/<name>--<entry>.test.js`
  or the name the standard suite gives it;
- `experiments/<name>/test-lib/suites/<suite>.js` becomes
  `test-lib/suites/<suite>.js`;
- never promote an alternate implementation file by moving it. Once a behavior
  is selected, write it out explicitly in its production boundary: `core-*` for
  a base requirement or `extensions/<name>/` for a selected extension.

Standard `test-lib/` never imports this tree. Standard `test/` imports only
`experiments/reference.mjs`, to check the public experiment reference surface.
A selected extension's own test gives evidence for that extension rather than
for base reference behavior; its gate installs the extension explicitly.

## Promote a selected requirement

Promotion applies only to a selected requirement and its tests. Never promote domain
code by moving it. Once you select a design, implement it in the owning base or
extension boundary and leave the variant implementation where it is, as
comparison evidence, or remove it later.

Promote the requirement only after the behavior is approved and a
target-neutral suite states it. Protocol changes also need their wire shape and
versioning decision before core changes.

1. Move the reusable suite from the experiment's `test-lib/suites/` to
   `test-lib/suites/`.
2. Change only mechanical relative imports. Keep its cases, fixtures,
   assertions and expected outcomes unchanged.
3. Add a thin entry point under `test/` that selects the new production
   behavior.
4. Implement the selected behavior in its owning `core-*` or
   `extensions/<name>/` boundary. Never promote an alternate implementation by
   moving it out of `experiments/<name>/implementation/` or
   `experiments/_implementation/`.
5. Run the standard suite against the selected production boundary with the
   chosen outcomes stated as ordinary assertions.
6. Keep comparison entry points under `experiments/<name>/test/` only while
   they still explain a useful rejected or historical choice.

If promotion requires weakening or rewriting an assertion, stop: either the
requirement was not actually selected or the candidate suite did not express
it independently of its prototype.

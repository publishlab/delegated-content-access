# JavaScript reference architecture

Status: Informative Draft

## Purpose and authority

The reference, native implementations and shared verification form one system.
The architecture supports directly usable JavaScript role entries, practical
native implementations and shared assertions that distinguish incorrect
behavior. Prefer a simpler composition when it preserves those properties;
introduce an abstraction for a concrete responsibility or observable behavior.
SDK packaging and release commitments are separate from supported-entry quality.

Design public contracts for both statically and dynamically typed implementations,
including PHP, JavaScript/TypeScript, Python, Go and Java, and for request-scoped
or long-running deployments. Preserve useful native types, interfaces and runtime
capabilities while requiring equivalent observable behavior and ownership
guarantees; ports need not emulate JavaScript internals.

This is the canonical architecture for the JavaScript reference.
[PORTING.md](PORTING.md) defines public API contracts, their native counterparts
and shared verification obligations. The
[specifications](../docs/spec---overview.md) define protocol behavior; source
placement, an integration default or a passing test does not change that
behavior. Native implementations need not reproduce this directory tree.

## Layers and application boundary

- **Canonical source.** One readable modern ESM graph is canonical. Source
  copying and production bundling are required consumption properties. Package
  exports, optimized bundles and optional browser artifacts are delivery views
  of that graph, never separately maintained implementations.
- **Entry effects and selection.** Library and profile imports are inert:
  network, DOM, storage, key generation, registration and startup effects begin
  through explicit calls. Auto-start behavior belongs in a separately declared
  artifact. Role- or profile-specific entries remain small and statically
  analyzable. Documented selections must omit unselected roles and profiles by
  copying and representative production bundling without changing behavior.
- **Shared implementation.** Demonstrations, source copies and delivery
  artifacts use the reusable role implementations and preserve their public
  behavior.

Core mechanics remain reusable without the demonstration assembly. Adapters
and integration entries depend inward; core imports neither. The allowed
runtime dependencies outside each reusable outer layer are:

| Source layer | Allowed reference dependencies outside its own layer |
| --- | --- |
| `adapter-client/` | Client core slice. |
| `adapter-publisher/` | Publisher core slice. |
| `adapter-issuer/` | Issuer core slice. |
| `ports/` | Issuer core slice. |
| `integration-client/` | Client core slice and `adapter-client/`; no endpoint port. |
| `integration-publisher/` | Publisher core slice; the application selects and invokes the output adapter. |
| `integration-issuer/` | Issuer core slice, `ports/` and `adapter-issuer/`. |

- Integration entries are supported composition boundaries. Applications supply
  transport, storage, registration, authentication, policy and presentation
  through explicit collaborators. Core does not acquire an implicit browser
  document, filesystem or application service.
- Role extraction and runtime neutrality are separate constraints. Applicable
  layers use the shared runtime APIs specified in
  [runtime by directory](README.md#runtime-by-directory); environment-specific
  integration remains at its declared boundary.
- `js/demo/` composes roles without becoming a dependency of reusable layers.
  Scenarios compose actors; browser presentation composes scenarios. Lower
  layers do not import those assemblies; direct imports of lower layers remain
  permitted. Demo `Browser` and `PageLoad` model client lifetimes without
  becoming supported library entries. A publisher/page test harness remains
  test code, not a client API.

## Role slices and extraction

A core module has one extraction-consumer set. Directory membership determines
that set recursively, including nested modules:

| Consumers | Core directory |
| --- | --- |
| Client | `core-client/` |
| Issuer | `core-issuer/` |
| Publisher | `core-publisher/` |
| Client, issuer | `core-shared--client-issuer/` |
| Client, publisher | `core-shared--client-publisher/` |
| Publisher, issuer | `core-shared--publisher-issuer/` |
| Client, publisher, issuer | `core-shared/` |

A role's base core slice consists of `core-shared/`, its `core-<role>/` and
pairwise directories naming that role.

- A role core imports its own core, universal shared core and its named
  pairwise slices. A pairwise slice imports itself and universal shared core,
  not a different pairwise consumer set. Universal shared core imports no
  role-specific core. No core imports adapters, integration entries, endpoint
  ports or demonstration code.
- These constraints preserve extraction and bound client distribution
  requirements; they are not security or conformance boundaries. Publisher and
  issuer applications may carry both roles without moving their shared code
  into a client-selected slice. Split a module for a distinct responsibility
  or unwanted role dependency, identifying its public imports and behavioral
  checks. Do not create empty slices to complete the matrix.
- Actor [copy manifests](README.md#publisher-client-and-issuer-artifacts)
  select core, reusable adapters and integration entries, beyond the core
  formula above. Selected files and their complete runtime import closure must
  agree. A role label does not make a convenience barrel suitable for a client
  distribution. Type-only dependencies do not enter the runtime closure.
- Core-only declaration extraction is supported independently of actor assembly.
  The selected core formula, plus selected extension cores and their required
  sibling cores, must emit declarations and type-check consumers without copying
  adapters or integration entries. Core contracts describe their actual
  collaborators structurally; assembled aliases belong to integration owners.
  Adapter type aliases may refer inward to those contracts. This adds no runtime
  layer permission and makes no protocol conformance claim. The isolated
  declaration checks cover the affected client, issuer and publisher selections;
  assembled actor consumers retain their separate source/declaration checks.

## Extension composition

- Base runtime source loads without implementation extensions and imports none
  of them. Extensions enter through explicit seams and obey the same role and
  consumer-set constraints. Required sibling implementations may be reused
  where the consuming behavior belongs; pairwise reuse preserves the consumer
  set. Dependency cycles are forbidden. Unrelated extensions remain removable;
  a missing required sibling is a prerequisite failure, not skipped coverage.
- An implementation extension is a source package, not a protocol profile.
  Base may recognize optional wire vocabulary for forwarding, binding or
  counting without selecting its processing. Deployment selects the required
  role implementations according to the specifications. A directory name or
  local bundle alone establishes neither matching peer support nor a complete
  protocol-profile claim.
- A base seam separates responsibilities already present in the behavior;
  it does not interpret a generic mechanism or profile language. When no
  suitable seam exists, an extension's local copy identifies the base code
  copied and the missing seam. The copy does not change base or justify an
  abstraction before the required responsibility is understood. Record local
  contracts and dependencies with the [extension](extensions/README.md).

## Composition and state ownership

- **Contracts and delegation.** Integration entries assemble reusable
  implementations without absorbing application policy or reimplementing core
  behavior. Collaborator contracts describe required behavior, preserving
  supported structural and synchronous implementations. Extension-specific
  input types declare composition; runtime contributions still need validation.
  Wrappers preserve base collaborator contracts and delegate stateful behavior.
  They expose only forwarded options. Extensions project their added request
  members for conditional retries; a route that cannot be projected cannot
  retry with the broader request. See
  [role integration operations](PORTING.md#role-integration-operations).
- **Admission and capture.** Construction checks and runtime snapshots are
  separate obligations. A valid selected configuration member must reach the
  snapshot, including a non-enumerable own member when the contract admits it.
  See [publisher render input](PORTING.md#publisher-render-input).
- **Lifetime and identity.** Mutable runtime state belongs to an explicitly
  owned instance or composition, not module scope. Time and randomness enter
  through explicit collaborators; composition supplies documented production
  defaults. Capturing input values does not freeze mutable state inside
  application callbacks. Per-render state belongs to its render;
  reusable services and shared caches retain their assigned lifetimes.
  Preserve collaborator identity where composition requires it. Native
  factories may construct their own callbacks and state. See
  [injected collaborators](PORTING.md#injected-collaborators).

### Long-running native services

A Java server can retain a configured publisher or issuer composition while
handling many calls. Reuse depends on its collaborators' contracts; a service's
lifetime does not make each call's mutable state shared. A practical mapping is:

| Responsibility | Lifetime and ownership |
| --- | --- |
| Configured role assembly and reusable services | Host-owned; reusable where their configuration and collaborators permit it. |
| Publisher render | Fresh Sealer per `publish`; each low-level seal owns its captured inputs and result. |
| Issuer invocation | Request, registration, policy input, captured instant and result belong to that call. |
| Retained generation or cache | Explicit owner, scope and retention lifetime, including when the host replaces or releases it. |

Reusable services must not keep replaceable current-request or current-render
fields. Request-confined builders can hold their own state. Java interfaces,
records and byte arrays can express the contracts naturally; a record alone
does not copy or freeze its contained arrays or collections. Capture owned
values while preserving borrowed collaborator identity. Native synchronous
methods, futures and exceptions preserve operation ordering, result values and
failure scope as defined in [PORTING.md](PORTING.md).

Native threads add a scheduling model beyond JavaScript asynchronous overlap.
Separate instances or host serialization are valid; shared-instance parallel use
needs a documented native synchronization contract. Verify isolation and failure
recovery with multiple calls in one process, and parallel execution where the
port offers that support. JavaScript interleaving tests establish no native
thread-safety claim. Resource and cache lifetimes follow their explicit owners;
correctness must not depend on request teardown or garbage-collection timing.

## Architectural enforcement

- **Structural checks.** The
  [source-boundary checks](test-base/import-boundary.test.js) enforce role and
  layer dependencies. The [extension-boundary checks](test-base/extension-boundary.test.js)
  enforce base independence, extension dependency closure and runtime/development separation. Actor manifests are checked against allowed
  layers and import closure. Development helpers may cross roles and
  extensions; unclassified extension modules retain runtime constraints.
  Unsafe fixture code stays outside extractable roles and demo runtime.
  Extension-owned tests stay with their feature; interactions without a primary
  owner belong in `test-extensions/`. The
  [test inventory](test-reference/test-infra-layout/test-inventory.test.js)
  checks test ownership.
- **Behavioral obligations.** Source boundaries do not establish substitution,
  input ownership or protocol conformance. Those need discriminating behavior
  tests and consumer checks; declaration emission alone does not establish
  useful types. The [checks](README.md#checks) state the current executable
  scope. Architectural rules remain obligations where automation is incomplete.
- **Native evidence.** Shared assertions must exercise real target operations
  with visible routing and distinguish independent state from shared state.
  Bridge behavior, selected native crossings and deployment readiness are
  separate claims. The [port-testing contract](PORTING.md#testing-a-port) and
  [bridge evidence](test-bridges/README.md) define the evidence boundaries.

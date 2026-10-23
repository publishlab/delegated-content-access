# Extensions

A deployment selects optional behavior on top of the base reference, one
extension per directory.

An extension directory is an optional implementation package with explicit source dependencies,
not a protocol profile identifier. A package may hold related methods sharing
one source seam, as `client-bound-transport` does for ECDH-P256 and RSA-OAEP.
One named profile may select several mechanisms, and one directory may support
several profiles. The profile specification decides what an operation selects;
each extension README identifies the profile, proposal or experiment its code
serves. Directory names describe the implementation mechanism without adding
a second protocol identifier vocabulary.

The [reference architecture](../design--reference.md#extension-composition)
defines source and composition constraints. Extension-local obligations:

- Each extension README states its affected behavior, required dependencies,
  base seams, copied base code and status. Everything under an extension
  directory is provisional until a specification names it.
- Tests and bench scenarios stay with their primary feature owner even when
  they import siblings. Shared interactions without a primary owner belong in
  `../test-extensions/`. Development prerequisites are separate from runtime
  source dependencies.

## Nonce omission prototypes

`nonce-free-envelope/` and `nonce-free-response/` are isolated candidate
implementations with behavior tests. They are not registered profiles and do
not change the currently specified procedures. Their READMEs state the exact
candidate, setup, seam limitations and evidence. Tests and portable assertion
suites stay inside those extensions until any later adoption.

## Content-groups proposal extension

[`content-groups/`](content-groups/README.md) implements the
[content groups proposal](../../docs/spec-profile--content-groups.md):
flat named groups, one 32-byte seed per content name and window, and 16-byte
item connectors.
Its runtime uses the required `chain-keys` implementation through role-specific
imports. Owned tests live in `content-groups/test/`; shared interactions remain
in `../test-extensions/`. It has configurable deployment admission budgets and no
protocol-wide group-count ceiling.

This is releasable proposal code, not an adopted profile or a complete current
DCA conformance claim. Its README states implemented transports, composition
interfaces, tests and remaining integration limits.

## Finding source for a role

Start with the selected protocol profiles and their dependencies in
`docs/spec--profiles.md`; the checked
[`profile catalogue`](../../verification/profile-catalogue/README.md)
provides the current machine-readable names and closure. For base source,
copy the direct `.js` files named by the pinned-revision manifest for the
chosen role: [`client`](../copy-manifest--client.json),
[`publisher`](../copy-manifest--publisher.json) or
[`issuer`](../copy-manifest--issuer.json). Those manifests include base
components and integration entries but no optional extension code.

For each selected extension, read its README for the affected roles and host
composition. Its `core-*` subtree follows the same role rule as base: take
`core-shared`, that role's `core-*`, and pairwise slices whose role set contains
the chosen role, including nested `.js` files. Copy the extension's other
host-facing modules only when their import closure fits the intended role.
Root convenience entries such as `client-bound-transport/ecdhP256.js` and
`chain-keys/referenceProfile.js` compose both client and issuer or publisher
source; they are not automatically part of a client-only slice. Tests, test
helpers and tools are outside a role copy. Follow the complete runtime import
closure into required sibling extensions, applying the same role selection.
Imports/reexports express source dependencies; no separate dependency manifest
is needed. Root convenience barrels may combine roles and are not a safe
substitute for checking a client-only closure. The host selects extensions
through base injection seams; extension implementations can import their own
required siblings directly. A source import alone does not enable a wire
profile. No automated extension extractor is currently supplied.

For a client, the host passes each selected extension's value or factory to
the relevant [`composeClient`](../integration-client/composeClient.js) option:
`chainKeyProfile` with `chainCache` for `chain-keys`,
`clientBoundKeyCapability` for `client-bound-transport`, and `contentDecoders`
for `content-compression`. `content-key-seal-omission` has no option of its own:
its `content-key-seal-omission/core-client/OmissionRequestBuilder.js` and
`content-key-seal-omission/core-client/BoundContentKeyResolver.js` stand in
for the base request builder and resolver, so a client selects it through
`requestBuilderFactory` and `resolverFactory`.
Resolver factories used by a delivery client must provide `resolveAuthenticated`
as well as its other required operations; item authentication selects among all
admitted candidates. Construction refuses an incomplete resolver.

Anything an extension needs beyond these boundaries (a seam, a wire member,
an error code) changes base at the design level. Write it up as a design
change. The extension does not land until that change is reviewed and
approved.

## Test and claim documentation

Each extension README names the protocol profile, proposal or
implementation-only experiment it realizes. It also names its focused test
command, the boundaries those tests exercise and any applicable vector,
fixture, composition or conformance evidence. Passing those checks establishes
only the behavior exercised at the named source and evidence revisions; later
cases may strengthen the same claim.

A `test/` directory does not need another README when its extension README
supplies that information. Tests that select several extensions inherit the
claim and placement rules in [`../test-extensions/README.md`](../test-extensions/README.md),
which names the combinations that directory exercises. Directory placement
does not turn an implementation test into independent conformance evidence.

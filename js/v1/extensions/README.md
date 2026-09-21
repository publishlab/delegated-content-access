# Extensions

A deployment selects optional behavior on top of the base reference, one
extension per directory. The boundaries:

- Base imports nothing from here. `npm run check:boundaries` runs base with
  this directory deleted.
- An extension imports base and its own directory, nothing else. It does not
  import another extension. A test that needs two extensions goes to
  `../test-extensions/`.
- Any one extension can be deleted and base plus every other extension still
  load. `check:boundaries` removes each in turn.
- Role slices inside an extension use the `core-*` names and follow the same
  role import rules as base: a `core-client` slice reaches no publisher or
  issuer module, a pairwise slice only its two roles and `core-shared`.
- An extension reaches base through the injection seams base already has.
- Where base has no seam for what an extension needs, the extension copies the
  base lines into itself. The module names the lines it copied and why no seam
  existed, so base and other extensions can be refactored without it.
- Nothing here changes base.
- Each extension's README states what it changes, which base seams it uses,
  what it copied, and its own status. Everything under an extension directory
  is provisional until a spec names it.

[`../copy-manifest--client.json`](../copy-manifest--client.json) names no
extension directory, so a consumer following it copies no extension code. A
consumer that selects one extension also copies that extension's client-side
directories, following the same role-directory rule the base slice follows, and
passes the extension's value or factory as the
[`composeClient`](../integration-client/composeClient.js) option that takes it:
`periodChainProfile` with `chainCache` for `period-chain`,
`clientBoundKeyCapability` for `client-bound-transport`, and `contentDecoders`
for `content-compression`. `content-key-seal-omission` has no option of its own:
its `content-key-seal-omission/core-client/OmissionRequestBuilder.js` and
`content-key-seal-omission/core-client/BoundContentKeyResolver.js` stand in
for the base request builder and resolver, so a client selects it through `requestBuilderFactory` and
`resolverFactory`.

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

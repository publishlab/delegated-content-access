# Portable issuer-core contract

The binding exposes `admit(rawRequest)` and then
`processMiss({ request: theSameOpaqueHandle, policyInput: { principal, context },
capturedAtMs? })`. The binding supplies the host-selected publisher
registration; `capturedAtMs`, when needed, is host-captured rather than a DCA
wire field. Admission is a closed `{ kind: 'admitted', handle } | { kind:
'failure', code }` result; miss processing is `{ kind: 'success', document,
policyData } | { kind: 'failure', code }`. The harness never parses or
replaces the admitted handle.

This target proves raw semantic results: item content keys, period keys,
coordinate error codes, whole-request codes, and opaque policy data. It
requires `dca-profile-period-keys`; a chain-key profile must be declared later.
It does not prove HTTP status, error prose, delivery callbacks, cache behavior,
or collaborator reach. Its classification as a base contract target describes
runner selection, not the baseline protocol profile.

The current reference binding also consumes the JavaScript source files
themselves: it directly selects `core-issuer/IssuerProcessor.js`,
`core-issuer/IssuerEngine.js`, and the shared JWT-header reader the application
uses to select one publisher registration before a miss. A check walks their
relative imports and reaches exactly `core-shared`, `core-issuer`,
`core-shared--client-issuer`, and `core-shared--publisher-issuer`. That check
proves the source closure; it adds no public entry-point API.

Run this target against supplied bindings with
`npm run test:contract:issuer-core -- <binding> [...]`. The checked-in reference
implementation also declares this target in the combined binding selected by
`npm run test:contract:reference:base`.

<!-- contract-target
{
  "directory": "issuer-core",
  "test": "issuer-core.contract.test.js",
  "runner": "test:contract:issuer-core",
  "requiredAccess": "public issuer-core component",
  "versions": ["1"],
  "deliveryModes": ["direct"],
  "contractProfiles": ["dca-profile-period-keys"],
  "observations": [],
  "fixtureSets": [
    "fixtures/v1/baseline/issuer-admission",
    "fixtures/v1/profiles/dca-profile-period-keys/issuer-admission"
  ],
  "fixtureConsumer": "base-contract",
  "fixtureFormats": ["1", "2"]
}
-->


The registered-signing-key controls carry real ES256 signatures and attacker
`jwk`, `jku` and `x5u` header material. A signature under the registered key
continues to work; a signature under the header's attacker key is refused.
The harness constructs these serialized inputs independently of the tested
implementation. No network key fetch or primitive corpus regeneration is used.

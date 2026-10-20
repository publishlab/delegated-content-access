# Issuer endpoint contract

This target proves the final response a caller receives from a complete issuer
endpoint. It sends a raw DCA request plus harness-only provisioning and expects
only the wire `{ status, body }` response. The driver must not verify, decide,
unseal, map a core result to HTTP, or repair an incomplete response.

Its binding module exports `dcaTestBinding.targets['issuer-endpoint']`. The
driver imports the fixture keys and implements `createIssuerEndpoint(config)`,
which returns `unlock(rawRequest, input)`. `input` provisions a test principal
and policy context; it is not a DCA wire field. This target requires
`dca-profile-period-keys` and has no optional observations. Its classification as a
base contract target describes runner selection, not the baseline protocol
profile. A binding that does not declare the selected version, direct delivery
mode or period-key profile is reported unsupported rather than silently
skipped.

Two local endpoint bindings run in the local aggregate: the ordinary reference
binding through the combined base-reference command, and a differently shaped
fixture binding around the same endpoint. The latter changes only construction,
call, and result containers; it does not implement or repair DCA behavior.

Run this target against supplied bindings with
`npm run test:contract:issuer-endpoint -- <binding> [...]`. The local aggregate
selects the reference implementation through `test:contract:reference:base`
and the alternate fixture through `test:contract:fixture:issuer-endpoint`.

`support/issuer-endpoint-statuses.json` records the status the endpoint must
return, written from the endpoint contract and never copied out of an
implementation. A vector's non-null top-level `code` selects `wholeRequest`,
per-coordinate errors select `partial`, and an answer with neither selects
`success`. The named cases in `support/issuer-endpoint-statuses.js` carry the
entries no vector reaches, and any issuer endpoint implementation can run the
same table in its own contract test.

<!-- contract-target
{
  "directory": "issuer-endpoint",
  "test": "issuer-endpoint.contract.test.js",
  "runner": "test:contract:issuer-endpoint",
  "requiredAccess": "black-box endpoint",
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
The refusal control also instruments the provisioned opening-key store: no
lookup occurs before successful publisher verification. This collaborator
assertion is separate from the wire result and does not add an observations
member to `{status, body}` or establish browser-Origin profile conformance.

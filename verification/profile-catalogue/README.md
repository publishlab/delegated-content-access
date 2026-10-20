# DCA v1 profile catalogue

[`v1.json`](v1.json) is a checked projection of the named profiles in
[`docs/spec--profiles.md`](../../docs/spec--profiles.md). The specification and
its focused mechanism documents remain authoritative for every role duty and
profile-validity requirement; the [Adding a profile](#adding-a-profile) section
below explains how to maintain this checked projection. The catalogue records
profile dependencies, role duty identifiers, and small typed selection shapes
for integrations and conformance reports. It does not select a route, grant
access, interpret a wire message, or prove that a role implements a duty.

`requestedProfiles` contains the most-specific requested profile identifiers
and has set semantics: caller order carries no meaning, and the resolver
rejects duplicate and unknown names. `resolvedProfiles` contains the
de-duplicated baseline, transitive dependencies and requested leaves in
canonical dependency order. These names describe a reporting model; they are
not DCA wire members.

To produce canonical dependency order, repeatedly emit the available profile
whose dependencies have already been emitted and whose identifier is first in
ascending ASCII byte order. For reporting, remove from `requestedProfiles` any
explicitly requested identifier that another requested identifier transitively
requires, then sort the remaining identifiers in ascending ASCII byte order.
Thus explicitly requesting an inherited dependency changes neither reported
array; a baseline-only request reports `requestedProfiles` as
`[dca-profile-baseline]` and resolves to `dca-profile-baseline`.

For the chain-key profile, the projection is:

```text
requestedProfiles: [dca-profile-chain-keys]
resolvedProfiles:  [dca-profile-baseline,
                    dca-profile-period-keys,
                    dca-profile-chain-keys]
```

The profile arrays declare profile closure. They do not encode scope-specific
selections such as supply form, response representation, transform list or
fallback permission; deployment enablement and operation selection are
recorded separately, in the typed configuration owned by the applicable
profile.

`duties` provides stable profile/role/duty names for later evidence claims.
`selections` describes the required fields of a selection record for one
profile. An absent record means that profile has not been selected for that
scope. The catalogue checker validates shape and local implications, while
the integration remains responsible for establishing trusted inputs and
cross-role compatibility. A client-bound chain-key result may use either direct
or client-bound transport when the selected issuer and client duties support
that form. The baseline has no typed selection; the `dca-profile-html-carrier`
record lets the publisher's publication arrangement pick the `json` or `html`
delivery carrier for one delivery.

For `dca-profile-chain-keys`, one record describes **one operation** across the
publisher, issuer, and client. `supply` names the publisher's available
period-key and chain-key forms (`both` permits either); `selectedInput` names
the form used by this operation. `issuerOutput` names the actual response
kind, so an enabled choice of "either" must be recorded as separate selected
operations. The boolean fields state the corresponding enabled issuer and
client duties. Chain input requires issuer chain input and client relay. Chain
output additionally requires client derivation; period-key output projected
from chain input instead requires projected period-key admission, even if the
client does not derive. Available chain supply does not force an operation
using a period key to enable chain duties. This record describes evidence; it does not
make the publisher's, issuer's, or client's selection for them.

The focused JavaScript checker and tests live in
[`js/test-tools/`](../../js/test-tools/). A later verification claim
index may consume this closure and duty vocabulary; evidence-package
membership belongs to that index.

## Adding a profile

[Profiles Section 11](../../docs/spec--profiles.md#11-composition-rules) defines
what a profile must specify, and
[Section 11.1](../../docs/spec--profiles.md#111-profile-validity) owns its validity
requirements. When adding a catalogue entry, first establish that its definition
satisfies those requirements. Record its dependencies, assigned role duties and
selection shapes, then run the catalogue checker. A catalogue entry does not
create or replace a normative profile definition.

A catalogue check can establish the graph conditions: known identifiers, no
cycle, no repeated edge, and at least one assigned duty or two effective
direct dependencies. The checker refuses a profile other than the baseline
that owns no duty and has fewer than two effective direct parents; a parent
that another direct parent already requires does not count, though it stays
in `dependsOn` and the closure. The rule is structural only: whether a duty is
substantive, and whether two parents differ in meaning and can be satisfied
together, stay editorial review.

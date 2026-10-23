# DCA v1 conformance checklist

Status: Informative Draft

Use this checklist for **one claimed role** (publisher, issuer or client) and
the profiles that role implements. It points to requirements in the
[profile specification](../docs/spec--profiles.md) and its focused
specifications; it adds no protocol requirements. A checked box needs evidence
for the named implementation and revision. A deployed path needs its own
cross-role check.

Specification editors must first use this checklist on the DCA implementations
they maintain, role by role and profile by profile. Record where a requirement
cannot be checked, where evidence is missing, and where the checklist is
unclear. This is the checklist's first practical test; it does not turn an
incomplete implementation into a conformance claim.

## Set the claim scope

- [ ] Name the DCA version, implementation and revision, and every claimed
  role. A claim for one role does not claim its peers.
- [ ] Name each optional profile implemented by that role. Resolve its
  dependencies using the [profile catalogue](profile-catalogue/README.md):
  `dca-profile-baseline` is always included; `dca-profile-chain-keys` also includes
  `dca-profile-period-keys`.
- [ ] Record applicable envelope algorithms and content transforms. For a
  deployment claim, distinguish what is **implemented**, **enabled** and
  **selected**, including the selected operation's scope and compatible peers.
- [ ] For every applicable duty below, identify a positive check, a refusal
  or negative check where required, an ordering check where required, and a
  composition check. Record the command, inputs, result and evidence revision.
  Mark untested duties incomplete; a passing vector alone does not complete a
  role or profile claim.

The [profile specification §12](../docs/spec--profiles.md#12-conformance-claims)
defines the full claim record. The catalogue names dependency and role-duty
IDs; neither this checklist nor the catalogue proves a claim.

## Baseline: `dca-profile-baseline`

Check the baseline for **every** claimed role. Apply the common substrate and
the relevant role section in the
[baseline profile](../docs/spec--profiles.md#3-dca-profile-baseline-profile).

- [ ] **Publisher:** signed resource assertion, protected item and compatible
  delivery, with a usable issuer-mediated content-key envelope. Produce the
  delivery as the serialized UTF-8 JSON document of
  [data format Section 6](../docs/spec--data-format.md); markup delivery
  belongs to `dca-profile-html-carrier`. Support the
  required baseline envelope algorithm and the algorithm selected for each
  issuer actually served. Declare in `contentEncodings` exactly the transforms
  applied to each item, in application order, and omit the member when none
  was applied. Emit no `unlockUrl` in any issuer block
  ([data format Section 4.2](../docs/spec--data-format.md#42-issuerdata)).
- [ ] **Issuer:** verify publisher evidence, enforce the core request and
  policy order, open the selected envelope, and produce an authorized direct
  result through the DCA HTTPS JSON endpoint.
- [ ] **Client:** consume the delivery from the serialized JSON document, admit
  it and the associated issuer response,
  relay the needed request material, accept only authorized content-key
  results, and open the protected item. Admit an item's whole
  `contentEncodings` list before resolving its content key, refuse a malformed
  or unsupported list for that item only, authenticate and decrypt before
  decoding, apply the inverse transforms in reverse list order and release no
  partial output.
  A client that supports no transform still conforms. Select each issuer
  endpoint from trusted configuration, ignore any carried `unlockUrl`, and send
  no request when no usable endpoint or applicable issuer material is available
  ([data format Section 4.2](../docs/spec--data-format.md#42-issuerdata),
  [core Section 9](../docs/spec--core-protocol.md#9-delegation-completeness)).
- [ ] **Client context and host composition:** keep pending admission, key
  retention, opening and output with their captured context and delivery under
  [core Section 2.2.1](../docs/spec--core-protocol.md#221-logical-client-contexts-and-pending-work).
  End the predecessor's output eligibility before successor use, check again
  at the actual side effect after awaits, and isolate retained capabilities
  including late writes. Preserve unrelated live contexts; retirement does
  not revoke delivered bytes. This duty applies to item-key-only clients too.
- [ ] **Combined path, when claimed:** a compatible publisher, issuer and
  client complete the selected request and result path, including refusal and
  partial-result cases. Record the endpoint and algorithm selection used.

## Optional profiles

For each selected optional profile, check its **dependency first**, then only
the duties assigned to the claimed role. A profile can have several permitted
forms; record which form was implemented or selected instead of treating its
name as proof that every form ran.

### `dca-profile-browser-origin`: requires baseline

[Profile §4](../docs/spec--profiles.md#4-dca-profile-browser-origin-profile), the
[browser-origin profile](../docs/spec-profile--browser-origin.md) and the
[signed-origin form](../docs/spec--http-binding.md#32-canonical-signed-origin):

- [ ] **Publisher:** sign the canonical delivery origin.
- [ ] **Issuer and trusted HTTP boundary:** compare the signed origin with the
  authenticated observation before protected work; apply the specified
  refusal and CORS behavior. Check any configured proxy's observation rule.
- [ ] **Browser client:** use the selected browser-origin request and response
  behavior. Record what the browser and endpoint actually observed.

### `dca-profile-period-keys`: requires baseline

[Profile §5](../docs/spec--profiles.md#5-dca-profile-period-keys-profile),
[period keys](../docs/spec-profile--period-keys.md) and
[content protection](../docs/spec--content-protection.md):

- [ ] **Publisher:** produce period keys and item wraps at the specified
  width, and provide a complete issuer-mediated path for an item that relies
  on those wraps.
- [ ] **Issuer:** admit presented period material and return only the period
  keys it can source and currently authorizes.
- [ ] **Client:** relay required coordinates, associate and admit returned
  keys, partition retained capabilities, and attempt authenticated content-key
  unwrap within finite bounds.

### `dca-profile-chain-keys`: requires `dca-profile-period-keys`

[Profile §5.1](../docs/spec--profiles.md#51-dca-profile-chain-keys-profile)
and [chain keys](../docs/spec-profile--chain-keys.md):

- [ ] **Publisher:** use the canonical construction for any generation that
  selects it; record period-key, chain-key or combined supply for each relevant issuer.
- [ ] **Request path and issuer:** when an operation relies on chain-key supply,
  relay it unchanged and admit/process it under the resolved family and
  geometry. Populate `requestedPeriodKeys` from desired unresolved item-wrap
  coordinates under [chain keys Section 12.4](../docs/spec-profile--chain-keys.md#124-requested-article-periods),
  rather than the render timestamp. Bound raw selector counts before
  deduplication, validate every label and enforce whole-request refusal for
  malformed or excess selector input. Unsigned hints authorize no capability.
- [ ] **Issuer selection:** under
  [chain keys Section 13.1](../docs/spec-profile--chain-keys.md#131-article-selection-and-optional-future-grants),
  independently authorize reusable reach and select sourceable article targets
  separately from optional `futurePeriodCount`. Check old article selection
  without current-time supply, zero future count without family denial, future
  gaps without loss of selected article targets, and article priority within
  projected output bounds. Open only an admitted source authorized to produce
  useful capability, under its original supplied coordinate and BIND.
- [ ] **Issuer and client result:** record whether the issuer projected period
  keys or returned a positioned chain key. Check the corresponding client
  admission; claim chain derivation only if that path was implemented and
  exercised. Check policy and valid supply for every position in a returned
  chain prefix; narrow or withhold overbroad capability. Project period keys
  only when the selected response agreement permits that form. Check projected
  period-key admission against the associated request's source geometry,
  windows and supplied positions even for a relay-only client. Check `denied`
  versus `unavailable`, absence of a family report beside a returned period
  capability, and source-opening errors at the supplied coordinate.

### `dca-profile-content-compression`: requires baseline

[Profile §6](../docs/spec--profiles.md#6-dca-profile-content-compression-profile)
and the [`gzip` transform](../docs/spec--content-protection.md#82-gzip-transform):

- [ ] **Publisher:** produce the single-layer sequence `["gzip"]` as exactly
  one gzip member, and select it per item only for intended clients that
  support it.
- [ ] **Client:** decode the single-layer sequence `["gzip"]` under the strict
  one-member contract, including header, trailer and exact-consumption
  refusal, within finite resource limits.

An issuer has no content-compression duty.

### `dca-profile-client-bound-ecdh-p256`: requires baseline

[Profile §7](../docs/spec--profiles.md#7-client-bound-custody-profiles)
and [response binding](../docs/spec--response-binding.md):

- [ ] **Client:** offer the ECDH method, retain its private key, and admit and
  open a response bound to that offer and request.
- [ ] **Issuer:** select the offered method only where configured and wrap
  every delivered key of a selected kind in the required response form.

### `dca-profile-client-bound-rsa-oaep`: requires baseline

[Profile §7](../docs/spec--profiles.md#7-client-bound-custody-profiles)
and [response binding](../docs/spec--response-binding.md):

- [ ] **Client:** offer the RSA-OAEP method, retain its private key, and admit
  and open a response bound to that offer and request.
- [ ] **Issuer:** select the offered method only where configured and wrap
  every delivered key of a selected kind in the required response form.

Support for either client-bound method does not imply support for the other.

### `dca-profile-recipient-grant-unlock`: requires baseline

[Profile §8](../docs/spec--profiles.md#8-dca-profile-recipient-grant-unlock-profile)
and [recipient-grant unlock Sections 2 to 6](../docs/spec-profile--recipient-grant-unlock.md#2-grant-and-endpoint-agreement):

- [ ] **Client/recipient host:** present the grant only to its chosen issuer
  and resource; admit only the authorized content-key result and refuse
  broader capability or later-render reuse without a fresh issuer decision.
- [ ] **Issuer:** admit grant, request and signed resource scope before policy
  and opening work; return only currently authorized item content keys.
- [ ] **Browser use, if selected:** also satisfy the browser-origin profile's
  applicable client and issuer duties.

### `dca-profile-html-carrier`: requires baseline

[Profile §9](../docs/spec--profiles.md#9-dca-profile-html-carrier-profile), the
[HTML carrier profile](../docs/spec-profile--html-carrier.md) and
[markup delivery](../docs/spec--data-format.md#3-markup-delivery):

- [ ] **Publisher:** emit the reserved `dca-data` element, and the reserved
  `dca-sealed-content` element when the delivery carries ciphertext, as inert
  JSON `script` elements whose values cannot end or alter the element.
- [ ] **Client:** inspect every element in the parsed document's `body` subtree
  with scripting enabled for parsing, carrying a reserved class token,
  enforce element type and cardinality, and fail the whole delivery on a
  duplicate or malformed reserved carrier. Every later step is the baseline's.

The passive [script-text writer case](fixtures/v1/profiles/dca-profile-html-carrier/script-text/README.md)
contains `</script>`, `</SCRIPT` and `<!--<script>`. The selected
[HTML-writer contract](../js/test-contract/html-writer/README.md) checks semantic
carrier preservation and a following page sentinel through a supplied writer.

An issuer has no HTML carrier duty. Browser-origin admission is a separate
profile and is neither selected nor required by this one.

## Finish the claim

- [ ] Check interactions among every selected profile, not only each profile
  in isolation. State the actual publisher supply, issuer response form,
  client admission, transport method and fallback behavior where relevant.
- [ ] List gaps, unavailable evidence and deployment assumptions explicitly.
  Report support, deployment enablement and selected-operation results
  separately. A role's implementation support can be checked without a live
  peer; a deployed interoperable path requires compatible peers.

The [verification overview](README.md) explains which evidence belongs in
vectors, primitive conformance, implementation tests and deployment checks.
The current [JavaScript claim index](claim-index/README.md) is an incomplete
pilot for that implementation, not a completed DCA v1 conformance result.

For a **new profile**, first define its identifier, baseline and dependency
closure, affected roles, selection and acceptance behavior, representations,
refusals and interactions in the applicable specifications. Then add its
role-specific requirements here and to the checked catalogue. The candidate
HTML content-map in [profile §10](../docs/spec--profiles.md#10-candidate-html-content-map-profile)
is not a current DCA v1 conformance profile.

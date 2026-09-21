# Integrating issuer-side metering

Status: Informative Draft

This guide shows where an issuer integrating the JavaScript reference makes
and records a metered access decision. Metering is issuer application
behavior, not a DCA wire profile: DCA supplies authenticated resource facts,
presented key coordinates, and a seam where the issuer's policy decides what
to grant.

The worked request below uses the
[`dca-v1-exact-period`](spec--profiles.md#5-dca-v1-exact-period-profile)
profile because exact period keys are the draft's compatibility anchor and
make the visibility trade-off concrete. The policy and key-result accounting
seams are not exact-period mechanisms.

The central limit is simple: an issuer can observe an unlock and prepare a
key-bearing response for return. It cannot prove that the client received or
used that response, and it cannot observe a later opening performed with a key
the client already holds. The
[capability lifecycle](spec--period-keys.md#11-capability-lifecycle) and
[pre-delivery and revocation rules](spec--period-keys.md#121-pre-delivery-and-revocation)
own that limit. Use direct content-key grants when every unresolved render must
reach the issuer. Use exact period-key grants when fewer issuer calls and
bounded reuse are the intended trade-off.

A later period-chain integration example can add its different request and
response representation here. It does not need another metering callback:
once the issuer delivers a reusable period capability, later client-local
opens within that capability's reach remain invisible to the issuer.

## What arrives from the client

An unlock request has this shape. The sealed values are publisher-produced
ciphertexts relayed by the client; their presence grants nothing.

```json
{
  "version": "1",
  "issuerName": "meter.example",
  "resourceJWT": "<publisher-signed resource>",
  "keyId": "2026-09",
  "sealed": {
    "contentKeys": {
      "bodytext": "<content key sealed for this issuer>"
    },
    "periodKeys": {
      "subscriber": {
        "260921T1000": "<exact period key sealed for this issuer>"
      }
    }
  }
}
```

The client may omit routes it does not need or support. It may also present
more publisher-authored alternatives than the issuer will use. The issuer
therefore never treats the request as entitlement or as trusted profile
selection.

After structural admission and publisher-signature verification, the
reference reduces the request to the coordinates the policy may decide on:

```js
requested = {
  contentNames: ["bodytext"],
  accessGroups: ["subscriber"]
};
```

The policy does not receive the unsigned request object. Its other inputs are:

- `claims.resource`: the verified `resourceJWT` payload, including
  publisher-signed `origin`, `resourceId`, `renderId`, `issuedAt`, and `data`;
- `input.principal`: the identity and entitlements authenticated by the
  issuer host;
- `input.context`: an issuer-owned snapshot such as prior metered renders,
  account state, or the captured request time; and
- `input.publisher.origin`: the verified signed publisher origin filled by
  the engine, rather than a value supplied by the client.

Publisher-signed `data` is authenticated publisher context. It is not the
reader's identity and does not grant access by itself; issuer configuration
decides which of its fields have policy meaning.

The [core request specification](spec--core-protocol.md#5-core-unlock-request)
defines the wire object. The policy contract is visible in
[`IssuerEngine.js`](../js/v1/core-issuer/IssuerEngine.js), and the reference
request construction is exercised in
[`dca-request-builder.test.js`](../js/v1/test/dca-request-builder.test.js).

## Inject the access-policy callback

Supply an object with `decide(claims, requested, input)` when constructing the
issuer engine. The callback returns only coordinates the issuer intends to
grant, plus optional opaque host work to commit after the key result is
prepared:

```js
const accessPolicy = {
  async decide(claims, requested, input) {
    const { renderId, resourceId, data } = claims.resource;
    const { principal, context, publisher } = input;

    if (typeof principal?.user !== "string") {
      return { contentNames: [], periodGrants: [], policyData: [] };
    }

    const mayRead = await decideFromIssuerState({
      principal,
      context,
      publisherOrigin: publisher.origin,
      resourceId,
      publisherData: data
    });

    if (!mayRead || !requested.contentNames.includes("bodytext")) {
      return { contentNames: [], periodGrants: [], policyData: [] };
    }

    return {
      contentNames: ["bodytext"],
      periodGrants: [],
      policyData: [{ type: "view", user: principal.user, renderId }]
    };
  }
};

const engine = new IssuerEngine({ accessPolicy });
```

`contentNames` grants direct content keys. `periodGrants` grants a bounded
prefix of the exact period labels the request presented for an access group.
For example, `{ accessGroup: "subscriber", periodCount: 1 }` grants at most
the first presented exact coordinate in canonical order.
The engine clamps both answers to presented coordinates, but that clamp is not
authorization: the callback must still decide from verified claims and
issuer-owned state.

When the decision depends on an entitlement, meter or policy-state source that
times out, is unavailable, refuses to answer or returns unusable input, the
issuer has no policy decision. It fails closed and returns no key material; it
does not substitute a default grant. The normative rule is in
[authentication and policy](spec--core-protocol.md#62-authentication-and-policy).

The example returns no `periodGrants` deliberately. Granting the
`subscriber` family would let the client open later matching articles from its
cache, so those views would never call this meter. To meter reusable access
instead of individual renders, the corresponding decision is:

```js
return {
  contentNames: [],
  periodGrants: [{ accessGroup: "subscriber", periodCount: 1 }],
  policyData: [{ type: "capability-grant", user: principal.user, renderId }]
};
```

That `policyData` shape is illustrative; the host defines and validates its
own pending records. The demo `IssuerBusinessData` accepts only its `view`
record, so a `capability-grant` record needs a deployment-owned applier. The
event being counted is the reusable grant, not each later article it can open.

The demonstration policy in
[`AccessPolicy.js`](../js/v1/demo/support/AccessPolicy.js) shows a complete
callback with public, entitlement, and metered rules. It is example policy,
not a deployment API or a required business model.

## Commit only for a deliverable key result

Do not debit a meter merely because `decide` returned a grant. Envelope
opening, response representation, or final transport preparation can still
fail. Returning `policyData` lets the policy describe a pending host action
without mutating durable state inside the decision.

The issuer integration should:

1. authenticate the caller and take one issuer-owned policy snapshot;
2. call the engine with that `principal` and `context`;
3. prepare the selected
   [response representation](spec--response-binding.md#4-selection-and-agreement)
   and the binding's [HTTP response](spec--browser-http-binding.md#34-response);
4. determine whether the prepared response contains at least one key member;
   and
5. atomically apply the returned `policyData` only when that key-bearing
   response is ready to return.

This commit point means "the issuer issued a key-bearing response," not "the
reader received, opened, or viewed the content." A network failure after the
commit remains possible. A product that charges money needs its own retry,
reservation, settlement, and reconciliation rules around that boundary.

The demo [`IssuerServer`](../js/v1/demo/actors/IssuerServer.js) performs this
ordering, while
[`IssuerBusinessData`](../js/v1/demo/actors/issuer/IssuerBusinessData.js)
validates and applies its pending view records. A production integration must
replace the in-memory store with its own atomic, idempotent operation. A
stable event identity such as publisher plus reader plus signed `renderId`
prevents a retry from consuming the same render twice.

The JavaScript reference does not yet publish a supported issuer integration
entry or copy manifest. Treat the demo assembly as executable wiring to study,
then compose the issuer core, adapters, authentication, policy, storage, and
transport inside the deployment's own application boundary.

## Choose what the meter means

- **Per unresolved render:** grant only direct `contentNames`. A later render
  without a retained usable key reaches the issuer again.
- **Per reusable capability grant:** grant `periodGrants` and count the grant.
  Later matching opens are intentionally invisible to the issuer.
- **Per request:** usually the wrong event. Refusals, retries, cache hits, and
  responses that deliver no key make request count differ from access.
- **Per plaintext view:** unavailable to an issuer once the client holds a
  usable key. DCA does not provide remote observation of client rendering.

An issuer response cache can also bypass a fresh policy decision. Do not place
a metered route behind such a cache unless its cache key, replay semantics,
and accounting operation deliberately implement the same meter. Multiple or
fallback issuers similarly need shared accounting state, or an explicit rule
that each issuer maintains a separate meter.

## Run and inspect the reference evidence

Run from `js/v1/`:

```sh
node --test test/access-policy.test.js
node --test test/scenario.test.js
```

[`access-policy.test.js`](../js/v1/test/access-policy.test.js) demonstrates
two metered direct reads followed by denial, retry-safe counting by signed
`renderId`, no debit when no key is delivered, and the key limitation: a
second article opened from a retained period key never reaches the issuer.
`scenario.test.js` makes that retained-key behavior visible as two opened
articles and one issuer call.

These tests exercise the reference integration. They do not make its example
metering policy part of the DCA protocol.

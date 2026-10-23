# DCA reference implementation status

Status: Informative Draft

This guide records bounded observations about the JavaScript reference in
the same repository revision as this guide. It defines no
protocol requirement or conformance claim. The requirements remain in
[content protection](spec--content-protection.md),
[data format](spec--data-format.md), the
[period-key](spec-profile--period-keys.md) and [chain-key](spec-profile--chain-keys.md)
specifications and the selected [profiles](spec--profiles.md).

## Content representation limits

The reference enforces finite representation limits.
[`contentEncodings.js`](../js/core-client/contentEncodings.js) defines
`DEFAULT_CONTENT_ENCODING_LIMITS` (layer count, name length, per-layer and total
input and output bytes), and
[`ContentRepresentationOpener.js`](../js/core-client/ContentRepresentationOpener.js)
applies them. Normal client composition decodes `gzip` with the strict
single-member decoder in
[`gzipCodec.js`](../js/extensions/content-compression/core-shared--client-publisher/gzipCodec.js),
over the inflater in
[`inflate.js`](../js/extensions/content-compression/core-shared--client-publisher/inflate/inflate.js).
Tests pin both: `js/test-reference/core-client/wire-lookup-client.test.js`
covers the layer, name, per-layer and total output limits, and
`js/extensions/content-compression/test/gzip-codec.test.js` rejects
concatenated, padded, damaged and truncated members and bounds input and
output. The limits are byte caps; nothing here bounds decoding time.

## Period-key nonce accounting

The JS publisher
([`Sealer.js`](../js/core-publisher/Sealer.js)) derives each period-key wrap
nonce from the render ID and the wrap's coordinate and keeps no invocation
count. Deployment-wide compliance with the invocation bound requires a
budget mechanism around this component; the component does not enforce that
quota itself.

## Chain-key extension

Publisher family and window supply is configured in
`js/extensions/chain-keys/core-publisher/periodFamilySupply.js`, and
per-issuer period-key and chain-key delivery in
`js/core-publisher/issuerSupplyPlan.js`. Composing
`js/extensions/chain-keys/core-issuer/chainKeyIssuerEngine.js` enables
issuer input. Once the engine is configured for chain input, an authored
carrier determines which families are presented; the engine still applies
trusted configuration, admission and issuer policy. Its `representation` option
selects period-key or chain-key output.
Request relay is the injected
`js/extensions/chain-keys/core-client/ChainKeyRequestBuilder.js`. Client
chain consumption requires `chainCache` and an admitted `chainKeyProfile`;
retaining raw key bytes from a response in direct transport mode also depends
on `acceptDirectFallback` and `persistRawPeriodKeys`. Chain output is
available in direct and client-bound issuer responses when the corresponding
client capability is composed. No reference path selects the response form
from the request. One processor holds one engine with a fixed representation,
so mixed client populations use separately composed endpoints.

These observations concern the reference source in this tree and the named
source paths. Recheck them when updating the reference before treating any gap
as current or any fix as complete.

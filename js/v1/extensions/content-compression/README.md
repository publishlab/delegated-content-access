# Content compression

Status: experimental extension; implementation evidence, no protocol authority

The modules here supply gzip for the base layered-content seam. Issuers and
key delivery are unchanged.

## Publisher use

For dynamic content, wrap base with `CompressingSealer`:

```js
const sealer = new CompressingSealer(config);
sealer.resource('123456', resourceData);
sealer.content('bodytext', html, 'text/html', { accessGroups: ['premium'] });
const render = await sealer.seal();
```

The adapter snapshots the raw input, gzip-encodes each selected item at
`seal()`, appends `gzip` to its ordered `contentEncodings`, and delegates the
complete render to base `Sealer`. With `{ contentEncoding: 'identity' }` the
adapter adds no gzip layer.

A representation descriptor carries bytes that already hold their layers. The
adapter delegates such an item to base unchanged, appends no gzip layer to it,
and refuses a fourth argument the way base does. The adapter reads
`accessGroups` only from the options alongside a descriptor, and refuses a
`contentEncoding` option there with `unsupported_option`, because the
descriptor states its own layers.

The adapter copies none of base's sealing engine. It does copy base's entry-time
validation for `content()`, because base sees a buffered call only at `seal()`;
`test/entry-validation-parity.test.js` drives both sealers through the same
refusing calls and holds them to one code.

For build-time preparation, compress once and call base directly:

```js
import { Sealer } from '../../core-publisher/Sealer.js';

const sealer = new Sealer(config);
sealer.resource('123456', resourceData);
sealer.content('bodytext', {
    bytes: alreadyGzipped,
    contentType: 'text/html',
    contentEncodings: ['gzip'],
}, { accessGroups: ['premium'] });
```

Base snapshots and seals descriptor bytes without encoding or inspecting them.
Build-time precompression saves repeated runtime CPU and prepares a
deterministic artifact, but its bytes and ordered metadata must be deployed
together. Runtime compression is simpler for dynamic content and spends CPU on
every render, inside the async `seal()` call.

The current `contentType` member remains required and unchanged. It does not
select or drive a decoder.

## Client use

Inject this extension's registry through the supported browser-client entry:

```js
import { createBrowserClient } from '../../integration-client/createBrowserClient.js';
import { decoders } from './core-shared--client-publisher/gzipCodec.js';

const client = createBrowserClient({
    root: document,
    issuerName,
    transport,
    contentDecoders: decoders,
});
```

The host supplies `issuerName` and a `transport` with the contract documented by
`createBrowserClient()`. Code that composes the lower-level client directly
passes the same `contentDecoders` option to `composeClient()`.

Base validates the list, decrypts, then decodes its layers in reverse order.
Actors know only the generic registry. When an item declares an encoding the
client's registry does not hold, base reports `unsupported_encoding` for that
item. When a decoder fails, including on bytes that do not match their
declaration, base reports `bad_encoding`, and base returns no partial bytes.

Publisher and client must therefore use matching registry names. The ordered
`contentEncodings` list is visible on the wire and describes the
representation, and no key or access decision reads it.

## Composition

| Role | Module | Behavior |
| --- | --- | --- |
| gzip | `core-shared--client-publisher/gzipCodec.js` | Web Streams encode/decode plus injected decoder registry |
| publisher | `core-publisher/CompressingSealer.js` | Buffer, gzip, delegate descriptors to base |
| portable inflater | `core-client/inflate/inflate.js` | Optional decoder when `DecompressionStream` is unavailable |
| client convenience | `core-client/openEncodedContent.js` | Installs gzip in base's generic opener |

Each item gets its own compression context. A host without Web Streams injects
another `{ encode(bytes), decode(bytes) }` implementation.

Run from `js/v1/`:

```sh
npm run test:reference:extension:content-compression
```

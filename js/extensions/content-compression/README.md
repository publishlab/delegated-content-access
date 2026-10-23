# Content compression

Status: prototype reference for the optional profile `dca-profile-content-compression`;
implementation evidence, no protocol authority

The modules here implement gzip for the baseline layered-content seam. The
[`dca-profile-content-compression` profile](../../../docs/spec--profiles.md#6-dca-profile-content-compression-profile)
and [content protection Section 8.2](../../../docs/spec--content-protection.md#82-gzip-transform)
hold the contract; the modules gain no authority from them. The normal client
registry uses the strict single-member inflater and refuses extra members,
padding, malformed trailers and truncated input. Issuers and key delivery are
unchanged.

## Publisher use

For dynamic content, wrap base with `CompressingSealer`:

```js
const sealer = new CompressingSealer(config);
sealer.resource('123456', resourceData);
sealer.content('bodytext', html, 'text/html', { accessGroups: ['premium'] });
const render = await sealer.seal();
```

The adapter snapshots the raw input, gzip-encodes each selected item at
`seal()`, verifies that the result is exactly one member containing the input,
appends `gzip` to its ordered `contentEncodings`, and delegates the complete
render to base `Sealer`. With `{ contentEncoding: 'identity' }` the
adapter adds no gzip layer.

The second constructor argument selects the publisher's supported complete
encoding sequences: `{ supportedEncodingSequences: [[], ['gzip']] }` is the
default. Each item's ordered list must match one configured sequence in full,
including repeated layers. The adapter checks prepared descriptors and the
prospective output of raw calls at `content()`, before codec work. Unsupported
sequences fail with `unsupported_encoding`; they never fall back to identity.
For a baseline publication, select `[[]]` and pass `contentEncoding: 'identity'`
for raw calls; leaving the raw-call default at gzip then refuses the item.
Configuration is copied at construction.

A deployment may explicitly list wider prepared sequences. That admits their
descriptors unchanged; it supplies no additional codec and validates neither
those prepared payloads nor client support. Publisher and intended clients
must separately implement the complete selected sequence.

A representation descriptor carries bytes that already hold their layers. The
adapter delegates such an item to base unchanged, appends no gzip layer to it,
and refuses a fourth argument the way base does. Beside a descriptor the adapter
reads `accessGroups` and the declared contributed item options, and refuses a
`contentEncoding` option there with `unsupported_option`, because the
descriptor states its own layers.

A selected publisher contribution declares its per-item options, and composition lists them in
`config.itemOptionMembers`.

- The adapter passes every declared option to base on the gzip, identity and descriptor paths.
- It copies each declared option as plain JSON at `content()`, under base's rule: a non-JSON value refuses
  `bad_config` at that call, and a later change to the caller's object reaches no render.
- It refuses any other option with `unsupported_option`. Base passes over an undeclared option; the adapter
  refuses it, because a misspelled option would otherwise seal the item without the route it named and fail no
  call.

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
By default, base admits at most eight layers with names of at most 128 UTF-16
code units. It caps each decoder input at 16 MiB, each result at 64 MiB, and
the sums of decoder inputs and results at 128 MiB each. The strict gzip decoder independently
caps its input at 16 MiB and enforces the caller's output allowance while growing
its output. A direct `decode(bytes)` call defaults to 64 MiB of output. Lower-level callers may set
`new ContentRepresentationOpener(registry, { limits: { maxLayers, maxInputBytes, maxOutputBytes, maxTotalInputBytes, maxTotalOutputBytes, maxNameLength } })`
for their deployment. Clients with lower configured caps may refuse an item
another client opens; publishers must choose item sizes and layers for their
intended clients.
Actors know only the generic registry. When an item declares an encoding the
client's registry does not hold, base reports `unsupported_encoding` for that
item. When a decoder fails, including on bytes that do not match their
declaration, base reports `bad_encoding`, and base returns no partial bytes.

Publisher and client must therefore use matching registry names. The ordered
`contentEncodings` list is visible on the wire and describes the
representation. The content tag does not bind the list. An admitted change
can alter decoding or fail during transformation; deleting it can return
compressed representation bytes as base bytes. Admission, capture and
authenticate-before-decode order remain required. No key or access decision
reads the list.

## Composition

| Role | Module | Behavior |
| --- | --- | --- |
| gzip | `core-shared--client-publisher/gzipCodec.js` | Web Streams encode, strict default decode and injected decoder registry |
| publisher | `core-publisher/CompressingSealer.js` | Buffer, gzip, delegate descriptors to base |
| strict inflater | `core-shared--client-publisher/inflate/inflate.js` | Single-member decoder with framing and output limits |
| client convenience | `core-client/openEncodedContent.js` | Installs gzip in base's generic opener |

Each item gets its own compression context. A host without Web Streams injects
another `{ encode(bytes), decode(bytes, { maxOutputBytes }) }` implementation.
Base passes the lesser of its per-layer limit and the remaining total output
allowance to each decoder. Zero permits only empty output; strict gzip still
validates the complete member and its trailer. The decoder must enforce this
allowance during expansion. Base also checks the returned bytes, including when
an injected decoder ignores its allowance. Injected code remains trusted: this
contract does not interrupt it or bound all of its allocations or execution time.
Parser tables, input buffers and copies are additional memory.
The separate `decodeWebStreams` and `webStreamsGzip.decode` use the native
`DecompressionStream`; native runtimes may accept concatenated gzip members.
They are opt-in helpers for callers that do not claim the DCA compression
profile and are not suitable for the registry above.

Run from `js/`:

```sh
npm run test:reference:extension:content-compression
```

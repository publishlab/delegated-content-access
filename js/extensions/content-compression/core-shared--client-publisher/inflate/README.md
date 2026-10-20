# inflate

`inflate.js` decodes gzip and does not compress. It is written from the
specifications below. It reads exactly one gzip member, verifies its trailer,
and produces the bytes under it.

The normal `gzipCodec.js` decoder registry uses it, including in a runtime
without `DecompressionStream`. Its defaults cap compressed input at 16 MiB and
decoded output at 64 MiB. `gunzip(bytes, { maxInputBytes, maxOutputBytes })`
accepts deployment-selected positive safe-integer limits.

Lower-level callers may also inject it directly:

```js
import { inflateGzip } from './core-shared--client-publisher/inflate/inflate.js';

const gzip = { encode, decode: inflateGzip.decode };
openEncodedContent({ item: dcaData.contentItemFor(contentName), ciphertext, resolveKey, gzip });
```

- DEFLATE, https://www.rfc-editor.org/rfc/rfc1951
- gzip, https://www.rfc-editor.org/rfc/rfc1952

Every part of `inflate.js` names the section it implements. The file carries
the two code tables of RFC 1951 section 3.2.5 alongside the code that
transcribes them.

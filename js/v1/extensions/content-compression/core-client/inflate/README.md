# inflate

`inflate.js` decodes gzip and does not compress. It is written from the
specifications below, for a runtime with no `DecompressionStream`. It reads one
gzip member and produces the bytes under it.

Opt-in. Nothing in this extension imports it, and a client that says nothing
gets the Web Streams gzip in `core-shared--client-publisher/gzipCodec.js`.

Select it by injection:

```js
import { inflateGzip } from './core-client/inflate/inflate.js';

const gzip = { encode, decode: inflateGzip.decode };
openEncodedContent({ record, contentName, ciphertext, resolveKey, gzip });
```

Remove it by deleting this directory and the `test/inflate--*` files.

- DEFLATE, https://www.rfc-editor.org/rfc/rfc1951
- gzip, https://www.rfc-editor.org/rfc/rfc1952

Every part of `inflate.js` names the section it implements. The file carries
the two code tables of RFC 1951 section 3.2.5 alongside the code that
transcribes them.
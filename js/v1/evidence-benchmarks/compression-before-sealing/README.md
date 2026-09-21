# Compression before sealing

Transport gzip or Brotli applied after encryption cannot compress the
ciphertext; compressing the content bytes before sealing does shrink the wire.
The runs below measure both paths in bytes on the wire.

Measured 2026-09-10, synthetic html, bytes on the wire:

```text
30 KB of html
Base (not pre-compressed before encryption):
    30 842 when html is gziped (40 906 if not)
Gzip extension:
     7 583 when html is gziped (10 030 if not)

3 KB of html, nearer a typical article body
Base:
     2 976 when html is gziped (3 904 if not)
Gzip extension:
     1 146 when html is gziped (1 467 if not)
```

Transport gzip takes back the third that base64url added and no more,
because the ciphertext under it does not compress.

The run generates its input in memory with
[`synthetic-html.js`](../../tools/synthetic-html.js), in three forms: html,
readable text and structured json, each at 3, 10 and 30 KB. The run
needs no network, writes no files, and produces the same table on a rerun apart
from its two median columns. Run it from the repository root:

```sh
node js/v1/evidence-benchmarks/compression-before-sealing/run-synthetic.js
node js/v1/evidence-benchmarks/compression-before-sealing/run-downloads.js
```

The second downloads the pages listed below, or whichever URLs and local paths it
is given, to the OS temp directory and measures their html and text the same way.
It prints measurements with which to compare the synthetic gzip ratio against
article HTML, and it writes nothing into the repository.

These are the pages it was last checked against, fetched 2026-09-10 at the
revision in each URL. Bytes of the html body, its gzip and Brotli ratios, then
wire bytes for the two profiles when the html is gzipped, with the ungzipped
figure in parentheses:

| page | bytes | gzip | brotli | base | gzip extension |
| --- | --- | --- | --- | --- | --- |
| [Sursild](https://no.wikipedia.org/api/rest_v1/page/html/Sursild/25833098) | 2 747 | 0.412 | 0.354 | 2 811 (3 684) | 1 195 (1 530) |
| [Rommegrot](https://no.wikipedia.org/api/rest_v1/page/html/R%C3%B8mmegr%C3%B8t/23941856) | 11 008 | 0.327 | 0.288 | 11 093 (14 699) | 3 666 (4 822) |
| [Sodd](https://en.wikipedia.org/api/rest_v1/page/html/Sodd/1327060023) | 14 787 | 0.251 | 0.204 | 14 904 (19 738) | 3 779 (4 972) |
| [Sitron](https://no.wikipedia.org/api/rest_v1/page/html/Sitron/25828561) | 30 053 | 0.220 | 0.190 | 30 230 (40 092) | 6 695 (8 850) |

Sodd is English; the other three are Norwegian.

Retune by running the downloads, running the synthetic samples, moving the
constants in [`synthetic-html.js`](../../tools/synthetic-html.js), and
repeating until the ratios sit within a tenth.

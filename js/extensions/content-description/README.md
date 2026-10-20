# Optional content descriptions

Candidate implementation of `docs/spec-proposal--content-description-and-placement.md`.
This does not adopt a new baseline requirement. Ordinary HTML and other items may
omit descriptions. An explanation alone is useful: `{version: "1", description:
"Daily temperatures in Celsius."}` needs neither a schema nor a placement map.

The portable helpers are independent of HTML, network and platform globals:

- `core-shared--client-publisher/contentDescription.js` exports
  `admitContentDescription(item, options = {})`, returning `{state, description}`.
  States are `absent`, `available`, `unsupported` and `invalid`; only `available`
  includes the copied description, otherwise `description` is `null`.
- `core-publisher/withContentDescriptions.js` exports
  `withContentDescriptions(dcaData, descriptionsByName, options = {})`. Call it on
  a published delivery before choosing a carrier writer. It checks the whole
  supplied description map and all retained descriptions, refuses unknown item
  names or malformed metadata, and returns a new delivery with copied item records
  and descriptions. Other nested values are shared; neither input is mutated.
- `core-client/contentDescriptionHandoff.js` exports
  `contentDescriptionHandoff(item, description, openedBytes)`. Before its first
  await for the item, the caller captures `item = dcaData.contentItemFor(name)`
  and `description = admitContentDescription(dcaData.contentDataFor(name))`;
  after opening and inverse transforms it passes both with the bytes. The result
  has `{contentName, contentType, bytes, description}`, all from those captured
  values: a page that sets the live record's `contentType` to `text/html` during
  the await still hands off `application/json`. The function reads no record.
  The separate metadata result makes malformed descriptions observable.

The client module also exports `selectContentDescriptionHandler(handoff,
{requiresSchema, supportedSchemas})`, an optional application policy check.
It returns `{state: "ready" | "refused", schema: string | null}`. A required schema
must be available and match a configured identifier exactly. A handler explicitly
configured with `requiresSchema: false` may proceed using the media type even
when description admission failed. Refusal affects only that item.

`ready` permits handoff; it makes no payload-validation claim. Trusted application
handlers perform text decoding, JSON/NDJSON framing, schema validation and rendering.
No identifier triggers retrieval, code loading or execution. Schema identifiers are
nonempty Unicode scalar strings naming an immutable contract; stable namespaced
spellings such as URNs or HTTPS identifiers are recommended. This helper does not
parse URI syntax. Compare exact strings without trimming, Unicode normalization,
percent decoding, case folding or relative resolution. This helper
contains no JSON Schema engine or registry framework.

The content owner chooses the browser handler through the existing integration
setup. It may be its own function or a library supplied by its CMS or issuer. A
callback can update application state for React, Angular or another renderer;
it need not insert HTML itself. Description admission supplies metadata to that
callback without choosing or invoking code. The separate HTML map extension is
for explicitly selected independent reconstruction. Do not run it alongside a
handler that owns the same destinations, or use it as an automatic fallback
after that handler refuses.

Public descriptions grant no access and are outside the content AAD, which binds
only the render ID and item name. Type and encodings are also outside it. Successful
opening does not establish their provenance. The host applies its trusted-source
policy before relying on them. Sensitive metadata belongs inside protected data.

## Limits

`DEFAULT_DESCRIPTION_LIMITS` discloses defaults. Each may be overridden with a
positive safe integer in the options record; unknown options are refused:

| Option                     | Default | Unit                                |
| -------------------------- | ------: | ----------------------------------- |
| `maxDescriptionCodePoints` |    4096 | Unicode code points                 |
| `maxSchemaCodePoints`      |    2048 | Unicode code points                 |
| `maxSerializedBytes`       |   32768 | UTF-8 octets of compact JSON        |
| `maxNodes`                 |     128 | Visited JSON values, including root |
| `maxDepth`                 |       8 | Value depth, root = 1               |

This native-object adapter bounds traversal before copying. It accepts JSON data
records, rejects accessors, cycles, nonfinite numbers and unpaired surrogates, and
measures compact serialization without calling user serialization hooks. Carrier
readers own their serialized-input size limits and normal JSON duplicate-member
policy; this extension adds no JSON parser. An over-limit envelope is `invalid`
even for a future version. A bounded object with another string version is
`unsupported` before version-1 member grammar is considered.

Run focused evidence with:

```sh
node --test extensions/content-description/test/*.test.js
```

Tests cover plain descriptions, opaque schema identity and exact matching, finite bounds,
Unicode, malformed and future descriptions, untouched media types, the captured
contentType after a live-record edit, input copying,
trusted JSON and NDJSON handlers, ordinary HTML without metadata, and preservation
through the real JSON/markup readers and baseline `DcaData`. The markup-reader
case supplies its documented tree port; it does not claim browser reconstruction.

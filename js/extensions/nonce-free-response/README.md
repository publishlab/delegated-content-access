# Nonce-free response experiment

Status: provisional implementation-only experiment. No profile or method ID,
profile-system registration, negotiation, fallback or operative protocol change.
Adoption remains paused. Only an explicit caller of this experiment uses it.
It depends on `client-bound-transport` for peer admission and settled kind/AAD
semantics; it does not select that extension's current wire procedure.

## Candidate bytes and lifecycle

For each fresh response P-256 agreement, derive non-extractable HKDF material
from the full 32-byte shared x-coordinate, preserving leading zero bytes.
For an entry's section-fixed kind and semantic path from the response root:
base paths are `keys`, the collection name, and that collection's coordinate
fields (`contentName`; `accessGroup` and `period`; or `accessGroup` and
`cutoff`). Composed sections declare their prefix and coordinate `fields`.

```text
LP(b) = U32BE(length(b)) || b
Path(p) = U32BE(p.length) || LP(UTF8(p[0])) || ... || LP(UTF8(p[n-1]))
info = UTF8("dca-derivation-client-bound-entry-key") || 0x00 ||
       LP(UTF8(kind)) || Path(p)
Kentry = HKDF-SHA256(Z, empty salt, info, 32 bytes)  # full extract + expand
nonce = twelve zero bytes
AAD = UTF8("dca-bind-client-bound-key-kind") || 0x00 || UTF8(kind)
entry = { "key": BASE64URL(AES-256-GCM(Kentry, nonce, keyBytes, AAD)) }
```

Strings are nonempty Unicode scalar strings with exact spelling. Lone
surrogates are rejected; Unicode normalization is not applied. Lengths count
UTF-8 octets. Path includes the base/composed section prefix and the record's
semantic coordinate values, excluding the array index and the record's `key`
member. Kind/path come from trusted composition and the admitted section,
never from the ciphertext. Record permutation does not change them.
The unchanged compact entry loses 27 JSON bytes compared with carrying a
16-character nonce member. Runtime cost and compression are not measured.

`core-issuer/prepare.js` exports `preflight(clientPublicJwk, options)`. Its
`prepare(body)` takes arrays of named key records whose `key` values are
Uint8Array or canonical base64url. It replaces each record's `key` with `{key}`
and adds a public `transport.publicKey`, retaining coordinates and metadata.
An instance prepares once, including empty or failed calls. Concurrent/repeated calls fail before encryption. Failure requires a
fresh preflight; retransmit the saved ciphertext rather than reseal it.
The ordinary API generates the fresh ephemeral pair itself. The optional
`ephemeralKeyPair` injection is solely for deterministic tests: it must not be
reused across responses.

The implementation captures selected bytes, coordinates and kind AAD before
crypto awaits. `structuredClone` gives this small prototype ownership of the
output and prevents caller mutation during preparation. This convenience is
not a proposed protocol requirement to freeze an entire response or adopt a
batch framework. Cloning preserves shared array references, so the output writer
copies ancestors before replacing each entry. An issuer may reuse an array in
different sections without one location overwriting another's ciphertext.

**Unique-coordinate restriction:** this paused prototype refuses a repeated
kind and semantic path before any derivation or encryption, consuming that
preparation attempt. It does not support same-coordinate rival candidates,
even if their key bytes are equal. The local duplicate check prevents reuse
of an entry key and zero nonce; it is not an adopted protocol restriction.
The operative named-record format permits rivals. Stock response nonces stay
in place, and this prototype cannot replace stock response protection until
that difference is resolved. Array index locates the output record only; it
is not a cryptographic discriminator.

`core-shared--client-issuer/entry.js` exports
`open(transport, clientPrivateKey, composedKinds)`. Its opener takes
`open(value, usages, kind, originalFullPath)`. Content/ordinary period entries
unwrap directly to non-extractable AES handles; chain/composed derivation
kinds open to bytes. The opener never exports delivered AES keys. Retained
ciphertext reopening needs the entry, original kind/path, issuer public point
and original client private handle, without retaining the whole response,
sibling list, agreed transport secret or derived entry-key table.

## Seams exercised and missing

Reused without copying:

- `core-shared--client-issuer/responseKeys.js`: `recordPath` reads the named
  coordinate fields, and `settleComposedSections` validates composed prefixes
  and their `fields`, rejecting overlapping declarations. The prototype walks
  record arrays, keeping semantic paths separate from output array locations.
- `client-bound-transport/core-shared--client-issuer/ecdhP256.js`: `importPeer`
  provides canonical P-256 public point admission.
- The sibling's `keyKind.js` supplies settled kind descriptors and unchanged
  kind AAD. Base `aead.js`, codec, binary-string and own-property helpers are
  reused directly.

Repeated code is limited to ECDH `subtle.deriveKey(..., "HKDF", ...)` from the
sibling's `agreeTransport` function. That exported function immediately derives
one AES transport key, so it cannot expose the HKDF-material seam this candidate
needs. The experiment repeats that short sequence rather than changing base.
The controlled traversal translates existing coordinate records into full paths;
it copies neither the response mappers nor `KeyDelivery` nor the resolver.

Still missing for actual host integration: stock `KeyDelivery` mappers pass only
key/kind to a wrapping callback; stock resolver and extension `openKey` omit full
path; retained wrapped-period cache reopening does not pass it. These callers
need one consistent original-path argument before stock composition could use
this candidate. Current generic composed names also admit lone surrogates;
this experiment's framing enforces scalar admission locally. No stock source,
cache adapter, spec, profile catalogue, vector or conformance corpus changed.
The tests demonstrate candidate mechanics and usable delivered capability, not
a stock resolver or whole application integration claim.

A future SDK adapter must also preserve existing failure and reset semantics:
malformed/authentication failures map to the resolver's typed `unwrap_failed`
entry failure, while configuration/programming failures keep their identity.
Do not swallow `context_retired`: existing reader revision checks reject late
results after reset, and retaining cache owners clear their records. This
candidate's direct opener currently exposes generic/crypto exceptions; it is
not a drop-in stock resolver adapter.

Client-bound wrapping does not authenticate an issuer or authorize access.
Run it after the existing issuer verification/policy checks and inside the
authenticated, request-associated response channel required by
[response binding Section 2](../../../docs/spec--response-binding.md#2-layered-security-model).
Path binding adds no issuer signature and does not replace publisher BIND.

## Focused evidence

From `js/`:

```sh
node --test extensions/nonce-free-response/test/*.test.js
pnpm exec eslint extensions/nonce-free-response
pnpm exec prettier --check extensions/nonce-free-response
```

`test-lib/behavior.js` accepts a small implementation adapter for reusable
recovery, actual decryption/unwrap, custody, recipient rejection, tampering,
record order, partial collections and individual retained reopening assertions.
If the construction is adopted in core, provide the corresponding core adapter;
these assertions need no protocol-specific import change. It currently runs
only against this candidate. This is not evidence stock passes it today.

The focused tests cover aliased issuer-array output and rejection of duplicate
semantic coordinates before encryption. They do not establish support for
rival candidates or adoption into stock response protection.

Special candidate assertions remain in `test/response.test.js`: full-path and
cross-namespace binding, framing/Unicode, record traversal, explicit nonce
omission, duplicate-coordinate refusal, preparation lifecycle and input capture. Full-path binding is additional to
current response binding, so stock is not expected to pass those assertions.
The independent transcript uses Node `createECDH`, `hkdfSync`, `createCipheriv`
and literal info octets rather than the candidate's derivation/encryption
helpers. Test-only private scalars 1 and 2 are constructed in that test file;
they are public deterministic test material, not operational secrets.
Passing these tests establishes the exercised construction and implementation
behavior, not independent language interoperability, a complete cryptographic
proof, profile conformance or approval for adoption.

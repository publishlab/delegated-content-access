# Vectors

Recorded wire bytes for any implementation to replay. The JavaScript reference
owns its explicit vector-test tier under `../../js/test-vectors/`.

Whole-protocol renders and unlock requests are test fixtures rather than
primitive vector sets. They live under [`../fixtures/`](../fixtures/README.md),
where each package declares exact membership and assertion consumers. The
three protocol fixture packages that `js/tools/make-vectors.js` writes stay
separate from the dedicated period-key composition package and its recorder.

This subtree is passive recorded data. It imports and executes nothing; each
consumer selects its set explicitly. The independent
`../conformance-primitives/` corpus does not read these vectors.

`check-sums.sh` verifies each set still carries the bytes its `SHA256SUMS` was
written over. With no path argument it reads `sets.txt`, so it verifies exactly
the full manifest walk and treats an empty or disagreeing manifest as a failure.
Each set directory must carry a `set.json` naming the set and declaring phase
`devel` or `stable`. Each vector file's `vectorFormat` selects its replay path.

The script exits with one of the three codes below:

| | |
|---|---|
| 0 | every set in the walk carries the bytes its `SHA256SUMS` was written over, and under `--write` every one was recorded |
| 1 | a set was read and did not hold: bytes that disagree with the sums file, a hashed file that is gone, a vector on disk named in no sums file, a set with no `SHA256SUMS` at all, a set holding nothing to hash, or a `--write` that could not write |
| 2 | the run covered less than the walk it was asked for: no `sha256sum` and no `shasum`, a named set that is no directory, a `sets.txt` that disagrees with the directories beside it, or a set whose `set.json` is missing or has no supported readable phase |

A set without a supported readable phase declares no bytes, so there is nothing
to compare it against and 1 would report a mismatch that was never read. The
script exits 2 there for the same reason a recorded-source check does, and 2
wins over 1 when both apply.

## The run manifest

`sets.txt` names one set path per data line and owns the complete vector
walk. It includes direct child sets, baseline algorithm packages at exact
depth `v1/baseline/<item>/`, profile packages at
`v1/profiles/<profile>/`, and recorded alternatives at
`v1/experiments/<experiment>/`. The `v1/` directory is a container that
holds only those three group directories, and every set is flat.
`read-sets.sh` validates that walk and `check-sums.sh` hashes every listed
set. A set that fails ends the run red.

The shared readers implement both of these rules:

- A directory named in `sets.txt` that is missing is a failure, not a skip.
- A root set or nested package that no line names is a failure.
- A file or directory off that layout is a failure, and the reader names each
  one: `v1/extras/hidden/vector.json`, `v1/baseline/stray.json` and
  `v1/baseline/<item>/nested/` all sit where no walk reads them. Beside
  `sets.txt` it refuses only JSON files and `SHA256SUMS`.

The second rule catches a forgotten line. Without it, someone adds a
package, forgets the line, and the checksum walk silently passes the package
by and still reports green. Each listed package also refuses a JSON member
absent from its `SHA256SUMS`.

The public `../../js/check` runs no vector command. Run `check-sums.sh` for
recorded-byte integrity, or `sh check-replays.sh` for the explicit all-set
maintainer gate. The latter validates the full set manifest, checksums and
set-to-replayer map, then runs the JavaScript vector tests and the independent
Python chain-key replay. Each replayer checks exact member coverage for its
set. This aggregate is not a role-scoped conformance claim.
When changing the Python chain-key replayer's membership check, run
`python3 check-chain-key-primitives.test.py` from this directory. That
focused self-test remains a maintainer command; the public JavaScript test
gate does not depend on Python or claim to test this tool.

The [claim-index pilot](../claim-index/README.md) lists every package in this
walk. All eight pilots select the baseline ECDH carrier-open package. The
client-bound ECDH and RSA-OAEP pilots also select their respective profile
packages. The baseline RSA-OAEP and chain-key construction packages remain
`unmapped`, and the BIND package is an `experiment`. A package's path under
`v1/baseline/` or `v1/profiles/` names what it records, not a claim that it
covers that profile's duties.

## Replay payload formats

`vectorFormat` names a payload's replay schema; despite the member name, it
does not decide whether the containing record is a vector or fixture. The
record's path, package manifest, consuming boundary and assertions make that
classification. Each format has its own replay path.
The optional baseline `v1/baseline/rsa-oaep-envelope-open/` package carries
format 3. Format 4 lives in
`v1/experiments/bind-on-renderId-and-slot/`, and the two client-bound sets carry
`"profile"`. The baseline ECDH carrier-open package carries
`"ecdh-p256-envelope-open/v1"`. A set can gain a format after this sentence was written, so read
each file's own `vectorFormat`.

**Format 1 is a render.** The file carries an `input` on one side and the wire
it produces on the other. Seal the input, diff `expected`, then walk the
recorded wire on its own: unseal each blob, decrypt each ciphertext, and recover
each independently supplied periodKey with no derivation input in reach.
It pins what a conformant implementation produces.

Run it both ways. Unsealing shows an implementation can read the wire; only
sealing shows it writes the same bytes, and one that reads correctly and writes
something else passes every unseal check in the directory. Sealing reproduces
`expected.sealedContent`, the cached contentKey ciphertexts and the ephemeral
point at offset 0 of every blob byte for byte, with each periodKey read from
`input.periodKeys`. Unsealing verifies the resourceJWT, rebuilds
each binding as a string, unseals every contentKey and periodKey on the agreed
x-coordinate the envelope format states, and opens the content and the cached
contentKeys under them.

A replayer can diff the seal direction because the vector supplies everything
the sealer would otherwise draw at random: `input.ephemeralKeys` is an array
with one keypair record per sealed coordinate, including its `issuerName` and
either its `contentName` or its `accessGroup` and `t`. The IVs are on the wire
side - `expected.dcaData.contentData[name].nonce`, each
`expected.dcaData.contentData[name].keys[group][i].nonce`, and for a sealed blob the 12 bytes
the format packs inline at offset 65. A sealer with no way to inject those two
can only be checked for width and round trip.

**Format 2 is an unlock request an issuer must not answer as asked.** It carries
`rawBody`, the issuer key material to process it with, and the `expected`
answer: the refusal code where a whole-request check refuses, the coordinates
that come back with key material, the ones that come back as errors, and
`privateKeyReached`. A replayer running this corpus proves out the frozen
protocol bytes, the signatures over them, the binding reconstruction, the
refusal classes and the fail-closed private-key reach. HTTP, routing and
endpoint policy are outside it: no transport status is recorded here, and no
vector records how a deployment finds a signing key. Those belong to the
endpoint contract under `../../js/test-contract/issuer-endpoint/`, and a
replayer that gets every byte right does not fail this corpus over a status code
or a key it was handed rather than told to look up. These vectors pin what a
conformant implementation declines to produce, the half that positive vectors
leave uncovered: an issuer that answers every request passes every format 1
vector in the directory.

Post `rawBody` verbatim, verify the resourceJWT under the signing keys the
vector supplies in `publisher.signingKeys` before any private key, rebuild
the binding from each presented coordinate, and report each coordinate on its
own: the ones `expected.errors` lists fail the GCM tag, the ones
`expected.keys` lists open, and `expected.privateKeyReached` is asserted against
the ECDH operations the run actually spent. Each refused blob is then opened at
the coordinate it was really sealed at, which shows it is a real key rather than
something corrupt. A replayer finds that coordinate by trying every value its
own builder can produce, and for a blob sealed with the delimiter inside a bound
field there is no such value, because the builder never builds a value for that
field. A vector carrying such a blob records a `sealedUnder` array instead: the
coordinate, the exact bind string, and the key inside. A replayer puts that
recorded string at the head of its candidate list, so the blob opens and yields
the real key instead of looking like damaged bytes.

One validly signed reject has a 22-character renderId that decodes to 16 bytes
but uses non-zero unused trailing bits; it pins the refusal of a non-canonical
spelling ahead of any private-key reach. The set also pins the binding-delimiter
ban, over four
vectors: two where the caller writes the delimiter into a coordinate and the
blob under it is honest, and two where the blob itself was sealed with the
delimiter inside a bound field. A name carrying the character the binding fields
are joined on yields no binding value at all, and structural admission refuses
the whole request before any coordinate is answered. The section
"What a conformant issuer answers" below says which vector does which.

**Format 3 is an optional baseline RSA-OAEP envelope open.** A replayer opens a
recorded ciphertext and
compares the recovered binding-plus-key whole; OAEP seals are randomized and
cannot be byte-replayed. **Format 4** is the focused bound-carrier fixture:
deterministic ECDH seals and an RSA-OAEP open under one binding grammar.

**`ecdh-p256-envelope-open/v1` is a baseline content-key carrier open.** Its
recorded blob and issuer test key were extracted from the `seal-ecdh` fixture
that mixes content keys and period keys. An independent replay imports the issuer
private key, parses the 65-byte ephemeral point and 12-byte nonce, derives the
raw 32-byte ECDH x-coordinate, and uses those bytes directly as an AES-256-GCM
key. The recorded BIND is UTF-8 additional data; a changed coordinate fails
the tag. The package isolates one baseline carrier observation without
counting the mixed render as baseline-only or claiming a complete profile.

A replay that meets a `vectorFormat` it does not know has to fail, not skip.
A vector nobody executes still leaves the run green. A replayer enumerates
`*.json`, and inside that glob `set.json` is the only file that carries no
vector; it names the set and its phase, and a replayer skips it by name rather
than by shape, for the same reason. The `SHA256SUMS` beside it falls outside the
glob, and `check-sums.sh` reads that one.

**Profile vectors are portable replay contracts.** Their `vectorFormat` is
`"profile"` and their `profile` string names the selected delivery profile.
`dca-profile-client-bound-ecdh-p256` exposes the client key, issuer ephemeral keypair,
client-bound transport fields and three `deliveredKeys`: one content key,
one period key and one chain key. Each records its key kind, delivery key,
nonce and kind context. Its public JWK is the semantic P-256 point only (`kty`,
`crv`, `x`, `y`), avoiding browser-specific JWK export metadata. The injected
ephemeral pair and nonces keep sealing repeatable, so a replayer checks both
directions. `dca-profile-client-bound-rsa-oaep` likewise records three delivered keys, each
opened with its key-kind context as the OAEP label; its recorded `{key}`
ciphertexts are open-only because OAEP sealing is randomized. Neither fixture
imports issuer, page or request context; they carry client key material,
delivery keys and profile crypto inputs.

**Chain-key primitive vectors are recorded construction bytes.** Their
`vectorFormat` is `"chain-key-primitives-v1"`; their `profile` names
`dca-profile-chain-keys`, which selects the
`dca-construction-chain-keys` construction whose outputs they record. They
are not a complete delivery-profile claim.

The chain-key rows are literal recorded observations with no generator. A
standard-library Python script checks them independently:

```sh
python3 verification/vectors/check-chain-key-primitives.py
```

It builds the section 6.4 contexts of `../../docs/spec-profile--chain-keys.md`
itself, runs HKDF-SHA-256 with an empty salt, and compares every recorded info,
ikm and okm, plus the values of the JavaScript canonical fixture that it can
derive. This set and that fixture both record `dca-profile-chain-keys` bytes, so a
row they share holds the same value in both. The conformance `hkdf/01` to `hkdf/11` expectations are
literal recorded observations too; the script checks each as plain
HKDF-SHA-256 from its own recorded ikm, info and length and compares none of
them with the chain-key rows. No replay reads superseded construction records. The
script also refuses another JSON vector beside its named member, so a new
member cannot sit in the set without a replay. It imports no implementation,
writes nothing, and exits 1 on any disagreement.

## Inside a sealed blob

A value under `sealed.contentKeys` or `sealed.periodKeys` is base64url of a
self-contained blob, and the two key types lay those bytes out differently. The
wire carries no algorithm field, because the issuer knows its own key type.
`../../js/core-shared--publisher-issuer/keySealing.js` seals and opens both.

**ECDH P-256** uses fixed-size fields with no length prefixes, and the envelope
specification carries their field table:
[ECDH P-256 envelope](../../docs/spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope).
The reference reads those same three offsets out of `EPHEMERAL_BYTES` in
`keySealing.js` and `NONCE_BYTES` and `TAG_BYTES` in
`../../js/core-shared/aead.js`, which are 65, 12 and 16, so the canonical
16-byte key seals to 109 bytes and 146 base64url characters. The binding value
travels outside those bytes, as the AES-256-GCM `additionalData` that the issuer
rebuilds and the tag covers.

**RSA-OAEP** carries the binding inside the ciphertext instead, so the blob
holds one field and the layout that matters sits in the plaintext under it. The
blob, as `sealRsa` writes it and `unsealRsa` measures it:

| Offset | Length | Field | Encoding |
|---|---|---|---|
| 0 | the modulus width, 256 bytes at 2048 bits | RSA-OAEP ciphertext, SHA-256 digest, MGF1 over SHA-256, zero-length label | base64url on the wire, 342 characters at 2048 bits |

The plaintext `unsealRsa` recovers:

| Offset | Length | Field | Encoding |
|---|---|---|---|
| 0 | the binding value's own length | the value `bindValue` built for this coordinate | UTF-8, no terminator and no length prefix |
| that length | 16 bytes | the sealed key | raw AES-128 |

The plaintext carries no marker for where the value stops, so `unsealRsa` takes
the boundary from the fixed key width: the value is everything ahead of the last
16 bytes, and it is compared whole against the value the issuer rebuilt.
`unsealRsa` answers `unseal_failed` for a plaintext that is not exactly that
length, or that differs anywhere. Comparing only the first bytes would be a
prefix test, and a prefix test opens `premiumtext`'s blob under a `premium`
grant. A blob that is not one modulus wide fails as `unseal_failed` ahead of the
decrypt, so a 109-byte ECDH blob routed to an RSA issuer draws a stated refusal
rather than a bare `OperationError` from inside WebCrypto.

OAEP draws its padding seed inside WebCrypto with nothing to inject, so an RSA
render does not repeat and format 3 pins an open and never a re-seal.

## Post a reject body verbatim

`rawBody` is a JSON **string**, and a replayer posts exactly those bytes.

One of the attacks repeats a member name inside `sealed.contentKeys`, and no
parsed object can hold the same key twice - parse it, re-serialize it, and the
attack is gone before the run starts. Anything on the path that re-encodes a
body (a proxy, a framework that normalizes JSON, a test helper that takes an
object) removes what is being tested.

## What the reference issuer answers

Where a paragraph below names a function, that function belongs to the
JavaScript reference under `../../js/`.

**A request that fails integrity is refused whole.** The signed resource
carries the renderId every blob of that render is bound to, so a signature that
does not verify, or a signed resource with no renderId at the width `bind`
requires, leaves nothing that could be answered. The issuer refuses the request
with one code and HTTP 400 before it consults the key store, and hands back no
key material of any kind.
`reject-no-renderid`, `reject-renderid-noncanonical`,
`reject-renderid-wrong-width`, `reject-forged-resourcejwt`,
`reject-tampered-resourcejwt`, `reject-alg-substituted` and
`reject-alg-substituted-hs256` record that side of the line as
`privateKeyReached: false`.

**A blob at a coordinate it was not sealed at costs that one coordinate.** The
request around it is ordinary and trying the blob is the only way to find out,
so the issuer reaches the key store, answers 200 with no code, returns that coordinate
under `errors` as `unseal_failed`, and answers everything else the body carried
beside it. `reject-relabeled`, `reject-foreign-render`, `reject-unknown-contentname` and
the recorded reading of `reject-duplicate-member-name` record
`privateKeyReached: true`. The untouched
`periodKeys` come back in full: the client asked for them honestly, the relabel
never reached them, and a page has to keep working around one bad blob.

**A name the identifier grammar refuses costs the whole request.** A
`contentName` or an `accessGroup` carrying `|` is a coordinate no value can be
joined out of. `IssuerProcessor` refuses it at structural admission, ahead of
the policy decision, ahead of any binding value, and ahead of the engine asking
the key store for anything. That check runs the member names through the
identifier grammar rather than through a delimiter check of its own, so one
refusal covers `__proto__` and every other name the grammar rejects.
`reject-delimiter-contentname`, `reject-delimiter-accessgroup`,
`reject-delimiter-sealed-contentname`, `reject-delimiter-sealed-accessgroup`,
`reject-identifier-contentname`, `reject-identifier-accessgroup` and
`reject-prototype-name` all record that as `binding_failed` with HTTP 400, an
empty `errors` and `privateKeyReached: false`.

The whole-request `binding_failed` is raised a second time in `checkEnvelopes`,
which runs once over the anchor and ahead of the key store: once directly, where
the verified payload carries no renderId at all, which is what
`reject-no-renderid` lands on, and once inside `validateRenderId` on the line
below, which refuses a renderId that does not decode, is not 16 bytes, or is
spelled non-canonically.

**Two of the four delimiter vectors separate an issuer that runs the ban from
one that joins blindly.** `reject-delimiter-contentname` and
`reject-delimiter-accessgroup` present a delimited coordinate holding an honest
blob. A conformant issuer refuses the request at admission. An issuer that
skipped the grammar check would join a value nothing was sealed under and fail
the tag. Neither hands back a key, so these two pin that a delimited name never
opens anything rather than separating the two implementations by their answer.
`reject-delimiter-sealed-contentname` and
`reject-delimiter-sealed-accessgroup` carry a blob that was sealed with the
delimiter inside a bound field, so a blind join rebuilds the exact string the
blob was sealed under, the tag verifies, and a key comes back at a coordinate
`expected.keys` does not list. Take the ban out of a binding builder and the
older pair still passes while these two fail, handing back
`periodKeys.premium.sport|251023T1400` and `contentKeys.body|text`. The
accessgroup one carries the collision the ban exists for: `("premium|sport",
"251023T1400")` and `("premium", "sport|251023T1400")` join to one string. The
contentname one is there because an issuer that runs the ban on the two fields
that can collide and skips `contentName` passes everything else in the corpus
and still hands a key back.

**Refuse before touching a private key.** The port measures the body against
its byte cap, parses it once, and counts coordinates against the entry caps.
The engine then takes the version, the publisher registration the token
header's `kid` selects, the ES256 signature over the resource under that
registration's key, and the renderId and origin out of the verified payload -
the renderId at its canonical width, the origin as the canonical
`scheme://host[:port]` a browser reports. The access policy then runs on what is
left, and only then does the engine ask the key store for a private key. An
implementation that unseals first and refuses afterwards has already done the
work the attacker wanted.

**Walk the coordinates that arrived.** A client that resolved half a page from
cache sends half the blobs, so a short request is ordinary and the issuer
answers the coordinates the body carries. A blob at a coordinate the publisher
never sealed it at is caught at the unseal: the issuer rebuilds
`dca-bind-key-envelope|c|` + renderId + `|` + contentName as the AES-256-GCM
additionalData,
the tag fails, and `reject-unknown-contentname` records that as `unseal_failed`
at that one coordinate inside a 200.

**One reading of the body.** Every check and every unsealing runs against the
same parsed value. No vector can catch an implementation that reads the body for
one check and unseals against a second reading: each reading of a duplicate
member is conformant on its own, so the fault sits in the disagreement between
two passes inside one implementation, and the wire carries nothing that tells
the two apart. `reject-duplicate-member-name` records the rule every
reading shares instead: whatever comes back under a name is that name's own
contentKey or nothing.

**Own-property lookups on everything off the wire.** Every map in a request is
keyed by a name the client picked, `constructor` and `__proto__` included.

These codes and exact statuses describe the reference issuer; the browser
binding fixes status classes where noted, not every code or exact status.
Each whole-request refusal names the check that refused. `invalid_json`,
`too_many_entries`, `bad_version`, `bad_jwt`, `bad_alg`,
`bad_signature`, `unknown_publisher_key` and `binding_failed` answer 400.
An out-of-scope issuer alias is terminal 4xx; an unknown opening-key version
is operational 5xx (503 in the reference). `policy_unavailable` is 503,
`body_too_large` answers 413, and `denied` answers 401.
`internal_error` sits outside that map: `IssuerProcessor` re-codes a
`bad_config` thrown beneath it to `internal_error` at the request boundary,
`UnlockEndpoint` holds no entry for that code, and its status lookup falls
through to 500. That code reports a broken issuer rather than anything about the
request. Two codes sit outside the map for the other reason, that each marks one
coordinate inside a 200: `unseal_failed`, and `key_retired` where the request
names a keyId this issuer has let go. The codes stay separate so an operator
reading a log knows which check refused: `UnlockEndpoint` returns the true code
beside the response for the application to count and log, and puts on the wire
what its `errorDetail` option selects, either that code or the one word
`rejected` for every refusal alike.

**The refusal body is one member.** `refusalBody` in
`../../js/ports/UnlockEndpoint.js` writes it, and the port passes it no detail
of its own, so a refusal puts exactly this on the wire:

| `errorDetail` | body | |
|---|---|---|
| `code`, the default | `{"error":"bad_signature"}` | the refusal code that was reached |
| `uniform` | `{"error":"rejected"}` | the same bytes for every refusal, whatever it was refused for |

Neither member is free text. `error` is the only name either setting writes,
its value under `uniform` is the literal `rejected`, and its value under `code`
is a refusal code out of the vocabulary above, never a message and never a
reason. The port takes the status from its own map, the pairing listed above,
which also answers 400 for `request_mismatch`, `unsupported_option` and
`client_key_required`; a code the map does not hold falls through to 500, and
under `code` the body carries that unmapped code.

`errorDetail` selects the wording and never the status, and it never reaches a
200: the per-coordinate `errors` an answered request comes back with read
`unseal_failed` under both settings.

A host that words its own refusals hands `refusalBody` extra members, and only
`code` keeps them. `IssuerServer` in `../../js/demo/actors/` adds `issuerName`,
so a fault there reads
`{"error":"internal_error","issuerName":"paywall_subscription_service"}` under
`code` and `{"error":"rejected"}` under `uniform`. Uniform drops host detail
along with everything else.

## Where the runtimes disagree

These are dated runtime observations relevant to the wire. Current lane READMEs
state only their own binding and toolchain boundaries; the observations below
do not define conformance behavior.

**The four runtimes with a base64url decoder disagree, and not in the same
direction.** No implementation can rely on its own decoder for canonicality:

| | JVM `getUrlDecoder` | Go `RawURLEncoding` | .NET `Base64Url` | Python `urlsafe_b64decode` |
|---|---|---|---|---|
| `+` and `/` | rejected | rejected | rejected | **accepted**, it translates then decodes on the standard alphabet |
| `=` padding | accepted, count checked | rejected by `RawURLEncoding` | accepted, count not checked | **required**: unpadded input, which is every field on this wire, is refused |
| non-zero unused trailing bits | accepted | accepted | rejected | accepted, and still accepted under `validate=True` |
| whitespace, including embedded | rejected | `\r` and `\n` ignored at any position, space and tab rejected | accepted, any whitespace at any position | any non-alphabet character at all is silently discarded, whitespace included |
| data after the padding | untested | untested | untested | decoding continues past `==`, so `<v>==<v>==` yields a bit-shifted tail rather than an error |

The last row has not been measured for the JVM, .NET or Go. It remains outside
the current recorded evidence.

The base set's refusal of a non-canonically spelled `renderId` now passes in every
lane. All but one reach it through their own canonical check, and .NET gets it
from a decoder that refuses non-zero trailing bits outright, so the same green
row rests on different work underneath.
The whitespace row is the wider one. The JVM accepts 2^k spellings of a value, k
being the unused trailing bits. Go, .NET and Python each accept unboundedly many:
Go because `encoding/base64`'s decoder skips `\r` and `\n` at any position,
as documented by the decoder in Go's `encoding/base64` package, .NET
because it skips any whitespace anywhere, and Python because it discards every
non-alphabet character.

The [data format](../../docs/spec--data-format.md#22-binary-strings)
requires canonical base64url. A decoder must enforce the admitted alphabet,
length and trailing bits; decoding and unpadded re-encoding can check canonical
spelling. Recorded refusal cases for non-zero trailing bits and an embedded
space remain evidence work; they do not decide the already-adopted rule.

**A shared secret is a fixed-width field element.** Every runtime checked
returns the full 32 bytes for P-256, left zero padded, including when the
leading byte is zero. An implementation that trims leading zeros shortens about
one secret in 256, which becomes a short AES-256 key on the sealed blob and a
different-length input to the client-bound HKDF. Recorded evidence uses a pair
whose secret begins `00`, avoiding reliance on random sampling.

**Recorded EC private keys need their public point.** .NET refuses a private
scalar paired with a public point that is not its own; the JVM accepts it,
because its private key spec carries no public point to check. Key material
meant for more than one lane therefore records `x` and `y` alongside `d`.

**AES-GCM tag placement is only testable on .NET.** WebCrypto, Go, PHP, Python
and the JCA all natively produce and consume one ciphertext-then-tag buffer, so a
tag-first mistake cannot be made in those lanes. .NET's `AesGcm` takes separate
buffers and is the only place the joining order is written down in code.

The four below came out of running the operation bridges in `conformance-primitives/`
against one corpus, 2026-08-30. Each is a property of the wire rather than of a
lane, which is why they are here.

**The wire matches a JSON member name byte for byte, and Go's `encoding/json`
case-folds instead.** Go fills a field declared `value` from a member spelled
`Value`, so an issuer written in Go reads `{"ContentName":"premiumtext"}` as
`contentName`. A check keyed on one spelling is walked past with another.
`DisallowUnknownFields` does not close it, because the folding happens while
matching the names it does know. The Go bridge compares exact member sets
instead of declaring fields.

**JSON string escaping is the encoder's business, so comparison is over the
decoded string.** Go escapes `<`, `>` and `&` as `\u003c`, `\u003e` and
`\u0026` unless told
not to, the JVM bridge escapes everything above `~`, and PHP emits raw UTF-8. All
three carry the same string. A frozen-byte expectation is therefore over the
decoded value and never over its JSON spelling, and a lane that pins bytes by
comparing raw response text matches only its own encoder.

**PHP takes an AES key of any length and uses the first 32 bytes.** A 33-byte and
a 64-byte key sharing their first 32 bytes both return the correct plaintext, so
a wrong key looks like a right answer. Go, Python, the JVM and .NET each refuse a
key that is not 32 bytes and a nonce that is not 12. The selected
[ECDH envelope](../../docs/spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope)
already fixes a 32-octet wrapping key and a 12-octet nonce; another width is
malformed input, not permission to trim. These are envelope widths, not the
16-octet item-content or ordinary period-key width.

**A carrier shorter than the 16-byte tag has no agreed answer.** Python, Go, the
JVM and .NET report the authentication refusal, the JVM reaching it through
`AEADBadTagException` without an explicit length test. PHP treats it as a
malformed request and exits nonzero. Four runtimes to one, and the contract
already states that a tag failing under any cause is the refusal. No case sends
this input, so the disagreement stays invisible until someone sends it. A rule
that only produces a nonzero exit cannot be a case, which argues for settling it
as the refusal.

## What your runtime makes you do

Every row below cost somebody a day, and they fail the same way. Your bytes are
self-consistent, your own seal opens under your own open, and nothing works
against another implementation. The spec looks wrong at that point, and the
cause is a default your crypto library picked for you. Read this before deciding
the format is at fault.

Observed on 2026-08-27 under PHP 7.3.33, 8.3.33 and 8.4.24, Temurin 21.0.12.1+1,
25.0.4.1+1 and 26.0.2.1+1, Go 1.27.0, .NET SDK 10.0.400, Node v22.22.2, and a
static PHP 8.5.8 build fetched for the occasion. That 8.5.8 is a different
build from the static PHP 8.4.23 `../conformance-primitives/php/install-toolchain` pins;
both come from static-php-cli 2.8.6 and both report OpenSSL 3.6.2. Each tool
reports its own crypto library, which is what an implementer can check on
their own machine: the distro PHP links OpenSSL 3.0.20, the static PHP 8.5.8
carries 3.6.2, Node bundles 3.5.5, and on Python the interpreter's `ssl` links
3.5.8 while the `cryptography` wheel bundles 4.0.2. Go's crypto is pure Go and
the JVM's is Java, so neither has a number to report. One container holds five
OpenSSL builds spanning multiple release lines; the defaults below differ
across those builds.

**HKDF-SHA256.** Nothing here is subtle, it is only missing in places.

| Runtime | What you do |
|---|---|
| PHP 7.1.2 and newer | `hash_hkdf('sha256', ...)`, built in |
| JVM 24 and older | hand-roll extract and expand over `Mac("HmacSHA256")`, there is no KDF API |
| JVM 25 and newer | `javax.crypto.KDF`, final since the 25 LTS |
| Go | `crypto/hkdf`, in the standard library |
| .NET | built-in HKDF |
| WebCrypto | `deriveBits` under HKDF |

The one trap is an empty salt, which the chain-key and client-bound-transport
constructions both use. Java throws on a zero-length `SecretKeySpec` key, so
widen the salt to 32 zero bytes; .NET's built-in treats a null salt exactly as a
zero-length one, which confirms that reading from the outside. A hand-rolled
version stays useful after your runtime grows its own: run both and compare, and
the two answers pin each other.

**RSA-OAEP, SHA-256 for OAEP and SHA-256 for the MGF1 mask.** The label is
zero-length. Two hash parameters, not one, are the whole problem.

| Runtime | What you do |
|---|---|
| PHP, every version | hand-roll: `openssl_public_encrypt` and `openssl_private_decrypt` take a padding constant and no digest, so you do the modexp under `OPENSSL_NO_PADDING` and the RFC 8017 Sections 7.1.1 and 7.1.2 steps yourself |
| JVM, every version tested | pass an explicit `OAEPParameterSpec` naming `MGF1ParameterSpec.SHA256`; the string-named transform masks with SHA-1 |
| Go | `EncryptOAEP` and `DecryptOAEP` take the hash, and `OAEPOptions.MGFHash` falls back to `Hash` when zero |
| .NET | `RSAEncryptionPadding.OaepSHA256` sets both |
| WebCrypto | MGF1 follows the key's hash, by specification |

PHP's limit sits in the binding rather than the library: the same OpenSSL 3.0.20
seals and opens OAEP-SHA256 from its own command line under `rsa_oaep_md:sha256`,
so no OpenSSL release will fix what PHP has no argument to ask for. JDK-8058549
tracks the JVM's default, open for years and still present on 26.

**ES256 signature form: raw r||s, never ASN.1 DER.** A mismatched form usually
returns false rather than throwing, so nothing points at the encoding.

| Runtime | What you do |
|---|---|
| JVM | `Signature.getInstance("SHA256withECDSAinP1363Format")` and read the boolean; DER fed to a P1363 verifier returns false rather than throwing |
| .NET | the default `ECDsa` signature is already 64 bytes raw; the DER form is the one you ask for |
| Go | assemble r and s yourself, each left-padded to 32 bytes |
| WebCrypto | raw by specification |

## Replay ownership

Current JavaScript replay lives in `../../js/test-vectors/`.
This vector directory owns recorded bytes, set metadata and checksum behavior.

## Where the rest is written

Lane READMEs carry what is genuinely lane-specific: the runtime README says how
that runtime is installed, the binding README says how the bridge is built and
what its crypto library gets wrong. `../conformance-primitives/jvm/README.md`
and `../conformance-primitives/jvm/jca-jackson/README.md` are the current
example of that split.

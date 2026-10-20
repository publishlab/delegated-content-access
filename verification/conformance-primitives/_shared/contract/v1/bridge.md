# Operation-bridge contract v1

A bridge is one executable the harness starts, hands one batch of questions on stdin, and reads one batch of
answers from stdout. It computes observations. It never judges them.

This file is everything a bridge needs. An implementer writing one in Go, Python, Java or C# reads this and
nothing else; the case corpus is not an input to a bridge, and the harness source is not a specification.

Seven operations are carried: decode a strict base64url field, derive octets with HKDF-SHA-256, open and seal
an AES-GCM carrier, agree a P-256 ECDH secret, encode a P-256 public point, and open an RSA-OAEP ciphertext.
The member the lane's `bridge.json` names answers each one. In most lanes that member is a library call, and
in some it is code written in the lane: the strict base64url verdict in every lane, the P-256 point layout in
every lane whose library does not export the uncompressed point itself, HKDF in `jvm/jca-jackson` over the
JCA's HMAC, and OAEP unpadding in `php/openssl` over ext/openssl's raw private-key operation ([Building is not
answering](#building-is-not-answering)). Each refusal below is a fact about bytes: a spelling that does not
decode, a tag that does not verify, and a ciphertext that does not open. An operation whose answer a runtime's
own libraries cannot reach is not here, because reaching it would mean every bridge reimplementing the harness
once per language.

For strict base64url decoding, `lane` owns the answer because its canonical
alphabet, length and re-encode checks decide whether the input is accepted.
The runtime decoder supplies bytes only after those checks; that library call
does not make the acceptance rule its member attribution.

No operation decides anything, and no operation knows a protocol. A bridge is handed octets, keys and lengths.
No input member names anything a DCA specification defines, and no bridge joins, slices or derives a value on a
specification's behalf. Every intermediate value a protocol would compute between two library calls arrives as
a recorded input, so each operation is asked alone. An operation that had to judge its own answer, or to read
a document to know what its answer should be, would be the wrong operation.

## Process contract

The harness starts the bridge once per invocation, writes one newline-terminated JSON document to its stdin,
and closes stdin. The bridge reads stdin to end of input, writes one JSON value to stdout, and exits 0.

- stdout carries exactly one JSON value and nothing else. Trailing whitespace is ignored. A second value,
  non-JSON bytes, or a repeated member name in the bridge's result makes the run incomplete.
- stderr is diagnostic. A bridge may write whatever helps a person read a failure. Nothing is ever read out of
  stderr as a result, so a bridge that reports an answer only on stderr has reported nothing. The harness
  reprints a capped part of it and states how much there was, so a bridge writing megabytes still leaves the
  reason readable in a terminal.
- Both streams are UTF-8. Every value in this contract's corpus is ASCII, so no case turns on the encoding of
  the streams themselves.
- stdout is capped at 256 KiB and one batch is capped at 10000 ms by default. A full batch answer is well
  under 2 KiB, so neither cap is near.
- Exit 0 means the bridge answered every request it was given. Any other exit status, a fatal signal, or an
  empty stdout means the run could not be completed.

A batch the bridge cannot serve is a nonzero exit with a stderr line and no partial results on stdout. That
covers a batch that does not parse, a protocol string it does not speak, an `op` it does not implement, and an
input shape outside this file. It does not cover the defined refusals below, which are answers.

### Building is not answering

A bridge that has to be compiled, restored or otherwise built is built before the batch is sent, under a
separate and generous allowance, and the harness then starts a program that is already runnable. The 10000 ms
budget covers answering the batch. A bridge launched through a build command would be timed on its compiler,
which says nothing about the bytes it produces.

A lane names its build command and every operation it implements in its own `bridge.json`, at the lane's
root: `script`, the bridge's source; `command`, what is started to answer a batch; and an optional
`prepare: {command, args?}`, the build command itself. A set of cases that asks for an operation the lane has
not declared is unsupported for that lane; it is not a held result. A declared operation that the bridge then
omits is incomplete.
Paths in a manifest are written from the conformance directory, not from the lane's own directory. A
build that fails is a run that could not be completed, reported as incomplete with the build's own output,
because nothing was asked yet.

The same file says which part of the binding answers each operation:

```json
{
    "members": {
        "openssl": "ext/openssl",
        "hash": "ext/hash, PHP's own SHA-256 and HKDF",
        "lane": "code written in this lane"
    },
    "operations": {
        "decode-base64url": "lane",
        "hkdf-sha256": "hash",
        "open-aes-gcm": "openssl"
    }
}
```

- `members` is mandatory. A member name is lowercase letters and digits, and its value says in one line what
  the member is.
- `operations` is mandatory. Each key is an operation this bridge can answer, and each value names a key of
  `members`. Every member answers at least one operation.
- An empty `members` beside an empty `operations` declares an intentionally unavailable operation surface:
  every set is unsupported for that lane, and its record carries no operation row.
- The member of an operation is the code that computes the answer bytes, or the accept/refuse verdict, that the
  harness compares. Lane code around a library call does not change the member unless that lane code decides
  the contract's answer, as strict base64url acceptance checks do. Reading JWK members for a key import alone
  does not change the member. Where the code written in the lane is
  itself the computation, the member is by convention named `lane`. The harness gives that name no special
  meaning.
- The attribution is harness metadata. A lane record carries one `operation=<operation> member=<member>` row
  per declared operation, and the bridge is never asked who answered: nothing about it crosses stdin or
  stdout.
- The attribution says which code computes the answer, not that it is independent of a library. A `lane`
  member may still call a library underneath, such as a raw RSA private-key operation below hand-written OAEP
  unpadding; the binding README names that call beside the row.
- The aggregate, `_shared/aggregate-results`, refuses an operation row that is malformed, names an operation
  outside the seven or repeats one, and it proves nothing more. It does not prove the attribution complete or
  true: a record with no operation rows, or with fewer rows than the lane declares, passes, and so does any
  member name of lowercase letters and digits. The aggregate refolds the set verdicts and trusts the
  attribution the record carries; it attests no provider. Making the rows mandatory, or checking a record
  against the lane's current `bridge.json`, is a separate decision.

## Batch envelope

Request, one line on stdin:

```json
{"protocol":"dca-operation-bridge-v1","requests":[
  {"id":"encoding/01","op":"decode-base64url","input":{"value":"..."}}
]}
```

Result, one JSON value on stdout:

```json
{"protocol":"dca-operation-bridge-v1","results":[
  {"id":"encoding/01","op":"decode-base64url","observation":{"bytesHex":"..."}}
]}
```

- `protocol` is byte-exactly `dca-operation-bridge-v1` on both sides, compared as a case-sensitive string. A
  result whose top level is anything else, a wrong string, a missing member, a non-object or an array, makes
  the run incomplete.
- The request top level carries `protocol` and `requests`, and nothing else. The result top level carries
  `protocol` and `results`, and nothing else.
- A request entry carries `id`, `op` and `input`. A result entry carries `id`, `op` and `observation`. An
  unknown member, a missing member or a member of the wrong JSON type makes the run incomplete, in a result
  and in a request alike. These shapes are closed on both sides, and both sides check them: a bridge handed a
  request carrying a member this file does not name exits nonzero rather than answering it.
- Every requested `(id, op)` pair appears in `results` exactly once. Result order is irrelevant and member
  order inside any object is irrelevant. A duplicate `(id, op)` makes the run incomplete even when both copies
  say the same thing. A result whose `op` differs from the one requested for that `id` answers a question
  nobody asked, and leaves the asked one missing.
- `id` and `op` in a result are copied from the request they answer.
- A batch may hold one request or all of them. One case is a batch of one, which is how an operator narrows a
  failure by halving the selection; the bridge treats every batch the same way.

The request never carries an expected value or a verdict field. A bridge that asks for one is asking to be
told the answer it is being tested on.

### The identifier says nothing about the answer

`id` is opaque, `<set>/<nn>`, and carries no word describing how its case comes out. It is a name for one
question, usable in an operator's `--case` argument and in a failure report, and nothing more. The readable
description of each case lives on the harness side and never crosses to a bridge.

A bridge has no use for the identifier beyond copying it back into the result it answers. A bridge that reads
it for anything else is reading a label, and the labels are gone.

### Duplicate member names

A bridge uses its runtime's own JSON parser to read the batch, and nothing else. Most parsers keep one
spelling of a repeated member and say nothing, and that is fine here: the harness writes these bytes and never
repeats a member, so a bridge scanning for duplicates would be defending against its own harness, and the
scanner would have to be written once per language.

Duplicate member names in a request are out of scope: the harness writes those bytes and never repeats a
member, so no bridge detects them. The harness does reject duplicate members in a bridge's result, because it
must not choose between two observations the bridge wrote for one name. No corpus case tests either parser;
duplicate detection is process-envelope validation, not a primitive observation.

## Observations

An observation is a JSON object carrying exactly one of its operation's defined member sets, with each member
of the defined type. Nothing else is an observation: an empty object is not, an object carrying both a success
member and `refused` is not, and an object with an extra member is not.

Every operation may answer with `{"refused": <code>}` in place of its success shape, drawn from the codes
listed for that operation. The refusal codes are the whole vocabulary. A code outside them is a wrong answer,
not a new kind of answer, and a bridge that wants to say more says it on stderr.

```text
decode-base64url  -> {"bytesHex": string}               | {"refused":"invalid_base64url"}
hkdf-sha256       -> {"okmBase64url": string}
open-aes-gcm      -> {"plaintextBase64url": string}     | {"refused":"authentication_failed"}
seal-aes-gcm      -> {"ciphertextBase64url": string}
ecdh-p256         -> {"sharedSecretBase64url": string}
p256-point        -> {"pointBase64url": string}
open-rsa-oaep     -> {"plaintextBase64url": string}     | {"refused":"unseal_failed"}
```

A seal defines no refusal, and neither does a derivation or an encoding. That is the reason the list is written per operation rather than as
one vocabulary: a seal that cannot be computed is a request the bridge could not serve, which is a nonzero
exit. There is no byte a correct sealer refuses to seal.

Well-formedness is what separates the harness's two failing exits, and the value list is not. A well-formed
observation that differs from what the case expects, including an unknown `refused` code, a wrong defined code
on a refusal case, and a refusal where a value was expected, is a disagreement: the bridge reached an answer
in this vocabulary and the answer is wrong. An observation outside the shapes above is incomplete: the bridge
never reached an answer, and reporting a finding about bytes nobody compared would claim a measurement the run
did not make.

## Encodings

- `bytesHex` is lowercase hexadecimal, two digits per byte, no separator, no prefix. Comparison is exact
  string equality, so uppercase hex is a wrong answer. Normalising it on the harness side would hide a real
  spelling divergence between two bridges.
- Every `...Base64url` member, in an input and in an observation, is canonical unpadded base64url over RFC
  4648 section 5: the alphabet `A-Z`, `a-z`, `0-9`, `-`, `_`, and no `=`.
- Every string comparison is byte equality after JSON decoding. No trimming, no case folding, no Unicode
  normalisation.

### A spelling that does not decode, and a carrier that is too short

Two operations open a carrier: `open-aes-gcm` and `open-rsa-oaep`. They answer these two inputs the same way,
and it is written once here because each implementation would otherwise have to choose.

A `...Base64url` member that does not decode is a request the bridge cannot serve, and that is a nonzero exit.
Every value the harness sends is canonical, so a spelling that is not says the batch was written wrong.
`decode-base64url` is where a spelling is the subject.

A member that decodes and is then too short for its carrier is the operation's own refusal: fewer octets than
the AES-GCM tag, or an RSA ciphertext that is not one modulus wide. It is `{"refused": "authentication_failed"}`
on `open-aes-gcm` and `{"refused": "unseal_failed"}` on `open-rsa-oaep`. Nothing downstream of a short carrier
can produce a plaintext, which is the same fact a failed tag states, and a bridge that exited instead would
take a whole batch down over one answer it had already reached.

No case exercises either input today, so neither sentence moves a verdict. They are here because the answer is
otherwise unwritten, and an unwritten answer is where two bridges quietly disagree.

## decode-base64url

Decodes one strict base64url field.

Input: `{"value": string}`.

The value is canonical when all four of these hold. A value failing any one of them is refused.

1. Every character is in the alphabet `A-Z`, `a-z`, `0-9`, `-`, `_`. The characters `+`, `/` and `=`, all
   whitespace, and every other byte fail this rule.
2. The length modulo 4 is 0, 2 or 3. A length of 1 modulo 4 encodes no whole byte count.
3. No padding. This is rule 1 applied to `=`, and it is why a padded spelling is refused.
4. No unused trailing bits: decoding and re-encoding unpadded reproduces the input string exactly.

The empty string is canonical and decodes to zero bytes.

Success is `{"bytesHex": <lowercase hex of the decoded bytes>}`. Any failure is `{"refused":
"invalid_base64url"}`, whichever rule fired. Which rule fired may go to stderr and never into the observation.

Rule 4 is spelled out because common runtime decoders do not enforce it by
themselves. Decode the value, encode the resulting bytes again with canonical
unpadded base64url, and compare that spelling byte for byte with the input. A
value with non-zero unused trailing bits decodes to bytes but fails this
comparison. A general-purpose decoder may also accept the standard base64
alphabet or padding; acceptance there does not satisfy this operation's strict
field rule.

## hkdf-sha256

Input: `{"ikmBase64url": string, "infoBase64url": string, "length": number}`.

The bridge runs one HKDF-SHA-256 invocation (RFC 5869) with an empty salt,
`HKDF-Expand(HKDF-Extract(salt = "", ikm), info, length)`, and answers the `length` output octets. A library
that substitutes 32 zero octets for an absent salt produces the same bytes.

`info` is octets. Some recorded values carry `0x00` and octets above `0x7f`, so a bridge that routes `info`
through a text string type answers different bytes. Some recorded cases ask for 16 octets, fewer than one
SHA-256 block, so a bridge that always answers the whole 32-octet block is wrong.

The operation defines no refusal. A `length` outside 1 through 8160 is a batch fault.

Success is `{"okmBase64url": string}`.

## open-aes-gcm

Input:

```json
{"keyBase64url": string, "nonceBase64url": string, "ciphertextBase64url": string, "aadBase64url": string}
```

The key is 16 octets for AES-128-GCM or 32 octets for AES-256-GCM, and the key's width selects the cipher. The
nonce is 12 octets. The tag is 16 octets appended to the ciphertext, so `ciphertextBase64url` decodes to
`ciphertext || tag` in one buffer. A runtime whose API takes the tag separately splits the last 16 octets off
itself. Ciphertext-then-tag is the order every runtime but .NET produces natively, and carrying the tag as its
own member would hand .NET's split API to every other bridge as extra work while testing nothing new.

`aadBase64url` may be the empty string, which means additional data of zero octets. A runtime whose API tells
an absent AAD apart from an empty one passes whichever form authenticates zero octets.

Success is `{"plaintextBase64url": string}`. A tag that does not verify is
`{"refused": "authentication_failed"}`: a wrong key, a wrong nonce, other additional data and a flipped octet
are one answer, because the tag check does not tell them apart.

A key that is neither 16 nor 32 octets, or a nonce that is not 12, is a batch fault.

## seal-aes-gcm

Input:

```json
{"keyBase64url": string, "nonceBase64url": string, "plaintextBase64url": string, "aadBase64url": string}
```

The same widths and the same empty-AAD rule as `open-aes-gcm`. The nonce is an input, which is the whole reason
a seal has one determined answer.

Success is `{"ciphertextBase64url": string}`, the ciphertext with the 16-octet tag appended, compared as an
exact string. A runtime whose API returns the tag separately appends it.

The operation defines no refusal.

## Keys

Every `...Jwk` member is one JSON object in RFC 7517 form, passed through unchanged. An EC key is `kty` `EC`,
`crv` `P-256` and the base64url coordinates `x` and `y`, with `d` on a private one. An RSA key is `kty` `RSA`
with `n` and `e`, and on a private one `d`, `p`, `q`, `dp`, `dq` and `qi`, and it may carry `alg`
`RSA-OAEP-256`. The harness never reshapes one and never compares one: no observation carries a JWK. A bridge
reads the JWK members it needs, such as `x`, `y` and `d` of an EC key or `n`, `e` and `d` of an RSA key, and
builds from them a key its library takes. Where the runtime has no JWK importer, that member handling is code
written in the lane. Where it has one, such as WebCrypto's `importKey` with the `jwk` format, the importer
reads the JWK itself and the lane writes no member code.
Reading members still judges nothing and derives nothing a DCA specification defines, which no bridge ever
does.

## ecdh-p256

Input: `{"privateKeyJwk": object, "peerPointBase64url": string}`.

`peerPointBase64url` decodes to the peer's public key as an uncompressed SEC 1 point: the octet `0x04`, then
the 32-octet `x`, then the 32-octet `y`, 65 octets in all. The bridge imports the point with its runtime's own
routines and runs one ECDH agreement over P-256.

Success is `{"sharedSecretBase64url": string}`: the agreed x-coordinate as an unsigned big-endian integer at
the P-256 field width, exactly 32 octets, keeping or adding leading zero octets as needed. A runtime that
hands back a big integer drops a leading zero octet; the corpus includes an agreement whose shared x-coordinate
starts with `0x00`.

The operation defines no refusal. Every recorded peer value is a valid point, and a value the runtime cannot
import is a batch fault. The bridge applies no KDF to the secret.

## p256-point

Input: `{"publicKeyJwk": object}`.

Success is `{"pointBase64url": string}`: the key as the 65-octet uncompressed SEC 1 point described under
`ecdh-p256`. Each coordinate keeps its full 32-octet width, and one recorded case has a coordinate that starts
with a zero octet.

The operation defines no refusal.

## open-rsa-oaep

Input: `{"ciphertextBase64url": string, "privateKeyJwk": object}`.

One decryption, RSA-OAEP over SHA-256, MGF1 with the same hash, no label. There is no hash member, because a
runtime that defaults MGF1 to SHA-1 is the defect the recorded cases find. Label support is missing from stock
PHP and .NET, so there is no label. The ciphertext is exactly one modulus wide.

Success is `{"plaintextBase64url": string}`, the whole plaintext and nothing read out of it.

A wrong private key, a ciphertext that is not one modulus wide, and a flipped octet are one
`{"refused": "unseal_failed"}`. OAEP's own padding check does not tell them apart, and a bridge that reported
which one happened would be answering the question a padding oracle asks.

## What a bridge must never do

- Never read, receive or look up an expected value. The request carries none, and the case corpus is not an
  input to a bridge process.
- Never emit a verdict. There is no held, disagreed, incomplete, pass, fail or total anywhere in a result. A
  bridge reporting its own conclusion gives the harness a second opinion it would then have to reconcile.
- Never print a result on stderr. Results live on stdout and only on stdout.
- Never write a partial batch. A bridge that cannot serve one request in a batch exits nonzero with a stderr
  line and writes nothing to stdout.
- Never invent a refusal code, and never refuse in place of a failure it cannot serve. The codes an operation
  defines are answers inside an exit-0 result; anything else the bridge wants to say is a nonzero exit and a
  stderr line.
- Never normalise, reorder or prettify an observation value. Hex case, base64url spelling and member order are
  the behaviour under test.
- Never answer from the identifier. It says nothing about the answer, and a bridge that reads it as though it
  did is answering a question the harness did not ask.

## Outside this contract, recorded

- Everything a DCA specification defines on top of these calls: a binding string and its grammar, a sealed
  blob's layout, which secret keys which carrier, a derivation's context layout and its labels. An
  implementation tests those in its own suite against `verification/vectors/` and
  `verification/fixtures/v1/`. Here they appear only as recorded octets.
- A batch carries both directions of one value: a `seal-aes-gcm` whose expected ciphertext is the input of an
  `open-aes-gcm` beside it. A bridge that answered one request out of another request's input is not caught by
  that pair. The cases with no partner are where a bridge that answers without computing is caught: opaque
  identifiers, no expectation on the wire, and no value shared between two cases.
- An RSA-OAEP seal. OAEP draws its padding seed inside the crypto library, so two correct implementations
  produce two different ciphertexts for one key, and there is no determined answer to ask for.
- An ECDH key pair drawn by the bridge. Every private key is a recorded input, for the same reason a nonce is.
- A signature of any kind. ES256 draws a nonce of its own, so a signing operation has no determined answer.
- Which requests an issuer answers and which come back as errors, an entitlement decision rather than a fact
  about bytes.

## Where the recorded values come from

The cases are literal and this directory owns them. Most octets in them were cut from the published DCA
vectors, so that a bridge which holds here computes what a DCA implementation on the same runtime will need:

- `ecdh-p256`, `open-aes-gcm` with a 32-octet key and `seal-aes-gcm` carry the agreement, the binding octets
  and the blob parts of sealed key blobs in `verification/vectors/v1/experiments/bind-on-renderId-and-slot/` and
  `verification/fixtures/v1/`.
- `hkdf-sha256` carries the client-bound delivery derivation of
  `verification/vectors/v1/profiles/dca-profile-client-bound-ecdh-p256/` and chain-key contexts in the layout that
  `spec-profile--chain-keys.md` section 6.4 lays out. Those cases were cut before the construction id became
  `dca-v1-chain-keys` (since renamed `dca-construction-chain-keys`), so their `info` octets spell the earlier id; the operation is stock HKDF and holds for any
  `info`.
- `open-rsa-oaep` carries the zero-label RSA-OAEP ciphertext of
  `verification/vectors/v1/baseline/rsa-oaep-envelope-open/` and a recorded
  16-octet plaintext case under the same primitive. Current client-bound
  RSA-OAEP delivery uses a nonempty key-kind label and is outside this
  zero-label operation.

Each derived value was proved against those published bytes before it was recorded: a shared secret is right
when it opens the recorded carrier under the recorded tag, and a sealed value is right when it equals the
recorded one. No value was read off an implementation's output alone.

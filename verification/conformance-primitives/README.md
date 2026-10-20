# Primitive conformance

## Admit an operation only when it is a primitive

One operation invokes one public deterministic primitive once and compares its
one canonical result. "The primitives are often run together" is not a reason
to add their composition here. If Step and Leaf each return the required bytes,
running Step and Leaf repeatedly in an `expand-chain` operation only tests a
loop; that loop belongs to each implementation's ordinary tests. For the same
reason, leave out projections, round trips and end-to-end workflows assembled
from already-covered operations.

Before adding an operation, name the independently meaningful output that no
existing operation already establishes. If there is none, do not add it. A
larger example may still belong in a reference or integration test; do not
admit an operation here on the grounds that it produces deterministic output.

For an admitted primitive, cover every input distinction that can change its
meaning or expose a plausible wrong implementation. Do not confuse that with
sampling more values from the same class. Differing bytes alone do not make a
second arbitrary 16-byte state another conformance variation. The candidates
are a distinct key width, algorithm parameter, point representation, tag
layout or canonical encoding boundary, a parameter passed as binary rather
than as text, or another distinction the library call itself exposes. Each one
is a variation when an implementation could plausibly omit, reorder, truncate
or mis-encode it and still pass the existing examples. State the wrong
implementation each added vector distinguishes.

## Hand a bridge bytes, never a protocol field

No domain in here. These are primitives.

A primitive is a stock library call the specifications ultimately rest on: decode
base64url, open AES-GCM, agree a secret with ECDH, open RSA-OAEP, derive octets
with HKDF. The same operation would fit unchanged in a corpus for another
protocol built on the same libraries. Everything DCA defines on top of those
calls is domain: a context layout, a geometry, a label, a position, which key
wraps which. The specification defines domain once, and each implementation
tests it in its own suite.

- A bridge takes octets, key material and lengths, and it answers octets. A
  bridge works out no value the protocol defines.
- No input member names something in the DCA protocol.
- Where an input came from is outside this corpus. A bridge gets `251023T1415`
  as eleven characters and never learns that a clock produced them. Nothing in
  a bridge or in the driver converts, parses or formats a value to make an input.
- A case earns its place when a library call gives a concrete reason to suspect
  that two platforms answer differently: where AES-GCM puts the tag, which hash
  RSA-OAEP uses for MGF1, how ECDH encodes a point, whether binary HKDF `info`
  survives a text-typed parameter, how strictly a decoder reads base64url.
- Finding the characters or values that one platform mishandles is that
  platform's job, and it costs more than this corpus can pay. String inputs are
  ASCII, which is all the specification admits in an identifier; what varies
  between cases is length.
- More coverage means more recorded inputs for an operation that exists. It
  never means a conversion, a loop or a second step inside a bridge.

Two tests before adding an input member. Could a cryptographer implement the
operation from its name and its members, knowing nothing about DCA? Does the
bridge compute anything the driver could have recorded once? A no to the first
or a yes to the second means the member is domain, and it stays out.

Every lane, node included, answers each operation through its own runtime's
libraries, and nothing in this directory reads a file outside it.

Someone writing their own DCA implementation runs this to find out whether it produces the same bytes as
everyone else. One driver, written in JavaScript, holds every expected value and does every comparison. Each
language or platform under test has a lane: one directory holding a bridge. The bridge is a small program
that reads a JSON batch of requests on stdin, runs one primitive from its own crypto or codec library per
request, and writes the observations on stdout. A bridge reads only the requests in its batch and writes
back what its own library returned; the expected values and every comparison stay with the driver. The
driver asks for low-level work: decode this spelling, derive these octets, open this carrier under this
key. The bridge writes back bytes, or one of a few named refusal codes: a spelling that does not decode, a
tag that does not verify, a ciphertext that does not open.

The request and observation shapes, the operation names and the refusal codes are written once, in
`_shared/contract/v1/bridge.md`. That file is the only one someone needs in order to write a bridge.

Nothing here is designed to test entitlement, access policy, HTTP, routing or end-to-end behavior; those are
checked elsewhere. The Node lane happens to exercise repository code, but coverage of that code is not this
framework's purpose. A run that holds shows that the implementation
behind the bridge produced the same bytes out from the same bytes in.

## Running it

From `verification/`:

```sh
conformance-primitives/check                 # every lane at its default runtime versions, one tally
conformance-primitives/php/openssl/check     # one lane, everything it answers
conformance-primitives/run php/openssl       # one lane, the case corpus only, after the framework's own self-check
```

The framework needs a JavaScript runtime with WebCrypto and bash. Node is the default; `DCA_JS=deno` runs
the same files under Deno, and names a runtime, never a behavior. That runtime runs the driver only. Every
lane, node included, installs its pinned runtime into a cache the first time it runs and reads nothing off
`PATH`.

## Runtime versions

The runtime version is the one input a run takes besides its selectors: `--version <v>` on `check`, on a
lane's `check` and on `run`, or `DCA_VERSION`, and `default` when neither is given.

```sh
conformance-primitives/check                          # every lane at its runtime's default versions
conformance-primitives/check --version all            # every lane at every version its runtime lists
conformance-primitives/check --version 8.3            # only the lanes whose runtime lists 8.3
conformance-primitives/php/openssl/check --version 8.3
conformance-primitives/run node/openssl --version 22
```

Each runtime lists its versions in `<runtime>/versions`, beside its installer, one line per token:

```text
8.4 8.4.23 default
8.3 8.3.32 listed
```

The columns are the version token, the release pinned by the installer and
the selection state (`default` or `listed`). Do not add comments or other text
to a data line; the version-list reader accepts only those three fields.

`default` runs every token marked `default`; the gate runs this. A runtime with a readable list but no `default`
token makes the default gate incomplete (exit 2), because that lane cannot be included in the claimed default
run. `all` runs every token the list names. A token runs that version alone. `check` then selects only the lanes whose runtime lists the token, prints the
others as not selected, and exits 2 when no runtime lists it; a lane's `check` given a token its runtime does
not list refuses with exit 2 before anything is installed. `run` answers one version, so `default` there is
the list's first default line and `all` is refused.

The installer keeps the download and its checksum per token and installs each version into a directory of
its own, so two versions sit side by side in one cache. The lane check exports the token as `DCA_VERSION`,
and the prepare step and the answering process `bridge.json` names pass it to the installer, so the version
that answers is the one selected and never a binary on `PATH`.

A run is one (lane, version) pair. Its record carries the token and the version the installed binary
reported when asked (`php -r 'echo PHP_VERSION;'`, `node --version`), not the list's value:

```text
lane=php/openssl
version=8.3
runtime=8.3.32
operation=decode-base64url member=lane
operation=hkdf-sha256 member=hash
...
set=encoding status=held
...
exit=0
```

A lane check given several tokens and `--record <file>` writes `<file>.<token>` per token; `check` calls
each lane once per pair and names every pair `<lane>@<token>`, as in `node/openssl@24: held`. A binding
that cannot run a version its runtime lists writes a record with `status=refused` and a `reason=` line
instead of set rows; it folds into no exit code, the way an unsupported set does, and the aggregate names
it apart from `unsupported`.

## Exit codes

- `0` held. Every selected case was answered and every answer matched.
- `1` disagreed. A bridge answered inside the contract and answered wrongly. The output names the case.
- `2` incomplete. The run verified nothing: a bridge crashed, timed out, wrote something outside the contract,
  or left a selected case unanswered, or the selection itself was refused before any bridge started.

A lane check runs the corpus one set at a time and folds those runs by one ranking: incomplete outranks
disagreement, and disagreement outranks holding. The run prints a set asking for an operation the lane has not
declared as unsupported and folds it into no exit code, so a lane holds over the sets it answered and the
output names the sets nobody asked it.

## Narrowing a failure

Selectors pick which cases run. One axis per invocation:

```sh
conformance-primitives/run php/openssl --set encoding
conformance-primitives/run php/openssl --op open-aes-gcm
conformance-primitives/run php/openssl --case encoding/03
conformance-primitives/run php/openssl \
  --case encoding/03 \
  --case rsa-oaep/01
```

`--set` with `--op`, a repeated `--set`, a repeated `--op`, the same `--case` twice, an unknown name and a
selection matching nothing are all refused with exit 2 before a bridge starts. Combining axes would leave
the driver to decide whether to run the cases in both selections or the cases in either, and either answer
adds a behavior toggle; any grouping worth running is already spellable as a `--case` list. The same
`--case` twice is refused rather than deduped: when you are halving a list of cases to find the failing one,
the exact membership of each half is what you are controlling, and a copy-paste slip there is worth seeing.

When a batch comes back empty or unreadable, the exit-2 output prints the selected IDs, the reason and
whatever the bridge wrote on stderr. Copy the IDs, run half of them as repeated `--case` arguments, and repeat
on the failing half until one case is left. Every command starts a fresh bridge process, and a single case
travels as a batch of one, so nothing about the contract changes as the selection shrinks.

Every selected case is printed as its identifier, its operation and its label:

```text
    encoding/03 (decode-base64url) trailing bits set
```

The identifier is opaque, `<set>/<nn>`, because it travels to the bridge inside the request: an identifier
saying how its case comes out would ship the answer to the implementation under test. A probe that read its
own identifier and ignored the input once held every case whose name ended in `-refused`. The label carries
the readable text, lives in the corpus, and never crosses to a bridge.

## One corpus

The case corpus, `_shared/cases/v1/cases.json`, holds every question a run asks, each with its expectation
withheld from the bridge. This framework owns those expectations as written-out literals, and no expectation
is computed by one of the implementations under test, which would match that implementation by construction.
Selected inputs were copied from published DCA vectors; other cases have independent known-answer or
canonical encoding-rule provenance. The contract's closing section names each source. Runs read only this
literal corpus, never the vectors or the reference implementation.

A held lane reproduces the expected results for the covered stock calls and supplied parameters. Agreement
between lanes tests reproducibility; standards, specification rules and each case's provenance establish
its expected answer separately. Several runtimes share library ancestry, so a runtime count is not a count
of independent cryptographic stacks. The four JavaScript lanes share one `decode-base64url` answer, the decoder
in `_source/js/v1/answer.mjs`, so a held `encoding` set across them is one data point, not four. DCA
composition and a port's joins between calls require that implementation's own tests. The [verification overview](../README.md#what-the-evidence-establishes) explains
how these evidence boundaries fit together.

The cases are grouped into sets by the operations they ask for, and a lane declares in its own `bridge.json`
which operations its bridge answers. A set asking for one the lane has not declared is unsupported for that
lane: no bridge starts for it, the run says so, and nobody reads it as a hold. A lane answering four of the
seven operations therefore still holds the sets it can answer.

Where a value came from has no bearing on the check. If a value in the corpus is wrong, every lane is wrong
the same way, and that surfaces the first time someone reads the corpus against the document that fixes the
value, or the first time two implementations exchange real bytes. The fix then lands in the corpus and the
document, never in a lane.

## Where things live

Shared code lives under `_shared/`: the driver, the contract, the case corpus, the shell helpers and their
tests. Bridge source that several lanes run unchanged lives under [`_source/`](_source/README.md); it is no
lane, and each lane that runs it owns its own wrapper, `bridge.json` and `check`. Every lane sits at
`<runtime>/<binding>/`: the runtime binary and the set of libraries that answers the bridge calls are the two
things that can change a lane's answers, so both are levels even when a runtime has one binding. The top-level
entry points are `check` and `run`. `check` discovers a lane by an executable `check`; the driver discovers it
by `bridge.json`. Nothing lists a lane by name.

A bridge is written against [`_shared/contract/v1/bridge.md`](_shared/contract/v1/bridge.md). Each lane's
README says which platform owns its crypto binding, and its runtime's README says how the toolchain arrives:
[bun/boringssl](bun/boringssl/README.md), [deno/rustcrypto-awslc](deno/rustcrypto-awslc/README.md),
[dotnet/bcl](dotnet/bcl/README.md), [go/stdlib](go/stdlib/README.md),
[jvm/jca-jackson](jvm/jca-jackson/README.md), [node/openssl](node/openssl/README.md),
[php/openssl](php/openssl/README.md), [python/cryptography](python/cryptography/README.md),
[rust/rustcrypto](rust/rustcrypto/README.md), which uses a pinned RustCrypto crate stack and answers all seven
operations, and [workerd/boringssl](workerd/boringssl/README.md).

`bridge.json` names `script`, `command`, `members` and `operations`, and optionally `prepare: {command,
args?}`. `members` names each part of the binding that answers something, such as `openssl` for ext/openssl or
`lane` for code written in the lane; `operations` maps each operation the bridge answers to the member that
answers it ([contract](_shared/contract/v1/bridge.md#building-is-not-answering)).
Paths in it are written from the conformance directory, so a lane names its own directory first:
`php/openssl/bridge.json` names `php/openssl/v1/bridge.php` rather than a path relative to its own directory. `prepare` runs once before the batch, outside its time budget, and
is where a lane installs its toolchain or compiles its bridge.

A shell script that is run carries no extension; its shebang names the interpreter. A `.sh` file here is
sourced, never run.

The public gate, `js/check`, runs none of this. `conformance-primitives/run` runs the driver's own tests and the
shell fixtures before it starts a lane; a red self-check exits 2 and starts no bridge.

## What a lane check runs

Every lane check runs one step: the case corpus through that lane's own bridge, one run per set, so each row
carries its own measured status, once per selected runtime version. `_shared/driver/select-sets.mjs` names
the sets and says which of them the lane declares every operation for. The record a `--record` run writes
holds the lane, the version and the observed runtime, then one `operation=<operation> member=<member>` row per
declared operation, then one row per set; `_shared/aggregate-results` refolds the records of several (lane,
version) pairs, prints each pair's operation rows under it, and refuses a record that covers nothing. The
operation rows join no comparison and no exit code, and they attribute rather than claim independence: a `lane`
row may rest on a library call its binding README names. The aggregate refuses a malformed, unknown or
repeated operation row and trusts the rest: a record with fewer or no operation rows, or any well-formed
member name, passes, so the rows repeat the lane's own attribution and prove no provider
([contract](_shared/contract/v1/bridge.md#building-is-not-answering)).

## Adding a lane

One binding directory, `<runtime>/<binding>/`. The runtime directory keeps the installer and the `versions`
list; the installer takes `--version <token>`, puts the toolchain into a cache and answers print-only
queries without downloading.
In the binding directory: `bridge.json`, naming the binding's members and the member that answers each
operation; the bridge, written against `_shared/contract/v1/
bridge.md` using the runtime's own libraries or a pinned third-party stack named in the lane README for JSON
and crypto (strict base64url checks and JWK member handling remain lane code); a
`check` that runs the corpus through the driver once per selected version and observes the installed
runtime's version; a README saying which platform owns the crypto binding and repeating which member answers
each operation. A new lane needs no
registration step: `conformance-primitives/check` counts it in its tally and the driver lists it as soon as
the directory exists.

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
conformance-primitives/check                 # every lane, one tally
conformance-primitives/php/check             # one lane, everything it answers
conformance-primitives/run php               # one lane, the case corpus only, after the framework's own self-check
```

The framework needs a JavaScript runtime with WebCrypto and bash. Node is the default; `DCA_JS=deno` runs
the same files under Deno, and names a runtime, never a behavior. A lane whose language needs a toolchain
installs a pinned one into a cache the first time it runs and reads nothing off `PATH`; the node lane runs
under the runtime the framework already has.

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
conformance-primitives/run php --set encoding
conformance-primitives/run php --op open-aes-gcm
conformance-primitives/run php --case encoding/03
conformance-primitives/run php \
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
Most octets in the corpus were cut from published DCA vectors, so a bridge that holds here computes what a
DCA implementation on the same runtime will need; the contract's closing section says which value came from
where.

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
tests. Everything else at the top level is a lane, plus this file and the two entry points, `check` and
`run`. `check` finds a lane by walking the immediate child directories for an executable `check`; the driver
finds a lane by walking them for a `bridge.json`. Nothing anywhere lists a lane by name.

A bridge is written against [`_shared/contract/v1/bridge.md`](_shared/contract/v1/bridge.md). Each lane's
README says which platform owns its crypto binding and how its toolchain arrives:
[dotnet](dotnet/README.md), [go](go/README.md), [jvm](jvm/README.md), [node](node/README.md),
[php](php/README.md), [python](python/README.md).

`bridge.json` names `script`, `command` and an `operations` array, and optionally `prepare: {command,
args?}`. Paths in it are written from the conformance directory, so a lane names its own directory first:
`php/bridge.json` names `php/v1/bridge.php` rather than a path relative to its own directory. `prepare` runs once before the batch, outside its time budget, and
is where a lane installs its toolchain or compiles its bridge.

A shell script that is run carries no extension; its shebang names the interpreter. A `.sh` file here is
sourced, never run.

The public gate, `js/check`, runs none of this. `conformance-primitives/run` runs the driver's own tests and the
shell fixtures before it starts a lane; a red self-check exits 2 and starts no bridge.

## What a lane check runs

Every lane check runs one step: the case corpus through that lane's own bridge, one run per set, so each row
carries its own measured status. `_shared/driver/select-sets.mjs` names the sets and says which of them the
lane declares every operation for. The record a `--record` run writes holds one row per set;
`_shared/aggregate-results` refolds the records of several lanes and refuses a record that covers nothing.

## Adding a lane

One directory at the top level. In it: `bridge.json`; the bridge, written against `_shared/contract/v1/
bridge.md` using the runtime's own JSON parser and crypto library and nothing hand-written; an installer
that puts a pinned toolchain into the lane's cache and answers print-only queries without downloading; a
`check` that runs the corpus through the driver; a README saying which platform owns the crypto binding. A new lane needs no
registration step: `conformance-primitives/check` counts it in its tally and the driver lists it as soon as
the directory exists.

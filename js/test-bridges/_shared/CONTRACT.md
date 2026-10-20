# Portable test-bridge adapter contract

Status: Public Working Draft

A bridge lets unchanged Node tests call matching exports in a test target. The
Node test driver owns fixtures, expected values, assertions, routing and the
verdict. The target adapter returns observations or refusals. The bridge
connects the driver to the test target but does not include it.

## Vocabulary

| Name                        | Meaning                                                                                                                      |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **driver side**             | The Node process that selects tests and fixtures, withholds expectations, makes assertions and writes the transcript.        |
| **test target**             | The implementation being exercised: a literal language port, an independently designed implementation or a product.         |
| **bridge JS values**        | The closed set of driver-side values the bridge serializer accepts.                                                          |
| **bridge values**           | The typed JSON representations of bridge JS values.                                                                          |
| **bridge definition**       | The driver-side module that names a bridge and says how to start its target adapter.                                         |
| **target adapter**          | The target-side endpoint inside the bridge. It discovers, serializes, maps, dispatches and speaks the process protocol.       |
| **target mapping**          | The adapter-owned mapping from a reference export to a target entry.                                                         |
| **target entry**            | The native function, static method or other callable a target adapter maps a reference export to.                           |
| **native value serializer** | The runtime's recursive conversion between native values and bridge values, with focused helpers for nontrivial types.       |
| **process binding**         | The driver-side client that starts the target adapter and calls the entries it advertises.                                   |
| **bridge operation**        | An opaque, adapter-assigned identifier for one callable member. Generic bridge code never interprets it.                     |
| **bridge proxy**            | A generated JavaScript module that keeps the reference module's import surface and routes claimed exports to the binding.    |
| **reference fallback**      | The original JavaScript export, used in overlay mode for an unclaimed export or an input the bridge cannot carry.         |
| **bridge transcript**       | The append-only driver record of capabilities, exact requests and responses, infrastructure events and observed routes.      |
| **session**                 | One adapter process, started for one Node test process, from discovery until `dispose` or process exit.                      |
| **handle**                  | An opaque, adapter-issued name for one object of a claimed class, valid only in the session that issued it.                  |
| **handle proxy**            | The driver-side object a test holds for a handle. It exposes only the members the test target claims for its class.        |

Write `test target` in prose. A bare `target` could mean a suite, module,
callable or child process.

## Operation keys

Reference module paths and export names are the bridge's operation keys, for
example `core-shared/codec.js` and `base64urlDecode`. A test target maps
them; it need not mirror them in its own files, classes or names. The keys
change when the reference moves a module or renames an export.

Named selection manifests are the stable interface. A manifest names the
modules and exports its tests require, so a moved reference module fails that
selection instead of passing on the reference. An overlay run has no such
list: a moved module falls back to the reference, and only the transcript's
routes show it.

Only implementation modules cross. The driver never describes a test file, a
module under a `test-*` directory or a module under `demo/`; test fixtures
and expectation helpers always run on the driver side. A test that needs the
test target's own object gets it from a claimed export, such as a factory, or
from a [claimed constructor](#construct-an-object-of-a-claimed-class).

## Process

The driver starts one adapter process per Node test process. The adapter
remains alive until `dispose`.

Each stdin/stdout frame is:

```text
4-byte unsigned big-endian JSON byte length
UTF-8 JSON bytes
```

The maximum JSON body is 1 MiB. Stdout contains frames only. Diagnostics go to
stderr. The adapter must complete partial reads and writes. A malformed,
oversized or incomplete frame terminates the adapter with exit status 2.
When the adapter exits, the driver's failure names its exit code or signal and
the last 4 KiB of its stderr, so a refusal at startup reaches the run's output.

Every message has protocol `version: 1` and a non-empty opaque request `id`.
Every response repeats the request ID exactly.

A call times out after five seconds by default. After a timeout, an adapter
exit, or a response the driver cannot read (malformed, or over the maximum
body), the driver kills the adapter process, and every later call in that Node
process fails without dispatch.

## Startup inputs

An adapter receives trusted configuration when it starts. It never arrives in
a test request. The adapter inherits the driver's whole environment, except
`DCA_TARGET_ROOT`: the driver sets it to the bridge definition's `targetRoot`
and removes an inherited value when the definition names no target root. The
child starts in the definition's `adapterCwd`.

| Variable                    | Read by                  | Meaning                                                                                      |
| --------------------------- | ------------------------ | -------------------------------------------------------------------------------------------- |
| `DCA_BRIDGE`                | `preload.mjs`, `run.mjs` | A bridge ID, a `test-bridges/` directory with a `bridge.mjs` (`js`, `js-loopback`, `php`), or a path to a bridge module (`.mjs`). |
| `DCA_BRIDGE_MODE`           | bridge module, `run.mjs` | `overlay` (default) or `strict`; any other value is refused. Named selections force `strict`. |
| `DCA_BRIDGE_MODULES`        | bridge module, `run.mjs` | Optional comma-separated reference module paths: the [named module set](#modes) of a direct strict run. |
| `DCA_BRIDGE_EXCLUSIONS`     | `run.mjs`                | Optional path of a [named exclusion](#named-exclusions) list for a direct run of one test file. |
| `DCA_TEST_SELECTION`        | test files, bridge module | The named selection whose cases register and whose [input mappings](#input-mappings) apply. `run.mjs` sets it. |
| `DCA_LOG_DIR`               | bridge module, `run.mjs` | Caller-owned parent directory for dated run directories and transcript shards.               |
| `DCA_DEBUG`                 | bridge module, `run.mjs` | `1` writes concise lifecycle lines to stderr. Unset or `0` is quiet.                         |
| `DCA_TIMING`                | bridge module, `run.mjs` | `1` records per-call timing. Unset or `0` avoids timing work.                                |
| `DCA_TARGET_ROOT`             | bridge module, adapter   | The test-target root. `run.mjs` resolves a relative path against the caller's directory.     |
| `DCA_TARGET_NAMESPACE`        | PHP adapter              | Optional PHP namespace prefix for the one-prefix autoloader, used without `DCA_TARGET_AUTOLOAD`. |
| `DCA_TARGET_AUTOLOAD`         | PHP adapter              | Optional absolute path of a PHP autoload file the adapter requires before discovery.          |
| `DCA_PHP`                   | PHP bridge module        | The PHP executable. Defaults to `php`.                                                       |
| `DCA_PHP_MODULE_ATTRIBUTE`  | PHP adapter              | The class attribute naming the reference module. Defaults to `Dca\Porting\SourceModule`.      |
| `DCA_PHP_EXPORT_ATTRIBUTE`  | PHP adapter              | The attribute naming a renamed export. Defaults to `Dca\Porting\SourceExport`.                |
| `DCA_PHP_RETURN_TYPE_ATTRIBUTE` | PHP adapter          | The method attribute naming a return value type. Defaults to `Dca\Porting\ReturnType`.        |
| `DCA_PHP_BYTES_CLASS`       | PHP adapter              | Class for explicitly typed or `mixed` byte inputs and marked byte returns. Defaults to `Dca\Porting\Bytes`. |
| `DCA_PHP_UNDEFINED_CLASS`   | PHP adapter              | The class a port returns to send `undefined`. Defaults to `Dca\Porting\Undefined`.            |
| `DCA_NODE_TEST_ISOLATION`   | `run.mjs`                | Node's `--experimental-test-isolation` value for public or explicit-file runs. Named selections use `process`. |
| `DCA_NODE_TEST_CONCURRENCY` | `run.mjs`                | Node's `--test-concurrency` value for named selections. Defaults to `1`.                     |

`DCA_PORT_ROOT` and `DCA_PORT_NAMESPACE` are obsolete names. While either is
set, the driver and `run.mjs` refuse before any adapter starts and name the
replacement, for example `DCA_PORT_ROOT is obsolete; use DCA_TARGET_ROOT`.

An adapter must keep module and file resolution below its configured test-target
root.

## Requests

### Describe the adapter

```json
{ "version": 1, "id": "1", "type": "describe" }
```

```json
{
  "version": 1,
  "id": "1",
  "type": "response",
  "result": {
    "kind": "observation",
    "value": {
      "identity": {
        "bridge": "example",
        "adapterVersion": "1",
        "targetVersion": "example-1"
      },
      "capabilities": {
        "moduleDiscovery": true,
        "valueTypes": [
          "null",
          "boolean",
          "string",
          "number",
          "record",
          "list",
          "undefined",
          "Uint8Array",
          "Date",
          "CryptoKey"
        ]
      },
      "errorTypes": []
    }
  }
}
```

The value has exactly these members. `identity` is optional, and each of its
members is a string the transcript records. `capabilities` has only
`moduleDiscovery`, which is `true`, and `valueTypes`, the serializer's actual
inventory rather than an operation or domain profile. `errorTypes` is optional
and lists mapped native exception classes (see below). The driver refuses a
reply with any other member, including `errorTypes` placed inside
`capabilities`.

### Describe one imported module

The driver derives `sourceModule` from an actual import below the trusted
reference root. The path is relative, uses `/`, ends in `.js` or `.mjs`, and
contains no empty, `.` or `..` segment, query or fragment.

```json
{
  "version": 1,
  "id": "2",
  "type": "describeModule",
  "sourceModule": "example/math.js"
}
```

```json
{
  "version": 1,
  "id": "2",
  "type": "response",
  "result": {
    "kind": "observation",
    "value": {
      "members": [
        { "id": "op-1", "sourceExport": "twice", "callShape": "sync" },
        { "id": "op-2", "sourceExport": "later", "callShape": "async" },
        { "id": "op-3", "sourceExport": "VERSION", "callShape": "value" }
      ]
    }
  }
}
```

Member IDs are adapter-local and opaque. They must be unique and stable for
the adapter process. `sourceExport` is a JavaScript identifier. The driver
caches the result for that module.

A description may add `classes`: the classes of that module whose objects the
test target returns by [handle](#object-handles), each with the instance
members it claims.

```json
{
  "members": [{ "id": "op-1", "sourceExport": "openCounter", "callShape": "sync" }],
  "classes": [
    {
      "id": "class-1",
      "sourceExport": "Counter",
      "members": [{ "id": "op-2", "sourceMember": "add", "callShape": "sync" }]
    }
  ]
}
```

A class `id` is adapter-local and opaque, and unique in the adapter process.
`sourceExport` is the reference class export the class implements, and
`sourceMember` the reference method name. A class member's `id` is an
operation ID like any other, unique beside every member ID, and its
`callShape` is `sync` or `async`. A class the test target can construct from
bridge values adds `"construct": { "id": "new-1" }`, the operation ID of its
[constructor](#construct-an-object-of-a-claimed-class), unique beside every
member ID. The driver refuses a description with any other member in a class,
its `construct` or a class member. Only methods are members: a getter,
setter, field, constructor or static member of the class is not.
One `construct` ID may cover several native constructors; the adapter picks
the one matching each input, and the driver still sees one operation.

An adapter may resolve native overloads behind one member ID. A test target
whose language has several methods of one name, told apart by parameter types
or count, can claim them as one member, and the adapter picks the overload
that fits each call's arguments. The driver still sees one operation with one
`callShape`.

`sync` preserves an ordinary function's immediate return or throw through the
driver's synchronous worker binding. When a `sync` entry returns a promise,
the adapter awaits it and its response carries `"settled": "promise"` beside
`result`; the driver then returns a promise that settles the same way. `async` preserves an adapter-advertised
asynchronous function and awaits its observation or refusal in the adapter.
When the reference declares the export `async` and the test target describes
it `sync`, the driver keeps the reference's promise shape: the target's
answer resolves the promise the test receives and its refusal rejects it,
with the target's code and message. A bridge failure before or during
dispatch still throws at once, so it cannot pass for a target rejection.
`value` describes a serializable non-function export; the driver still reads
value exports from the reference module.

An adapter with no corresponding module returns an observation with an empty
`members` list. Invalid or unsafe paths return a refusal.

### Call a discovered function

```json
{
  "version": 1,
  "id": "3",
  "type": "call",
  "protocol": "dca-test-bridge/v1",
  "operation": "op-1",
  "input": [21]
}
```

```json
{
  "version": 1,
  "id": "3",
  "type": "response",
  "result": { "kind": "observation", "value": 42 }
}
```

An observation of a call may carry `declared`, which says where the test
target stated the JavaScript type itself:

```json
{
  "kind": "observation",
  "value": { "items": [], "key": "k" },
  "declared": [{ "at": [], "type": "record" }]
}
```

Each entry names one position by the record member names and list indexes
from the value's root, so `[]` is the value itself and `["items", 0]` the
first entry of its `items`, and gives its type: `record`, `list` or
`Uint8Array`. `"all"` in place of the list declares every position; the `js`
adapter sends it, because every value it returns is a JavaScript value with
one reading. [Reading answers by the reference
type](#reading-answers-by-the-reference-type) says what the driver does with
it. `"all"` also declares `null`, and the driver never reads a declared `null`
as `undefined`. An adapter that sends `"all"` therefore sends a void result
as the `undefined` tag, or it declares a list that leaves that position out.
`_shared/self-test/reference-shapes.test.js` holds the refusal: a `null`
declared `"all"` where the reference type admits `undefined` and not `null`.

`protocol` is always `dca-test-bridge/v1`. A call frame that carries a
`target` member, this member's former name, is refused.

A call carries `instances` when an [input mapping](#input-mappings) applies
to it:

```json
{
  "version": 1,
  "id": "3",
  "type": "call",
  "protocol": "dca-test-bridge/v1",
  "operation": "op-4",
  "input": [{ "width": 2, "height": 3 }],
  "instances": [{ "argument": 0, "sourceModule": "example/shape.js", "sourceExport": "Shape" }]
}
```

Each entry marks one argument, by its index in `input`, as the data of an
instance of the reference class that `sourceModule` and `sourceExport` name.
The list is non-empty and names each index once.

The adapter invokes only operation IDs from its frozen discovery result. A
call's `instances` may name a target class module and export for rebuilding an
argument, as described below; it does not select the callable to invoke.
Arguments are one encoded dense list.

An unknown operation returns:

```json
{ "version": 1, "id": "3", "type": "response", "result": { "kind": "unsupported" } }
```

A call whose test target returned, but whose answer the adapter cannot encode,
returns `uncarried` with a diagnostic. That covers a result that is not a
bridge value and a call that changed its arguments, a change the driver would
never see:

```json
{
  "version": 1,
  "id": "3",
  "type": "response",
  "result": { "kind": "uncarried", "message": "the call changed its arguments" }
}
```

A test target that throws answers with a refusal, never with `uncarried`.

### Call a member of a returned object

A call to a class member names the object by its handle in `receiver`:

```json
{
  "version": 1,
  "id": "6",
  "type": "call",
  "protocol": "dca-test-bridge/v1",
  "operation": "op-2",
  "input": [2],
  "receiver": { "$type": "Handle", "class": "class-1", "handle": "h-5f0c-1" }
}
```

`receiver` has the exact handle layout. The adapter runs the member on the
object the handle names in this session. It answers an adapter refusal, with
code `adapter_refusal` and no `errorType`, and invokes nothing, when the
handle names no live object in this session, when its `class` is not the
object's class, when the member belongs to another class, when a class member
comes without `receiver`, or when an export call comes with one. The answer is
read like any call's answer; a class member has no entry in the
[reference shapes](#reading-answers-by-the-reference-type), so the driver
converts nothing in it.

### Construct an object of a claimed class

A named strict selection may route `new X` to the test target. Its manifest
lists each class under `constructors`:

```json
"constructors": [{ "module": "example/counter.js", "class": "Counter" }]
```

Each entry has exactly `module`, a reference implementation module, and
`class`, a class export of that module; a class appears once, and never as the
class of an input mapping, which sends an instance of it as data. A selection
without `constructors` routes no constructor, so a test that constructs a
reference class runs the reference constructor, as before. A run with a
[module set](#modes) may only name classes of modules in the set. A direct
run opts classes in the same way through `registerBridge`'s `constructors`
option.

In the module that exports a listed class, the driver replaces the class
export with a stand-in function. `new X(...input)` sends an ordinary call
frame for the class's `construct.id` with `input` and no `receiver`, like
`binding.construct(module, class, input)`:

```json
{
  "version": 1,
  "id": "8",
  "type": "call",
  "protocol": "dca-test-bridge/v1",
  "operation": "new-1",
  "input": [5]
}
```

- **The test target builds the object.** The JS adapter runs `new` on its own
  class; the PHP adapter constructs the reflected class. A PHP class is
  constructible when it is instantiable, and its constructor is public with
  parameters discovery supports, or it has none. The adapter answers a new
  object, which crosses as a new handle. Later member calls name that handle
  and run on the same native object.
- **Handles go in as the object.** A handle proxy in the input reaches the
  constructor as the native object it names, so two target objects compose
  without a copy.
- **Refusals stay apart.** A constructor that throws a mapped error answers
  the test target's refusal with its `errorType`, code and message. A frame
  with a `receiver` gets an adapter refusal, `adapter_refusal` with no
  `errorType`, and builds nothing.
- **Fails closed.** A listed class whose module description declares no
  `construct` fails at `new` before dispatch, and the reference constructor
  never runs. After dispatch, an answer that is no handle of that class fails
  the call.
- **What the route does not promise.** The stand-in has no reference
  prototype or statics: the object is a
  [handle proxy](#object-handles), so `instanceof X` is false, and getters,
  fields and private state stay in the test target. Calling the stand-in
  without `new`, or constructing a subclass of it, throws. A test that needs
  any of these fails instead of running reference code.

Each listed constructor is a required operation of the selection: it counts
only when a process described the class with `construct` and called its
operation.

### Dispose

```json
{ "version": 1, "id": "4", "type": "dispose" }
```

```json
{ "version": 1, "id": "4", "type": "response", "result": { "kind": "observation", "value": null } }
```

The adapter releases process-local handles and exits after acknowledging the
request. The driver kills an adapter still running half a second later, and
kills it when the Node process exits without a dispose. Dispose ends the
session: the driver refuses every handle proxy of it from then on.

## Value serialization

The **bridge JS values** are the closed set of driver-side values accepted here:
JSON null, booleans, strings, finite numbers, dense arrays and plain objects,
plus the explicitly supported `undefined`, `Uint8Array`, `Date` and `CryptoKey`
values below. They compose recursively and are acyclic. **Bridge values** are
their typed JSON representations.

JSON itself defines no byte, date, undefined, error or cryptographic-key value
([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)). The tagged layouts below
are this bridge protocol's closed JSON profile, not DCA domain types. Unknown
tags and known tags with extra, missing or malformed members are refused.
WHATWG structured clone is an in-runtime algorithm rather than a JSON
representation; CBOR would be a different transport, not an alternate spelling
inside this protocol.

Node and JavaScript belong to the test driver, not to the bridge-value contract
or the test target. Tag names identify the driver value whose semantics must
survive the crossing; a target adapter materializes the corresponding native
value without copying JavaScript's class model or source layout.

The runtime-to-bridge-value meanings are:

| Bridge JS value           | Bridge value             | Receiving meaning                  |
| ------------------------- | ------------------------ | ---------------------------------- |
| `null`, boolean, string   | same JSON primitive      | same scalar                        |
| finite `number`           | JSON number              | same number in the portable range  |
| dense `Array`             | JSON array               | ordered dense list                 |
| plain object              | JSON object              | string-keyed record                |
| object containing `$type` | `Record` tag             | ordinary record, not a runtime tag |
| `undefined`               | `undefined` tag          | explicit undefined sentinel        |
| `Uint8Array`              | `Uint8Array` tag         | exact octet sequence               |
| valid `Date`              | `Date` tag               | exact UTC millisecond instant      |
| supported `CryptoKey`     | `CryptoKey` tag with JWK | key material plus runtime metadata |

JSON numbers preserve the common ECMAScript `Number` domain. Integer identity
is portable only through the safe-integer range. An adapter must not claim
that a larger native integer crosses unchanged merely because its JSON encoder
accepts it.

Reserved tagged layouts are exact:

```json
{ "$type": "undefined" }
```

```json
{ "$type": "Uint8Array", "base64url": "AAECAw" }
```

`base64url` is canonical unpadded base64url: only `A-Z`, `a-z`, `0-9`, `-`
and `_`, with no `=`. Invalid characters, padding, impossible lengths and
nonzero unused trailing bits are refused.

```json
{ "$type": "Date", "iso": "2026-09-22T12:34:56.000Z" }
```

`iso` is UTC `YYYY-MM-DDTHH:mm:ss.sssZ` with exactly three millisecond digits.
Offsets, variable precision and invalid dates are refused.

An ordinary record containing `$type` is escaped:

```json
{
  "$type": "Record",
  "value": { "$type": "caller-data", "answer": 42 }
}
```

A WebCrypto key uses its runtime metadata and JWK representation:

```json
{
  "$type": "CryptoKey",
  "keyType": "public",
  "algorithm": { "name": "ECDSA", "namedCurve": "P-256" },
  "extractable": true,
  "usages": ["verify"],
  "format": "jwk",
  "value": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "...",
    "key_ops": ["verify"],
    "ext": true
  }
}
```

The receiver imports native key material with the declared algorithm,
extractability and usages, then verifies the resulting metadata. JWK is the
standard JSON representation of key material
([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)); it does not preserve a
live handle's identity or physical non-exportability. `algorithm`, `keyType`,
`extractable`, `usages`, JWK `ext` and JWK `key_ops` must agree. Encoded JWK
octets use the same canonical unpadded base64url rule as other bridge bytes.

An unknown non-extractable key cannot be serialized. A bridge-created
non-extractable key may cross only when its serializer retained the trusted
source JWK. Advertising the `CryptoKey` value family does not claim every key
type or algorithm; unsupported metadata is refused before native invocation.

Callbacks, sparse arrays, `Array` subclasses, cycles, arbitrary instances and
object identity are not serializable. An input mapping sends the data of one
listed argument; it does not make the instance a bridge value. An object of a
class the test target claims crosses by [handle](#object-handles), which
carries its identity within one session and none of its data.

An adapter materializes each argument as the native type its parameter
declares. When it cannot, for example a JSON list where the parameter takes
bytes, the call fails. The adapter does not call the test target. It answers
an ordinary refusal with its own code, such as `adapter_refusal`, never a DCA
code and without `errorType`. Nothing falls back to the reference, in any
mode, so the case that made the call fails, and its selection with it.

## Object handles

When a call's answer holds an object of a class a module description
declared, the adapter sends a handle in its place, at any depth:

```json
{ "$type": "Handle", "class": "class-1", "handle": "h-5f0c-1" }
```

- **One object, one handle.** The adapter gives the same object the same
  handle every time, and a new object a new one. The handle includes a part
  random to the adapter process, so no other session's handle names one of
  its objects. The driver makes one handle proxy per handle and session, so
  an object that comes back again is the same proxy. Within that session, the
  adapter maps each opaque handle ID to a native object reference; different
  language adapters may use different table or reference mechanisms.
- **Handles go back as the object.** A handle proxy in a call's input, at any
  depth, crosses as its handle, and the adapter passes the object it names to
  the test target. A handle of another session, or of a disposed one, is
  refused: the driver refuses before dispatch, and the adapter refuses a
  handle it did not issue. Product code never receives a handle.
- **A record is not a handle.** A test's own record with the same members
  crosses escaped as a `Record` and reaches the test target as a record.
- **Only claimed members.** A handle proxy has no prototype and no state. Each
  claimed member is a function that calls the test target with the handle as
  `receiver`; nothing falls back to the reference, in any mode. Reading any
  other member throws, so a getter, a field or an unclaimed method fails
  instead of running reference code, and every write throws. A symbol read and
  a `then` read answer `undefined`. A handle proxy is no instance of the
  reference class.
- **Not a value type.** A handle is no entry in `valueTypes`; an adapter that
  never declares a class never sends one. Without a session, as in the
  bridge-values suite, the codec refuses a handle.

An object whose class the test target does not claim is still no bridge
value: the call answers `uncarried`. Getters, callbacks into the test and
object identity across sessions have no route. A test that constructs a
reference class still runs the reference constructor, unless its selection
[routes that constructor](#construct-an-object-of-a-claimed-class).

## Input mappings

Some reference exports take an instance of a reference class that wraps plain
data. A named selection may list such an argument in its manifest's `inputs`:

```json
{
  "module": "example/math.js",
  "export": "area",
  "argument": 0,
  "class": { "module": "example/shape.js", "export": "Shape" },
  "data": "toObject"
}
```

- The driver imports the class from the reference, the same class a test
  imports. For a call to `area`, argument 0 must be an instance of it. The
  driver calls its `toObject` method with no arguments, sends the result as
  argument 0 and marks it in the frame's `instances`. The result must be
  bridge JS values.
- Every other value keeps the path it had without the mapping. A plain
  record at a listed position crosses as a plain record, unmarked, so the
  test target answers it as it answers any record, refusal included. An
  instance of another class, or of the same class at a position no mapping
  lists, is still not a bridge value: overlay uses the reference and strict
  fails before dispatch.
- The `js` adapter rebuilds each marked argument as `new Shape(data)`,
  importing `Shape` from `example/shape.js` in the test target, and refuses
  the call when that module exports no such class. The `php` adapter
  rebuilds nothing: a port receives the data as the `stdClass` record any
  record arrives as.
- The adapter checks the data for changes as it checks any argument, so a
  call that changes the instance's data answers `uncarried`.

The mappings apply when `DCA_TEST_SELECTION` names the selection. `run.mjs`
sets it for a named selection. A direct run gets the same mappings by
setting `DCA_TEST_SELECTION` to the selection name, which also registers only
that selection's cases. A run without it, `public` included, maps no input.

A bridge may also be started with an `ignoredArguments` mapping for an argument
that the named reference export declares unused. Before checking whether a call
can cross or dispatching it, the driver copies the argument list and replaces
only that position with `undefined`. It applies the same projection to
synchronous and asynchronous carry checks and calls. The caller's array stays
unchanged. An argument cannot have both an input mapping and an ignored-
argument mapping. This is bridge configuration for source-declared unused
arguments; it does not change the reference export or permit other values to
cross.

## Reading answers by the reference type

Some native values have more than one JavaScript reading. A PHP `[]` is an
empty list or an empty record, a PHP string is text or bytes, and PHP has
`null` but no `undefined`. Either side may state the JavaScript type, or both:
the test target through `declared`, the reference through the JSDoc return
type of the export. `_shared/reference-shapes-write.mjs` reads those types
with the TypeScript checker and records the parts that matter in
`_shared/reference-shapes.json`: record or list, bytes or string, `null` or
`undefined`, per position. A self-test fails when the file differs from the
code.

The driver, not the adapter, reads each answer by that type. Where a position
is undeclared and exactly one reading fits, it converts:

- an empty list where the reference type is a record and not a list becomes
  `{}`;
- a string where the type is `Uint8Array` and not a string becomes the same
  UTF-8 bytes;
- `null` where the type admits `undefined` and not `null` becomes `undefined`.

Every other value passes unchanged. That covers a value a union admits, such
as `[]` where the type is a list or a record, a position the type leaves open
(`any`, `unknown`, a generic that returns its input, or an export without a
JSDoc return type), and a value that contradicts the type, on which the test
then fails. Where the type is a union of records told apart by a member with a
distinct literal in each, such as `kind`, the driver picks the branch by that
member of the answer and reads inside it; a union of records without one
passes unchanged. Nested positions are read the same way.

The `null` conversion is a portability convention, not a reading of what the
port meant. PHP has no `undefined`, so a port can write `return null` where the
reference returns `undefined` and never `null`. The same rule turns a mistaken
`null` at such a position into `undefined`, and a test that expects
`undefined` then passes. Where the type admits both `null` and `undefined`,
`null` stays `null`, and a port that means `undefined` returns the undefined
class, `Dca\Porting\Undefined` unless `DCA_PHP_UNDEFINED_CLASS` names
another, at the top level or inside a record or list.

A declared position is never converted. When the reference type at a declared
position does not admit the declared type, the driver refuses the answer, and
the call fails with, for example, `bridge refuses the result of example/math.js
twice: the test target declares list at items, where the reference type admits
record`. A declaration that does not match the value it names is a bridge
error. The driver refuses nothing else on account of a type.

## Refusals and mapped errors

An ordinary adapter refusal carries a stable code and optional diagnostic:

```json
{
  "version": 1,
  "id": "5",
  "type": "response",
  "result": {
    "kind": "refusal",
    "code": "adapter_refusal",
    "message": "native call refused"
  }
}
```

The driver throws an `Error` with that `message` and `code`.

A refusal may add `errorType`. The driver accepts exactly these forms:

- **A declared ID.** An ID from the `describe` reply's `errorTypes`. The
  supplied PHP adapter declares one for each exception class it discovers
  through the same source metadata as implementation exports:

  ```php
  #[\Dca\Porting\SourceModule('example/errors.js')]
  #[\Dca\Porting\SourceExport('ExampleError')]
  final class NativeExampleException extends \RuntimeException
  {
      public function errorCode(): string { return 'invalid_example'; }
  }
  ```

  ```json
  { "id": "error-1", "sourceModule": "example/errors.js", "sourceExport": "ExampleError" }
  ```

- **An implicit ID.** For every `Error` export of every module it proxies, the
  driver registers `error-` followed by the unpadded base64url of the UTF-8
  bytes `sourceModule`, a zero byte, and `sourceExport`. An adapter may name a
  reference error class this way without declaring it. The supplied
  `js` adapter does so.
- **`native:<Name>`**, where `<Name>` is one of `Error`, `TypeError`,
  `RangeError`, `ReferenceError`, `SyntaxError`, `EvalError`, `URIError` or
  `AggregateError`. The driver builds that JavaScript error with the message
  and restores `code`.
- **`native-dom:<Name>`**. The driver builds a `DOMException` with the message
  and that name.

This list is closed. Any other `errorType` is an unknown error type, and the
driver fails the call with a bridge error instead of a refusal. Portable selections assert no
runtime-specific error class or name, so a non-JavaScript test target needs
neither native form.

```json
{
  "version": 1,
  "id": "5",
  "type": "response",
  "result": {
    "kind": "refusal",
    "errorType": "error-1",
    "code": "invalid_example",
    "message": "the example is invalid"
  }
}
```

Before tests run, the driver resolves every declared error descriptor below
the trusted reference root and verifies that its export has an `Error`
prototype. For a declared or implicit ID it creates an error with that
prototype and restores `code`, `message` and the own `name` the class's
constructor sets, as `DcaError` does. It never runs a constructor to rebuild
an error: it reads that `name` once, when it registers the class, from one
instance built without arguments. Stack traces, `cause`, arbitrary exception properties
and the native class name do not cross.

## Discovery example

Reference module:

```js
export const VERSION = 1;
export function twice(value) {
  return value * 2;
}
```

PHP implementation:

```php
#[\Dca\Porting\SourceModule('example/math.js')]
final class ExampleMath
{
    public const VERSION = 1;

    public static function twice($value)
    {
        return $value * 2;
    }
}
```

PHP discovery scans below `DCA_TARGET_ROOT`, names each file's class from its
declared namespace and base name, loads it through the test target's
autoloader, and reflects attributed classes. A same-named
public static method maps to a function export. A same-named public class
constant maps to the value export of the same name. A method whose export
name differs carries the export attribute (`Dca\Porting\SourceExport` by
default); a constant always maps by its own name. Duplicate module/export
pairs are refused.

JavaScript discovery resolves the requested module below its configured
test-target root, imports it once, reflects its exports and caches the
result. It does not use a handwritten module or operation map.

## Modes

- **`overlay`** is the default. A claimed function export crosses to the test
  target. An unclaimed export, or a call whose values the adapter's
  `valueTypes` cannot carry, uses the reference before dispatch. Such a call
  runs entirely on the reference: the implementation modules it imports load
  as reference fallbacks too, so its own internal calls never cross. A
  run with no external call proves nothing about the test target; its
  transcript says `vacuous`.
- **`strict`** never falls back for a claimed export. A claimed call whose
  input the adapter cannot carry fails before dispatch. A run with no external
  call fails. A call to a function export the test target does not claim
  fails with `strict bridge run: <module>#<export> is not claimed by the test
  target`; the driver lists the reference module's exports from its loaded
  namespace. A class export stays the reference class: a test's `instanceof`
  checks, the mapped errors and the input mappings need its prototype.
  Constructing one runs reference code. An object the test target returns
  crosses as a handle proxy, not as an instance of that class. Value exports stay the
  reference's too. A strict run therefore still needs and evaluates
  every reference module the test imports, for its export names, its classes
  and its value exports, but runs no reference function
  (`_shared/self-test/reference-absent.test.js`).

A strict run may name a **module set** in `DCA_BRIDGE_MODULES`, such as
`core-shared--publisher-issuer/periodKeys.js,core-shared/periodKeyProfiles.js`, for a test
target that ports only part of what a test file imports. Only the listed
modules route, under the strict rules above: a call the test target does not
claim or an input it cannot carry fails, and nothing falls back. Every other
implementation module loads as its reference fallback instance, as a module
with nothing to claim does, so the test's calls to it and its internal calls
never cross. The driver refuses a set in overlay mode, a path that names no
reference module, and, in `run.mjs`, a set given with a named selection,
whose manifest already names what it requires.

In every mode, a test target that throws fails closed: the refusal reaches the
test, and nothing retries through the reference. An `uncarried` answer fails
the call in both modes with `bridge cannot carry the result of <module>
<export>`. The test target already ran that call, so a rerun on the reference
would repeat its effects, such as a changed argument, and the test would pass
on the reference's answer.

## Named exclusions

A direct run of one test file may skip cases by exact name, for example a case
that stops at a value no bridge value carries. `DCA_BRIDGE_EXCLUSIONS` names
a JSON list:

```json
{
  "version": 1,
  "exclusions": [
    {
      "file": "test-reference/example/cases.test.js",
      "name": "a sparse list keeps its holes",
      "reason": "array hole gap"
    }
  ]
}
```

Each entry names a test file under `js`, the exact name of one of its cases
and why the run skips it; a file and name pair appears once. `run.mjs` applies
the entries for the file it runs and ignores the rest, so one list can serve a
test target's runs of several files. Before the run, `list-cases.mjs` lists
the cases the file registers, and each applied entry must name exactly one of
them, so a renamed or duplicated case cannot hide behind an exclusion. The
runner skips each case with an anchored `--test-skip-pattern` of its escaped
name, and its report names every skipped case with its reason. `run.json` records the entries it applied. A
portable selection or the public run refuses the list: a selection's cases are
registered in the test file itself.

## Evidence

Expected values, assertions and verdicts never cross the process boundary.
This separation stops an adapter from reading the expected answer; it does
not independently establish that a reference assertion is correct. A passing
selection establishes only its exercised behavior under the documented bridge
conversions, not full equivalence or a protocol conformance claim.
With `DCA_LOG_DIR` set, each Node test process writes one transcript shard.
The adapter never writes it. A shard holds:

- `capabilities`: the `describe` reply and `entry`, the test file of that
  process when Node's process isolation started it;
- `module`: each module description, with `classes` when it declares any;
- `call`: each exact operation, encoded input, `instances` when an input
  mapping marked an argument, `receiver` for a class member, and response;
- `route`: each reference fallback with its encoded input, or
  `{ "uncarried": reason }` when the input is what the bridge cannot carry;
- `uncarried`: each call the test target answered `uncarried`, with its encoded
  input and the response. The call was dispatched and then failed; it is not
  an external call, an observation or a fallback;
- `infrastructure`: a timeout or a failed dispose;
- `final`: `lifecycle: "disposed"`, the mode, `entry`, with a module set
  `modules` and `unroutedModules`, the implementation modules the process
  loaded on the reference instead, then `routes`, `externalCalls`,
  `referenceFallbacks`, `uncarriedResults` (the count of `uncarried`
  records), and `evidence: "vacuous"` for an overlay run with no external
  call.

`routes` maps each operation that was called or fell back to its external
and reference counts, plus an `uncarried` count once the test target answers
`uncarried` for it; discovery alone adds nothing. The transcript is not a
verdict. The verdict is Node's exit status, which `run.mjs` records as
`exitStatus` in `run.json`.

A named selection passes only when every registered case passes, every selected test file
makes at least one external call, every required export and required class
member is called, no call falls back, no call answers `uncarried`, and the
registered case count matches the manifest. A manifest requires a class member
as `{ "module": "<module>", "class": "<class export>", "members": ["<member>"] }`;
it counts only when a process described that member under that class and
called its operation. Each class the manifest lists under `constructors` is
required as well; `run.mjs` reports
`required constructors <called>/<total> called`. A case that expects a throw could otherwise pass on the
bridge-limitation error. Passing
proves only the selected tests and the calls the transcript records as
external. The calls a test target makes inside itself, such as a factory
constructing the object it returns, do not cross and are not recorded. Transcripts contain test inputs, including test keys; do not run
the bridge with production credentials.

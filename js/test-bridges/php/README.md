# PHP target adapter

This adapter lets unchanged Node tests invoke a PHP test target through the
generic [test-bridge contract](../_shared/CONTRACT.md). Bridge values stay language-neutral;
this guide defines its PHP materialization and reflection conventions.

## Start coordinates

`DCA_TARGET_ROOT` names the root of the PHP test target, the directory that
holds the mapped classes. The settings on this page are trusted process
configuration, never test request data.

The adapter recursively scans PHP files below that root and reads each file's
declared namespace. The class a file declares is that namespace plus the
file's base name, so `Engine.php` declaring `namespace Acme\Issuer;` holds
`Acme\Issuer\Engine`. A class declares the reference module it implements
with a single-line marker:

```php
#[\Dca\Porting\SourceModule('core-shared/geometryBounds.js')]
final class Geometry
{
}
```

The module path names a file in the JavaScript reference, the `js/` tree
that holds this adapter. A path that names no file there, such as
`core-shared/geometryBound.js`, stops discovery, so a typo cannot leave the
test running on the reference.

A public static method maps to the export of its own name. A renamed method
uses `Dca\Porting\SourceExport`. Discovery assigns opaque operation IDs; no
module, class or method name enters a call request.

Keep every marker on one line when the test target supports PHP 7.3. PHP 7.3 reads the
line as a comment, and production code does not depend on an attribute class.

## Loading the test target

Discovery asks PHP for each class, and an autoloader loads it. There are two
ways to provide one:

- `DCA_TARGET_AUTOLOAD` names a PHP file, such as the port's
  `/path/to/port/vendor/autoload.php`, as an absolute path. The adapter
  requires it before discovery. Discovery then admits a class by its module
  attribute, whatever its namespace, and the port's autoloader also loads the
  helpers and packages the mapped classes call. A missing or unreadable file,
  or a relative path, stops the adapter at startup, and the message names the
  variable.
- Without an autoload file, the adapter registers a one-prefix autoloader:
  `DCA_TARGET_NAMESPACE`, such as `Acme\Issuer`, maps to `DCA_TARGET_ROOT`
  as in PSR-4. When the variable is unset, the adapter takes the prefix from
  the first file below the root that declares a namespace. A file declaring a
  namespace under the prefix must sit at its PSR-4 path. A class outside the
  prefix does not load, so a mapped class that calls a helper in another
  namespace needs the autoload file.

With an autoload file set, the adapter ignores `DCA_TARGET_NAMESPACE`, so
exactly one autoloader serves the test target. Discovery requires no target
file itself, so a class is never loaded twice.

```sh
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/port/src \
  DCA_TARGET_AUTOLOAD=/path/to/port/vendor/autoload.php \
  pnpm test:bridge portable-core
```

## Attribute names

The adapter reads three attributes. Their names are settings, so a port that
already records provenance, such as
`#[Acme\PortedFrom('core-issuer/IssuerEngine.js')]`, names its own attribute
and needs no second one.

| Variable                        | Default                    | Read from                   | First string argument                                            |
| ------------------------------- | -------------------------- | --------------------------- | ---------------------------------------------------------------- |
| `DCA_PHP_MODULE_ATTRIBUTE`      | `Dca\Porting\SourceModule` | a class                     | the reference module path, such as `core-issuer/IssuerEngine.js` |
| `DCA_PHP_EXPORT_ATTRIBUTE`      | `Dca\Porting\SourceExport` | a method or exception class | the reference export name, when it differs from the method name  |
| `DCA_PHP_RETURN_TYPE_ATTRIBUTE` | `Dca\Porting\ReturnType`   | a method                    | the bridge value type of the return, such as `Uint8Array`        |

The adapter also accepts the argument by name: `path` for the module
attribute, `name` for the other two.

`bridge.mjs` passes the settings to the adapter unchanged. The adapter drops
one leading `\`, so `\Acme\PortedFrom` and `Acme\PortedFrom` name the same
class. PHP reflection returns resolved names, so an imported short form counts:

```php
use Acme\PortedFrom;

#[PortedFrom('core-shared/geometryBounds.js')]
final class Geometry
{
}
```

```sh
DCA_BRIDGE=php DCA_TARGET_ROOT=/path/to/src \
  DCA_PHP_MODULE_ATTRIBUTE='Acme\PortedFrom' pnpm test:bridge portable-core
```

A configured name replaces the default. At startup the adapter refuses a
value with an empty segment or a segment that is not a PHP identifier, such as
`Acme\\PortedFrom` or `Acme\Ported-From`, and names the variable.

`src/Porting/` declares the three default classes, so IDEs and PHPStan
resolve them. Discovery reads attributes without instantiating them, so the
adapter never loads these classes. An implementer who configures other names
declares those classes. `src/Porting/Bytes.php` beside them is the byte value
class, which the adapter does load ([Value mappings](#value-mappings)).

## What an issuer port crosses

An issuer port uses two levels. This bridge carries its free functions and
static methods, such as `checkVersion`, `publisherFor` and `checkEnvelopes`
from `core-issuer/IssuerEngine.js`. The `issuer-core` and `issuer-endpoint`
contracts in [`js/test-contract/`](../../test-contract/README.md) cover the
engine classes. The bridge carries no callbacks, and carries an object only as
a handle to an object the port created
([CONTRACT.md](../_shared/CONTRACT.md#object-handles)), so `IssuerEngine`,
which takes a JavaScript `accessPolicy`, cannot cross it.

## Objects a port returns

A class with a module marker, other than an exception class, is a claimed
class. An object of it that a port returns crosses as a handle, and the test
holds a proxy whose members call the port's object. Each public instance
method the class itself declares is a member of its own name; the export
attribute renames it. The class takes the reference class export its export
attribute names, or its own short name:

```php
#[\Dca\Porting\SourceModule('example/counter.js')]
#[\Dca\Porting\SourceExport('Counter')]
final class NativeCounter
{
    #[\Dca\Porting\SourceExport('openCounter')]
    public static function open($start) { return new self($start); }

    public function add($step) { /* ... */ }
}
```

Static methods stay exports, as above. Constructors, inherited and magic
methods, properties and methods whose signature the adapter cannot fill are
not members. A handle argument, at any depth, reaches the port as its own
object, and an object of a class with no module marker still answers
`uncarried`.

## Value mappings

A port needs no declaration where the reference's type decides. The driver
reads a PHP `[]`, a string and `null` by the JSDoc return type of the
reference export ([CONTRACT.md](../_shared/CONTRACT.md#reading-answers-by-the-reference-type)):
`[]` where the reference returns a record becomes `{}`, a string where it
returns `Uint8Array` becomes the same bytes, and `null` where it returns
`undefined` and never `null` becomes `undefined`. A port states the type
itself only where the reference's type leaves more than one reading, such as a
union a test asserts one member of. It does so in one of two ways: by the PHP
type it returns, or by a `ReturnType` attribute on the method.

| Bridge JS value           | Bridge value            | PHP implementation receives | PHP implementation returns                                   |
| ------------------------- | ----------------------- | --------------------------- | ------------------------------------------------------------ |
| `null`, boolean, string   | same JSON primitive     | `null`, `bool`, `string`    | the same; a string that is not UTF-8 goes out as bytes       |
| finite `number`           | JSON number             | `int` or `float`            | `int` or `float`                                             |
| dense `Array`             | JSON array              | list array                  | list array; the reference type reads `[]`                    |
| plain object              | JSON object             | `stdClass`                  | `stdClass`, or an associative array with string keys         |
| object containing `$type` | `Record` tag            | `stdClass` with `$type`     | the same                                                     |
| `undefined`               | `undefined` tag         | `UndefinedValue`            | `Dca\Porting\Undefined`, or `null` the reference type reads  |
| `Uint8Array`              | canonical base64url tag | binary `string`             | `Dca\Porting\Bytes`, a string the attribute marks, or a string the reference type reads |
| valid `Date`              | canonical UTC tag       | UTC `DateTimeImmutable`     | any `DateTimeInterface`                                      |

These hold at any depth. The adapter decodes bytes to a PHP binary string before
calling the target. A parameter explicitly declared `mixed` receives a byte
object instead, because it can also receive text and PHP cannot distinguish
ASCII bytes from text in a string. A parameter declared as the class named by
`DCA_PHP_BYTES_CLASS` receives that class. The default is `Dca\Porting\Bytes`.
A port can return `new \Dca\Porting\Bytes($raw)` to mark bytes. A custom bytes
class must take one string argument and implement `__toString`; an invalid
class setting stops the adapter at startup.

A port returns `new \Dca\Porting\Undefined()` for `undefined`. It needs
the marker only where the reference type admits both `null` and `undefined`;
where the type admits `undefined` and not `null`, a plain `null` reads as
`undefined`, and a mistaken `null` there reads the same way.
`DCA_PHP_UNDEFINED_CLASS` names another class to use instead; a malformed
name, or a class that does not load, stops the adapter at startup.

Where the reference's type leaves a choice, a method that returns plain PHP
values marks what the PHP type cannot say:

```php
#[\Dca\Porting\ReturnType('Uint8Array')]
public static function decode($value)
{
    return $nativeByteString;
}

#[\Dca\Porting\ReturnType(['key' => 'Uint8Array', 'parts' => ['Uint8Array'], 'meta' => 'record', 'inner' => ['blob' => 'Uint8Array']])]
public static function unpack($value)
{
    return ['key' => $raw, 'parts' => [$a, $b], 'meta' => [], 'inner' => ['blob' => $c]];
}
```

A marker is `'Uint8Array'` for a byte string, `'record'` or `'list'` for an
array, a list of one marker for a list whose every entry has it, or member
names mapped to markers for a record, nested to any depth. Unmarked members
follow the table. `null` and the undefined class pass wherever a marker
stands. A value that does not fit its marker is refused. A marker in any other
form stops discovery.

The adapter tells the driver which positions the port declared: a `stdClass`
or an associative array is a record, a list array with entries is a list, a
bytes object is `Uint8Array`, and so is every position a `ReturnType` marker
names. `[]`, a plain string and `null` stay undeclared, and so does a string
that is not UTF-8, which cannot be JSON text and goes out as bytes. The driver
never converts a declared position. Where the reference's type does not admit
what the port declared, such as `ReturnType('list')` on a method whose
reference export returns a record, the driver refuses the answer.

The adapter refuses what it would have to guess:

- An associative array with an integer key, such as `[0 => 'a', 2 => 'b']`,
  answers `uncarried`; return a `stdClass` for a record with numeric member
  names.
- Any other object answers `uncarried`.

`ReturnType` names a generic value type from the bridge contract. It neither
names a DCA operation nor changes the production method's PHP value.

The adapter does not list `CryptoKey` in `valueTypes`. Every PHP member is
`sync`, and the driver's synchronous call cannot serialize a key, so a key
never reaches a PHP entry through the bridge proxy; the adapter cannot return
one either. In overlay a call that carries a key uses the reference; in strict
it fails before dispatch. A frame that does carry a public ECDSA P-256 `verify`
JWK still becomes an OpenSSL key in `CryptoKeyValue`.

The PHP bridge configures one source-declared unused argument:
`wholeRenderIssuerSupplyPlan`'s issuer argument. The reference export names it
`_issuer`, and the PHP implementation does not read `$issuer`; the bridge
projects that position to `undefined` before its carry check and call. This
does not make `CryptoKey` a PHP bridge value or authorize projecting any other
argument.

## Mapped exceptions

A PHP exception maps to a JavaScript error export through the module and
export attributes. It must expose a stable application error code.
The adapter reads a string code from `errorCode()` first, then `getCode()`;
non-string values do not supply an application error code.
The bridge carries only the opaque discovered error type, code and message. It
does not carry the PHP class name, stack, cause or arbitrary properties.

The driver resolves the declared JavaScript error below its trusted reference
root and restores that prototype without invoking its constructor.

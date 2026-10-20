import nodeTest from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { ProcessBinding } from "../../_shared/register.mjs";

// A public checkout may have no PHP. These self-tests then report as skipped
// with the reason, so `pnpm test` still runs every JavaScript test.
const phpMissing = spawnSync("php", ["-v"], { stdio: "ignore" }).error !== undefined;
/** @param {string} name @param {() => unknown} body */
const test = (name, body) =>
  phpMissing ? nodeTest(name, { skip: "php not on PATH" }, body) : nodeTest(name, body);

const root = fileURLToPath(new URL("../../../", import.meta.url));
const geometryTest = join(root, "test-reference/core-shared/geometry-bounds.test.js");
const preload = join(root, "test-bridges/php/bridge.mjs");
const targetMap = join(root, "test-bridges/php/src/TestBridge/TargetMap.php");
const adapter = join(root, "test-bridges/php/adapter.php");

/** Variables the PHP adapter reads, cleared so a caller's shell cannot steer a self-test. */
const ADAPTER_VARIABLES = [
  "DCA_TARGET_NAMESPACE",
  "DCA_TARGET_AUTOLOAD",
  "DCA_PHP_MODULE_ATTRIBUTE",
  "DCA_PHP_EXPORT_ATTRIBUTE",
  "DCA_PHP_RETURN_TYPE_ATTRIBUTE",
  "DCA_PHP_BYTES_CLASS",
  "DCA_PHP_UNDEFINED_CLASS",
];

/** @param {Record<string, string>} [settings] */
function adapterEnvironment(settings = {}) {
  /** @type {Record<string, string | undefined>} */
  const environment = { ...process.env };
  for (const name of ADAPTER_VARIABLES) delete environment[name];
  return { ...environment, ...settings };
}

/** @param {string} root @param {Record<string, string>} files */
function writeTree(root, files) {
  for (const [path, source] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), source);
  }
}

/**
 * Builds a TargetMap over `files` in a temporary test-target root and runs
 * `php` with it as `$map`. Module paths resolve against `referenceRoot`, or
 * against a temporary JavaScript reference holding an empty file for each
 * `reference` path. The root is `src/` in a temporary port directory that
 * also holds `port` files; `autoload` names one of them as DCA_TARGET_AUTOLOAD.
 *
 * @param {Record<string, string>} files
 * @param {string} php
 * @param {{ namespace?: string | null, reference?: string[], referenceRoot?: string, settings?: Record<string, string>, argument?: string, port?: Record<string, string>, autoload?: string }} [options]
 */
function runTargetMap(files, php, options = {}) {
  const { namespace = "Fixture", reference = [], settings = {}, argument = "" } = options;
  const port = mkdtempSync(join(tmpdir(), "dca-php-port-"));
  const targetRoot = join(port, "src");
  const referenceRoot = options.referenceRoot ?? mkdtempSync(join(tmpdir(), "dca-php-reference-"));
  try {
    mkdirSync(targetRoot);
    writeTree(targetRoot, files);
    writeTree(port, options.port ?? {});
    if (options.referenceRoot === undefined)
      writeTree(referenceRoot, Object.fromEntries(reference.map((path) => [path, ""])));
    return execFileSync(
      "php",
      [
        "-r",
        `require ${JSON.stringify(targetMap)}; $map = Dca\\TestBridge\\TargetMap::fromEnvironment($argv[1]); ${php}`,
        "--",
        referenceRoot,
        argument,
      ],
      {
        env: adapterEnvironment({
          DCA_TARGET_ROOT: targetRoot,
          ...(namespace === null ? {} : { DCA_TARGET_NAMESPACE: namespace }),
          ...(options.autoload === undefined
            ? {}
            : { DCA_TARGET_AUTOLOAD: join(port, options.autoload) }),
          ...settings,
        }),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
  } finally {
    rmSync(port, { recursive: true, force: true });
    if (options.referenceRoot === undefined)
      rmSync(referenceRoot, { recursive: true, force: true });
  }
}

/**
 * @param {Record<string, string>} files
 * @param {string} sourceModule
 * @param {Parameters<typeof runTargetMap>[2]} [options]
 */
function discover(files, sourceModule, options = {}) {
  return runTargetMap(
    files,
    "echo json_encode($map->describeModule($argv[2]), JSON_THROW_ON_ERROR);",
    { reference: [sourceModule], ...options, argument: sourceModule },
  );
}

/** @param {Record<string, string>} files @param {Parameters<typeof runTargetMap>[2]} [options] */
function discoverErrors(files, options = {}) {
  return runTargetMap(files, "echo json_encode($map->errorTypes(), JSON_THROW_ON_ERROR);", options);
}

/**
 * Copies the adapter into `<root>/test-bridges/php/`, the place it has in the
 * JavaScript reference, so `root` serves as that reference for fixture modules.
 */
function adapterInReference() {
  const referenceRoot = mkdtempSync(join(tmpdir(), "dca-php-reference-"));
  const copy = join(referenceRoot, "test-bridges/php");
  mkdirSync(copy, { recursive: true });
  cpSync(adapter, join(copy, "adapter.php"));
  cpSync(join(root, "test-bridges/php/src"), join(copy, "src"), { recursive: true });
  return { referenceRoot, adapter: join(copy, "adapter.php") };
}

test("generic discovery honors source markers and method export names", () => {
  assert.deepEqual(
    JSON.parse(
      discover(
        {
          "Alpha.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Alpha { #[\\Dca\\Porting\\SourceExport("renamed")] public static function original($value) { return $value; } }
`,
          "Beta.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("beta.js")]
class Beta { public static function plain($value) { return $value; } }
`,
        },
        "alpha.js",
        { reference: ["alpha.js", "beta.js"] },
      ),
    ),
    [{ id: "op-1", sourceExport: "renamed", callShape: "sync" }],
  );
  assert.deepEqual(
    JSON.parse(
      discover({ "Ignored.php": "<?php namespace Fixture; class Ignored {}\n" }, "ignored.js"),
    ),
    [],
  );
});

test("generic discovery infers a namespace from a test-target root when configuration omits it", () => {
  assert.deepEqual(
    JSON.parse(
      discover(
        {
          "Alpha.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Alpha { public static function plain($value) { return $value; } }
`,
        },
        "alpha.js",
        { namespace: null },
      ),
    ),
    [{ id: "op-1", sourceExport: "plain", callShape: "sync" }],
  );
});

test("generic discovery keeps equal exports in separate modules and omits unsupported signatures", () => {
  assert.deepEqual(
    JSON.parse(
      discover(
        {
          "First.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("first.js")]
class First { public static function same($value) { return $value; } }
`,
          "Second.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("second.js")]
class Second { public static function same($value) { return $value; } }
`,
        },
        "first.js",
        { reference: ["first.js", "second.js"] },
      ),
    ),
    [{ id: "op-1", sourceExport: "same", callShape: "sync" }],
  );
  assert.throws(
    () =>
      discover(
        {
          "First.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("first.js")]
class First { public static function same($value) { return $value; } }
`,
          "Second.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("first.js")]
class Second { public static function same($value) { return $value; } }
`,
        },
        "first.js",
      ),
    /duplicate module export/,
  );
  assert.deepEqual(
    JSON.parse(
      discover(
        {
          "ByReference.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("reference.js")]
class ByReference { public static function unusable(&$value) { return $value; } }
`,
        },
        "reference.js",
      ),
    ),
    [],
  );
});

test("generic discovery rejects unsafe module metadata", () => {
  assert.throws(
    () =>
      discover(
        {
          "Unsafe.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("../unsafe.js")]
class Unsafe { public static function call($value) { return $value; } }
`,
        },
        "unsafe.js",
      ),
    /safe relative JavaScript path/,
  );
});

test("discovery reads the Dca\\Porting attribute names by default and not the old Porting names", () => {
  const files = {
    "Current.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Current { public static function current($value) { return $value; } }
`,
    "Old.php": `<?php
namespace Fixture;
#[\\Porting\\SourceModule("alpha.js")]
class Old { public static function old($value) { return $value; } }
`,
  };
  assert.deepEqual(JSON.parse(discover(files, "alpha.js")), [
    { id: "op-1", sourceExport: "current", callShape: "sync" },
  ]);
});

test("the shipped Porting classes carry the arguments discovery reads", () => {
  const porting = join(root, "test-bridges/php/src/Porting");
  const files = {
    "Alpha.php": `<?php
namespace Fixture;
use Dca\\Porting\\ReturnType;
use Dca\\Porting\\SourceExport;
use Dca\\Porting\\SourceModule;
#[SourceModule(path: "alpha.js")]
class Alpha {
  #[SourceExport(name: "renamed")]
  #[ReturnType(name: "Uint8Array")]
  public static function original($value) { return $value; }
}
`,
    "Failure.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
#[\\Dca\\Porting\\SourceExport("AlphaFailure")]
class Failure extends \\RuntimeException {}
`,
  };
  const observed = runTargetMap(
    files,
    `foreach (['SourceModule', 'SourceExport', 'ReturnType'] as $name) require $argv[2] . "/$name.php";
$class = new ReflectionClass('Fixture\\\\Alpha');
$method = $class->getMethod('original');
$failure = new ReflectionClass('Fixture\\\\Failure');
echo json_encode([
  $class->getAttributes()[0]->newInstance()->path,
  $method->getAttributes(Dca\\Porting\\SourceExport::class)[0]->newInstance()->name,
  $method->getAttributes(Dca\\Porting\\ReturnType::class)[0]->newInstance()->name,
  $failure->getAttributes(Dca\\Porting\\SourceExport::class)[0]->newInstance()->name,
  $map->describeModule('alpha.js'),
], JSON_THROW_ON_ERROR);`,
    { reference: ["alpha.js"], argument: porting },
  );
  assert.deepEqual(JSON.parse(observed), [
    "alpha.js",
    "renamed",
    "Uint8Array",
    "AlphaFailure",
    [{ id: "op-1", sourceExport: "renamed", callShape: "sync" }],
  ]);
});

test("a configured module attribute counts in its imported short form and replaces the default", () => {
  const files = {
    "Ported.php": `<?php
namespace Fixture;
use Acme\\PortedFrom;
#[PortedFrom("alpha.js")]
class Ported { public static function ported($value) { return $value; } }
`,
    "Standard.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Standard { public static function unclaimed($value) { return $value; } }
`,
  };
  const expected = [{ id: "op-1", sourceExport: "ported", callShape: "sync" }];
  for (const setting of ["Acme\\PortedFrom", "\\Acme\\PortedFrom"])
    assert.deepEqual(
      JSON.parse(discover(files, "alpha.js", { settings: { DCA_PHP_MODULE_ATTRIBUTE: setting } })),
      expected,
      setting,
    );
});

test("a configured export attribute renames a method; other methods keep their own names", () => {
  const files = {
    "Alpha.php": `<?php
namespace Fixture;
use Acme\\ExportedAs;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Alpha {
  #[ExportedAs("renamed")] public static function original($value) { return $value; }
  #[\\Dca\\Porting\\SourceExport("ignored")] public static function own($value) { return $value; }
}
`,
  };
  assert.deepEqual(
    JSON.parse(
      discover(files, "alpha.js", { settings: { DCA_PHP_EXPORT_ATTRIBUTE: "Acme\\ExportedAs" } }),
    ),
    [
      { id: "op-1", sourceExport: "own", callShape: "sync" },
      { id: "op-2", sourceExport: "renamed", callShape: "sync" },
    ],
  );
});

test("a configured return-type attribute is the one discovery reads", () => {
  const files = {
    "Alpha.php": `<?php
namespace Fixture;
use Acme\\Returns;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Alpha { #[Returns("NotAType")] public static function bytes($value) { return $value; } }
`,
  };
  assert.deepEqual(JSON.parse(discover(files, "alpha.js")), [
    { id: "op-1", sourceExport: "bytes", callShape: "sync" },
  ]);
  assert.throws(
    () =>
      discover(files, "alpha.js", { settings: { DCA_PHP_RETURN_TYPE_ATTRIBUTE: "Acme\\Returns" } }),
    /supported JavaScript runtime type/,
  );
});

test("a malformed attribute setting refuses at adapter startup and names the variable", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  try {
    const cases = [
      ["DCA_PHP_MODULE_ATTRIBUTE", "Acme\\\\PortedFrom"],
      ["DCA_PHP_MODULE_ATTRIBUTE", "Acme\\Ported-From"],
      ["DCA_PHP_MODULE_ATTRIBUTE", "\\\\Acme\\PortedFrom"],
      ["DCA_PHP_MODULE_ATTRIBUTE", "Acme\\"],
      ["DCA_PHP_MODULE_ATTRIBUTE", ""],
      ["DCA_PHP_EXPORT_ATTRIBUTE", "Acme\\1Export"],
      ["DCA_PHP_RETURN_TYPE_ATTRIBUTE", "Acme Returns"],
    ];
    for (const [name, value] of cases) {
      const run = spawnSync("php", [adapter], {
        env: adapterEnvironment({ DCA_TARGET_ROOT: targetRoot, [name]: value }),
        input: "",
        encoding: "utf8",
      });
      assert.notEqual(run.status, 0, `${name}=${value}`);
      assert.match(run.stderr, new RegExp(`${name} `), `${name}=${value}`);
    }
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("a startup refusal reaches the bridge failure with the variable it names", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  /** @param {Record<string, string>} settings @param {string | undefined} root */
  const failure = async (settings, root) => {
    const saved = { ...process.env };
    for (const name of ADAPTER_VARIABLES) delete process.env[name];
    Object.assign(process.env, settings);
    const binding = new ProcessBinding(
      defineBridge({ id: "php", adapter, command: "php", targetRoot: root }),
      { timeout: 10_000 },
    );
    try {
      return await binding.start().then(
        () => assert.fail("the adapter answered describe"),
        (/** @type {Error} */ error) => error.message,
      );
    } finally {
      await binding.dispose();
      for (const name of Object.keys(process.env)) if (!(name in saved)) delete process.env[name];
      Object.assign(process.env, saved);
    }
  };
  try {
    const malformed = await failure({ DCA_PHP_MODULE_ATTRIBUTE: "Acme Ported" }, targetRoot);
    assert.match(malformed, /^bridge describe failed: child_exit \(exit code [1-9]/);
    assert.match(malformed, /DCA_PHP_MODULE_ATTRIBUTE /);
    const rootless = await failure({}, undefined);
    assert.match(rootless, /^bridge describe failed: child_exit \(exit code [1-9]/);
    assert.match(rootless, /test target root is a readable directory/);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("a malformed or unloadable bytes class refuses at adapter startup and names the variable", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  try {
    for (const value of [
      "Acme Bytes",
      "Acme\\\\Bytes",
      "Acme\\MissingBytes",
      "DateTimeImmutable",
    ]) {
      const run = spawnSync("php", [adapter], {
        env: adapterEnvironment({ DCA_TARGET_ROOT: targetRoot, DCA_PHP_BYTES_CLASS: value }),
        input: "",
        encoding: "utf8",
      });
      assert.notEqual(run.status, 0, value);
      assert.match(run.stderr, /DCA_PHP_BYTES_CLASS /, value);
    }
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("a malformed or unloadable undefined class refuses at adapter startup and names the variable", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  try {
    for (const value of ["Acme Undefined", "Acme\\\\Undefined", "Acme\\MissingUndefined"]) {
      const run = spawnSync("php", [adapter], {
        env: adapterEnvironment({ DCA_TARGET_ROOT: targetRoot, DCA_PHP_UNDEFINED_CLASS: value }),
        input: "",
        encoding: "utf8",
      });
      assert.notEqual(run.status, 0, value);
      assert.match(run.stderr, /DCA_PHP_UNDEFINED_CLASS /, value);
    }
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("a module path that names no file in the JavaScript reference refuses at discovery", () => {
  const geometry = (/** @type {string} */ module) => ({
    "Geometry.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("${module}")]
class Geometry { public static function inspectPeriodGeometryBounds($value) { return $value; } }
`,
  });
  assert.deepEqual(
    JSON.parse(
      discover(geometry("core-shared/geometryBounds.js"), "core-shared/geometryBounds.js", {
        referenceRoot: root,
      }),
    ),
    [{ id: "op-1", sourceExport: "inspectPeriodGeometryBounds", callShape: "sync" }],
  );
  assert.throws(
    () =>
      discover(geometry("core-shared/geometryBound.js"), "core-shared/geometryBound.js", {
        referenceRoot: root,
      }),
    /core-shared\/geometryBound\.js names no file in the JavaScript reference/,
  );
  assert.throws(
    () =>
      discoverErrors(
        {
          "Failure.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("fixture/fault.js")]
#[\\Dca\\Porting\\SourceExport("FixtureFailure")]
class Failure extends \\RuntimeException {}
`,
        },
        { reference: ["fixture/faults.js"] },
      ),
    /fixture\/fault\.js names no file in the JavaScript reference/,
  );
  const outside = mkdtempSync(join(tmpdir(), "dca-php-outside-"));
  const referenceRoot = mkdtempSync(join(tmpdir(), "dca-php-reference-"));
  try {
    writeFileSync(join(outside, "linked.js"), "");
    symlinkSync(join(outside, "linked.js"), join(referenceRoot, "linked.js"));
    assert.throws(
      () => discover(geometry("linked.js"), "linked.js", { referenceRoot }),
      /linked\.js names no file in the JavaScript reference/,
    );
  } finally {
    rmSync(outside, { recursive: true, force: true });
    rmSync(referenceRoot, { recursive: true, force: true });
  }
});

/**
 * A port whose mapped Fixture\\Geometry calls Acme\\Helpers\\Clock in lib/,
 * outside the test-target root. The port's autoload.php maps both namespaces
 * with plain `require`, as Composer does, and logs each class it loads.
 */
const portWithHelper = {
  files: {
    "Geometry.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Geometry { public static function label() { return \\Acme\\Helpers\\Clock::label(); } }
`,
  },
  port: {
    "autoload.php": `<?php
spl_autoload_register(static function (string $class): void {
  $map = ['Fixture\\\\' => __DIR__ . '/src/', 'Acme\\\\Helpers\\\\' => __DIR__ . '/lib/'];
  foreach ($map as $prefix => $directory) {
    if (str_starts_with($class, $prefix)) {
      $GLOBALS['portLoads'][] = $class;
      require $directory . str_replace('\\\\', '/', substr($class, strlen($prefix))) . '.php';
    }
  }
});
`,
    "lib/Clock.php": `<?php
namespace Acme\\Helpers;
class Clock { public static function label() { return "clock"; } }
`,
  },
};
const invokeLabel = `$operation = $map->describeModule('alpha.js')[0]['id'];
echo json_encode([$map->invoke($operation, []), $GLOBALS['portLoads'] ?? []], JSON_THROW_ON_ERROR);`;

test("a mapped class reaches a helper in a second namespace only through DCA_TARGET_AUTOLOAD", () => {
  const options = { reference: ["alpha.js"], port: portWithHelper.port };
  assert.deepEqual(
    JSON.parse(
      runTargetMap(portWithHelper.files, invokeLabel, {
        ...options,
        namespace: null,
        autoload: "autoload.php",
      }),
    ),
    ["clock", ["Fixture\\Geometry", "Acme\\Helpers\\Clock"]],
  );
  assert.throws(
    () => runTargetMap(portWithHelper.files, invokeLabel, options),
    /Class "Acme\\Helpers\\Clock" not found/,
  );
});

test("with an autoload file and a namespace, the port's autoloader loads each class once", () => {
  // DCA_TARGET_NAMESPACE would drive the one-prefix autoloader for Fixture\.
  // Beside an autoload file it does not, so the port's log names every class,
  // and its plain require would fail on a class loaded twice.
  assert.deepEqual(
    JSON.parse(
      runTargetMap(portWithHelper.files, invokeLabel, {
        reference: ["alpha.js"],
        port: portWithHelper.port,
        namespace: "Fixture",
        autoload: "autoload.php",
      }),
    ),
    ["clock", ["Fixture\\Geometry", "Acme\\Helpers\\Clock"]],
  );
});

test("with an autoload file, discovery admits a class by its module attribute whatever its namespace", () => {
  const files = {
    "Alpha.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Alpha { public static function first($value) { return $value; } }
`,
    "nested/Beta.php": `<?php
namespace Other\\Place;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Beta { public static function second($value) { return $value; } }
`,
  };
  const port = {
    "autoload.php": `<?php
spl_autoload_register(static function (string $class): void {
  $map = ['Fixture\\\\Alpha' => '/src/Alpha.php', 'Other\\\\Place\\\\Beta' => '/src/nested/Beta.php'];
  if (isset($map[$class])) require __DIR__ . $map[$class];
});
`,
  };
  assert.deepEqual(
    JSON.parse(discover(files, "alpha.js", { namespace: null, port, autoload: "autoload.php" })),
    [
      { id: "op-1", sourceExport: "first", callShape: "sync" },
      { id: "op-2", sourceExport: "second", callShape: "sync" },
    ],
  );
});

test("without an autoload file, a file under the namespace prefix sits where the one-prefix autoloader looks", () => {
  assert.throws(
    () =>
      discover(
        {
          "Sub/Misplaced.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Misplaced { public static function call($value) { return $value; } }
`,
        },
        "alpha.js",
      ),
    /namespace matches its directory path/,
  );
});

test("a missing or unreadable autoload file refuses at adapter startup and names the variable", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  try {
    for (const value of [join(targetRoot, "missing.php"), targetRoot, "", "vendor/autoload.php"]) {
      const run = spawnSync("php", [adapter], {
        env: adapterEnvironment({ DCA_TARGET_ROOT: targetRoot, DCA_TARGET_AUTOLOAD: value }),
        input: "",
        encoding: "utf8",
      });
      assert.notEqual(run.status, 0, value);
      assert.match(run.stderr, /DCA_TARGET_AUTOLOAD /, value);
    }
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("generic throwable discovery assigns stable opaque descriptors", () => {
  const files = {
    "Failure.php": [
      "<?php",
      "namespace Fixture;",
      '#[\\Dca\\Porting\\SourceModule("fixture/faults.js")]',
      '#[\\Dca\\Porting\\SourceExport("FixtureFailure")]',
      'class Failure extends \\RuntimeException { public function errorCode() { return "fixture_failure"; } }',
      "",
    ].join("\n"),
  };
  const first = JSON.parse(discoverErrors(files, { reference: ["fixture/faults.js"] }));
  const second = JSON.parse(discoverErrors(files, { reference: ["fixture/faults.js"] }));
  assert.deepEqual(first, second);
  assert.deepEqual(
    first.map(({ sourceModule, sourceExport }) => ({ sourceModule, sourceExport })),
    [{ sourceModule: "fixture/faults.js", sourceExport: "FixtureFailure" }],
  );
  assert.match(first[0].id, /^error-[a-f0-9]{24}$/);
});

test("generic bridge converts nested byte values and restores an annotated byte result", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  const reference = adapterInReference();
  const binding = new ProcessBinding(
    defineBridge({ id: "php", adapter: reference.adapter, command: "php", targetRoot }),
  );
  try {
    writeFileSync(join(reference.referenceRoot, "bytes.js"), "");
    writeFileSync(
      join(targetRoot, "Bytes.php"),
      [
        "<?php",
        '#[\\Dca\\Porting\\SourceModule("bytes.js")]',
        "class Bytes {",
        '  #[\\Dca\\Porting\\ReturnType("Uint8Array")]',
        '  public static function append($value) { return $value->nested[0] . "\\x7f"; }',
        "}",
        "",
      ].join("\n"),
    );
    await binding.start();
    const identity = /** @type {any} */ (binding.description).identity;
    assert.equal(identity.targetVersion, "php-test");
    assert.equal(Object.hasOwn(identity, "implementationVersion"), false);
    const operation = binding
      .describeModule("bytes.js")
      .find((member) => member.sourceExport === "append");
    assert.ok(operation);
    assert.deepEqual(
      binding.call(operation.id, [{ nested: [new Uint8Array([1, 2])] }]),
      new Uint8Array([1, 2, 127]),
    );
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(reference.referenceRoot, { recursive: true, force: true });
  }
});

test("generic mapped throw restores the declared Error prototype without calling its constructor", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  const { referenceRoot, adapter: adapterCopy } = adapterInReference();
  const binding = new ProcessBinding(
    defineBridge({ id: "php", adapter: adapterCopy, command: "php", targetRoot }),
  );
  try {
    writeFileSync(join(referenceRoot, "actions.js"), "");
    writeFileSync(
      join(targetRoot, "Failure.php"),
      [
        "<?php",
        '#[\\Dca\\Porting\\SourceModule("faults.js")]',
        '#[\\Dca\\Porting\\SourceExport("FixtureFailure")]',
        'class Failure extends \\RuntimeException { public function errorCode() { return "fixture_failure"; } }',
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(targetRoot, "Actions.php"),
      [
        "<?php",
        '#[\\Dca\\Porting\\SourceModule("actions.js")]',
        'class Actions { public static function fail() { throw new Failure("fixture message"); } public static function unmapped() { throw new \\RuntimeException("ordinary message"); } }',
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(referenceRoot, "faults.js"),
      [
        "export class FixtureFailure extends Error {",
        '  constructor() { throw new Error("a bridge must not invoke this constructor"); }',
        "}",
        "",
      ].join("\n"),
    );
    await binding.start();
    await binding.preloadErrorTypes(referenceRoot);
    const failure = await import(pathToFileURL(join(referenceRoot, "faults.js")).href);
    const operation = binding
      .describeModule("actions.js")
      .find((member) => member.sourceExport === "fail");
    assert.ok(operation);
    assert.throws(
      () => binding.call(operation.id, []),
      (error) =>
        error instanceof failure.FixtureFailure &&
        error instanceof Error &&
        error.code === "fixture_failure" &&
        error.message === "fixture message" &&
        Object.hasOwn(error, "code") &&
        Object.hasOwn(error, "message"),
    );
    assert.throws(
      () =>
        binding.refusalError({ errorType: "unknown", code: "fixture_failure", message: "nope" }),
      /unknown error type/,
    );
    const unmapped = binding
      .describeModule("actions.js")
      .find((member) => member.sourceExport === "unmapped");
    assert.ok(unmapped);
    assert.throws(
      () => binding.call(unmapped.id, []),
      (error) =>
        error instanceof Error &&
        !(error instanceof failure.FixtureFailure) &&
        error.code === "adapter_refusal" &&
        error.message === "ordinary message",
    );
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(referenceRoot, { recursive: true, force: true });
  }
});

test("generic error preloading refuses exports that are not Error constructors", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  const binding = new ProcessBinding(
    defineBridge({ id: "php", adapter, command: "php", targetRoot }),
  );
  try {
    writeFileSync(join(targetRoot, "not-error.js"), "export const NotError = {};\n");
    binding.errorDescriptors = [
      { id: "error-fixture", sourceModule: "not-error.js", sourceExport: "NotError" },
    ];
    await assert.rejects(binding.preloadErrorTypes(targetRoot), /Error prototype/);
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("mapped error preload leaves later reference imports under the bridge hooks", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-errors-target-"));
  try {
    writeFileSync(
      join(targetRoot, "Failure.php"),
      `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("core-shared/errors.js")]
#[\\Dca\\Porting\\SourceExport("DcaError")]
class Failure extends \\RuntimeException {}
`,
    );
    const run = spawnSync(
      process.execPath,
      [
        "--import",
        preload,
        "--input-type=module",
        "-e",
        `const { dcaError } = await import("./core-shared/errors.js");
try { dcaError("bad_config", "probe"); console.log("reference ran"); }
catch (error) { console.log(error.message); }`,
      ],
      {
        cwd: root,
        env: adapterEnvironment({
          DCA_BRIDGE_MODE: "strict",
          DCA_TARGET_ROOT: targetRoot,
          DCA_TARGET_NAMESPACE: "Fixture",
        }),
        encoding: "utf8",
      },
    );
    assert.match(run.stdout, /strict bridge run: core-shared\/errors\.js#dcaError is not claimed/);
    assert.doesNotMatch(run.stdout, /reference ran/);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("generic error preloading keeps descriptor modules below its trusted root", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  const outside = mkdtempSync(join(tmpdir(), "dca-php-outside-"));
  const binding = new ProcessBinding(
    defineBridge({ id: "php", adapter, command: "php", targetRoot }),
  );
  try {
    writeFileSync(join(outside, "errors.js"), "export class FixtureError extends Error {}\n");
    mkdirSync(join(targetRoot, "fixture"));
    symlinkSync(outside, join(targetRoot, "fixture", "linked"), "dir");
    binding.errorDescriptors = [
      {
        id: "error-fixture",
        sourceModule: "fixture/linked/errors.js",
        sourceExport: "FixtureError",
      },
    ];
    await assert.rejects(binding.preloadErrorTypes(targetRoot), /trusted reference root/);
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

// The refusal comes before PHP starts, so it runs without PHP on PATH.
nodeTest("the PHP bridge refuses without a target root", () => {
  const environment = { ...process.env };
  delete environment.DCA_TARGET_ROOT;
  delete environment.NODE_TEST_CONTEXT;
  const refused = spawnSync(
    process.execPath,
    ["--import", preload, "--test", "--test-reporter=tap", geometryTest],
    {
      cwd: root,
      env: environment,
      encoding: "utf8",
    },
  );
  // Node's test runner reports the preload's error from the test child on stdout.
  const output = `${refused.stdout}${refused.stderr}`;
  assert.notEqual(refused.status, 0);
  assert.match(output, /the php bridge needs DCA_TARGET_ROOT/);
  assert.doesNotMatch(refused.stdout, /^# pass [1-9]/m);
});

/**
 * A generic PHP test target for core-shared/geometryBounds.js. `header` holds the
 * `use` lines and the class attribute; `method` the method's attribute and
 * signature line. `wrong` shifts windowMinutes by one.
 *
 * @param {{ header: string[], method: string[], wrong?: boolean }} shape
 */
function geometrySource({ header, method, wrong = false }) {
  return [
    "<?php",
    "namespace Fixture;",
    ...header,
    "final class Geometry",
    "{",
    ...method,
    "    {",
    "        if (!is_int($chainsPerDay) || $chainsPerDay <= 0 || 1440 % $chainsPerDay !== 0) return ['kind' => 'invalidChainsPerDay'];",
    `        $windowMinutes = intdiv(1440, $chainsPerDay)${wrong ? " + 1" : ""};`,
    "        if (!is_int($periodMinutes) || $periodMinutes <= 0 || $windowMinutes % $periodMinutes !== 0) return ['kind' => 'invalidPeriodMinutes', 'windowMinutes' => $windowMinutes];",
    "        $positions = intdiv($windowMinutes, $periodMinutes);",
    "        if ($positions > 288) return ['kind' => 'tooManyPositions', 'windowMinutes' => $windowMinutes, 'positionsPerWindow' => $positions];",
    "        return ['kind' => 'valid', 'windowMinutes' => $windowMinutes, 'positionsPerWindow' => $positions];",
    "    }",
    "}",
    "",
  ].join("\n");
}

/**
 * Runs the unchanged geometry test in strict mode through the shipped PHP bridge
 * against `files` in a temporary test-target root.
 *
 * @param {Record<string, string>} files
 * @param {Record<string, string>} [settings]
 */
function runGeometry(files, settings = {}) {
  const logs = mkdtempSync(join(tmpdir(), "dca-php-integration-"));
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  try {
    writeTree(targetRoot, files);
    const environment = adapterEnvironment({
      DCA_BRIDGE_MODE: "strict",
      DCA_TARGET_ROOT: targetRoot,
      DCA_LOG_DIR: logs,
      ...settings,
    });
    delete environment.NODE_TEST_CONTEXT;
    const run = spawnSync(
      process.execPath,
      ["--import", preload, "--test", "--test-reporter=tap", geometryTest],
      {
        cwd: root,
        env: environment,
        encoding: "utf8",
      },
    );
    const records = [];
    for (const entry of readdirSync(logs, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      for (const file of readdirSync(join(logs, entry.name))) {
        if (!file.endsWith(".transcript.jsonl")) continue;
        records.push(
          ...readFileSync(join(logs, entry.name, file), "utf8")
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line)),
        );
      }
    }
    return { status: run.status, output: `${run.stdout}${run.stderr}`, records };
  } finally {
    rmSync(logs, { recursive: true, force: true });
    rmSync(targetRoot, { recursive: true, force: true });
  }
}

/** @param {ReturnType<typeof runGeometry>} run */
function assertCrossedExternally(run) {
  assert.equal(run.status, 0, run.output);
  assert.match(run.output, /^# pass [1-9]\d*$/m);
  const final = run.records.find((record) => record.event === "final");
  assert.ok(final.externalCalls > 0);
  assert.equal(final.referenceFallbacks, 0);
  assert.ok(
    run.records
      .filter((record) => record.event === "call")
      .every(
        (record) => typeof record.operation === "string" && record.operation.startsWith("op-"),
      ),
  );
}

test("the unchanged strict reference test crosses the generic PHP bridge externally", () => {
  // The method name differs from the export, so the SourceExport marker carries
  // the mapping.
  const run = runGeometry(
    {
      "Geometry.php": geometrySource({
        header: ["#[\\Dca\\Porting\\SourceModule('core-shared/geometryBounds.js')]"],
        method: [
          "    #[\\Dca\\Porting\\SourceExport('inspectPeriodGeometryBounds')]",
          "    public static function inspect($chainsPerDay, $periodMinutes)",
        ],
      }),
    },
    { DCA_TARGET_NAMESPACE: "Fixture" },
  );
  assertCrossedExternally(run);
});

test("the shipped PHP bridge reads a configured module attribute in its imported short form", () => {
  // The method keeps the export's own name, so it needs no export attribute.
  const shape = {
    header: ["use Acme\\PortedFrom;", "#[PortedFrom('core-shared/geometryBounds.js')]"],
    method: [
      "    public static function inspectPeriodGeometryBounds($chainsPerDay, $periodMinutes)",
    ],
  };
  const settings = { DCA_PHP_MODULE_ATTRIBUTE: "Acme\\PortedFrom" };
  assertCrossedExternally(runGeometry({ "Geometry.php": geometrySource(shape) }, settings));
  const wrong = runGeometry(
    { "Geometry.php": geometrySource({ ...shape, wrong: true }) },
    settings,
  );
  assert.notEqual(wrong.status, 0, wrong.output);
  assert.match(wrong.output, /^# fail [1-9]/m);
});

test("the PHP adapter accepts a protocol call frame and refuses one with target", () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  try {
    const frame = (/** @type {object} */ value) => {
      const body = Buffer.from(JSON.stringify(value));
      const header = Buffer.alloc(4);
      header.writeUInt32BE(body.length);
      return Buffer.concat([header, body]);
    };
    const call = { version: 1, type: "call", operation: "op-none", input: [] };
    const run = spawnSync("php", [adapter], {
      env: { ...process.env, DCA_TARGET_ROOT: targetRoot },
      input: Buffer.concat([
        frame({ ...call, id: "current", protocol: "dca-test-bridge/v1" }),
        frame({ ...call, id: "renamed", target: "dca-test-bridge/v1" }),
      ]),
    });
    assert.equal(run.status, 0, String(run.stderr));
    /** @type {any[]} */
    const responses = [];
    for (let offset = 0; offset < run.stdout.length;) {
      const size = run.stdout.readUInt32BE(offset);
      responses.push(JSON.parse(run.stdout.subarray(offset + 4, offset + 4 + size).toString()));
      offset += 4 + size;
    }
    assert.deepEqual(
      responses.map(({ id, result }) => [id, result.kind]),
      [
        ["current", "unsupported"],
        ["renamed", "refusal"],
      ],
    );
    assert.match(responses[1].result.message, /target/);
  } finally {
    rmSync(targetRoot, { recursive: true, force: true });
  }
});

test("a PHP result the bridge cannot encode is uncarried, a string that is not UTF-8 crosses as bytes, and a PHP throw stays a refusal", async () => {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  const reference = adapterInReference();
  const binding = new ProcessBinding(
    defineBridge({ id: "php", adapter: reference.adapter, command: "php", targetRoot }),
    { mode: "strict" },
  );
  try {
    writeFileSync(join(reference.referenceRoot, "results.js"), "");
    writeFileSync(
      join(targetRoot, "Results.php"),
      [
        "<?php",
        '#[\\Dca\\Porting\\SourceModule("results.js")]',
        "class Results {",
        "  public static function infinite() { return INF; }",
        '  public static function rawBytes() { return "\\xff"; }',
        '  public static function refuse() { throw new \\TypeError("the target refused"); }',
        "}",
        "",
      ].join("\n"),
    );
    await binding.start();
    const members = binding.describeModule("results.js");
    const operation = (/** @type {string} */ name) => {
      const member = members.find((entry) => entry.sourceExport === name);
      assert.ok(member);
      return member.id;
    };
    const response = /** @type {any} */ (
      binding.request({
        version: 1,
        type: "call",
        protocol: "dca-test-bridge/v1",
        operation: operation("infinite"),
        input: [],
      })
    );
    assert.equal(response.result.kind, "uncarried");
    assert.throws(
      () => binding.call(operation("infinite"), []),
      /bridge cannot carry the result of results\.js infinite/,
    );
    // Not JSON text, so bytes; the answer declares nothing, so the reference type reads it.
    assert.deepEqual(
      /** @type {any} */ (
        binding.request({
          version: 1,
          type: "call",
          protocol: "dca-test-bridge/v1",
          operation: operation("rawBytes"),
          input: [],
        })
      ).result,
      { kind: "observation", value: { $type: "Uint8Array", base64url: "_w" } },
    );
    assert.deepEqual(binding.call(operation("rawBytes"), []), new Uint8Array([255]));
    assert.throws(() => binding.call(operation("refuse"), []), /the target refused/);
  } finally {
    await binding.dispose();
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(reference.referenceRoot, { recursive: true, force: true });
  }
});

/**
 * Starts the shipped PHP adapter on `files` in a temporary test-target root and
 * a temporary reference holding an empty `values.js`, then calls `run`.
 *
 * @param {Record<string, string>} files
 * @param {(binding: ProcessBinding, operation: (name: string) => string) => void} run
 * @param {Record<string, string>} [settings]
 * @param {{ referenceShapes?: import("../../_shared/reference-shapes.mjs").ReferenceShapes, inputs?: readonly import("../../_shared/register.mjs").BoundInputMapping[] }} [options]
 *   `referenceShapes` stands in for the reference types of `values.js`;
 *   `inputs` lists the input mappings the binding applies.
 */
async function withValuesTarget(files, run, settings = {}, options = {}) {
  const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-target-"));
  const reference = adapterInReference();
  const saved = { ...process.env };
  for (const name of ADAPTER_VARIABLES) delete process.env[name];
  Object.assign(process.env, settings);
  const binding = new ProcessBinding(
    defineBridge({ id: "php", adapter: reference.adapter, command: "php", targetRoot }),
    { mode: "strict", ...options },
  );
  try {
    writeFileSync(join(reference.referenceRoot, "values.js"), "");
    writeTree(targetRoot, files);
    await binding.start();
    const members = binding.describeModule("values.js");
    run(binding, (name) => {
      const member = members.find((entry) => entry.sourceExport === name);
      assert.ok(member, name);
      return member.id;
    });
  } finally {
    await binding.dispose();
    for (const name of Object.keys(process.env)) if (!(name in saved)) delete process.env[name];
    Object.assign(process.env, saved);
    rmSync(targetRoot, { recursive: true, force: true });
    rmSync(reference.referenceRoot, { recursive: true, force: true });
  }
}

test("records reach a PHP target as stdClass with native byte strings, and typed output crosses unmarked", async () => {
  await withValuesTarget(
    {
      "Values.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values {
  public static function kinds($value) { return [get_class($value), gettype($value->blob), $value->blob, $value->list]; }
  public static function key(string $value) { return bin2hex($value); }
  public static function typed() { return (object) ["empty" => new \\stdClass(), "list" => [], "blob" => new \\Dca\\Porting\\Bytes("\\xff"), "7" => 7]; }
}
`,
    },
    (binding, operation) => {
      assert.deepEqual(
        binding.call(operation("kinds"), [{ blob: new Uint8Array([97]), list: [] }]),
        ["stdClass", "string", "a", []],
      );
      assert.equal(binding.call(operation("key"), [new Uint8Array([0, 255])]), "00ff");
      assert.deepEqual(binding.call(operation("typed"), []), {
        empty: {},
        list: [],
        blob: new Uint8Array([255]),
        7: 7,
      });
    },
  );
});

test("an argument an input mapping lists reaches a PHP target as the stdClass record of its data", async () => {
  class Box {
    #document;
    /** @param {unknown} document */
    constructor(document) {
      this.#document = document;
    }
    data() {
      return this.#document;
    }
  }
  await withValuesTarget(
    {
      "Values.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values {
  public static function kind($value) { return get_class($value) . ":" . $value->n; }
}
`,
    },
    (binding, operation) => {
      assert.equal(binding.call(operation("kind"), [new Box({ n: 7 })]), "stdClass:7");
    },
    {},
    {
      inputs: [
        {
          module: "values.js",
          export: "kind",
          argument: 0,
          class: { module: "box.js", export: "Box" },
          data: "data",
          type: Box,
        },
      ],
    },
  );
});

test("a ReturnType shape marks nested bytes and records in plain PHP output", async () => {
  await withValuesTarget(
    {
      "Values.php": `<?php
namespace Fixture;
use Dca\\Porting\\ReturnType;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values {
  #[ReturnType(["key" => "Uint8Array", "items" => "list", "empty" => "record", "parts" => ["Uint8Array"], "inner" => ["blob" => "Uint8Array"]])]
  public static function shaped() {
    return ["key" => "\\xff\\x00", "items" => [], "empty" => [], "parts" => ["a", "\\x01"], "inner" => ["blob" => "b", "text" => "b"], "text" => "plain", "absent" => null];
  }
  #[ReturnType("record")]
  public static function emptyRecord() { return []; }
  public static function emptyList() { return []; }
  #[ReturnType(["key" => "Uint8Array"])]
  public static function misfit() { return ["key" => 1]; }
  public static function unmarkedBinary() { return ["key" => "\\xff"]; }
}
`,
    },
    (binding, operation) => {
      assert.deepEqual(binding.call(operation("shaped"), []), {
        key: new Uint8Array([255, 0]),
        items: [],
        empty: {},
        parts: [new Uint8Array([97]), new Uint8Array([1])],
        inner: { blob: new Uint8Array([98]), text: "b" },
        text: "plain",
        absent: null,
      });
      assert.deepEqual(binding.call(operation("emptyRecord"), []), {});
      assert.deepEqual(binding.call(operation("emptyList"), []), []);
      assert.throws(
        () => binding.call(operation("misfit"), []),
        /matches its JavaScript runtime type marker/,
      );
      assert.deepEqual(binding.call(operation("unmarkedBinary"), []), {
        key: new Uint8Array([255]),
      });
    },
  );
});

test("a PHP answer declares the positions whose PHP type says the JS type, and nothing else", async () => {
  await withValuesTarget(
    {
      "Values.php": `<?php
namespace Fixture;
use Dca\\Porting\\ReturnType;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values {
  public static function typed() {
    return (object) ["record" => ["a" => 1], "list" => [1, [], "x"], "empty" => [], "blob" => new \\Dca\\Porting\\Bytes("b"), "text" => "t", "nothing" => null, "7" => new \\stdClass()];
  }
  #[ReturnType(["items" => "list", "parts" => ["Uint8Array"], "key" => "Uint8Array", "meta" => "record"])]
  public static function marked() { return ["items" => [], "parts" => [], "key" => "k", "meta" => []]; }
  public static function plain() { return "text"; }
}
`,
    },
    (binding, operation) => {
      const declared = (/** @type {string} */ name) =>
        /** @type {any} */ (
          binding.request({
            version: 1,
            type: "call",
            protocol: "dca-test-bridge/v1",
            operation: operation(name),
            input: [],
          })
        ).result.declared;
      const byPosition = (/** @type {{ at: unknown[], type: string }[]} */ entries) =>
        entries.map(({ at, type }) => `${JSON.stringify(at)} ${type}`).sort();
      assert.deepEqual(byPosition(declared("typed")), [
        '["7"] record',
        '["blob"] Uint8Array',
        '["list"] list',
        '["record"] record',
        "[] record",
      ]);
      assert.deepEqual(byPosition(declared("marked")), [
        '["items"] list',
        '["key"] Uint8Array',
        '["meta"] record',
        '["parts"] list',
        "[] record",
      ]);
      assert.equal(declared("plain"), undefined);
    },
  );
});

test("the driver reads an undeclared PHP answer by the reference type and refuses a declaration it does not admit", async () => {
  await withValuesTarget(
    {
      "Values.php": `<?php
namespace Fixture;
use Dca\\Porting\\ReturnType;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values {
  public static function emptyRecord() { return []; }
  public static function text() { return "abc"; }
  public static function nothing() { return null; }
  public static function nested() { return ["key" => "k", "items" => [], "note" => null]; }
  public static function either() { return []; }
  #[ReturnType("list")]
  public static function markedList() { return []; }
  public static function bytesForText() { return new \\Dca\\Porting\\Bytes("a"); }
  public static function rawForText() { return "\\xff"; }
}
`,
    },
    (binding, operation) => {
      assert.deepEqual(binding.call(operation("emptyRecord"), []), {});
      assert.deepEqual(binding.call(operation("text"), []), new TextEncoder().encode("abc"));
      assert.equal(binding.call(operation("nothing"), []), undefined);
      assert.deepEqual(binding.call(operation("nested"), []), {
        key: new TextEncoder().encode("k"),
        items: {},
        note: undefined,
      });
      assert.deepEqual(binding.call(operation("either"), []), []);
      assert.throws(
        () => binding.call(operation("markedList"), []),
        /bridge refuses the result of values\.js markedList: the test target declares list at the result, where the reference type admits record/,
      );
      assert.throws(
        () => binding.call(operation("bytesForText"), []),
        /bridge refuses the result of values\.js bytesForText: the test target declares Uint8Array at the result, where the reference type admits string/,
      );
      // Undeclared bytes the reference type does not admit pass unchanged; the test then fails.
      assert.deepEqual(binding.call(operation("rawForText"), []), new Uint8Array([255]));
    },
    {},
    {
      referenceShapes: {
        version: 1,
        modules: {
          "values.js": {
            emptyRecord: { record: {} },
            text: "Uint8Array",
            nothing: "undefined",
            nested: {
              record: {
                key: "Uint8Array",
                items: { record: {}, values: "string" },
                note: { anyOf: ["string", "undefined"] },
              },
            },
            either: { anyOf: [{ list: "string" }, { record: {} }] },
            markedList: { record: {} },
            bytesForText: "string",
            rawForText: "string",
          },
        },
      },
    },
  );
});

test("a malformed ReturnType shape stops discovery", () => {
  for (const [shape, message] of [
    ['["key" => "NotAType"]', /supported JavaScript runtime type/],
    ["[]", /supported JavaScript runtime type/],
    ['["Uint8Array", "list"]', /record members or one list entry type/],
  ])
    assert.throws(
      () =>
        discover(
          {
            "Alpha.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("alpha.js")]
class Alpha { #[\\Dca\\Porting\\ReturnType(${shape})] public static function shaped() { return []; } }
`,
          },
          "alpha.js",
        ),
      message,
      shape,
    );
});

test("a parameter declared as DCA_PHP_BYTES_CLASS receives that class", async () => {
  await withValuesTarget(
    {
      "Blob.php": `<?php
namespace Fixture;
final class Blob { public function __construct(private string $raw) {} public function __toString(): string { return $this->raw; } }
`,
      "Values.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values { public static function reversed(Blob $value) { return [get_class($value), new Blob(strrev((string) $value))]; } }
`,
    },
    (binding, operation) => {
      assert.deepEqual(binding.call(operation("reversed"), [new Uint8Array([1, 2])]), [
        "Fixture\\Blob",
        new Uint8Array([2, 1]),
      ]);
    },
    { DCA_TARGET_NAMESPACE: "Fixture", DCA_PHP_BYTES_CLASS: "Fixture\\Blob" },
  );
});

test("Dca\\Porting\\Undefined crosses as undefined where the reference type admits null and undefined, and a plain null stays null", async () => {
  await withValuesTarget(
    {
      "Values.php": `<?php
namespace Fixture;
use Dca\\Porting\\Undefined;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values {
  public static function marker() { return new Undefined(); }
  public static function plain() { return null; }
  public static function nested() { return ["note" => new Undefined(), "left" => null, "items" => [new Undefined(), null]]; }
  #[\\Dca\\Porting\\ReturnType(["key" => "Uint8Array"])]
  public static function marked() { return ["key" => new Undefined()]; }
}
`,
    },
    (binding, operation) => {
      assert.equal(binding.call(operation("marker"), []), undefined);
      assert.equal(binding.call(operation("plain"), []), null);
      const nested = /** @type {any} */ (binding.call(operation("nested"), []));
      assert.ok(Object.hasOwn(nested, "note"));
      assert.deepEqual(nested, { note: undefined, left: null, items: [undefined, null] });
      // The marker passes wherever a ReturnType marker stands, as null does.
      assert.deepEqual(binding.call(operation("marked"), []), { key: undefined });
    },
    {},
    {
      referenceShapes: {
        version: 1,
        modules: {
          "values.js": {
            marker: { anyOf: ["null", "undefined"] },
            plain: { anyOf: ["null", "undefined"] },
            nested: {
              record: {
                note: { anyOf: ["null", "string", "undefined"] },
                left: { anyOf: ["null", "string", "undefined"] },
                items: { list: { anyOf: ["null", "undefined"] } },
              },
            },
            marked: { record: { key: { anyOf: ["Uint8Array", "undefined"] } } },
          },
        },
      },
    },
  );
});

test("DCA_PHP_UNDEFINED_CLASS names the class a port returns for undefined", async () => {
  await withValuesTarget(
    {
      "Nothing.php": `<?php
namespace Fixture;
final class Nothing {}
`,
      "Values.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule("values.js")]
class Values { public static function marker() { return [new Nothing()]; } }
`,
    },
    (binding, operation) => {
      assert.deepEqual(binding.call(operation("marker"), []), [undefined]);
    },
    { DCA_TARGET_NAMESPACE: "Fixture", DCA_PHP_UNDEFINED_CLASS: "Fixture\\Nothing" },
    {
      referenceShapes: {
        version: 1,
        modules: { "values.js": { marker: { list: { anyOf: ["null", "undefined"] } } } },
      },
    },
  );
});

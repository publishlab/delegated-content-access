import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import test from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { ProcessBinding } from "../../_shared/register.mjs";
import { constructedTally, testObjectHandles } from "../../_shared/object-handles/suite.mjs";

// A public checkout may have no PHP; the tests then report as skipped.
const phpMissing = spawnSync("php", ["-v"], { stdio: "ignore" }).error !== undefined;

// The neutral fixture ../../_shared/object-handles/suite.mjs describes. The
// PHP names differ from the reference names on purpose: export markers map
// the class, the factory and one member.
const FILES = {
  "NativeCounter.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule('counter.js')]
#[\\Dca\\Porting\\SourceExport('Counter')]
final class NativeCounter {
  public $count;
  private function __construct($start) { $this->count = $start; }
  #[\\Dca\\Porting\\SourceExport('openCounter')]
  public static function open($start) { return new self($start); }
  public static function openOther() { return new Other(); }
  public static function openHidden() { return new \\ArrayObject(); }
  public static function same($left, $right) { return $left === $right; }
  public function add($step) { $this->count += $step; return $this->count; }
  #[\\Dca\\Porting\\SourceExport('self')]
  public function itself() { return $this; }
  public function pair() { return [$this, ['inner' => $this]]; }
  public function holds($entries) { return $entries->list[0] === $this && $entries->record->inner === $this; }
  private function hidden() { return 0; }
}
`,
  "Other.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule('counter.js')]
final class Other {
  public function name() { return 'other'; }
}
`,
  "Tally.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule('counter.js')]
final class Tally {
  private $total;
  public function __construct($start) {
    if (!(is_int($start) || is_float($start)) || $start < 0) {
      throw new CounterError('bad_start', 'a tally starts at a non-negative number');
    }
    $this->total = $start;
  }
  public function add($step) { $this->total += $step; return $this->total; }
}
`,
  "Holder.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule('counter.js')]
final class Holder {
  private $tally;
  private $label;
  public function __construct($tally, $label) { $this->tally = $tally; $this->label = $label; }
  public function native() { return $this->tally instanceof Tally; }
  public function tally() { return $this->tally; }
  public function bump($step) { return $this->tally->add($step); }
  public function label() { return $this->label; }
}
`,
  "CounterError.php": `<?php
namespace Fixture;
#[\\Dca\\Porting\\SourceModule('counter.js')]
#[\\Dca\\Porting\\SourceExport('CounterError')]
final class CounterError extends \\Exception {
  private $errorCode;
  public function __construct($errorCode, $message) { parent::__construct($message); $this->errorCode = $errorCode; }
  public function errorCode() { return $this->errorCode; }
}
`,
};

// A plausible wrong test target: its Tally ignores the start it receives.
const WRONG_TALLY = `<?php
namespace Wrong;
#[\\Dca\\Porting\\SourceModule('counter.js')]
final class Tally {
  private $total = 0;
  public function __construct($start) {}
  public function add($step) { $this->total += $step; return $this->total; }
}
`;

// The adapter checks each module path against the JavaScript reference it
// ships in, so a copy of it sits in a temporary reference beside counter.js.
const bridgeDirectory = fileURLToPath(new URL("../", import.meta.url));
const referenceRoot = mkdtempSync(join(tmpdir(), "dca-php-reference-"));
const adapterCopy = join(referenceRoot, "test-bridges/php");
mkdirSync(adapterCopy, { recursive: true });
cpSync(join(bridgeDirectory, "adapter.php"), join(adapterCopy, "adapter.php"));
cpSync(join(bridgeDirectory, "src"), join(adapterCopy, "src"), { recursive: true });
// The reference error class a CounterError refusal maps to.
writeFileSync(join(referenceRoot, "counter.js"), "export class CounterError extends Error {}\n");
const targetRoot = mkdtempSync(join(tmpdir(), "dca-php-object-handles-"));
for (const [name, source] of Object.entries(FILES)) writeFileSync(join(targetRoot, name), source);
test.after(() => {
  rmSync(referenceRoot, { recursive: true, force: true });
  rmSync(targetRoot, { recursive: true, force: true });
});

// The adapter inherits this environment; a caller's shell must not steer it.
for (const name of [
  "DCA_TARGET_NAMESPACE",
  "DCA_TARGET_AUTOLOAD",
  "DCA_PHP_MODULE_ATTRIBUTE",
  "DCA_PHP_EXPORT_ATTRIBUTE",
  "DCA_PHP_RETURN_TYPE_ATTRIBUTE",
  "DCA_PHP_BYTES_CLASS",
  "DCA_PHP_UNDEFINED_CLASS",
])
  delete process.env[name];

const bridge = defineBridge({
  id: "php",
  adapter: join(adapterCopy, "adapter.php"),
  command: "php",
  targetRoot,
});

testObjectHandles({
  id: "php",
  start: async () => {
    const binding = await new ProcessBinding(bridge, { mode: "strict" }).start();
    await binding.preloadErrorTypes(referenceRoot);
    return binding;
  },
  ...(phpMissing ? { skip: "php not on PATH" } : {}),
});

test(
  "php: a class whose constructor is not public claims no constructor, and construction is refused before dispatch",
  { ...(phpMissing ? { skip: "php not on PATH" } : {}) },
  async () => {
    const binding = await new ProcessBinding(bridge, { mode: "strict" }).start();
    try {
      binding.describeModule("counter.js");
      const counter = binding.moduleClasses
        .get("counter.js")
        ?.find((entry) => entry.sourceExport === "Counter");
      assert.ok(counter);
      assert.equal(Object.hasOwn(counter, "construct"), false);
      assert.throws(
        () => binding.construct("counter.js", "Counter", [1]),
        /strict bridge run: new counter\.js Counter is not claimed by the test target/,
      );
      assert.equal(binding.externalCalls, 0);
    } finally {
      await binding.dispose();
    }
  },
);

test(
  "php: a wrong test target whose constructor drops its input fails the result assertion",
  { ...(phpMissing ? { skip: "php not on PATH" } : {}) },
  async () => {
    const wrongRoot = mkdtempSync(join(tmpdir(), "dca-php-tally-wrong-"));
    writeFileSync(join(wrongRoot, "Tally.php"), WRONG_TALLY);
    const wrong = defineBridge({
      id: "php",
      adapter: join(adapterCopy, "adapter.php"),
      command: "php",
      targetRoot: wrongRoot,
    });
    const binding = await new ProcessBinding(wrong, { mode: "strict" }).start();
    try {
      assert.throws(() => constructedTally(binding), {
        name: "AssertionError",
        message: /the object holds the start its constructor received/,
      });
    } finally {
      await binding.dispose();
      rmSync(wrongRoot, { recursive: true, force: true });
    }
  },
);

test(
  "the unchanged object case fails against a PHP test target whose document drops a member nobody named",
  { ...(phpMissing ? { skip: "php not on PATH" } : {}) },
  () => {
    const wrongRoot = mkdtempSync(join(tmpdir(), "dca-php-object-wrong-"));
    writeFileSync(
      join(wrongRoot, "Request.php"),
      `<?php
namespace Wrong;
#[\\Dca\\Porting\\SourceModule('core-shared--client-issuer/DcaRequest.js')]
#[\\Dca\\Porting\\SourceExport('DcaRequest')]
final class Request {
  private $document;
  private function __construct($document) { $this->document = $document; }
  #[\\Dca\\Porting\\SourceExport('parseDcaRequest')]
  public static function parse($raw) { return new self(json_decode($raw)); }
  #[\\Dca\\Porting\\SourceExport('toObject')]
  public function document() {
    return (object) ['issuerName' => $this->document->issuerName, 'version' => $this->document->version];
  }
}
`,
    );
    try {
      const run = spawnSync(
        process.execPath,
        [join(bridgeDirectory, "../_shared/run.mjs"), "portable-object-core"],
        {
          cwd: fileURLToPath(new URL("../../../", import.meta.url)),
          env: {
            ...process.env,
            DCA_BRIDGE: "php",
            DCA_TARGET_ROOT: wrongRoot,
            NODE_TEST_CONTEXT: undefined,
          },
          encoding: "utf8",
        },
      );
      // The target refuses nothing, so the parse-refusal twin fails beside the
      // dropped member.
      assert.notEqual(run.status, 0, run.stdout);
      assert.match(run.stdout, /^# fail 2$/m);
      assert.match(
        run.stdout,
        /not ok 1 - the document goes back as it arrived, members nobody named included\n[^]*?error: \|-\n\s+Expected values to be strictly equal/,
      );
      assert.match(run.stderr, /portable selection passed 0\/2; failed 2/);
    } finally {
      rmSync(wrongRoot, { recursive: true, force: true });
    }
  },
);

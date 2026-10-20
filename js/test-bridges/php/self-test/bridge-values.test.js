import test from "node:test";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { testBridgeValues } from "../../_shared/bridge-values/suite.mjs";

// A public checkout may have no PHP; the tests then report as skipped.
const phpMissing = spawnSync("php", ["-v"], { stdio: "ignore" }).error !== undefined;

// The adapter checks each module path against the JavaScript reference it
// ships in. A copy of the adapter in a temporary tree, beside an empty
// `values.js`, gives the fixture module path a reference that holds it.
const bridgeDirectory = fileURLToPath(new URL("../", import.meta.url));
const referenceRoot = mkdtempSync(join(tmpdir(), "dca-php-reference-"));
const adapterCopy = join(referenceRoot, "test-bridges/php");
mkdirSync(adapterCopy, { recursive: true });
cpSync(join(bridgeDirectory, "adapter.php"), join(adapterCopy, "adapter.php"));
cpSync(join(bridgeDirectory, "src"), join(adapterCopy, "src"), { recursive: true });
writeFileSync(join(referenceRoot, "values.js"), "");
test.after(() => rmSync(referenceRoot, { recursive: true, force: true }));

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

testBridgeValues(
  defineBridge({
    id: "php",
    adapter: join(adapterCopy, "adapter.php"),
    command: "php",
    targetRoot: fileURLToPath(new URL("./fixtures/", import.meta.url)),
  }),
  {
    sourceModule: "values.js",
    ...(phpMissing ? { skip: "php not on PATH" } : {}),
  },
);

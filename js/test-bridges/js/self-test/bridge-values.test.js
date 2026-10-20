import { fileURLToPath } from "node:url";

import { defineBridge } from "../../_shared/bridge-definition.mjs";
import { testBridgeValues } from "../../_shared/bridge-values/suite.mjs";

// js-loopback runs this same adapter with the reference as its root, so this
// entry covers it too.
testBridgeValues(
  defineBridge({
    id: "js",
    adapter: fileURLToPath(new URL("../adapter.mjs", import.meta.url)),
    targetRoot: fileURLToPath(new URL("./fixtures/", import.meta.url)),
  }),
  { sourceModule: "values.mjs" },
);

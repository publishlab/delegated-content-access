import { fileURLToPath } from "node:url";

import { defineBridge } from "../_shared/bridge-definition.mjs";
import { refuseObsoleteVariables } from "../_shared/environment.mjs";
import { startBridge } from "../_shared/register.mjs";

refuseObsoleteVariables();
const targetRoot = process.env.DCA_TARGET_ROOT;
if (targetRoot === undefined || targetRoot === "")
  throw new Error("the php bridge needs DCA_TARGET_ROOT, the root of the PHP test target");
// The adapter inherits this environment, so DCA_TARGET_NAMESPACE and the
// attribute settings DCA_PHP_MODULE_ATTRIBUTE, DCA_PHP_EXPORT_ATTRIBUTE and
// DCA_PHP_RETURN_TYPE_ATTRIBUTE reach it unchanged; the adapter checks them.
export const bridge = defineBridge({
  id: "php",
  adapter: fileURLToPath(new URL("./adapter.php", import.meta.url)),
  targetRoot,
  command: process.env.DCA_PHP ?? "php",
});
// The publisher declares the issuer argument unused; it is not part of this
// operation's output and need not cross the JSON bridge.
export const activeBridge = await startBridge(bridge, {
  ignoredArguments: [
    {
      module: "core-publisher/issuerSupplyPlan.js",
      export: "wholeRenderIssuerSupplyPlan",
      argument: 0,
    },
  ],
});

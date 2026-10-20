import { fileURLToPath } from "node:url";

import { defineBridge } from "../_shared/bridge-definition.mjs";
import { refuseObsoleteVariables } from "../_shared/environment.mjs";
import { startBridge } from "../_shared/register.mjs";

refuseObsoleteVariables();
const targetRoot = process.env.DCA_TARGET_ROOT;
if (targetRoot === undefined || targetRoot === "")
  throw new Error(
    "the js bridge needs DCA_TARGET_ROOT, the root of the JavaScript test target; DCA_BRIDGE=js-loopback runs the reference instead",
  );
export const bridge = defineBridge({
  id: "js",
  adapter: fileURLToPath(new URL("./adapter.mjs", import.meta.url)),
  targetRoot,
});
// `node --import=... --test ...` keeps every ordinary Node selector intact.
export const activeBridge = await startBridge(bridge);

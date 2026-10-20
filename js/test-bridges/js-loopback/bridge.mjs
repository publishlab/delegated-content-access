import { fileURLToPath } from "node:url";

import { defineBridge } from "../_shared/bridge-definition.mjs";
import { startBridge } from "../_shared/register.mjs";

// The js adapter with the reference (js/) as its test target. This run
// checks the bridge, not an implementation. To test your own JavaScript
// implementation, copy this file and change targetRoot to your tree.
export const bridge = defineBridge({
  id: "js-loopback",
  adapter: fileURLToPath(new URL("../js/adapter.mjs", import.meta.url)),
  targetRoot: fileURLToPath(new URL("../../", import.meta.url)),
});
export const activeBridge = await startBridge(bridge);

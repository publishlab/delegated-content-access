import { pathToFileURL } from "node:url";

import { bridgeModule } from "./run-support.mjs";

// DCA_BRIDGE is an installed bridge id or a path to a bridge module.
const bridge = process.env.DCA_BRIDGE;
if (bridge === undefined || bridge === "")
  throw new Error("DCA_BRIDGE names an installed bridge or a path to a bridge module");

await import(pathToFileURL(bridgeModule(bridge, process.cwd())).href);

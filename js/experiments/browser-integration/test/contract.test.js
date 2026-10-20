// @ts-check
// Thin selection of the independently reusable participant contracts.

import { registerContracts } from "../test-lib/contract.js";
import { installRegistry } from "../implementation/registry.js";
import { createContentHandler } from "../implementation/content-handler.js";
import { createContextSource } from "../implementation/context-source.js";
import { createAccountSource } from "../implementation/account-source.js";
import { createContextHost } from "../test-lib/context-host.js";
import { createAccountMenu } from "../test-lib/account-menu.js";

// Suppress optional diagnostics to prove shared cases require behavior, not
// this implementation's reason/error spellings. Unit tests cover its diagnostics.
/** @returns {import("../types/content-handler.js").ContentHandler} */
function diagnosticFreeHandler() {
  const handler = createContentHandler();
  return {
    connect(setup) {
      const connection = handler.connect(setup);
      return {
        async handleContent(content) {
          const outcomes = await connection.handleContent(content);
          return Object.fromEntries(
            Object.entries(outcomes).map(([name, outcome]) => [name, { status: outcome.status }]),
          );
        },
        dispose: connection.dispose,
      };
    },
  };
}

registerContracts({
  createRegistry: installRegistry,
  createContentHandler: diagnosticFreeHandler,
  createContextSource,
  createContextHost,
  createAccountSource,
  createAccountMenu,
});

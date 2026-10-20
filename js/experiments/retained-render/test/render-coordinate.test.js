// @ts-check

import * as keySealing from "../../../core-shared--publisher-issuer/keySealing.js";
import { registerRetainedRenderSuite } from "../test-lib/suites/retained-render.js";

registerRetainedRenderSuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.open,
    binding: ({ renderId, accessGroup, t }) => ({ renderId, accessGroup, t, chainKey: false }),
  },
  targetLabel: "render-coordinate BIND (control)",
  movedValueOutcome: "refused",
});

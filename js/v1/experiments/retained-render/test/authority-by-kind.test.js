// @ts-check

import * as keySealing from "../../_implementation/bind-on-authority/keySealing.js";
import { registerRetainedRenderSuite } from "../test-lib/suites/retained-render.js";

registerRetainedRenderSuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.unseal,
    binding: ({ publisher, accessGroup, t }) => ({ publisher, accessGroup, t, periodChain: false }),
  },
  targetLabel: "authority-by-kind BIND",
});

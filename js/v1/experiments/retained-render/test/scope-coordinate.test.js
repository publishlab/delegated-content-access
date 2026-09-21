// @ts-check

import * as keySealing from "../../_implementation/bind-on-accessGroup/keySealing.js";
import { registerRetainedRenderSuite } from "../test-lib/suites/retained-render.js";

registerRetainedRenderSuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.unseal,
    binding: ({ accessGroup }) => ({ accessGroup }),
  },
  targetLabel: "scope-coordinate BIND",
});

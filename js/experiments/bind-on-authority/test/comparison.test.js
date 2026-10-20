// @ts-check
//
// Candidate authority BIND. Every comparison outcome is pinned here.

import * as keySealing from "../../_implementation/bind-on-authority/keySealing.js";
import { registerPeriodBindingAuthoritySuite } from "../test-lib/suites/period-binding-authority.js";

registerPeriodBindingAuthoritySuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.unseal,
    binding: ({ publisher, accessGroup, t, chainKey }) => ({
      publisher,
      accessGroup,
      t,
      chainKey,
    }),
  },
  targetLabel: "publisher/group/period/kind authority candidate",
  classifiedOutcomes: {
    "period-key/cross-render": "accepted",
    "period-key/publisher": "refused",
    "period-key/accessGroup": "refused",
    "period-key/t": "refused",
    "chain-key/cross-render": "accepted",
    "chain-key/publisher": "refused",
    "chain-key/accessGroup": "refused",
    "chain-key/t": "refused",
    "kind/period-key-as-chain-key": "refused",
    "kind/chain-key-as-period-key": "refused",
  },
});

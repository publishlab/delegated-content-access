// @ts-check
//
// Candidate authority BIND. Every comparison outcome is pinned here.

import * as keySealing from "../../_implementation/bind-on-authority/keySealing.js";
import { registerPeriodBindingAuthoritySuite } from "../test-lib/suites/period-binding-authority.js";

registerPeriodBindingAuthoritySuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.unseal,
    binding: ({ publisher, accessGroup, t, periodChain }) => ({
      publisher,
      accessGroup,
      t,
      periodChain,
    }),
  },
  targetLabel: "publisher/group/period/kind authority candidate",
  classifiedOutcomes: {
    "exact/cross-render": "accepted",
    "exact/publisher": "refused",
    "exact/accessGroup": "refused",
    "exact/t": "refused",
    "chain/cross-render": "accepted",
    "chain/publisher": "refused",
    "chain/accessGroup": "refused",
    "chain/t": "refused",
    "kind/exact-as-chain": "refused",
    "kind/chain-as-exact": "refused",
  },
});

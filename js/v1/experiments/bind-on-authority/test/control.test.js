// @ts-check
//
// The shipped BIND serves as the control. It binds each publisher-sealed value
// to its render while the delivered period key remains reusable. The publisher-only
// fixture deliberately holds renderId and issuer keyset constant.

import * as keySealing from "../../../core-shared--publisher-issuer/keySealing.js";
import { registerPeriodBindingAuthoritySuite } from "../test-lib/suites/period-binding-authority.js";

registerPeriodBindingAuthoritySuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.open,
    // The shipped chain kind binds its resolved geometry, so the adapter
    // supplies one geometry for every chain case here. The comparison is
    // about the coordinate fields, and every case holds the geometry fixed.
    binding: ({ renderId, accessGroup, t, periodChain }) =>
      periodChain
        ? {
            renderId,
            accessGroup,
            suppliedT: `${t}00`,
            periodChain,
            chainsPerDay: 2,
            periodMinutes: 15,
          }
        : { renderId, accessGroup, t, periodChain },
  },
  targetLabel: "shipped render-coordinate BIND (control)",
  classifiedOutcomes: {
    "exact/cross-render": "refused",
    "exact/publisher": "accepted",
    "exact/accessGroup": "refused",
    "exact/t": "refused",
    "chain/cross-render": "refused",
    "chain/publisher": "accepted",
    "chain/accessGroup": "refused",
    "chain/t": "refused",
    "kind/exact-as-chain": "refused",
    "kind/chain-as-exact": "refused",
  },
});

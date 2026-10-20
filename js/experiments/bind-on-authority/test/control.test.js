// @ts-check
//
// The shipped BIND serves as the control. It binds each publisher-sealed value
// to its render while the delivered period key remains reusable. The publisher-only
// fixture deliberately holds renderId and issuer keyset constant as a primitive
// stress probe, not as a permitted isolation setup for mutually untrusted publishers.

import * as keySealing from "../../../core-shared--publisher-issuer/keySealing.js";
import { registerPeriodBindingAuthoritySuite } from "../test-lib/suites/period-binding-authority.js";

registerPeriodBindingAuthoritySuite({
  target: {
    seal: keySealing.seal,
    open: keySealing.open,
    // The shipped chain kind binds its resolved geometry, so the adapter
    // supplies one geometry for every chain case here. The comparison is
    // about the coordinate fields, and every case holds the geometry fixed.
    binding: ({ renderId, accessGroup, t, chainKey }) =>
      chainKey
        ? {
            renderId,
            accessGroup,
            suppliedT: t,
            chainKey,
            chainsPerDay: 2,
            periodMinutes: 15,
          }
        : { renderId, accessGroup, t, chainKey },
  },
  targetLabel: "shipped render-coordinate BIND (control)",
  classifiedOutcomes: {
    "period-key/cross-render": "refused",
    "period-key/publisher": "accepted",
    "period-key/accessGroup": "refused",
    "period-key/t": "refused",
    "chain-key/cross-render": "refused",
    "chain-key/publisher": "accepted",
    "chain-key/accessGroup": "refused",
    "chain-key/t": "refused",
    "kind/period-key-as-chain-key": "refused",
    "kind/chain-key-as-period-key": "refused",
  },
});

# Scenario rigs and stories

This directory currently holds both the reusable browser-world rig and the
stories that run on it.

- `world.js` creates a valid starting deployment: actors, keys, clocks,
  network, storage, publisher, issuer endpoints, and browser. Its exported
  families are reusable rigs that a scenario builds on. It also currently
  holds the direct-endpoint test rig; the shared provisioning helpers live in
  `../support/provisioning.js` and are re-exported here for existing callers.
- A scenario takes a fresh world, changes state over time, and records the
  outcomes. It may call the world factory itself. It may change entitlement,
  availability, time, session, or rendered page; it does not recreate DCA
  protocol behavior.
- An actor holds its own state and behavior, the world factory wires the actors
  together, and a scenario drives them.

When someone adds a second reusable world, create `demo/worlds/`, split the
browser rig to `browser.js`, and add `edge.js`. Move the direct-endpoint rig to
`test-lib`; place the shared provisioning where its real consumers import it
from. Do not put edge access, crypto, or policy behavior into a scenario.

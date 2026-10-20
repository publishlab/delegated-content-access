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

Reusable application entry points live in `../../integration-client/`,
`../../integration-issuer/` and `../../integration-publisher/`. A demo world
composes those roles with example state; it is not an SDK assembly API.
Extract a neutral helper only when a concrete consumer needs the shared
assembly. Keep edge access, crypto and policy behavior out of scenario stories.

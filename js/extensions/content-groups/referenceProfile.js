// @ts-check

// The reference content-groups composition, for a host that selects
// `dca-profile-content-groups` on every role. It holds no state and adds no
// behavior: each member is the extension's own role entry, so a host composes
// the same publisher, issuer and client a hand-built composition would.
//
// - The publisher half is a `createPublisher` contribution: connectors per
//   item and the per-issuer seed
//   envelopes.
// - The issuer half is a `createIssuerCore` contribution: request bounds before
//   signature verification and the `contentGroupKeys` response section.
// - The client half is `createContentGroupClient`: two dedicated caches the
//   host builds through the factories it passes, the recovery source, the
//   `contentGroupKeys` response consumer and the request builder, with the two
//   `composeClient` members ready in `composeOptions`.
// - Client-bound transport takes the extension's two derivation kinds. The
//   host settles `kindDescriptors` with its selected transport's
//   `settleKindDescriptors`; the host selects transport independently of this
//   extension's required chain-key implementation dependency, and
//   hands the settled set to `keyDeliveryMembers` for the issuer's
//   `KeyDelivery` and to `capabilityOptions` for the client capability. The
//   issuer members always carry every content-group response section, so a
//   client-bound response never carries a content-group key unwrapped.
//
// This file imports every role. A browser build imports
// `core-client/client.js` directly, as the chain-keys profile's client half
// is imported, so the client walk reaches no publisher or issuer module.

import { dcaError } from "../../core-shared/errors.js";
import { CONTRACT } from "./core-shared/construction.js";
import { KIND_DESCRIPTORS, RESPONSE_SECTIONS } from "./core-shared--client-issuer/request.js";
import { contentGroupsPublisherContribution } from "./core-publisher/publish.js";
import { contentGroupsIssuerContribution } from "./core-issuer/unlock.js";
import { createContentGroupClient } from "./core-client/client.js";

/**
 * The host's settled kind set must carry both content-group kinds exactly as
 * this extension declares them. A set without them would let a transport wrap
 * nothing under these kinds; an unfrozen set is no settled set.
 *
 * @param {unknown} composedKinds
 * @returns {Readonly<Record<string, Readonly<{ width: number, open: string }>>>}
 */
function settledContentGroupKinds(composedKinds) {
  if (
    composedKinds === null ||
    typeof composedKinds !== "object" ||
    Array.isArray(composedKinds) ||
    !Object.isFrozen(composedKinds)
  )
    throw dcaError("bad_config", "content groups take the transport's settled kind set");
  const kinds = /** @type {Record<string, any>} */ (composedKinds);
  for (const [kind, { width, open }] of Object.entries(KIND_DESCRIPTORS)) {
    const held = Object.hasOwn(kinds, kind) ? kinds[kind] : undefined;
    if (held?.width !== width || held?.open !== open)
      throw dcaError(
        "bad_config",
        `the settled kind set needs ${kind} as { width: ${width}, open: "${open}" }`,
      );
  }
  return kinds;
}

/**
 * The selected content-groups composition.
 *
 * - `profile`, `construction`: the profile and construction identifiers.
 * - `responseSections`, `kindDescriptors`: the client-bound transport table
 *   and the two derivation kinds, each opening to 16 raw bytes.
 * - `publisherContribution(options)`: see `core-publisher/publish.js`.
 * - `issuerContribution(options)`: see `core-issuer/unlock.js`.
 * - `client(config)`: see `core-client/client.js`.
 * - `keyDeliveryMembers(composedKinds)`: `{ composedSections, composedKinds }`
 *   for the issuer's `KeyDelivery`.
 * - `capabilityOptions(composedKinds)`: `{ composedKinds }` for the client's
 *   `clientBoundKeyCapability`.
 */
export const contentGroupsProfile = Object.freeze({
  profile: CONTRACT.profile,
  construction: CONTRACT.construction,
  responseSections: RESPONSE_SECTIONS,
  kindDescriptors: KIND_DESCRIPTORS,
  publisherContribution: contentGroupsPublisherContribution,
  issuerContribution: contentGroupsIssuerContribution,
  client: createContentGroupClient,
  /**
   * @param {Readonly<Record<string, Readonly<{ width: number, open: string }>>>} composedKinds -
   *   the transport-settled set that includes `kindDescriptors`
   */
  keyDeliveryMembers(composedKinds) {
    return Object.freeze({
      composedSections: RESPONSE_SECTIONS,
      composedKinds: settledContentGroupKinds(composedKinds),
    });
  },
  /**
   * @param {Readonly<Record<string, Readonly<{ width: number, open: string }>>>} composedKinds -
   *   the transport-settled set that includes `kindDescriptors`
   */
  capabilityOptions(composedKinds) {
    return Object.freeze({ composedKinds: settledContentGroupKinds(composedKinds) });
  },
});

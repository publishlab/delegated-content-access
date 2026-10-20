// @ts-check
//
// This module builds the onboarding table a world hands its issuer, from the
// signing keys that world drew. Two scenario builders stand issuers up and both
// need the same table, so the assembly lives here beside `PublisherRegistrations`
// rather than inside either of them.
//
// This module only composes: no clock, no network, no actor, and no protocol
// behavior. It returns a `PublisherRegistrations`, the issuer application's own
// onboarding state.

import { PublisherRegistrations } from "./PublisherRegistrations.js";

/**
 * One canonical browser origin for the demo's historical host-shaped fixture
 * values. Public protocol data never contains this conversion.
 *
 * @param {string} host
 */
export function originForHost(host) {
  return host.includes("://") ? host : `https://${host}`;
}

/**
 * The issuer's onboarding table for these publishers. A registration holds a
 * kid, its verification key and the opening-key view it may address; the origin a
 * render is delivered from comes out of the render's own resourceJWT, so
 * onboarding needs none.
 *
 * `origins` turns the optional issuer-held limit on, the way a deployment would
 * run it as defense in depth.
 *
 * @param {Record<string, Record<string, CryptoKey>>} keys - host -> kid -> public key
 * @param {{ get: Function }} openingKeys
 * @param {{ origins?: boolean }} [limit]
 */
export function publisherRegistrationsOver(keys, openingKeys, limit = {}) {
  const entries = [];
  for (const host of Object.keys(keys)) {
    for (const kid of Object.keys(keys[host])) {
      entries.push({
        kid,
        publicKey: keys[host][kid],
        openingKeys,
        ...(limit.origins === true ? { origins: [originForHost(host)] } : {}),
      });
    }
  }
  return new PublisherRegistrations(entries);
}

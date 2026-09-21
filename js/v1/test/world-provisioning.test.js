// @ts-check
//
// What the two documented scenario builders onboard, before anything crosses a
// wire. A world's issuer holds one registration per (domain, kid) it was
// configured with, and that registration carries a kid, the public half of
// exactly that pair's signing key, an optional origin limit and the opening-key
// view the publisher may address.
//
// Onboarding leaves the origin limit off unless a scenario asks for it, because
// the origin a render is delivered from is the one the publisher signed into its
// resourceJWT. `registrationOrigins` turns the optional issuer-held limit on,
// and then the limit is the domain's own origin: the host as written when it
// already names a scheme, and `https://` in front of it when it does not.
//
// The opening-key view scopes what a registration reaches. Every registration
// addresses its issuer's keys through `openingKeysOver`, so a coordinate outside
// the view misses without the private-key store being reached at all.
// `reachCount` shows that: a miss that consulted the store and a miss that
// never got there produce the same `undefined`, and only the count tells them
// apart.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { actorWorld, directWorld } from "../demo/scenarios/world.js";
import {
  ALGORITHM,
  DOMAIN,
  FALLBACK_ISSUER_NAME,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
} from "../demo/scenarios/fixtures.js";

/** A second host, so a world holds two domains with a kid apiece. */
const OTHER_DOMAIN = "other-publisher.example";

/** A host written with its scheme; the origin a registration lists keeps it. */
const SCHEME_DOMAIN = "http://www-default.localhost";

const KIDS = {
  [DOMAIN]: ["sign-home-1", "sign-home-2"],
  [OTHER_DOMAIN]: ["sign-other-1"],
  [SCHEME_DOMAIN]: ["sign-local-1"],
};

/**
 * Every (domain, kid) a world holding `KIDS` was configured with.
 *
 * @returns {{ domain: string, kid: string }[]}
 */
function configuredPairs() {
  return Object.entries(KIDS).flatMap(([domain, kids]) => kids.map((kid) => ({ domain, kid })));
}

/**
 * What one world onboarded: the registration filed under each configured kid,
 * checked against the keypair that world drew for it.
 *
 * @param {any} world
 * @param {{ origins: boolean }} expected - whether the optional limit is on
 * @returns {void}
 */
function assertRegistrations(world, expected) {
  for (const { domain, kid } of configuredPairs()) {
    const registration = world.publisherRegistrations.get(kid);
    assert.ok(registration, `${domain} kid ${kid} is registered`);
    assert.equal(registration.kid, kid);
    assert.equal(
      registration.publicKey,
      world.signingKeyPairs[domain][kid].publicKey,
      `${kid} verifies with the public half of its own pair, not another domain's`,
    );
    if (expected.origins) {
      assert.deepEqual(
        registration.origins,
        [domain.includes("://") ? domain : `https://${domain}`],
        `${kid} lists exactly the origin its domain is served from`,
      );
    } else {
      assert.equal(registration.origins, undefined, `${kid} onboards without an origin limit`);
    }
  }

  const views = new Set(
    configuredPairs().map(({ kid }) => world.publisherRegistrations.get(kid).openingKeys),
  );
  assert.equal(views.size, 1, "one issuer holds one opening-key view over all its registrations");
  assert.equal(world.publisherRegistrations.get("sign-never-onboarded"), undefined);
}

/**
 * The reach one registration's opening-key view has into the store behind it:
 * the issuer's own coordinate answers, and everything else misses without the
 * private-key store being consulted.
 *
 * @param {any} registration
 * @param {{ reachCount: number }} keyStore
 * @returns {void}
 */
function assertOpeningKeyReach(registration, keyStore) {
  const before = keyStore.reachCount;

  const held = registration.openingKeys.get(ISSUER_NAME, KEY_ID);
  assert.equal(held?.algorithm, ALGORITHM);
  assert.ok(held?.privateKey, "the issuer opens with the key it holds at its own coordinate");
  assert.equal(
    keyStore.reachCount,
    before + 1,
    "an allowed coordinate reaches the store exactly once",
  );
  assert.equal(registration.openingKeys.allows(ISSUER_NAME, KEY_ID), true);

  const reached = keyStore.reachCount;
  for (const [issuerName, keyId] of [
    [ISSUER_NAME, "a-key-this-issuer-never-held"],
    [FALLBACK_ISSUER_NAME, KEY_ID],
    [FALLBACK_ISSUER_NAME, "a-key-this-issuer-never-held"],
  ]) {
    assert.equal(
      registration.openingKeys.get(issuerName, keyId),
      undefined,
      `${issuerName}/${keyId} is outside this registration's view`,
    );
    assert.equal(registration.openingKeys.allows(issuerName, keyId), false);
  }
  assert.equal(
    keyStore.reachCount,
    reached,
    "a coordinate outside the view never reaches the private-key store",
  );
}

describe("scenario-world provisioning", () => {
  test("actorWorld onboards the default world under one kid and one keypair", async () => {
    const world = await actorWorld();
    const registration = world.publisherRegistrations.get(SIGNING_KID);

    assert.equal(world.publisherRegistration, registration);
    assert.equal(registration.kid, SIGNING_KID);
    assert.equal(registration.publicKey, world.signingKeyPairs[DOMAIN][SIGNING_KID].publicKey);
    assert.equal(registration.origins, undefined);
    assertOpeningKeyReach(registration, world.keyStores.primary);
  });

  test("actorWorld registers every configured domain kid, with no origin limit unless asked", async () => {
    assertRegistrations(await actorWorld({ signingKids: KIDS }), { origins: false });
    assertRegistrations(await actorWorld({ signingKids: KIDS, registrationOrigins: true }), {
      origins: true,
    });
  });

  test("an actorWorld registration reaches only its own issuer coordinate", async () => {
    const world = await actorWorld({ fallback: true, signingKids: KIDS });

    assertOpeningKeyReach(
      world.publisherRegistrations.get(KIDS[DOMAIN][0]),
      world.keyStores.primary,
    );
    assert.equal(
      world.keyStores.fallback.reachCount,
      0,
      "the primary's registrations never address the fallback issuer's store",
    );
  });

  test("directWorld onboards the same registrations over its single issuer", async () => {
    const world = await directWorld();
    const registration = world.publisherRegistrations.get(SIGNING_KID);

    assert.equal(world.publisherRegistration, registration);
    assert.equal(registration.kid, SIGNING_KID);
    assert.equal(registration.publicKey, world.signingKeyPairs[DOMAIN][SIGNING_KID].publicKey);
    assert.equal(registration.origins, undefined);
    assertOpeningKeyReach(registration, world.keyStore);
  });

  test("directWorld registers every configured domain kid without an origin limit", async () => {
    const world = await directWorld({ signingKids: KIDS });

    assertRegistrations(world, { origins: false });
    assertOpeningKeyReach(world.publisherRegistrations.get(KIDS[OTHER_DOMAIN][0]), world.keyStore);
  });
});

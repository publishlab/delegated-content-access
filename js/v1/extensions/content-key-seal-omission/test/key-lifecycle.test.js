// @ts-check
//
// What a keyId this issuer never held, and one it has let go of, do to the
// bound route, and which sources either of them may reach.
//
// The two are separate events. A keyId this issuer never held marks a request
// that came to the wrong door: it is refused whole, before any coordinate is
// walked. A retired one ends a rollover in the ordinary way: the envelope is
// intact and the only thing wrong is that the markup outlived the key, so every
// coordinate the decision granted comes back as an error beside a 200.
//
// The bound route adds a question base does not have: an injected leaf source
// is material this issuer can produce without the retired key, so a route that
// asked it anyway would answer a content key under a key this issuer no longer
// holds. It does not ask it, and the tests below hold it to that.
//
// Source material follows the publisher's registration. Two registered
// publishers may use the same access group and the same period label, so which
// leaf view a request reaches is selected from application state keyed by the
// authenticated registration. `publisher-isolation.test.js` proves that,
// against two publishers with separate opening keysets and a copied candidate.
// This file adds the other half: the view held for a registration is not
// reached at all once the keyId is retired.

import test from "node:test";
import assert from "node:assert/strict";

import { Random } from "../../../demo/actors/Random.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { exactPeriodKeySupply } from "../../../demo/support/exactPeriodKeySupply.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import {
  ISSUER_A,
  KEY_ID,
  PERIODS,
  PUB,
  SIGNING_KID,
  contentOnlyPolicy,
  render,
  world,
} from "../test-lib/world.js";

const { subtle } = globalThis.crypto;

/** A second publisher's own delivery origin and signing kid. */
const OTHER_PUB = "https://www.other-site.example";
const OTHER_KID = "sign-other-2025-10";

/**
 * One active-issuer render and the request a client builds from it.
 *
 * @param {{ items?: string[] }} [options]
 */
async function activeRender(options = {}) {
  const { issuerConfig, periodKeySupply, registration, sealerConfig, keyStoreFor } = await world();
  const page = await render(
    new OmittingSealer(
      sealerConfig({
        issuers: [issuerConfig(ISSUER_A, { extensions: [EXTENSION_NAME] })],
      }),
    ),
    { items: options.items ?? ["bodytext"] },
  );

  const request = new OmissionRequestBuilder({ relayExactPeriod: true }).build(
    new DcaData(page, { publisherOrigin: PUB }),
    ISSUER_A,
    options.items ?? ["bodytext"],
  );

  return { page, request, registration, periodKeySupply, keyStoreFor, options };
}

/**
 * The same registration, over a key store that answers one fixed way for this
 * issuer's keyId. `undefined` is a keyId never held; `{ retired: true }` is one
 * held and let go.
 *
 * @param {any} registration
 * @param {any} answer
 */
function registrationAnswering(registration, answer) {
  return {
    ...registration,
    kid: registration.kid,
    publicKey: registration.publicKey,
    openingKeys: { get: () => answer },
  };
}

/**
 * Count each guarded stage on the bound route without changing what that
 * stage answers. The authorized control below proves every counter is wired
 * to a route that can actually be reached.
 *
 * @param {any} registration
 * @param {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }} periodKeySupply
 * @param {(claims: any, requested: any) => any} decide
 */
function observedRoute(registration, periodKeySupply, decide) {
  const calls = { policy: 0, openingStore: 0, leafView: 0, leafMaterial: 0 };
  const observedRegistration = {
    ...registration,
    kid: registration.kid,
    publicKey: registration.publicKey,
    openingKeys: {
      get(issuerName, keyId) {
        calls.openingStore += 1;
        return registration.openingKeys.get(issuerName, keyId);
      },
    },
  };
  const exactPeriodLeaves = {
    get(selectedRegistration) {
      calls.leafView += 1;
      assert.strictEqual(selectedRegistration, observedRegistration);
      return (accessGroup, t) => {
        calls.leafMaterial += 1;
        return periodKeySupply.derive(accessGroup, t);
      };
    },
  };
  const accessPolicy = {
    decide(claims, requested) {
      calls.policy += 1;
      return decide(claims, requested);
    },
  };

  return {
    calls,
    registration: observedRegistration,
    engine: omissionIssuerEngine({ accessPolicy, exactPeriodLeaves }),
  };
}

test("an invalid signature reaches none of the bound route decision or key stages", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const policy = contentOnlyPolicy(["bodytext"]);
  const {
    calls,
    registration: observedRegistration,
    engine,
  } = observedRoute(registration, periodKeySupply, (claims, requested) =>
    policy.decide(claims, requested),
  );

  const document = request.toObject();
  const [header, payload, signature] = document.resourceJWT.split(".");
  const flipped = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  document.resourceJWT = `${header}.${payload}.${flipped}`;

  await assert.rejects(
    engine.unlock(request, observedRegistration),
    (/** @type {any} */ error) => error.code === "bad_signature",
  );
  assert.deepEqual(calls, { policy: 0, openingStore: 0, leafView: 0, leafMaterial: 0 });
});

test("a complete denial reaches policy once and none of the bound key stages", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const {
    calls,
    registration: observedRegistration,
    engine,
  } = observedRoute(registration, periodKeySupply, () => ({}));

  await assert.rejects(
    engine.unlock(request, observedRegistration),
    (/** @type {any} */ error) => error.code === "denied",
  );
  assert.deepEqual(calls, { policy: 1, openingStore: 0, leafView: 0, leafMaterial: 0 });
});

test("an authorized bound request reaches each guarded decision and key stage once", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const policy = contentOnlyPolicy(["bodytext"]);
  const {
    calls,
    registration: observedRegistration,
    engine,
  } = observedRoute(registration, periodKeySupply, (claims, requested) =>
    policy.decide(claims, requested),
  );

  const result = await engine.unlock(request, observedRegistration);

  assert.equal(typeof result.contentKeys.bodytext, "string");
  assert.deepEqual(result.errors, {});
  assert.deepEqual(calls, { policy: 1, openingStore: 1, leafView: 1, leafMaterial: 1 });
});

test("one selected leaf is asked once when two granted items share a coordinate", async () => {
  const { request, registration, periodKeySupply } = await activeRender({
    items: ["bodytext", "note"],
  });
  /** @type {object[]} */
  const selected = [];
  /** @type {{ accessGroup: string, t: string }[]} */
  const asked = [];
  const exactPeriodLeaves = {
    get(selectedRegistration) {
      selected.push(selectedRegistration);
      return async (accessGroup, t) => {
        asked.push({ accessGroup, t });
        return periodKeySupply.derive(accessGroup, t);
      };
    },
  };
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext", "note"]),
    exactPeriodLeaves,
  });

  const result = await engine.unlock(request, registration);

  assert.deepEqual(Object.keys(result.contentKeys), ["bodytext", "note"]);
  assert.deepEqual(
    selected,
    [registration],
    "the authenticated registration selects one leaf view per unlock",
  );
  assert.deepEqual(asked, [{ accessGroup: "premium", t: PERIODS[0] }]);
});

test("a keyId this issuer never held refuses the whole request, bound route included", async () => {
  const { request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
  });

  await assert.rejects(
    engine.unlock(request, registrationAnswering(registration, undefined)),
    (/** @type {any} */ error) => error.code === "unknown_key",
  );
});

test("a retired keyId answers the bound item as one per-item failure beside a 200", async () => {
  const { request, registration } = await activeRender();
  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
  });

  const result = await engine.unlock(
    request,
    registrationAnswering(registration, { retired: true }),
  );

  // Every granted coordinate answers the rollover, and it answers it in one
  // wording: the key this render was sealed to is gone, which is what the
  // client's next render will fix.
  assert.deepEqual(result.contentKeys, {});
  assert.deepEqual(result.errors, {
    bodytext: {
      error: "key_retired",
      message: 'keyId "2025-10" is retired and this issuer no longer holds it',
    },
  });
});

test("a retired keyId asks no injected leaf source for material", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const retiredRegistration = registrationAnswering(registration, { retired: true });

  /** @type {[string, string][]} */
  const asked = [];
  /** @type {WeakMap<object, (accessGroup: string, t: string) => Promise<Uint8Array>>} */
  const exactPeriodLeaves = new WeakMap();
  exactPeriodLeaves.set(retiredRegistration, (accessGroup, t) => {
    asked.push([accessGroup, t]);
    return periodKeySupply.derive(accessGroup, t);
  });

  const engine = omissionIssuerEngine({
    accessPolicy: contentOnlyPolicy(["bodytext"]),
    exactPeriodLeaves,
  });

  const result = await engine.unlock(request, retiredRegistration);

  // The leaf this issuer holds for that registration would have opened the
  // item. A retired keyId ends this issuer's reach into the render, so the
  // view is never asked for one.
  assert.deepEqual(asked, []);
  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "key_retired");
});

test("a retired keyId selects neither a source scope nor source material", async () => {
  const { request, registration, periodKeySupply } = await activeRender();
  const retiredRegistration = registrationAnswering(registration, { retired: true });
  const {
    calls,
    registration: observedRegistration,
    engine,
  } = observedRoute(retiredRegistration, periodKeySupply, (claims, requested) =>
    contentOnlyPolicy(["bodytext"]).decide(claims, requested),
  );

  const result = await engine.unlock(request, observedRegistration);

  assert.deepEqual(result.contentKeys, {});
  assert.equal(result.errors.bodytext.error, "key_retired");
  assert.deepEqual(calls, { policy: 1, openingStore: 1, leafView: 0, leafMaterial: 0 });
});

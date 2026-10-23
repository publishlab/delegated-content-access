// Ordinary item routes beside content-group routes on one page, through the
// production roles: the base Sealer seals an ordinary content-key envelope for
// each item the issuer supply plan names, the base issuer answers it under base
// policy, and the same delivery client opens both route kinds.
//
// The retired form took the ordinary envelopes from two host sealing ports
// beside its own publisher. The base Sealer now writes them, so the checks on
// those ports' outputs (malformed maps, unregistered issuers, short blobs, a
// reused argument buffer) have no subject left and are not carried over.
import test from "node:test";
import assert from "node:assert/strict";
import { KeyDelivery } from "../../../adapter-issuer/KeyDelivery.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import * as ecdhMethod from "../../client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../../client-bound-transport/core-client/clientBoundKeyCapability.js";
import { contentGroupsProfile } from "../referenceProfile.js";
import { T18, chainPolicy, claimsOf, copy, item, world } from "./_lib/world.js";
import { connectorsOf, find, issuerBlock, sealedContentKey, seedRecords } from "./_lib/records.js";

const none = () => ({ grants: [], authorizePeriod: () => true });
/** The content names a response section's records carry, each once. */
const names = (records) => [...new Set(records.map(({ contentName }) => contentName))];

// Replaces `connectors: [null]` and the root `contentGroups: ["sports"]`: an
// ordinary-only item carries no connectors member at all.
test("a mixed page opens its connector item and its purchased ordinary item through one client", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("sportsArticle", ["sports"]), item("purchasedArticle")],
    ordinary: ["purchasedArticle"],
  });
  const { page } = published;
  assert.equal(Object.hasOwn(page, "contentGroups"), false);
  const purchased = find(page.contentData, { contentName: "purchasedArticle" });
  assert.equal(Object.hasOwn(purchased, "connectors"), false);
  assert.equal(Object.hasOwn(purchased, "keys"), false);
  assert.deepEqual(
    connectorsOf(page, "sportsArticle").map(({ group }) => group),
    ["sports"],
  );
  assert.equal(typeof sealedContentKey(page, "issuer", "purchasedArticle"), "string");
  assert.deepEqual(
    [...new Set(seedRecords(page, "issuer").map(({ contentName }) => contentName))],
    ["sportsArticle"],
  );
  assert.equal(Object.hasOwn(claimsOf(page.resourceJWT), "contentKeyCommitments"), false);

  const issuer = w.issuer({ purchased: ["purchasedArticle"] });
  const client = w.reader().client(published, issuer);
  const walk = await client.unlock(["sportsArticle", "purchasedArticle"]);
  assert.deepEqual(walk.missing, []);
  const [answer] = issuer.calls.answers;
  assert.deepEqual(names(answer.body.keys.contentKeys), ["purchasedArticle"]);
  assert.deepEqual(names(answer.body.contentGroupKeys.chainKeys), ["sportsArticle"]);
  assert.deepEqual(w.openingLookups, [["issuer", "issuer-k1"]]);
  assert.equal(issuer.calls.decide.length, 1);
  assert.equal(await client.open("sportsArticle"), "content:sportsArticle");
  assert.equal(await client.open("purchasedArticle"), "content:purchasedArticle");
});

test("an item with both routes opens through its ordinary item grant without any chain key", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("sportsArticle", ["sports"])],
    ordinary: ["sportsArticle"],
  });
  // This reader bought only this item; content-group policy grants nothing reusable.
  const issuer = w.issuer({ purchased: ["sportsArticle"], policy: none });
  const reader = w.reader();
  const client = reader.client(published, issuer);
  await client.unlock(["sportsArticle"]);
  const [answer] = issuer.calls.answers;
  assert.deepEqual(names(answer.body.keys.contentKeys), ["sportsArticle"]);
  assert.equal(Object.hasOwn(answer.body, "contentGroupKeys"), false);
  assert.equal(await client.open("sportsArticle"), "content:sportsArticle");
  assert.deepEqual(await reader.chainKeyCache().entries(), []);
  // The other route reaches the very same fresh key.
  const grouped = w.reader().client(published, w.issuer({ purchased: [], policy: chainPolicy() }));
  await grouped.unlock(["sportsArticle"]);
  assert.equal(await grouped.open("sportsArticle"), "content:sportsArticle");
});

// Replaces the ordinary-only issuer without a seed public key: an issuer the
// seed windows leave out receives no seed member, only its ordinary envelopes.
test("an ordinary-only issuer receives no seed, and each render gets a fresh item key", async () => {
  const w = await world();
  const keys = [];
  const renderIds = [];
  for (let i = 0; i < 2; i++) {
    const published = await w.publish({
      items: [item("purchasedArticle")],
      ordinary: ["purchasedArticle"],
      seedWindows: {},
    });
    assert.equal(
      Object.hasOwn(issuerBlock(published.page, "issuer").sealed, "contentWindowSeeds"),
      false,
    );
    const issuer = w.issuer();
    const client = w.reader().client(published, issuer);
    await client.unlock(["purchasedArticle"]);
    assert.equal(await client.open("purchasedArticle"), "content:purchasedArticle");
    keys.push(
      find(issuer.calls.answers[0].body.keys.contentKeys, { contentName: "purchasedArticle" })?.key,
    );
    renderIds.push(claimsOf(published.page.resourceJWT).renderId);
  }
  assert.notEqual(renderIds[0], renderIds[1]);
  assert.notEqual(keys[0], keys[1]);
});

// Replaces the empty ordinary-wrapper ports: an item with neither a seeded
// connector route nor an ordinary envelope has no route, and publishing refuses.
test("an item with no group and no ordinary supply gets no manufactured route", async () => {
  const w = await world();
  for (const groups of [undefined, []])
    await assert.rejects(
      w.publish({ items: [item("purchasedArticle", groups)], ordinary: [] }),
      /route/,
      JSON.stringify(groups),
    );
});

test("base acquisition cannot use another keyId for the ordinary item route", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("sportsArticle", ["sports"]), item("purchasedArticle")],
    ordinary: ["purchasedArticle"],
  });
  const issuer = w.issuer({ purchased: ["purchasedArticle"] });
  const client = w.reader().client(published, issuer);
  await client.unlock(["purchasedArticle"]);
  w.openingLookups.length = 0;
  const otherKey = { ...copy(client.sent[0]), keyId: "issuer-k2" };
  const result = await issuer.answer(otherKey);
  assert.equal(find(result.body.keys?.contentKeys, { contentName: "purchasedArticle" }), undefined);
  assert.deepEqual(w.openingLookups, [["issuer", "issuer-k2"]], "no fallback to issuer-k1");
});

// Replaces the separate base resolver beside the broad client: one resolver
// reads both sections, ignores the stock chain section it did not select and
// still files the content-group answer.
test("an unselected stock chain section leaves the content-group answer usable", async () => {
  const w = await world();
  const published = await w.publish({
    items: [item("sportsArticle", ["sports"]), item("purchasedArticle")],
    ordinary: ["purchasedArticle"],
  });
  const reader = w.reader();
  const client = reader.client(published, w.issuer({ purchased: ["purchasedArticle"] }), {
    answered: (body) => {
      body.keys.chainKeys = [{ accessGroup: "sports", cutoff: T18, key: "unsupported" }];
      return body;
    },
  });
  await client.unlock(["sportsArticle", "purchasedArticle"]);
  assert.equal(await client.open("sportsArticle"), "content:sportsArticle");
  assert.equal(await client.open("purchasedArticle"), "content:purchasedArticle");
  assert.equal((await reader.chainKeyCache().entries()).length, 1);
});

const RETIRED = Object.freeze({ error: "key_retired" });
const random = { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) };
const kinds = ecdhMethod.settleKindDescriptors(contentGroupsProfile.kindDescriptors);

/**
 * The world's issuer core behind an HTTP-like host: admission, client-bound
 * agreement through `KeyDelivery` when `method` is given, then the endpoint
 * under `registration`, which a test retires to model a key rollover.
 */
function hostedIssuer(w, { registration = w.registration, method, purchased } = {}) {
  const issuer = w.issuer({ purchased });
  const delivery =
    method === undefined
      ? null
      : new KeyDelivery({
          random,
          profile: method,
          ...contentGroupsProfile.keyDeliveryMembers(kinds),
        });
  async function answer(document) {
    const admission = issuer.core.processor.admit(new DcaRequest(document));
    assert.equal(admission.kind, "admitted");
    const view = delivery && (await delivery.preflight("client-bound", admission.request));
    const result = await issuer.core.endpoint.handleRequest({
      request: admission.request,
      registration,
    });
    const body =
      result.response.status === 200 && view
        ? await delivery.prepare(result.response.body, view)
        : result.response.body;
    const response = {
      status: result.response.status,
      body: JSON.parse(JSON.stringify(body)),
      code: result.code,
    };
    issuer.calls.answers.push(response);
    return response;
  }
  return { ...issuer, answer };
}
/** The world's registration after its opening key was retired. */
function retiredRegistration(w) {
  return {
    kid: "p1",
    publicKey: w.signing.publicKey,
    openingKeys: { get: () => ({ retired: true }) },
  };
}
async function ecdhCapability() {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"],
  );
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  return clientBoundKeyCapability(
    {
      privateKey: pair.privateKey,
      publicKey: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    },
    ecdhMethod,
    contentGroupsProfile.capabilityOptions(kinds),
  );
}

for (const [label, method] of [
  ["direct", undefined],
  ["client-bound ECDH-P256", ecdhMethod],
]) {
  test(`${label}: a retired opening key reports base and scoped key_retired and files no key`, async () => {
    const w = await world();
    const published = await w.publish({
      items: [item("sportsArticle", ["sports"]), item("purchasedArticle")],
      ordinary: ["purchasedArticle"],
    });
    const names = ["sportsArticle", "purchasedArticle"];
    const capability = method === undefined ? undefined : await ecdhCapability();
    const reader = w.reader();
    const retiredIssuer = hostedIssuer(w, {
      registration: retiredRegistration(w),
      method,
      purchased: ["purchasedArticle"],
    });
    const client = reader.client(published, retiredIssuer, { capability });
    const { status, application } = await client.attempt(names);
    assert.equal(status, 200);
    const [answer] = retiredIssuer.calls.answers;
    assert.equal(answer.status, 200);
    assert.deepEqual(
      find(answer.body.errors, { coordinate: "purchasedArticle" })?.error,
      "key_retired",
    );
    // The source's default connector route is also an authorized alternative;
    // its render-window seed is retired alongside the ordinary purchased key.
    assert.deepEqual(answer.body.contentGroupKeys, {
      errors: {
        chainKeys: [{ contentName: "sportsArticle", group: "sports", cutoff: T18, ...RETIRED }],
        contentKeys: [{ contentName: "sportsArticle", ...RETIRED }],
      },
    });
    if (method !== undefined) assert.equal(answer.body.transport.method, method.METHOD);
    // The client admitted the answer whole: no refused member, no key.
    assert.equal(application.accepted, 0);
    assert.deepEqual(application.issues, []);
    assert.deepEqual(
      application.errors.map(({ message, ...entry }) => entry),
      [
        { coordinate: "purchasedArticle", error: "key_retired" },
        {
          section: "chainKeys",
          contentName: "sportsArticle",
          group: "sports",
          windowStart: "261014T1200",
          t: T18,
          error: "key_retired",
          consumer: "contentGroupKeys",
        },
        {
          section: "contentKeys",
          contentName: "sportsArticle",
          group: "sports",
          error: "key_retired",
          consumer: "contentGroupKeys",
        },
      ],
    );
    for (const name of names) assert.equal(await client.open(name), null, name);

    // Nothing was retained, so after the rollover the next walk asks again,
    // and a reset in between changes nothing.
    await client.delivery.clearReaderContext();
    const healthy = hostedIssuer(w, { method, purchased: ["purchasedArticle"] });
    const next = reader.client(published, healthy, { capability });
    const walk = await next.unlock(names);
    assert.deepEqual(walk.missing, []);
    assert.equal(healthy.calls.answers.length, 1);
    for (const name of names) assert.equal(await next.open(name), `content:${name}`, name);
  });
}

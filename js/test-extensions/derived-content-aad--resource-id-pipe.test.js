// @ts-check
//
// A resourceId may hold `|` now that no transcript joins on it: the content AAD
// length-prefixes its fields and carries the signing input, not the resourceId,
// and BIND does not carry the resourceId (docs/spec--core-protocol.md Section 4.1;
// docs/spec--content-protection.md Section 3.2). The names that do enter a
// `|`-joined BIND grammar keep their refusal: contentName, accessGroup and
// issuerName.
//
// The resourceId below publishes and opens through the ordinary Sealer path and
// the content-groups path over JSON and HTML, and is the exact subject of a
// signed recipient grant. A neighbouring resourceId is a different subject.

import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../core-publisher/Sealer.js";
import { createPublisher } from "../integration-publisher/createPublisher.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { domOver } from "../test-lib/helpers/domOver.js";
import { issuerKeypair, signingKeypair } from "../test-reference/support/keys.js";
import { createRecipientGrantIssuer } from "../extensions/recipient-grant/issuer.js";
import { createRecipientGrantBrowserClient } from "../extensions/recipient-grant/client.js";
import {
  createSignedGrantStore,
  mintSignedRecipientGrant,
} from "../extensions/recipient-grant/signedGrant.js";
import {
  item as groupItem,
  world as groupsWorld,
} from "../extensions/content-groups/test/_lib/world.js";
import { BODY, LOCKED, exchangeWorld } from "./support/derivedContentAadExchanges.js";

const RESOURCE_ID = "news|2026|42";
const NEIGHBOUR_ID = "news|2026|43";

/** @param {Uint8Array} bytes */
const text = (bytes) => new TextDecoder().decode(bytes);

test("a resourceId with | publishes and opens through the ordinary Sealer path over JSON and HTML", async () => {
  for (const carrier of /** @type {const} */ (["json", "html"])) {
    const w = await exchangeWorld({
      route: "period",
      transport: "direct",
      resourceId: RESOURCE_ID,
    });
    const rendered = await w.render();
    assert.equal(rendered.dcaData.resource.resourceId, RESOURCE_ID);
    assert.equal(decodeCompactJwt(rendered.dcaData.resourceJWT).payload.resourceId, RESOURCE_ID);
    const client = w.clientFor(rendered, carrier, await w.readerState());
    const carried = /** @type {any} */ (client.dcaData.resource);
    assert.equal(carried.resourceId, RESOURCE_ID, `${carrier} carried it intact`);
    for (const item of [BODY, LOCKED]) {
      assert.equal(text((await client.open(item.name)).bytes), item.value, carrier);
    }
    assert.equal(w.answers[0].status, 200);
  }
});

test("a resourceId with | publishes and opens through the content-groups path over JSON and HTML", async () => {
  for (const carrier of /** @type {const} */ (["json", "html"])) {
    const w = await groupsWorld();
    const published = await w.publish({
      resourceId: RESOURCE_ID,
      items: [groupItem("bodytext", ["sports"], "match report")],
    });
    const render = { dcaData: published.page, sealedContent: published.sealedContent };
    const publisherOrigin = published.origin;
    const deliveryReader =
      carrier === "json"
        ? new JsonDeliveryReader(writeJsonDelivery(render), { publisherOrigin })
        : new MarkupDeliveryReader(domOver(writeMarkupDelivery(render), { publisherOrigin }));
    const issuer = w.issuer();
    const client = w.reader().client(published, issuer, { deliveryReader });
    assert.deepEqual((await client.unlock(["bodytext"])).missing, [], carrier);
    // The issuer verified the signed resource whose subject is this resourceId.
    assert.equal(issuer.calls.decide[0].claims.resourceId, RESOURCE_ID, carrier);
    assert.equal(await client.open("bodytext"), "match report", carrier);
  }
});

const ORIGIN = "https://publisher.example";
const ISSUER = "selected_issuer";
const UNLOCK = "https://issuer.example/recipient-unlock";
const NOW = Date.parse("2026-10-15T12:00:00Z");
const GRANT_KID = "publisher-share-2026-10";

/** A publisher, a recipient-grant issuer trusting signed grants, and a grant minter. */
async function recipientWorld() {
  const opening = await issuerKeypair();
  const signing = await signingKeypair();
  const grantSigning = await signingKeypair();
  const publisher = createPublisher({
    origin: ORIGIN,
    clock: { now: () => new Date(NOW) },
    random: { bytes: (/** @type {number} */ n) => crypto.getRandomValues(new Uint8Array(n)) },
    signingKeys: { publisher_signing: signing.privateKey },
    issuers: [
      {
        issuerName: ISSUER,
        keyId: "opening_key",
        algorithm: "ecdh-p256",
        publicKey: opening.publicKey,
      },
    ],
    issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ render) => ({
      contentKeyNames: render.contentNames,
      suppliedAccessGroups: render.accessGroups,
    }),
    periodKeySupply: { derive: async () => new Uint8Array(16).fill(9) },
  });
  const registration = {
    registrationId: "publisher-one",
    kid: "publisher_signing",
    publicKey: signing.publicKey,
    openingKeys: {
      allows: (/** @type {string} */ name, /** @type {string} */ id) =>
        name === ISSUER && id === "opening_key",
      get: (/** @type {string} */ name, /** @type {string} */ id) =>
        name === ISSUER && id === "opening_key"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  const issuer = createRecipientGrantIssuer({
    issuerId: ISSUER,
    operatingIssuerNames: [ISSUER],
    grants: /** @type {any} */ (
      createSignedGrantStore({
        keys: {
          [ORIGIN]: {
            [GRANT_KID]: {
              key: grantSigning.publicKey,
              alg: "ES256",
              purpose: "recipient-unlock",
              issuer: "publisher-authority",
              publisher: ORIGIN,
              publisherRegistrationId: "publisher-one",
              maxLifetimeSeconds: 60 * 60 * 24,
            },
          },
        },
        issuerId: ISSUER,
        now: () => NOW,
      })
    ),
    accessPolicy: {
      decide: (/** @type {any} */ _claims, /** @type {any} */ requested) => ({
        contentNames: requested.contentNames,
      }),
    },
    now: () => NOW,
  });
  const http = issuer.browserHttp((/** @type {string} */ origin) => origin === ORIGIN);
  const statuses = /** @type {number[]} */ ([]);
  /** @param {string} _url @param {any} init */
  async function fetch(_url, init) {
    const answer = await http.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: init.body,
      authorization: init.headers.Authorization,
      hostContext: { registration, capturedAtMs: NOW },
    });
    statuses.push(answer.status);
    return {
      status: answer.status,
      headers: { get: () => "application/json" },
      json: async () => answer.body,
    };
  }
  /** @param {string} resourceId */
  async function render(resourceId) {
    const output = await publisher.publish({
      resourceId,
      data: {},
      items: [
        {
          name: "body",
          value: `article ${resourceId}`,
          contentType: "text/plain",
          accessGroups: ["premium"],
        },
      ],
    });
    return domOver(writeMarkupDelivery(output), { publisherOrigin: ORIGIN });
  }
  /** @param {string} sub */
  function mint(sub) {
    const iat = Math.floor(NOW / 1000) - 10;
    return mintSignedRecipientGrant({
      request: { operation: "share" },
      authorize: () => ({ publisher: ORIGIN, sub, contentNames: ["body"], iat, exp: iat + 600 }),
      signer: { kid: GRANT_KID, alg: "ES256", key: grantSigning.privateKey },
    });
  }
  /** @param {any} root @param {string} resourceId @param {string} grant */
  function client(root, resourceId, grant) {
    return createRecipientGrantBrowserClient({
      root,
      issuer: { issuerName: ISSUER, unlockUrl: UNLOCK, publisherOrigin: ORIGIN, resourceId },
      grantReference: grant,
      fetch,
    });
  }
  return { render, mint, client, statuses };
}

/** @param {any} client */
async function openedBody(client) {
  return text(
    await client.opener.open({
      item: client.dcaData.contentItemFor("body"),
      ciphertext: client.reader.extract("body"),
      resolveKey: () => client.resolver.contentKeyFor(client.dcaData, "body"),
    }),
  );
}

test("a resourceId with | is the exact recipient-grant subject; a neighbouring id is another subject", async () => {
  const w = await recipientWorld();
  const page = await w.render(RESOURCE_ID);
  const neighbour = await w.render(NEIGHBOUR_ID);
  const grant = await w.mint(RESOURCE_ID);
  const otherGrant = await w.mint(NEIGHBOUR_ID);
  assert.equal(decodeCompactJwt(grant).payload.sub, RESOURCE_ID);

  const granted = w.client(page, RESOURCE_ID, grant);
  assert.equal(/** @type {any} */ (await granted.unlock(["body"])).status, 200);
  assert.equal(await openedBody(granted), `article ${RESOURCE_ID}`);

  // The neighbour's grant does not apply to this resource, nor this grant to
  // the neighbour's render.
  /** @type {[any, string, string, string][]} */
  const misfits = [
    [page, RESOURCE_ID, otherGrant, "a 43 grant on the 42 render"],
    [neighbour, NEIGHBOUR_ID, grant, "a 42 grant on the 43 render"],
  ];
  for (const [root, resourceId, token, why] of misfits) {
    const refused = w.client(root, resourceId, token);
    const result = /** @type {any} */ (await refused.unlock(["body"]));
    assert.notEqual(result.status, 200, why);
    assert.equal(await refused.resolver.contentKeyFor(refused.dcaData, "body"), null, why);
  }

  assert.deepEqual(w.statuses, [200, 401, 401], "the issuer itself refused both grants");

  // Its own grant opens the neighbour.
  const neighbourClient = w.client(neighbour, NEIGHBOUR_ID, otherGrant);
  assert.equal(/** @type {any} */ (await neighbourClient.unlock(["body"])).status, 200);
  assert.equal(await openedBody(neighbourClient), `article ${NEIGHBOUR_ID}`);
});

test("names that enter a |-joined BIND grammar still refuse |", async () => {
  const signing = await signingKeypair();
  const opening = await issuerKeypair();
  /** @param {string} issuerName */
  const config = (issuerName) => ({
    origin: ORIGIN,
    clock: new Clock("2026-10-15T12:00:00Z"),
    random: new Random({ seed: 1 }),
    signingKeys: { publisher_signing: signing.privateKey },
    periodKeySupply: { derive: async () => new Uint8Array(16).fill(9) },
    issuerSupplyPlanFor: (/** @type {any} */ _issuer, /** @type {any} */ render) => ({
      contentKeyNames: render.contentNames,
      suppliedAccessGroups: render.accessGroups,
    }),
    issuers: [
      { issuerName, keyId: "opening_key", algorithm: "ecdh-p256", publicKey: opening.publicKey },
    ],
  });
  assert.throws(() => new Sealer(config("news|issuer")), { code: "bad_name" }, "issuerName");
  const sealer = new Sealer(config(ISSUER));
  assert.throws(
    () => sealer.content("body|x", "v", "text/plain"),
    { code: "bad_name" },
    "contentName",
  );
  assert.throws(
    () => sealer.content("body", "v", "text/plain", { accessGroups: ["prem|ium"] }),
    { code: "bad_name" },
    "accessGroup",
  );
  assert.doesNotThrow(() => sealer.resource(RESOURCE_ID, {}), "resourceId admits |");
});

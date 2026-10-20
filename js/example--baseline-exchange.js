// @ts-check
// Run from js/: node example--baseline-exchange.js
// Fresh local keys model one trusted publisher and issuer. A deployment owns
// persisted keys, caller authentication, registration lookup and route selection.
import { pathToFileURL } from "node:url";
import { argv } from "node:process";
import { log } from "node:console";
import { createPublisher } from "./integration-publisher/createPublisher.js";
import { createIssuerCore } from "./integration-issuer/createIssuerCore.js";
import { createDeliveryClient } from "./integration-client/createDeliveryClient.js";
import { JsonDeliveryReader } from "./adapter-client/JsonDeliveryReader.js";
import { writeJsonDelivery } from "./adapter-publisher/writeJsonDelivery.js";

/** A baseline exchange through public role entries, without demo actors. */
export async function runBaselineExchange() {
  const signing = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const opening = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const publisherOrigin = "https://news.example";
  const issuerName = "issuer";
  const keyId = "opening";
  const unlockUrl = "https://issuer.example/unlock";
  const publisher = createPublisher({
    origin: publisherOrigin,
    clock: { now: () => new Date("2026-10-17T14:20:00Z") },
    random: { bytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)) },
    signingKeys: { signing: signing.privateKey },
    issuers: [{ issuerName, keyId, algorithm: "ecdh-p256", publicKey: opening.publicKey }],
    issuerSupplyPlanFor: () => ({ contentKeyNames: ["bodytext"], suppliedAccessGroups: [] }),
  });
  const render = await publisher.publish({
    resourceId: "article",
    data: { section: "politics" },
    items: [{ name: "bodytext", value: "Readable content", contentType: "text/plain" }],
  });
  const delivery = writeJsonDelivery(render);

  // The host selects this trusted registration. Request fields do not choose
  // another publisher's signing key or opening-key namespace.
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    openingKeys: {
      get: (/** @type {string} */ issuer, /** @type {string} */ id) =>
        issuer === issuerName && id === keyId
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  const principal = Object.freeze({ user: "example-reader", mayReadArticle: true });
  const issuer = createIssuerCore({
    operatingIssuerNames: [issuerName],
    accessPolicy: {
      decide(claims, requested, input) {
        // An explicit host grant for this reader/article, not a default policy.
        const allowed =
          input.principal === principal &&
          principal.mayReadArticle &&
          claims.resource.origin === publisherOrigin &&
          claims.resource.resourceId === "article";
        return {
          contentNames: allowed ? requested.contentNames.filter((n) => n === "bodytext") : [],
        };
      },
    },
  });
  let issuerRequests = 0;
  const client = createDeliveryClient({
    reader: new JsonDeliveryReader(delivery, { publisherOrigin }),
    issuerName,
    unlockUrl,
    transport: {
      async post(url, request) {
        if (url !== unlockUrl) throw new Error("unexpected issuer route");
        issuerRequests += 1;
        // Real transport authenticates the caller. This local transport still
        // crosses serialized request and response boundaries.
        const result = await issuer.endpoint.handleDocument(JSON.stringify(request), registration, {
          principal,
        });
        return {
          status: result.response.status,
          body: JSON.parse(JSON.stringify(result.response.body)),
          contentType: "application/json",
        };
      },
    },
  });
  const opened = await client.open("bodytext");
  const retained = await client.open("bodytext");
  return {
    plaintext: new globalThis.TextDecoder().decode(opened.bytes),
    retainedPlaintext: new globalThis.TextDecoder().decode(retained.bytes),
    contentType: opened.contentType,
    issuerRequests,
  };
}

if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) {
  log(JSON.stringify(await runBaselineExchange(), null, 2));
}

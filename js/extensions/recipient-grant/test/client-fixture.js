import { createRecipientGrantBrowserClient } from "../client.js";
import { createRecipientGrantIssuer } from "../issuer.js";
import { createPublisher } from "../../../integration-publisher/createPublisher.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { domOver } from "../../../test-lib/helpers/domOver.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";
import { utf8Decode } from "../../../core-shared/codec.js";

export const ORIGIN = "https://publisher.example";
export const URL = "https://issuer.example/recipient-unlock";
export const REFERENCE = "opaque-test-grant-reference";
export const NOW = Date.parse("2026-09-29T12:00:00Z");
export const SELECTION = {
  issuerName: "selected_issuer",
  unlockUrl: URL,
  publisherOrigin: ORIGIN,
  resourceId: "article-42",
};

export async function world() {
  const opening = await issuerKeypair();
  const signing = await signingKeypair();
  const publisher = createPublisher({
    origin: ORIGIN,
    clock: { now: () => new Date(NOW) },
    random: { bytes: (n) => crypto.getRandomValues(new Uint8Array(n)) },
    signingKeys: { publisher_signing: signing.privateKey },
    issuers: ["selected_issuer", "other_issuer"].map((issuerName) => ({
      issuerName,
      keyId: "opening_key",
      algorithm: "ecdh-p256",
      publicKey: opening.publicKey,
      // Delivery names a different endpoint: trusted configuration selects
      // the recipient endpoint before the bearer is obtained.
    })),
    issuerSupplyPlanFor: (_issuer, render) => ({
      contentKeyNames: render.contentNames,
      suppliedAccessGroups: render.accessGroups,
    }),
    periodKeySupply: { derive: async () => new Uint8Array(16).fill(9) },
  });
  const grant = {
    purpose: "recipient-unlock",
    issuerId: SELECTION.issuerName,
    publisherRegistrationId: "publisher-one",
    resourceId: SELECTION.resourceId,
    contentNames: ["body"],
    notBeforeMs: NOW - 1000,
    expiresAtMs: NOW + 1000,
    revoked: false,
  };
  const registration = {
    registrationId: "publisher-one",
    kid: "publisher_signing",
    publicKey: signing.publicKey,
    openingKeys: {
      allows: (name, id) => name === SELECTION.issuerName && id === "opening_key",
      get: (name, id) =>
        name === SELECTION.issuerName && id === "opening_key"
          ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
          : undefined,
    },
  };
  const issuer = createRecipientGrantIssuer({
    issuerId: SELECTION.issuerName,
    operatingIssuerNames: [SELECTION.issuerName],
    grants: { get: (reference) => (reference === REFERENCE ? grant : undefined) },
    accessPolicy: { decide: (_claims, requested) => ({ contentNames: requested.contentNames }) },
    now: () => NOW,
  });
  const browser = issuer.browserHttp((origin) => origin === ORIGIN);
  async function render(value = "first article text") {
    const output = await publisher.publish({
      resourceId: SELECTION.resourceId,
      data: {},
      items: [
        { name: "body", value, contentType: "text/plain", accessGroups: ["premium"] },
        {
          name: "extra",
          value: "outside the grant",
          contentType: "text/plain",
          accessGroups: ["premium"],
        },
        ...(value === "first article text"
          ? []
          : [
              {
                name: "new_item",
                value: "new name on the later render",
                contentType: "text/plain",
                accessGroups: ["premium"],
              },
            ]),
      ],
    });
    // An unselected extension carrier must never be projected into this
    // recipient attempt, even when delivery carries it for another flow.
    output.dcaData.issuerData.find(
      (/** @type {any} */ record) => record.issuerName === "selected_issuer",
    ).sealed.chainKeys = [
      { accessGroup: "premium", cutoff: "260929T1200", key: "unselected-chain-envelope" },
    ];
    return { output, root: domOver(writeMarkupDelivery(output), { publisherOrigin: ORIGIN }) };
  }
  const calls = [];
  async function fetch(url, init) {
    calls.push({ url, init, request: JSON.parse(init.body) });
    const answer = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: init.body,
      authorization: init.headers.Authorization,
      hostContext: { registration },
    });
    return response(answer.body, answer.status);
  }
  return { render, fetch, issuer, calls, grant, registration };
}

export function response(body, status = 200, contentType = "application/json") {
  return { status, headers: { get: () => contentType }, json: async () => body };
}

export function client(root, fetch, overrides = {}) {
  return createRecipientGrantBrowserClient({
    root,
    issuer: { ...SELECTION },
    grantReference: REFERENCE,
    fetch,
    ...overrides,
  });
}

export async function opened(client, contentName = "body") {
  return utf8Decode(
    await client.opener.open({
      item: client.dcaData.contentItemFor(contentName),
      ciphertext: client.reader.extract(contentName),
      resolveKey: () => client.resolver.contentKeyFor(client.dcaData, contentName),
    }),
  );
}

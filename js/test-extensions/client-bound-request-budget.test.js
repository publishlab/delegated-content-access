// @ts-check
// Publisher projection plus actual recipient offer -> UTF-8 admission -> real
// client-bound answer -> authenticated plaintext. This is an in-process host
// composition, not HTTP/browser-origin or cross-language conformance evidence.
import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../core-publisher/Sealer.js";
import {
  issuerRequestDocument,
  assertIssuerRequestBudget,
} from "../core-publisher/issuerRequestBudget.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { KeyDelivery } from "../adapter-issuer/KeyDelivery.js";
import { Client } from "../test-lib/harnesses/client.js";
import { clientBoundKeyCapability } from "../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";
import * as ecdh from "../extensions/client-bound-transport/ecdhP256.js";
import * as rsa from "../extensions/client-bound-transport/rsaOaep.js";
import { utf8Decode } from "../core-shared/codec.js";

for (const [method, profile, recipientAlgorithm, usages] of [
  ["ECDH-P256", ecdh, { name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]],
  [
    "RSA-OAEP",
    rsa,
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    ["unwrapKey"],
  ],
]) {
  test(`${method} actual recipient offer fits the exact UTF-8 request bound and opens content`, async () => {
    const issuerName = "issuer_a";
    const keyId = "clé";
    const origin = "https://publisher.example";
    const text = "Readable café 🐕";
    const subtle = globalThis.crypto.subtle;
    const random = { bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)) };
    const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
      "verify",
    ]);
    const opening = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveBits",
    ]);
    const recipient = await subtle.generateKey(recipientAlgorithm, false, usages);
    const capability = clientBoundKeyCapability(
      {
        privateKey: recipient.privateKey,
        publicKey: await subtle.exportKey("jwk", recipient.publicKey),
      },
      profile,
    );
    const client = () =>
      new Client({
        publisherOrigin: origin,
        relayPeriodKeys: false,
        clientBoundKeyCapability: capability,
      });
    async function publish(maxBodyBytes = 65536, clientRequestExtraBytes = undefined) {
      const sealer = new Sealer({
        origin,
        random,
        clock: { now: () => new Date("2026-10-17T12:00:00Z") },
        signingKeys: { signing: signing.privateKey },
        issuers: [
          {
            issuerName,
            keyId,
            algorithm: "ecdh-p256",
            publicKey: opening.publicKey,
            limits: { maxBodyBytes },
            ...(clientRequestExtraBytes === undefined ? {} : { clientRequestExtraBytes }),
          },
        ],
        issuerSupplyPlanFor: () => ({ contentKeyNames: ["body"], suppliedAccessGroups: [] }),
      });
      return sealer.resource("123456", {}).content("body", text, "text/plain").seal();
    }
    const initial = await publish();
    const initialRequest = client().buildRequest(initial.dcaData, issuerName, ["body"]);
    const baseBytes = Buffer.byteLength(
      JSON.stringify(issuerRequestDocument(initial.dcaData, { issuerName })),
    );
    const requestBytes = Buffer.byteLength(JSON.stringify(initialRequest));
    const overhead = requestBytes - baseBytes;
    assert.equal(
      overhead,
      Buffer.byteLength(',"clientPublicKey":' + JSON.stringify(capability.publicKey)),
      "measure the actual projected public-key field rather than exported JWK size",
    );
    assertIssuerRequestBudget(initial.dcaData, {
      issuerName,
      limits: { maxBodyBytes: requestBytes, maxEntries: 16, maxEntriesPerGroup: 4 },
      clientRequestExtraBytes: overhead,
    });
    assert.throws(
      () =>
        assertIssuerRequestBudget(initial.dcaData, {
          issuerName,
          limits: { maxBodyBytes: requestBytes - 1, maxEntries: 16, maxEntriesPerGroup: 4 },
          clientRequestExtraBytes: overhead,
        }),
      { code: "bad_config", message: /maxBodyBytes/ },
    );
    const rendered = await publish(requestBytes, overhead);
    await assert.rejects(publish(requestBytes - 1, overhead), {
      code: "bad_config",
      message: /maxBodyBytes/,
    });
    const c = client();
    const request = c.buildRequest(rendered.dcaData, issuerName, ["body"]);
    const raw = JSON.stringify(request);
    assert.equal(Buffer.byteLength(raw), requestBytes);
    assert.ok(
      Buffer.byteLength(raw) > raw.length,
      "Unicode keyId distinguishes UTF-8 bytes from code units",
    );
    let policyCalls = 0;
    let lookups = 0;
    const engine = new IssuerEngine({
      operatingIssuerNames: [issuerName],
      accessPolicy: {
        decide(_claims, requested) {
          policyCalls++;
          return { contentNames: requested.contentNames, periodGrants: [] };
        },
      },
    });
    assert.deepEqual(
      new IssuerProcessor(engine, { limits: { maxBodyBytes: requestBytes - 1 } }).admit(raw),
      { kind: "failure", code: "body_too_large" },
    );
    assert.equal(policyCalls, 0);
    assert.equal(lookups, 0);
    const processor = new IssuerProcessor(engine, { limits: { maxBodyBytes: requestBytes } });
    const admitted = processor.admit(raw);
    assert.equal(admitted.kind, "admitted");
    const delivery = new KeyDelivery({ random, profile });
    const view = await delivery.preflight("client-bound", admitted.request);
    const result = await processor.processMiss({
      request: admitted.request,
      registration: {
        kid: "signing",
        publicKey: signing.publicKey,
        openingKeys: {
          get(name, id) {
            lookups++;
            return name === issuerName && id === keyId
              ? { algorithm: "ecdh-p256", privateKey: opening.privateKey }
              : undefined;
          },
        },
      },
    });
    assert.equal(result.kind, "success");
    assert.equal(policyCalls, 1);
    assert.equal(lookups, 1);
    const response = await delivery.prepare(result.document, view);
    assert.equal(response.transport.method, method);
    assert.equal(typeof response.keys.contentKeys.body, "object");
    const applied = await c.applyResponse(
      rendered.dcaData,
      issuerName,
      JSON.parse(JSON.stringify(response)),
      request,
    );
    assert.equal(applied.accepted, 1);
    assert.equal(
      utf8Decode(await c.decrypt(rendered.dcaData, "body", rendered.sealedContent.body)),
      text,
    );
    // An absent allowance only promises the publisher-authored lower bound.
    await publish(baseBytes);
    assert.equal(
      new IssuerProcessor(engine, { limits: { maxBodyBytes: baseBytes } }).admit(raw).code,
      "body_too_large",
    );
  });
}

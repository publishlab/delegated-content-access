import test from "node:test";
import assert from "node:assert/strict";
import { signingKeypair } from "../../../test-reference/support/keys.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { es256Sign } from "../../../core-shared/cryptoProvider.js";
import {
  mintSignedRecipientGrant,
  verifySignedRecipientGrant,
  createSignedGrantStore,
} from "../signedGrant.js";
import { createRecipientGrantIssuer } from "../issuer.js";
import { createRecipientGrantBrowserClient } from "../client.js";
import { world, response, opened, NOW, ORIGIN, SELECTION, URL } from "./client-fixture.js";

const now = () => NOW;
const kid = "publisher-share-2026-10";
const claims = () => ({
  publisher: ORIGIN,
  sub: SELECTION.resourceId,
  contentNames: ["body"],
  iat: Math.floor(NOW / 1000) - 10,
  exp: Math.floor(NOW / 1000) + 120,
});
async function signing() {
  const pair = await signingKeypair();
  const signer = { kid, alg: "ES256", key: pair.privateKey };
  const trust = {
    keys: {
      [ORIGIN]: {
        [kid]: {
          key: pair.publicKey,
          alg: "ES256",
          purpose: "recipient-unlock",
          issuer: "publisher-authority",
          publisher: ORIGIN,
          publisherRegistrationId: "publisher-one",
          maxLifetimeSeconds: 60 * 60 * 24 * 31,
        },
      },
    },
    issuerId: SELECTION.issuerName,
    now,
  };
  return { signer, trust };
}
async function mint(signer, value = claims(), authorize = () => value) {
  return mintSignedRecipientGrant({ request: { operation: "share" }, authorize, signer });
}

async function withHeader(token, signer, patch) {
  const decoded = decodeCompactJwt(token);
  const header = base64urlEncode(utf8Encode(JSON.stringify({ ...decoded.header, ...patch })));
  const message = `${header}.${decoded.parts[1]}`;
  const signature = base64urlEncode(
    new Uint8Array(await es256Sign(signer.key, utf8Encode(message))),
  );
  return `${message}.${signature}`;
}

test("extra noncritical grant header metadata is ignored while unsafe header controls are refused", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  assert.deepEqual(Object.keys(decodeCompactJwt(token).header), ["typ", "alg", "kid"]);
  for (const patch of [{ cty: "JWT" }, { x5t: "thumbprint" }, { "x5t#S256": "thumbprint" }]) {
    assert.ok(await verifySignedRecipientGrant(await withHeader(token, signer, patch), trust));
  }
  for (const patch of [
    { crit: ["cty"] },
    { b64: true },
    { jwk: {} },
    { jku: "https://attacker.example/key" },
    { x5u: "https://attacker.example/key" },
  ]) {
    assert.equal(
      await verifySignedRecipientGrant(await withHeader(token, signer, patch), trust),
      null,
    );
  }
  const [header, body, signature] = token.split(".");
  for (const invalid of [
    `.${body}.${signature}`,
    `${header}..${signature}`,
    `${header}.${body}.`,
  ]) {
    assert.equal(await verifySignedRecipientGrant(invalid, trust), null);
  }
});

test("a numeric resource subject is valid grant scope", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer, { ...claims(), sub: "123456" });
  assert.equal((await verifySignedRecipientGrant(token, trust)).resourceId, "123456");
});

test("authorized ES256 mint verifies under publisher-scoped onboarding and preserves token bytes", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const second = await mint(signer);
  assert.notEqual(decodeCompactJwt(token).payload.jti, decodeCompactJwt(second).payload.jti);
  assert.match(token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.deepEqual((await verifySignedRecipientGrant(token, trust)).contentNames, ["body"]);
  const snapshot = createSignedGrantStore(trust);
  trust.keys[ORIGIN][kid].publisherRegistrationId = "changed";
  assert.equal((await snapshot.get(token)).publisherRegistrationId, "publisher-one");
  const [head, body, signature] = token.split(".");
  assert.equal(
    await verifySignedRecipientGrant(
      `${head}.${body}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`,
      trust,
    ),
    null,
  );
});

test("signed grant store snapshots the onboarding key's explicit content-name scope", async () => {
  const { signer, trust } = await signing();
  const contentNames = ["body"];
  trust.keys[ORIGIN][kid].contentNames = contentNames;
  const store = createSignedGrantStore(trust);
  const allowed = await mint(signer);
  const outside = await mint(signer, { ...claims(), contentNames: ["extra"] });
  assert.deepEqual((await store.get(allowed)).contentNames, ["body"]);
  assert.equal(await store.get(outside), null);
  contentNames.splice(0, 1, "extra");
  assert.deepEqual((await store.get(allowed)).contentNames, ["body"]);
  assert.equal(await store.get(outside), null, "caller mutation cannot widen configured key scope");
});

test("unapproved mint and malformed, wrong-scope, retired or wrong-purpose signer refuse", async () => {
  const { signer, trust } = await signing();
  await assert.rejects(
    mint(signer, claims(), () => null),
    { code: "denied" },
  );
  await assert.rejects(mint(signer, { ...claims(), jti: "AAAAAAAAAAAAAAAAAAAAAA" }), {
    code: "denied",
  });
  for (const change of [
    { sub: "other-resource" },
    { publisher: "https://other.example" },
    { contentNames: ["new_item"] },
    { exp: Math.floor(NOW / 1000) },
    { nbf: Math.floor(NOW / 1000) + 1 },
    { iat: Math.floor(NOW / 1000) + 1 },
    { iss: "wrong-issuer" },
    { aud: "other-service" },
  ]) {
    const token = await mint(signer, { ...claims(), ...change });
    const result = await verifySignedRecipientGrant(token, trust);
    if (change.sub === "other-resource" || change.contentNames) {
      assert.ok(
        result,
        "resource and names are checked against the current verified render by issuer composition",
      );
    } else {
      assert.equal(result, null, JSON.stringify(change));
    }
  }
  const token = await mint(signer);
  for (const entryPatch of [
    { purpose: "ordinary-jwt" },
    { alg: "HS256" },
    { retired: true },
    { publisherRegistrationId: "other" },
  ]) {
    const modified = {
      ...trust,
      keys: { [ORIGIN]: { [kid]: { ...trust.keys[ORIGIN][kid], ...entryPatch } } },
    };
    const grant = await verifySignedRecipientGrant(token, modified);
    assert.equal(
      entryPatch.publisherRegistrationId === "other" ? grant?.publisherRegistrationId : grant,
      entryPatch.publisherRegistrationId === "other" ? "other" : null,
    );
  }
});

test("logical audience is configured per application and may be shared by two accepting issuers", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer, { ...claims(), aud: "dca-readers" });
  assert.ok(
    await verifySignedRecipientGrant(token, {
      ...trust,
      audience: "dca-readers",
      requireAudience: true,
    }),
  );
  assert.ok(
    await verifySignedRecipientGrant(token, {
      ...trust,
      issuerId: "other_issuer",
      audience: "dca-readers",
      requireAudience: true,
    }),
  );
  assert.equal(
    await verifySignedRecipientGrant(token, {
      ...trust,
      audience: "other-app",
      requireAudience: true,
    }),
    null,
  );
  const noAudience = await mint(signer);
  assert.equal(
    await verifySignedRecipientGrant(noAudience, {
      ...trust,
      audience: "dca-readers",
      requireAudience: true,
    }),
    null,
  );
  assert.ok(await verifySignedRecipientGrant(noAudience, trust));
});

test("serialized signed grant passes real issuer admission and opens only current-render named content", async () => {
  const w = await world();
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const issuer = createRecipientGrantIssuer({
    issuerId: SELECTION.issuerName,
    operatingIssuerNames: [SELECTION.issuerName],
    grants: createSignedGrantStore(trust),
    accessPolicy: { decide: (_claims, requested) => ({ contentNames: requested.contentNames }) },
    now,
  });
  const browser = issuer.browserHttp((origin) => origin === ORIGIN);
  let sends = 0;
  const fetch = async (url, init) => {
    sends++;
    assert.equal(url, URL);
    assert.equal(init.body.includes(token), false);
    const result = await browser.handle({
      method: "POST",
      contentType: "application/json",
      origin: ORIGIN,
      body: init.body,
      authorization: init.headers.Authorization,
      hostContext: { registration: w.registration, capturedAtMs: NOW },
    });
    return response(result.body, result.status);
  };
  for (const value of ["first article text", "changed article under the same granted name"]) {
    const { root } = await w.render(value);
    const client = createRecipientGrantBrowserClient({
      root,
      issuer: SELECTION,
      grantReference: token,
      fetch,
    });
    const result = await client.unlock(["body", "extra", "new_item"]);
    assert.equal(result.status, 200);
    assert.equal(await opened(client), value);
    assert.equal(await client.resolver.contentKeyFor(client.dcaData, "extra"), null);
    assert.equal(await client.resolver.contentKeyFor(client.dcaData, "new_item"), null);
  }
  assert.equal(sends, 2);
  const { root } = await w.render();
  const [head, body, signature] = token.split(".");
  const invalid = `${head}.${body}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  const client = createRecipientGrantBrowserClient({
    root,
    issuer: SELECTION,
    grantReference: invalid,
    fetch,
  });
  assert.equal((await client.unlock(["body"])).status, 401);
  assert.equal(await client.resolver.contentKeyFor(client.dcaData, "body"), null);
});

test("configured HS256 secret supports issuer/delegate minting without treating a public key as a MAC secret", async () => {
  const key = await crypto.subtle.importKey(
    "raw",
    crypto.getRandomValues(new Uint8Array(32)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const signer = { kid: "issuer-delegate-1", alg: "HS256", key };
  const token = await mint(signer, { ...claims(), iss: "reader-gift-authority" });
  const { trust } = await signing();
  trust.keys[ORIGIN][signer.kid] = {
    key,
    alg: "HS256",
    purpose: "recipient-unlock",
    issuer: "reader-gift-authority",
    publisher: ORIGIN,
    publisherRegistrationId: "publisher-one",
    maxLifetimeSeconds: 60 * 60 * 24 * 31,
  };
  assert.ok(await verifySignedRecipientGrant(token, trust));
  assert.equal(
    await verifySignedRecipientGrant(token, {
      ...trust,
      keys: {
        [ORIGIN]: {
          [signer.kid]: { ...trust.keys[ORIGIN][signer.kid], key: trust.keys[ORIGIN][kid].key },
        },
      },
    }),
    null,
  );
  const short = await crypto.subtle.importKey(
    "raw",
    crypto.getRandomValues(new Uint8Array(16)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  await assert.rejects(mint({ ...signer, key: short }), { code: "bad_config" });
});

test("revocation and exact expiry stop fresh admission while prior opening remains historical", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const revoked = {
    ...trust,
    revoked: (seen, entry) =>
      seen === decodeCompactJwt(token).payload.jti && entry.publisher === ORIGIN,
  };
  assert.equal(await verifySignedRecipientGrant(token, revoked), null);
  assert.ok(await verifySignedRecipientGrant(token, trust));
  assert.equal(
    await verifySignedRecipientGrant(token, { ...trust, now: () => claims().exp * 1000 }),
    null,
  );
});

test("same publisher token opens through two independently trusted provisioned routes", async () => {
  const w = await world();
  const { root } = await w.render();
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const openedKey = w.registration.openingKeys.get(SELECTION.issuerName, "opening_key");
  for (const issuerName of [SELECTION.issuerName, "other_issuer"]) {
    const route = { ...SELECTION, issuerName, unlockUrl: `https://${issuerName}.example/unlock` };
    const registration = {
      ...w.registration,
      openingKeys: {
        allows: (name, id) => name === issuerName && id === "opening_key",
        get: (name, id) => (name === issuerName && id === "opening_key" ? openedKey : undefined),
      },
    };
    const issuer = createRecipientGrantIssuer({
      issuerId: issuerName,
      operatingIssuerNames: [issuerName],
      grants: createSignedGrantStore({ ...trust, issuerId: issuerName }),
      accessPolicy: { decide: (_claims, requested) => ({ contentNames: requested.contentNames }) },
      now,
    });
    const browser = issuer.browserHttp((origin) => origin === ORIGIN);
    let admittedRequest;
    const client = createRecipientGrantBrowserClient({
      root,
      issuer: route,
      grantReference: token,
      fetch: async (url, init) => {
        assert.equal(url, route.unlockUrl);
        assert.equal(init.headers.Authorization, `Bearer ${token}`);
        admittedRequest = JSON.parse(init.body);
        const result = await browser.handle({
          method: "POST",
          contentType: "application/json",
          origin: ORIGIN,
          body: init.body,
          authorization: init.headers.Authorization,
          hostContext: { registration, capturedAtMs: NOW },
        });
        return response(result.body, result.status);
      },
    });
    assert.equal((await client.unlock(["body"])).status, 200);
    assert.equal(await opened(client), "first article text");
    if (issuerName === "other_issuer") {
      const absentSupply = createRecipientGrantBrowserClient({
        root,
        issuer: route,
        grantReference: token,
        fetch: async (_url, init) => {
          const request = JSON.parse(init.body);
          request.sealed.contentKeys = {};
          const result = await browser.handle({
            method: "POST",
            contentType: "application/json",
            origin: ORIGIN,
            body: JSON.stringify(request),
            authorization: init.headers.Authorization,
            hostContext: { registration, capturedAtMs: NOW },
          });
          return response(result.body, result.status);
        },
      });
      const missing = await absentSupply.unlock(["body"]);
      assert.equal(missing.application?.accepted ?? 0, 0);
      assert.equal(await absentSupply.resolver.contentKeyFor(absentSupply.dcaData, "body"), null);
      const forbidden = await browser.handle({
        method: "POST",
        contentType: "application/json",
        origin: ORIGIN,
        body: JSON.stringify({ ...admittedRequest, sealed: { periodKeys: {} } }),
        authorization: `Bearer ${token}`,
        hostContext: { registration, capturedAtMs: NOW },
      });
      assert.equal(forbidden.status, 400);
    }
  }
});

test("reader gifting needs publisher share permission and issuer reader qualification upstream", async () => {
  const { signer, trust } = await signing();
  const authorizeGift = ({ publisherSharing, readerQualified, issuerSharing }) =>
    publisherSharing && readerQualified && issuerSharing ? claims() : null;
  for (const request of [
    { publisherSharing: false, readerQualified: true, issuerSharing: true },
    { publisherSharing: true, readerQualified: false, issuerSharing: true },
    { publisherSharing: true, readerQualified: true, issuerSharing: false },
  ]) {
    await assert.rejects(mintSignedRecipientGrant({ request, authorize: authorizeGift, signer }), {
      code: "denied",
    });
  }
  const token = await mintSignedRecipientGrant({
    request: { publisherSharing: true, readerQualified: true, issuerSharing: true },
    authorize: authorizeGift,
    signer,
  });
  assert.ok(await verifySignedRecipientGrant(token, trust));
  assert.equal(
    await verifySignedRecipientGrant(token, { ...trust, keys: {} }),
    null,
    "unsupported issuer has no sharing trust",
  );
});

test("mint refuses a JSON hook that would change authorized scope while serializing", async () => {
  const { signer } = await signing();
  const approved = {
    ...claims(),
    toJSON() {
      return { ...claims(), contentNames: ["extra"] };
    },
  };
  await assert.rejects(mint(signer, approved), { code: "denied" });
});

test("signed key onboarding requires a stable issuing authority even when token iss is absent", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  let authority;
  const store = createSignedGrantStore({
    ...trust,
    revoked: (_jti, entry) => {
      authority = entry.issuer;
      return false;
    },
  });
  assert.ok(await store.get(token));
  assert.equal(authority, "publisher-authority");
  for (const issuer of [undefined, "", "bad\u0001authority"]) {
    const entry = { ...trust.keys[ORIGIN][kid], issuer };
    const config = { ...trust, keys: { [ORIGIN]: { [kid]: entry } } };
    assert.throws(() => createSignedGrantStore(config), { code: "bad_config" });
    assert.equal(await verifySignedRecipientGrant(token, config), null);
  }
  assert.throws(
    () =>
      createSignedGrantStore({
        ...trust,
        keys: { [ORIGIN]: { [kid]: { ...trust.keys[ORIGIN][kid], contentNames: [""] } } },
      }),
    { code: "bad_config" },
    "an explicitly configured grant scope cannot contain an empty content name",
  );
  assert.ok(
    await verifySignedRecipientGrant(await mint(signer, { ...claims(), iss: authority }), trust),
  );
});

test("explicit captured clock options are finite instants and replace the store clock", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  let clockCalls = 0;
  const store = createSignedGrantStore({
    ...trust,
    now: () => {
      clockCalls++;
      return Infinity;
    },
  });
  assert.ok(await store.get(token, { nowMs: NOW }));
  assert.equal(clockCalls, 0);
  await assert.rejects(store.get(token), { code: "bad_config" });
  for (const options of [
    null,
    [],
    { nowMs: undefined },
    { nowMs: null },
    { nowMs: "123" },
    { nowMs: NaN },
    { nowMs: Infinity },
  ])
    await assert.rejects(verifySignedRecipientGrant(token, trust, options), { code: "bad_config" });
});

test("returned record starts no earlier than both iat and nbf", async () => {
  const { signer, trust } = await signing();
  for (const nbf of [claims().iat - 1, claims().iat + 1]) {
    const token = await mint(signer, { ...claims(), nbf });
    const grant = await verifySignedRecipientGrant(token, trust);
    assert.equal(grant.notBeforeMs, Math.max(claims().iat, nbf) * 1000);
  }
});

test("issuer and signed store share one captured instant without any future-iat allowance", async () => {
  const w = await world();
  const { root } = await w.render();
  const { signer, trust } = await signing();
  const second = NOW / 1000;
  for (const [capturedAtMs, storeNow, nbf, expected] of [
    [NOW + 1100, NOW + 900, second + 1, 200],
    [NOW + 900, NOW + 1100, second + 1, 401],
    [NOW + 1900, NOW + 2100, second + 2, 401],
    [NOW + 2000, NOW + 1900, second + 2, 200],
    [NOW + 2900, NOW + 3100, second + 1, 200],
    [NOW + 3000, NOW + 2900, second + 1, 401],
  ]) {
    const token = await mint(signer, { ...claims(), iat: second + 1, nbf, exp: second + 3 });
    let storeClockCalls = 0;
    const store = createSignedGrantStore({
      ...trust,
      now: () => {
        storeClockCalls++;
        return storeNow;
      },
    });
    const seen = [];
    const issuer = createRecipientGrantIssuer({
      issuerId: SELECTION.issuerName,
      operatingIssuerNames: [SELECTION.issuerName],
      grants: {
        get(reference, options) {
          seen.push(options.nowMs);
          return store.get(reference, options);
        },
      },
      accessPolicy: { decide: (_claims, requested) => ({ contentNames: requested.contentNames }) },
      now: () => {
        throw new Error("the explicit host instant must replace the issuer clock");
      },
    });
    const browser = issuer.browserHttp((origin) => origin === ORIGIN);
    const client = createRecipientGrantBrowserClient({
      root,
      issuer: SELECTION,
      grantReference: token,
      fetch: async (_url, init) => {
        const result = await browser.handle({
          method: "POST",
          contentType: "application/json",
          origin: ORIGIN,
          body: init.body,
          authorization: init.headers.Authorization,
          hostContext: { registration: w.registration, capturedAtMs },
        });
        return response(result.body, result.status);
      },
    });
    assert.equal((await client.unlock(["body"])).status, expected);
    if (expected === 200) assert.equal(await opened(client), "first article text");
    else assert.equal(await client.resolver.contentKeyFor(client.dcaData, "body"), null);
    assert.deepEqual(seen, [capturedAtMs]);
    assert.equal(storeClockCalls, 0);
  }
});

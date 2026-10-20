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
import { requestFor } from "../../../test-lib/harnesses/issuer-endpoint.js";
import {
  world as hardeningWorld,
  BODYTEXT,
  PREMIUM,
  ISSUER_NAME,
  PUBLISHER_ORIGIN,
} from "../../../test-lib/fixtures/endpoint-hardening-world.js";

const NOW = Date.parse("2026-09-29T12:00:00Z");
const ORIGIN = "https://publisher.example";
const ISSUER_ID = "selected_issuer";
const kid = "publisher-share-2026-10";
const MAX_LIFETIME = 60 * 60 * 24 * 31;
const claims = () => ({
  publisher: ORIGIN,
  sub: "article-42",
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
          maxLifetimeSeconds: MAX_LIFETIME,
        },
      },
    },
    issuerId: ISSUER_ID,
    now: () => NOW,
  };
  return { signer, trust, pair };
}
const mint = (signer, value = claims()) =>
  mintSignedRecipientGrant({ request: {}, authorize: () => value, signer });
const seg = (value) => base64urlEncode(utf8Encode(JSON.stringify(value)));
// Sign arbitrary header and payload segments with the ES256 signer: the way to make
// tokens mint() refuses to make.
async function rawSign(signer, headerSegment, payloadSegment) {
  const message = `${headerSegment}.${payloadSegment}`;
  const signature = new Uint8Array(await es256Sign(signer.key, utf8Encode(message)));
  return `${message}.${base64urlEncode(signature)}`;
}
const withJti = (value) => ({
  ...value,
  jti: base64urlEncode(crypto.getRandomValues(new Uint8Array(16))),
});
async function withHeader(token, signer, patch) {
  const decoded = decodeCompactJwt(token);
  const header = { ...decoded.header, ...patch };
  for (const name of Object.keys(patch)) if (patch[name] === undefined) delete header[name];
  return rawSign(signer, seg(header), decoded.parts[1]);
}
async function hmacKey(bytes = 32) {
  return crypto.subtle.importKey(
    "raw",
    crypto.getRandomValues(new Uint8Array(bytes)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}
function flipSignature(token) {
  const [head, body, signature] = token.split(".");
  return `${head}.${body}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
}

test("a tampered or foreign-secret HS256 grant is refused", async () => {
  const key = await hmacKey();
  const signer = { kid: "delegate-1", alg: "HS256", key };
  const { trust } = await signing();
  trust.keys[ORIGIN][signer.kid] = {
    key,
    alg: "HS256",
    purpose: "recipient-unlock",
    issuer: "publisher-authority",
    publisher: ORIGIN,
    publisherRegistrationId: "publisher-one",
    maxLifetimeSeconds: MAX_LIFETIME,
  };
  const token = await mint(signer);
  assert.ok(await verifySignedRecipientGrant(token, trust));
  assert.equal(await verifySignedRecipientGrant(flipSignature(token), trust), null);
  const other = await hmacKey();
  const foreign = await mint({ ...signer, key: other });
  assert.equal(await verifySignedRecipientGrant(foreign, trust), null);
});

test("a grant whose exp - iat exceeds the entry's maxLifetimeSeconds is refused", async () => {
  const { signer, trust } = await signing();
  const base = claims();
  const atBound = await mint(signer, { ...base, exp: base.iat + MAX_LIFETIME });
  assert.ok(await verifySignedRecipientGrant(atBound, trust));
  const over = await mint(signer, { ...base, exp: base.iat + MAX_LIFETIME + 1 });
  assert.equal(await verifySignedRecipientGrant(over, trust), null);
});

test("header alg must equal the selected entry's alg before verification", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const relabelled = await withHeader(token, signer, { alg: "HS256" });
  assert.equal(await verifySignedRecipientGrant(relabelled, trust), null);
});

test("entry contentNames narrow what a token may name", async () => {
  const { signer, trust } = await signing();
  trust.keys[ORIGIN][kid].contentNames = ["body"];
  assert.ok(await verifySignedRecipientGrant(await mint(signer), trust));
  for (const contentNames of [["extra"], ["body", "extra"]]) {
    const outside = await mint(signer, { ...claims(), contentNames });
    assert.equal(await verifySignedRecipientGrant(outside, trust), null);
  }
});

test("typ must be exactly dca-share+jwt", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  for (const typ of ["JWT", "dca-share+JWT", undefined]) {
    assert.equal(
      await verifySignedRecipientGrant(await withHeader(token, signer, { typ }), trust),
      null,
      String(typ),
    );
  }
});

test("an aud array must contain the configured audience", async () => {
  const { signer, trust } = await signing();
  const config = { ...trust, audience: "dca-readers", requireAudience: true };
  const wrong = await mint(signer, { ...claims(), aud: ["other-app"] });
  assert.equal(await verifySignedRecipientGrant(wrong, config), null);
  const mixed = await mint(signer, { ...claims(), aud: ["other-app", "dca-readers"] });
  assert.ok(await verifySignedRecipientGrant(mixed, config));
});

test("a payload segment with malformed UTF-8 is refused even under a valid signature", async () => {
  const { signer, trust } = await signing();
  const json = utf8Encode(JSON.stringify({ ...withJti(claims()), note: "X" }));
  const bad = Uint8Array.from(json);
  bad[json.indexOf(0x58)] = 0xff; // the X becomes a lone 0xFF byte
  const token = await rawSign(
    signer,
    seg({ typ: "dca-share+jwt", alg: "ES256", kid }),
    base64urlEncode(bad),
  );
  assert.equal(await verifySignedRecipientGrant(token, trust), null);
});

test("a compact token above 8192 characters is refused at verification", async () => {
  const { signer, trust } = await signing();
  const token = await rawSign(
    signer,
    seg({ typ: "dca-share+jwt", alg: "ES256", kid }),
    seg({ ...withJti(claims()), pad: "x".repeat(8192) }),
  );
  assert.ok(token.length > 8192);
  assert.equal(await verifySignedRecipientGrant(token, trust), null);
});

test("an entry whose publisher differs from the token's publisher namespace is refused", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const entry = { ...trust.keys[ORIGIN][kid], publisher: "https://other.example" };
  assert.equal(
    await verifySignedRecipientGrant(token, { ...trust, keys: { [ORIGIN]: { [kid]: entry } } }),
    null,
  );
  assert.throws(() => createSignedGrantStore({ ...trust, keys: { [ORIGIN]: { [kid]: entry } } }), {
    code: "bad_config",
  });
});

test("exp must be strictly greater than iat at mint and at verify", async () => {
  const { signer, trust } = await signing();
  const base = claims();
  await assert.rejects(mint(signer, { ...base, exp: base.iat }), { code: "denied" });
  const token = await rawSign(
    signer,
    seg({ typ: "dca-share+jwt", alg: "ES256", kid }),
    seg(withJti({ ...base, exp: base.iat })),
  );
  // This empty interval also fails exact expiry admission; the mint assertion
  // above distinguishes removal of the shared iat < exp claim guard.
  assert.equal(
    await verifySignedRecipientGrant(token, { ...trust, now: () => base.iat * 1000 }),
    null,
  );
});

test("duplicate contentNames are refused", async () => {
  const { signer } = await signing();
  await assert.rejects(mint(signer, { ...claims(), contentNames: ["body", "body"] }), {
    code: "denied",
  });
});

test("more than 64 contentNames are refused", async () => {
  const { signer, trust } = await signing();
  const names = (count) => Array.from({ length: count }, (_, index) => `item_${index}`);
  assert.ok(
    await verifySignedRecipientGrant(
      await mint(signer, { ...claims(), contentNames: names(64) }),
      trust,
    ),
  );
  await assert.rejects(mint(signer, { ...claims(), contentNames: names(65) }), { code: "denied" });
});

test("identifiers with control characters are refused", async () => {
  const { signer, trust } = await signing();
  await assert.rejects(mint(signer, { ...claims(), iss: "authority\u0001" }), { code: "denied" });
  // A raw trust object (not the store) holding a control-character kid: the
  // verifier's own identifier rule must still refuse the header's kid.
  const oddKid = "share\u0001";
  const token = await rawSign(
    signer,
    seg({ typ: "dca-share+jwt", alg: "ES256", kid: oddKid }),
    seg(withJti(claims())),
  );
  const raw = { ...trust, keys: { [ORIGIN]: { [oddKid]: trust.keys[ORIGIN][kid] } } };
  assert.equal(await verifySignedRecipientGrant(token, raw), null);
});

test("a jti shorter than 22 characters is refused", async () => {
  const { signer, trust } = await signing();
  const token = await rawSign(
    signer,
    seg({ typ: "dca-share+jwt", alg: "ES256", kid }),
    seg({ ...claims(), jti: "short-identifier-1" }),
  );
  assert.equal(await verifySignedRecipientGrant(token, trust), null);
});

test("an ES256 entry needs a P-256 key", async () => {
  const { trust } = await signing();
  const p384 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, [
    "sign",
    "verify",
  ]);
  const entry = { ...trust.keys[ORIGIN][kid], key: p384.publicKey };
  assert.throws(() => createSignedGrantStore({ ...trust, keys: { [ORIGIN]: { [kid]: entry } } }), {
    code: "bad_config",
  });
});

test("an unknown kid under a known publisher is refused", async () => {
  const { signer, trust } = await signing();
  const token = await mint({ ...signer, kid: "publisher-share-2026-11" });
  assert.equal(await verifySignedRecipientGrant(token, trust), null);
});

test("the signing input is the original segments, not re-encoded JSON", async () => {
  const { signer, trust } = await signing();
  const token = await mint(signer);
  const { header, payload } = decodeCompactJwt(token);
  const spaced = base64urlEncode(utf8Encode(JSON.stringify(payload, null, 1)));
  const resigned = await rawSign(signer, seg(header), spaced);
  assert.notEqual(resigned.split(".")[1], token.split(".")[1]);
  assert.ok(await verifySignedRecipientGrant(resigned, trust));
});

async function issuerFixture(policy, grantOverrides = {}) {
  const w = await hardeningWorld();
  const page = await w.render();
  const seen = [];
  const registration = { ...w.publisherRegistration, registrationId: "publisher-one" };
  const issuer = createRecipientGrantIssuer({
    operatingIssuerNames: [ISSUER_NAME],
    issuerId: "issuer-a",
    grants: {
      get: () => ({
        purpose: "recipient-unlock",
        issuerId: "issuer-a",
        publisherRegistrationId: "publisher-one",
        resourceId: "123456",
        contentNames: [BODYTEXT],
        notBeforeMs: NOW - 1_000,
        expiresAtMs: NOW + 60_000,
        revoked: false,
        ...grantOverrides,
      }),
    },
    accessPolicy: {
      decide(_claims, requested) {
        seen.push([...requested.contentNames]);
        return policy(requested);
      },
    },
    now: () => NOW,
  });
  const document = (names) => {
    const wire = JSON.parse(JSON.stringify(requestFor(page, ISSUER_NAME, names)));
    delete wire.sealed.periodKeys;
    delete wire.sealed.chainKeys;
    return JSON.stringify(wire);
  };
  return { issuer, registration, document, seen };
}

test("policy input carries only names inside the grant", async () => {
  const { issuer, registration, document, seen } = await issuerFixture((requested) => ({
    contentNames: requested.contentNames,
    periodGrants: [],
  }));
  const answer = await issuer.unlock({
    document: document([BODYTEXT, PREMIUM]),
    registration,
    authorization: "Bearer reference",
    observedOrigin: PUBLISHER_ORIGIN,
  });
  assert.equal(answer.status, 200);
  assert.deepEqual(seen, [[BODYTEXT]]);
});

test("a policy answering beyond its question cannot widen the grant", async () => {
  const { issuer, registration, document } = await issuerFixture(() => ({
    contentNames: [BODYTEXT, PREMIUM],
    periodGrants: [],
  }));
  const answer = await issuer.unlock({
    document: document([BODYTEXT, PREMIUM]),
    registration,
    authorization: "Bearer reference",
    observedOrigin: PUBLISHER_ORIGIN,
  });
  assert.equal(answer.status, 200);
  assert.ok(answer.body.keys.contentKeys[BODYTEXT]);
  assert.equal(answer.body.keys.contentKeys[PREMIUM], undefined);
});

test("unlock refuses an observed origin the render did not sign, without an origins list", async () => {
  const { issuer, registration, document, seen } = await issuerFixture((requested) => ({
    contentNames: requested.contentNames,
    periodGrants: [],
  }));
  assert.equal(registration.origins, undefined);
  const answer = await issuer.unlock({
    document: document([BODYTEXT]),
    registration,
    authorization: "Bearer reference",
    observedOrigin: "https://other.example",
  });
  assert.equal(answer.status, 400);
  assert.deepEqual(seen, []);
});

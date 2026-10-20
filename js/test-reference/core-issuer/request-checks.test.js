// @ts-check
//
// The two request checks an issuer runs before it reaches a private key,
// called on their own: `checkVersion` and `checkEnvelopes`. No engine, no
// processor and no policy take part. A request and what the application
// supplied go in; nothing, the verified claims or a typed error come out.
//
// The resource tokens are signed here with WebCrypto, so the tests need no
// publisher code. Every case asserts error codes, never an error class.

import assert from "node:assert/strict";

import { portableTest } from "../support/portable-test.js";

import { checkEnvelopes, checkVersion } from "../../core-issuer/IssuerEngine.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";

const test = portableTest("portable-issuer");

const { subtle } = globalThis.crypto;
const text = new TextEncoder();

/** @param {Uint8Array} bytes */
const base64url = (bytes) => Buffer.from(bytes).toString("base64url");

/** @param {unknown} value */
const segment = (value) => base64url(text.encode(JSON.stringify(value)));

const KID = "sign-2026-09";

/** A resource with every member the issuer admits, and a renderId of 16 bytes. */
const RESOURCE = Object.freeze({
  renderId: base64url(new Uint8Array(16).fill(7)),
  origin: "https://news.example",
  issuedAt: "2026-09-23T12:00:00Z",
  resourceId: "article-1",
  data: { section: "politics" },
});

const publisher = /** @type {CryptoKeyPair} */ (
  await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
);
const stranger = /** @type {CryptoKeyPair} */ (
  await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
);

/**
 * A compact ES256 token over `payload`, signed by `privateKey`.
 *
 * @param {unknown} payload
 * @param {CryptoKey} [privateKey]
 * @param {Record<string, string>} [header]
 */
async function token(
  payload,
  privateKey = publisher.privateKey,
  header = { alg: "ES256", typ: "JWT", kid: KID },
) {
  const signing = `${segment(header)}.${segment(payload)}`;
  const signature = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    text.encode(signing),
  );
  return `${signing}.${base64url(new Uint8Array(signature))}`;
}

/**
 * The request a client posts for `resourceJWT`, as the issuer parsed it.
 *
 * @param {unknown} resourceJWT
 */
function requestWith(resourceJWT) {
  return new DcaRequest({
    version: "1",
    issuerName: "issuer.example",
    resourceJWT,
    sealed: { contentKeys: {} },
  });
}

/** @param {Record<string, unknown>} resource */
async function signed(resource) {
  return requestWith(await token(resource));
}

test("checkVersion accepts a version the default set supports", () => {
  assert.equal(checkVersion(new DcaRequest({ version: "1" })), undefined);
});

test("checkVersion reads the supported set it is given", () => {
  assert.equal(checkVersion(new DcaRequest({ version: "2" }), ["1", "2"]), undefined);
  assert.throws(() => checkVersion(new DcaRequest({ version: "2" }), ["1"]), {
    code: "bad_version",
  });
});

test("checkVersion refuses a version that is missing or not a string", () => {
  for (const document of [{}, { version: 1 }, { version: null }, { version: ["1"] }])
    assert.throws(
      () => checkVersion(new DcaRequest(document)),
      { code: "bad_version" },
      JSON.stringify(document),
    );
});

test("checkEnvelopes returns the signed resource and nothing beside it", async () => {
  assert.deepEqual(await checkEnvelopes(await signed(RESOURCE), publisher.publicKey), {
    resource: RESOURCE,
  });
});

test("checkEnvelopes refuses a request that carries no resourceJWT", async () => {
  await assert.rejects(
    checkEnvelopes(new DcaRequest({ version: "1", sealed: {} }), publisher.publicKey),
    { code: "bad_jwt" },
  );
  await assert.rejects(checkEnvelopes(requestWith(7), publisher.publicKey), { code: "bad_jwt" });
});

test("checkEnvelopes refuses a token another key signed", async () => {
  const request = requestWith(await token(RESOURCE, stranger.privateKey));
  await assert.rejects(checkEnvelopes(request, publisher.publicKey), { code: "bad_signature" });
});

test("checkEnvelopes refuses a token whose header names another algorithm or type", async () => {
  for (const header of [
    { alg: "none", typ: "JWT", kid: KID },
    { alg: "ES256", typ: "JOSE", kid: KID },
  ]) {
    const request = requestWith(await token(RESOURCE, publisher.privateKey, header));
    await assert.rejects(
      checkEnvelopes(request, publisher.publicKey),
      { code: "bad_alg" },
      JSON.stringify(header),
    );
  }
});

test("checkEnvelopes refuses a resource with no renderId or one outside the binding width", async () => {
  for (const renderId of [undefined, "", base64url(new Uint8Array(15).fill(7)), "not base64url!"])
    await assert.rejects(
      checkEnvelopes(await signed({ ...RESOURCE, renderId }), publisher.publicKey),
      { code: "binding_failed" },
      JSON.stringify(renderId),
    );
});

test("checkEnvelopes admits only a canonical signed origin, and http only on loopback in development", async () => {
  for (const origin of [
    undefined,
    null,
    "https://News.example",
    "https://news.example/",
    "https://news.example:443",
    "http://news.example",
    "http://localhost:8080",
  ])
    await assert.rejects(
      checkEnvelopes(await signed({ ...RESOURCE, origin }), publisher.publicKey),
      { code: "bad_jwt" },
      JSON.stringify(origin),
    );

  const loopback = { ...RESOURCE, origin: "http://localhost:8080" };
  assert.deepEqual(await checkEnvelopes(await signed(loopback), publisher.publicKey, true), {
    resource: loopback,
  });
  await assert.rejects(
    checkEnvelopes(
      await signed({ ...RESOURCE, origin: "http://news.example" }),
      publisher.publicKey,
      true,
    ),
    { code: "bad_jwt" },
    "development admits http on a loopback host only",
  );
});

test("checkEnvelopes refuses a malformed issuedAt, resourceId or data", async () => {
  /** @type {[string, unknown][]} */
  const malformed = [
    ["issuedAt", "2026-09-23 12:00:00Z"],
    ["issuedAt", "2026-09-23T12:00:00+02:00"],
    ["issuedAt", "2026-09-23T12:00:00"],
    ["issuedAt", "2026-02-30T12:00:00Z"],
    ["issuedAt", "2026-13-01T12:00:00Z"],
    ["issuedAt", "2026-09-00T12:00:00Z"],
    ["issuedAt", "2026-09-23T24:00:00Z"],
    ["issuedAt", 1_790_000_000],
    ["issuedAt", undefined],
    ["issuedAt", ["2026-09-23T12:00:00Z"]],
    ["resourceId", ""],
    ["resourceId", "article-\ud800"],
    ["resourceId", "article-\udfff"],
    ["resourceId", 123_456],
    ["resourceId", undefined],
    ["data", []],
    ["data", "politics"],
    ["data", null],
    ["data", undefined],
  ];
  for (const [member, value] of malformed)
    await assert.rejects(
      checkEnvelopes(await signed({ ...RESOURCE, [member]: value }), publisher.publicKey),
      { code: "bad_jwt" },
      `${member} as ${JSON.stringify(value)}`,
    );
});

test("checkEnvelopes reads issuedAt as a format, not an expiry", async () => {
  for (const resource of [
    { ...RESOURCE, issuedAt: "2024-09-01T08:00:00Z", iat: 1, exp: 1 },
    { ...RESOURCE, issuedAt: "2024-09-01t08:00:00z" },
    { ...RESOURCE, issuedAt: "2016-12-31T23:59:60.5Z" },
  ])
    assert.deepEqual(
      await checkEnvelopes(await signed(resource), publisher.publicKey),
      { resource },
      resource.issuedAt,
    );
});

test("verified resource IDs retain supplementary scalars and literal replacement characters", async () => {
  for (const resourceId of ["article-\u{1f600}", "article-\ufffd"]) {
    const resource = { ...RESOURCE, resourceId };
    assert.deepEqual(await checkEnvelopes(await signed(resource), publisher.publicKey), {
      resource,
    });
  }
});

test("checkEnvelopes admits leap days only in Gregorian leap years", async () => {
  for (const year of [2024, 2000]) {
    const resource = { ...RESOURCE, issuedAt: `${year}-02-29T12:00:00Z` };
    assert.deepEqual(await checkEnvelopes(await signed(resource), publisher.publicKey), {
      resource,
    });
  }
  for (const year of [2023, 1900])
    await assert.rejects(
      checkEnvelopes(
        await signed({ ...RESOURCE, issuedAt: `${year}-02-29T12:00:00Z` }),
        publisher.publicKey,
      ),
      { code: "bad_jwt" },
    );
});

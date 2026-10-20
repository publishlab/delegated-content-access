//
// The integrity surface. The publisher signs what it rendered - the resource,
// under one JWT - and the issuer verifies that signature before it touches a
// private key.
//
// What the envelope buys is the whole of this file: the sealed blobs travel
// through the client, which chooses what to send and under which name.
// The signed resource carries the renderId, and every blob of that render was
// sealed and bound to it and to the coordinate it sits at, so the issuer opens
// one under a renderId the publisher signed and a member name it read off the
// request it is answering.
//
// This file pins two shapes of failure. A signature, a version or an anchor
// that does not hold is 400 with nothing beside it: what an access decision
// reads and what every blob is opened under both come out of that one token, so
// a request failing there has asked nothing that could be answered in part. A
// blob that does not open at the coordinate it was presented at is one item of
// an answer that otherwise stands: 200, the keys that opened, and an entry in
// `errors` for the one that did not.
//
// This file runs two signing kids from the start, because a rotation here is a
// change of which held key signs and both public halves have to be resolvable by
// the issuer at once. That is a world with two kids on one domain, which
// `demo/scenarios/world.js` stands up. What stays local is the lookup wrapped
// around the world's own: it counts what it was asked, and the tests assert "the
// request stopped before the key lookup" against that count. Nothing shared
// counts.
//
// Pinned: one publisher, one issuer, ECDH P-256 sealing, direct transport,
// grant-all policy, the clock still.

import test from "node:test";
import assert from "node:assert/strict";

import {
  admitHeader,
  sign,
  verify,
  proofHash,
  decodeHeader,
} from "../../core-shared--publisher-issuer/jwt.js";
import { checkEnvelopes, checkVersion, publisherFor } from "../../core-issuer/IssuerEngine.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { RENDER_ID_BYTES } from "../../core-shared--publisher-issuer/bind.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { Clock } from "../../demo/actors/Clock.js";
import {
  base64urlEncode,
  base64urlDecode,
  utf8Encode,
  utf8Decode,
} from "../../core-shared/codec.js";
import { es256Sign, es256Verify } from "../../core-shared/cryptoProvider.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { seededRandom, signingKeypair } from "../support/keys.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { cryptoMeter } from "../../test-lib/fixtures/endpoint-hardening-world.js";
import {
  ACCESS_GROUP as PREMIUM,
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME as BODYTEXT,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  SIGNING_KID as KID_NEW,
  article,
  ungroupedArticle,
} from "../../demo/scenarios/fixtures.js";
import { directWorld } from "../../demo/scenarios/world.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

/** The kid the fixtures' publisher rotated away from. There is one in there. */
const KID_OLD = "sign-2025-09";

/**
 * The second name this file seals, and the accessGroup it sits in - one string
 * doing both jobs, so a per-item failure names the coordinate unambiguously.
 */
const LOCKED = "locked-data";

/** Coordinate messages are deliberately non-authoritative; clients branch on error. */
const UNSEAL_MESSAGE = "sealed value could not be opened";

/** What a client asks for when it has resolved nothing from its cache. */
const WHOLE_PAGE = [BODYTEXT, LOCKED];

/** The bodytext every render here carries, and what has to come back out. */
const ARTICLE = ARTICLES.A;
const DATA = '{"vote":{"for":7,"against":2},"passed":true}';

/**
 * One publisher over two signing keys, one issuer, and the pieces on both
 * sides of the wire. Two kids exist from the start so a rotation is a change
 * of which one signs, not a change of world.
 */
async function world() {
  const stage = await directWorld({ signingKids: { [DOMAIN]: [KID_OLD, KID_NEW] } });
  const pairs = stage.signingKeyPairs[DOMAIN];

  /** Counts application-owned exact-kid registration selections. */
  const asked = { publisherRegistrations: 0 };

  /** @param {any} request */
  const registrationFor = (request) => {
    try {
      const body = typeof request === "string" ? JSON.parse(request) : request;
      const { kid } = decodeHeader(body?.resourceJWT);
      asked.publisherRegistrations++;
      return typeof kid === "string" ? stage.publisherRegistrations.get(kid) : undefined;
    } catch {
      return undefined;
    }
  };

  // The store the world holds counts its own reaches, and the tests assert "no
  // private key was touched" against that count - the engine absorbs an unseal
  // failure into a per-item error, so the wire cannot tell a key that opened
  // nothing from a key that was never asked for.
  const { issuerKeys, keyStore } = stage;
  const engine = new IssuerEngine({
    operatingIssuerNames: [ISSUER_NAME],
    accessPolicy: new AllowAllPolicy(),
  });
  const endpointProcessor = new IssuerProcessor(engine, { periodKeyInput: true });
  const rawEndpoint = new UnlockEndpoint(endpointProcessor);
  const endpoint = {
    // A raw-body host admits first and selects the registration from the
    // admitted request only (core 6.2), as `createIssuerCore` describes.
    handleDocument: async (body) => {
      const admission = endpointProcessor.admit(body);
      if (admission.kind !== "admitted") return rawEndpoint.refusal(admission);
      return rawEndpoint.handleRequest({
        request: admission.request,
        registration: registrationFor(admission.request),
      });
    },
    handleRequest: (invocation) =>
      rawEndpoint.handleRequest({
        ...invocation,
        registration: registrationFor(invocation.request),
      }),
    refusal: rawEndpoint.refusal.bind(rawEndpoint),
  };

  /**
   * A publisher per render, because the two things a render varies here -
   * which key signs, and whether there is a cached path at all - are both
   * fixed at construction.
   *
   * With `periodKeySupply: null` the publisher has no cached path, so the
   * same two items render ungrouped unless `grouped` keeps their groups.
   *
   * @param {string} resourceId
   * @param {{ kid?: string, periodKeySupply?: object|null, grouped?: boolean }} [config]
   */
  async function render(resourceId, config = {}) {
    const publisher = stage.publisherWith({
      ...(config.kid === undefined ? {} : { signingKid: config.kid }),
      ...(config.periodKeySupply === undefined ? {} : { periodKeySupply: config.periodKeySupply }),
    });

    const contentKeyOnly = config.periodKeySupply === null && config.grouped !== true;
    const options = {
      resourceId,
      items: [
        {
          name: LOCKED,
          value: DATA,
          contentType: "application/json",
          accessGroups: contentKeyOnly ? [] : [LOCKED],
        },
      ],
    };
    const page = await publisher.render(
      contentKeyOnly ? ungroupedArticle("A", options) : article("A", options),
    );
    return page.asJson();
  }

  return {
    render,
    pairs,
    issuerKeys,
    keyStore,
    publisherRegistrations: stage.publisherRegistrations,
    engine,
    endpointProcessor,
    endpoint,
    rawEndpoint,
    asked,
    registrationFor,
  };
}

/**
 * A structurally valid token whose unverified header says something else. A
 * member patched to `undefined` leaves the header, because `JSON.stringify`
 * omits it.
 *
 * @param {string} token
 * @param {Record<string, unknown>} patch
 */
function forgeHeader(token, patch) {
  const [head, payload] = token.split(".");
  const header = JSON.parse(utf8Decode(base64urlDecode(head)));
  const forged = base64urlEncode(utf8Encode(JSON.stringify({ ...header, ...patch })));
  return `${forged}.${payload}.`;
}

/** A structurally valid token that says it is signed with something else. */
function forgeAlg(token, alg) {
  return forgeHeader(token, { alg });
}

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** @param {string} segment */
function withPadding(segment) {
  return segment + "=".repeat((4 - (segment.length % 4)) % 4);
}

/** @param {string} segment */
function withStandardAlphabet(segment) {
  return segment.replace(/-/g, "+").replace(/_/g, "/");
}

/** @param {string} segment */
function withNonzeroUnusedBits(segment) {
  const remainder = segment.length % 4;
  if (remainder !== 2 && remainder !== 3) {
    throw new Error("a base64url segment needs unused trailing bits");
  }
  const final = segment.at(-1);
  if (final === undefined) throw new Error("a base64url segment must not be empty");
  const index = BASE64URL_ALPHABET.indexOf(final);
  if (index < 0) throw new Error("the final character must be base64url");
  const dirty = BASE64URL_ALPHABET[index | 1];
  if (dirty === undefined) throw new Error("no altered base64url character");
  return segment.slice(0, -1) + dirty;
}

/**
 * Signs exactly the segment spelling supplied. This makes a malformed spelling
 * a publisher-authored token rather than a broken signature fixture.
 *
 * @param {string} headerSegment
 * @param {string} payloadSegment
 * @param {CryptoKey} privateKey
 */
async function signSegments(headerSegment, payloadSegment, privateKey) {
  const input = `${headerSegment}.${payloadSegment}`;
  const signature = await es256Sign(privateKey, utf8Encode(input));
  return `${input}.${base64urlEncode(signature)}`;
}

test("a token round-trips, carries its kid, and pins ES256", async () => {
  const pair = await signingKeypair();
  const payload = { renderId: "AAAAAAAAAAAA" };

  const token = await sign(payload, pair.privateKey, { kid: KID_NEW });
  assert.equal(token.split(".").length, 3);

  assert.deepEqual(decodeHeader(token), { alg: "ES256", typ: "JWT", kid: KID_NEW });
  assert.deepEqual(await verify(token, pair.publicKey), payload);

  // Another publisher's key does not open it.
  const other = await signingKeypair();
  await assert.rejects(
    () => verify(token, other.publicKey),
    (/** @type {any} */ err) => err.code === "bad_signature",
  );

  // A changed payload does not either, and the failure is the signature's.
  const [head, , signature] = token.split(".");
  const swapped = base64urlEncode(
    utf8Encode(JSON.stringify({ ...payload, renderId: "BBBBBBBBBBBB" })),
  );
  await assert.rejects(
    () => verify(`${head}.${swapped}.${signature}`, pair.publicKey),
    (/** @type {any} */ err) => err.code === "bad_signature",
  );
});

test("any alg but ES256 is refused, at signing and at verifying", async () => {
  const pair = await signingKeypair();
  const token = await sign({ renderId: "AAAAAAAAAAAA" }, pair.privateKey, { kid: KID_NEW });

  for (const alg of ["none", "HS256", "ES384", "RS256"]) {
    await assert.rejects(
      () => verify(forgeAlg(token, alg), pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_alg",
      `alg "${alg}" is refused before any signature work`,
    );
    await assert.rejects(
      () => sign({}, pair.privateKey, { alg }),
      (/** @type {any} */ err) => err.code === "unsupported_algorithm",
      `signing under "${alg}" is refused rather than downgraded`,
    );
  }

  for (const malformed of ["", "a.b", "a.b.c.d", "not-a-token", ".."]) {
    await assert.rejects(
      () => verify(malformed, pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `"${malformed}" is not a token`,
    );
  }

  // A header that is base64url JSON but not an object dies one layer in:
  // decodeSegment refuses an array or a bare value before alg is read.
  const [, body] = token.split(".");
  for (const notObject of [[], 42, "nope", null]) {
    const headSeg = base64urlEncode(utf8Encode(JSON.stringify(notObject)));
    await assert.rejects(
      () => verify(`${headSeg}.${body}.`, pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `a ${JSON.stringify(notObject)} header segment is not a JSON object`,
    );
  }
});

test("any typ but JWT is refused, at signing and at verifying", async () => {
  // The format fixes `typ` the way it fixes `alg`, and one ordered rule
  // admits both: a header that says anything else is refused where the alg
  // family dies, before a verification key is reached for. The refusal is
  // the alg one's code, because the two are one rule rather than two.
  const pair = await signingKeypair();
  const token = await sign({ renderId: "AAAAAAAAAAAA" }, pair.privateKey, { kid: KID_NEW });

  for (const typ of ["DCA", "jwt", "JWS", "", undefined]) {
    await assert.rejects(
      () => verify(forgeHeader(token, { typ }), pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_alg",
      `typ ${JSON.stringify(typ)} is refused before any signature work`,
    );
  }

  for (const typ of ["DCA", "jwt", "JWS", ""]) {
    await assert.rejects(
      () => sign({}, pair.privateKey, { typ }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
      `signing under typ "${typ}" is refused rather than relabelled`,
    );
  }
});

test("signing accepts the fixed alg and typ when a caller names them", async () => {
  const pair = await signingKeypair();
  for (const header of [
    { alg: "ES256" },
    { typ: "JWT" },
    { alg: "ES256", typ: "JWT", kid: KID_NEW },
  ]) {
    const token = await sign({ renderId: "AAAAAAAAAAAA" }, pair.privateKey, header);
    const decoded = decodeHeader(token);
    assert.equal(decoded.alg, "ES256", JSON.stringify(header));
    assert.equal(decoded.typ, "JWT", JSON.stringify(header));
  }
});

test("header admission answers the kid and refuses alg, then typ, then kid", async () => {
  // What the application selects a registration with. The three header
  // members are admitted in the order the protocol fixes, so a header wrong
  // in more than one place reports the first refusal and a token this issuer
  // will not verify never costs a registration lookup.
  const pair = await signingKeypair();
  const token = await sign({ renderId: "AAAAAAAAAAAA" }, pair.privateKey, { kid: KID_NEW });

  assert.equal(admitHeader(token), KID_NEW, "an admitted header answers the kid to select on");

  assert.throws(
    () => admitHeader(forgeHeader(token, { alg: "none", typ: "DCA", kid: "" })),
    (/** @type {any} */ err) => err.code === "bad_alg",
    "alg is the first refusal, whatever else the header got wrong",
  );
  assert.throws(
    () => admitHeader(forgeHeader(token, { typ: "DCA", kid: "" })),
    (/** @type {any} */ err) => err.code === "bad_alg",
    "typ is the second, still ahead of the kid",
  );
  for (const kid of [undefined, "", 42, null]) {
    assert.throws(
      () => admitHeader(forgeHeader(token, { kid })),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `kid ${JSON.stringify(kid)} selects no registration`,
    );
  }
  assert.throws(
    () => admitHeader("not-a-token"),
    (/** @type {any} */ err) => err.code === "bad_jwt",
  );
});

test("noncanonical signature spelling is bad_jwt; canonical bad signatures are bad_signature", async () => {
  const pair = await signingKeypair();
  const token = await sign({ renderId: "AAAAAAAAAAAA" }, pair.privateKey, { kid: KID_NEW });
  const [head, body, signature] = token.split(".");

  for (const segment of ["***", "@@@@", "not base64!"]) {
    await assert.rejects(
      () => verify(`${head}.${body}.${segment}`, pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `signature "${segment}" is refused as noncanonical JWS syntax`,
    );
  }

  // A canonical signature segment reaches ES256 verification. Wrong-width and
  // wrong-byte signatures therefore retain the signature-failure code.
  const wrongLength = base64urlEncode(new Uint8Array(63).fill(7));
  await assert.rejects(
    () => verify(`${head}.${body}.${wrongLength}`, pair.publicKey),
    (/** @type {any} */ err) => err.code === "bad_signature",
  );
  const wrongBytes = new Uint8Array(base64urlDecode(signature));
  wrongBytes[0] ^= 1;
  const wrongSignature = base64urlEncode(wrongBytes);
  await assert.rejects(
    () => verify(`${head}.${body}.${wrongSignature}`, pair.publicKey),
    (/** @type {any} */ err) => err.code === "bad_signature",
  );
});

test("noncanonical signature spellings are screened before verification", async () => {
  const pair = await signingKeypair();
  let token = "";
  let payload = { renderId: "AAAAAAAAAAAA", resourceId: "signature-spelling-0" };
  for (let attempt = 0; attempt < 128; attempt += 1) {
    payload = { renderId: "AAAAAAAAAAAA", resourceId: `signature-spelling-${attempt}` };
    token = await sign(payload, pair.privateKey, { kid: KID_NEW });
    const signatureSegment = token.split(".")[2];
    if (signatureSegment !== undefined && /[-_]/.test(signatureSegment)) break;
  }
  assert.ok(token, "the publisher signed a canonical control token");
  const [head, body, signature] = token.split(".");
  assert.ok(head && body && signature);
  assert.ok(/[-_]/.test(signature), "the signature has a URL-safe symbol to respell");
  assert.equal(
    signature.length % 4,
    2,
    "a 64-byte ES256 signature has two base64url remainder characters",
  );
  assert.deepEqual(await verify(token, pair.publicKey), payload);

  const signatureBytes = base64urlDecode(signature);
  const alternatives = [
    ["padding", `${signature}==`, true],
    ["standard alphabet", withStandardAlphabet(signature), true],
    ["two linefeeds", `${signature.slice(0, 40)}\n\n${signature.slice(40)}`, true],
    ["one space", `${signature.slice(0, 40)} ${signature.slice(40)}`, false],
    ["nonzero unused pad bits", withNonzeroUnusedBits(signature), true],
  ];
  for (const [name, segment, decodesToSameBytes] of alternatives) {
    if (decodesToSameBytes) assert.deepEqual(base64urlDecode(segment), signatureBytes, name);
    const respelled = `${head}.${body}.${segment}`;
    assert.throws(
      () => admitHeader(respelled),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `${name} is refused before header/kid admission`,
    );
    await assert.rejects(
      () => verify(respelled, pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `${name} is a noncanonical segment, not a bad ES256 signature`,
    );
  }
});

test("publisher-signed noncanonical header and payload segments are bad_jwt", async () => {
  const pair = await signingKeypair();

  let header;
  let headerSegment;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    header = { alg: "ES256", typ: "JWT", kid: `jws-kid-${attempt}` };
    headerSegment = base64urlEncode(utf8Encode(JSON.stringify(header)));
    if (headerSegment.length % 4 !== 0) break;
  }
  assert.ok(headerSegment && headerSegment.length % 4 !== 0, "header padding case is available");

  let payload;
  let payloadSegment;
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    payload = { renderId: "AAAAAAAAAAAAAAAAAAAAAA", resourceId: `publisher-${attempt}?>~` };
    payloadSegment = base64urlEncode(utf8Encode(JSON.stringify(payload)));
    if (payloadSegment.length % 4 !== 0 && /[-_]/.test(payloadSegment)) break;
  }
  assert.ok(
    payloadSegment && payloadSegment.length % 4 !== 0 && /[-_]/.test(payloadSegment),
    "payload has a pad position and a URL-safe symbol to respell",
  );

  const canonical = await signSegments(headerSegment, payloadSegment, pair.privateKey);
  assert.deepEqual(await verify(canonical, pair.publicKey), payload);

  const variants = [
    [
      "padded header",
      await signSegments(withPadding(headerSegment), payloadSegment, pair.privateKey),
    ],
    [
      "standard-alphabet payload",
      await signSegments(headerSegment, withStandardAlphabet(payloadSegment), pair.privateKey),
    ],
  ];
  for (const [name, token] of variants) {
    const [signedHeader, signedPayload, signature] = token.split(".");
    assert.equal(
      await es256Verify(
        pair.publicKey,
        base64urlDecode(signature),
        utf8Encode(`${signedHeader}.${signedPayload}`),
      ),
      true,
      `${name} token has a valid signature over its exact segment spelling`,
    );
    assert.throws(
      () => admitHeader(token),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `${name} is rejected before header/kid admission`,
    );
    await assert.rejects(
      () => verify(token, pair.publicKey),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `${name} is rejected as noncanonical syntax, not as a broken signature`,
    );
  }
});

test("noncanonical signature syntax is refused before publisher registration lookup", async () => {
  const { render, endpointProcessor, endpoint, asked, keyStore } = await world();
  const page = await render("123456");
  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);
  const [head, body, signature] = request.resourceJWT.split(".");
  assert.ok(head && body && signature);
  const beforeLookup = asked.publisherRegistrations;

  const answer = await unlockThroughAdmission(endpointProcessor, endpoint, {
    ...request,
    resourceJWT: `${head}.${body}.${signature}==`,
  });

  assert.equal(answer.status, 400);
  assert.equal(answer.body.error, "bad_jwt");
  assert.equal(
    asked.publisherRegistrations,
    beforeLookup,
    "noncanonical segment syntax is rejected before exact-kid registration lookup",
  );
  assert.equal(keyStore.reachCount, 0, "noncanonical segment syntax reaches no private key");
});

test("the proof hash covers the base64url string, never the bytes behind it", async () => {
  // The spec's deliberate choice, and the one a re-implementation gets wrong
  // by doing the more usual thing. Both readings are computed here, so the
  // test says which one is meant rather than pinning an opaque constant.
  const blob = "BFN2c2hlbGxvLXdvcmxkLXNlYWxlZC1ibG9iLWJ5dGVz";

  const overString = base64urlEncode(await subtle.digest("SHA-256", utf8Encode(blob)));
  const overBytes = base64urlEncode(await subtle.digest("SHA-256", base64urlDecode(blob)));

  assert.equal(await proofHash(blob), overString);
  assert.notEqual(overString, overBytes, "the two readings differ, which is why it has to be said");
  assert.equal(overString.length, 43, "32 bytes of digest, base64url, no padding");
  assert.match(overString, /^[A-Za-z0-9_-]{43}$/);

  // The argument is the wire string; anything else is a caller error, refused
  // rather than hashed after a coercion.
  for (const notString of [123, null, undefined, {}, new Uint8Array([1, 2, 3])]) {
    await assert.rejects(
      () => proofHash(/** @type {any} */ (notString)),
      (/** @type {any} */ err) => err.code === "bad_proof",
    );
  }
});

test("the render carries the envelope, and the blobs carry their own coordinate", async () => {
  const { render, pairs } = await world();
  const page = await render("123456");

  assert.deepEqual(
    Object.keys(page),
    ["version", "resource", "resourceJWT", "contentData", "issuerData", "sealedContent"],
    "the wire order the format writes",
  );

  const resource = await verify(page.resourceJWT, pairs[KID_NEW].publicKey);
  assert.deepEqual(
    resource,
    page.resource,
    "the signed payload is the resource object, no wrapper",
  );
  assert.equal(
    resource.origin,
    ORIGIN,
    "the delivery origin is a signed claim, and the issuer compares the observed Origin with it",
  );

  // The anchor every blob of this render was sealed under, and its width is
  // what a substitution from another render has to guess.
  assert.equal(base64urlDecode(resource.renderId).length, 16);

  // Beside a blob there is the name it sits under and nothing else - what it
  // is committed to is inside it, so there is no second copy of a coordinate
  // for a client to move independently.
  const sealed = page.issuerData[ISSUER_NAME].sealed;
  assert.deepEqual(Object.keys(sealed), ["contentKeys", "periodKeys"]);
  assert.deepEqual(Object.keys(sealed.contentKeys), [BODYTEXT, LOCKED]);

  const blobs = [
    ...Object.values(sealed.contentKeys),
    ...Object.values(sealed.periodKeys).flatMap((periods) => Object.values(periods)),
  ];
  assert.equal(blobs.length, 6, "two contentKeys and two accessGroups over two periods");
  assert.equal(new Set(blobs).size, 6, "one blob per coordinate, and every one its own seal");

  // The token names the signing key, so an issuer holding two can pick.
  assert.equal(decodeHeader(page.resourceJWT).kid, KID_NEW);
});

test("a publisher with no period-key supply ships no cached path at all", async () => {
  const { render } = await world();
  // A named group would need a cached path, so the render refuses it rather
  // than sealing the item without its wraps.
  await assert.rejects(render("123456", { periodKeySupply: null, grouped: true }), {
    code: "bad_config",
    message: /names accessGroups, and this publisher holds no periodKeySupply/,
  });
  const page = await render("123456", { periodKeySupply: null });

  assert.equal(
    Object.hasOwn(page.contentData.bodytext, "keys"),
    false,
    "nothing for a client to unwrap",
  );
  assert.deepEqual(
    Object.keys(page.issuerData[ISSUER_NAME].sealed),
    ["contentKeys"],
    "and nothing sealed for an issuer to hand out",
  );
});

test("the request carries the envelope and the whole page unlocks", async () => {
  const { render, endpointProcessor, endpoint, keyStore, asked } = await world();
  const page = await render("123456");
  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);

  assert.deepEqual(
    Object.keys(request),
    ["version", "issuerName", "resourceJWT", "keyId", "sealed"],
    "the field order the issuer reference builds",
  );
  assert.equal(
    request.resourceJWT,
    page.resourceJWT,
    "the envelope as it arrived, which the client cannot check",
  );

  const { status, body } = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    JSON.stringify(request),
  );

  assert.equal(status, 200);
  assert.deepEqual(Object.keys(body.keys.contentKeys), [BODYTEXT, LOCKED]);
  assert.deepEqual(Object.keys(body.keys.periodKeys), [PREMIUM, LOCKED]);
  assert.equal(body.errors, undefined);
  assert.equal(asked.publisherRegistrations, 1, "one exact kid selects one publisher registration");
  assert.equal(
    keyStore.reachCount,
    1,
    "the private key is reached for once, after the envelopes passed",
  );
});

test("a sealed blob moved to another slot does not open, and the honest ones beside it do", async () => {
  const { render, endpointProcessor, endpoint, keyStore, registrationFor } = await world();
  const page = await render("123456");

  const clean = requestFor(page, ISSUER_NAME, WHOLE_PAGE);
  const before = keyStore.reachCount;

  // The relabel: the blob sealed for `bodytext`, sent under `locked-data`.
  // It is this issuer's blob and this issuer's key does open blobs; what it
  // was sealed and bound to is `bodytext`, and the coordinate the issuer
  // rebuilds is the name it is answering under.
  const relabelled = structuredClone(clean);
  relabelled.sealed.contentKeys[LOCKED] = clean.sealed.contentKeys[BODYTEXT];

  const { status, body } = await unlockThroughAdmission(endpointProcessor, endpoint, relabelled);

  assert.equal(status, 200);
  assert.deepEqual(
    Object.keys(body.keys.contentKeys),
    [BODYTEXT],
    "the coordinate that was honest still answers",
  );
  assert.deepEqual(body.errors[LOCKED], { error: "unseal_failed", message: UNSEAL_MESSAGE });
  assert.equal(
    keyStore.reachCount,
    before + 1,
    "the refusal is the seal opening, so the private key was reached for",
  );

  const uniform = new UnlockEndpoint(endpointProcessor, { errorDetail: "uniform" });
  const uniformAnswer = await unlockThroughAdmission(
    endpointProcessor,
    uniform,
    relabelled,
    registrationFor(relabelled),
  );
  assert.equal(uniformAnswer.status, 200);
  assert.deepEqual(
    uniformAnswer.body,
    body,
    "errorDetail changes refusals only, never 200 coordinate errors",
  );

  // A periodKey moved across `t` is the same refusal at the other coordinate,
  // reported under the pair that names it.
  const acrossPeriods = structuredClone(clean);
  const [first, second] = Object.keys(clean.sealed.periodKeys[PREMIUM]);
  acrossPeriods.sealed.periodKeys[PREMIUM][second] = clean.sealed.periodKeys[PREMIUM][first];

  const moved = await unlockThroughAdmission(endpointProcessor, endpoint, acrossPeriods);
  assert.equal(moved.status, 200);
  assert.deepEqual(moved.body.errors[`${PREMIUM}|${second}`], {
    error: "unseal_failed",
    message: UNSEAL_MESSAGE,
  });
  assert.deepEqual(Object.keys(moved.body.keys.periodKeys[PREMIUM]), [first]);

  // And a blob from another render of the same publisher, under its own name:
  // the coordinate matches and the render it was sealed under does not.
  const other = await render("123457");
  const crossRender = structuredClone(clean);
  crossRender.sealed.contentKeys[BODYTEXT] =
    other.issuerData[ISSUER_NAME].sealed.contentKeys[BODYTEXT];

  const swapped = await unlockThroughAdmission(endpointProcessor, endpoint, crossRender);
  assert.equal(swapped.status, 200);
  assert.deepEqual(swapped.body.errors[BODYTEXT], {
    error: "unseal_failed",
    message: UNSEAL_MESSAGE,
  });
  assert.deepEqual(Object.keys(swapped.body.keys.contentKeys), [LOCKED]);

  // A period envelope is bound to its render too. Keep the target request's
  // signed resource and content-key siblings, and copy only one period blob.
  const periodT = Object.keys(clean.sealed.periodKeys[PREMIUM])[0];
  const periodSiblings = Object.keys(clean.sealed.periodKeys[PREMIUM]).filter((t) => t !== periodT);
  const honestPeriods = structuredClone(clean);
  honestPeriods.sealed.contentKeys = {};
  const honestPeriodAnswer = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    honestPeriods,
  );
  assert.equal(honestPeriodAnswer.status, 200);
  assert.equal(honestPeriodAnswer.body.errors, undefined);
  assert.ok(honestPeriodAnswer.body.keys.periodKeys[PREMIUM][periodT]);

  const crossRenderPeriod = structuredClone(honestPeriods);
  crossRenderPeriod.sealed.periodKeys[PREMIUM][periodT] =
    other.issuerData[ISSUER_NAME].sealed.periodKeys[PREMIUM][periodT];
  const periodAnswer = await unlockThroughAdmission(endpointProcessor, endpoint, crossRenderPeriod);
  assert.equal(periodAnswer.status, 200);
  assert.deepEqual(periodAnswer.body.errors[`${PREMIUM}|${periodT}`], {
    error: "unseal_failed",
    message: UNSEAL_MESSAGE,
  });
  assert.equal(periodAnswer.body.keys.periodKeys[PREMIUM][periodT], undefined);
  assert.deepEqual(Object.keys(periodAnswer.body.keys.periodKeys[PREMIUM]), periodSiblings);

  // The other period envelope remains useful: the client uses the issuer's
  // valid sibling key to unwrap this render's real item content.
  const periodClient = new Client({ publisherOrigin: ORIGIN });
  const periodData = periodClient.parse(page);
  await periodClient.applyResponse(periodData, ISSUER_NAME, periodAnswer.body, crossRenderPeriod);
  assert.equal(
    utf8Decode(
      await periodClient.decrypt(periodData, BODYTEXT, periodClient.extract(page, BODYTEXT)),
    ),
    ARTICLE,
  );

  // A name this render never sealed, added by the client. Whatever blob it
  // carries was sealed somewhere else, which is what the client cannot fix.
  const invented = structuredClone(clean);
  invented.sealed.contentKeys.premiumtext = clean.sealed.contentKeys[BODYTEXT];

  const added = await unlockThroughAdmission(endpointProcessor, endpoint, invented);
  assert.equal(added.status, 200);
  assert.deepEqual(added.body.errors.premiumtext, {
    error: "unseal_failed",
    message: UNSEAL_MESSAGE,
  });
  assert.deepEqual(Object.keys(added.body.keys.contentKeys), [BODYTEXT, LOCKED]);

  const malformed = structuredClone(clean);
  malformed.sealed.contentKeys[BODYTEXT] = { not: "a string" };
  const nonString = await unlockThroughAdmission(endpointProcessor, endpoint, malformed);
  assert.equal(nonString.status, 200);
  assert.deepEqual(nonString.body.errors[BODYTEXT], {
    error: "unseal_failed",
    message: UNSEAL_MESSAGE,
  });
  assert.deepEqual(
    Object.keys(nonString.body.keys.contentKeys),
    [LOCKED],
    "a non-string coordinate leaves its sibling open",
  );
});

test("a subset of the sealed keys is legal - the cache resolved the rest", async () => {
  const { render, endpointProcessor, endpoint } = await world();
  const page = await render("123456");

  const request = requestFor(page, ISSUER_NAME, [BODYTEXT]);
  assert.deepEqual(
    Object.keys(request.sealed.contentKeys),
    [BODYTEXT],
    "locked-data came out of the cache",
  );
  assert.deepEqual(Object.keys(request.sealed.periodKeys), [PREMIUM]);

  const { status, body } = await unlockThroughAdmission(endpointProcessor, endpoint, request);

  assert.equal(status, 200);
  assert.deepEqual(Object.keys(body.keys.contentKeys), [BODYTEXT]);
  assert.deepEqual(Object.keys(body.keys.periodKeys), [PREMIUM]);

  // A subset stops being a request when it goes down to nothing at all. A client
  // that resolved the whole page from its cache presents no coordinate, and
  // an ask with nothing in it is refused whole rather than answered with an
  // empty map.
  const empty = requestFor(page, ISSUER_NAME, []);
  const nothing = await unlockThroughAdmission(endpointProcessor, endpoint, empty);

  assert.equal(nothing.status, 400);
  assert.equal(nothing.body.error, "binding_failed");
  assert.equal(nothing.body.keys, undefined);
});

test("an unsupported version is refused before anything is read", async () => {
  const { render, endpointProcessor, endpoint, keyStore, asked } = await world();
  const page = await render("123456");

  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);
  const before = asked.publisherRegistrations;

  const meter = cryptoMeter();
  try {
    for (const version of ["2", "0", "1.0", "", null]) {
      // The native object and its serialized bytes: a raw-body host must keep
      // the same order, so the bytes path is counted too.
      for (const sent of [{ ...request, version }, JSON.stringify({ ...request, version })]) {
        const { status, body } = await unlockThroughAdmission(endpointProcessor, endpoint, sent);
        assert.equal(status, 400, `version ${JSON.stringify(version)} as ${typeof sent}`);
        assert.equal(body.error, "bad_version");
      }
    }
  } finally {
    meter.stop();
  }
  assert.equal(meter.counts.verify, 0, "version refusal precedes signature verification");

  assert.equal(
    asked.publisherRegistrations,
    before,
    "unsupported version refusal precedes publisher registration lookup",
  );
  assert.equal(keyStore.reachCount, 0);

  // The supported set is configuration, not a constant: an issuer that
  // speaks two versions accepts both.
  assert.doesNotThrow(() => checkVersion(new DcaRequest({ version: "2" }), ["1", "2"]));
  assert.throws(
    () => checkVersion(new DcaRequest({ version: "2" }), ["1"]),
    (/** @type {any} */ err) => err.code === "bad_version",
  );
});

test("a forged alg, a foreign signature or a missing envelope is a whole-request refusal", async () => {
  const { render, endpointProcessor, endpoint, keyStore } = await world();
  const page = await render("123456");
  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);
  const before = keyStore.reachCount;

  const cases = [
    ["resourceJWT stripped", { ...request, resourceJWT: undefined }, "bad_jwt"],
    [
      "resourceJWT under alg none",
      { ...request, resourceJWT: forgeAlg(request.resourceJWT, "none") },
      "bad_alg",
    ],
    [
      "resourceJWT under alg HS256",
      { ...request, resourceJWT: forgeAlg(request.resourceJWT, "HS256") },
      "bad_alg",
    ],
  ];

  const meter = cryptoMeter();
  let head;
  let payload;
  let signature;
  try {
    for (const [name, body, code] of cases) {
      const answer = await unlockThroughAdmission(endpointProcessor, endpoint, body);
      assert.equal(answer.status, 400, name);
      assert.equal(answer.body.error, code, name);
      assert.equal(answer.body.keys, undefined, name);
    }

    // A well-formed kid no registration answers is distinct from a malformed
    // locator. Neither reaches private work.
    [head, payload, signature] = request.resourceJWT.split(".");
    const header = JSON.parse(utf8Decode(base64urlDecode(head)));
    const unknownKid = base64urlEncode(
      utf8Encode(JSON.stringify({ ...header, kid: "sign-1999-01" })),
    );
    const strange = await unlockThroughAdmission(endpointProcessor, endpoint, {
      ...request,
      resourceJWT: `${unknownKid}.${payload}.${signature}`,
    });
    assert.equal(strange.status, 400);
    assert.equal(strange.body.error, "unknown_publisher_key");

    const emptyKid = base64urlEncode(utf8Encode(JSON.stringify({ ...header, kid: "" })));
    const empty = await unlockThroughAdmission(endpointProcessor, endpoint, {
      ...request,
      resourceJWT: `${emptyKid}.${payload}.${signature}`,
    });
    assert.equal(empty.status, 400);
    assert.equal(empty.body.error, "bad_jwt");

    const { kid: _kid, ...withoutKidHeader } = header;
    const missingKid = base64urlEncode(utf8Encode(JSON.stringify(withoutKidHeader)));
    const missing = await unlockThroughAdmission(endpointProcessor, endpoint, {
      ...request,
      resourceJWT: `${missingKid}.${payload}.${signature}`,
    });
    assert.equal(missing.status, 400);
    assert.equal(missing.body.error, "bad_jwt");
  } finally {
    meter.stop();
  }
  assert.equal(
    meter.counts.verify,
    0,
    "shape, algorithm and locator refusals precede verification",
  );

  const badSignature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  const verified = cryptoMeter();
  let foreign;
  try {
    foreign = await unlockThroughAdmission(endpointProcessor, endpoint, {
      ...request,
      resourceJWT: `${head}.${payload}.${badSignature}`,
    });
  } finally {
    verified.stop();
  }
  assert.equal(foreign.status, 400);
  assert.equal(foreign.body.error, "bad_signature");
  assert.equal(
    verified.counts.verify,
    1,
    "a known-key signature failure reaches verification once",
  );

  assert.equal(keyStore.reachCount, before, "not one of them reached a private key");
});

test("the envelope has to be the one these blobs were sealed under", async () => {
  const { render, endpointProcessor, endpoint, keyStore } = await world();
  const page = await render("123456");
  const other = await render("123457");

  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);
  const before = keyStore.reachCount;

  // A resourceJWT from another render: same publisher, same signing key, a
  // valid signature over a resource these blobs are not from. The envelope
  // passes, and every coordinate in the request is opened under the renderId
  // that token carries, so not one of them opens.
  const mixed = await unlockThroughAdmission(endpointProcessor, endpoint, {
    ...request,
    resourceJWT: other.resourceJWT,
  });

  assert.equal(mixed.status, 200);
  assert.deepEqual(mixed.body.keys.contentKeys, {});
  assert.equal(mixed.body.keys.periodKeys, undefined, "an empty section stays off the answer");
  assert.equal(Object.keys(mixed.body.errors).length, 6, "every coordinate the request carried");
  for (const entry of Object.values(mixed.body.errors)) {
    assert.equal(/** @type {any} */ (entry).error, "unseal_failed");
  }
  assert.equal(keyStore.reachCount, before + 1);

  // The unsigned `resource` beside it is not what anchors: it still names the
  // render these blobs are from, and it changed nothing above. The same
  // request with its own envelope back is the whole page again.
  const honest = await unlockThroughAdmission(endpointProcessor, endpoint, request);
  assert.deepEqual(Object.keys(honest.body.keys.contentKeys), [BODYTEXT, LOCKED]);
  assert.equal(honest.body.errors, undefined);
});

test("markup signed before a signing-key rotation still verifies, selected by kid", async () => {
  const { render, endpointProcessor, endpoint, pairs } = await world();

  // Rendered under the old key, then the publisher rotates. The issuer holds
  // both public halves, which is what an edge cache full of yesterday's
  // markup requires.
  const cached = await render("123456", { kid: KID_OLD });
  const fresh = await render("123457", { kid: KID_NEW });

  assert.equal(decodeHeader(cached.resourceJWT).kid, KID_OLD);
  assert.equal(decodeHeader(fresh.resourceJWT).kid, KID_NEW);

  for (const page of [cached, fresh]) {
    const { status, body } = await unlockThroughAdmission(
      endpointProcessor,
      endpoint,
      requestFor(page, ISSUER_NAME, WHOLE_PAGE),
    );
    assert.equal(status, 200);
    assert.deepEqual(Object.keys(body.keys.contentKeys), [BODYTEXT, LOCKED]);
  }

  // The kid selects, and it is not a hint: a token that names the new key and
  // was signed with the old one fails.
  const [, payload, signature] = cached.resourceJWT.split(".");
  const relabelledKid = base64urlEncode(
    utf8Encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: KID_NEW })),
  );
  const lying = await unlockThroughAdmission(endpointProcessor, endpoint, {
    ...requestFor(cached, ISSUER_NAME, WHOLE_PAGE),
    resourceJWT: `${relabelledKid}.${payload}.${signature}`,
  });
  assert.equal(lying.status, 400);
  assert.equal(lying.body.error, "bad_signature");

  // Both keys are real and different, so the pass above was not one key
  // answering for both.
  assert.notEqual(pairs[KID_OLD].publicKey, pairs[KID_NEW].publicKey);
  await assert.rejects(
    () => verify(cached.resourceJWT, pairs[KID_NEW].publicKey),
    (/** @type {any} */ err) => err.code === "bad_signature",
  );
});

test("a duplicate JSON member cannot make the gate and the backend disagree", async () => {
  // A raw body is the only place this attack exists - a parsed object cannot
  // carry one name twice. JSON.parse keeps the last member; a gate that read
  // the first would see a different blob. There is one view here, the
  // parsed one: the blob that survives the parse is the blob that gets
  // opened, at the name it was read from, and what it was sealed and bound to
  // travels inside it rather than in a second place to disagree with.
  const { render, endpointProcessor, endpoint } = await world();
  const page = await render("123456");
  const other = await render("123457");

  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);
  const mine = request.sealed.contentKeys[BODYTEXT];
  const foreign = other.issuerData[ISSUER_NAME].sealed.contentKeys[BODYTEXT];

  const honest = JSON.stringify(request);
  const member = (/** @type {string} */ blob) =>
    `${JSON.stringify(BODYTEXT)}:${JSON.stringify(blob)}`;
  assert.equal(honest.split(member(mine)).length - 1, 1, "the honest body names it once");

  /** The one member, written twice, in the order asked for. */
  const twice = (/** @type {string[]} */ blobs) =>
    honest.replace(member(mine), blobs.map(member).join(","));

  // Foreign blob first, the page's own last. JSON.parse takes the last, and
  // the answer is the one the honest body gets - byte for byte.
  const clean = await unlockThroughAdmission(endpointProcessor, endpoint, honest);
  const shadowed = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    twice([foreign, mine]),
  );

  assert.equal(shadowed.status, 200);
  assert.deepEqual(shadowed.body, clean.body, "the foreign member changed nothing that came back");

  // The other order: the foreign blob is what JSON.parse keeps, so it is what
  // the engine tries to open under `bodytext` - and it was sealed under
  // another render, so no key comes back for that name.
  const answer = await unlockThroughAdmission(endpointProcessor, endpoint, twice([mine, foreign]));
  assert.equal(answer.status, 200);
  assert.equal(answer.body.errors[BODYTEXT].error, "unseal_failed");
  assert.deepEqual(Object.keys(answer.body.keys.contentKeys), [LOCKED]);
});

test("the pure checks decide nothing about access", async () => {
  // They take a request and a key and either throw or return the verified
  // claims. No policy, no state, no keys of the issuer's own.
  const { render, pairs, endpointProcessor, endpoint, keyStore } = await world();
  const page = await render("123456");
  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);

  const claims = await checkEnvelopes(new DcaRequest(request), pairs[KID_NEW].publicKey);
  assert.deepEqual(
    Object.keys(claims),
    ["resource"],
    "what the signature carried, and nothing assembled beside it",
  );
  assert.deepEqual(claims.resource, page.resource);

  // The binding failure that is whole-request, and the only one: a signed
  // resource with no renderId anchors nothing, so there is no coordinate in
  // the request that could be opened and no partial answer to give.
  const anchorless = {
    issuedAt: page.resource.issuedAt,
    resourceId: page.resource.resourceId,
    data: page.resource.data,
  };
  const unanchored = {
    ...request,
    resource: anchorless,
    resourceJWT: await sign(anchorless, pairs[KID_NEW].privateKey, { kid: KID_NEW }),
  };

  await assert.rejects(
    () => checkEnvelopes(new DcaRequest(unanchored), pairs[KID_NEW].publicKey),
    (/** @type {any} */ err) => err.code === "binding_failed",
  );

  const before = keyStore.reachCount;
  const refused = await unlockThroughAdmission(endpointProcessor, endpoint, unanchored);

  assert.equal(refused.status, 400);
  assert.equal(refused.body.error, "binding_failed");
  assert.equal(refused.body.keys, undefined, "nothing partial comes back");
  assert.equal(refused.body.errors, undefined);
  assert.equal(keyStore.reachCount, before, "no private key was touched");
});

test("the registration is checked against the token kid, and nothing else", async () => {
  // The third of the pure pre-private-key checks, and the same shape as the
  // two beside it: a request and what the application supplied go in, the
  // registration or a typed error comes out. It reads no state of its own.
  const { render, publisherRegistrations } = await world();
  const request = new DcaRequest(requestFor(await render("123456"), ISSUER_NAME, WHOLE_PAGE));
  const registration = publisherRegistrations.get(KID_NEW);

  assert.equal(
    publisherFor(request, registration),
    registration,
    "the token names the kid this one was selected by",
  );

  assert.throws(
    () => publisherFor(request, publisherRegistrations.get(KID_OLD)),
    (/** @type {any} */ err) => err.code === "unknown_publisher_key",
  );
  assert.throws(
    () => publisherFor(new DcaRequest({ version: "1" }), registration),
    (/** @type {any} */ err) => err.code === "bad_jwt",
  );
});

test("a renderId outside the binding width is refused whole too", async () => {
  // The binding format has one 16-byte width, so a publisher
  // that renders at another width signs a render this issuer cannot
  // anchor. One anchor serves every coordinate, so there is no blob whose own
  // failure this could be: answering it per item would put `unseal_failed` on
  // each name and read like a key the issuer no longer holds.
  const { render, pairs, endpointProcessor, endpoint, keyStore } = await world();
  const page = await render("123456");
  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);

  const shallow = {
    ...page.resource,
    renderId: base64urlEncode(new Uint8Array(RENDER_ID_BYTES - 1).fill(9)),
  };
  const wrongWidth = {
    ...request,
    resource: shallow,
    resourceJWT: await sign(shallow, pairs[KID_NEW].privateKey, { kid: KID_NEW }),
  };

  await assert.rejects(
    () => checkEnvelopes(new DcaRequest(wrongWidth), pairs[KID_NEW].publicKey),
    (/** @type {any} */ err) => err.code === "binding_failed",
  );

  const before = keyStore.reachCount;
  const refused = await unlockThroughAdmission(endpointProcessor, endpoint, wrongWidth);

  assert.equal(refused.status, 400);
  assert.equal(refused.body.error, "binding_failed");
  assert.equal(refused.body.keys, undefined, "nothing partial comes back");
  assert.equal(refused.body.errors, undefined, "and no per-blob verdict either");
  assert.equal(keyStore.reachCount, before, "no private key was touched");
});

test("the other signed payload members are admitted, and none of them becomes a window", async () => {
  // `issuedAt`, `resourceId` and `data` are required members of the signed
  // resource and the issuer decides on them, so a render that signs one of
  // them malformed is refused whole: one token carries every coordinate, so
  // there is no blob whose own failure this could be.
  const { render, pairs, endpointProcessor, endpoint, keyStore } = await world();
  const page = await render("123456");
  const request = requestFor(page, ISSUER_NAME, WHOLE_PAGE);

  /** @param {object} resource */
  const signedAs = async (resource) => ({
    ...request,
    resource,
    resourceJWT: await sign(resource, pairs[KID_NEW].privateKey, { kid: KID_NEW }),
  });

  /** @type {[string, unknown][]} */
  const malformed = [
    ["issuedAt", "2025-10-23 14:20:00Z"],
    ["issuedAt", "2025-10-23T14:20:00+02:00"],
    ["issuedAt", "2025-10-23T14:20:00"],
    ["issuedAt", "2025-02-30T14:20:00Z"],
    ["issuedAt", "2025-13-01T14:20:00Z"],
    ["issuedAt", "2025-10-23T24:20:00Z"],
    ["issuedAt", 1_730_000_000],
    ["issuedAt", undefined],
    ["resourceId", ""],
    ["resourceId", 123_456],
    ["resourceId", undefined],
    ["data", []],
    ["data", "politics"],
    ["data", undefined],
  ];

  for (const [member, value] of malformed) {
    const posted = await signedAs({ ...page.resource, [member]: value });
    await assert.rejects(
      () => checkEnvelopes(new DcaRequest(posted), pairs[KID_NEW].publicKey),
      (/** @type {any} */ err) => err.code === "bad_jwt",
      `${member} as ${JSON.stringify(value)} is not admitted`,
    );

    const before = keyStore.reachCount;
    const refused = await unlockThroughAdmission(endpointProcessor, endpoint, posted);

    assert.equal(
      refused.status,
      400,
      `${member} as ${JSON.stringify(value)} is a whole-request refusal`,
    );
    assert.equal(refused.body.error, "bad_jwt");
    assert.equal(refused.body.keys, undefined, "nothing partial comes back");
    assert.equal(keyStore.reachCount, before, "no private key was touched");
  }

  // The format the member has to be in, and nothing more than that. A render
  // stamped a year ago still unlocks: `issuedAt` is admitted as a date-time
  // and carries no validity window, and the registered claims the format
  // says to ignore stay ignored beside it.
  const old = await signedAs({
    ...page.resource,
    issuedAt: "2024-09-01T08:00:00Z",
    iat: 1,
    exp: 1,
  });
  const answered = await unlockThroughAdmission(endpointProcessor, endpoint, old);

  assert.equal(
    answered.status,
    200,
    "an old issuedAt and an expired iat/exp pair are not an expiry",
  );
  assert.equal(typeof answered.body.keys.contentKeys[BODYTEXT], "string");

  const lowercase = await signedAs({
    ...page.resource,
    issuedAt: "2024-09-01t08:00:00z",
  });
  await assert.doesNotReject(
    () => checkEnvelopes(new DcaRequest(lowercase), pairs[KID_NEW].publicKey),
    "RFC 3339 permits lowercase t and z in a date-time",
  );
});

test("an engine takes publisher authority per request, not from constructor state", async () => {
  assert.doesNotThrow(
    () =>
      new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], accessPolicy: new AllowAllPolicy() }),
    "the application supplies the exact-kid PublisherRegistration for each request",
  );

  const { render, endpointProcessor, rawEndpoint, publisherRegistrations, keyStore } =
    await world();
  const request = requestFor(await render("123456"), ISSUER_NAME, WHOLE_PAGE);
  const oldRegistration = publisherRegistrations.get(KID_OLD);
  const result = await unlockThroughAdmission(
    endpointProcessor,
    rawEndpoint,
    request,
    oldRegistration,
  );

  assert.equal(result.status, 400);
  assert.equal(
    result.body.error,
    "unknown_publisher_key",
    "a valid but wrong-kid registration is not authority for this token",
  );
  assert.equal(
    keyStore.reachCount,
    0,
    "registration mismatch stops before scoped opening-key lookup",
  );
});

test("an engine with no access policy does not exist", async () => {
  assert.throws(
    () => new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME] }),
    (/** @type {any} */ err) => err.code === "bad_config",
    "a publisher signature authenticates claims but grants no caller a key",
  );
});

test("a publisher with no signing key does not exist either", async () => {
  const { issuerKeys } = await world();

  assert.throws(
    () =>
      new Sealer({
        origin: ORIGIN,
        clock: new Clock(AT),
        random: seededRandom(1),
        issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
        issuers: [
          {
            issuerName: ISSUER_NAME,
            keyId: KEY_ID,
            algorithm: ALGORITHM,
            publicKey: issuerKeys.publicKey,
          },
        ],
      }),
    (/** @type {any} */ err) => err.code === "bad_config",
  );
});

test("the client refuses an option it does not implement", async () => {
  // The same rule PeriodKeyCache and keySealing follow. A caller handing in a
  // clock, a transport mode or an options bag must not believe it was used.
  // (`clientKeys` is a real option, and a malformed one is a `bad_config`
  // rather than an option that is not there - see client-bound.test.js.)
  for (const config of [
    { clock: new Clock(AT) },
    { transportMode: "direct" },
    { options: {} },
    { keyBy: () => "" },
  ]) {
    assert.throws(
      () => new Client(config),
      (/** @type {any} */ err) => err.code === "unsupported_option",
      `Client({ ${Object.keys(config)[0]} })`,
    );
  }

  assert.doesNotThrow(() => new Client({ publisherOrigin: ORIGIN }));
});

test("the client refuses to stand in for a delivery origin it was not given", () => {
  // The origin is the coordinate the client files period keys under, and no
  // client invents it: a construction that names none has nowhere to file
  // them, and one that names a spelling the delivery boundary would never
  // report is refused on the same canonical rule the publisher signs under.
  for (const config of [
    undefined,
    {},
    { publisherOrigin: "" },
    { publisherOrigin: null },
    { publisherOrigin: `${ORIGIN}/` },
    { publisherOrigin: "www.news-site.example" },
  ]) {
    assert.throws(
      () => new Client(/** @type {any} */ (config)),
      (/** @type {any} */ err) => err.code === "bad_config",
      `Client(${JSON.stringify(config)})`,
    );
  }
});

test("the whole page decrypts after the verified unlock", async () => {
  // This file end to end, so the envelopes are not proven in isolation from
  // the thing they protect.
  const { render, endpointProcessor, endpoint } = await world();
  const page = await render("123456");

  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  const { status, body } = await unlockThroughAdmission(
    endpointProcessor,
    endpoint,
    unsealer.buildRequest(dcaData, ISSUER_NAME, WHOLE_PAGE),
  );
  assert.equal(status, 200);

  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);

  assert.equal(
    utf8Decode(await unsealer.decrypt(dcaData, BODYTEXT, unsealer.extract(page, BODYTEXT))),
    ARTICLE,
  );
  assert.equal(
    utf8Decode(await unsealer.decrypt(dcaData, LOCKED, unsealer.extract(page, LOCKED))),
    DATA,
  );
});

//
// Publisher seals one content item, the page crosses to a client as JSON, the
// client asks an issuer to unseal the contentKey, and the content decrypts.
//
// Pinned: one contentKey, ECDH P-256 key sealing, direct transport, no
// periodKeys, no cache, no breaker, no fallback. The signed envelope is here
// because there is no render without it - what it proves belongs to
// jwt-proof.test.js, and this only carries it.
//
// `periodKeySupply: null` is the whole of what this file asks of its world. A
// publisher holding a supply fills each record's `keys`, and the render
// without them is the one section every test here reads. Its items name no
// group, because a publisher with no supply refuses one it cannot wrap under.
//
// The render is configured from the fixture and asserted against the spelling.
// A name that is read back as `CONTENT_NAME` on both sides would follow a
// fixture rename along and go on passing over a wire that had moved.
//
// What an issuer answers a keyId with - held, retired or never held - is
// rotation.test.js's axis; the unseal failure below comes from a wrong key
// rather than a wrong keyId.

import test from "node:test";
import assert from "node:assert/strict";

import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { Client } from "../test-lib/harnesses/client.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { IssuerKeyStore } from "../demo/support/IssuerKeyStore.js";
import { assertWireSafe } from "../demo/support/wireSafe.js";
import { Clock } from "../demo/actors/Clock.js";
import { utf8Decode } from "../core-shared/codec.js";
import { DcaError } from "../core-shared/errors.js";
import { Sealer } from "../core-publisher/Sealer.js";
import { directWorld } from "../demo/scenarios/world.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import {
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  SIGNING_KID,
  ungroupedArticle,
} from "../demo/scenarios/fixtures.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../test-reference/support/keys.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";
import {
  contentRecordOf,
  issuerBlockOf,
  sealedContentByName,
  sealedContentOf,
} from "../test-lib/helpers/inspect.js";
import { errorMap, keyAt } from "../test-reference/support/namedRecords.js";

const ARTICLE = ARTICLES.A;

/**
 * What every render in this file is asked for: the spec's own resourceId, and
 * metadata with a second field in it so the signed claims are more than one
 * string.
 */
const ARTICLE_OPTIONS = {
  resourceId: RESOURCE_ID,
  data: { section: "politics", tags: ["breaking"] },
};

/** The stream the world's own publisher draws from, so a red run replays. */
const SEED = 20251023;

/**
 * The delivery form, split back into the two halves the render produced. A page
 * carries them joined; every assertion here is about one side or the other, and
 * saying which is what keeps a claim about the dca-data off the ciphertext.
 * The ciphertext half comes back as the Sealer returns it, by contentName.
 *
 * @param {any} page
 * @returns {{ dcaData: any, sealedContent: Record<string, string> }}
 */
function halves(page) {
  const { sealedContent: _records, ...dcaData } = page;
  return { dcaData, sealedContent: sealedContentByName(page) };
}

/**
 * The two cores facing each other, with the one article rendered across them.
 * The page arrives as a client reads it - a JSON round trip, so anything in a
 * render that could not cross a wire died at the render rather than silently.
 */
async function render() {
  const stage = await directWorld({
    periodKeySupply: null,
    seed: SEED,
  });
  const page = await stage.render("A", ARTICLE_OPTIONS);

  return { stage, page, rendered: halves(page) };
}

/**
 * A publisher of this world's own, drawing from a stream at `seed` rather than
 * the world's. Two of them at one seed replay each other; one of them asked
 * twice draws on from where it left off.
 *
 * @param {any} stage
 * @param {number} seed
 * @returns {{ seal: () => Promise<{ dcaData: any, sealedContent: any }> }}
 */
function publisherAt(stage, seed) {
  const publisher = stage.publisherWith({ random: seededRandom(seed) });

  return {
    seal: async () =>
      halves((await publisher.render(ungroupedArticle("A", ARTICLE_OPTIONS))).asJson()),
  };
}

/**
 * One page sealed for an RSA-OAEP issuer. RSA has no ECDH ephemeral pair.
 */
async function rsaRender() {
  const issuerKeys = await issuerKeypair("rsa-oaep");
  const signing = await signingKeypair();
  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock(AT),
    random: seededRandom(91),
    signingKeys: { [SIGNING_KID]: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "rsa-oaep",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource(RESOURCE_ID, ARTICLE_OPTIONS.data);
  sealer.content(CONTENT_NAME, ARTICLE, "text/html", { accessGroups: [] });

  const { dcaData, sealedContent } = await sealer.seal();
  return { page: { ...dcaData, sealedContent }, issuerKeys, signing };
}

test("seal, unlock, decrypt", async () => {
  const { stage, page } = await render();

  const unsealer = new Client({ publisherOrigin: ORIGIN });

  const dcaData = unsealer.parse(page);
  assert.equal(dcaData.version, "1");
  assert.equal(
    dcaData.resource.origin,
    ORIGIN,
    "the one origin the render is delivered from is signed",
  );

  const request = unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
  assert.equal(request.issuerName, ISSUER_NAME);
  assert.equal(request.keyId, KEY_ID);
  assert.equal(typeof keyAt(request.sealed.contentKeys, { contentName: "bodytext" }), "string");

  // The one hop. An HTTP body is a raw JSON string.
  const { status, body } = await unlockThroughAdmission(
    stage.processor,
    stage.endpoint,
    JSON.stringify(request),
    stage.publisherRegistration,
  );
  assert.equal(status, 200);
  assert.equal(typeof keyAt(body.keys.contentKeys, { contentName: "bodytext" }), "string");
  assert.equal(body.errors, undefined);

  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);

  const contentKey = await unsealer.contentKeyFor(dcaData, "bodytext");
  assert.ok(contentKey instanceof Uint8Array);
  assert.equal(contentKey.length, 16, "AES-128");

  const ciphertext = unsealer.extract(page, "bodytext");
  const plaintext = await unsealer.decrypt(dcaData, "bodytext", ciphertext);

  assert.equal(utf8Decode(plaintext), ARTICLE);
});

test("a Sealer renders to an RSA-OAEP issuer without ECDH-only options", async () => {
  const { page } = await rsaRender();

  const sealed = keyAt(issuerBlockOf(page, ISSUER_NAME).sealed.contentKeys, {
    contentName: CONTENT_NAME,
  });
  assert.equal(typeof sealed, "string");
  assert.equal(sealed.length, 342, "one 2048-bit RSA-OAEP ciphertext");
});

test("an RSA-OAEP IssuerEngine opens a bound RSA blob with a 200 response", async () => {
  const { page, issuerKeys, signing } = await rsaRender();
  const keyStore = new IssuerKeyStore([
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: "rsa-oaep",
      privateKey: issuerKeys.privateKey,
    },
  ]);
  const publisherRegistration = {
    kid: SIGNING_KID,
    publicKey: signing.publicKey,
    origin: `https://${DOMAIN}`,
    openingKeys: keyStore,
  };
  const processor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: new AllowAllPolicy(),
    }),
  );
  const endpoint = new UnlockEndpoint(processor);
  const client = new Client({ publisherOrigin: ORIGIN });
  const dcaData = client.parse(page);

  const { status, body } = await unlockThroughAdmission(
    processor,
    endpoint,
    client.buildRequest(dcaData, ISSUER_NAME, [CONTENT_NAME]),
    publisherRegistration,
  );

  assert.equal(status, 200);
  assert.equal(typeof keyAt(body.keys.contentKeys, { contentName: CONTENT_NAME }), "string");
  assert.equal(body.errors, undefined);
});

test("the page carries nothing but JSON values", async () => {
  const { rendered } = await render();

  assert.deepEqual(Object.keys(rendered.dcaData).sort(), [
    "contentData",
    "issuerData",
    "resource",
    "resourceJWT",
    "version",
  ]);
  assert.equal(typeof rendered.dcaData.resourceJWT, "string");
  assert.deepEqual(Object.keys(contentRecordOf(rendered.dcaData, "bodytext")).sort(), [
    "contentName",
    "contentType",
  ]);
  assert.equal(rendered.dcaData.resource.issuedAt, "2025-10-23T14:20:00.000Z");
  assert.equal(rendered.dcaData.resource.resourceId, "123456");
  assert.equal(
    rendered.dcaData.resource.renderId.length,
    22,
    "exactly 16 bytes in unpadded base64url",
  );
  assert.equal(Object.hasOwn(issuerBlockOf(rendered.dcaData, ISSUER_NAME), "unlockUrl"), false);
  assert.equal(typeof rendered.sealedContent.bodytext, "string");
});

test("the sealed content on the page is opaque without an unlock", async () => {
  const { page } = await render();
  assert.ok(!sealedContentOf(page, "bodytext").includes("council"));

  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  assert.equal(await unsealer.contentKeyFor(dcaData, "bodytext"), null);
  await assert.rejects(
    () => unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext")),
    /no key/i,
  );
});

test("one publisher rendering the same article twice shares no key material", async () => {
  const { stage } = await render();

  const publisher = publisherAt(stage, 9);
  const first = await publisher.seal();
  const second = await publisher.seal();

  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const openContentKey = async (rendered) => {
    const dcaData = unsealer.parse(rendered.dcaData);
    const { status, body } = await unlockThroughAdmission(
      stage.processor,
      stage.endpoint,
      unsealer.buildRequest(dcaData, ISSUER_NAME, [CONTENT_NAME]),
      stage.publisherRegistration,
    );
    assert.equal(status, 200);
    await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
    return unsealer.contentKeyFor(dcaData, CONTENT_NAME);
  };

  const firstContentKey = await openContentKey(first);
  const secondContentKey = await openContentKey(second);

  assert.notEqual(first.dcaData.resource.renderId, second.dcaData.resource.renderId);
  assert.equal(Object.hasOwn(contentRecordOf(first.dcaData, "bodytext"), "nonce"), false);
  assert.equal(Object.hasOwn(contentRecordOf(second.dcaData, "bodytext"), "nonce"), false);
  assert.notEqual(first.sealedContent.bodytext, second.sealedContent.bodytext);
  assert.notEqual(
    keyAt(issuerBlockOf(first.dcaData, ISSUER_NAME).sealed.contentKeys, {
      contentName: "bodytext",
    }),
    keyAt(issuerBlockOf(second.dcaData, ISSUER_NAME).sealed.contentKeys, {
      contentName: "bodytext",
    }),
  );
  assert.ok(firstContentKey instanceof Uint8Array);
  assert.ok(secondContentKey instanceof Uint8Array);
  assert.notDeepEqual(
    firstContentKey,
    secondContentKey,
    "the contentKey itself changes on every render",
  );
});

test("two content items in one render receive distinct 16-byte contentKeys", async () => {
  const { stage } = await render();
  const page = await stage.render("A", {
    ...ARTICLE_OPTIONS,
    items: [{ name: "sidebar", value: "<p>Related coverage</p>" }],
  });
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);
  const contentNames = [CONTENT_NAME, "sidebar"];
  const { status, body } = await unlockThroughAdmission(
    stage.processor,
    stage.endpoint,
    unsealer.buildRequest(dcaData, ISSUER_NAME, contentNames),
    stage.publisherRegistration,
  );
  assert.equal(status, 200);
  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);

  const bodytextKey = await unsealer.contentKeyFor(dcaData, CONTENT_NAME);
  const sidebarKey = await unsealer.contentKeyFor(dcaData, "sidebar");
  assert.ok(bodytextKey instanceof Uint8Array);
  assert.ok(sidebarKey instanceof Uint8Array);
  assert.equal(bodytextKey.length, 16, "bodytext uses one raw AES-128 key");
  assert.equal(sidebarKey.length, 16, "sidebar uses one raw AES-128 key");
  assert.notDeepEqual(bodytextKey, sidebarKey, "each item receives independent key bytes");
});

test("a seeded byte stream replays a render byte for byte", async () => {
  // Same seed, same issuer key, same clock - only the ephemeral seal keypair
  // and the ES256 nonce are WebCrypto's, so everything but the sealed blob
  // and the JWT signatures has to match.
  const { stage } = await render();

  // A publisher apiece, each drawing from its own stream at the same seed.
  // Asking one of them twice would replay the second render on the bytes left
  // over from the first, which is the thing this test would then not be
  // checking.
  const first = await publisherAt(stage, 5).seal();
  const second = await publisherAt(stage, 5).seal();

  assert.equal(first.dcaData.resource.renderId, second.dcaData.resource.renderId);
  assert.equal(Object.hasOwn(contentRecordOf(first.dcaData, "bodytext"), "nonce"), false);
  assert.equal(Object.hasOwn(contentRecordOf(second.dcaData, "bodytext"), "nonce"), false);
  assert.deepEqual(
    contentRecordOf(first.dcaData, "bodytext"),
    contentRecordOf(second.dcaData, "bodytext"),
  );
  assert.equal(first.sealedContent.bodytext, second.sealedContent.bodytext);
});

test("the issuer reports an unseal failure per item and still answers 200", async () => {
  const { stage, page } = await render();

  // The same coordinate, another issuer's key behind it. Reaching the store
  // is what finds that out, which is why this is a per-item error rather than a
  // whole-request refusal.
  const otherIssuer = await issuerKeypair();
  const keyStore = new IssuerKeyStore([
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      privateKey: otherIssuer.privateKey,
    },
  ]);

  const processor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: new AllowAllPolicy(),
    }),
  );
  const endpoint = new UnlockEndpoint(processor);
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  const wrongKeyRegistration = { ...stage.publisherRegistration, openingKeys: keyStore };
  const { status, body } = await unlockThroughAdmission(
    processor,
    endpoint,
    unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]),
    wrongKeyRegistration,
  );

  assert.equal(status, 200);
  assert.deepEqual(body.keys.contentKeys, []);
  assert.equal(errorMap(body.errors).bodytext.error, "unseal_failed");
});

test("a page with no envelope builds a request the wire will carry, and the issuer says why it fails", async () => {
  const { stage, page } = await render();
  const unsealer = new Client({ publisherOrigin: ORIGIN });

  // No resourceJWT on the page: the format makes that a bad page before a
  // request is derived from it, so the request with the member absent is
  // built off a sound page and the member dropped on its way to the wire. A
  // member holding undefined would die at assertWireSafe on the client, and
  // the reader would never hear the issuer's own answer.
  //
  // The request below is therefore manufactured, and says nothing about what
  // the builder emits for a member it cannot fill. That property is held at
  // `test-reference/core-shared/dca-request.test.js`, "an optional member
  // the client cannot fill sends no member in its place".
  const stripped = JSON.parse(JSON.stringify(page));
  delete stripped.resourceJWT;
  assert.throws(
    () => unsealer.buildRequest(unsealer.parse(stripped), ISSUER_NAME, ["bodytext"]),
    (/** @type {any} */ e) => e.code === "bad_page",
  );

  const request = unsealer.buildRequest(unsealer.parse(page), ISSUER_NAME, ["bodytext"]);
  delete request.resourceJWT;
  assert.equal(
    Object.hasOwn(request, "resourceJWT"),
    false,
    "absent, not a member holding undefined",
  );
  assert.doesNotThrow(() => assertWireSafe(request));

  const { status, body } = await unlockThroughAdmission(
    stage.processor,
    stage.endpoint,
    request,
    stage.publisherRegistration,
  );
  assert.equal(status, 400);
  assert.equal(body.error, "bad_jwt");

  // A keyId the page's issuer entry does not carry is another matter: the
  // format derives no request from a block with no keyId, so the client asks
  // that issuer nothing instead of sending a request with the member absent.
  const noKeyId = JSON.parse(JSON.stringify(page));
  delete issuerBlockOf(noKeyId, ISSUER_NAME).keyId;

  assert.throws(
    () => unsealer.buildRequest(unsealer.parse(noKeyId), ISSUER_NAME, ["bodytext"]),
    (/** @type {any} */ e) => e.code === "unknown_issuer",
  );
});

test("absent or malformed carried nonce and aad do not affect opening", async () => {
  const { stage, page } = await render();

  // Unlocked first, so the mangled field is what answers. A client holding no
  // key reports the miss it reaches first, and that would say nothing about
  // what a codec does with a nonce that is not there.
  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const held = unsealer.parse(page);
  const { body } = await unlockThroughAdmission(
    stage.processor,
    stage.endpoint,
    unsealer.buildRequest(held, ISSUER_NAME, ["bodytext"]),
    stage.publisherRegistration,
  );
  await unsealer.applyResponse(held, ISSUER_NAME, body);

  /** @param {(p: any) => void} mangle */
  const mangled = (mangle) => {
    const copy = JSON.parse(JSON.stringify(page));
    mangle(copy);
    return copy;
  };

  assert.equal(Object.hasOwn(contentRecordOf(page, "bodytext"), "nonce"), false);
  const noNonce = page;
  assert.ok(
    (
      await unsealer.decrypt(
        unsealer.parse(noNonce),
        "bodytext",
        unsealer.extract(noNonce, "bodytext"),
      )
    ).length > 0,
  );

  for (const aad of [42, "123456|1|bodytext", { a: 1 }, null]) {
    const carried = mangled((p) => {
      contentRecordOf(p, "bodytext").aad = aad;
      contentRecordOf(p, "bodytext").nonce = aad;
    });
    const bytes = await unsealer.decrypt(
      unsealer.parse(carried),
      "bodytext",
      unsealer.extract(carried, "bodytext"),
    );
    assert.ok(bytes.length > 0, `aad ${JSON.stringify(aad)} is ignored`);
  }
});

test("a tampered or undecodable ciphertext is a typed refusal, not a bare crypto throw", async () => {
  const { stage, page } = await render();

  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  const request = unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
  const { body } = await unlockThroughAdmission(
    stage.processor,
    stage.endpoint,
    JSON.stringify(request),
    stage.publisherRegistration,
  );
  await unsealer.applyResponse(dcaData, ISSUER_NAME, body);

  const ciphertext = unsealer.extract(page, "bodytext");
  assert.equal(
    utf8Decode(await unsealer.decrypt(dcaData, "bodytext", ciphertext)),
    ARTICLE,
    "the control",
  );

  // The key is the one that just worked and the substitute is still
  // base64url, so the only thing left to refuse is the tag. `DcaError` is the
  // assertion rather than "it threw": `PageLoad` rethrows anything else, and
  // a tampered blob has to reach the reader as a locked item.
  const flipped = (ciphertext[0] === "A" ? "B" : "A") + ciphertext.slice(1);
  await assert.rejects(
    () => unsealer.decrypt(dcaData, "bodytext", flipped),
    (/** @type {any} */ err) => err instanceof DcaError && err.code === "decrypt_failed",
  );

  // And a string that is not base64url at all fails one step earlier, in the
  // codec. A page carried it, so the fault lies with the page.
  await assert.rejects(
    () => unsealer.decrypt(dcaData, "bodytext", "not base64url!!"),
    (/** @type {any} */ err) => err instanceof DcaError && err.code === "bad_page",
  );
});

test("the endpoint refuses a body that is not JSON", async () => {
  const { stage } = await render();
  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], accessPolicy: new AllowAllPolicy() }),
  );
  const endpoint = new UnlockEndpoint(processor);
  const { status, body } = await unlockThroughAdmission(
    processor,
    endpoint,
    "{not json",
    stage.publisherRegistration,
  );

  assert.equal(status, 400);
  assert.equal(body.error, "invalid_json");
});

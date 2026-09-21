//
// The content aad rebuilt on the client instead of shipped to it. The variant
// is `experiments/derived-content-aad/implementation/`; this file checks behaviour.
//
// Four questions, in order: does the derivation agree with the publisher on
// every page there is to check, does a page whose shipped aad is wrong for
// every item still go end to end through an untouched issuer, does the derived
// binding fail the same way the shipped one does when its inputs are moved, and
// what does ignoring the field cost. The last two tests go under the aad
// itself: what it is holding today, and the one arrangement where a
// transmitted binding and a rebuilt one stop agreeing.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  contentAadFor,
  disagreeingShippedAad,
  DISAGREEING_AAD,
} from "../implementation/contentAad.js";
import { DerivingUnsealer } from "../test-lib/harnesses/DerivingUnsealer.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { exactPeriodKeySupply } from "../../../demo/support/exactPeriodKeySupply.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { encrypt, decrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import {
  base64urlEncode,
  base64urlDecode,
  utf8Decode,
  utf8Encode,
} from "../../../core-shared/codec.js";
import { DcaError } from "../../../core-shared/errors.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";

const { subtle } = globalThis.crypto;

const DOMAIN = "www.news-site.example";
const ORIGIN = `https://${DOMAIN}`;
const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const GROUP = "premium";
const AT = "2025-10-23T14:20:00Z";

const BODYTEXT = "<p>The council voted 7-2 to rezone the harbour.</p>";
const LOCKED_DATA = '{"votes":{"for":7,"against":2}}';

/**
 * A publisher, an issuer that shares nothing with it but a public key, and the
 * stock endpoint between them. Two content items under one accessGroup, which
 * is the smallest world in which a ciphertext has another slot to be moved to.
 *
 * The issuer holds one publisher registration: the exact resourceJWT header kid
 * this publisher signs under, the verification key, the browser origin it is
 * onboarded on, and the opening keys that registration may address. The
 * application resolves it by kid and hands it in, so `unlock` below carries it
 * the way an issuer application does.
 *
 * @returns {Promise<{
 *   render: (resourceId?: string) => Promise<any>,
 *   unlock: (unsealer: Client, dcaData: any, contentNames: string[]) => Promise<void>,
 * }>}
 */
async function world() {
  const issuerKeys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const signingKeys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);

  const publisherRegistration = {
    kid: SIGNING_KID,
    publicKey: signingKeys.publicKey,
    origin: `https://${DOMAIN}`,
    openingKeys: {
      /**
       * @param {string} issuerName
       * @param {string} keyId
       */
      get: (issuerName, keyId) =>
        issuerName === ISSUER_NAME && keyId === KEY_ID
          ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
          : undefined,
    },
  };

  const endpointProcessor = new IssuerProcessor(
    new IssuerEngine({
      accessPolicy: new AllowAllPolicy(),
    }),
  );
  const endpoint = new UnlockEndpoint(endpointProcessor);

  let seed = 1;
  const periodKeySupply = exactPeriodKeySupply({ random: new Random({ seed: 7 }) });

  return {
    /** @param {string} [resourceId] */
    async render(resourceId = "123456") {
      const sealer = new Sealer({
        origin: ORIGIN,
        clock: new Clock(AT),
        random: new Random({ seed: seed++ }),
        signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
        periodKeySupply,
        issuers: [
          {
            issuerName: ISSUER_NAME,
            keyId: KEY_ID,
            algorithm: "ECDH-P256",
            publicKey: issuerKeys.publicKey,
            unlockUrl: "https://api.example.com/unlock",
          },
        ],
      });

      sealer.resource(resourceId, { section: "politics" });
      sealer.content("bodytext", BODYTEXT, "text/html", { accessGroups: [GROUP] });
      sealer.content("locked-data", LOCKED_DATA, "application/json", { accessGroups: [GROUP] });

      const rendered = await sealer.seal();
      return JSON.parse(
        JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
      );
    },

    /**
     * One unlock, through the port and the engine as they ship. `unsealer`
     * is whichever client is being run; `buildRequest` and `applyResponse`
     * are the base class's on both of them.
     *
     * @param {Client} unsealer
     * @param {any} dcaData
     * @param {string[]} contentNames
     * @returns {Promise<void>}
     */
    async unlock(unsealer, dcaData, contentNames) {
      const { status, body } = await unlockThroughAdmission(
        endpointProcessor,
        endpoint,
        unsealer.buildRequest(dcaData, ISSUER_NAME, contentNames),
        publisherRegistration,
      );
      assert.equal(status, 200, "the issuer answered");
      await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
    },
  };
}

/**
 * A refusal with the code named. `assert.rejects` takes its second argument as
 * a failure message when it is a string, so a bare description there passes on
 * any rejection at all; every check below wants the code.
 *
 * @param {Promise<unknown>} work
 * @param {string} code
 * @param {string} why
 * @returns {Promise<void>}
 */
async function refuses(work, code, why) {
  await assert.rejects(
    work,
    (/** @type {any} */ err) => err instanceof DcaError && err.code === code,
    why,
  );
}

// ---------------------------------------------------------------------------
// a. The derivation against the publisher, on a fresh render and on every
//    vector the repository has pinned.
// ---------------------------------------------------------------------------

test("the derived aad is the aad the publisher shipped, on a fresh render", async () => {
  const page = await (await world()).render();

  const names = Object.keys(page.contentData);
  assert.deepEqual(names, ["bodytext", "locked-data"], "both items ship a record");

  for (const contentName of names) {
    assert.equal(
      contentAadFor(page, contentName),
      page.contentData[contentName].aad,
      `${contentName}: derived and shipped are one string`,
    );
  }

  // And it is the grammar, not a coincidence of this render: the page's own
  // fields in the publisher's order.
  assert.equal(contentAadFor(page, "bodytext"), "123456|1|bodytext");
});

test("the derived aad is the aad every checked-in protocol fixture recorded", () => {
  const dir = fileURLToPath(
    new URL("../../../../../verification/fixtures/protocol-v1/", import.meta.url),
  );

  let checkedVectors = 0;
  let checkedItems = 0;

  for (const file of readdirSync(dir).filter((name) => name.endsWith(".json"))) {
    const vector = JSON.parse(readFileSync(dir + file, "utf8"));
    const dcaData = vector.expected?.dcaData;
    if (!dcaData?.contentData) continue;

    checkedVectors++;
    for (const [contentName, record] of Object.entries(dcaData.contentData)) {
      assert.equal(
        contentAadFor(dcaData, contentName),
        /** @type {any} */ (record).aad,
        `${file}: ${contentName}`,
      );
      checkedItems++;
    }
  }

  // The reject vectors carry an unlock request rather than a render, so they
  // have no contentData to check; the counts say how much of the
  // directory this test actually covered.
  assert.equal(checkedVectors, 1, "the one render vector");
  assert.equal(checkedItems, 2, "its two content items");
});

test("a page missing either input is refused, not joined into a plausible string", () => {
  const page = { version: "1", resource: { resourceId: "123456" } };

  for (const [label, dcaData] of [
    ["no version", { resource: page.resource }],
    ["a numeric version", { version: 1, resource: page.resource }],
    ["no resource", { version: "1" }],
    ["no resourceId", { version: "1", resource: {} }],
    ["a numeric resourceId", { version: "1", resource: { resourceId: 123456 } }],
  ]) {
    assert.throws(
      () => contentAadFor(/** @type {any} */ (dcaData), "bodytext"),
      (/** @type {any} */ err) => err instanceof DcaError && err.code === "bad_page",
      `${label}: a typed refusal rather than "undefined|1|bodytext"`,
    );
  }

  assert.equal(
    contentAadFor(page, "bodytext"),
    "123456|1|bodytext",
    "and the complete page still derives",
  );
});

// ---------------------------------------------------------------------------
// b. A wire whose aad disagrees with the derivation, through the issuer that
//    never had an opinion about it.
// ---------------------------------------------------------------------------

test("disagreeingShippedAad rewrites every aad and leaves the caller's page alone", async () => {
  const page = await (await world()).render();
  const disagreeing = disagreeingShippedAad(page);

  for (const contentName of Object.keys(disagreeing.contentData)) {
    const record = disagreeing.contentData[contentName];
    assert.equal(
      record.aad,
      DISAGREEING_AAD,
      `${contentName}: the shipped field carries the wrong value`,
    );
    assert.notEqual(
      record.aad,
      contentAadFor(page, contentName),
      `${contentName}: and it is not the derived one`,
    );
    assert.equal(
      record.contentType,
      page.contentData[contentName].contentType,
      "contentType stays",
    );
    assert.equal(record.nonce, page.contentData[contentName].nonce, "nonce stays");
  }

  // Still the format's page: `aad` is a required member, so the base reader
  // that holds a record to its shape takes every one of these and the variant
  // asks nothing of it.
  const reader = new DcaData(disagreeing);
  for (const contentName of Object.keys(disagreeing.contentData)) {
    assert.equal(
      reader.contentDataFor(contentName),
      disagreeing.contentData[contentName],
      `${contentName}: a record the base reader accepts`,
    );
  }

  // The input is the comparison, so it has to survive being rewritten.
  for (const contentName of Object.keys(page.contentData)) {
    assert.equal(
      page.contentData[contentName].aad,
      contentAadFor(page, contentName),
      `${contentName}: the publisher's value is still on the original`,
    );
  }

  // Everything else on the page is carried through, ciphertext included.
  assert.deepEqual(disagreeing.sealedContent, page.sealedContent);
  assert.deepEqual(disagreeing.issuerData, page.issuerData);
  for (const contentName of Object.keys(page.contentData)) {
    assert.deepEqual(disagreeing.contentData[contentName].keys, page.contentData[contentName].keys);
  }
});

test("a page whose shipped aad is wrong for every item goes end to end through the stock issuer", async () => {
  const { render, unlock } = await world();
  const page = disagreeingShippedAad(await render());

  for (const contentName of Object.keys(page.contentData)) {
    assert.equal(
      page.contentData[contentName].aad,
      DISAGREEING_AAD,
      "the field is wrong, not absent",
    );
  }

  const unsealer = new DerivingUnsealer({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  assert.deepEqual(
    await unsealer.resolve(dcaData, ["bodytext", "locked-data"]),
    { covered: [], missing: ["bodytext", "locked-data"] },
    "an empty cache covers nothing",
  );

  // `UnlockEndpoint` and `IssuerEngine` are imported from ports/ and core/
  // unchanged, and that is the point of running them here: the issuer never
  // reads contentData, so a page whose aad disagrees with the derivation is a
  // page it cannot tell from any other. Nothing on the signed side moved
  // either: `resourceJWT` signs the resource, and the sealed blobs are held
  // by the binding rebuilt from the renderId inside it.
  await unlock(unsealer, dcaData, ["bodytext", "locked-data"]);

  for (const [contentName, expected] of [
    ["bodytext", BODYTEXT],
    ["locked-data", LOCKED_DATA],
  ]) {
    const plaintext = await unsealer.decrypt(
      dcaData,
      contentName,
      unsealer.extract(page, contentName),
    );
    assert.equal(utf8Decode(plaintext), expected, `${contentName}: opened under a rebuilt aad`);
  }

  // The cached path too: the same unlock filed periodKeys, so a second read
  // of the same page resolves without asking again and decrypts the same way.
  assert.deepEqual(
    (await unsealer.resolve(dcaData, ["bodytext", "locked-data"])).covered,
    ["bodytext", "locked-data"],
    "the periodKeys from that one unlock cover both items",
  );

  // The same page on the stock client, which reads the field: it is granted
  // the same keys and opens nothing. So the page above really does disagree,
  // and the deriving client got through it on the derivation.
  const shipped = new Client({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
  const shippedData = shipped.parse(page);
  await unlock(shipped, shippedData, ["bodytext", "locked-data"]);

  for (const contentName of ["bodytext", "locked-data"]) {
    await refuses(
      shipped.decrypt(shippedData, contentName, shipped.extract(page, contentName)),
      "decrypt_failed",
      `${contentName}: the shipped value is not what the ciphertext was sealed under`,
    );
  }
});

test("the deriving client keeps the base class's misses", async () => {
  const { render, unlock } = await world();
  const page = disagreeingShippedAad(await render());

  const unsealer = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  await refuses(
    unsealer.decrypt(dcaData, "byline", "AAAA"),
    "unknown_content",
    "a name the page has no entry for",
  );
  await refuses(
    unsealer.decrypt(dcaData, "constructor", "AAAA"),
    "unknown_content",
    "an inherited name",
  );
  await refuses(unsealer.decrypt(dcaData, "bodytext", null), "unknown_content", "no ciphertext");
  await refuses(
    unsealer.decrypt(dcaData, "bodytext", page.sealedContent.bodytext),
    "no_key",
    "nothing has opened a key yet",
  );

  await unlock(unsealer, dcaData, ["bodytext"]);
  assert.equal(
    utf8Decode(await unsealer.decrypt(dcaData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
    "and the same call once a key is held",
  );

  // The page guards too, which are the ones a copied `decrypt` drifts away
  // from: only the aad is this class's to choose, so a nonce the page does not
  // carry and a ciphertext that is not base64url are the same bad page here as
  // on the base class: a typed refusal and not a TypeError out of the codec.
  const noNonce = structuredClone(dcaData);
  delete noNonce.contentData.bodytext.nonce;
  await refuses(
    unsealer.decrypt(noNonce, "bodytext", page.sealedContent.bodytext),
    "bad_page",
    "a record with no nonce",
  );
  await refuses(
    unsealer.decrypt(dcaData, "bodytext", "not base64url!!"),
    "bad_page",
    "a ciphertext the codec cannot read",
  );
});

// ---------------------------------------------------------------------------
// c. The derived binding under tampered inputs, beside the shipped one.
// ---------------------------------------------------------------------------

test("a derived aad fails closed when the fields it is built from are moved", async () => {
  const { render, unlock } = await world();
  const page = disagreeingShippedAad(await render());

  const unsealer = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  // Unlocked first, so what follows is about the aad and not about a key the
  // client never got. The renderId is untouched by both edits, so the held
  // contentKey is still found.
  await unlock(unsealer, dcaData, ["bodytext"]);
  assert.equal(
    utf8Decode(await unsealer.decrypt(dcaData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
  );

  for (const [code, why, edit] of [
    [
      "decrypt_failed",
      "a changed resourceId derives another aad, and GCM refuses the tag",
      (/** @type {any} */ d) => {
        d.resource.resourceId = "123457";
      },
    ],
    // `version` is also read by `DcaData`'s own constructor, which runs
    // before `decrypt()` ever derives an aad. A changed version is an
    // unknown page version, and the parser refuses it there: a bad_page,
    // not a tag GCM rejected.
    [
      "bad_page",
      "a changed version is an unknown page version, and the parser refuses it before any AEAD work",
      (/** @type {any} */ d) => {
        d.version = "X";
      },
    ],
  ]) {
    const tampered = structuredClone(dcaData);
    /** @type {any} */ (edit)(tampered);

    await refuses(unsealer.decrypt(tampered, "bodytext", page.sealedContent.bodytext), code, why);
  }
});

test("a tampered shipped aad fails the same way, on the stock client", async () => {
  // The comparison: the failure the variant produces is the failure the
  // format already produces. A shipped aad that no longer matches what the
  // ciphertext was sealed under is a tag failure, exactly as a derived one is.
  const { render, unlock } = await world();
  const page = await render();

  const unsealer = new Client({ publisherOrigin: ORIGIN });
  const dcaData = unsealer.parse(page);

  await unlock(unsealer, dcaData, ["bodytext"]);
  assert.equal(
    utf8Decode(await unsealer.decrypt(dcaData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
  );

  // The empty string is a string, so it clears the aad guard in
  // the client's decrypt and reaches the tag, which is why it is a tampered
  // aad here and not a bad page in the test above.
  for (const aad of ["123457|1|bodytext", "123456|2|bodytext", "123456|1|locked-data", ""]) {
    const tampered = structuredClone(dcaData);
    tampered.contentData.bodytext.aad = aad;

    await refuses(
      unsealer.decrypt(tampered, "bodytext", page.sealedContent.bodytext),
      "decrypt_failed",
      `a shipped aad of "${aad}" opens nothing`,
    );
  }

  // Neither client hands back a plaintext it could not authenticate: the two
  // readings differ in where the string comes from and not in what a
  // mismatch does.
});

// ---------------------------------------------------------------------------
// d. What the wire field is for: an aad the grammar does not describe.
// ---------------------------------------------------------------------------

/**
 * A page assembled by hand around one ciphertext, with the aad as its
 * publisher chose it. No Sealer, because a Sealer cannot produce this (the
 * grammar is compiled into it), and no issuer, because the contentKey is
 * handed to the client directly through `applyResponse`, which is the shape a
 * direct-transport answer arrives in.
 *
 * @param {string} aad
 * @param {string} value
 * @returns {Promise<{ page: any, contentKey: Uint8Array }>}
 */
async function pageWithAad(aad, value) {
  const contentKey = new Uint8Array(16).fill(11);
  const nonce = new Uint8Array(NONCE_BYTES).fill(3);
  const ciphertext = await encrypt(contentKey, nonce, utf8Encode(value), utf8Encode(aad));

  return {
    page: {
      version: "1",
      resource: {
        renderId: "handAssembled01",
        domain: DOMAIN,
        issuedAt: AT,
        resourceId: "123456",
        data: {},
      },
      resourceJWT: `eyJhbGciOiJFUzI1NiIsImtpZCI6InNpZ24tMjAyNS0xMCJ9.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "handAssembled01", domain: DOMAIN, issuedAt: AT, resourceId: "123456", data: {} })))}.signature`,
      issuerData: {
        [ISSUER_NAME]: {
          keyId: KEY_ID,
          unlockUrl: "https://issuer.example/unlock",
          sealed: { contentKeys: { bodytext: "sealed-placeholder" } },
        },
      },
      contentData: {
        bodytext: { contentType: "text/html", nonce: base64urlEncode(nonce), aad },
      },
      sealedContent: { bodytext: base64urlEncode(ciphertext) },
    },
    contentKey,
  };
}

/**
 * The contentKey for one render, put where a direct answer would have put it.
 *
 * @param {Client} unsealer
 * @param {any} dcaData
 * @param {Record<string, Uint8Array>} contentKeys
 * @returns {Promise<void>}
 */
async function handOver(unsealer, dcaData, contentKeys) {
  const delivered = Object.fromEntries(
    Object.entries(contentKeys).map(([name, key]) => [name, base64urlEncode(key)]),
  );
  unsealer.buildRequest(dcaData, ISSUER_NAME, Object.keys(contentKeys));
  await unsealer.applyResponse(dcaData, ISSUER_NAME, { keys: { contentKeys: delivered } });
}

test("an aad outside the grammar opens on the stock client and not on the deriving one", async () => {
  const { page, contentKey } = await pageWithAad("my-custom-binding-v2", BODYTEXT);

  const shipped = new Client({ publisherOrigin: ORIGIN });
  const shippedData = shipped.parse(page);
  await handOver(shipped, shippedData, { bodytext: contentKey });

  assert.equal(
    utf8Decode(await shipped.decrypt(shippedData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
    "the page is conformant under the shipped-aad reading",
  );

  const derived = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const derivedData = derived.parse(page);
  await handOver(derived, derivedData, { bodytext: contentKey });

  await assert.rejects(
    derived.decrypt(derivedData, "bodytext", page.sealedContent.bodytext),
    'and unreadable under derivation: the client builds "123456|1|bodytext" and the seal is not under it',
  );

  // The refusal is the aad and not the hand assembly: the same page sealed
  // inside the grammar opens on the same client. That is the trade: a
  // deriving client makes the grammar normative, and a publisher that wants
  // its own binding has to give up on that client.
  const inGrammar = await pageWithAad("123456|1|bodytext", BODYTEXT);
  const inGrammarData = derived.parse(inGrammar.page);
  await handOver(derived, inGrammarData, { bodytext: inGrammar.contentKey });

  assert.equal(
    utf8Decode(
      await derived.decrypt(inGrammarData, "bodytext", inGrammar.page.sealedContent.bodytext),
    ),
    BODYTEXT,
  );
});

// ---------------------------------------------------------------------------
// e. What the content aad is load-bearing for, at the level of core-shared/aead.
// ---------------------------------------------------------------------------

test("per-slot aads stop a ciphertext swap, and so does a per-slot key on its own", async () => {
  const nonceA = new Uint8Array(NONCE_BYTES).fill(1);
  const nonceB = new Uint8Array(NONCE_BYTES).fill(2);
  const aadA = utf8Encode("123456|1|bodytext");
  const aadB = utf8Encode("123456|1|locked-data");

  // One key over two slots, separated by the aad alone.
  const shared = new Uint8Array(16).fill(5);
  const sealedA = await encrypt(shared, nonceA, utf8Encode(BODYTEXT), aadA);
  const sealedB = await encrypt(shared, nonceB, utf8Encode(LOCKED_DATA), aadB);

  assert.equal(
    utf8Decode(await decrypt(shared, nonceA, sealedA, aadA)),
    BODYTEXT,
    "each slot opens as itself",
  );
  assert.equal(utf8Decode(await decrypt(shared, nonceB, sealedB, aadB)), LOCKED_DATA);

  // Slot A's ciphertext read as slot A, which is what a client filling that
  // slot does: the aad is the only thing that refuses it.
  await assert.rejects(
    decrypt(shared, nonceB, sealedA, aadB),
    "B's slot will not take A's ciphertext",
  );
  await assert.rejects(decrypt(shared, nonceA, sealedB, aadA), "nor the other way");

  // The same swap with no aad at all, under the fresh per-item contentKeys
  // the format actually seals with. The key separation refuses it on its own.
  const keyA = new Uint8Array(16).fill(6);
  const keyB = new Uint8Array(16).fill(7);
  const plainA = await encrypt(keyA, nonceA, utf8Encode(BODYTEXT));
  const plainB = await encrypt(keyB, nonceB, utf8Encode(LOCKED_DATA));

  assert.equal(utf8Decode(await decrypt(keyA, nonceA, plainA)), BODYTEXT);
  await assert.rejects(decrypt(keyB, nonceB, plainA), "B's key does not open A's ciphertext");
  await assert.rejects(decrypt(keyA, nonceA, plainB), "nor the other way");

  // So: with one contentKey per item per render, the content aad is shadowed
  // by key separation; every swap it refuses is a swap the wrong key refuses
  // first. It becomes load-bearing the moment a key is shared across slots,
  // which is the arrangement the next test builds.
});

// ---------------------------------------------------------------------------
// f. Where the two readings stop agreeing: a shipped binding travels with the
//    ciphertext, a rebuilt one stays with the slot.
// ---------------------------------------------------------------------------

/**
 * Two items under one contentKey, each sealed under its own grammar aad.
 * `core-publisher/Sealer` draws a fresh key per item, so it never produces
 * this, and that is the point: this is the arrangement in which the content
 * aad is the only thing keeping the two slots apart.
 *
 * @returns {Promise<{ page: any, contentKey: Uint8Array }>}
 */
async function sharedKeyPage() {
  const contentKey = new Uint8Array(16).fill(13);

  /** @type {Record<string, any>} */
  const contentData = {};
  /** @type {Record<string, string>} */
  const sealedContent = {};

  for (const [index, [contentName, contentType, value]] of [
    ["bodytext", "text/html", BODYTEXT],
    ["locked-data", "application/json", LOCKED_DATA],
  ].entries()) {
    const nonce = new Uint8Array(NONCE_BYTES).fill(index + 1);
    const aad = `123456|1|${contentName}`;
    const ciphertext = await encrypt(contentKey, nonce, utf8Encode(value), utf8Encode(aad));

    contentData[contentName] = { contentType, nonce: base64urlEncode(nonce), aad };
    sealedContent[contentName] = base64urlEncode(ciphertext);
  }

  return {
    page: {
      version: "1",
      resource: {
        renderId: "sharedKeyRender1",
        domain: DOMAIN,
        issuedAt: AT,
        resourceId: "123456",
        data: {},
      },
      resourceJWT: `eyJhbGciOiJFUzI1NiIsImtpZCI6InNpZ24tMjAyNS0xMCJ9.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "sharedKeyRender1", domain: DOMAIN, issuedAt: AT, resourceId: "123456", data: {} })))}.signature`,
      issuerData: {
        [ISSUER_NAME]: {
          keyId: KEY_ID,
          unlockUrl: "https://issuer.example/unlock",
          sealed: {
            contentKeys: {
              bodytext: "sealed-placeholder",
              "locked-data": "sealed-placeholder",
            },
          },
        },
      },
      contentData,
      sealedContent,
    },
    contentKey,
  };
}

/**
 * The attack: the ciphertext and its whole seal-data record moved into the
 * other slot. Nothing signs contentData, so the record moves as freely as
 * the ciphertext does, which makes a shipped binding a binding to whatever
 * it arrived with.
 *
 * @param {any} page
 * @returns {any}
 */
function swapSlots(page) {
  const swapped = structuredClone(page);

  swapped.contentData = {
    bodytext: page.contentData["locked-data"],
    "locked-data": page.contentData.bodytext,
  };
  swapped.sealedContent = {
    bodytext: page.sealedContent["locked-data"],
    "locked-data": page.sealedContent.bodytext,
  };

  return swapped;
}

test("a shipped aad moves with the ciphertext it was meant to pin; a derived one does not", async () => {
  const { page, contentKey } = await sharedKeyPage();
  const swapped = swapSlots(page);

  const shipped = new Client({ publisherOrigin: ORIGIN });
  const shippedData = shipped.parse(swapped);
  await handOver(shipped, shippedData, { bodytext: contentKey, "locked-data": contentKey });

  // The client asks for the `bodytext` slot and is handed the other item's
  // plaintext, authenticated: the aad it checked against travelled inside the
  // record that moved.
  assert.equal(
    utf8Decode(await shipped.decrypt(shippedData, "bodytext", swapped.sealedContent.bodytext)),
    LOCKED_DATA,
    "the shipped binding verified, in the slot it was moved into",
  );

  const derived = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const derivedData = derived.parse(swapped);
  await handOver(derived, derivedData, { bodytext: contentKey, "locked-data": contentKey });

  // The tag and not any rejection: both slots hold a key and a decodable
  // record here, so `decrypt_failed` says the aad refused the move.
  // A bare "it threw" would pass on a client that had merely lost the key.
  await assert.rejects(
    derived.decrypt(derivedData, "bodytext", swapped.sealedContent.bodytext),
    (/** @type {any} */ err) => err instanceof DcaError && err.code === "decrypt_failed",
    "the derived aad names the slot being filled, so the move is what it refuses",
  );
  await assert.rejects(
    derived.decrypt(derivedData, "locked-data", swapped.sealedContent["locked-data"]),
    (/** @type {any} */ err) => err instanceof DcaError && err.code === "decrypt_failed",
    "and the other direction of the same swap",
  );

  // Unswapped, both clients agree: the difference is the attack and not the
  // reading.
  const straightShipped = new Client({ publisherOrigin: ORIGIN });
  const straightShippedData = straightShipped.parse(page);
  await handOver(straightShipped, straightShippedData, {
    bodytext: contentKey,
    "locked-data": contentKey,
  });

  const straightDerived = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const straightDerivedData = straightDerived.parse(page);
  await handOver(straightDerived, straightDerivedData, {
    bodytext: contentKey,
    "locked-data": contentKey,
  });

  for (const [contentName, expected] of [
    ["bodytext", BODYTEXT],
    ["locked-data", LOCKED_DATA],
  ]) {
    assert.equal(
      utf8Decode(
        await straightShipped.decrypt(
          straightShippedData,
          contentName,
          page.sealedContent[contentName],
        ),
      ),
      expected,
    );
    assert.equal(
      utf8Decode(
        await straightDerived.decrypt(
          straightDerivedData,
          contentName,
          page.sealedContent[contentName],
        ),
      ),
      expected,
    );
  }

  // This is the issuer's own argument, one layer down. It opens a blob under
  // the coordinate the request presented it at rather than under a label
  // travelling beside it, for the reason this test just ran.
});

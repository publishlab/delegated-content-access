//
// Current render/name content AAD beside the old carried one. The publisher
// uses a fresh key with fixed zero nonce and carries neither nonce nor AAD;
// the stock client builds the transcript and ignores a
// carried member. The old carried format and the historical mirror rebuild are
// explicit controls here: `test-lib/oldFormat.js` reseals an authentic render
// under `resourceId|1|contentName`, `CarriedAadClient` opens under the carried
// string, and `DerivingUnsealer` rebuilds that string from the mirror.
//
// The stock issuer tests use authentic publisher output and keys a real issuer
// granted. The hand-built invalid examples characterize a local AEAD or client
// behavior.

import test from "node:test";
import assert from "node:assert/strict";

import {
  contentAadFor,
  disagreeingShippedAad,
  DISAGREEING_AAD,
} from "../implementation/contentAad.js";
import { DerivingUnsealer } from "../test-lib/harnesses/DerivingUnsealer.js";
import { CarriedAadClient } from "../test-lib/harnesses/CarriedAadClient.js";
import { oldCarriedAad, resealOldFormat, openOldPeriodRecord } from "../test-lib/oldFormat.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { randomPeriodKeySupply } from "../../../demo/support/randomPeriodKeySupply.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { encrypt, decrypt, NONCE_BYTES } from "../../../core-shared/aead.js";
import {
  base64urlDecode,
  base64urlEncode,
  utf8Decode,
  utf8Encode,
} from "../../../core-shared/codec.js";
import { DcaError } from "../../../core-shared/errors.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import { adoptedContentAad } from "../implementation/tokenRepresentationAad.js";

// Ciphertext remains the Sealer's local name map; descriptor wire collections
// use named records. Looking up a descriptor follows last-whole-record order.
const contentRecord = (page, name) =>
  page.contentData.findLast((record) => record.contentName === name);
const issuerRecord = (page, name) =>
  page.issuerData.findLast((record) => record.issuerName === name);
const contentNames = (page) => page.contentData.map((record) => record.contentName);
const replaceRecord = (page, name, record) => {
  page.contentData = page.contentData.map((current) =>
    current.contentName === name ? { ...record, contentName: name } : current,
  );
};

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
 * @param {'both'|'period-only'|'item-only'} [supply]
 * @returns {Promise<{
 *   render: (resourceId?: string, bodytext?: string) => Promise<any>,
 *   unlock: (unsealer: Client, dcaData: any, contentNames: string[]) => Promise<any>,
 * }>}
 */
async function world(supply = "both") {
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
          ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
          : undefined,
    },
  };

  const endpointProcessor = new IssuerProcessor(
    new IssuerEngine({
      operatingIssuerNames: [ISSUER_NAME],
      accessPolicy: new AllowAllPolicy(),
    }),
    { periodKeyInput: supply === "period-only" },
  );
  const endpoint = new UnlockEndpoint(endpointProcessor);

  let seed = 1;
  const periodKeySupply = randomPeriodKeySupply({ random: new Random({ seed: 7 }) });

  return {
    /** @param {string} [resourceId] @param {string} [bodytext] */
    async render(resourceId = "123456", bodytext = BODYTEXT) {
      const sealer = new Sealer({
        origin: ORIGIN,
        clock: new Clock(AT),
        random: new Random({ seed: seed++ }),
        signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
        periodKeySupply,
        issuerSupplyPlanFor:
          supply === "both"
            ? wholeRenderIssuerSupplyPlan
            : (_issuer, render) => ({
                contentKeyNames: supply === "item-only" ? [...render.contentNames] : [],
                suppliedAccessGroups: supply === "period-only" ? [...render.accessGroups] : [],
              }),
        issuers: [
          {
            issuerName: ISSUER_NAME,
            keyId: KEY_ID,
            algorithm: "ecdh-p256",
            publicKey: issuerKeys.publicKey,
          },
        ],
      });

      sealer.resource(resourceId, { section: "politics" });
      sealer.content("bodytext", bodytext, "text/html", { accessGroups: [GROUP] });
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
     * @returns {Promise<any>} the issuer's response body
     */
    async unlock(unsealer, dcaData, contentNames) {
      const { status, body } = await unlockThroughAdmission(
        endpointProcessor,
        endpoint,
        unsealer.buildRequest(dcaData, ISSUER_NAME, contentNames),
        publisherRegistration,
      );
      assert.equal(status, 200, `the issuer answered: ${JSON.stringify(body)}`);
      await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
      return body;
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

/**
 * Old-format control: the same authentic render, every item resealed under the
 * old carried string with the keys a real issuer grants for it. The issuer
 * envelopes and resourceJWT stay the publisher's.
 *
 * @param {(unsealer: Client, dcaData: any, contentNames: string[]) => Promise<any>} unlock
 * @param {any} page
 * @param {string} [resourceId]
 * @returns {Promise<any>}
 */
async function oldFormatOf(unlock, page, resourceId = "123456", periodKeys = undefined) {
  const reader = new Client({ publisherOrigin: ORIGIN });
  const data = reader.parse(page);
  const names = contentNames(page);
  await unlock(reader, data, names);
  /** @type {Record<string, Uint8Array|CryptoKey>} */
  const keys = {};
  for (const name of names) {
    const key = await reader.contentKeyFor(data, name);
    assert.ok(key, `the real grant reached the "${name}" key`);
    keys[name] = key;
  }
  return resealOldFormat(page, keys, resourceId, periodKeys);
}

// ---------------------------------------------------------------------------
// a. The adopted format against the old one, on a fresh render.
// ---------------------------------------------------------------------------

test("old and new formats do not open each other's seals on a fresh render", async () => {
  const { render, unlock } = await world();
  const page = await render();
  const names = contentNames(page);
  assert.deepEqual(names, ["bodytext", "locked-data"], "both items ship a record");
  for (const contentName of names) {
    assert.equal(
      Object.hasOwn(contentRecord(page, contentName), "aad"),
      false,
      `${contentName}: the current publisher carries no aad`,
    );
  }

  const stock = new Client({ publisherOrigin: ORIGIN });
  const stockData = stock.parse(page);
  await unlock(stock, stockData, names);
  for (const [contentName, expected] of [
    ["bodytext", BODYTEXT],
    ["locked-data", LOCKED_DATA],
  ]) {
    assert.equal(
      utf8Decode(await stock.decrypt(stockData, contentName, page.sealedContent[contentName])),
      expected,
      `${contentName}: the stock client opens under the adopted transcript`,
    );
    const key = await stock.contentKeyFor(stockData, contentName);
    assert.ok(key);
    await assert.rejects(
      decrypt(
        key,
        new Uint8Array(NONCE_BYTES),
        base64urlDecode(page.sealedContent[contentName]),
        utf8Encode(oldCarriedAad("123456", contentName)),
      ),
      `${contentName}: the old carried string does not open an adopted seal`,
    );
  }

  // The historical rebuild still yields the old grammar from this page's
  // mirror, and the old-format control carries exactly that string.
  assert.equal(contentAadFor(page, "bodytext"), "123456|1|bodytext");
  const old = await oldFormatOf(unlock, page);
  for (const contentName of names) {
    assert.equal(contentRecord(old, contentName).aad, contentAadFor(old, contentName));
  }

  const carried = new CarriedAadClient({ publisherOrigin: ORIGIN });
  const carriedData = carried.parse(old);
  await unlock(carried, carriedData, names);
  for (const [contentName, expected] of [
    ["bodytext", BODYTEXT],
    ["locked-data", LOCKED_DATA],
  ]) {
    assert.equal(
      utf8Decode(await carried.decrypt(carriedData, contentName, old.sealedContent[contentName])),
      expected,
      `${contentName}: the old carried AAD opens the same zero-nonce ciphertext`,
    );
  }
  await assert.rejects(
    carried.decrypt(carried.parse(page), "bodytext", page.sealedContent.bodytext),
    { code: "bad_page", message: 'the contentData record for "bodytext" carries no aad' },
    "a current record reaches the carried-AAD guard before its absent nonce matters",
  );

  // The old-format page does not open on the stock client: it ignores the
  // carried string and builds the adopted transcript.
  const current = new Client({ publisherOrigin: ORIGIN });
  const oldData = current.parse(old);
  await unlock(current, oldData, names);
  for (const contentName of names) {
    await refuses(
      current.decrypt(oldData, contentName, old.sealedContent[contentName]),
      "decrypt_failed",
      `${contentName}: an old-format seal is a format mismatch, not a fallback`,
    );
  }
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
// b. Old-format control: a carried aad that disagrees with the mirror rebuild,
//    through the issuer that never had an opinion about it.
// ---------------------------------------------------------------------------

test("disagreeingShippedAad rewrites every aad and leaves the caller's page alone", async () => {
  const { render, unlock } = await world();
  const page = await oldFormatOf(unlock, await render());
  const disagreeing = disagreeingShippedAad(page);

  for (const contentName of contentNames(disagreeing)) {
    const record = contentRecord(disagreeing, contentName);
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
      contentRecord(page, contentName).contentType,
      "contentType stays",
    );
    assert.equal(record.nonce, contentRecord(page, contentName).nonce, "nonce stays");
  }

  // The record is structurally admitted, but violates the old producer rule:
  // the carried AAD differs from the transcript it was sealed under. The
  // current reader admits it because it ignores the member.
  const reader = new DcaData(disagreeing);
  for (const contentName of contentNames(disagreeing)) {
    assert.equal(
      reader.contentDataFor(contentName),
      contentRecord(disagreeing, contentName),
      `${contentName}: a record the base reader accepts`,
    );
  }

  // The input is the comparison, so it has to survive being rewritten.
  for (const contentName of contentNames(page)) {
    assert.equal(
      contentRecord(page, contentName).aad,
      contentAadFor(page, contentName),
      `${contentName}: the publisher's value is still on the original`,
    );
  }

  // Everything else on the page is carried through, ciphertext included.
  assert.deepEqual(disagreeing.sealedContent, page.sealedContent);
  assert.deepEqual(disagreeing.issuerData, page.issuerData);
  for (const contentName of contentNames(page)) {
    assert.deepEqual(
      contentRecord(disagreeing, contentName).keys,
      contentRecord(page, contentName).keys,
    );
  }
});

test("structurally admitted but nonconforming AAD passes issuer and opens only under historical rebuild", async () => {
  const { render, unlock } = await world("item-only");
  const page = disagreeingShippedAad(await oldFormatOf(unlock, await render()));

  for (const contentName of contentNames(page)) {
    assert.equal(
      contentRecord(page, contentName).aad,
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

  // The same unlock delivered direct item keys. A second read resolves from
  // those held keys without asking the issuer again.
  assert.deepEqual(
    (await unsealer.resolve(dcaData, ["bodytext", "locked-data"])).covered,
    ["bodytext", "locked-data"],
    "the held direct item keys from that one unlock cover both items",
  );

  // The same page on the old carried-AAD client, which reads the field: it is
  // granted the same keys and opens nothing. So the page above really does
  // disagree, and the deriving client got through it on the derivation.
  const shipped = new CarriedAadClient({ cache: new PeriodKeyCache(), publisherOrigin: ORIGIN });
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

test("only the historical rebuild needs the optional resource mirror", async () => {
  const { render, unlock } = await world();
  const page = await render();
  const old = await oldFormatOf(unlock, page);
  delete page.resource;
  delete old.resource;

  const stock = new Client({ publisherOrigin: ORIGIN });
  const stockData = stock.parse(page);
  await unlock(stock, stockData, ["bodytext"]);
  assert.equal(
    utf8Decode(await stock.decrypt(stockData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
    "the adopted transcript reads the signing input, not the mirror",
  );

  const carried = new CarriedAadClient({ publisherOrigin: ORIGIN });
  const carriedData = carried.parse(old);
  await unlock(carried, carriedData, ["bodytext"]);
  assert.equal(
    utf8Decode(await carried.decrypt(carriedData, "bodytext", old.sealedContent.bodytext)),
    BODYTEXT,
    "old-format control: the carried string needed no mirror either",
  );

  const derived = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const derivedData = derived.parse(old);
  await unlock(derived, derivedData, ["bodytext"]);
  await refuses(
    derived.decrypt(derivedData, "bodytext", old.sealedContent.bodytext),
    "bad_page",
    "missing diagnostic mirror cannot supply historical AAD",
  );

  old.resource = { resourceId: "different-diagnostic-id" };
  const mismatched = derived.parse(old);
  await unlock(derived, mismatched, ["bodytext"]);
  await refuses(
    derived.decrypt(mismatched, "bodytext", old.sealedContent.bodytext),
    "decrypt_failed",
    "unverified mirror mismatch changes historical AAD",
  );
});

test("the deriving client keeps the base class's misses", async () => {
  const { render, unlock } = await world();
  const page = disagreeingShippedAad(await oldFormatOf(unlock, await render()));

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
  delete contentRecord(noNonce, "bodytext").nonce;
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
// c. The mirror rebuild under tampered inputs, beside the carried string and
//    the adopted transcript.
// ---------------------------------------------------------------------------

test("a derived aad fails closed when the fields it is built from are moved", async () => {
  const { render, unlock } = await world();
  const page = disagreeingShippedAad(await oldFormatOf(unlock, await render()));

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

test("a tampered carried aad fails the old-format client and cannot steer the stock client", async () => {
  // Old-format control: the failure the mirror rebuild produces is the failure
  // the carried format produced. A carried aad that no longer matches what the
  // ciphertext was sealed under is a tag failure, exactly as a rebuilt one is.
  const { render, unlock } = await world();
  const page = await render();
  const old = await oldFormatOf(unlock, page);

  const carried = new CarriedAadClient({ publisherOrigin: ORIGIN });
  const oldData = carried.parse(old);
  await unlock(carried, oldData, ["bodytext"]);
  assert.equal(
    utf8Decode(await carried.decrypt(oldData, "bodytext", old.sealedContent.bodytext)),
    BODYTEXT,
  );

  // The empty string is a string, so it clears the old client's aad guard
  // and reaches the tag, which is why it is a tampered aad here and not a
  // bad page in the test above.
  const tamperings = ["123457|1|bodytext", "123456|2|bodytext", "123456|1|locked-data", ""];
  for (const aad of tamperings) {
    const tampered = structuredClone(oldData);
    contentRecord(tampered, "bodytext").aad = aad;
    await refuses(
      carried.decrypt(tampered, "bodytext", old.sealedContent.bodytext),
      "decrypt_failed",
      `a carried aad of "${aad}" opens nothing`,
    );
  }

  // The stock client ignores a carried aad of any value and type, so none of
  // these, nor a malformed one, selects a transcript or changes the opening.
  const stock = new Client({ publisherOrigin: ORIGIN });
  const stockData = stock.parse(page);
  await unlock(stock, stockData, ["bodytext"]);
  for (const aad of [...tamperings, oldCarriedAad("123456", "bodytext"), 42, null, { a: 1 }]) {
    const carrying = structuredClone(stockData);
    contentRecord(carrying, "bodytext").aad = aad;
    assert.equal(
      utf8Decode(await stock.decrypt(carrying, "bodytext", page.sealedContent.bodytext)),
      BODYTEXT,
      `a carried aad of ${JSON.stringify(aad)} is ignored`,
    );
  }
});

// ---------------------------------------------------------------------------
// d. A nonconforming arbitrary-AAD construction that the old carried-AAD client
//    can locally decrypt when handed the key. This was never publisher freedom
//    in v1, and the stock client now ignores the carried string.
// ---------------------------------------------------------------------------

/**
 * A page assembled by hand around one ciphertext. It carries a fake JWT and
 * placeholder issuer seal; the key is injected directly into the client.
 * The result is a local AEAD comparison, never a conformant DCA delivery.
 *
 * @param {string} aad
 * @param {string} value
 * @returns {Promise<{ page: any, contentKey: Uint8Array }>}
 */
async function pageWithAad(aad, value) {
  const contentKey = new Uint8Array(16).fill(11);
  const nonce = new Uint8Array(NONCE_BYTES);
  const ciphertext = await encrypt(contentKey, nonce, utf8Encode(value), utf8Encode(aad));

  return {
    page: {
      version: "1",
      resource: {
        renderId: "AAAAAAAAAAAAAAAAAAAAAA",
        domain: DOMAIN,
        issuedAt: AT,
        resourceId: "123456",
        data: {},
      },
      resourceJWT: `eyJhbGciOiJFUzI1NiIsImtpZCI6InNpZ24tMjAyNS0xMCJ9.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "AAAAAAAAAAAAAAAAAAAAAA", domain: DOMAIN, issuedAt: AT, resourceId: "123456", data: {} })))}.c2lnbmF0dXJl`,
      issuerData: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          unlockUrl: "https://issuer.example/unlock",
          sealed: {
            contentKeys: [
              { contentName: "bodytext", key: base64urlEncode(utf8Encode("sealed-placeholder")) },
            ],
          },
        },
      ],
      contentData: [
        { contentName: "bodytext", contentType: "text/html", nonce: base64urlEncode(nonce), aad },
      ],
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
  const delivered = Object.entries(contentKeys).map(([contentName, key]) => ({
    contentName,
    key: base64urlEncode(key),
  }));
  unsealer.buildRequest(dcaData, ISSUER_NAME, Object.keys(contentKeys));
  await unsealer.applyResponse(dcaData, ISSUER_NAME, { keys: { contentKeys: delivered } });
}

test("nonconforming arbitrary AAD opens only on the permissive old carried-AAD client", async () => {
  const { page, contentKey } = await pageWithAad("my-custom-binding-v2", BODYTEXT);

  const shipped = new CarriedAadClient({ publisherOrigin: ORIGIN });
  const shippedData = shipped.parse(page);
  await handOver(shipped, shippedData, { bodytext: contentKey });

  assert.equal(
    utf8Decode(await shipped.decrypt(shippedData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
    "old-format control: the injected key opens the arbitrary AAD under the carried string",
  );

  const stock = new Client({ publisherOrigin: ORIGIN });
  const stockData = stock.parse(page);
  await handOver(stock, stockData, { bodytext: contentKey });
  await refuses(
    stock.decrypt(stockData, "bodytext", page.sealedContent.bodytext),
    "decrypt_failed",
    "the stock client ignores the carried string and builds the adopted transcript",
  );

  const derived = new DerivingUnsealer({ publisherOrigin: ORIGIN });
  const derivedData = derived.parse(page);
  await handOver(derived, derivedData, { bodytext: contentKey });

  await assert.rejects(
    derived.decrypt(derivedData, "bodytext", page.sealedContent.bodytext),
    'and unreadable under derivation: the client builds "123456|1|bodytext" and the seal is not under it',
  );

  // The in-grammar control isolates the local AAD difference. It does not
  // validate either hand-assembled page as a DCA render.
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

  // Under the required independent per-item keys, this direct cross-slot swap
  // already fails by key separation. The later complete-record test exercises
  // a different case: a period grant can unwrap the moved record's own key.
});

// ---------------------------------------------------------------------------
// f. Where the readings stop agreeing: an old carried binding travels with the
//    ciphertext; the adopted transcript and the mirror rebuild stay with the
//    selected slot and render.
// ---------------------------------------------------------------------------

/**
 * Deliberately nonconforming: two items share one content key, have a fake
 * JWT and placeholder issuer seals, and receive injected keys. This isolates
 * a local AAD difference but does not demonstrate a conforming DCA attack.
 *
 * @returns {Promise<{ page: any, contentKey: Uint8Array }>}
 */
async function sharedKeyPage() {
  const contentKey = new Uint8Array(16).fill(13);

  /** @type {any[]} */
  const contentData = [];
  /** @type {Record<string, string>} */
  const sealedContent = {};

  for (const [index, [contentName, contentType, value]] of [
    ["bodytext", "text/html", BODYTEXT],
    ["locked-data", "application/json", LOCKED_DATA],
  ].entries()) {
    const nonce = new Uint8Array(NONCE_BYTES).fill(index + 1);
    const aad = `123456|1|${contentName}`;
    const ciphertext = await encrypt(contentKey, nonce, utf8Encode(value), utf8Encode(aad));

    contentData.push({ contentName, contentType, nonce: base64urlEncode(nonce), aad });
    sealedContent[contentName] = base64urlEncode(ciphertext);
  }

  return {
    page: {
      version: "1",
      resource: {
        renderId: "AAAAAAAAAAAAAAAAAAAAAA",
        domain: DOMAIN,
        issuedAt: AT,
        resourceId: "123456",
        data: {},
      },
      resourceJWT: `eyJhbGciOiJFUzI1NiIsImtpZCI6InNpZ24tMjAyNS0xMCJ9.${base64urlEncode(utf8Encode(JSON.stringify({ renderId: "AAAAAAAAAAAAAAAAAAAAAA", domain: DOMAIN, issuedAt: AT, resourceId: "123456", data: {} })))}.c2lnbmF0dXJl`,
      issuerData: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          unlockUrl: "https://issuer.example/unlock",
          sealed: {
            contentKeys: [
              { contentName: "bodytext", key: base64urlEncode(utf8Encode("sealed-placeholder")) },
              {
                contentName: "locked-data",
                key: base64urlEncode(utf8Encode("sealed-placeholder")),
              },
            ],
          },
        },
      ],
      contentData,
      sealedContent,
    },
    contentKey,
  };
}

/**
 * Move ciphertext and its whole item record together. Used both for the
 * invalid shared-key diagnostic and for substitutions in authentic publisher
 * output, adopted and old-format, opened through period-key and direct
 * item-key issuer grants.
 *
 * @param {any} page
 * @returns {any}
 */
function swapSlots(page) {
  const swapped = structuredClone(page);

  swapped.contentData = [
    { ...contentRecord(page, "locked-data"), contentName: "bodytext" },
    { ...contentRecord(page, "bodytext"), contentName: "locked-data" },
  ];
  swapped.sealedContent = {
    bodytext: page.sealedContent["locked-data"],
    "locked-data": page.sealedContent.bodytext,
  };

  return swapped;
}

test("a real period grant opens a moved complete record only under the old carried AAD", async () => {
  const { render, unlock } = await world("period-only");
  const page = await render();
  assert.deepEqual(Object.keys(issuerRecord(page, ISSUER_NAME).sealed), ["periodKeys"]);
  assert.equal(Object.hasOwn(contentRecord(page, "bodytext"), "aad"), false);

  const original = new Client({ publisherOrigin: ORIGIN });
  const originalData = original.parse(page);
  const grant = await unlock(original, originalData, ["bodytext"]);
  assert.deepEqual(grant.keys.contentKeys, [], "the issuer delivered no direct item key");
  assert.ok(grant.keys.periodKeys.filter((record) => record.accessGroup === GROUP).length > 0);
  assert.deepEqual(
    (await original.resolve(originalData, ["bodytext", "locked-data"])).covered,
    ["bodytext", "locked-data"],
    "one issuer period grant reaches both same-group items",
  );
  const bodyKey = await original.contentKeyFor(originalData, "bodytext");
  const dataKey = await original.contentKeyFor(originalData, "locked-data");
  assert.ok(bodyKey instanceof Uint8Array && dataKey instanceof Uint8Array);
  assert.notDeepEqual(bodyKey, dataKey, "the publisher generated independent item keys");
  assert.equal(
    utf8Decode(await original.decrypt(originalData, "bodytext", page.sealedContent.bodytext)),
    BODYTEXT,
  );
  assert.equal(
    utf8Decode(
      await original.decrypt(originalData, "locked-data", page.sealedContent["locked-data"]),
    ),
    LOCKED_DATA,
  );

  // Current wraps bind the authored slot before the content tag is reached.
  const moved = swapSlots(page);
  const reader = new Client({ publisherOrigin: ORIGIN });
  const movedData = reader.parse(moved);
  await unlock(reader, movedData, ["bodytext"]);
  assert.equal(await reader.contentKeyFor(movedData, "bodytext"), null);
  await refuses(
    reader.decrypt(movedData, "bodytext", moved.sealedContent.bodytext),
    "no_key",
    "a moved wrap has another slot's derived nonce",
  );
  await assert.rejects(
    decrypt(
      dataKey,
      new Uint8Array(NONCE_BYTES),
      base64urlDecode(moved.sealedContent.bodytext),
      adoptedContentAad(moved, "bodytext"),
    ),
    "the source item's correct key also refuses the moved ciphertext under the target slot AAD",
  );

  // Old-format control: the same render resealed under the carried string with
  // the same issuer-reached keys. The carried B AAD travels with its record.
  const old = await resealOldFormat(
    page,
    { bodytext: bodyKey, "locked-data": dataKey },
    "123456",
    grant.keys.periodKeys,
  );
  assert.equal(contentRecord(old, "bodytext").aad, "123456|1|bodytext");
  assert.equal(contentRecord(old, "locked-data").aad, "123456|1|locked-data");
  const oldMoved = swapSlots(old);
  const historical = await openOldPeriodRecord(oldMoved, "bodytext", grant.keys.periodKeys);
  assert.deepEqual(historical.key, dataKey);
  assert.equal(
    utf8Decode(historical.plaintext),
    LOCKED_DATA,
    "the historical carried wrap and AAD travel with the authorized record",
  );
  // Both source items were in the one group the issuer granted. This changes
  // which authorized plaintext fills a slot; it does not acquire an ungranted item.
});

test("an item-key-only issuer grant does not open a moved other-item record", async () => {
  const { render, unlock } = await world("item-only");
  const page = await render();
  assert.deepEqual(Object.keys(issuerRecord(page, ISSUER_NAME).sealed), ["contentKeys"]);
  const moved = swapSlots(page);
  const reader = new Client({ publisherOrigin: ORIGIN });
  const data = reader.parse(moved);
  await unlock(reader, data, ["bodytext"]);
  assert.ok(await reader.contentKeyFor(data, "bodytext"), "the direct A key was granted");
  await refuses(
    reader.decrypt(data, "bodytext", moved.sealedContent.bodytext),
    "decrypt_failed",
    "the direct A key cannot authenticate B's ciphertext",
  );
});

test("a period grant opens another render's same-slot record only under the old carried AAD", async () => {
  const { render, unlock } = await world("period-only");
  const prior = await render("123456", "<p>prior render</p>");
  const current = await render("123456", "<p>current render</p>");
  assert.notEqual(prior.resourceJWT, current.resourceJWT);
  assert.notEqual(prior.resource.renderId, current.resource.renderId);

  const priorReader = new Client({ publisherOrigin: ORIGIN });
  const priorData = priorReader.parse(prior);
  await unlock(priorReader, priorData, ["bodytext"]);
  const priorKey = await priorReader.contentKeyFor(priorData, "bodytext");
  assert.ok(priorKey instanceof Uint8Array);
  assert.equal(
    utf8Decode(
      await decrypt(
        priorKey,
        new Uint8Array(NONCE_BYTES),
        base64urlDecode(prior.sealedContent.bodytext),
        adoptedContentAad(prior, "bodytext"),
      ),
    ),
    "<p>prior render</p>",
    "the retained source key opens the original ciphertext under its original AAD",
  );

  // Current wraps refuse the prior record at key recovery, before content AAD.
  const mixed = structuredClone(current);
  replaceRecord(mixed, "bodytext", contentRecord(prior, "bodytext"));
  mixed.sealedContent.bodytext = prior.sealedContent.bodytext;
  const reader = new Client({ publisherOrigin: ORIGIN });
  const data = reader.parse(mixed);
  await unlock(reader, data, ["bodytext"]);
  assert.equal(await reader.contentKeyFor(data, "bodytext"), null);
  assert.notDeepEqual(
    adoptedContentAad(prior, "bodytext"),
    adoptedContentAad(mixed, "bodytext"),
    "the adopted transcript distinguishes these render identifiers",
  );
  await refuses(
    reader.decrypt(data, "bodytext", mixed.sealedContent.bodytext),
    "no_key",
    "the current renderId changes the derived wrap nonce",
  );
  await assert.rejects(
    decrypt(
      priorKey,
      new Uint8Array(NONCE_BYTES),
      base64urlDecode(mixed.sealedContent.bodytext),
      adoptedContentAad(mixed, "bodytext"),
    ),
    "the correct prior key also refuses its ciphertext under the current render's content AAD",
  );

  // Old-format control: both renders resealed under the carried string. The
  // carried AAD is equal across renders, so the earlier record opens.
  const original = new Client({ publisherOrigin: ORIGIN });
  const grant = await unlock(original, original.parse(current), ["bodytext"]);
  const oldPrior = await oldFormatOf(unlock, prior, "123456", grant.keys.periodKeys);
  const oldMixed = await oldFormatOf(unlock, current, "123456", grant.keys.periodKeys);
  assert.equal(contentRecord(oldPrior, "bodytext").aad, contentRecord(oldMixed, "bodytext").aad);
  replaceRecord(oldMixed, "bodytext", contentRecord(oldPrior, "bodytext"));
  oldMixed.sealedContent.bodytext = oldPrior.sealedContent.bodytext;
  const historical = await openOldPeriodRecord(oldMixed, "bodytext", grant.keys.periodKeys);
  assert.equal(
    utf8Decode(historical.plaintext),
    "<p>prior render</p>",
    "the historical carried wrap and AAD open under the real period grant",
  );
});

test("old-format control: with a prohibited shared item key, carried AAD moves with ciphertext", async () => {
  const { page, contentKey } = await sharedKeyPage();
  const swapped = swapSlots(page);

  const shipped = new CarriedAadClient({ publisherOrigin: ORIGIN });
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
  const straightShipped = new CarriedAadClient({ publisherOrigin: ORIGIN });
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

  // An issuer never admitted this fake delivery, and a conforming publisher
  // must assign distinct keys to the two items. This is negative evidence
  // about a different construction, not a bypass of current DCA.
});

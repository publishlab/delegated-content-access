// @ts-check
//
// One complete composition with the HTML carrier selected. A real Sealer seals
// one content-key-only item to an ECDH issuer, `writeMarkupDelivery` writes the
// render as the two reserved inert JSON script elements of the data format's
// Section 3, and `MarkupDeliveryReader` reads them back off a root that
// `domOver` builds from that markup string. From the extraction on, every step
// is the baseline's: `DcaData`, the composed request builder and resolver, the
// real issuer and the content opener.
//
// Requested: dca-profile-html-carrier.
// Resolved: dca-profile-baseline and dca-profile-html-carrier.
//
// The issuer has no HTML-carrier duty and runs unchanged. Browser-origin
// admission is neither selected nor required: the host supplies the page origin
// through the root, and the issuer admits the request by its registration.
//
// The carrier rules stay in force when HTML is selected, and a few
// distinguishing cases show it: a wrong type, an element that is no script, two
// data blocks and one element with both class tokens. The full refusal set is
// in test-reference/adapter-client/markup-delivery-reader.test.js and the
// writer's in test-reference/adapter-publisher/markup-writer.test.js. The
// baseline JSON form is in dca-profile-baseline.test.js.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../core-publisher/issuerSupplyPlan.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { openingKeysOver, PublisherRegistrations } from "../demo/support/PublisherRegistrations.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { domOver } from "../test-lib/helpers/domOver.js";
import { refuses } from "../test-lib/helpers/refuses.js";
import { issuerKeypair, signingKeypair } from "../test-reference/support/keys.js";

import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { DcaData } from "../core-client/DcaData.js";
import { ResponseAssociation } from "../core-client/ResponseAssociation.js";
import { composeClient } from "../integration-client/composeClient.js";
import { utf8Decode, utf8Encode } from "../core-shared/codec.js";

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const AT = "2025-10-23T14:20:00Z";
const CONTENT_NAME = "bodytext";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

// Publisher-defined resource data reaches the data block verbatim, so it
// carries the two sequences that would end or unbalance a script element.
const RESOURCE_DATA = Object.freeze({ caption: "a </script> tag and <!-- <script> inside" });

/** @typedef {{ dcaData: any, sealedContent: Record<string, string> }} Render */
/** @typedef {(requestDocument: string) => Promise<{ status: number, body: any }>} Unlock */

/**
 * One publisher and one issuer. The publisher seals one content-key-only item
 * and hands back the render's two values, which a test writes in the form it
 * is about.
 *
 * @returns {Promise<{ render: Render, unlock: Unlock }>}
 */
async function world() {
  const issuerKeys = await issuerKeypair();
  const signingKeys = await signingKeypair();

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 5 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { ...RESOURCE_DATA });
  sealer.content(CONTENT_NAME, ARTICLE, "text/html");
  const render = await sealer.seal();

  const keyStore = {
    /** @param {string} issuerName @param {string} keyId */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);
  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], accessPolicy: new AllowAllPolicy() }),
    { periodKeyInput: false },
  );
  const endpoint = new UnlockEndpoint(processor);

  return {
    render: { dcaData: render.dcaData, sealedContent: render.sealedContent },
    async unlock(requestDocument) {
      const { status, body } = await unlockThroughAdmission(
        processor,
        endpoint,
        requestDocument,
        registration,
      );
      return { status, body: JSON.parse(JSON.stringify(body)) };
    },
  };
}

/** The `.dca-data` element of emitted markup, close tag included. */
const DATA_BLOCK = /<script type="application\/json" class="dca-data">[\s\S]*?<\/script>/;

/** The `.dca-sealed-content` element of emitted markup, close tag included. */
const SEALED_BLOCK =
  /<script type="application\/json" class="dca-sealed-content">[\s\S]*?<\/script>/;

/**
 * @param {string} markup
 * @param {RegExp} block
 * @returns {string}
 */
function blockOf(markup, block) {
  const found = block.exec(markup);
  assert.ok(found, `the markup carries ${block}`);
  return found[0];
}

describe("The HTML carrier selected over the baseline", () => {
  test(
    "the markup delivery opens to the original item through the real issuer",
    {
      tags: [
        "dca-profile-html-carrier/publisher/markup-emission",
        "dca-profile-html-carrier/client/markup-extraction",
        "dca-profile-baseline/publisher/content-key-envelope",
        "dca-profile-baseline/issuer/direct-result",
        "dca-profile-baseline/client/direct-admission",
      ],
    },
    async () => {
      const { render, unlock } = await world();
      const markup = writeMarkupDelivery(render);
      assert.equal(markup.includes("</script> tag"), false, "the data block stays inert");
      assert.equal(markup.includes("<!-- <script>"), false, "and opens no escaped state");

      const reader = new MarkupDeliveryReader(domOver(markup, { publisherOrigin: PUB }));
      assert.deepEqual(reader.dcaData.resource.data, RESOURCE_DATA, "the resource data survived");

      const dcaData = new DcaData(reader.dcaData, { publisherOrigin: reader.publisherOrigin });
      const { resolver, builder, opener } = composeClient();
      const request = builder.build(dcaData, ISSUER_NAME, [CONTENT_NAME]).toObject();
      const association = new ResponseAssociation(dcaData, ISSUER_NAME, request);
      const answer = await unlock(JSON.stringify(request));
      assert.equal(answer.status, 200, "the issuer answered");

      const application = await resolver.applyResponse(
        dcaData,
        ISSUER_NAME,
        answer.body,
        association,
      );
      assert.equal(application.accepted, 1);
      const plaintext = await opener.open({
        item: /** @type {any} */ (dcaData.contentItemFor(CONTENT_NAME)),
        ciphertext: /** @type {string} */ (reader.extract(CONTENT_NAME)),
        resolveKey: () => resolver.contentKeyFor(dcaData, CONTENT_NAME),
      });
      assert.equal(utf8Decode(plaintext), ARTICLE, "the original plaintext");
    },
  );

  test(
    "the carrier rules hold when HTML is selected",
    { tags: ["dca-profile-html-carrier/client/markup-extraction"] },
    async () => {
      const { render } = await world();
      const markup = writeMarkupDelivery(render);
      const data = blockOf(markup, DATA_BLOCK);
      const sealed = blockOf(markup, SEALED_BLOCK);
      const body = data.slice(data.indexOf(">") + 1, data.lastIndexOf("</script>"));

      for (const [label, page, message] of [
        [
          "a data block of another type",
          markup.replace(
            '<script type="application/json" class="dca-data">',
            '<script type="text/plain" class="dca-data">',
          ),
          /application\/json/,
        ],
        [
          "a data block that is no script",
          `<div type="application/json" class="dca-data">${body}</div>\n${sealed}`,
          /script/,
        ],
        ["two data blocks", `${markup}\n${data}`, /exactly one/],
        [
          "one element with both class tokens",
          `<script type="application/json" class="dca-data dca-sealed-content">${body}</script>`,
          /both/,
        ],
      ]) {
        await refuses(
          () =>
            new MarkupDeliveryReader(
              domOver(/** @type {string} */ (page), { publisherOrigin: PUB }),
            ),
          { code: "bad_page", message: /** @type {RegExp} */ (message) },
          /** @type {string} */ (label),
        );
      }
    },
  );

  test("a publication in one form and a client of the other do not compose", async () => {
    const { render } = await world();

    // Compatibility mismatch, not a malformed delivery: the markup is a valid
    // HTML-carrier publication, and a client that selected only the JSON
    // document finds no JSON document in its octets.
    await refuses(
      () =>
        new JsonDeliveryReader(utf8Encode(writeMarkupDelivery(render)), { publisherOrigin: PUB }),
      "bad_page",
      "markup octets handed to the JSON reader",
    );

    // Compatibility mismatch, not a malformed delivery: the JSON document is a
    // valid baseline publication, and as page text it carries no reserved
    // carrier for a client that selected only markup.
    const documentText = utf8Decode(writeJsonDelivery(render));
    await refuses(
      () => new MarkupDeliveryReader(domOver(documentText, { publisherOrigin: PUB })),
      { code: "bad_page", message: /carries no/ },
      "a root with no reserved carrier handed to the markup reader",
    );
  });
});

// @ts-check
// Real reference sealing/admission/opening; only serialized documents cross roles.
import { Sealer } from "../../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { writeJsonDelivery } from "../../../adapter-publisher/writeJsonDelivery.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";
import { JsonDeliveryReader } from "../../../adapter-client/JsonDeliveryReader.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { composeClient } from "../../../integration-client/composeClient.js";

const PUB = "https://news.example";
const ISSUER = "subscription";
const KEY_ID = "opening-1";
const SIGNING_ID = "signing-1";

/** @typedef {{name: string, bytes: Uint8Array, contentType: string, contentEncodings?: string[]}} Item */

/**
 * @param {Item[]} items
 * @param {{seal?: (input: {items: Item[], issuerPublicKey: CryptoKey, signingPrivateKey: CryptoKey, origin: string, issuerName: string, keyId: string, signingId: string}) => Promise<{dcaData: any, sealedContent: any}>}} [options]
 */
export async function exchange(items, options = {}) {
  const issuerKeys = await issuerKeypair();
  // An external sealing hook may need to export this ephemeral fixture key.
  const signingKeys = options.seal
    ? await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ])
    : await signingKeypair();
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_ID]: signingKeys.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("article-1", { section: "politics" });
  for (const item of items) {
    sealer.content(item.name, {
      bytes: item.bytes,
      contentType: item.contentType,
      contentEncodings: item.contentEncodings ?? [],
    });
  }
  const { dcaData, sealedContent } = options.seal
    ? await options.seal({
        items,
        issuerPublicKey: issuerKeys.publicKey,
        signingPrivateKey: signingKeys.privateKey,
        origin: PUB,
        issuerName: ISSUER,
        keyId: KEY_ID,
        signingId: SIGNING_ID,
      })
    : await sealer.seal();
  const bytes = writeJsonDelivery({ dcaData, sealedContent });
  const keyStore = {
    get(issuerName, keyId) {
      return issuerName === ISSUER && keyId === KEY_ID
        ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
        : null;
    },
  };
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_ID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_ID);
  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [ISSUER], accessPolicy: new AllowAllPolicy() }),
    { periodKeyInput: false },
  );
  const endpoint = new UnlockEndpoint(processor);
  /** @param {object | string} request */
  async function respond(request) {
    return unlockThroughAdmission(
      processor,
      endpoint,
      typeof request === "string" ? request : JSON.stringify(request),
      registration,
    );
  }

  /**
   * Each client owns its resolver. A context-aware host supplies the eligibility
   * of the captured work that owns this client, not its currently active provider.
   * @param {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [contentDecoders]
   * @param {(requestJson: string, credential: unknown) => Promise<any>} [sendRequest]
   * @param {() => boolean} [isEligible]
   */
  function createClient(
    contentDecoders = {},
    sendRequest = (requestJson) => respond(requestJson),
    isEligible = () => true,
  ) {
    const reader = new JsonDeliveryReader(Uint8Array.from(bytes), { publisherOrigin: PUB });
    const page = new DcaData(reader.dcaData, { publisherOrigin: PUB });
    const { resolver, builder, opener } = composeClient({ contentDecoders });
    let requests = 0;
    let responseApplications = 0;
    return {
      delivery: reader.dcaData,
      get requests() {
        return requests;
      },
      get responseApplications() {
        return responseApplications;
      },
      // Holding response processing proves that an already sent request remains
      // captured by this client across an independently observed context change.
      /** @param {() => Promise<void>} [afterResponse] @param {unknown} [credential] */
      async unlock(afterResponse = async () => {}, credential = undefined) {
        if (!isEligible()) return null;
        const request = builder
          .build(
            page,
            ISSUER,
            items.map((item) => item.name),
          )
          .toObject();
        const association = new ResponseAssociation(page, ISSUER, request);
        requests += 1;
        // Credentials are captured by the application for this transport call;
        // they are never inserted into the serialized DCA request.
        const response = await sendRequest(JSON.stringify(request), credential);
        if (response.status !== 200) throw new Error(`issuer status ${response.status}`);
        await afterResponse();
        // The host may retire this work while transport or its completion hook
        // waits. A valid response association does not establish current context
        // ownership; check it before calling into the resolver at all.
        if (!isEligible()) return null;
        responseApplications += 1;
        return resolver.applyResponse(
          page,
          ISSUER,
          JSON.parse(JSON.stringify(response.body)),
          association,
        );
      },
      /** @param {string} name */
      keyFor(name) {
        return resolver.contentKeyFor(page, name);
      },
      /** @param {string} name @returns {Promise<Uint8Array>} */
      open(name) {
        // The view captures the content AAD inputs before the key await.
        const item = page.contentItemFor(name);
        if (item === null) throw new Error(`no item "${name}" on the page`);
        return opener.open({
          item,
          ciphertext: reader.extract(name),
          resolveKey: () => resolver.contentKeyFor(page, name),
        });
      },
    };
  }
  return {
    bytes,
    respond,
    createClient,
    /** @param {Record<string, (bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array>} [contentDecoders] */
    async client(contentDecoders = {}) {
      const client = createClient(contentDecoders);
      const applied = await client.unlock();
      return { ...client, applied };
    },
  };
}

export function deferred() {
  /** @type {() => void} */
  let resolve = () => {};
  const promise = new Promise((done) => {
    resolve = () => done(null);
  });
  return { promise, resolve };
}

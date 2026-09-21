import { Sealer } from "../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../demo/support/PublisherRegistrations.js";
import { exactPeriodKeySupply } from "../../demo/support/exactPeriodKeySupply.js";
import { Clock } from "../../demo/actors/Clock.js";
import {
  ALGORITHM,
  ARTICLES,
  AT,
  ISSUER_NAME,
  KEY_ID,
  SIGNING_KID,
  UNLOCK_URL,
  article,
} from "../../demo/scenarios/fixtures.js";
import { wire } from "../helpers/inspect.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../../test-reference/support/keys.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";

/**
 * Two hosts of this file's own, where the shared fixture has one. Every fold
 * below is spelled against `example.com`: the dressed spellings, the list of
 * hosts that must not merge, the second publisher one of them folds to. These
 * tests are about the host itself rather than a name the story is told with.
 */
export const DOMAIN = "example.com";
export const OTHER_DOMAIN = "other.example.com";

/**
 * The default render's publisher, folded the way the resolver folds it. A key
 * seeded straight into the backing cache has to name it, since the resolver
 * reads candidates back under the page's publisher.
 */
export const PUB = `https://${DOMAIN}`;

/** The two periods a render at the fixture's clock ships. */
export const T_NOW = "251023T14";
export const T_NEXT = "251023T15";

export const RESOURCE_ID = "123456";

/**
 * One item under one group, which is what most of these tests need. The fixture
 * names it `bodytext`, and that is the coordinate spelled out below wherever a
 * wire member is read by name.
 */
export const [BODYTEXT] = article("A").items;

/** A second item under the same group: the deferred one, and the JSON one. */
export const PREMIUMTEXT = { ...BODYTEXT, name: "premiumtext", value: ARTICLES.D };

/**
 * What a JSON hop does to one object. `wire()` gives the whole render; this
 * gives the halves of it, which the markup delivery ships as two artefacts, and
 * the seal data a test holds on to before the page it came from is edited.
 *
 * @template T
 * @param {T} value
 * @returns {T}
 */
function hop(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * Two publishers on one issuer, so "which key was selected" is a question with
 * a wrong answer available. Both hold ECDSA signing keys; the issuer holds one
 * ECDH keypair and an exact registration for each signing kid and canonical
 * origin, which is what a deployment onboards.
 *
 * This builds a `Sealer` where the rest of the suite renders through
 * `Publisher`: a `Page` carries the two artefacts already merged, and the
 * JSON-variant tests below are about telling them apart.
 */
export async function world() {
  const issuerKeys = await issuerKeypair();
  const periodKeySupply = exactPeriodKeySupply();

  /** @type {Record<string, CryptoKeyPair>} */
  const publishers = {};
  for (const domain of [DOMAIN, OTHER_DOMAIN]) {
    publishers[domain] = await signingKeypair();
  }

  let seed = 1;

  /**
   * One render, delivered both ways: the two artefacts a markup page carries
   * in its two elements, and the single document the JSON API variant is.
   *
   * @param {object} [config]
   * @param {string} [config.signAs] - whose signing key signs it; the
   *   registered domain by default, so the honest case is the default
   * @param {string} [config.resourceId]
   * @param {object[]} [config.items]
   * @param {import('../../core-publisher/Sealer.js').PeriodKeySupply|null} [config.periodKeySupply]
   */
  async function render(config = {}) {
    const signAs = config.signAs ?? DOMAIN;
    const supply = config.periodKeySupply === undefined ? periodKeySupply : config.periodKeySupply;

    // One key held and no `signingKid`, which is the `world.js` knob's
    // `null` path: the Sealer takes the only key it was handed.
    const sealer = new Sealer({
      origin: `https://${signAs}`,
      clock: new Clock(AT),
      random: seededRandom(seed++),
      signingKeys: {
        [signAs === DOMAIN ? SIGNING_KID : `${SIGNING_KID}-other`]: publishers[signAs].privateKey,
      },
      // A null supply renders direct only: no cached path.
      ...(supply ? { periodKeySupply: supply } : {}),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuerKeys.publicKey,
          unlockUrl: UNLOCK_URL,
        },
      ],
    });

    sealer.resource(config.resourceId ?? RESOURCE_ID, { section: "politics" });
    for (const item of config.items ?? [BODYTEXT]) {
      sealer.content(item.name, item.value, item.contentType, { accessGroups: item.accessGroups });
    }

    const rendered = await sealer.seal();

    // The markup delivery is two artefacts; the JSON API delivery is one
    // document. Both go through a JSON hop, because both crossed a wire.
    return {
      dcaData: hop(rendered.dcaData),
      sealedContent: hop(rendered.sealedContent),
      page: wire(rendered),
    };
  }

  const keyStore = {
    /**
     * @param {string} issuerName
     * @param {string} keyId
     */
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: ALGORITHM, privateKey: issuerKeys.privateKey };
    },
  };

  /**
   * The onboarded publisher keys. `fold` is the whole question: with it, the
   * wire value is folded to an index before the lookup; without it, the
   * lookup is on the string as it arrived, which is the deployment that
   * forgot.
   *
   * @param {{ fold: boolean }} options
   */
  const keyStoreForRegistration = openingKeysOver(keyStore, [
    { issuerName: ISSUER_NAME, keyId: KEY_ID },
  ]);
  const publisherRegistrations = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: publishers[DOMAIN].publicKey,
      openingKeys: keyStoreForRegistration,
    },
    {
      kid: `${SIGNING_KID}-other`,
      publicKey: publishers[OTHER_DOMAIN].publicKey,
      openingKeys: keyStoreForRegistration,
    },
  ]);

  /**
   * @param {{ fold?: boolean }} [options] - retained call compatibility; registration is exact
   */
  function endpointWith(options = {}) {
    const processor = new IssuerProcessor(
      new IssuerEngine({
        accessPolicy: options.accessPolicy ?? new AllowAllPolicy(),
      }),
      { exactPeriodInput: true },
    );
    return {
      processor,
      endpoint: new UnlockEndpoint(processor),
      publisherRegistrations,
      publisherRegistration: publisherRegistrations.get(SIGNING_KID),
    };
  }

  return {
    render,
    endpointWith,
    publisherRegistrations,
    publisherRegistration: publisherRegistrations.get(SIGNING_KID),
    periodKeySupply,
  };
}

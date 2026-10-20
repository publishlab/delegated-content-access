// @ts-check
//
// Renders pages. It holds the configuration one publisher renders under: its
// origin, its signing keys, its periodKeySupply, its period, and the issuers it
// was onboarded with. From those it turns an article into a `Page`.
//
// The unlock exchange runs without it. No client and no issuer asks it anything;
// a render leaves and the publisher is done. So it keeps configuration and keys,
// and nothing about a user.
//
// `render` builds a fresh `Sealer` every time, which is what lets rotation be a
// method. The three keys a publisher rotates (which signing key signs, which
// periodKeySupply provides the cached path, and which public half an issuer is
// sealed to) each move on their own schedule, and none of them is coordinated
// with the next render. Holding one Sealer would freeze all three at
// construction; building one per render lets a caller rotate at any point, and
// the render after that call is the first one to carry it.
//
// The three are independent on purpose: `rotateSigningKey` moves the envelope,
// `rotatePeriodKeySupply` moves the cached path, `rotateIssuerKey` moves what one
// issuer can open. A test rotates one and reads the other two to show they do not
// drag each other.
//
// `period` is configuration, not a constant: two publishers with different
// periods run in one process, and each one labels its own `t`.

import { Sealer } from "../../core-publisher/Sealer.js";
import { Page } from "../support/Page.js";
import { dcaError } from "../../core-shared/errors.js";
import { signableOrigin } from "../../core-shared/publisherOrigin.js";

const OPTIONS = [
  "origin",
  "clock",
  "random",
  "signingKeys",
  "signingKid",
  "periodKeySupply",
  "issuers",
  "period",
  "issuerSupplyPlanFor",
  "developmentHttpOrigin",
];

/**
 * One item of a render, as a `Sealer` consumes it.
 *
 * @typedef {object} ContentItem
 * @property {string} name
 * @property {string} value
 * @property {string} contentType
 * @property {string[]} accessGroups
 */

/**
 * What a publisher renders. The two-articles-of-a-period tests start with one
 * publisher rendering two different articles.
 *
 * @typedef {object} Article
 * @property {string} resourceId
 * @property {object} data - publisher-defined metadata an issuer decides on
 * @property {ContentItem[]} items
 */

export class Publisher {
  #origin;
  #clock;
  #random;
  /** @type {Record<string, CryptoKey>} */
  #signingKeys;
  /** @type {string|null} */
  #signingKid;
  /** @type {import('../../core-publisher/Sealer.js').PeriodKeySupply|null} */
  #periodKeySupply;
  /** @type {(issuer: import('../../core-publisher/Sealer.js').IssuerConfig, render: { accessGroups: string[], contentNames: string[], now: Date }) => object} */
  #issuerSupplyPlanFor;
  /** @type {{ length?: number, slots?: number }|undefined} */
  #period;
  /** @type {boolean} */
  #developmentHttpOrigin;
  /** @type {import('../../core-publisher/Sealer.js').IssuerConfig[]} */
  #issuers;

  #renders = 0;

  /**
   * @param {object} config
   * @param {string} config.origin - the canonical page origin registered
   *   beside this publisher's signing-key kids
   * @param {{ now: () => Date }} config.clock
   * @param {{ bytes: (n: number) => Uint8Array }} config.random
   * @param {Record<string, CryptoKey>} config.signingKeys - ECDSA P-256
   *   private keys by `kid`. Plural because a rotation has to leave the
   *   previous key resolvable: markup an edge cache is still serving names the
   *   key that signed it.
   * @param {import('../../core-publisher/Sealer.js').IssuerConfig[]} config.issuers - what
   *   this publisher was onboarded with, one entry per issuer
   * @param {string} [config.signingKid] - which key signs. Left out with one
   *   key held, the `Sealer` takes the only one; left out with two, it refuses,
   *   because a publisher holding two has to say which one signs.
   * @param {import('../../core-publisher/Sealer.js').PeriodKeySupply} [config.periodKeySupply] -
   *   where a periodKey's bytes come from, and the whole of the cached path.
   *   Left out, this publisher has no cached path at all, and a render
   *   refuses an item that names a group. The base slice ships no
   *   algorithmic default.
   * @param {{ length?: number, slots?: number }} [config.period]
   * @param {(issuer: import('../../core-publisher/Sealer.js').IssuerConfig, render: { accessGroups: string[], contentNames: string[], now: Date }) => object} config.issuerSupplyPlanFor - each issuer's scope per
   *   render, which the `Sealer` requires; left out, every render refuses
   * @param {boolean} [config.developmentHttpOrigin] - admit an HTTP loopback
   *   origin under the same explicit development profile as `Sealer`
   */
  constructor(config) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `Publisher has no ${name} yet, and will not pretend to`,
        );
      }
    }
    const { origin, clock, random, signingKeys, issuers } = config ?? /** @type {any} */ ({});
    for (const [name, value] of Object.entries({ origin, clock, random, signingKeys, issuers })) {
      if (!value) throw dcaError("bad_config", `Publisher needs a ${name}`);
    }
    const developmentHttpOrigin = config.developmentHttpOrigin ?? false;
    if (typeof developmentHttpOrigin !== "boolean") {
      throw dcaError("bad_config", "developmentHttpOrigin is a profile that is on or off");
    }
    if (signableOrigin(origin, developmentHttpOrigin) === null) {
      throw dcaError("bad_config", "Publisher origin is one this profile may sign");
    }
    if (!Array.isArray(issuers) || issuers.length === 0) {
      throw dcaError("bad_config", "Publisher needs the issuers it was onboarded with");
    }
    this.#origin = origin;
    this.#clock = clock;
    this.#random = random;
    this.#signingKeys = { ...signingKeys };
    this.#signingKid = config.signingKid ?? null;
    this.#periodKeySupply = config.periodKeySupply ?? null;
    this.#issuerSupplyPlanFor = config.issuerSupplyPlanFor;
    this.#period = config.period === undefined ? undefined : { ...config.period };
    this.#developmentHttpOrigin = developmentHttpOrigin;
    this.#issuers = issuers.map((issuer) => ({ ...issuer }));

    if (this.#signingKid !== null) this.#checkKid(this.#signingKid);
  }

  /**
   * @param {string} kid
   * @returns {void}
   */
  #checkKid(kid) {
    if (typeof kid !== "string" || !Object.hasOwn(this.#signingKeys, kid)) {
      throw dcaError("bad_config", `this publisher holds no signing key "${kid}"`);
    }
  }

  /** What this publisher is onboarded with, copied out. */
  get issuers() {
    return this.#issuers.map((issuer) => ({ ...issuer }));
  }

  get origin() {
    return this.#origin;
  }

  /**
   * One render, as it leaves: dca-data, the sealed ciphertext beside it, and
   * nothing left of the objects that made it.
   *
   * @param {Article} article
   * @returns {Promise<Page>}
   */
  async render(article) {
    if (!article?.resourceId || !Array.isArray(article?.items)) {
      throw dcaError("bad_config", "an article is a resourceId, its data, and the items to seal");
    }

    const sealer = new Sealer({
      origin: this.#origin,
      clock: this.#clock,
      random: this.#random,
      signingKeys: this.#signingKeys,
      ...(this.#signingKid === null ? {} : { signingKid: this.#signingKid }),
      ...(this.#periodKeySupply === null ? {} : { periodKeySupply: this.#periodKeySupply }),
      issuerSupplyPlanFor: this.#issuerSupplyPlanFor,
      ...(this.#period === undefined ? {} : { period: this.#period }),
      developmentHttpOrigin: this.#developmentHttpOrigin,
      issuers: this.#issuers,
    });

    sealer.resource(article.resourceId, article.data ?? {});
    for (const item of article.items) {
      sealer.content(item.name, item.value, item.contentType, { accessGroups: item.accessGroups });
    }

    const { dcaData, sealedContent } = await sealer.seal();
    this.#renders++;
    return new Page({ publisherOrigin: this.#origin, dcaData, sealedContent });
  }

  /**
   * Which held key signs from here on. The keys themselves do not move; a
   * rotation changes which one is used, and the previous one stays resolvable
   * because the markup it signed is still being served.
   *
   * @param {string} kid
   * @returns {void}
   */
  rotateSigningKey(kid) {
    this.#checkKid(kid);
    this.#signingKid = kid;
  }

  /**
   * Which supply provides the cached-path key family from here on. Rotating
   * the cached path hands over a new key source.
   *
   * @param {import('../../core-publisher/Sealer.js').PeriodKeySupply} periodKeySupply
   * @returns {void}
   */
  rotatePeriodKeySupply(periodKeySupply) {
    if (typeof periodKeySupply?.derive !== "function") {
      throw dcaError("bad_config", "a periodKeySupply is an object with a derive(accessGroup, t)");
    }
    this.#periodKeySupply = periodKeySupply;
  }

  /**
   * The public half one issuer is sealed to, and the keyId the render names it
   * by. Both move together: the issuer selects on the keyId, so a new key under
   * the old name would yield a page nothing can open and nothing can say why.
   *
   * Only an issuer this publisher already knows. Onboarding a new issuer
   * changes the publisher configuration rather than rotating an existing key.
   *
   * @param {string} issuerName
   * @param {string} keyId
   * @param {CryptoKey} publicKey
   * @returns {void}
   */
  rotateIssuerKey(issuerName, keyId, publicKey) {
    const issuer = this.#issuers.find((held) => held.issuerName === issuerName);
    if (!issuer) {
      throw dcaError("bad_config", `this publisher is not onboarded with issuer "${issuerName}"`);
    }
    if (typeof keyId !== "string" || !publicKey) {
      throw dcaError(
        "bad_config",
        "an issuer key rotation is a keyId and the public half it names",
      );
    }
    issuer.keyId = keyId;
    issuer.publicKey = publicKey;
  }

  /** @returns {{ renders: number, origin: string, issuers: string[], signingKid: string|null }} */
  stats() {
    return {
      renders: this.#renders,
      origin: this.#origin,
      issuers: this.#issuers.map((issuer) => issuer.issuerName),
      signingKid: this.#signingKid,
    };
  }
}

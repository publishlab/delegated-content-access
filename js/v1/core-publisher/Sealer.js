// @ts-check
//
// The publisher side. Collects the items of one render, then produces the
// dca-data a page carries and the sealed ciphertext beside it.
//
// This module: one contentKey per content item, sealed for each issuer with
// ECDH P-256, plus the cached path - a periodKey per (accessGroup, t) taken
// from the injected `periodKeySupply`, wrapping each contentKey into that
// item's `contentData` record and sealed to each issuer under
// `sealed.periodKeys`, and both signed envelopes over the result.
//
// The publisher signs the resource as `resourceJWT`, and an issuer acts on that
// signature: the claims it reads when deciding access came from the publisher
// and not from the client that forwarded them. Every sealed blob of this render
// is bound to its `renderId`, which is why one signed copy of it is enough.
//
// Each render carries one origin. The publisher configures the delivery origin
// instead of passing it per call: it is signed as `resourceJWT.origin`, and an
// issuer compares the observed HTTP `Origin` against that signed value before
// it opens anything. A publisher delivering one article from two origins
// renders it once per origin.
//
// The blobs travel through the client, so each one is sealed and bound to its own
// coordinate (`core-shared/bind`), and a blob presented under another name, or
// lifted into another render, does not open. The coordinate is sealed into the
// blob rather than carried beside it.
//
// Signing keys are plural and keyed by `kid`, which the header carries. A
// rotation changes which one signs; the markup an edge cache is still serving
// carries the kid of the key that signed it, and the issuer picks by kid.
//
// A publisher without a `periodKeySupply` has no periodKeys to derive - the
// direct-only case - so an item names no accessGroup and its record carries no
// `keys` member at all. A publisher holding a supply names at least one group per
// item, and that group's periodKey unwraps the item's contentKey.
//
// The two paths carry the same contentKey. Direct hands it to one client for
// one render; cached hands out the periodKey that unwraps it, and every
// article of that family and period unwraps with the same periodKey.
//
// Every nonce, contentKey and renderId comes from the injected `random`,
// `issuedAt` and every `t` from the injected `clock`.
//
// A composition may take two roles here, at two different scopes. The
// content-key wrap strategy is selected once for the render, because
// `contentData[contentName].keys` is emitted once and every issuer reads the
// same entries. The issuer supply plan is asked once per issuer, and says only
// what that issuer is supplied. Both are settled before this module draws a
// random byte, asks the period-key supply, seals to an issuer or signs. Base
// then executes plans that can no longer change.

import { base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { encrypt, NONCE_BYTES } from "../core-shared/aead.js";
import { periodsFor } from "../core-shared--publisher-issuer/periodKeys.js";
import { sign } from "../core-shared--publisher-issuer/jwt.js";
import { AAD_DELIMITER, validateResourceId } from "../core-shared--client-publisher/names.js";
import { validateAccessGroup, validateContentName } from "../core-shared/names.js";
import { dcaError } from "../core-shared/errors.js";
import { own } from "../core-shared/wire.js";
import {
  inspectPeriodGeometryBounds,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
} from "../core-shared/geometryBounds.js";
import { RENDER_ID_BYTES } from "../core-shared--publisher-issuer/bind.js";
import { assertCompleteIssuerRoutes, normalizedIssuerSupplyPlan } from "./issuerSupplyPlan.js";
import { validatePublisherConfig } from "./publisherConfig.js";
import {
  isContentRepresentation,
  normalizeContentRepresentation,
} from "./contentRepresentation.js";

/** Re-exported for callers that generate publisher fixtures. */
export { RENDER_ID_BYTES };

/** DCA data format version this sealer emits. */
const VERSION = "1";

/** Canonical AES-128 content key. */
const CONTENT_KEY_BYTES = 16;

/**
 * Both carriers receive their binding and the injected random source. RSA-OAEP
 * returns before reading the random source; ECDH uses it for the nonce.
 *
 * @param {{ bytes: (n: number) => Uint8Array }} random
 * @param {{ renderId: string } & Omit<EphemeralContext, 'issuerName'>} binding
 * @returns {any}
 */
function carrierOptions(random, binding) {
  const options = {
    random,
    binding,
  };
  return options;
}

/**
 * An issuer this publisher seals for, as configured at onboarding.
 *
 * @typedef {object} IssuerConfig
 * @property {string} issuerName
 * @property {string} keyId
 * @property {string} algorithm - 'ECDH-P256'
 * @property {CryptoKey} publicKey
 * @property {string} unlockUrl
 */

/**
 * @typedef {object} ContentItem
 * @property {string} name
 * @property {Uint8Array} bytes
 * @property {string} contentType
 * @property {readonly string[]} contentEncodings
 * @property {string[]} accessGroups
 */

/**
 * One wrapped contentKey, as `contentData[name].keys[accessGroup]` carries it.
 * In the format, this leaf is an array of these rather than a `t`-keyed map.
 * It is the one place the wire uses a list, and each entry carries its own `t`.
 *
 * @typedef {object} SealedContentKeyEntry
 * @property {string} t
 * @property {string} nonce - base64url, 12 bytes, one per wrap
 * @property {string} key - base64url contentKey wrapped under the periodKey
 */

/**
 * One content item as the client reads it: what the item was encrypted under,
 * and the contentKey candidates a cached path can unwrap. `keys` is absent on
 * an item the render offers no cached path for.
 *
 * @typedef {object} ContentDataRecord
 * @property {string} contentType - handling metadata; encoding traversal does not read it
 * @property {string} nonce - base64url, 12 bytes
 * @property {string} aad
 * @property {string[]} [contentEncodings] - applied in order, reversed by the client
 * @property {Record<string, SealedContentKeyEntry[]>} [keys] - by accessGroup
 */

/**
 * The publisher-to-client wire shape. Keyed maps, keyed by contentName,
 * accessGroup, issuerName and `t`. The publisher chose every one of those
 * names, which is why the reading side never does a bare `map[name]`.
 *
 * @typedef {object} DcaData
 * @property {string} version
 * @property {{ renderId: string, origin: string, issuedAt: string, resourceId: string, data: object }} resource
 * @property {string} resourceJWT - ES256 over `resource`, shared across issuers
 * @property {{ accessGroups: Record<string, { chainsPerDay: number, periodMinutes: number }> }} [periodChain]
 * @property {Record<string, ContentDataRecord>} contentData
 * @property {Record<string, { sealed: { contentKeys: Record<string, string>, periodKeys?: Record<string, Record<string, string>>, periodChainKeys?: Record<string, Record<string, string>> }, unlockUrl: string, keyId: string }>} issuerData
 */

/**
 * @typedef {object} Render
 * @property {DcaData} dcaData
 * @property {Record<string, string>} sealedContent - base64url ciphertext per contentName
 */

/**
 * Where a periodKey's opaque bytes come from. Base consumes an injected exact-key
 * supply, and a selected extension may answer the same call.
 *
 * Base requires `derive` alone, and asks it only for exact keys. An extension
 * may additionally provide one synchronous `familyPlan` snapshot per access
 * group; base still receives only labels and opaque key-acquisition
 * operations, never a derivation construction.
 *
 * The base slice ships no default supply and imports no derivation profile: a
 * periodKey's bytes are the publisher's to choose, so a publisher on the cached
 * path injects its supply. The Sealer is asked for bytes at a coordinate and
 * assigns no derivation meaning to them.
 *
 * @typedef {object} PeriodKeySupply
 * @property {(accessGroup: string, t: string) => Promise<Uint8Array>} derive
 * @property {(accessGroup: string, now: Date, period: object) => object} [familyPlan]
 */

/** Canonical exact-period and period-chain key width. */
const PERIOD_KEY_BYTES = 16;

/**
 * This module accepts the signed resource context only as a JSON tree. A
 * JavaScript object that merely survives one call to JSON.stringify does not
 * pass. In particular, do not let a
 * getter, toJSON hook, sparse member or host object change what the publisher
 * thought it was signing while serialization is under way.
 *
 * This deliberately reads descriptors rather than serializing. It does not
 * invoke accessors or toJSON hooks, and snapshots the JSON tree immediately so
 * mutation after resource() cannot change the value later signed. Publisher
 * metadata is opaque to DCA core (though issuer policy may read the verified
 * signed value), so a valid JSON value including a string that looks like
 * markup is not sanitized.
 *
 * @param {unknown} data
 * @returns {object}
 */
function snapshotResourceData(data) {
  try {
    if (!isPlainObject(data)) invalidResourceData();
    return /** @type {object} */ (snapshotJsonValue(data, new Set()));
  } catch (error) {
    if (/** @type {any} */ (error)?.code === "bad_config") throw error;
    invalidResourceData();
  }
}

/** @param {unknown} value @returns {value is object} */
function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** @returns {never} */
function invalidResourceData() {
  throw dcaError(
    "bad_config",
    "resource data is a non-array plain JSON object with no omitted or runtime-defined members",
  );
}

/**
 * @param {unknown} value
 * @param {Set<object>} ancestors
 */
function snapshotJsonValue(value, ancestors) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (Number.isFinite(value)) return value;
    invalidResourceData();
  }
  if (typeof value !== "object") invalidResourceData();
  if (ancestors.has(value)) invalidResourceData();

  ancestors.add(value);
  try {
    if (Array.isArray(value)) return snapshotJsonArray(value, ancestors);
    if (isPlainObject(value)) return snapshotJsonObject(value, ancestors);
    invalidResourceData();
  } finally {
    ancestors.delete(value);
  }
}

/**
 * @param {object} value
 * @param {Set<object>} ancestors
 */
function snapshotJsonObject(value, ancestors) {
  const snapshot = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") invalidResourceData();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable)
      invalidResourceData();
    // defineProperty, rather than assignment, keeps a legal own
    // "__proto__" JSON member as data instead of invoking the inherited
    // Object.prototype setter.
    Object.defineProperty(snapshot, key, {
      value: snapshotJsonValue(descriptor.value, ancestors),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return snapshot;
}

/**
 * @param {unknown[]} value
 * @param {Set<object>} ancestors
 */
function snapshotJsonArray(value, ancestors) {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) invalidResourceData();
  const snapshot = new Array(value.length);

  for (const key of keys) {
    if (key === "length") continue;
    if (typeof key !== "string") invalidResourceData();
    const index = Number(key);
    if (
      !Number.isSafeInteger(index) ||
      index < 0 ||
      index >= value.length ||
      String(index) !== key
    ) {
      invalidResourceData();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) invalidResourceData();
    Object.defineProperty(snapshot, key, {
      value: snapshotJsonValue(descriptor.value, ancestors),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return snapshot;
}

/** @param {unknown} labels @param {string} accessGroup @param {string} field */
function checkedLabels(labels, accessGroup, field) {
  if (
    !Array.isArray(labels) ||
    labels.length === 0 ||
    labels.some((t) => typeof t !== "string" || t.length === 0 || t.includes(AAD_DELIMITER)) ||
    new Set(labels).size !== labels.length
  ) {
    throw dcaError(
      "bad_config",
      `${field} for accessGroup "${accessGroup}" is a nonempty list of unique binding-safe labels`,
    );
  }
  return Object.freeze([...labels]);
}

/**
 * @param {unknown} declared
 * @param {string} accessGroup
 */
function checkedFamilyPlan(declared, accessGroup) {
  if (declared === null || typeof declared !== "object" || Array.isArray(declared)) {
    throw dcaError("bad_config", `the period family plan for "${accessGroup}" is an object`);
  }
  const plan = /** @type {any} */ (declared);
  for (const name of Object.keys(plan)) {
    if (name !== "periods" && name !== "exactAt" && name !== "chain") {
      throw dcaError(
        "unsupported_option",
        `a period family plan has no ${name} yet, and will not pretend to`,
      );
    }
  }
  if (typeof plan.exactAt !== "function") {
    throw dcaError(
      "bad_config",
      `the period family plan for "${accessGroup}" acquires an exact key at each label`,
    );
  }
  const periods = checkedLabels(plan.periods, accessGroup, "periods");
  if (plan.chain === undefined) return Object.freeze({ periods, exactAt: plan.exactAt });

  if (plan.chain === null || typeof plan.chain !== "object" || Array.isArray(plan.chain)) {
    throw dcaError("bad_config", `the chain plan for "${accessGroup}" is an object`);
  }
  const { geometry, suppliedTs, capabilityAt } = plan.chain;
  for (const name of Object.keys(plan.chain)) {
    if (name !== "geometry" && name !== "suppliedTs" && name !== "capabilityAt") {
      throw dcaError(
        "unsupported_option",
        `a chain family plan has no ${name} yet, and will not pretend to`,
      );
    }
  }
  const geometryBounds =
    geometry === null || typeof geometry !== "object"
      ? null
      : inspectPeriodGeometryBounds(geometry.chainsPerDay, geometry.periodMinutes);
  if (geometryBounds?.kind !== "valid") {
    throw dcaError(
      "bad_config",
      `the chain plan for "${accessGroup}" carries valid complete geometry`,
    );
  }
  for (const name of Object.keys(geometry)) {
    if (name !== "chainsPerDay" && name !== "periodMinutes") {
      throw dcaError(
        "unsupported_option",
        `chain geometry has no ${name} yet, and will not pretend to`,
      );
    }
  }
  if (typeof capabilityAt !== "function") {
    throw dcaError(
      "bad_config",
      `the chain plan for "${accessGroup}" acquires a capability at each supplied label`,
    );
  }
  const checkedSuppliedTs = checkedLabels(suppliedTs, accessGroup, "supplied chain labels");
  if (checkedSuppliedTs.length > MAX_CHAIN_MEMBERS_PER_FAMILY) {
    throw dcaError(
      "bad_config",
      `the chain plan for "${accessGroup}" supplies at most ${MAX_CHAIN_MEMBERS_PER_FAMILY} capabilities`,
    );
  }
  return Object.freeze({
    periods,
    exactAt: plan.exactAt,
    chain: Object.freeze({
      geometry: Object.freeze({
        chainsPerDay: geometry.chainsPerDay,
        periodMinutes: geometry.periodMinutes,
      }),
      suppliedTs: checkedSuppliedTs,
      capabilityAt,
    }),
  });
}

/**
 * One acquired key, at the width the selected profile states. A leaf of the
 * other profile's width is refused here, at the coordinate that produced it,
 * rather than wrapped at whatever arrived.
 *
 * @param {unknown} value
 * @param {string} kind
 * @param {string} accessGroup
 * @param {string} t
 * @param {number} width - the stated width, from the selected profile
 */
function checkedKeyBytes(value, kind, accessGroup, t, width) {
  if (!(value instanceof Uint8Array) || value.length !== width) {
    throw dcaError(
      "bad_key",
      `${kind} for accessGroup "${accessGroup}" at "${t}" is ${width} bytes`,
    );
  }
  return Uint8Array.from(value);
}

/**
 * How a key is sealed to an issuer. An explicit `keySealing` replaces the core
 * default, and is then responsible for every selected producer requirement,
 * including a fresh ECDH pair and nonce per envelope.
 * The core default conforms. A variant may commit to another coordinate or
 * carrier when its selected profile defines that construction.
 *
 * @typedef {object} KeySealing
 * @property {(keyBytes: Uint8Array, publicKey: CryptoKey, algorithm: string, options: any) => Promise<string>} seal
 */

/**
 * What a sealed blob is for, so a supplied ephemeral keypair can be matched to
 * it. A contentKey blob names its contentName; a period capability names its
 * accessGroup, its period label and whether it is chain state. The member name
 * is `t` for an exact leaf and `suppliedT` for chain state. Keyed by context
 * rather than by call order, so a provider does not have to know how many blobs
 * a render makes.
 *
 * @typedef {object} EphemeralContext
 * @property {string} issuerName
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t]
 * @property {string} [suppliedT]
 * @property {boolean} [periodChain]
 * @property {number} [chainsPerDay]
 * @property {number} [periodMinutes]
 */

export class Sealer {
  /** @type {string} */
  #origin;
  #clock;
  #random;
  /** @type {Record<string, CryptoKey>} */
  #signingKeys;
  /** @type {string} */
  #signingKid;
  /** @type {import('../core-shared--publisher-issuer/periodKeys.js').Period} */
  #period;
  /** @type {PeriodKeySupply|null} */
  #periodKeySupply;
  /** @type {KeySealing} */
  #keySealing;
  /** @type {import('./contentKeyWrap.js').CheckedContentKeyWrap} */
  #contentKeyWrap;
  /** @type {(issuer: IssuerConfig, render: { accessGroups: string[], contentNames: string[] }) => any} */
  #issuerSupplyPlanFor;
  /** @type {IssuerConfig[]} */
  #issuers;
  /** @type {ContentItem[]} */
  #items = [];
  /** @type {{ resourceId: string, data: object }|null} */
  #resource = null;

  /**
   * @param {object} config
   * @param {string} config.origin - the one canonical browser origin this
   *   publisher's renders are delivered from, `scheme://host[:port]`. It is
   *   signed as `resourceJWT.origin`, and an issuer compares the observed
   *   HTTP Origin against it.
   * @param {boolean} [config.developmentHttpOrigin] - the explicit
   *   development profile. With it off, this publisher signs https and nothing
   *   else. With it on, it may also sign http for a localhost host, and still
   *   not for a public one. A production deployment leaves it off.
   * @param {{ now: () => Date }} config.clock
   * @param {{ bytes: (n: number) => Uint8Array }} config.random
   * @param {IssuerConfig[]} config.issuers
   * @param {import('../core-shared--publisher-issuer/periodKeys.js').Period} [config.period] - `{ length,
   *   slots }`, hourly and two slots by default. Two publishers with
   *   different periods run in one process, so each publisher configures its
   *   own.
   * @param {PeriodKeySupply} [config.periodKeySupply] - where a periodKey's
   *   bytes come from, and the whole of the cached path. With it left out,
   *   the render carries no cached path at all: no `keys` on an item
   *   record, no `sealed.periodKeys`, and an issuer can only answer with
   *   contentKeys.
   *   A selected extension may instead provide a grant with a different
   *   reach; its bundle stays outside this base role slice.
   * @param {KeySealing} [config.keySealing] - how each key is sealed to an
   *   issuer. `core-shared--publisher-issuer/keySealing.js` by default; a variant module carries
   *   another binding, and it is handed the same coordinate either way.
   * @param {Record<string, CryptoKey>} config.signingKeys - the publisher's
   *   ECDSA P-256 private keys, keyed by `kid`. Plural because a rotation has
   *   to leave the previous key resolvable: markup an edge cache is still
   *   serving carries the kid of the key that signed it, and the issuer
   *   selects by kid.
   * @param {string} [config.signingKid] - which one signs this render.
   *   Optional while there is only one, required as soon as there are two:
   *   a publisher holding two keys has to say which of them signs.
   * @param {import('./contentKeyWrap.js').ContentKeyWrapStrategy} [config.contentKeyWrapStrategy]
   *   how this render writes `contentData[contentName].keys`: the aad each
   *   wrap is made under and the entry that carries it. One per render,
   *   because that member is emitted once and every issuer reads the same
   *   entries. `ordinaryContentKeyWrap` by default, which is the format's v1
   *   representation.
   * @param {(issuer: IssuerConfig, render: { accessGroups: string[], contentNames: string[] }) => object}
   *   [config.issuerSupplyPlanFor] - what one issuer is supplied, asked once
   *   per issuer before the render draws anything. It answers a value and
   *   writes nothing: the access groups that issuer's period material covers,
   *   whether it receives the direct content-key map, the content names it
   *   must be able to reach through those groups, and the extra members its
   *   block carries. Every plan is checked before the first random byte, so
   *   base refuses a plan this render cannot serve before producing anything.
   */
  constructor(config) {
    const {
      origin,
      clock,
      random,
      issuers,
      signingKeys,
      signingKid,
      period,
      periodKeySupply,
      keySealing,
      contentKeyWrap,
      issuerSupplyPlanFor,
    } = validatePublisherConfig(config);

    this.#origin = origin;
    this.#signingKeys = signingKeys;
    this.#signingKid = signingKid;
    this.#clock = clock;
    this.#random = random;
    this.#period = period;
    this.#periodKeySupply = periodKeySupply;
    this.#keySealing = keySealing;
    this.#contentKeyWrap = contentKeyWrap;
    this.#issuerSupplyPlanFor = issuerSupplyPlanFor;
    this.#issuers = issuers;
  }

  /**
   * @param {string} resourceId
   * @param {object} data - publisher-defined metadata an issuer decides on
   * @returns {this}
   */
  resource(resourceId, data) {
    // The resourceId is the first field of the content aad, so it may not
    // carry the character the aad joins on. It is a value and never a member
    // name, which is why it keeps the publisher's own identifier scheme
    // otherwise. The format's own example is `123456`, which no member-name
    // grammar would admit.
    validateResourceId(resourceId);
    this.#resource = { resourceId, data: snapshotResourceData(data) };
    return this;
  }

  /**
   * The item names the accessGroups it is wrapped under, so two articles can
   * assign the same contentName differently.
   *
   * The item's contentKey is wrapped under the `accessGroups` named here: one
   * `contentData[name].keys[accessGroup]` list per group, and every issuer
   * granted that group can hand out the periodKey that opens it.
   *
   * A sealer holding a `periodKeySupply` needs at least one group per item.
   * Naming a supply asks for the cached path, and there is no default group
   * to fall back on. A sealer without one is direct-only: the groups may be
   * omitted or empty, the item is held with none, and its record ships no
   * `keys`. Groups named on such a sealer are still checked and kept, and
   * still wrap nothing.
   *
   * Bare strings keep the legacy API and are UTF-8 encoded here. Bare bytes
   * and descriptor bytes are copied here, and a descriptor's ordered
   * contentEncodings are copied with them. Descriptor bytes are already
   * encoded; base records their layers and never applies a codec.
   *
   * @param {string} name
   * @param {string|Uint8Array|{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} value
   * @param {string|{ accessGroups?: string[] }} [contentTypeOrOptions]
   * @param {{ accessGroups?: string[] }} [legacyOptions]
   * @returns {this}
   */
  content(name, value, contentTypeOrOptions, legacyOptions) {
    // Both names key a map on the wire (`contentData[name]` and
    // `contentData[name].keys[accessGroup]`), and the contentName is also
    // the aad's last field. This method refuses a bad name here rather than
    // at seal(), so the call that introduced the name is the one that fails.
    validateContentName(name);
    // Every emitted map is keyed by contentName, so a second item under one
    // name could only survive as a duplicate member - the shape
    // `tools/duplicateMembers.js` lints against and the reject vector
    // refuses. The call that repeats the name fails instead.
    if (this.#items.some((item) => item.name === name)) {
      throw dcaError("bad_config", `content "${name}" is already in this render`);
    }
    const descriptor = isContentRepresentation(value);
    if (descriptor && legacyOptions !== undefined) {
      throw dcaError(
        "bad_config",
        `content "${name}" uses descriptor options as its third argument`,
      );
    }
    const options = descriptor ? (contentTypeOrOptions ?? {}) : (legacyOptions ?? {});
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw dcaError("bad_config", `content "${name}" options are an object`);
    }
    const representation = normalizeContentRepresentation(
      value,
      descriptor ? undefined : contentTypeOrOptions,
    );
    const accessGroups = own(options, "accessGroups");
    const groups = accessGroups ?? [];
    if (!Array.isArray(groups)) {
      throw dcaError("bad_config", `content "${name}" accessGroups are a list`);
    }
    if (this.#periodKeySupply && !groups.length) {
      throw dcaError("bad_config", `content "${name}" needs at least one accessGroup`);
    }
    for (const accessGroup of groups) validateAccessGroup(accessGroup);
    this.#items.push({
      name,
      bytes: representation.bytes,
      contentType: representation.contentType,
      contentEncodings: representation.contentEncodings,
      accessGroups: [...groups],
    });
    return this;
  }

  /**
   * One render. The core default, and any conforming selected provider, gives
   * a fresh renderId, contentKey and nonce per item, nonce per wrapped
   * contentKey, and ECDH ephemeral keypair per sealed blob. An explicit
   * provider is responsible for its own producer conformance; deterministic replay is
   * fixture-only and intentionally nonconforming.
   *
   * The periodKeys are the exception, and deliberately: a shared supply
   * returns the same bytes for one (accessGroup, t) in every render, and the
   * client's cache is built on that.
   *
   * @returns {Promise<Render>}
   */
  async seal() {
    if (!this.#resource) throw dcaError("bad_config", "Sealer needs a resource before it can seal");
    if (!this.#items.length)
      throw dcaError("bad_config", "Sealer needs a content item before it can seal");

    // One render instant for the whole render, read once and checked here.
    // Two reads would let a clock that turned invalid between them stamp a
    // valid `issuedAt` and still name the periods, and `formatT` does not
    // reject NaN: every slot would collapse onto `NaNNaNNaNTNaN`, one label
    // covering everything sealed while the clock was broken. Checking at the
    // read also keeps the refusal independent of the order the statements
    // below happen to stand in.
    const observedNow = this.#clock.now();
    if (!(observedNow instanceof Date) || !Number.isFinite(observedNow.getTime())) {
      throw dcaError("bad_config", "a publisher render instant is a valid Date");
    }
    // Keep the captured instant even if a caller-owned Clock returns a
    // mutable Date and supplier code later changes that same object.
    const now = new Date(observedNow.getTime());

    // Base settles every plan first, and settles the compatibility question
    // at the same time. What follows draws from the random source, asks the
    // supply for key material and seals to an issuer, and a refusal after any
    // of that would leave a caller holding a partial answer it cannot tell
    // from a complete one.
    const accessGroups = this.#accessGroups();
    const contentNames = this.#items.map((item) => item.name);
    const plans = this.#issuerSupplyPlans(accessGroups, contentNames);
    assertCompleteIssuerRoutes(this.#items, plans);
    const periodKeys = await this.#derivePeriodKeys(now, plans, accessGroups);

    const renderId = base64urlEncode(this.#random.bytes(RENDER_ID_BYTES));

    const resource = {
      renderId,
      origin: this.#origin,
      issuedAt: now.toISOString(),
      resourceId: this.#resource.resourceId,
      // Each render gets its own copy. A host may annotate or otherwise
      // mutate one returned delivery without changing the next render's
      // signed resource context.
      data: snapshotResourceData(this.#resource.data),
    };

    /** @type {Record<string, ContentDataRecord>} */
    const contentData = {};
    /** @type {Record<string, string>} */
    const sealedContent = {};
    /** @type {Record<string, Uint8Array>} */
    const contentKeys = {};

    for (const item of this.#items) {
      const contentKey = this.#random.bytes(CONTENT_KEY_BYTES);
      const nonce = this.#random.bytes(NONCE_BYTES);
      // Both fields around the version are refused the delimiter at
      // entry, so `premium1` and `premium|1` cannot join to one string.
      const aad = [this.#resource.resourceId, VERSION, item.name].join(AAD_DELIMITER);

      const ciphertext = await encrypt(contentKey, nonce, item.bytes, utf8Encode(aad));

      contentData[item.name] = {
        contentType: item.contentType,
        nonce: base64urlEncode(nonce),
        aad,
        ...(item.contentEncodings.length === 0
          ? {}
          : { contentEncodings: [...item.contentEncodings] }),
      };
      sealedContent[item.name] = base64urlEncode(ciphertext);
      contentKeys[item.name] = contentKey;
    }

    if (periodKeys) await this.#wrapContentKeys(renderId, contentData, contentKeys, periodKeys);

    /** @type {Record<string, any>} */
    const issuerData = {};

    for (const [index, issuer] of this.#issuers.entries()) {
      const plan = plans[index];

      /** @type {{ contentKeys?: Record<string, string>, periodKeys?: Record<string, Record<string, string>>, periodChainKeys?: Record<string, Record<string, string>> }} */
      const sealed = {};
      if (plan.directContentKeys) {
        /** @type {Record<string, string>} */
        const sealedKeys = {};
        for (const item of this.#items) {
          sealedKeys[item.name] = await this.#keySealing.seal(
            contentKeys[item.name],
            issuer.publicKey,
            issuer.algorithm,
            carrierOptions(this.#random, {
              renderId,
              contentName: item.name,
            }),
          );
        }
        sealed.contentKeys = sealedKeys;
      }
      if (periodKeys) {
        const exact = await this.#sealPeriodKeys(issuer, plan, renderId, periodKeys);
        if (Object.keys(exact).length > 0) sealed.periodKeys = exact;
        const chains = await this.#sealPeriodChainKeys(issuer, plan, renderId, periodKeys);
        if (Object.keys(chains).length > 0) sealed.periodChainKeys = chains;
      }

      issuerData[issuer.issuerName] = {
        // The planned members lead the block. They say which route the
        // rest of it is written for, and a reader meets them before it
        // reads a `sealed` that may be shaped for that route.
        ...plan.issuerMembers,
        sealed,
        unlockUrl: issuer.unlockUrl,
        keyId: issuer.keyId,
      };
    }

    // Assembled here rather than filled in as it goes, because the wire has
    // an order: the format's example carries the envelope between the
    // resource and contentData, and a JSON object's key order is the order
    // its keys were first set.
    /** @type {DcaData} */
    const dcaData = {
      version: VERSION,
      resource,
      resourceJWT: await this.#sign(resource),
      ...(periodKeys?.periodChain ? { periodChain: periodKeys.periodChain } : {}),
      contentData,
      issuerData,
    };

    return { dcaData, sealedContent };
  }

  /**
   * One token under the active signing key, with its `kid` in the header so
   * the issuer knows which public half verifies it.
   *
   * @param {object} payload
   * @returns {Promise<string>}
   */
  #sign(payload) {
    return sign(payload, this.#signingKeys[this.#signingKid], { kid: this.#signingKid });
  }

  /**
   * One closed plan per issuer, in the order the render lists them. Each one
   * is asked and checked on its own, against the coordinates of this render
   * and the one wrap strategy it selected, so the render refuses an
   * incompatible plan whichever issuer it belongs to.
   *
   * @param {string[]} accessGroups
   * @param {string[]} contentNames
   * @returns {import('./issuerSupplyPlan.js').IssuerSupplyPlan[]}
   */
  #issuerSupplyPlans(accessGroups, contentNames) {
    return this.#issuers.map((issuer) =>
      normalizedIssuerSupplyPlan(
        issuer.issuerName,
        this.#issuerSupplyPlanFor(issuer, {
          accessGroups: [...accessGroups],
          contentNames: [...contentNames],
        }),
        { accessGroups, items: this.#items, contentKeyWrapStrategy: this.#contentKeyWrap.strategy },
      ),
    );
  }

  /**
   * The accessGroups this render wraps under, in the order the items named
   * them. Two items in one group share its periodKey family.
   *
   * @returns {string[]}
   */
  #accessGroups() {
    /** @type {string[]} */
    const groups = [];
    for (const item of this.#items) {
      for (const accessGroup of item.accessGroups) {
        if (!groups.includes(accessGroup)) groups.push(accessGroup);
      }
    }
    return groups;
  }

  /**
   * One periodKey per (accessGroup, t) for this render, requested once and
   * reused; the same bytes come back however many times it is asked for.
   * Null when this publisher has no periodKeySupply, which is the direct-only
   * case.
   *
   * An ordinary exact supply retains the base `periodsFor` plan. An optional
   * family planner may replace that list for a family while exposing only
   * opaque exact and positioned key acquisition to base.
   *
   * @param {Date} now - the render instant, already checked by `seal()`
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan[]} issuerPlans
   * @param {string[]} accessGroups - collected once for this render
   * @returns {Promise<{
   *   periodsFor: (accessGroup: string) => readonly string[],
   *   keyFor: (accessGroup: string, t: string) => Uint8Array,
   *   chainKeysFor: (accessGroup: string) => { t: string, key: Uint8Array }[],
   *   geometryFor: (accessGroup: string) => { chainsPerDay: number, periodMinutes: number }|null,
   *   periodChain?: { accessGroups: Record<string, { chainsPerDay: number, periodMinutes: number }> }
   * }|null>}
   */
  async #derivePeriodKeys(now, issuerPlans, accessGroups) {
    const supply = this.#periodKeySupply;
    if (!supply) {
      if (
        issuerPlans.some((plan) =>
          Object.values(plan.periodKeyDelivery).some((modes) => modes.includes("chain")),
        )
      ) {
        throw dcaError("bad_config", "chain delivery needs a configured period-family supply");
      }
      return null;
    }

    /** @type {Map<string, any>} */
    const familyPlans = new Map();
    for (const accessGroup of accessGroups) {
      const declared = supply.familyPlan
        ? supply.familyPlan(accessGroup, new Date(now.getTime()), { ...this.#period })
        : {
            periods: periodsFor(now, this.#period),
            exactAt: (/** @type {string} */ t) => supply.derive(accessGroup, t),
          };
      familyPlans.set(accessGroup, checkedFamilyPlan(declared, accessGroup));
    }

    const chainNeeded = new Set();
    for (const issuerPlan of issuerPlans) {
      for (const accessGroup of issuerPlan.suppliedAccessGroups) {
        const modes = issuerPlan.periodKeyDelivery[accessGroup];
        if (modes.includes("chain")) {
          const family = familyPlans.get(accessGroup);
          if (!family?.chain) {
            throw dcaError(
              "bad_config",
              `issuer chain delivery for accessGroup "${accessGroup}" has no configured chain family route`,
            );
          }
          chainNeeded.add(accessGroup);
        }
      }
    }

    for (const issuerPlan of issuerPlans) {
      let chainMemberCount = 0;
      for (const accessGroup of issuerPlan.suppliedAccessGroups) {
        if (issuerPlan.periodKeyDelivery[accessGroup].includes("chain")) {
          chainMemberCount += familyPlans.get(accessGroup).chain.suppliedTs.length;
        }
      }
      if (chainMemberCount > MAX_CHAIN_MEMBERS_PER_MESSAGE) {
        throw dcaError(
          "bad_config",
          `one issuer supply contains at most ${MAX_CHAIN_MEMBERS_PER_MESSAGE} period-chain capabilities`,
        );
      }
    }

    /** @type {Map<string, Uint8Array>} */
    const derived = new Map();
    /** @type {Map<string, { t: string, key: Uint8Array }[]>} */
    const chainKeys = new Map();
    /** @type {Map<string, { chainsPerDay: number, periodMinutes: number }>} */
    const geometries = new Map();
    for (const accessGroup of accessGroups) {
      const family = familyPlans.get(accessGroup);
      for (const t of family.periods) {
        derived.set(
          [accessGroup, t].join(AAD_DELIMITER),
          checkedKeyBytes(await family.exactAt(t), "periodKey", accessGroup, t, PERIOD_KEY_BYTES),
        );
      }

      if (chainNeeded.has(accessGroup)) {
        const { geometry, suppliedTs, capabilityAt } = family.chain;
        geometries.set(accessGroup, geometry);
        const entries = [];
        for (const t of suppliedTs) {
          entries.push({
            t,
            key: checkedKeyBytes(
              await capabilityAt(t),
              "periodChainKey",
              accessGroup,
              t,
              PERIOD_KEY_BYTES,
            ),
          });
        }
        chainKeys.set(accessGroup, entries);
      }
    }

    const result = /** @type {any} */ ({
      periodsFor: (/** @type {string} */ accessGroup) =>
        familyPlans.get(accessGroup)?.periods ?? [],
      keyFor: (/** @type {string} */ accessGroup, /** @type {string} */ t) =>
        /** @type {Uint8Array} */ (derived.get([accessGroup, t].join(AAD_DELIMITER))),
      chainKeysFor: (/** @type {string} */ accessGroup) => chainKeys.get(accessGroup) ?? [],
      geometryFor: (/** @type {string} */ accessGroup) => geometries.get(accessGroup) ?? null,
    });
    if (geometries.size > 0) {
      const accessGroupsContext = {};
      for (const [accessGroup, geometry] of geometries) {
        Object.defineProperty(accessGroupsContext, accessGroup, {
          value: geometry,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
      result.periodChain = { accessGroups: accessGroupsContext };
    }
    return result;
  }

  /**
   * Fills `contentData[contentName].keys[accessGroup]`, the client's side of
   * the cached path, into the record the item already has. One entry per
   * period, each with its own nonce.
   *
   * This member is emitted once for the whole render, which is why the wrap
   * strategy is selected once: it says what each wrap is bound to and what
   * the entry carrying it looks like, and every issuer of the render reads
   * the same entries. The ordinary strategy passes no aad, because the
   * periodKey is already specific to its accessGroup, per the format.
   *
   * The member is written last, so a record reads in the format's order and
   * an item with no cached path carries no `keys` at all.
   *
   * @param {string} renderId - the coordinate every wrap is offered under
   * @param {Record<string, ContentDataRecord>} contentData - changed in place
   * @param {Record<string, Uint8Array>} contentKeys
   * @param {{ periodsFor: (accessGroup: string) => readonly string[], keyFor: (accessGroup: string, t: string) => Uint8Array,
   * }} periodKeys
   * @returns {Promise<void>}
   */
  async #wrapContentKeys(renderId, contentData, contentKeys, periodKeys) {
    for (const item of this.#items) {
      /** @type {Record<string, object[]>} */
      const byGroup = {};
      for (const accessGroup of item.accessGroups) {
        /** @type {object[]} */
        const entries = [];
        for (const t of periodKeys.periodsFor(accessGroup)) {
          const nonce = this.#random.bytes(NONCE_BYTES);
          const coordinate = { renderId, contentName: item.name, accessGroup, t };
          const key = await encrypt(
            periodKeys.keyFor(accessGroup, t),
            nonce,
            contentKeys[item.name],
            this.#contentKeyWrap.aad(coordinate),
          );
          entries.push(
            this.#contentKeyWrap.entry({
              t,
              nonce: base64urlEncode(nonce),
              key: base64urlEncode(key),
            }),
          );
        }
        byGroup[accessGroup] = entries;
      }
      contentData[item.name].keys = /** @type {any} */ (byGroup);
    }
  }

  /**
   * The issuer's side of the same path,
   * `issuerData[issuerName].sealed.periodKeys[accessGroup][t]`: each periodKey
   * sealed to that issuer's public key.
   *
   * The groups are the ones this issuer's plan supplies, which is every group
   * of the render unless a plan named fewer. A composition that supplies an
   * issuer fewer groups than the render wraps under says so in the plan, and the plan
   * was already checked against what that issuer has to reach.
   *
   * @param {IssuerConfig} issuer
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan} plan
   * @param {string} renderId - the render every one of these blobs is bound to
   * @param {{ periodsFor: (accessGroup: string) => readonly string[], keyFor: (accessGroup: string, t: string) => Uint8Array,
   * }} periodKeys
   * @returns {Promise<Record<string, Record<string, string>>>}
   */
  async #sealPeriodKeys(issuer, plan, renderId, periodKeys) {
    /** @type {Record<string, Record<string, string>>} */
    const sealed = {};

    for (const accessGroup of plan.suppliedAccessGroups) {
      if (!plan.periodKeyDelivery[accessGroup].includes("exact")) continue;
      /** @type {Record<string, string>} */
      const byPeriod = {};
      for (const t of periodKeys.periodsFor(accessGroup)) {
        byPeriod[t] = await this.#keySealing.seal(
          periodKeys.keyFor(accessGroup, t),
          issuer.publicKey,
          issuer.algorithm,
          carrierOptions(this.#random, {
            renderId,
            accessGroup,
            t,
          }),
        );
      }
      sealed[accessGroup] = byPeriod;
    }

    return sealed;
  }

  /**
   * The terminal period-chain keys this supply gives an issuer. They
   * have their own BIND kind because moving one into an exact `periodKeys`
   * slot must not turn derivation authority into an exact-key answer.
   *
   * @param {IssuerConfig} issuer
   * @param {import('./issuerSupplyPlan.js').IssuerSupplyPlan} plan
   * @param {string} renderId
   * @param {{ chainKeysFor: (accessGroup: string) => { t: string, key: Uint8Array }[], geometryFor: (accessGroup: string) => { chainsPerDay: number, periodMinutes: number }|null }} periodKeys
   * @returns {Promise<Record<string, Record<string, string>>>}
   */
  async #sealPeriodChainKeys(issuer, plan, renderId, periodKeys) {
    /** @type {Record<string, Record<string, string>>} */
    const sealed = {};

    for (const accessGroup of plan.suppliedAccessGroups) {
      if (!plan.periodKeyDelivery[accessGroup].includes("chain")) continue;
      /** @type {Record<string, string>} */
      const byTerminal = {};
      const geometry = periodKeys.geometryFor(accessGroup);
      if (!geometry) {
        throw dcaError(
          "bad_config",
          `the chain supply for "${accessGroup}" carries the complete geometry its envelope binds`,
        );
      }
      for (const { t, key } of periodKeys.chainKeysFor?.(accessGroup) ?? []) {
        byTerminal[t] = await this.#keySealing.seal(
          key,
          issuer.publicKey,
          issuer.algorithm,
          carrierOptions(this.#random, {
            renderId,
            accessGroup,
            suppliedT: t,
            periodChain: true,
            ...geometry,
          }),
        );
      }
      if (Object.keys(byTerminal).length > 0) sealed[accessGroup] = byTerminal;
    }

    return sealed;
  }
}

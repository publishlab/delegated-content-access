// @ts-check
//
// One publisher, one render per call. A host hands this entry the inputs it
// renders under and calls `publish` for each article; the entry builds a fresh
// `Sealer` for every call, gives it the resource and each item, and returns
// what `seal` returns: the page's `dcaData` and the `sealedContent` beside it.
//
// Every configuration member is a host input the Sealer already takes, under
// the Sealer's name, and the Sealer's own checks admit it. A host that selects
// extensions passes their contributions after the configuration;
// `core-publisher/publisherComposition.js` decides who owns each seam and
// refuses two owners here, before any render. Base imports no extension. This entry
// adds no value of its own: no origin, clock, entropy, signing key, issuer,
// supply scope, period-key source or period geometry. `createPublisher` runs those
// checks once so a bad configuration fails when the host builds the publisher
// rather than at its first render; each `publish` runs them again because it
// builds another Sealer.
//
// A contribution may declare per-item options with `itemOptionMembers`; a
// render item then admits those members beside the base ones, and the Sealer
// copies them when the item is added, before any await. A member nobody
// declared is still refused.
//
// The entry keeps a copy of the records it was given, so a host that edits its
// issuer list, an issuer's limits, its period or its signing-key map afterwards
// changes no later render. A host
// that rotates a signing key, a period-key supply or an issuer key builds
// another publisher; construction reads nothing and costs nothing.
//
// Markup is a separate call. A host that emits the page's script carriers
// passes the render `publish` returned to `writeMarkupDelivery` in
// `adapter-publisher/`, which `copy-manifest--publisher.json` copies beside
// this entry.

import { Sealer } from "../core-publisher/Sealer.js";
import { validatePublisherConfig } from "../core-publisher/publisherConfig.js";
import { composePublisherConfig } from "../core-publisher/publisherComposition.js";
import { isContentRepresentation } from "../core-publisher/contentRepresentation.js";
import { dcaError } from "../core-shared/errors.js";

const OPTIONS = [
  "origin",
  "developmentHttpOrigin",
  "clock",
  "random",
  "signingKeys",
  "signingKid",
  "issuers",
  "issuerSupplyPlanFor",
  "periodKeySupply",
  "period",
  "keySealing",
  "contentKeyWrapStrategy",
];

const RENDER_MEMBERS = ["resourceId", "data", "items"];
const ITEM_MEMBERS = ["name", "value", "contentType", "accessGroups"];
const REPRESENTATION_MEMBERS = ["bytes", "contentType", "contentEncodings"];

/**
 * @typedef {object} PublisherEntryConfig
 * @property {string} origin - the publisher context origin. Required. The
 *   Sealer signs it as `resourceJWT.origin`; under the browser-origin profile,
 *   it is the calling page's origin compared with the observed HTTP `Origin`,
 *   not a JSON fetch or storage location.
 * @property {boolean} [developmentHttpOrigin] - the development profile, off
 *   when left out. On, the origin may also be `http` on a loopback host.
 * @property {{ now: () => Date }} clock - read once per render. Required.
 * @property {{ bytes: (n: number) => Uint8Array }} random - every renderId,
 *   content key, plus random bytes requested by selected contributions. Required.
 *   The ordinary ECDH envelope uses an implicit zero nonce. A production publisher supplies a
 *   cryptographic random-bit generator; a fixed or deterministic stream is a
 *   test fixture for reproducing vectors, not a conforming deployment source
 *   (docs/spec--sealed-key-envelopes.md).
 * @property {Record<string, CryptoKey>} signingKeys - ECDSA P-256 private
 *   keys by `kid`. Required.
 * @property {string} [signingKid] - which held key signs. Required once more
 *   than one key is held.
 * @property {import('../core-publisher/Sealer.js').IssuerConfig[]} issuers -
 *   the issuers this publisher is onboarded with. Required, and each record
 *   needs a nonempty string `keyId` and its opening key configuration.
 * @property {(issuer: import('../core-publisher/Sealer.js').IssuerConfig, render: { accessGroups: string[], contentNames: string[], now: Date }) => object} issuerSupplyPlanFor -
 *   what each issuer is supplied per render. Required, with no default scope.
 * @property {import('../core-publisher/Sealer.js').PeriodKeySupply} [periodKeySupply] -
 *   the period-key source. Left out, renders carry no period route, and an
 *   item that names an accessGroup is refused.
 * @property {import('../core-shared--publisher-issuer/periodKeys.js').Period} [period] -
 *   the period geometry. Left out, the Sealer applies its own.
 * @property {import('../core-publisher/Sealer.js').KeySealing} [keySealing] -
 *   selected publisher-to-issuer envelope implementation. Left out, the
 *   Sealer uses the base construction. An implementation that supplies its
 *   own ECDH ephemeral key pair may do so in production only with a pair
 *   freshly generated for each envelope; a fixed or replayed pair, such as
 *   the deterministic sealers under `tools/vector-fixtures/`, is test-vector
 *   material.
 * @property {import('../core-publisher/contentKeyWrap.js').ContentKeyWrapStrategy} [contentKeyWrapStrategy] -
 *   selected once for each render's shared item-key wrap representation.
 *   A selected contribution may own this seam instead; naming it here as well
 *   is refused as a second owner.
 */

/**
 * A text item. A bare string is UTF-8 encoded by the publisher.
 *
 * @typedef {object} PublishTextItem
 * @property {string} name - the item's contentName
 * @property {string} value
 * @property {string} contentType
 * @property {string[]} [accessGroups] - the groups whose period keys wrap
 *   this item. Omitted or empty, the item carries no wraps and needs an item
 *   content-key route from the issuer plan. Naming a group needs a
 *   `periodKeySupply`.
 */

/**
 * A byte item. The publisher copies the supplied octets unchanged.
 *
 * @typedef {object} PublishBytesItem
 * @property {string} name - the item's contentName
 * @property {Uint8Array} value
 * @property {string} contentType
 * @property {string[]} [accessGroups]
 */

/**
 * A pre-encoded representation. The descriptor carries its content type and
 * encoding layers; do not add a sibling `contentType` member.
 *
 * @typedef {object} PublishRepresentationItem
 * @property {string} name - the item's contentName
 * @property {{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} value
 * @property {never} [contentType] - a descriptor already carries this member;
 *   runtime validation also requires the sibling member be absent, not undefined
 * @property {string[]} [accessGroups]
 */

/**
 * Extension fields are declared by the integrator, never inferred from an item.
 * @template [Fields={}]
 * @typedef {(PublishTextItem|PublishBytesItem|PublishRepresentationItem) & Fields} PublishItem
 */

/**
 * @template [Fields={}]
 * @typedef {object} PublishInput
 * @property {string} resourceId
 * @property {object} data - publisher metadata the resource JWT signs
 * @property {PublishItem<Fields>[]} items
 */

/**
 * A declared publisher composition. The integrator must also supply matching
 * runtime contributions: this type does not prove they were configured.
 * Unknown-member and extension validation still run for every publish.
 * @template [Fields={}]
 * @typedef {{ publish: (render: PublishInput<Fields>) => Promise<import('../core-publisher/Sealer.js').Render> }} Publisher
 */

/**
 * @param {unknown} value
 * @param {string[]} members
 * @param {string} what - names the refused value in the message
 */
function refuseUnknownMembers(value, members, what) {
  for (const name of Reflect.ownKeys(/** @type {object} */ (value))) {
    if (typeof name !== "string" || !members.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `${what} has no ${String(name)}, and will not pretend to`,
      );
    }
  }
}

/**
 * Require schema fields to be own record members. Optional schema fields on a
 * prototype are refused too, so a caller cannot accidentally supply data by
 * inheritance.
 *
 * @param {Record<string, unknown>} value
 * @param {string[]} required
 * @param {string[]} optional
 * @param {string} what
 */
function requireOwnMembers(value, required, optional, what) {
  for (const name of required) {
    if (!Object.hasOwn(value, name)) {
      throw dcaError("bad_config", `${what} needs its own ${name} member`);
    }
  }
  for (const name of [...required, ...optional]) {
    if (name in value && !Object.hasOwn(value, name)) {
      throw dcaError("bad_config", `${what} takes ${name} only as its own member`);
    }
    if (optional.includes(name) && Object.hasOwn(value, name) && value[name] === undefined) {
      throw dcaError("bad_config", `${what} omits ${name} instead of setting it to undefined`);
    }
  }
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {PublisherEntryConfig} config
 * @param {...import('../core-publisher/publisherComposition.js').PublisherContribution} contributions -
 *   the selected extensions, in the order their planner wrappers nest
 * @returns {Publisher}
 */
export function createPublisher(
  config = /** @type {PublisherEntryConfig} */ ({}),
  ...contributions
) {
  if (!isRecord(config)) {
    throw dcaError("bad_config", "createPublisher takes one configuration object");
  }
  requireOwnMembers(
    config,
    ["origin", "clock", "random", "signingKeys", "issuers", "issuerSupplyPlanFor"],
    [
      "developmentHttpOrigin",
      "signingKid",
      "periodKeySupply",
      "period",
      "keySealing",
      "contentKeyWrapStrategy",
    ],
    "createPublisher",
  );
  refuseUnknownMembers(config, OPTIONS, "createPublisher");
  // The Sealer reads this member as `=== true`, so a string would switch the
  // profile off without a word.
  if (
    config.developmentHttpOrigin !== undefined &&
    typeof config.developmentHttpOrigin !== "boolean"
  ) {
    throw dcaError("bad_config", "developmentHttpOrigin is a profile that is on or off");
  }
  const composed = /** @type {PublisherEntryConfig} */ (
    contributions.length === 0 ? config : composePublisherConfig(config, ...contributions).config
  );
  const admitted = validatePublisherConfig(composed);

  // Only the members the host named go on, so the Sealer applies its own
  // treatment of an absent one. The two composed members come from the
  // selected contributions only.
  /** @type {Record<string, unknown>} */
  const sealerConfig = {};
  for (const name of [...OPTIONS, "itemPreparations", "itemOptionMembers"]) {
    if (Object.hasOwn(composed, name)) sealerConfig[name] = /** @type {any} */ (composed)[name];
  }
  const itemOptionMembers = /** @type {string[]} */ (
    /** @type {any} */ (composed).itemOptionMembers ?? []
  );
  const itemMembers = [...ITEM_MEMBERS, ...itemOptionMembers];
  // Admission above passed on these records; each copy takes what the
  // Sealer's own runtime copy takes, the record's own enumerable members. The
  // signing keys and the period come from that runtime view, which also holds
  // the selected key or a period option the host keeps non-enumerable.
  sealerConfig.signingKeys = Object.freeze({ ...admitted.signingKeys });
  sealerConfig.issuers = Object.freeze(
    [...composed.issuers].map((issuer) => {
      const entry = { ...issuer };
      if (entry.limits !== undefined) entry.limits = Object.freeze({ ...entry.limits });
      return Object.freeze(entry);
    }),
  );
  if (composed.period !== undefined) sealerConfig.period = Object.freeze({ ...admitted.period });

  /**
   * Seal one render.
   *
   * @param {PublishInput} render
   * @returns {Promise<import('../core-publisher/Sealer.js').Render>}
   */
  async function publish(render) {
    if (!isRecord(render)) {
      throw dcaError("bad_config", "publish takes one render: a resourceId, its data and items");
    }
    requireOwnMembers(render, RENDER_MEMBERS, [], "a render");
    refuseUnknownMembers(render, RENDER_MEMBERS, "a render");
    const { resourceId, data, items } = render;
    if (!Array.isArray(items)) {
      throw dcaError("bad_config", "a render's items are a list");
    }

    const sealer = new Sealer(/** @type {any} */ (sealerConfig));
    sealer.resource(resourceId, data);
    for (const item of items) {
      if (!isRecord(item)) throw dcaError("bad_config", "a render item is an object");
      requireOwnMembers(
        item,
        ["name", "value"],
        ["contentType", "accessGroups", ...itemOptionMembers],
        "a render item",
      );
      refuseUnknownMembers(item, itemMembers, "a render item");
      const contentType = Object.hasOwn(item, "contentType") ? item.contentType : undefined;
      /** @type {Record<string, unknown>} */
      const options = {};
      for (const member of ["accessGroups", ...itemOptionMembers]) {
        if (Object.hasOwn(item, member))
          options[member] = /** @type {Record<string, unknown>} */ (item)[member];
      }
      if (isContentRepresentation(item.value)) {
        requireOwnMembers(
          /** @type {Record<string, unknown>} */ (item.value),
          REPRESENTATION_MEMBERS,
          [],
          `content "${item.name}" representation`,
        );
        refuseUnknownMembers(
          item.value,
          REPRESENTATION_MEMBERS,
          `content "${item.name}" representation`,
        );
        // A descriptor carries its own contentType, so a second one beside it
        // would leave the host unsure which the page says.
        if (Object.hasOwn(item, "contentType")) {
          throw dcaError(
            "bad_config",
            `content "${item.name}" is a representation descriptor and carries its own contentType`,
          );
        }
        sealer.content(item.name, /** @type {any} */ (item.value), options);
      } else {
        sealer.content(item.name, item.value, contentType, options);
      }
    }
    return sealer.seal();
  }

  return Object.freeze({ publish });
}

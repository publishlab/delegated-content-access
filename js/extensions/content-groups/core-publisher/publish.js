import { seedHandle, STOCK_CHAIN } from "../core-shared--publisher-issuer/seedHandle.js";
import { base64urlEncode } from "../../../core-shared/codec.js";
import {
  validateAccessGroup,
  validateContentName,
  validateIssuerName,
} from "../../../core-shared/names.js";
import {
  CONTRACT,
  checkedGeometry,
  checkedPeriod,
  checkedWindow,
  contentNameSeed,
  contentNameSeedAad,
  itemPad,
  keyBytes,
  record,
  settleLimits,
  xor16,
} from "../core-shared/construction.js";
import { sealSeed } from "../core-shared/seed-envelope.js";
import {
  contentGroupRequestMembers,
  contentGroupRequestSelection,
} from "../core-shared--client-publisher/requestProjection.js";

/** The issuer envelope provisioning token whose key a seed envelope seals to. */
const SEED_ISSUER_ALGORITHM = "ecdh-p256";
/** The per-item option naming an item's connector groups. */
const ITEM_OPTION = "contentGroups";

/**
 * Response members one issuer exchange needs for what a render promises
 * (core Section 9). Each promise lists mutually exclusive alternatives, and
 * each alternative is the set of coordinates delivered jointly. The issuer may
 * answer any alternative, so a promise costs its largest one; the promises of
 * one exchange are delivered together, so their costs add. The set of every
 * coordinate a request may ask is a choice, not a promise, and is not counted.
 * @param {readonly (readonly (readonly string[])[])[]} promises
 */
function promisedMembers(promises) {
  return promises.reduce(
    (sum, alternatives) =>
      sum + Math.max(0, ...alternatives.map((coordinates) => new Set(coordinates).size)),
    0,
  );
}

/**
 * Item options owned by the content-groups contribution. Empty or omitted
 * groups leave an item ordinary; runtime validation checks each group name.
 * @typedef {{ contentGroups?: string[] }} ContentGroupsItemFields
 */

/**
 * @typedef {object} ContentGroupsPublisherOptions
 * @property {Uint8Array} retainedSecret - the publisher's 32-byte seed secret;
 *   copied when the contribution is made
 * @property {{ chainsPerDay: number, periodMinutes: number }} periodGeometry -
 *   the exact geometry every content-group key of this publisher uses
 * @property {Record<string, number>} [limits] - trusted bounds; see `settleLimits`
 * @property {Record<string, Record<string, string[]>>} [issuerSeedWindows] -
 *   `{issuerName: {contentName: [windowStart, ...]}}`: which aligned windows of
 *   which content names each issuer receives a seed for. No issuer receives a
 *   name it is not listed for.
 * @property {any} [chain] - optional trusted construction override: `settleGeometry`,
 *   `coordinate`, `labelAt` and `familyGeneration`
 */

/**
 * The content-groups contribution to a base publisher. A render item names its
 * connector groups with the item option `contentGroups: [group, ...]`; an item
 * without one, or with an empty list, is ordinary only.
 *
 * Per render, after the Sealer drew the content keys and before it signs, the
 * contribution derives each item's connectors at the render period from the
 * seed of that item's content name and render window, seals each
 * listed seed to its issuer under `sealed.contentWindowSeeds`, and writes the
 * page's `renderPeriod` and `periodGeometry`. A connector item has a route when
 * some issuer holds the seed of its render window; base requires its own route
 * for every other item.
 *
 * @param {ContentGroupsPublisherOptions} options
 * @returns {{ name: string, itemOptionMembers: string[], itemPreparation: import('../../../core-publisher/Sealer.js').ItemPreparation }}
 */
export function contentGroupsPublisherContribution({
  retainedSecret,
  periodGeometry,
  limits: inputLimits,
  issuerSeedWindows = {},
  chain = STOCK_CHAIN,
}) {
  if (
    !chain ||
    ["settleGeometry", "coordinate", "labelAt", "familyGeneration"].some(
      (name) => typeof chain[name] !== "function",
    )
  )
    throw new Error("content groups need the host's trusted chain port");
  const limits = settleLimits(inputLimits);
  const secret = keyBytes(retainedSecret, 32, "retained secret");
  const geometry = checkedGeometry(periodGeometry, chain);
  if (!record(issuerSeedWindows)) throw new Error("issuerSeedWindows is a map of issuer names");
  /** @type {Map<string, Map<string, string[]>>} */
  const seedWindows = new Map();
  for (const [issuerName, names] of Object.entries(issuerSeedWindows)) {
    validateIssuerName(issuerName);
    if (!record(names) || Object.keys(names).length > limits.maxItems)
      throw new Error(`issuer ${issuerName} seed windows are a map of at most maxItems names`);
    /** @type {Map<string, string[]>} */
    const byName = new Map();
    for (const [contentName, windows] of Object.entries(names)) {
      validateContentName(contentName);
      if (!Array.isArray(windows) || windows.length === 0 || windows.length > limits.maxSeedWindows)
        throw new Error("a content name lists between one and maxSeedWindows seed windows");
      const labels = windows.map((label) => {
        if (checkedWindow(label, geometry, chain).startT !== label)
          throw new Error("a seed window is an aligned window start");
        return label;
      });
      if (new Set(labels).size !== labels.length || labels.join() !== [...labels].sort().join())
        throw new Error("seed windows are unique and ordered");
      byName.set(contentName, labels);
    }
    seedWindows.set(issuerName, byName);
  }

  /** @param {Date} now */
  const renderAt = (now) => {
    const minutes = Math.floor(now.getTime() / 60_000);
    return checkedPeriod(
      chain.labelAt(minutes - (minutes % geometry.periodMinutes)),
      geometry,
      chain,
    );
  };

  /**
   * The connector groups of each item that names some, in item order.
   * @param {readonly any[]} items
   * @returns {Map<string, string[]>}
   */
  const connectorGroups = (items) => {
    /** @type {Map<string, string[]>} */
    const selected = new Map();
    for (const item of items) {
      if (!Object.hasOwn(item.options, ITEM_OPTION)) continue;
      const groups = item.options[ITEM_OPTION];
      if (!Array.isArray(groups) || groups.length > limits.maxGroups)
        throw new Error(`content "${item.name}" names its content groups as a bounded list`);
      groups.forEach(validateAccessGroup);
      if (new Set(groups).size !== groups.length)
        throw new Error(`content "${item.name}" names unique content groups`);
      if (groups.length > 0) selected.set(item.name, [...groups]);
    }
    if (selected.size > limits.maxItems) throw new Error("more connector items than maxItems");
    return selected;
  };

  /** @param {readonly any[]} issuers */
  const checkedIssuers = (issuers) => {
    for (const [issuerName] of seedWindows) {
      const issuer = issuers.find((entry) => entry.issuerName === issuerName);
      if (!issuer) throw new Error(`seed windows name ${issuerName}, not a configured issuer`);
      if (issuer.algorithm !== SEED_ISSUER_ALGORITHM)
        throw new Error(`issuer ${issuerName} receives seeds only under ${SEED_ISSUER_ALGORITHM}`);
    }
  };

  return Object.freeze({
    name: "content-groups",
    itemOptionMembers: [ITEM_OPTION],
    itemPreparation: Object.freeze({
      /** @param {{ items: readonly any[], issuers: readonly any[], now: Date }} render */
      routes({ items, issuers, now }) {
        checkedIssuers(issuers);
        const groups = connectorGroups(items);
        const at = renderAt(now);
        // An issuer holding a connector item's render-window seed promises
        // one key that opens this render: a chain of one group from that
        // window, the group's period key at the render period, or the item
        // key. A next-window seed promises nothing for this render.
        for (const [issuerName, byName] of seedWindows) {
          const promises = [...groups]
            .filter(([contentName]) => byName.get(contentName)?.includes(at.startT))
            .map(([contentName, names]) => [
              ...names.map((group) => [JSON.stringify(["chain", contentName, group, at.startT])]),
              ...names.map((group) => [JSON.stringify(["period", contentName, group, at.t])]),
              [JSON.stringify(["item", contentName])],
            ]);
          const members = promisedMembers(promises);
          if (members > limits.maxResponseMembers)
            throw new Error(
              `issuer ${issuerName} promises ${members} content-group response members over ` +
                `maxResponseMembers ${limits.maxResponseMembers}`,
            );
        }
        return [...groups.keys()].filter((contentName) =>
          [...seedWindows.values()].some((byName) => byName.get(contentName)?.includes(at.startT)),
        );
      },
      /**
       * What a client without narrowing relays to one issuer when it needs
       * every item: the client's own projection of this delivery.
       * @param {any} delivery
       * @param {string} issuerName
       */
      requestRelay(delivery, issuerName) {
        const selection = contentGroupRequestSelection(
          delivery,
          issuerName,
          delivery.contentData.map((/** @type {any} */ record) => record.contentName),
          {},
          limits,
        );
        return selection === null ? undefined : contentGroupRequestMembers(selection);
      },
      /** @param {any} context */
      async prepare(context) {
        // Read every input before the first await.
        const { renderId, origin, issuers } = context;
        const groups = connectorGroups(context.items);
        const contentKeys = new Map(
          [...groups.keys()].map((name) => [
            name,
            keyBytes(context.contentKeys[name], 16, "content key"),
          ]),
        );
        const at = renderAt(context.now);
        checkedIssuers(issuers);
        if (groups.size === 0) return {};

        /** @type {Map<string, Uint8Array>} */
        const seeds = new Map();
        /** @param {string} contentName @param {string} window */
        const seedFor = async (contentName, window) => {
          const id = JSON.stringify([contentName, window]);
          if (!seeds.has(id))
            seeds.set(
              id,
              await contentNameSeed(secret, origin, geometry, contentName, window, chain),
            );
          return /** @type {Uint8Array} */ (seeds.get(id));
        };
        /** @type {{ dispose(): void }[]} */
        const handles = [];
        try {
          /** @type {Record<string, Record<string, unknown>>} */
          const contentRecords = {};
          for (const [contentName, names] of groups) {
            const contentKey = /** @type {Uint8Array} */ (contentKeys.get(contentName));
            // The render window's seed at the render period, never the window start.
            const handle = seedHandle(
              await seedFor(contentName, at.startT),
              geometry,
              at.startT,
              chain,
            );
            handles.push(handle);
            /** @type {{ group: string, connector: string }[]} */
            const connectors = [];
            for (const group of names) {
              const pad = await itemPad(await handle.periodKey(group, at.t), {
                renderId,
                contentName,
              });
              connectors.push({ group, connector: base64urlEncode(xor16(contentKey, pad)) });
            }
            contentRecords[contentName] = { [CONTRACT.wire.connectors]: connectors };
          }
          /** @type {Record<string, Record<string, unknown>>} */
          const issuerSealed = {};
          for (const [issuerName, byName] of seedWindows) {
            const issuer = issuers.find(
              (/** @type {any} */ entry) => entry.issuerName === issuerName,
            );
            /** @type {{ contentName: string, windowStart: string, key: string }[]} */
            const sealed = [];
            for (const [contentName, windows] of byName) {
              if (!groups.has(contentName)) continue;
              for (const window of windows) {
                const aad = await contentNameSeedAad(
                  {
                    publisher: origin,
                    renderId,
                    issuerName,
                    contentName,
                    windowStartLabel: window,
                    periodGeometry: geometry,
                  },
                  chain,
                );
                sealed.push({
                  contentName,
                  windowStart: window,
                  key: await sealSeed(await seedFor(contentName, window), issuer.publicKey, aad),
                });
              }
            }
            if (sealed.length > 0)
              issuerSealed[issuerName] = { [CONTRACT.wire.sealedSeeds]: sealed };
          }
          return {
            contentRecords,
            issuerSealed,
            pageMembers: {
              periodGeometry: {
                chainsPerDay: geometry.chainsPerDay,
                periodMinutes: geometry.periodMinutes,
              },
              renderPeriod: at.t,
            },
          };
        } finally {
          // A handle keeps its own copy of the seed it was given.
          for (const handle of handles) handle.dispose();
          for (const seed of seeds.values()) seed.fill(0);
          for (const key of contentKeys.values()) key.fill(0);
        }
      },
    }),
  });
}

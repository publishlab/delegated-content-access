// @ts-check
//
// Test plumbing over the named-record wire. Pages and requests carry arrays of
// records; these helpers find one record by its identity fields and write the
// request collections from short literal maps, so a test states coordinates
// once. They read and write the wire shape only: no map form is accepted.

/** @param {any[]|undefined} records @param {Record<string, string>} identity */
export function find(records, identity) {
  const found = (records ?? []).filter((record) =>
    Object.entries(identity).every(([name, value]) => record?.[name] === value),
  );
  return found.at(-1);
}

/** @param {any[]|undefined} records @param {Record<string, string>} identity */
export function findAll(records, identity) {
  return (records ?? []).filter((record) =>
    Object.entries(identity).every(([name, value]) => record?.[name] === value),
  );
}

/** The issuer block of one issuer. @param {any} page @param {string} issuerName */
export function issuerBlock(page, issuerName) {
  return find(page.issuerData, { issuerName });
}

/** The item record of one content name. @param {any} page @param {string} contentName */
export function item(page, contentName) {
  return find(page.contentData, { contentName });
}

/** One item's connector for one group. @param {any} page @param {string} contentName @param {string} group */
export function connectorOf(page, contentName, group) {
  return find(connectorsOf(page, contentName), { group })?.connector;
}

/** Every connector record of one item. @param {any} page @param {string} contentName */
export function connectorsOf(page, contentName) {
  return /** @type {{ group: string, connector: string }[]} */ (
    item(page, contentName)?.connectors ?? []
  );
}

/** The seed records one issuer block carries. @param {any} page @param {string} issuerName */
export function seedRecords(page, issuerName) {
  return /** @type {{ contentName: string, windowStart: string, key: string }[]} */ (
    issuerBlock(page, issuerName)?.sealed?.contentWindowSeeds ?? []
  );
}

/** One seed envelope. @param {any} page @param {string} issuerName @param {string} contentName @param {string} windowStart */
export function seedOf(page, issuerName, contentName, windowStart) {
  return find(seedRecords(page, issuerName), { contentName, windowStart })?.key;
}

/** One sealed content-key record value. @param {any} page @param {string} issuerName @param {string} contentName */
export function sealedContentKey(page, issuerName, contentName) {
  return find(issuerBlock(page, issuerName)?.sealed?.contentKeys, { contentName })?.key;
}

/** `{name: [group]}` as `requestedContentGroups` records. @param {Record<string, string[]>} map */
export function groupRecords(map) {
  return Object.entries(map).map(([contentName, groups]) => ({ contentName, groups }));
}

/**
 * `{name: {group, connector}}` or `{name: [{group, connector}]}` as
 * `requestedContentKeys` records.
 * @param {Record<string, {group: string, connector: string}|{group: string, connector: string}[]>} map
 */
export function itemRecords(map) {
  return Object.entries(map).flatMap(([contentName, routes]) =>
    (Array.isArray(routes) ? routes : [routes]).map(({ group, connector }) => ({
      contentName,
      group,
      connector,
    })),
  );
}

/** `{windowStart: cutoff}` as `requestedChainCutoffs` records. @param {Record<string, string>} map */
export function cutoffRecords(map) {
  return Object.entries(map).map(([windowStart, cutoff]) => ({ windowStart, cutoff }));
}

/** `{name: key}` as `{contentName, key}` records. @param {Record<string, string>} map */
export function contentKeyRecords(map) {
  return Object.entries(map).map(([contentName, key]) => ({ contentName, key }));
}

/**
 * The keys of one response section at one coordinate, in record order.
 * @param {any[]|undefined} records @param {Record<string, string>} identity
 */
export function keysAt(records, identity) {
  return findAll(records, identity).map((record) => record.key);
}

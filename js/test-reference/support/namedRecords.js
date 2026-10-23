// @ts-check
//
// Test views over the named-record collections of requests, responses and
// engine results. A test that compares whole answers reads them as maps keyed
// by coordinate, and each view throws when two records share a coordinate: a
// map would keep only one of them, and a rival candidate must never disappear
// inside an assertion. An absent member stays `undefined`, so a test still
// tells an absent member from an empty one. Tests about rivals read the
// arrays directly.

/**
 * @param {unknown} records
 * @param {string} what
 * @returns {any[]}
 */
function arrayOf(records, what) {
  if (!Array.isArray(records)) throw new TypeError(`${what} is not a record array`);
  return records;
}

/**
 * @param {Record<string, any>} map
 * @param {string} name
 * @param {any} value
 * @param {string} what
 */
function putOnce(map, name, value, what) {
  if (Object.hasOwn(map, name)) throw new Error(`${what} carries ${name} twice`);
  Object.defineProperty(map, name, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * `[{contentName, key}]` as `{contentName: key}`.
 *
 * @param {unknown} records
 * @returns {Record<string, string>}
 */
export function contentKeyMap(records) {
  if (records === undefined) return /** @type {any} */ (undefined);
  /** @type {Record<string, string>} */
  const map = {};
  for (const { contentName, key } of arrayOf(records, "contentKeys"))
    putOnce(map, contentName, key, "contentKeys");
  return map;
}

/**
 * `[{accessGroup, period, key}]` as `{accessGroup: {period: key}}`. The
 * chain-key `cutoff` member reads the same way through `field`.
 *
 * @param {unknown} records
 * @param {"period" | "cutoff"} [field]
 * @returns {Record<string, Record<string, string>>}
 */
export function periodKeyMap(records, field = "period") {
  if (records === undefined) return /** @type {any} */ (undefined);
  /** @type {Record<string, Record<string, string>>} */
  const map = {};
  for (const record of arrayOf(records, field === "period" ? "periodKeys" : "chainKeys")) {
    if (!Object.hasOwn(map, record.accessGroup)) putOnce(map, record.accessGroup, {}, "keys");
    putOnce(map[record.accessGroup], record[field], record.key, record.accessGroup);
  }
  return map;
}

/**
 * `[{coordinate, error, message?}]` as `{coordinate: {error, message?}}`.
 *
 * @param {unknown} records
 * @returns {Record<string, any>}
 */
export function errorMap(records) {
  if (records === undefined) return /** @type {any} */ (undefined);
  /** @type {Record<string, any>} */
  const map = {};
  for (const { coordinate, ...failure } of arrayOf(records, "errors"))
    putOnce(map, coordinate, failure, "errors");
  return map;
}

/**
 * `[{accessGroup, reason, message?}]` as `{accessGroup: {reason, message?}}`.
 *
 * @param {unknown} records
 * @returns {Record<string, any>}
 */
export function notDeliveredMap(records) {
  if (records === undefined) return /** @type {any} */ (undefined);
  /** @type {Record<string, any>} */
  const map = {};
  for (const { accessGroup, ...report } of arrayOf(records, "notDelivered"))
    putOnce(map, accessGroup, report, "notDelivered");
  return map;
}

/**
 * The last record whose fields match `identity`, the record a reader keeps.
 *
 * @param {unknown} records
 * @param {Record<string, string>} identity
 * @returns {any}
 */
export function recordAt(records, identity) {
  return arrayOf(records, "collection")
    .filter((record) => Object.entries(identity).every(([name, value]) => record?.[name] === value))
    .at(-1);
}

/**
 * The `key` of the record at `identity`.
 *
 * @param {unknown} records
 * @param {Record<string, string>} identity
 * @returns {any}
 */
export function keyAt(records, identity) {
  return recordAt(records, identity)?.key;
}

/**
 * Replace the `key` of the record at `identity`, which has to exist.
 *
 * @param {unknown} records
 * @param {Record<string, string>} identity
 * @param {any} key
 */
export function setKeyAt(records, identity, key) {
  const record = recordAt(records, identity);
  if (record === undefined) throw new Error(`no record at ${JSON.stringify(identity)}`);
  record.key = key;
}

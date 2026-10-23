// @ts-check
//
// Reading a render and a cache back out in the shapes assertions are written
// against: lists of labels and coordinates rather than the record arrays the
// wire carries.
//
// Nothing here decides anything. A helper that folded two readings into one
// answer would let a test pass on the wrong half of it, so each of these hands
// back what it found and the test says what that has to be.

import { ACCESS_GROUP, CONTENT_NAME, ISSUER_NAME } from "../../demo/scenarios/fixtures.js";

/**
 * An own member of a wire object, or undefined. The test side reads members
 * itself rather than through `core-shared/wire.js`: a strict bridge run sends
 * every reference function a test calls to the test target, and a target that
 * ports only the Sealer does not claim `own`
 * (js/test-bridges/_shared/CONTRACT.md, section "Modes").
 *
 * @param {any} value
 * @param {string} key
 * @returns {any}
 */
function own(value, key) {
  if (value === null || typeof value !== "object") return undefined;
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

/**
 * A render as it reaches a client: plain JSON, the sealed ciphertext beside the
 * dca-data as `{contentName, content}` records, nothing left of the objects
 * that made it. What a `Sealer.seal()` result looks like once it has crossed.
 *
 * @param {{ dcaData: object, sealedContent: Record<string, string> }} rendered
 * @returns {any}
 */
export function wire(rendered) {
  const sealedContent = Object.entries(rendered.sealedContent).map(([contentName, content]) => ({
    contentName,
    content,
  }));
  return JSON.parse(JSON.stringify({ ...rendered.dcaData, sealedContent }));
}

/**
 * The same wire with every token cut back to its signing input - header and
 * payload, the two segments that are byte-stable. ES256 draws a fresh `k` per
 * signature, so the third segment cannot be compared and is verified instead.
 *
 * @param {any} dcaData
 * @returns {any}
 */
export function withoutSignatures(dcaData) {
  const stripped = structuredClone(dcaData);

  stripped.resourceJWT = stripped.resourceJWT.split(".").slice(0, 2).join(".");
  return stripped;
}

/**
 * The last record a collection carries under one name, as a reader resolves
 * it, or undefined. A test that edits the result edits the delivery.
 *
 * @param {unknown} collection - such as `page.contentData`
 * @param {string} member - the identity field, such as `contentName`
 * @param {string} name
 * @returns {any}
 */
export function recordNamed(collection, member, name) {
  if (!Array.isArray(collection)) return undefined;
  return collection.findLast((record) => own(record, member) === name);
}

/**
 * One item's record on a page, or undefined.
 *
 * @param {any} page
 * @param {string} [contentName]
 * @returns {any}
 */
export function contentRecordOf(page, contentName = CONTENT_NAME) {
  return recordNamed(own(page, "contentData"), "contentName", contentName);
}

/**
 * One issuer's block on a page, or undefined.
 *
 * @param {any} page
 * @param {string} [issuerName]
 * @returns {any}
 */
export function issuerBlockOf(page, issuerName = ISSUER_NAME) {
  return recordNamed(own(page, "issuerData"), "issuerName", issuerName);
}

/**
 * One item's ciphertext on a page's `sealedContent` records, or undefined.
 *
 * @param {any} page
 * @param {string} contentName
 * @returns {string|undefined}
 */
export function sealedContentOf(page, contentName) {
  return own(recordNamed(own(page, "sealedContent"), "contentName", contentName), "content");
}

/**
 * A page's `sealedContent` records as the contentName-to-ciphertext map the
 * Sealer returns and the delivery writers take.
 *
 * @param {any} page
 * @returns {Record<string, string>}
 */
export function sealedContentByName(page) {
  const records = own(page, "sealedContent");
  return Array.isArray(records)
    ? Object.fromEntries(
        records.map((record) => [own(record, "contentName"), own(record, "content")]),
      )
    : {};
}

/**
 * The items a page declares, in wire order.
 *
 * @param {any} page
 * @returns {string[]}
 */
export function contentNamesOn(page) {
  const records = own(page, "contentData");
  return Array.isArray(records) ? records.map((record) => own(record, "contentName")) : [];
}

/**
 * One item's wrap records under one accessGroup, in wire order. Each is
 * `{accessGroup, period, key, ...}` as the page carries it.
 *
 * @param {any} page
 * @param {string} contentName
 * @param {string} accessGroup
 * @returns {any[]}
 */
export function wrapsOf(page, contentName, accessGroup) {
  const entries = own(contentRecordOf(page, contentName), "keys");
  return Array.isArray(entries)
    ? entries.filter((entry) => own(entry, "accessGroup") === accessGroup)
    : [];
}

/**
 * The accessGroups one item's wraps name, each once, in first-seen order.
 *
 * @param {any} page
 * @param {string} contentName
 * @returns {string[]}
 */
export function wrapGroupsOn(page, contentName) {
  const entries = own(contentRecordOf(page, contentName), "keys");
  return Array.isArray(entries)
    ? [...new Set(entries.map((entry) => own(entry, "accessGroup")))]
    : [];
}

/**
 * The issuers a page names, in wire order.
 *
 * @param {any} page
 * @returns {string[]}
 */
export function issuerNamesOn(page) {
  const blocks = own(page, "issuerData");
  return Array.isArray(blocks) ? blocks.map((block) => own(block, "issuerName")) : [];
}

/**
 * The periods a page ships to the client, in wire order - the period it was
 * rendered in first, then forward.
 *
 * @param {any} page
 * @param {string} [contentName]
 * @param {string} [accessGroup]
 * @returns {string[]}
 */
export function periodsOn(page, contentName = CONTENT_NAME, accessGroup = ACCESS_GROUP) {
  const entries = own(contentRecordOf(page, contentName), "keys");
  return Array.isArray(entries)
    ? entries
        .filter((entry) => own(entry, "accessGroup") === accessGroup)
        .map((entry) => own(entry, "period"))
    : [];
}

/**
 * The periods the same page ships to the issuer. Both sides naming the same set
 * is a claim of its own, which is why these are read apart.
 *
 * @param {any} page
 * @param {string} [issuerName]
 * @param {string} [accessGroup]
 * @returns {string[]}
 */
export function issuerPeriodsOn(page, issuerName = ISSUER_NAME, accessGroup = ACCESS_GROUP) {
  const periods = own(own(issuerBlockOf(page, issuerName), "sealed"), "periodKeys");
  return Array.isArray(periods)
    ? periods
        .filter((entry) => own(entry, "accessGroup") === accessGroup)
        .map((entry) => own(entry, "period"))
    : [];
}

/**
 * What a cache holds, in the order it reports them - newest `t` first.
 *
 * `as` picks how each entry is spelled: its `t` alone, which is what a test over
 * one accessGroup is asking about; the `accessGroup/t` coordinate, which is what
 * a test holding several of them needs to tell two entries apart; or the
 * `accessGroup` alone, which answers which families are held whatever the period
 * and reports each of them once.
 *
 * `accessGroup` narrows it to one family, and `order` reads the report from the
 * other end - a cache reports newest first, and a test about what survived an
 * eviction is usually written oldest first.
 *
 * @param {{ entries: () => Promise<{ familyName: string, t: string }[]> }} cache
 * @param {'t'|'coordinate'|'accessGroup'|{ as?: 't'|'coordinate'|'accessGroup', accessGroup?: string, order?: 'newest'|'oldest' }} [options]
 * @returns {Promise<string[]>}
 */
export async function held(cache, options = {}) {
  const {
    as = "t",
    accessGroup,
    order = "newest",
  } = typeof options === "string" ? { as: options } : options;

  let entries = await cache.entries();
  if (accessGroup !== undefined)
    entries = entries.filter((entry) => entry.familyName === accessGroup);
  if (order === "oldest") entries = [...entries].reverse();

  const spelled = entries.map((entry) => {
    if (as === "coordinate") return `${entry.familyName}/${entry.t}`;
    return as === "accessGroup" ? entry.familyName : entry.t;
  });
  return as === "accessGroup" ? [...new Set(spelled)] : spelled;
}

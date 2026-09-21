// @ts-check
//
// Reading a render and a cache back out in the shapes assertions are written
// against: lists of labels and coordinates rather than the nested maps the wire
// carries.
//
// Nothing here decides anything. A helper that folded two readings into one
// answer would let a test pass on the wrong half of it, so each of these hands
// back what it found and the test says what that has to be.

import { own } from "../../core-shared/wire.js";
import { ACCESS_GROUP, CONTENT_NAME, ISSUER_NAME } from "../../demo/scenarios/fixtures.js";

/**
 * A render as it reaches a client: plain JSON, the sealed ciphertext beside the
 * dca-data, nothing left of the objects that made it. What a `Sealer.seal()`
 * result looks like once it has crossed.
 *
 * @param {{ dcaData: object, sealedContent: object }} rendered
 * @returns {any}
 */
export function wire(rendered) {
  return JSON.parse(JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }));
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
 * The periods a page ships to the client, in wire order - the period it was
 * rendered in first, then forward.
 *
 * @param {any} page
 * @param {string} [contentName]
 * @param {string} [accessGroup]
 * @returns {string[]}
 */
export function periodsOn(page, contentName = CONTENT_NAME, accessGroup = ACCESS_GROUP) {
  const entries = own(own(own(own(page, "contentData"), contentName), "keys"), accessGroup);
  return Array.isArray(entries) ? entries.map((entry) => own(entry, "t")) : [];
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
  const periods = own(own(own(own(page, "issuerData"), issuerName), "sealed"), "periodKeys");
  const group = own(periods, accessGroup);
  return group === undefined || group === null ? [] : Object.keys(group);
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

/**
 * The key one cache holds at one coordinate, and `undefined` where it holds
 * none. Apart from `held` rather than a mode of it: it answers with key material
 * instead of a list of labels, and one call that could hand back either is one a
 * test could assert the wrong half of.
 *
 * @param {{ entries: () => Promise<{ familyName: string, t: string, key?: any }[]> }} cache
 * @param {string} accessGroup
 * @param {string} t
 * @returns {Promise<any>}
 */
async function heldAt(cache, accessGroup, t) {
  const entries = await cache.entries();
  return entries.find((entry) => entry.familyName === accessGroup && entry.t === t)?.key;
}

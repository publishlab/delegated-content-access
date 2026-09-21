// @ts-check
//
// This module defines the identifier grammar once, for every role that reads a name.
//
// DCA carries three identifiers (`contentName`, `accessGroup`, `issuerName`)
// in JSON member position, and member position is the one place in the
// document whose host-language representation is lossy. Only some strings
// survive the round trip unchanged in JavaScript, PHP and Python, and this
// module defines that narrower set.
//
// One grammar covers all three. The publisher's sealer runs a name through
// here at the point it takes it, so a name that cannot be walked safely never
// reaches the wire; the issuer runs a name through here on the request path,
// so a coordinate nothing can be sealed at never reaches a policy decision.
// Consumers still use own-property lookup (`Object.hasOwn`,
// `core-shared/wire`'s `own`), because the grammar alone does not close the
// inherited-name class.
//
// Every role reads names, which is why this module belongs to the base core
// rather than to a pairwise slice.
//
// ## What a name has to survive
//
// A name is used as a JSON member key, looked up across JS, PHP and Python, and
// inside the sealed blob's BIND value. Exact period keys are also supplied at
// coordinates containing the accessGroup. Each of these uses needs the same
// bytes on every runtime and every read: no case folding, no Unicode
// normalization, no reordering, and a length small enough that the BIND still
// fits, which is what MAX_NAME_LENGTH guards.
// A consumer compares names by exact bytes, never a fuzzy or normalized match.
// A name enters the crypto binding and serves as a lookup key across runtimes,
// so every refusal below serves that byte stability.
//
// ## What the grammar refuses, and why
//
// - **integer-like names** - `2`, `10`, `0`, `2025-10`. ES
//   `OrdinaryOwnPropertyKeys` hoists integer-like member names ahead of every
//   string key and sorts them ascending, in every engine, so the client's
//   walk is no longer the publisher's authored order. PHP `json_encode` goes
//   further and emits a JSON **array** for a level whose keys are all numeric.
//   That silently corrupts the wire at the producer, and the publisher CMS is
//   written in PHP. Requiring a letter first closes the whole class, and that
//   is why the grammar starts `[a-zA-Z]`.
// - **the aad delimiter `|`** - the content aad and BIND values use it to join
//   their fields. With `|` banned in every
//   field that enters a join, `premium1` and `premium|1` cannot produce one
//   string, so no pair of fields can be relabelled into another pair's aad.
// - **non-ASCII** - the spec calls contentName and issuerName ASCII. Two
//   spellings of `premium` that a reader cannot tell apart are still different
//   exact accessGroup coordinates, and normalisation differences between a PHP
//   producer and a JS consumer would be a silent miss.
// - **`__proto__`** - the one inherited name that is a setter rather than a
//   data property on an object literal. Letter-initial refuses it.
// - **empty, whitespace, `.`, `/` and the rest** - nothing depends on them and
//   an identifier that needs quoting to be read aloud ends up as a support case.
//
// What none of them refuse: `constructor`, `toString`, `valueOf`,
// `hasOwnProperty`, `isPrototypeOf`. Those match the spec's own contentName
// grammar (spec--data-format.md Section 2.1), and narrowing here would put this producer
// outside the format it is demonstrating. Consumers close them with
// own-property lookup, and `test/wire-lookup-client.test.js`,
// `test/wire-lookup-issuer.test.js` and `test/wire-lookup-endpoint.test.js`
// cover that lookup.
//
// `contentName`, `accessGroup`, and `issuerName` use the same grammar. The
// public authority still needs to record that settled boundary; the reference
// no longer maintains a narrower producer grammar beside a wider accepted one.
//
// `resourceId` and `keyId` are values rather than member names, so the
// member-name reasoning does not apply to them. The spec's own examples,
// `123456` and `2025-10`, are digit-initial and would fail the grammar above.
// `keyId` is opaque, and consumers require only that it is a non-empty string.
// `resourceId` enters the aad, and its own rule lives in
// `core-shared--client-publisher/names`, beside the delimiter it must not
// contain.

import { dcaError } from "./errors.js";

/**
 * One grammar for all three names, docs/spec--data-format.md Section 2.1:
 * letter-initial, then letters, digits, `-`, `_` and `:`. `:` is there so a
 * publisher can write hierarchy into a name, as in `sponsor:intro` or `premium:sport`.
 *
 * Publishers write that hierarchy for display only. Nothing derives, grants or
 * matches on the structure of a name. `premium:sport` is a different accessGroup
 * from `premium` and a grant for one is not a grant for the other. Base supplies
 * exact keys for those distinct coordinates and assigns no derivation meaning to
 * their spelling. A reader who sees the prefix and infers containment has read
 * something the crypto does not implement: accessGroups are flat, and this
 * grammar does not weaken that.
 *
 * `|` stays banned in all three, which keeps the aad and BIND joins
 * unambiguous; `:` and `_` are safe there because neither is a join character.
 * A `:` in a name reaches a JSON member name in `dca-sealed-content`, where it
 * needs no escape: `{"sponsor:intro": "..."}`.
 */
export const NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_:-]*$/;

/**
 * The most characters a name may carry. docs/spec--data-format.md Section 2.1
 * fixes it at 64 as a wire limit.
 *
 * It also fits comfortably inside the RSA-OAEP-2048 bind budget. OAEP capacity
 * is 190 bytes; after the 16-byte sealed key, the period BIND's fixed bytes and
 * the exact 22-character renderId, a 64-character accessGroup remains below
 * that ceiling.
 *
 * The PHP validators enforce the same cap, and the rule reads: an identifier
 * contains 1 through 64 characters.
 */
export const MAX_NAME_LENGTH = 64;

/** spec--data-format.md Section 2.1, identifier rules. */
export const CONTENT_NAME_PATTERN = NAME_PATTERN;

/** Same grammar. An accessGroup is a name in its own namespace. */
export const ACCESS_GROUP_PATTERN = NAME_PATTERN;

/** Same grammar; the spec's own example contains `_`. */
export const ISSUER_NAME_PATTERN = NAME_PATTERN;

/**
 * `RegExp.test` coerces, so `null` reads as `"null"` and passes a grammar that
 * must not admit it. Every one of these checks the type first.
 *
 * @param {unknown} value
 * @param {RegExp} pattern
 * @returns {boolean}
 */
function matches(value, pattern) {
  return typeof value === "string" && value.length <= MAX_NAME_LENGTH && pattern.test(value);
}

/**
 * @param {unknown} name
 * @returns {boolean}
 */
export function isContentName(name) {
  return matches(name, CONTENT_NAME_PATTERN);
}

/**
 * @param {unknown} name
 * @returns {boolean}
 */
export function isAccessGroup(name) {
  return matches(name, ACCESS_GROUP_PATTERN);
}

/**
 * @param {unknown} name
 * @returns {boolean}
 */
export function isIssuerName(name) {
  return matches(name, ISSUER_NAME_PATTERN);
}

/**
 * @param {unknown} name
 * @param {boolean} ok
 * @param {string} kind - which identifier this is, for the message
 * @param {string} rule - what it had to be
 * @returns {string} the name, so a caller can validate inline
 */
function refuse(name, ok, kind, rule) {
  if (ok) return /** @type {string} */ (name);
  throw dcaError("bad_name", `${kind} ${JSON.stringify(name)} is not ${rule}`);
}

/**
 * This function checks a name in the same order as `matches`: type, length,
 * then grammar. The length branch is separate so that its error message names
 * the rule that actually refused the value, not the character grammar that the
 * check never reached.
 *
 * @param {unknown} name
 * @param {string} kind
 * @param {RegExp} pattern
 * @returns {string}
 */
function validateName(name, kind, pattern) {
  if (typeof name === "string" && name.length > MAX_NAME_LENGTH) {
    return refuse(name, false, kind, `at most ${MAX_NAME_LENGTH} characters`);
  }
  return refuse(name, matches(name, pattern), kind, String(pattern));
}

/**
 * @param {unknown} name
 * @returns {string}
 */
export function validateContentName(name) {
  return validateName(name, "contentName", CONTENT_NAME_PATTERN);
}

/**
 * @param {unknown} name
 * @returns {string}
 */
export function validateAccessGroup(name) {
  return validateName(name, "accessGroup", ACCESS_GROUP_PATTERN);
}

/**
 * @param {unknown} name
 * @returns {string}
 */
export function validateIssuerName(name) {
  return validateName(name, "issuerName", ISSUER_NAME_PATTERN);
}

//
// The shared coordinate grammars, from `core-shared/names`, and the two
// `resourceId` rules that stay in `core-shared--client-publisher/names` beside
// the aad delimiter. What a consumer does with a name that reaches it anyway is
// wire-lookup.test.js; publisher Sealer entry and AAD checks are
// sealer-names.test.js.

import test from "node:test";
import assert from "node:assert/strict";

import {
  ACCESS_GROUP_PATTERN,
  CONTENT_NAME_PATTERN,
  ISSUER_NAME_PATTERN,
  isAccessGroup,
  isContentName,
  isIssuerName,
  validateAccessGroup,
  validateContentName,
  validateIssuerName,
  MAX_NAME_LENGTH,
} from "../../core-shared/names.js";
import {
  AAD_DELIMITER,
  isResourceId,
  validateResourceId,
} from "../../core-shared--client-publisher/names.js";
import { DcaError } from "../../core-shared/errors.js";

const ISSUER_NAME = "paywall_subscription_service";
const RESOURCE_ID = "123456";
const INHERITED = ["constructor", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf"];

/**
 * @param {() => unknown} run - called here, and either throwing or rejecting is
 *   the refusal
 * @param {string|{ code: string, message?: RegExp }} expected - the code, or the
 *   code beside what the message has to say
 * @param {string} why - what this refusal is being asked to show, repeated into
 *   every failure message so a red line names the claim and not just the code
 * @returns {Promise<void>}
 */
async function refuses(run, expected, why) {
  const { code, message } =
    typeof expected === "string" ? { code: expected, message: undefined } : expected;

  await assert.rejects(
    async () => run(),
    (error) => {
      assert.ok(error instanceof DcaError, `${why}: expected a DcaError, got ${error}`);
      assert.equal(/** @type {DcaError} */ (error).code, code, why);
      if (message !== undefined) {
        assert.match(/** @type {DcaError} */ (error).message, message, why);
      }
      return true;
    },
  );
}

/** Names the spec writes down itself. Whatever is frozen here has to admit them. */
const SPEC_CONTENT_NAMES = ["bodytext", "premiumtext", "locked-data"];
const SPEC_ACCESS_GROUPS = ["premium", "subscriber", "staff", "locked-data"];
const SPEC_ISSUER_NAMES = ["paywall_subscription_service", "paywall", "archive_partner"];

/**
 * The hazard classes, each with why it is refused. Every kind of name that
 * lands in a JSON member position is held to all of them.
 */
const HAZARDS = [
  ["", "empty"],
  ["0", "integer-like: a purely numeric key level is a JSON array out of PHP json_encode"],
  ["2", "integer-like: ES OrdinaryOwnPropertyKeys hoists it ahead of every string key"],
  ["10", "integer-like: and sorts ascending among the hoisted, not in authored order"],
  ["2025-10", 'digit-initial, which is the same hoisting rule for `"10"`-shaped names'],
  ["__proto__", "the one inherited name that is a setter on an object literal"],
  ["premium|1", `the aad delimiter "${AAD_DELIMITER}"`],
  ["|", "the aad delimiter, alone"],
  ["prémium", "non-ASCII: confusable with `premium`, but a different exact accessGroup coordinate"],
  ["pre mium", "whitespace"],
  ["bodytext\n", "a trailing newline, which an unanchored grammar would let through"],
  ["-leading", "not letter-initial"],
  [".", "punctuation alone"],
  ["a/b", "a path separator"],
];

/** Regex `.test` coerces, so `null` reads as `"null"` and would pass. */
const NON_STRINGS = [null, undefined, 42, {}, ["bodytext"], true, Symbol("bodytext")];

test("the spec's own contentNames pass", () => {
  for (const name of SPEC_CONTENT_NAMES) {
    assert.equal(isContentName(name), true, name);
    assert.equal(validateContentName(name), name, "validate hands the name back");
  }
});

test("the spec's own accessGroups pass", () => {
  for (const name of SPEC_ACCESS_GROUPS) {
    assert.equal(isAccessGroup(name), true, name);
    assert.equal(validateAccessGroup(name), name);
  }
});

test("the spec's own issuerNames pass, underscore included", () => {
  for (const name of SPEC_ISSUER_NAMES) {
    assert.equal(isIssuerName(name), true, name);
    assert.equal(validateIssuerName(name), name);
  }

  // One grammar for all three kinds, docs/spec--data-format.md Section 2.1, so
  // the `_` in an issuerName such as `paywall_subscription_service` is legal
  // wherever a name is.
  assert.equal(isContentName(ISSUER_NAME), true);
  assert.equal(isAccessGroup(ISSUER_NAME), true);
});

test("a name can carry hierarchy, and nothing reads it", () => {
  // `:` is admitted so a publisher can group names legibly. It must not imply
  // containment anywhere in the system.
  for (const name of ["sponsor:intro", "premium:sport", "a:b:c"]) {
    assert.equal(isContentName(name), true, name);
    assert.equal(isAccessGroup(name), true, name);
    assert.equal(validateContentName(name), name, "validated verbatim, never split");
  }

  // The prefix is not the name. Two accessGroups sharing one are two
  // accessGroups, which is what keeps the flat model flat. Exact keys are
  // supplied for the whole coordinate, and a grant for one group opens
  // nothing of the other's.
  assert.notEqual(validateAccessGroup("premium"), validateAccessGroup("premium:sport"));

  // And the delimiter stays banned, so a name carrying hierarchy still cannot
  // reach across a field boundary in the aad or in BIND.
  assert.equal(isContentName("premium:sport|x"), false);
});

test("every hazard class is refused, for every name kind", async () => {
  for (const [name, why] of HAZARDS) {
    const offender = `${JSON.stringify(name)}: ${why}`;

    assert.equal(isContentName(name), false, `contentName ${offender}`);
    assert.equal(isAccessGroup(name), false, `accessGroup ${offender}`);
    assert.equal(isIssuerName(name), false, `issuerName ${offender}`);

    await refuses(() => validateContentName(name), "bad_name", `contentName ${offender}`);
    await refuses(() => validateAccessGroup(name), "bad_name", `accessGroup ${offender}`);
    await refuses(() => validateIssuerName(name), "bad_name", `issuerName ${offender}`);
  }
});

test("a non-string is refused rather than coerced into a match", async () => {
  for (const value of NON_STRINGS) {
    assert.equal(isContentName(/** @type {any} */ (value)), false, String(value));
    assert.equal(isAccessGroup(/** @type {any} */ (value)), false, String(value));
    assert.equal(isIssuerName(/** @type {any} */ (value)), false, String(value));
    assert.equal(isResourceId(/** @type {any} */ (value)), false, String(value));
    await refuses(() => validateContentName(value), "bad_name", `contentName ${String(value)}`);
    await refuses(() => validateAccessGroup(value), "bad_name", `accessGroup ${String(value)}`);
    await refuses(() => validateIssuerName(value), "bad_name", `issuerName ${String(value)}`);
  }
});

test("the error names the offender and the kind", async () => {
  // Two readings of one refusal, and apart on purpose: a single pattern over
  // both would also pin the order they are written in, which is wording.
  const bad = () => validateAccessGroup("2");

  await refuses(bad, { code: "bad_name", message: /accessGroup/ }, "the kind is named");
  await refuses(bad, { code: "bad_name", message: /"2"/ }, "and the offender is quoted");
});

test("the grammar admits the inherited names, and own-property lookup is the defence", () => {
  // Recorded rather than closed: `constructor` matches the spec's own
  // contentName grammar (spec--data-format.md Section 2.1), so narrowing here would put
  // the demo's producer outside the format. The consumer keeps them inert.
  for (const name of INHERITED) {
    assert.equal(isContentName(name), true, `${name} matches the spec grammar`);
    assert.equal(isAccessGroup(name), true, name);
    assert.equal(isIssuerName(name), true, name);
  }
});

test("resourceId is the widest rule: a value, never a member name", async () => {
  // The examples' own resourceId is digit-initial, so the member-name grammar
  // cannot apply. That leaves the aad delimiter and emptiness.
  for (const id of [RESOURCE_ID, "2", "artikkel-42", "nyheter/politikk", "sak_123", "kjøp"]) {
    assert.equal(isResourceId(id), true, id);
    assert.equal(validateResourceId(id), id);
  }

  for (const id of ["", "123|456", AAD_DELIMITER]) {
    assert.equal(isResourceId(id), false, JSON.stringify(id));
    await refuses(() => validateResourceId(id), "bad_name", `resourceId ${JSON.stringify(id)}`);
  }
});

test("no two fields can build the same aad", () => {
  // aad is `resourceId|version|contentName`. These pairs join to the same
  // string, so at least one field of each side has to be refused; with the
  // delimiter banned everywhere, both are.
  const version = "1";
  const collisions = [
    [
      { resourceId: "123", contentName: "1|bodytext" },
      { resourceId: "123|1", contentName: "bodytext" },
    ],
    [
      { resourceId: "1", contentName: "a|1|b" },
      { resourceId: "1|1|a", contentName: "b" },
    ],
  ];

  for (const [left, right] of collisions) {
    const aadOf = (/** @type {{resourceId: string, contentName: string}} */ f) =>
      `${f.resourceId}${AAD_DELIMITER}${version}${AAD_DELIMITER}${f.contentName}`;
    assert.equal(aadOf(left), aadOf(right), "the pair is a real collision");

    for (const side of [left, right]) {
      const ok = isResourceId(side.resourceId) && isContentName(side.contentName);
      assert.equal(ok, false, `${JSON.stringify(side)} must not be sealable`);
    }
  }
});

test("the patterns are exported as the one written source of each grammar", () => {
  // One grammar, written once and exported three times, so a widening lands
  // on all three kinds at once rather than drifting apart per name.
  const GRAMMAR = "^[a-zA-Z][a-zA-Z0-9_:-]*$";
  assert.equal(CONTENT_NAME_PATTERN.source, GRAMMAR);
  assert.equal(ACCESS_GROUP_PATTERN.source, GRAMMAR);
  assert.equal(ISSUER_NAME_PATTERN.source, GRAMMAR);
  assert.equal(AAD_DELIMITER, "|");
});

test("a name is capped in length, and the cap is one number for all three kinds", async () => {
  // The cap is ratified at 64 (core-shared/names.js MAX_NAME_LENGTH). The
  // assertion imports that one source rather than restating the
  // number, and tests the boundary from it: exactly-max passes, one-over is
  // refused, on all three kinds.
  const MAX = MAX_NAME_LENGTH;
  const atCap = "a".repeat(MAX);
  const overCap = "a".repeat(MAX + 1);

  // The longest still-legal name is a name like any other.
  assert.equal(isContentName(atCap), true, "a MAX-length contentName passes");
  assert.equal(validateContentName(atCap), atCap, "validate hands the MAX-length name back");

  // One character past the cap fails is*, so validate* throws the same
  // bad_name every other refused name gets. All three kinds share the number.
  assert.equal(isContentName(overCap), false, "an over-length contentName is refused");
  assert.equal(isAccessGroup(overCap), false, "an over-length accessGroup is refused");
  assert.equal(isIssuerName(overCap), false, "an over-length issuerName is refused");

  // The public validators name the length rule rather than the grammar that
  // the over-length value never reaches. Keep this one assertion per public
  // entry point: all three share the cap, but callers choose their kind.
  const lengthRule = new RegExp(`at most ${MAX_NAME_LENGTH} characters$`);
  await refuses(
    () => validateContentName(overCap),
    { code: "bad_name", message: lengthRule },
    "over-length contentName names the length rule",
  );
  await refuses(
    () => validateAccessGroup(overCap),
    { code: "bad_name", message: lengthRule },
    "over-length accessGroup names the length rule",
  );
  await refuses(
    () => validateIssuerName(overCap),
    { code: "bad_name", message: lengthRule },
    "over-length issuerName names the length rule",
  );

  // Pin the value, not just the boundary derived from it: the checks above
  // read MAX_NAME_LENGTH, so a JS-side drift to another number would pass them
  // all while PHP still enforces 64.
  assert.equal(MAX_NAME_LENGTH, 64, "the cap is the ratified 64");
});

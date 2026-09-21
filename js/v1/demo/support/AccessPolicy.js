// @ts-check
//
// Who may read what. The publisher sets the rules (which names are public,
// which family a subscription covers, how many metered views), and the issuer
// enforces them against its own subscriber base; the spec puts the
// enforcement on the issuer side, which is why this class holds rules and
// never key material. It reaches the engine as a constructor argument. That is
// only wiring: the access-policy tests swap policies to run the naive one
// against the strict one, and a deployment builds its policy from operator
// config the same way it builds its key store.
//
// Stateless. The rules are fixed at construction; the entitlement and the
// running counters arrive in issuer-owned context, which is why one
// issuer serving many publishers is still one policy. Nothing here reaches an
// actor, and nothing here is remembered between two calls.
//
// `AccessPolicy` files both allow-lists under the publisher first, because every
// name belongs to one. A contentName is the publisher's own word and one issuer
// serves many of them: two publishers who both call a tier `premium` are
// selling two different things, and one allow-list over the bare name would let
// a reader who subscribes at one open the other's article on a request where
// nothing is wrong and every integrity check passes. The publisher harmed there
// is a third party neither the reader's issuer nor the reader's publisher
// speaks for, which is why it is not covered by the publisher being trusted.
//
// The publisher registration selected by `kid` carries the browser origin
// that serves as the coordinate. It arrives beside the verified claims as issuer-owned policy input,
// never as a fabricated JWT claim. Rules use that exact canonical origin;
// noncanonical spellings are refused at construction instead of silently folded.
//
// `decide` runs after the integrity checks rather than in place of them. By
// the time it is called the version, the publisher's signature and the
// renderId under it have already passed. So a refusal here is a 401 and never
// a 400, and a name it says no to is an omission from a 200 rather than a
// rejected request. The publisher may ship a name this issuer has never been
// told about, and the issuer answers such a page in part.
//
// The rules deny by default. A contentName or accessGroup the rules do not
// name gets nothing. That keeps an issuer safe when a publisher ships a new
// premium name before the two of them have talked, and it is why the rules
// are held in a `Map`: `rules[name]` would answer for 'constructor' out of
// Object.prototype and hand a function to a check that only asked whether
// something was there.
//
// Input: verified claims, the names present in the request, and issuer-owned
// policy input. The engine never hands policy the unsigned request. The
// `NaiveAccessPolicy` below models an issuer with no access control: it grants
// every requested name without consulting trusted rules. The client chooses
// what to ask for, and an issuer that grants whatever the client asks for has
// no access control.

import { dcaError } from "../../core-shared/errors.js";
import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";
import { own } from "../../core-shared/wire.js";

/** What a rule may say. Anything else is a rule that means nothing. */
const RULE_OPTIONS = ["public", "entitlement", "meter"];

const POLICY_OPTIONS = ["contentNames", "accessGroups"];

/**
 * The prefix length a grant asks for when it means "every period this group
 * presented". It sits past any real ceiling on purpose: the engine clamps a
 * count down to the labels the request carried, so a policy that grants a whole
 * family names a number the engine cuts to size rather than counting the
 * periods itself. Whole grants are the default
 * this reference keeps; a bounded prefix is a smaller number a policy chooses.
 */
export const ALL_PERIODS = Number.MAX_SAFE_INTEGER;

/**
 * One entry of the allow-list. At least one of the three has to be there: a
 * rule that says nothing is a name an operator meant to configure and did not,
 * and reading it as a denial would hide the mistake behind correct behaviour.
 *
 * @typedef {object} Rule
 * @property {boolean} [public] - anyone, credential or not
 * @property {string} [entitlement] - the principal has to hold this one
 * @property {number} [meter] - how many renders a principal may open free
 */

/**
 * One family's bounded grant. The count gives a prefix length rather than a
 * period label. The engine sorts the labels the request carried into canonical
 * order and opens that many of them, so the policy never invents a coordinate.
 *
 * @typedef {object} PeriodGrant
 * @property {string} accessGroup - the family this grant opens
 * @property {number} periodCount - how many of the group's presented `t` labels
 *   to open, in canonical lexicographic order. An explicit prefix length: the
 *   engine sorts the presented labels and takes the first `periodCount`, clamped
 *   to how many the request carried. `ALL_PERIODS` is the whole-family grant.
 */

/**
 * What the policy hands back. `policyData` is opaque to the issuer core and is
 * kept apart from key bytes.
 *
 * @typedef {object} AccessDecision
 * @property {string[]} contentNames - granted, in the order the request listed them
 * @property {PeriodGrant[]} periodGrants - the bounded period grants, one per
 *   granted family. A group named nowhere here, or given `periodCount` 0, opens
 *   no period material.
 * @property {any} [policyData] - opaque host data; this demo policy uses pending view records
 */

/**
 * `decide` receives this object as its `input` argument. The issuer core defines
 * its shape; this demo reads `principal` as `{ user, entitlements }` and
 * `context` as its own view state. The engine passes a plain object rather than
 * the server: a core that could reach an actor would be a core that could change
 * one.
 *
 * @typedef {import('../../core-issuer/IssuerEngine.js').IssuerPolicyDecisionInput} PolicyInput
 */

/**
 * @param {any} rules
 * @param {string} where - for the message only
 * @returns {Map<string, Rule>}
 */
function rulesOf(rules, where) {
  if (rules === undefined) return new Map();
  if (rules === null || typeof rules !== "object") {
    throw dcaError("bad_config", `${where} is a map of name to rule`);
  }

  /** @type {Map<string, Rule>} */
  const map = new Map();
  for (const name of Object.keys(rules)) {
    const rule = rules[name];
    if (rule === null || typeof rule !== "object") {
      throw dcaError("bad_config", `the rule for ${where}.${name} is an object`);
    }
    for (const option of Object.keys(rule)) {
      if (!RULE_OPTIONS.includes(option)) {
        throw dcaError(
          "unsupported_option",
          `a rule has no ${option}, and this one will not pretend to`,
        );
      }
    }
    if (rule.meter !== undefined && (!Number.isInteger(rule.meter) || rule.meter < 0)) {
      throw dcaError("bad_config", `${where}.${name} wants a whole number of metered views`);
    }
    if (rule.public !== true && typeof rule.entitlement !== "string" && rule.meter === undefined) {
      throw dcaError("bad_config", `${where}.${name} gives no reason to say yes`);
    }
    map.set(name, rule);
  }
  return map;
}

/**
 * One section's allow-lists, one per publisher. Each key is already the exact
 * canonical browser origin registered beside the publisher signing key.
 *
 * @param {any} publishers
 * @param {string} where - for the message only
 * @returns {Map<string, Map<string, Rule>>}
 */
function publishersOf(publishers, where) {
  if (publishers === undefined) return new Map();
  if (publishers === null || typeof publishers !== "object") {
    throw dcaError("bad_config", `${where} is a map of publisher origin to name to rule`);
  }

  /** @type {Map<string, Map<string, Rule>>} */
  const map = new Map();
  for (const origin of Object.keys(publishers)) {
    const index = normalizePublisherOrigin(origin);
    if (index === null) {
      throw dcaError(
        "bad_config",
        `${where} files rules under ${JSON.stringify(origin)}, which is not a canonical origin`,
      );
    }
    if (map.has(index)) {
      throw dcaError(
        "bad_config",
        `${where} names ${index} twice, and only one of the two rule sets would be read`,
      );
    }
    map.set(index, rulesOf(publishers[origin], `${where}.${origin}`));
  }
  return map;
}

/**
 * @param {any} requested
 * @param {'contentNames'|'accessGroups'} section
 * @returns {string[]}
 */
function requestedNames(requested, section) {
  const names = own(requested, section);
  return Array.isArray(names) ? names.filter((name) => typeof name === "string") : [];
}

/** A publisher with rules in one section and none in the other. */
const NO_RULES = new Map();

export class AccessPolicy {
  /** @type {Map<string, Map<string, Rule>>} */
  #contentNames;
  /** @type {Map<string, Map<string, Rule>>} */
  #accessGroups;

  /**
   * @param {object} [config]
   * @param {Record<string, Record<string, Rule>>} [config.contentNames] - the
   *   allow-list per publisher origin; a name that is not on that publisher's
   *   is denied, which is the whole default
   * @param {Record<string, Record<string, Rule>>} [config.accessGroups] - the
   *   same for the cached path. Granting a group is granting every article of
   *   that family and period, so it is configured apart from the item names.
   */
  constructor(config = {}) {
    for (const name of Object.keys(config)) {
      if (!POLICY_OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `AccessPolicy has no ${name} yet, and will not pretend to`,
        );
      }
    }
    this.#contentNames = publishersOf(config.contentNames, "contentNames");
    this.#accessGroups = publishersOf(config.accessGroups, "accessGroups");
  }

  /**
   * One decision. Nothing is read from the request but the coordinates it is
   * asking about - every claim behind the answer comes from `claims`, which
   * the caller has already verified under the publisher's key.
   *
   * `input.publisher.origin` carries the verified `resourceJWT.origin` the
   * engine filled in after signature verification, so this policy looks its
   * rules up under a coordinate no caller chose.
   *
   * @param {{ resource: any }} claims - the verified payload
   * @param {{ contentNames: string[], accessGroups: string[] }} requested
   * @param {PolicyInput} [input]
   * @returns {AccessDecision}
   */
  decide(claims, requested, input = {}) {
    // A publisher this issuer holds no rules for is an issuer that was
    // never told what that publisher sells. Reading it as a denial would
    // hide an onboarding nobody finished behind an answer that looks
    // correct, which is what a rule with no reason to say yes gets too.
    const origin = normalizePublisherOrigin(own(own(input, "publisher"), "origin"));
    if (origin === null) {
      throw dcaError("bad_config", "policy input carries no registered publisher origin");
    }
    const contentRules = this.#contentNames.get(origin);
    const groupRules = this.#accessGroups.get(origin);
    if (contentRules === undefined && groupRules === undefined) {
      throw dcaError("bad_config", `no rules for the publisher at ${JSON.stringify(origin)}`);
    }

    const principal = input.principal ?? null;
    const user = typeof own(principal, "user") === "string" ? own(principal, "user") : null;
    const held = own(principal, "entitlements");
    const entitlements = Array.isArray(held) ? held : [];

    // The renderId the meter counts by is the signed one. The unsigned
    // resource is not available to policy.
    const renderId = own(claims?.resource, "renderId");
    const counted = user === null ? [] : own(own(input, "context")?.views, user);
    const seen = Array.isArray(counted) ? counted : [];

    const context = {
      user,
      entitlements,
      seen,
      renderId: typeof renderId === "string" ? renderId : null,
    };

    /** @type {string[]} */
    const contentNames = [];
    /** @type {PeriodGrant[]} */
    const periodGrants = [];
    let metered = false;

    for (const contentName of requestedNames(requested, "contentNames")) {
      const verdict = verdictFor(contentRules ?? NO_RULES, contentName, context);
      if (verdict === "no") continue;
      if (verdict === "meter") metered = true;
      contentNames.push(contentName);
    }

    // An entitled family is granted every period the request carried, which
    // is this reference's whole-group default: `ALL_PERIODS` is a prefix
    // length the engine clamps down to the presented ceiling. A policy that
    // wanted a shorter reach would name a smaller count here.
    for (const accessGroup of requestedNames(requested, "accessGroups")) {
      const verdict = verdictFor(groupRules ?? NO_RULES, accessGroup, context);
      if (verdict === "no") continue;
      if (verdict === "meter") metered = true;
      periodGrants.push({ accessGroup, periodCount: ALL_PERIODS });
    }

    // One view per render, whatever it took to read it: an article with
    // three metered items is one thing a reader read. Nothing is recorded
    // for a render already counted, which is what makes a reload free.
    /** @type {object[]} */
    const policyData =
      metered &&
      context.user !== null &&
      context.renderId !== null &&
      !seen.includes(context.renderId)
        ? [{ type: "view", user: context.user, renderId: context.renderId }]
        : [];

    return { contentNames, periodGrants, policyData };
  }
}

/**
 * @param {Map<string, Rule>} rules
 * @param {string} name
 * @param {{ user: string|null, entitlements: string[], seen: string[], renderId: string|null }} context
 * @returns {'yes'|'meter'|'no'}
 */
function verdictFor(rules, name, context) {
  const rule = rules.get(name);
  if (rule === undefined) return "no";

  if (rule.public === true) return "yes";
  if (typeof rule.entitlement === "string" && context.entitlements.includes(rule.entitlement))
    return "yes";
  if (rule.meter === undefined) return "no";

  // A meter is a count against somebody. An unidentified caller has no
  // counter, and metering one anyway would hand out an unlimited free ride
  // to whoever sends no credential at all.
  if (context.user === null || context.renderId === null) return "no";

  if (context.seen.includes(context.renderId)) return "yes";
  return context.seen.length < rule.meter ? "meter" : "no";
}

/**
 * An injectable policy that shows what happens without access control. It
 * grants every coordinate the request asked about, which reads as generous and
 * in fact lets the client choose.
 *
 * Everything around it is intact: the envelope verified, every blob opened at
 * the coordinate the publisher sealed it at. The binding proves where a blob
 * came from and never that this caller may have the key to it, so an issuer
 * that treats requested names as entitlement has no access control while every
 * cryptographic check it runs passes.
 *
 * `demo/support/AllowAllPolicy` deliberately makes the same decision for tests
 * whose subject is not entitlement. The two stay separate because this class
 * shows the failure and that one is explicit fixture wiring. Changes to how
 * either reads presented coordinates must be checked against its twin.
 */
export class NaiveAccessPolicy {
  /**
   * @param {{ resource: any }} claims - verified, and never read
   * @param {{ contentNames: string[], accessGroups: string[] }} requested
   * @returns {AccessDecision}
   */
  decide(claims, requested) {
    void claims;
    return {
      contentNames: requestedNames(requested, "contentNames"),
      periodGrants: requestedNames(requested, "accessGroups").map((accessGroup) => ({
        accessGroup,
        periodCount: ALL_PERIODS,
      })),
      policyData: [],
    };
  }
}

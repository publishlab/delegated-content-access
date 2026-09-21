//
// Direct issuer-policy decisions and configuration validation. Stateful issuer
// composition remains in access-policy.test.js.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { AccessPolicy, ALL_PERIODS } from "../demo/support/AccessPolicy.js";

const DOMAIN = "www.news-site.example";
const OTHER_DOMAIN = "www.other-paper.example";
const ORIGIN = `https://${DOMAIN}`;
const OTHER_ORIGIN = `https://${OTHER_DOMAIN}`;
const BODYTEXT = "bodytext";
const PREMIUM = "premium";
const ARTICLE_GROUP = "article";
const VAULT_GROUP = "premium-vault";

const RULES = {
  contentNames: {
    [ORIGIN]: {
      [BODYTEXT]: { public: true },
      [PREMIUM]: { entitlement: "premium" },
    },
  },
  accessGroups: {
    [ORIGIN]: {
      [ARTICLE_GROUP]: { public: true },
      [VAULT_GROUP]: { entitlement: "premium" },
    },
  },
};

const TWO_PUBLISHER_RULES = {
  contentNames: {
    [ORIGIN]: { [PREMIUM]: { entitlement: "news-site-premium" } },
    [OTHER_ORIGIN]: { [PREMIUM]: { entitlement: "other-paper-premium" } },
  },
  accessGroups: {},
};

/** @param {string} origin @param {any} [principal] */
function inputFor(origin, principal = null) {
  return { publisher: { origin }, principal, context: { views: {} } };
}

describe("The policy on its own", () => {
  test("a name the policy was never configured with is denied, prototype names included", () => {
    const policy = new AccessPolicy(RULES);

    const claims = { resource: { renderId: "r1" } };
    const requested = {
      contentNames: [BODYTEXT, PREMIUM, "breaking-news", "toString"],
      accessGroups: [ARTICLE_GROUP, VAULT_GROUP, "constructor"],
    };

    const decision = policy.decide(claims, requested, inputFor(ORIGIN));

    // Default deny: the unknown name and the two inherited members are absent,
    // and `premium` is out because nobody was standing there.
    assert.deepEqual(decision.contentNames, [BODYTEXT]);
    assert.deepEqual(decision.periodGrants, [
      { accessGroup: ARTICLE_GROUP, periodCount: ALL_PERIODS },
    ]);
    assert.deepEqual(decision.policyData, []);

    // Same rules, an entitled caller, and the vault opens. The rules did not
    // change; the policy input did, which is what stateless means.
    const entitled = policy.decide(
      claims,
      requested,
      inputFor(ORIGIN, { user: "alice", entitlements: ["premium"] }),
    );
    assert.deepEqual(entitled.contentNames, [BODYTEXT, PREMIUM]);
    assert.deepEqual(entitled.periodGrants, [
      { accessGroup: ARTICLE_GROUP, periodCount: ALL_PERIODS },
      { accessGroup: VAULT_GROUP, periodCount: ALL_PERIODS },
    ]);

    // And the first decision is unchanged by the second: nothing was kept.
    assert.deepEqual(policy.decide(claims, requested, inputFor(ORIGIN)), decision);
  });

  test("a rule needs a reason to say yes, and an option it has no meaning for is refused", () => {
    assert.throws(
      () => new AccessPolicy({ contentNames: { [ORIGIN]: { [BODYTEXT]: {} } } }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
    assert.throws(
      () => new AccessPolicy({ contentNames: { [ORIGIN]: { [BODYTEXT]: { publik: true } } } }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
    assert.throws(
      () => new AccessPolicy({ contentNames: { [ORIGIN]: { [BODYTEXT]: { meter: -1 } } } }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
    assert.throws(
      () => new AccessPolicy({ rules: {} }),
      (/** @type {any} */ err) => err.code === "unsupported_option",
    );
  });

  /**
   * What an operator writes when they mean no and the config file hands back a
   * string or a number. Each of the three is truthy, so a loose `public` check
   * would turn each one into a grant.
   */
  const NOT_PUBLIC = ["no", 1, "false"];

  test("a rule is public where it says `true`, and a truthy `no` is not a yes", () => {
    // Every one of these is paired with the entitlement, which gives the rule
    // its reason to say yes, so an operator could stand this rule up and the
    // only thing on trial is what `public` was read as. Read loosely, the
    // premium tier is public to a caller who bought nothing.
    for (const said of NOT_PUBLIC) {
      const policy = new AccessPolicy({
        contentNames: { [ORIGIN]: { [PREMIUM]: { public: said, entitlement: "premium" } } },
      });

      const claims = { resource: { renderId: "r1" } };
      const requested = { contentNames: [PREMIUM], accessGroups: [] };

      const anyone = policy.decide(claims, requested, inputFor(ORIGIN));
      assert.deepEqual(anyone.contentNames, [], `public: ${JSON.stringify(said)} says nothing`);

      const subscriber = policy.decide(
        claims,
        requested,
        inputFor(ORIGIN, { user: "alice", entitlements: ["premium"] }),
      );
      assert.deepEqual(
        subscriber.contentNames,
        [PREMIUM],
        "the entitlement opened it, and nothing else did",
      );
    }
  });
});

describe("Which publisher the names belong to", () => {
  test("two publishers, one name `premium`, and the entitlement at one does not open the other", () => {
    // A contentName is the publisher's word, and one issuer serves many
    // publishers. Rules held under the bare name would be one allow-list for
    // all of them, so a reader who subscribes at the news site would open the
    // other paper's premium on an honest request with every check passing,
    // and the publisher neither of the other two speaks for pays for it.
    const policy = new AccessPolicy(TWO_PUBLISHER_RULES);

    const requested = { contentNames: [PREMIUM], accessGroups: [] };
    const principal = { user: "alice", entitlements: ["news-site-premium"] };

    const newsSite = policy.decide(
      { resource: { renderId: "r1" } },
      requested,
      inputFor(ORIGIN, principal),
    );
    assert.deepEqual(newsSite.contentNames, [PREMIUM]);

    const otherPaper = policy.decide(
      { resource: { renderId: "r1" } },
      requested,
      inputFor(OTHER_ORIGIN, principal),
    );
    assert.deepEqual(
      otherPaper.contentNames,
      [],
      "the tier is the other paper's, and so is the subscription",
    );
  });

  test("a publisher the rules name nowhere is a fault, not a quiet no", () => {
    // "No rules for this publisher" means an issuer that was never told what
    // the publisher sells, the same class as a rule that gives no reason
    // to say yes: an operator meant to configure something and did not.
    const policy = new AccessPolicy(TWO_PUBLISHER_RULES);

    assert.throws(
      () =>
        policy.decide(
          { resource: { renderId: "r1" } },
          { contentNames: [PREMIUM], accessGroups: [] },
          inputFor("https://www.third-paper.example"),
        ),
      (/** @type {any} */ err) => err.code === "bad_config",
    );
  });

  test("policy configuration uses the same canonical origin spelling as registration and cache identity", () => {
    assert.throws(
      () =>
        new AccessPolicy({
          contentNames: { "HTTPS://Example.com:443": { [PREMIUM]: { public: true } } },
        }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );

    assert.throws(
      () =>
        new AccessPolicy({ contentNames: { "example.com/news": { [PREMIUM]: { public: true } } } }),
      (/** @type {any} */ err) => err.code === "bad_config",
    );

    const policy = new AccessPolicy({
      contentNames: { "https://example.com": { [PREMIUM]: { public: true } } },
    });
    assert.deepEqual(
      policy.decide(
        { resource: { renderId: "r1" } },
        { contentNames: [PREMIUM], accessGroups: [] },
        inputFor("https://example.com"),
      ).contentNames,
      [PREMIUM],
    );
  });
});

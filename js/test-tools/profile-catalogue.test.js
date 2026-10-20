// @ts-check

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  profileDutySummary,
  resolveProfiles,
  validateProfileCatalogue,
  validateSelection,
} from "../tools/profileCatalogue.js";

const catalogue = {
  authority: "docs/spec--profiles.md",
  baseline: "base",
  profiles: [
    { id: "base", dependsOn: [], ref: "#base" },
    { id: "a", dependsOn: ["base"], ref: "#a" },
    { id: "b", dependsOn: ["base"], ref: "#b" },
    { id: "c", dependsOn: ["base"], ref: "#c" },
    { id: "z", dependsOn: ["b", "a"], ref: "#z" },
  ],
  // Each single-parent profile owns a duty; z composes two parents instead.
  duties: [
    { id: "a/client/d", profile: "a", role: "client", ref: "#a" },
    { id: "b/client/d", profile: "b", role: "client", ref: "#b" },
    { id: "c/client/d", profile: "c", role: "client", ref: "#c" },
  ],
};

test("empty and baseline-only requests resolve the baseline", () => {
  assert.deepEqual(resolveProfiles(catalogue, []), {
    requestedProfiles: ["base"],
    resolvedProfiles: ["base"],
  });
  assert.deepEqual(resolveProfiles(catalogue, ["base"]), {
    requestedProfiles: ["base"],
    resolvedProfiles: ["base"],
  });
});

test("resolution trims inherited requests and orders ready names by ASCII", () => {
  assert.deepEqual(resolveProfiles(catalogue, ["c", "base", "z", "a"]), {
    requestedProfiles: ["c", "z"],
    resolvedProfiles: ["base", "a", "b", "c", "z"],
  });
  assert.deepEqual(resolveProfiles(catalogue, ["z", "c"]), resolveProfiles(catalogue, ["c", "z"]));
});

test("duplicate and unknown requests are rejected", () => {
  assert.throws(() => resolveProfiles(catalogue, ["a", "a"]), /duplicate/);
  assert.throws(() => resolveProfiles(catalogue, ["missing"]), /unknown requested/);
  assert.throws(() => resolveProfiles(catalogue, "a"), /array/);
});

test("catalogue validation checks duplicate, unknown, cyclic and disconnected dependencies", () => {
  assert.throws(
    () => validateProfileCatalogue({ ...catalogue, profiles: [...catalogue.profiles].reverse() }),
    /canonical dependency order/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        profiles: [...catalogue.profiles, catalogue.profiles[0]],
      }),
    /duplicate profile/,
  );
  assert.throws(
    () => validateProfileCatalogue({ ...catalogue, baseline: "missing" }),
    /unknown baseline/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        profiles: [
          { id: "base", dependsOn: [], ref: "#" },
          { id: "x", dependsOn: ["missing"], ref: "#" },
        ],
      }),
    /unknown dependency/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        profiles: [
          { id: "base", dependsOn: [], ref: "#" },
          { id: "x", dependsOn: ["y"], ref: "#" },
          { id: "y", dependsOn: ["x"], ref: "#" },
        ],
      }),
    /cycle/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        profiles: [
          { id: "base", dependsOn: [], ref: "#" },
          { id: "x", dependsOn: [], ref: "#" },
        ],
      }),
    /does not resolve the baseline/,
  );
});

test("catalogue validation checks profile metadata and duty references", () => {
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        profiles: [{ id: "base", dependsOn: ["base"], ref: "#" }],
      }),
    /baseline cannot depend/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        duties: [{ id: "d", profile: "missing", role: "client", ref: "#" }],
      }),
    /unknown profile/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...catalogue,
        duties: [
          { id: "base/client/d", profile: "base", role: "client", ref: "#" },
          { id: "base/client/d", profile: "base", role: "issuer", ref: "#" },
        ],
      }),
    /duplicate duty/,
  );
});

/**
 * Build a tiny catalogue under the real baseline id. Each extra profile gets
 * its own ref; `owners` names the profiles that own one client duty.
 * @param {{id: string, dependsOn: string[]}[]} extra
 * @param {string[]} [owners]
 */
function tiny(extra, owners = []) {
  return {
    authority: "docs/spec--profiles.md",
    baseline: "dca-profile-baseline",
    profiles: [
      { id: "dca-profile-baseline", dependsOn: [], ref: "#baseline" },
      ...extra.map((profile) => ({ ...profile, ref: `#${profile.id}` })),
    ],
    duties: owners.map((id) => ({
      id: `${id}/client/d`,
      profile: id,
      role: "client",
      ref: `#${id}`,
    })),
  };
}

const noDuty = /adds no duty and composes fewer than two effective dependencies/;

test("an empty request and an explicit baseline request resolve the same closure", () => {
  const small = tiny([{ id: "dca-vX-a", dependsOn: ["dca-profile-baseline"] }], ["dca-vX-a"]);
  for (const target of [small, realCatalogue()]) {
    const empty = resolveProfiles(target, []);
    const explicit = resolveProfiles(target, ["dca-profile-baseline"]);
    assert.deepEqual(empty.resolvedProfiles, ["dca-profile-baseline"]);
    assert.deepEqual(explicit.resolvedProfiles, empty.resolvedProfiles);
    assert.deepEqual(empty.requestedProfiles, ["dca-profile-baseline"]);
    assert.deepEqual(explicit, empty);
  }
});

test("unknown, repeated and retired requests and repeated dependency edges are refused", () => {
  const small = tiny([{ id: "dca-vX-a", dependsOn: ["dca-profile-baseline"] }], ["dca-vX-a"]);
  assert.throws(() => resolveProfiles(small, ["dca-vX-missing"]), /unknown requested profile/);
  assert.throws(() => resolveProfiles(small, ["dca-vX-a", "dca-vX-a"]), /duplicate/);
  assert.throws(
    () =>
      validateProfileCatalogue(
        tiny(
          [{ id: "dca-vX-a", dependsOn: ["dca-profile-baseline", "dca-profile-baseline"] }],
          ["dca-vX-a"],
        ),
      ),
    /dependsOn has duplicate names/,
  );
  // An unknown profile has no alias.
  assert.throws(
    () => resolveProfiles(realCatalogue(), ["dca-profile-baseline-invented"]),
    /unknown requested profile dca-profile-baseline-invented/,
  );
});

test("a cycle, a self-dependency and an undefined dependency are refused", () => {
  assert.throws(
    () =>
      validateProfileCatalogue(
        tiny(
          [
            { id: "dca-vX-a", dependsOn: ["dca-profile-baseline", "dca-vX-b"] },
            { id: "dca-vX-b", dependsOn: ["dca-vX-a"] },
          ],
          ["dca-vX-a", "dca-vX-b"],
        ),
      ),
    /cycle/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue(
        tiny([{ id: "dca-vX-a", dependsOn: ["dca-profile-baseline", "dca-vX-a"] }], ["dca-vX-a"]),
      ),
    /cycle at dca-vX-a/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue(
        tiny([{ id: "dca-vX-a", dependsOn: ["dca-vX-missing"] }], ["dca-vX-a"]),
      ),
    /unknown dependency dca-vX-missing/,
  );
});

test("a dutyless profile with one effective parent is refused", () => {
  assert.throws(
    () => validateProfileCatalogue(tiny([{ id: "dca-vX-a", dependsOn: ["dca-profile-baseline"] }])),
    new RegExp(`profile dca-vX-a ${noDuty.source}`),
  );
});

test("a parent that another parent already requires does not count as a second parent", () => {
  const extra = [
    { id: "dca-vX-a", dependsOn: ["dca-profile-baseline"] },
    { id: "dca-vX-z", dependsOn: ["dca-profile-baseline", "dca-vX-a"] },
  ];
  assert.throws(
    () => validateProfileCatalogue(tiny(extra, ["dca-vX-a"])),
    new RegExp(`profile dca-vX-z ${noDuty.source}`),
  );
  // With a duty of its own the same profile validates, and the redundant edge
  // stays in dependsOn and in the closure.
  const owning = tiny(extra, ["dca-vX-a", "dca-vX-z"]);
  validateProfileCatalogue(owning);
  assert.deepEqual(owning.profiles[2].dependsOn, ["dca-profile-baseline", "dca-vX-a"]);
  assert.deepEqual(resolveProfiles(owning, ["dca-vX-z"]).resolvedProfiles, [
    "dca-profile-baseline",
    "dca-vX-a",
    "dca-vX-z",
  ]);
});

test("a dutyless profile with two incomparable parents resolves a shared ancestor once", () => {
  const composed = tiny(
    [
      { id: "dca-vX-a", dependsOn: ["dca-profile-baseline"] },
      { id: "dca-vX-b", dependsOn: ["dca-profile-baseline"] },
      { id: "dca-vX-z", dependsOn: ["dca-vX-a", "dca-vX-b"] },
    ],
    ["dca-vX-a", "dca-vX-b"],
  );
  validateProfileCatalogue(composed);
  assert.deepEqual(resolveProfiles(composed, ["dca-vX-z"]), {
    requestedProfiles: ["dca-vX-z"],
    resolvedProfiles: ["dca-profile-baseline", "dca-vX-a", "dca-vX-b", "dca-vX-z"],
  });
});

test("a profile with one parent and one owned duty is accepted", () => {
  const owning = tiny([{ id: "dca-vX-a", dependsOn: ["dca-profile-baseline"] }], ["dca-vX-a"]);
  assert.equal(validateProfileCatalogue(owning), owning);
});

test("the live HTML carrier profile owns publisher and client duties and a delivery selection", () => {
  const real = realCatalogue();
  const byId = new Map(real.profiles.map((/** @type {any} */ profile) => [profile.id, profile]));
  assert.deepEqual(byId.get("dca-profile-html-carrier").dependsOn, ["dca-profile-baseline"]);
  /** @param {string} role */
  const owned = (role) =>
    profileDutySummary(real, ["dca-profile-html-carrier"], role).duties.filter((id) =>
      id.startsWith("dca-profile-html-carrier/"),
    );
  assert.deepEqual(owned("publisher"), ["dca-profile-html-carrier/publisher/markup-emission"]);
  assert.deepEqual(owned("client"), ["dca-profile-html-carrier/client/markup-extraction"]);
  assert.deepEqual(owned("issuer"), []);
  assert.throws(
    () => validateSelection(real, "dca-profile-baseline", {}),
    /has no typed selection/,
  );
  const htmlDelivery = { deliveryCarrier: "html" };
  assert.deepEqual(validateSelection(real, "dca-profile-html-carrier", htmlDelivery), htmlDelivery);
  assert.deepEqual(
    validateSelection(real, "dca-profile-html-carrier", { deliveryCarrier: "both" }),
    { deliveryCarrier: "both" },
  );
  assert.throws(
    () =>
      validateSelection(real, "dca-profile-html-carrier", { deliveryCarrier: "dca-vX-carrier" }),
    /must be one of/,
  );
  // Browser origin is a browser-boundary profile, not a markup profile.
  assert.equal(
    resolveProfiles(real, ["dca-profile-browser-origin"]).resolvedProfiles.includes(
      "dca-profile-html-carrier",
    ),
    false,
  );
});

test("typed selections require their fields, admitted values, and implications", () => {
  const withSelection = {
    ...catalogue,
    selections: [
      {
        profile: "z",
        scope: "route",
        decider: "config",
        ref: "#z",
        choices: {
          supply: ["period-keys", "chain-keys"],
          relay: "boolean",
          transforms: "named-spec-list",
        },
        requires: [{ if: { supply: "chain-keys" }, then: { relay: true } }],
      },
    ],
  };
  const valid = {
    supply: "chain-keys",
    relay: true,
    transforms: [
      { name: "a", definedBy: "spec-a" },
      { name: "b", definedBy: "spec-b" },
    ],
  };
  assert.deepEqual(validateSelection(withSelection, "z", valid), valid);
  assert.throws(
    () => validateSelection(withSelection, "z", { ...valid, relay: false }),
    /requires relay=true/,
  );
  assert.throws(
    () => validateSelection(withSelection, "z", { ...valid, extra: true }),
    /unknown field extra/,
  );
  assert.throws(
    () => validateSelection(withSelection, "z", { supply: "period-keys", relay: false }),
    /missing transforms/,
  );
  assert.throws(
    () => validateSelection(withSelection, "z", { ...valid, supply: "other" }),
    /must be one of/,
  );
  assert.throws(
    () =>
      validateSelection(withSelection, "z", {
        ...valid,
        transforms: [
          { name: "a", definedBy: "spec-a" },
          { name: "a", definedBy: "spec-b" },
        ],
      }),
    /duplicate/,
  );
  assert.throws(
    () =>
      validateProfileCatalogue({
        ...withSelection,
        selections: [
          {
            ...withSelection.selections[0],
            requires: [{ if: { missing: true }, then: { relay: true } }],
          },
        ],
      }),
    /unknown field missing/,
  );
});

const spec = readFileSync(new URL("../../docs/spec--profiles.md", import.meta.url), "utf8");

function realCatalogue() {
  return JSON.parse(
    readFileSync(new URL("../../verification/profile-catalogue/v1.json", import.meta.url), "utf8"),
  );
}

/**
 * Split Markdown into heading sections, skipping fenced code. `number` is the
 * section number such as `5.1`, or null for an unnumbered heading.
 * @param {string} text
 */
function sections(text) {
  /** @type {{number: string | null, title: string, lines: string[]}[]} */
  const result = [];
  let fenced = false;
  for (const line of text.split("\n")) {
    if (line.startsWith("```")) fenced = !fenced;
    const heading = fenced ? null : line.match(/^#{1,6} (.*)$/);
    if (heading) {
      const title = heading[1].trim();
      const number = title.match(/^(\d+(?:\.\d+)*)\. /)?.[1] ?? null;
      result.push({ number, title, lines: [] });
    } else {
      result.at(-1)?.lines.push(line);
    }
  }
  return result.map(({ number, title, lines }) => ({
    number,
    title,
    body: lines.join("\n").trim().replace(/\s+/g, " "),
  }));
}

const profileName = /`(dca-profile-[a-z0-9-]+)`/g;

/**
 * The spec selects a profile by naming it in backticks on a numbered heading,
 * or, where one section defines several profiles, in that section's opening
 * sentence "The optional profiles `a` and `b` ...". A candidate section names
 * its proposal only in body prose, so it stays outside the selected set.
 * @param {string} text
 */
function selectedProfileNames(text) {
  const names = new Set();
  for (const section of sections(text)) {
    if (section.number === null) continue;
    for (const match of section.title.matchAll(profileName)) names.add(match[1]);
    const grouped = section.body.match(
      /^The optional profiles ((?:`dca-profile-[a-z0-9-]+`(?:, and |, | and )?)+) /,
    )?.[1];
    for (const match of grouped?.matchAll(profileName) ?? []) names.add(match[1]);
  }
  return names;
}

/**
 * Parse the spec's indented profile relationship tree into child -> parent.
 * @param {string} text
 */
function relationshipParents(text) {
  const tree = text.match(/The profile relationship is:\n\n```text\n([\s\S]*?)\n```/)?.[1];
  assert.ok(tree, "profile relationship tree");
  /** @type {Map<string, string>} */
  const parents = new Map();
  /** @type {{column: number, id: string}[]} */
  const stack = [];
  for (const line of tree.split("\n")) {
    const match = line.match(/\bdca-profile-[a-z0-9-]+\b/);
    if (!match || match.index === undefined) continue;
    while (stack.length > 0 && (stack.at(-1)?.column ?? 0) >= match.index) stack.pop();
    const parent = stack.at(-1);
    if (parent) parents.set(match[0], parent.id);
    stack.push({ column: match.index, id: match[0] });
  }
  return parents;
}

/**
 * Collect the fragment targets of one Markdown file: GitHub-style heading
 * slugs (lowercase, keep letters, digits, spaces, `-` and `_`, spaces become
 * `-`, a repeated slug gains `-1`, `-2`) plus every explicit `<a id="...">`.
 * @param {string} text
 */
function markdownAnchors(text) {
  const anchors = new Set();
  /** @type {Map<string, number>} */
  const seen = new Map();
  let fenced = false;
  for (const line of text.split("\n")) {
    if (line.startsWith("```")) fenced = !fenced;
    if (fenced) continue;
    for (const match of line.matchAll(/<a id="([^"]+)"/g)) anchors.add(match[1]);
    const heading = line.match(/^#{1,6} (.*)$/)?.[1];
    if (heading === undefined) continue;
    const slug = heading
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{N} _-]/gu, "")
      .replace(/ /g, "-");
    const count = seen.get(slug) ?? 0;
    seen.set(slug, count + 1);
    anchors.add(count === 0 ? slug : `${slug}-${count}`);
  }
  return anchors;
}

test("markdown anchors follow GitHub heading slugs and explicit ids", () => {
  const anchors = markdownAnchors(spec);
  assert.ok(anchors.has("51-dca-profile-chain-keys-profile"));
  assert.ok(anchors.has("12-conformance-claims"));
  assert.ok(anchors.has("11-composition-rules"));
  assert.equal(anchors.has("5-1-dca-profile-chain-keys-profile"), false);
});

test("every catalogue ref into a specification resolves to a heading or explicit id", () => {
  const real = realCatalogue();
  /** @type {{ref: string}[]} */
  const entries = [...real.profiles, ...(real.duties ?? []), ...(real.selections ?? [])];
  const refs = new Set(
    entries.map((entry) => entry.ref).filter((ref) => ref.startsWith("docs/spec--")),
  );
  assert.ok(refs.size > 0);
  /** @type {Map<string, Set<string>>} */
  const byFile = new Map();
  const unresolved = [];
  for (const ref of refs) {
    const [path, fragment, ...rest] = ref.split("#");
    if (!fragment || rest.length > 0) {
      unresolved.push(ref);
      continue;
    }
    if (!byFile.has(path)) {
      const text = readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
      byFile.set(path, markdownAnchors(text));
    }
    if (!byFile.get(path)?.has(fragment)) unresolved.push(ref);
  }
  assert.deepEqual(unresolved.sort(), []);
});

test("the catalogue names exactly the profiles the specification selects", () => {
  const real = realCatalogue();
  validateProfileCatalogue(real);
  const selected = selectedProfileNames(spec);
  const baseline = spec.match(/designates `(dca-profile-[a-z0-9-]+)` as the \*\*baseline\*\*/)?.[1];
  assert.ok(baseline && selected.has(baseline));
  assert.equal(real.baseline, baseline);
  assert.deepEqual(real.profiles.map((profile) => profile.id).sort(), [...selected].sort());

  // Section 10 names a proposal that is "not yet a DCA v1 conformance claim".
  const candidate = sections(spec).find((section) => section.title.includes("Candidate"));
  assert.ok(candidate);
  assert.match(
    candidate.body,
    /`dca-profile-html-content-map` is not yet a DCA v1 conformance claim/,
  );
  assert.equal(selected.has("dca-profile-html-content-map"), false);
  assert.equal(
    real.profiles.some((profile) => profile.id === "dca-profile-html-content-map"),
    false,
  );
});

test("catalogue dependencies follow the specification's relationship tree", () => {
  const real = realCatalogue();
  const parents = relationshipParents(
    readFileSync(new URL("../../docs/spec-profile--chain-keys.md", import.meta.url), "utf8"),
  );
  assert.match(spec, /Optional profiles resolve the baseline\s+as their dependency/);
  const byId = new Map(real.profiles.map((profile) => [profile.id, profile.dependsOn]));
  assert.deepEqual(byId.get(real.baseline), []);
  for (const [child, parent] of parents) {
    assert.ok(byId.has(child) && byId.has(parent), `${child} -> ${parent} is catalogued`);
  }
  for (const id of byId.keys()) {
    if (id === real.baseline) continue;
    assert.deepEqual(byId.get(id), [parents.get(id) ?? real.baseline], id);
  }
  assert.deepEqual(resolveProfiles(real, ["dca-profile-chain-keys"]), {
    requestedProfiles: ["dca-profile-chain-keys"],
    resolvedProfiles: ["dca-profile-baseline", "dca-profile-period-keys", "dca-profile-chain-keys"],
  });
  const client = profileDutySummary(real, ["dca-profile-chain-keys"], "client");
  assert.ok(client.duties.includes("dca-profile-baseline/client/direct-admission"));
  assert.ok(client.duties.includes("dca-profile-chain-keys/client/chain-derivation"));
  assert.ok(!client.duties.some((id) => id.startsWith("dca-profile-browser-origin/")));
  assert.throws(() => profileDutySummary(real, [], "proxy"), /unknown role/);
});

test("real selection records reject missing duties and preserve client-bound chain transport", () => {
  const real = realCatalogue();
  const chain = {
    supply: "chain-keys",
    selectedInput: "chain-keys",
    issuerInput: true,
    relay: true,
    issuerOutput: "chain-keys",
    projectedPeriodKeyAdmission: false,
    clientDerivation: true,
    responseForm: "client-bound",
  };
  assert.deepEqual(validateSelection(real, "dca-profile-chain-keys", chain), chain);
  assert.throws(
    () => validateSelection(real, "dca-profile-chain-keys", { ...chain, relay: false }),
    /requires relay=true/,
  );
  assert.throws(
    () => validateSelection(real, "dca-profile-chain-keys", { ...chain, clientDerivation: false }),
    /requires clientDerivation=true/,
  );
  assert.throws(
    () => validateSelection(real, "dca-profile-chain-keys", { ...chain, issuerOutput: "either" }),
    /must be one of/,
  );
  assert.throws(
    () =>
      validateSelection(real, "dca-profile-chain-keys", {
        ...chain,
        issuerOutput: "period-keys",
        projectedPeriodKeyAdmission: false,
        clientDerivation: false,
      }),
    /requires projectedPeriodKeyAdmission=true/,
  );
  assert.throws(
    () => validateSelection(real, "dca-profile-chain-keys", { ...chain, supply: "period-keys" }),
    /requires selectedInput=period-keys/,
  );
  assert.throws(
    () =>
      validateSelection(real, "dca-profile-chain-keys", {
        ...chain,
        selectedInput: "period-keys",
        supply: "both",
      }),
    /requires selectedInput=chain-keys/,
  );
  assert.throws(
    () =>
      validateSelection(real, "dca-profile-chain-keys", {
        ...chain,
        selectedInput: "period-keys",
      }),
    /requires selectedInput=chain-keys/,
  );
  const projectedPeriodKey = {
    ...chain,
    issuerOutput: "period-keys",
    projectedPeriodKeyAdmission: true,
    clientDerivation: false,
  };
  assert.deepEqual(
    validateSelection(real, "dca-profile-chain-keys", projectedPeriodKey),
    projectedPeriodKey,
  );
  const bothSuppliedPeriodKeysUsed = {
    ...chain,
    supply: "both",
    selectedInput: "period-keys",
    issuerInput: false,
    relay: false,
    issuerOutput: "period-keys",
    projectedPeriodKeyAdmission: false,
    clientDerivation: false,
  };
  assert.deepEqual(
    validateSelection(real, "dca-profile-chain-keys", bothSuppliedPeriodKeysUsed),
    bothSuppliedPeriodKeysUsed,
  );
  assert.throws(
    () =>
      validateSelection(real, "dca-profile-client-bound-ecdh-p256", {
        endpointMode: "fallback-permitted",
        directFallbackAccepted: false,
      }),
    /requires directFallbackAccepted=true/,
  );
  assert.throws(
    () => validateSelection(real, "dca-profile-recipient-grant-unlock", { caller: "browser" }),
    /requires profile dca-profile-browser-origin/,
  );
  assert.throws(
    () =>
      validateSelection(real, "dca-profile-recipient-grant-unlock", { caller: "browser" }, [
        "dca-profile-recipient-grant-unlock",
      ]),
    /dca-profile-browser-origin/,
  );
  assert.deepEqual(
    validateSelection(real, "dca-profile-recipient-grant-unlock", { caller: "non-browser" }),
    { caller: "non-browser" },
  );
  assert.deepEqual(
    validateSelection(real, "dca-profile-recipient-grant-unlock", { caller: "browser" }, [
      "dca-profile-recipient-grant-unlock",
      "dca-profile-browser-origin",
    ]),
    {
      caller: "browser",
    },
  );
  for (const itemRepresentation of ["unencoded", "gzip"]) {
    const selection = { itemRepresentation };
    assert.deepEqual(
      validateSelection(real, "dca-profile-content-compression", selection),
      selection,
    );
  }
  assert.throws(
    () => validateSelection(real, "dca-profile-content-compression", { itemRepresentation: "br" }),
    /must be one of/,
  );
  // A baseline client may support no codec, so the baseline has no typed selection.
  assert.throws(
    () => validateSelection(real, "dca-profile-baseline", {}),
    /has no typed selection/,
  );
});

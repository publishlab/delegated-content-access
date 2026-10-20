// @ts-check
//
// Response sections a contribution declares for client-bound wrapping. The
// issuer core collects them, refuses a response section source whose
// key-bearing members no contribution declared, and exposes the union for the
// host's `KeyDelivery`. An undeclared section would otherwise leave raw under
// a body marked client-bound.

import test from "node:test";
import assert from "node:assert/strict";

import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { settleComposedSections } from "../../../core-shared--client-issuer/responseKeys.js";
import { contentGroupsProfile } from "../referenceProfile.js";
import { RESPONSE_SECTIONS } from "../core-shared--client-issuer/request.js";

const CONFIG = {
  operatingIssuerNames: ["issuerA"],
  accessPolicy: { decide: () => ({}) },
};
const SECTION = { path: ["fakeSection"], depth: 1, keyKind: "contentKey" };

/** @param {string[]} members @param {string} [name] */
function source(members, name = "fake") {
  return {
    name,
    members,
    presented: () => false,
    respond: async () => ({}),
  };
}

test("a source's key-bearing member needs a declared section", () => {
  assert.throws(
    () =>
      createIssuerCore(CONFIG, { name: "fake", responseSectionSource: source(["fakeSection"]) }),
    { code: "bad_config", message: /fakeSection/ },
  );
  assert.throws(
    () =>
      createIssuerCore(CONFIG, {
        name: "fake",
        responseSectionSource: source(["fakeSection", "periodGeometry"]),
        responseSections: [{ ...SECTION, path: ["otherSection"] }],
      }),
    { code: "bad_config", message: /fakeSection/ },
  );
  assert.throws(
    () => createIssuerCore({ ...CONFIG, responseSectionSources: [source(["fakeSection"])] }),
    { code: "bad_config", message: /fakeSection/ },
    "a host-level source declares nothing",
  );
});

test("the core exposes the union of declared sections, settled", () => {
  const core = createIssuerCore(
    CONFIG,
    {
      name: "fake",
      responseSectionSource: source(["fakeSection", "periodGeometry"]),
      responseSections: [SECTION],
    },
    {
      name: "fake2",
      responseSectionSource: source(["periodGeometry"], "fake2"),
      responseSections: [{ path: ["otherSection", "inner"], depth: 2, keyKind: "periodKey" }],
    },
  );
  assert.deepEqual(core.responseSections, [
    SECTION,
    { path: ["otherSection", "inner"], depth: 2, keyKind: "periodKey" },
  ]);
  assert.ok(Object.isFrozen(core.responseSections));
  assert.deepEqual(createIssuerCore(CONFIG).responseSections, []);
});

test("a declared errorPath is forwarded through composition and may root a source member", () => {
  const withErrors = { ...SECTION, errorPath: ["fakeErrors", "fakeSection"] };
  const core = createIssuerCore(CONFIG, {
    name: "fake",
    responseSectionSource: source(["fakeSection", "fakeErrors"]),
    responseSections: [withErrors],
  });
  assert.deepEqual(core.responseSections, [withErrors]);
  assert.ok(Object.isFrozen(core.responseSections[0].errorPath));
  assert.throws(
    () =>
      createIssuerCore(CONFIG, {
        name: "fake",
        responseSectionSource: source(["fakeSection", "fakeErrors"]),
        responseSections: [SECTION],
      }),
    { code: "bad_config", message: /fakeErrors/ },
  );
});

test("declared sections are a list of well-formed, distinct sections", () => {
  for (const responseSections of [
    SECTION,
    [{ ...SECTION, path: ["keys"] }],
    [{ ...SECTION, depth: 0 }],
    [SECTION, SECTION],
  ])
    assert.throws(
      () =>
        createIssuerCore(CONFIG, {
          name: "fake",
          responseSectionSource: source(["fakeSection"]),
          responseSections: /** @type {any} */ (responseSections),
        }),
      { code: "bad_config" },
      JSON.stringify(responseSections),
    );
});

test("the content-groups contribution declares its response sections", () => {
  const core = createIssuerCore(
    CONFIG,
    contentGroupsProfile.issuerContribution({
      // Construction reads only the port's shape; no request reaches it here.
      chain: /** @type {any} */ (
        Object.fromEntries(
          ["settleGeometry", "coordinate", "labelAt", "familyGeneration"].map((name) => [
            name,
            () => {
              throw new Error("not called");
            },
          ]),
        )
      ),
      policy: /** @type {any} */ ({ decide: () => ({ grants: [] }) }),
    }),
  );
  assert.deepEqual(core.responseSections, settleComposedSections(RESPONSE_SECTIONS));
});

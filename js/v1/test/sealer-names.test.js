//
// Publisher entry checks for coordinates and the AAD they form. names.test.js
// covers the shared coordinate grammar itself.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { AAD_DELIMITER } from "../core-shared--client-publisher/names.js";
import { decodePayload } from "../core-shared--publisher-issuer/jwt.js";
import { Sealer } from "../core-publisher/Sealer.js";
import { Clock } from "../demo/actors/Clock.js";
import {
  ALGORITHM,
  AT,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  SIGNING_KID,
  UNLOCK_URL,
} from "../demo/scenarios/fixtures.js";
import { exactPeriodKeySupply } from "../demo/support/exactPeriodKeySupply.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../test-reference/support/keys.js";
import { refuses } from "../test-lib/helpers/refuses.js";

/** The publisher entry hazards, each already refused by the shared grammar. */
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

describe("The sealer refuses at entry", () => {
  /**
   * A sealer, with one hole in its config left open for the case under test.
   * Built here rather than taken from `demo/scenarios/world.js`: every test below
   * is about what the constructor and the two builder calls refuse, and a
   * world hands back a publisher that has already made all three.
   *
   * @param {{ issuerName?: string, periodKeySupply?: object }} [overrides]
   */
  async function sealer(overrides = {}) {
    const signing = await signingKeypair();
    const issuerKeys = await issuerKeypair();

    return new Sealer({
      origin: ORIGIN,
      clock: new Clock(AT),
      random: seededRandom(20251023),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      ...(overrides.periodKeySupply ? { periodKeySupply: overrides.periodKeySupply } : {}),
      issuers: [
        {
          issuerName: overrides.issuerName ?? ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuerKeys.publicKey,
          unlockUrl: UNLOCK_URL,
        },
      ],
    });
  }

  test("the sealer refuses a bad contentName at content()", async () => {
    const s = await sealer();
    for (const [name] of HAZARDS) {
      await refuses(
        () => s.content(name, "x", "text/html", { accessGroups: ["premium"] }),
        "bad_name",
        `contentName ${JSON.stringify(name)}`,
      );
    }
  });

  test("the sealer refuses a bad accessGroup at content()", async () => {
    const s = await sealer();
    for (const [name] of HAZARDS) {
      await refuses(
        () => s.content("bodytext", "x", "text/html", { accessGroups: ["premium", name] }),
        "bad_name",
        `accessGroup ${JSON.stringify(name)}`,
      );
    }
  });

  test("the sealer refuses content() called without an options block", async () => {
    // The options argument defaults to an empty object, so a call that left
    // it off meets the same typed `bad_config` every neighbouring misuse
    // gets, rather than a raw TypeError from destructuring `accessGroups`
    // off `undefined`. A supply is held here because that is the sealer the
    // group is required on; the direct-only sealer beside it takes the same
    // call, covered in `sealer-direct-only.test.js`.
    const cached = await sealer({ periodKeySupply: exactPeriodKeySupply() });
    await refuses(
      () => cached.content("bodytext", "x", "text/html"),
      "bad_config",
      "content() with no options block still names at least one accessGroup",
    );

    const direct = await sealer();
    assert.equal(
      direct.content("bodytext", "x", "text/html"),
      direct,
      "and no TypeError on the direct-only one",
    );
  });

  test("the sealer refuses a repeated contentName at content()", async () => {
    const s = await sealer();
    s.content("bodytext", "x", "text/html", { accessGroups: ["premium"] });
    await refuses(
      () => s.content("bodytext", "y", "text/html", { accessGroups: ["premium"] }),
      "bad_config",
      "a contentName sealed twice on one render",
    );
    // A different name is a different map key, not a duplicate.
    assert.equal(s.content("headline", "y", "text/plain", { accessGroups: ["premium"] }), s);
  });

  test("the sealer refuses a bad resourceId at resource()", async () => {
    const s = await sealer();
    for (const id of ["", "123|456"]) {
      await refuses(() => s.resource(id, {}), "bad_name", `resourceId ${JSON.stringify(id)}`);
    }
    // The examples' own digit-initial resourceId stays legal.
    assert.equal(s.resource(RESOURCE_ID, {}), s);
  });

  test("the sealer refuses resource data JSON would alter or cannot represent", async () => {
    const cyclic = { nested: {} };
    cyclic.nested.self = cyclic;
    const inherited = Object.create({ section: "politics" });
    inherited.section = "science";
    const sparse = ["one"];
    sparse[2] = "three";
    const extraArrayMember = ["one"];
    extraArrayMember.note = "JSON would omit this";
    const hiddenMember = { section: "politics" };
    Object.defineProperty(hiddenMember, "internal", { value: "JSON would omit this" });
    const symbolMember = { section: "politics" };
    symbolMember[Symbol("internal")] = "JSON would omit this";

    for (const [data, description] of [
      [null, "a top-level null"],
      [[], "a top-level array"],
      [{ nested: undefined }, "an undefined member"],
      [{ nested: () => {} }, "a function member"],
      [{ nested: Symbol("value") }, "a symbol value"],
      [{ nested: 1n }, "a bigint value"],
      [{ nested: Infinity }, "a non-finite number"],
      [cyclic, "a cycle"],
      [new Date(), "a runtime object"],
      [inherited, "a custom-prototype object"],
      [sparse, "a sparse array"],
      [extraArrayMember, "an array member JSON omits"],
      [hiddenMember, "a hidden object member"],
      [symbolMember, "a symbol-keyed member"],
    ]) {
      const s = await sealer();
      await refuses(
        () => s.resource(RESOURCE_ID, /** @type {any} */ (data)),
        "bad_config",
        description,
      );
    }
  });

  test("the sealer refuses accessors and toJSON without running publisher code", async () => {
    let getterCalls = 0;
    let toJsonCalls = 0;
    const accessor = {};
    Object.defineProperty(accessor, "section", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "politics";
      },
    });
    const withToJson = {
      section: "politics",
      toJSON() {
        toJsonCalls += 1;
        return { section: "rewritten" };
      },
    };

    for (const [data, description] of [
      [accessor, "an accessor"],
      [withToJson, "a toJSON hook"],
    ]) {
      const s = await sealer();
      await refuses(() => s.resource(RESOURCE_ID, data), "bad_config", description);
    }
    assert.equal(getterCalls, 0, "validation reads descriptors, never an accessor");
    assert.equal(toJsonCalls, 0, "validation never delegates metadata serialization");
  });

  test("the sealer accepts nested JSON metadata without sanitizing markup-looking strings", async () => {
    const data = {
      section: "</script><img src=x onerror=alert(1)>",
      note: "<!--<script>",
      state: null,
      nested: {
        values: [true, false, 4.5, null, { label: "<em>unchanged</em>" }],
      },
    };
    Object.defineProperty(data, "__proto__", {
      value: { label: "a JSON member, not an object prototype" },
      enumerable: true,
      writable: true,
      configurable: true,
    });
    const s = await sealer();

    assert.equal(s.resource(RESOURCE_ID, data), s);
    s.content("bodytext", "x", "text/html", { accessGroups: ["premium"] });
    const { dcaData } = await s.seal();

    assert.deepEqual(
      dcaData.resource.data,
      data,
      "the valid publisher JSON is neither sanitized nor coerced",
    );
    assert.deepEqual(
      Object.getOwnPropertyDescriptor(dcaData.resource.data, "__proto__")?.value,
      { label: "a JSON member, not an object prototype" },
      "the snapshot retains a safe own __proto__ member as data",
    );
    assert.equal(
      Object.getPrototypeOf(dcaData.resource.data),
      Object.prototype,
      "the member never changes the snapshot prototype",
    );
  });

  test("the sealer signs the resource data snapshot it admitted, not later caller mutation", async () => {
    const data = { section: "politics", nested: { labels: ["headline"] } };
    const s = await sealer();
    s.resource(RESOURCE_ID, data);

    // These mutations happen after the admission check. The original tree
    // has become both semantically different and no longer admissible.
    data.section = "science";
    data.nested.labels.push("late");
    data.nested.self = data;
    Object.defineProperty(data, "lateAccessor", {
      enumerable: true,
      get() {
        throw new Error("the sealer must not read this");
      },
    });
    s.content("bodytext", "x", "text/html", { accessGroups: ["premium"] });

    const { dcaData } = await s.seal();
    const admitted = {
      section: "politics",
      nested: { labels: ["headline"] },
    };
    assert.deepEqual(
      dcaData.resource.data,
      admitted,
      "the readable mirror holds the admitted snapshot",
    );
    assert.deepEqual(
      decodePayload(dcaData.resourceJWT).data,
      admitted,
      "the signed policy input holds it too",
    );
  });

  test("each seal result has independent resource metadata", async () => {
    const s = await sealer();
    s.resource(RESOURCE_ID, { section: "politics", nested: { labels: ["headline"] } });
    s.content("bodytext", "x", "text/html", { accessGroups: ["premium"] });

    const first = (await s.seal()).dcaData;
    first.resource.data.section = "science";
    first.resource.data.nested.labels.push("late");
    first.resource.data.self = first.resource.data;

    const second = (await s.seal()).dcaData;
    assert.notEqual(
      second.resource.data,
      first.resource.data,
      "returned resource trees do not alias",
    );
    assert.deepEqual(second.resource.data, {
      section: "politics",
      nested: { labels: ["headline"] },
    });
  });

  test("the sealer refuses a bad issuerName at construction", async () => {
    for (const name of ["2", "pay|wall", "", "påvegg"]) {
      await refuses(
        () => sealer({ issuerName: name }),
        "bad_name",
        `issuerName ${JSON.stringify(name)}`,
      );
    }
  });

  test("a sealed aad has exactly the fields it joins", async () => {
    const s = await sealer();
    s.resource(RESOURCE_ID, { section: "politics" });
    s.content("bodytext", "<p>x</p>", "text/html", { accessGroups: ["premium"] });

    const { dcaData } = await s.seal();
    const { aad } = dcaData.contentData.bodytext;

    assert.deepEqual(aad.split(AAD_DELIMITER), [RESOURCE_ID, "1", "bodytext"]);
  });
});

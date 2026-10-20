//
// Publisher entry checks for coordinates and the AAD they form. names.test.js
// covers the shared coordinate grammar itself.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { AAD_DELIMITER } from "../../core-shared--client-publisher/names.js";
import { decodePayload } from "../../core-shared--publisher-issuer/jwt.js";
import { Sealer } from "../../core-publisher/Sealer.js";
import { seal as sealKey } from "../../core-shared--publisher-issuer/keySealing.js";
import { decrypt } from "../../core-shared/aead.js";
import { base64urlDecode, utf8Decode, utf8Encode } from "../../core-shared/codec.js";
import { contentAadOctets } from "../support/contentAadOctets.js";
import { Clock } from "../../demo/actors/Clock.js";
import {
  ALGORITHM,
  AT,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  SIGNING_KID,
} from "../../demo/scenarios/fixtures.js";
import { randomPeriodKeySupply } from "../../demo/support/randomPeriodKeySupply.js";
import { issuerKeypair, seededRandom, signingKeypair } from "../support/keys.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";

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
   * Without a `periodKeySupply` override it is content-key-only, so the
   * items below that are about names or metadata, not wraps, name no group.
   *
   * @param {{
   *   issuerName?: string,
   *   periodKeySupply?: object,
   *   issuerSupplyPlanFor?: Function,
   *   keySealing?: any,
   * }} [overrides]
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
      ...(overrides.keySealing ? { keySealing: overrides.keySealing } : {}),
      issuerSupplyPlanFor: overrides.issuerSupplyPlanFor ?? wholeRenderIssuerSupplyPlan,
      issuers: [
        {
          issuerName: overrides.issuerName ?? ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuerKeys.publicKey,
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

  test("content() without an options block adds an ungrouped item on either sealer", async () => {
    // The options argument defaults to an empty object, so a call that left
    // it off adds an item that names no group, rather than throwing a raw
    // TypeError from destructuring `accessGroups` off `undefined`. Groups are
    // optional per item: a sealer holding a supply admits the ungrouped item
    // and seals it with no `keys` member, through its item-key route.
    const cached = await sealer({ periodKeySupply: randomPeriodKeySupply() });
    cached.resource(RESOURCE_ID, {});
    assert.equal(cached.content("bodytext", "x", "text/html"), cached);
    const { dcaData } = await cached.seal();
    assert.equal(Object.hasOwn(dcaData.contentData.bodytext, "keys"), false);
    assert.deepEqual(Object.keys(dcaData.issuerData[ISSUER_NAME].sealed.contentKeys), ["bodytext"]);

    const contentKeyOnly = await sealer();
    assert.equal(
      contentKeyOnly.content("bodytext", "x", "text/html"),
      contentKeyOnly,
      "and no TypeError on the content-key-only one",
    );
  });

  test("an item without options still fails where its route is incomplete", async () => {
    // What the old blanket rule caught still fails, per item. An ungrouped
    // item that no issuer plan selects for an item key has no route, and
    // seal() refuses it. A content-key-only sealer refuses a named group at
    // content(), because it could only drop the wraps the group asks for.
    const unrouted = await sealer({
      periodKeySupply: randomPeriodKeySupply(),
      issuerSupplyPlanFor: () => ({ contentKeyNames: [], suppliedAccessGroups: [] }),
    });
    unrouted.resource(RESOURCE_ID, {});
    unrouted.content("bodytext", "x", "text/html");
    await refuses(
      () => unrouted.seal(),
      { code: "bad_config", message: /no complete issuer route for protected content "bodytext"/ },
      "an ungrouped item that no plan gives an item key",
    );

    const contentKeyOnly = await sealer();
    await refuses(
      () => contentKeyOnly.content("bodytext", "x", "text/html", { accessGroups: ["premium"] }),
      {
        code: "bad_config",
        message: /names accessGroups, and this publisher holds no periodKeySupply/,
      },
      "a named group on a sealer with no periodKeySupply",
    );
  });

  test("the sealer refuses a repeated contentName at content()", async () => {
    const s = await sealer();
    s.content("bodytext", "x", "text/html", { accessGroups: [] });
    await refuses(
      () => s.content("bodytext", "y", "text/html", { accessGroups: [] }),
      "bad_config",
      "a contentName sealed twice on one render",
    );
    // A different name is a different map key, not a duplicate.
    assert.equal(s.content("headline", "y", "text/plain", { accessGroups: [] }), s);
  });

  test("the sealer refuses a bad resourceId at resource()", async () => {
    const s = await sealer();
    for (const id of ["", "article-\ud800"]) {
      await refuses(() => s.resource(id, {}), "bad_name", `resourceId ${JSON.stringify(id)}`);
    }
    // The examples' own digit-initial resourceId stays legal, and so does `|`:
    // no BIND grammar carries a resourceId.
    assert.equal(s.resource(RESOURCE_ID, {}), s);
    assert.equal(s.resource("123|456", {}), s);
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
    s.content("bodytext", "x", "text/html", { accessGroups: [] });
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
    s.content("bodytext", "x", "text/html", { accessGroups: [] });

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
    s.content("bodytext", "x", "text/html", { accessGroups: [] });

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

  test("content refuses a contentType or encoding no content AAD admits", async () => {
    const s = await sealer();
    s.resource(RESOURCE_ID, { section: "politics" });
    await refuses(
      () => s.content("bodytext", "<p>x</p>", "text/\ud800", { accessGroups: [] }),
      "bad_config",
      "an unpaired surrogate in contentType",
    );
    await refuses(
      () =>
        s.content(
          "sidebar",
          { bytes: utf8Encode("x"), contentType: "text/plain", contentEncodings: ["b\udc00"] },
          { accessGroups: [] },
        ),
      "bad_config",
      "an unpaired surrogate in an encoding",
    );
    // A refused item never entered the render, so the same names still seal.
    s.content("bodytext", "<p>x</p>", "text/html", { accessGroups: [] });
    assert.ok(await s.seal());
  });

  test("a sealed item carries no aad and opens under its derived transcript", async () => {
    /** @type {Record<string, Uint8Array>} */
    const itemKeys = {};
    const s = await sealer({
      keySealing: {
        /** @type {typeof sealKey} */
        async seal(keyBytes, publicKey, algorithm, options) {
          itemKeys[/** @type {string} */ (options.binding.contentName)] = Uint8Array.from(keyBytes);
          return sealKey(keyBytes, publicKey, algorithm, options);
        },
      },
    });
    s.resource(RESOURCE_ID, { section: "politics" });
    s.content("bodytext", "<p>x</p>", "text/html", { accessGroups: [] });
    s.content(
      "sidebar",
      {
        bytes: utf8Encode("layered"),
        contentType: "text/plain; charset=\u00e6",
        contentEncodings: ["br", "br"],
      },
      { accessGroups: [] },
    );

    const { dcaData, sealedContent } = JSON.parse(JSON.stringify(await s.seal()));
    assert.deepEqual(Object.keys(dcaData.contentData.bodytext), ["contentType"]);
    assert.deepEqual(Object.keys(dcaData.contentData.sidebar), ["contentType", "contentEncodings"]);
    for (const [name, text] of [
      ["bodytext", "<p>x</p>"],
      ["sidebar", "layered"],
    ]) {
      const ciphertext = base64urlDecode(sealedContent[name]);
      const nonce = new Uint8Array(12);
      const opened = await decrypt(
        itemKeys[name],
        nonce,
        ciphertext,
        contentAadOctets(dcaData, name),
      );
      assert.equal(utf8Decode(opened), text, name);
      // The former carried string no longer authenticates the item.
      const former = utf8Encode([RESOURCE_ID, "1", name].join(AAD_DELIMITER));
      await assert.rejects(decrypt(itemKeys[name], nonce, ciphertext, former), name);
    }
  });
});

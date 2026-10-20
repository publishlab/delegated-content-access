// @ts-check
//
// The publisher family generation of the fixed `dca-construction-chain-keys`
// construction, against the neutral vectors in
// `fixtures/dca-profile-chain-keys.vectors.json`.
//
// Every expected byte below comes out of that fixture. It was written from
// `spec-profile--chain-keys.md` by two implementations that never read this
// tree, and their outputs were compared byte for byte, so a test that computed
// its own expectation from `periodFamilyGeneration` would only prove the
// module agrees with itself.
//
// The fixture's `r10` (a position outside its window), `r11` (a forward
// derivation) and `r12` (a derivation across a window boundary) have no surface
// here: this handle derives from its own key-derivation secret at a validated
// label, and takes neither a caller-supplied position nor a caller-held chain
// key. Their refusal belongs to the recipient side that accepts such a chain key.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { periodKeySupplyFor } from "../core-publisher/periodKeySupplyFor.js";
import {
  MAX_POSITIONS_PER_WINDOW,
  periodFamilyGeneration,
} from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import {
  CHAIN_KEY_CONSTRUCTION_ID,
  CHAIN_KEY_BYTES,
  CHAIN_KEY_PROFILE,
  periodKeysFromChainKey,
  periodKeyFromChainKey,
  chainKeyFromChainKey,
  validateChainKeyAccessGroup,
} from "../core-shared/chainKeyConstruction.js";
import { validateAccessGroup } from "../../../core-shared/names.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { unlockThroughAdmission } from "../../../test-lib/harnesses/unlockThroughAdmission.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { AllowAllPolicy } from "../../../demo/support/AllowAllPolicy.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";

const { subtle } = globalThis.crypto;

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-profile-chain-keys.vectors.json", import.meta.url), "utf8"),
);

// The vector set states its lifecycle before a byte of it is used: a set
// without `setIdentity`, `status` and `semanticWidths` is ambiguous about which
// width it records, and this loader does not accept one.
assert.equal(VECTORS.setIdentity, CHAIN_KEY_PROFILE);
assert.equal(VECTORS.status, "canonical-16");
assert.equal(VECTORS.semanticWidths.chainKey, 16);
assert.equal(VECTORS.semanticWidths.periodKey, 16);
assert.equal(VECTORS.semanticWidths.periodKeyWrapAlgorithm, "AES-128-GCM");

const ISSUER_NAME = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const PUB = "https://www.news-site.example";
const AT = "2025-10-23T14:20:00Z";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";

/** @param {string} hex */
function bytes(hex) {
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

/** @param {string} id */
function recorded(id) {
  const found = [
    ...VECTORS.cases,
    ...VECTORS.separation,
    ...VECTORS.edges,
    ...VECTORS.rejections,
  ].find((entry) => entry.id === id);
  assert.ok(found, `the fixture records ${id}`);
  return found;
}

/**
 * @param {{ secretHex: string, chainsPerDay: number, periodMinutes: number }} vector
 * @param {object} [options]
 */
function generationFor(vector, options = {}) {
  return periodFamilyGeneration({
    keyDerivationSecret: bytes(vector.secretHex),
    geometry: { chainsPerDay: vector.chainsPerDay, periodMinutes: vector.periodMinutes },
    ...options,
  });
}

/** Independently apply the profile's Leaf HKDF to a positioned capability. */
async function periodKeyFromCapability(capability, leafInfoHex) {
  const material = await subtle.importKey("raw", capability, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: bytes(leafInfoHex),
    },
    material,
    128,
  );
  return new Uint8Array(bits);
}

describe("The chain-key publisher family generation", () => {
  test("this build derives the profile the fixture was generated for", () => {
    assert.equal(CHAIN_KEY_PROFILE, VECTORS.profile);
    assert.equal(CHAIN_KEY_CONSTRUCTION_ID, VECTORS.constructionIdentity);
    assert.equal(CHAIN_KEY_BYTES, VECTORS.semanticWidths.chainKey);
    assert.equal(MAX_POSITIONS_PER_WINDOW, 288);
  });

  test("every recorded case derives its terminal, its step, its period key and its expansion", async () => {
    for (const vector of VECTORS.cases) {
      const generation = generationFor(vector);
      const at = generation.coordinateFor(vector.label);

      assert.equal(at.windowStart, vector.windowStart, `${vector.id}: window start`);
      assert.equal(at.position, vector.position, `${vector.id}: position`);
      assert.equal(
        generation.geometry.positionsPerWindow,
        vector.N,
        `${vector.id}: positions per window`,
      );

      const terminal = await generation.chainCapability(vector.accessGroup, at.terminalT);
      assert.equal(
        terminal.position,
        vector.N - 1,
        `${vector.id}: the terminal label is the last position`,
      );
      assert.equal(
        base64urlEncode(terminal.key),
        vector.rootChainKey,
        `${vector.id}: terminal chain key`,
      );

      const expansion = await generation.expansion(vector.accessGroup, at.terminalT);
      const oneStepBack = await generation.chainCapability(
        vector.accessGroup,
        expansion[vector.N - 2].t,
      );
      assert.equal(
        base64urlEncode(oneStepBack.key),
        vector.chainKeyAfterOneStep,
        `${vector.id}: one backward step`,
      );

      assert.equal(
        base64urlEncode(await generation.periodKey(vector.accessGroup, vector.label)),
        vector.periodKey,
        `${vector.id}: period key`,
      );
      assert.deepEqual(
        expansion.map((entry) => base64urlEncode(entry.key)),
        vector.expansion,
        `${vector.id}: whole-window expansion`,
      );
    }
  });

  test("a positioned capability reaches its own period key and every earlier position in its window", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector);
    const cutoff = await generation.chainCapability(vector.accessGroup, vector.label);

    assert.equal(cutoff.position, vector.position);
    assert.equal(cutoff.windowStart, vector.windowStart);
    assert.equal(
      base64urlEncode(await periodKeyFromCapability(cutoff.key, vector.leafInfoHex)),
      vector.periodKey,
      "the returned positioned chain key independently derives its canonical period key",
    );

    const reached = await generation.expansion(vector.accessGroup, vector.label);
    assert.deepEqual(
      reached.map((entry) => entry.position),
      [...Array(vector.position + 1).keys()],
      "a cutoff expansion covers the window start through the cutoff and stops there",
    );
    assert.deepEqual(
      reached.map((entry) => base64urlEncode(entry.key)),
      vector.expansion.slice(0, vector.position + 1),
      "those period keys are the recorded ones",
    );
    assert.equal(
      base64urlEncode(reached[vector.position].key),
      base64urlEncode(await generation.periodKey(vector.accessGroup, vector.label)),
      "the period-key operation lands on the period key the positioned chain key reaches",
    );
  });

  test("the shared supplied-chain-key primitives retain the recorded period-key and linear expansion bytes", async () => {
    for (const id of ["c1", "c2"]) {
      const vector = recorded(id);
      const generation = generationFor(vector);
      const cutoff = await generation.chainCapability(vector.accessGroup, vector.label);

      assert.equal(
        base64urlEncode(
          await periodKeyFromChainKey({
            chainKey: cutoff.key,
            accessGroup: vector.accessGroup,
            t: vector.label,
            geometry: generation.geometry,
          }),
        ),
        vector.periodKey,
        `${id}: one supplied chain key projects its period key without publisher key-derivation-secret access`,
      );
      const expansion = await periodKeysFromChainKey({
        chainKey: cutoff.key,
        accessGroup: vector.accessGroup,
        suppliedT: vector.label,
        cutoffT: vector.label,
        geometry: generation.geometry,
      });
      assert.deepEqual(
        expansion.map((entry) => base64urlEncode(entry.key)),
        vector.expansion.slice(0, vector.position + 1),
        `${id}: one backward walk reaches exactly the canonical window prefix`,
      );
    }
  });

  test("supplied-chain-key projection refuses forward and cross-window movement", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector);
    const chainKey = (await generation.chainCapability(vector.accessGroup, vector.label)).key;
    for (const targetT of ["251023T1430", "251023T1145"]) {
      await assert.rejects(
        chainKeyFromChainKey({
          chainKey,
          accessGroup: vector.accessGroup,
          suppliedT: vector.label,
          targetT,
          geometry: generation.geometry,
        }),
        (/** @type {any} */ error) => error.code === "bad_config",
      );
    }
  });

  test("family, access group, geometry, window and construction separate as recorded", async () => {
    let derivedSides = 0;
    for (const vector of VECTORS.separation) {
      for (const [side, expected] of [
        ["a", vector.periodKeyA],
        ["b", vector.periodKeyB],
      ]) {
        const input = vector[side];
        if (input.construction !== CHAIN_KEY_CONSTRUCTION_ID) {
          // This module has no construction selector: one build derives
          // exactly its fixed construction. A side recorded under another
          // construction is skipped here, and the count below fails on it.
          continue;
        }
        const generation = generationFor(input);
        assert.equal(
          base64urlEncode(await generation.periodKey(input.accessGroup, input.label)),
          expected,
          `${vector.id}.${side}`,
        );
        derivedSides++;
      }
      assert.notEqual(
        vector.periodKeyA,
        vector.periodKeyB,
        `${vector.id}: one dimension moved and the bytes moved with it`,
      );
      if (vector.sameCoordinate) {
        assert.equal(
          vector.a.label,
          vector.b.label,
          `${vector.id}: separation proved at one label`,
        );
      }
    }
    assert.ok(VECTORS.separation.length > 0, "the fixture records separation rows");
    assert.equal(
      derivedSides,
      2 * VECTORS.separation.length,
      "every side of every recorded separation row was derived, none skipped",
    );
  });

  test("window edges map to the recorded window and position", () => {
    const generation = periodFamilyGeneration({
      keyDerivationSecret: new Uint8Array(32).fill(7),
      geometry: { chainsPerDay: 2, periodMinutes: 15 },
    });
    for (const edge of VECTORS.edges) {
      const at = generation.coordinateFor(edge.label);
      assert.equal(at.windowStart, edge.windowStart, `${edge.id}: window start`);
      assert.equal(at.position, edge.position, `${edge.id}: position`);
    }
  });

  test("a caller mutating what it handed in does not move an existing generation", async () => {
    const vector = recorded("c1");
    const keyDerivationSecret = bytes(vector.secretHex);
    const geometry = { chainsPerDay: vector.chainsPerDay, periodMinutes: vector.periodMinutes };
    const config = { keyDerivationSecret, geometry };
    const generation = periodFamilyGeneration(config);

    keyDerivationSecret.fill(0xff);
    geometry.chainsPerDay = 4;
    geometry.periodMinutes = 5;
    config.keyDerivationSecret = new Uint8Array(32).fill(1);

    assert.equal(
      base64urlEncode(await generation.periodKey(vector.accessGroup, vector.label)),
      vector.periodKey,
      "the generation kept the key-derivation secret and geometry it was made with",
    );
    assert.equal(generation.geometry.chainsPerDay, vector.chainsPerDay);
    assert.equal(generation.geometry.periodMinutes, vector.periodMinutes);
  });

  test("a replaced key-derivation secret makes a rival generation and leaves the old one deriving its own bytes", async () => {
    const first = recorded("c1");
    const second = recorded("c5");
    const rivals = recorded("s2");
    assert.notEqual(
      first.secretHex,
      second.secretHex,
      "the fixture rotates the key-derivation secret and nothing else",
    );

    const original = generationFor(first);
    const before = base64urlEncode(await original.periodKey(first.accessGroup, first.label));

    const replacement = generationFor(second);
    assert.equal(
      base64urlEncode(await replacement.periodKey(second.accessGroup, second.label)),
      rivals.periodKeyB,
      "the new generation answers the same coordinate with its own bytes",
    );
    assert.equal(before, rivals.periodKeyA);
    assert.equal(
      base64urlEncode(await original.periodKey(first.accessGroup, first.label)),
      rivals.periodKeyA,
      "and the old generation is unchanged by it",
    );
  });

  test("one handle keeps its access groups and its windows apart", async () => {
    const separation = recorded("s1");
    const generation = generationFor(separation.a);
    const first = await generation.periodKey(separation.a.accessGroup, separation.a.label);
    const second = await generation.periodKey(separation.b.accessGroup, separation.b.label);

    assert.equal(base64urlEncode(first), separation.periodKeyA, "the first access group");
    assert.equal(
      base64urlEncode(second),
      separation.periodKeyB,
      "the second, at the same coordinate",
    );
    assert.equal(
      base64urlEncode(await generation.periodKey(separation.a.accessGroup, separation.a.label)),
      separation.periodKeyA,
      "and the first again, unaffected by what the second retained",
    );

    const windows = recorded("s5");
    const across = generationFor(windows.a);
    assert.equal(
      base64urlEncode(await across.periodKey(windows.a.accessGroup, windows.a.label)),
      windows.periodKeyA,
    );
    assert.equal(
      base64urlEncode(await across.periodKey(windows.b.accessGroup, windows.b.label)),
      windows.periodKeyB,
    );
  });

  test("expanding a window walks it once", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector, { cache: false });
    const at = generation.coordinateFor(vector.label);

    let derivations = 0;
    const derive = globalThis.crypto.subtle.deriveBits;
    globalThis.crypto.subtle.deriveBits = function count(...args) {
      derivations += 1;
      return derive.apply(this, args);
    };
    try {
      await generation.expansion(vector.accessGroup, at.terminalT);
    } finally {
      globalThis.crypto.subtle.deriveBits = derive;
    }

    // The root, then one step per position below the terminal, then one
    // Leaf derivation per position. Deriving each period key by walking again from the
    // terminal is quadratic and is not a conforming expansion.
    assert.equal(
      derivations,
      2 * vector.N,
      `${vector.id}: root, ${vector.N - 1} steps and ${vector.N} Leaf derivations`,
    );
  });

  test("the same bytes come out with the cache off, and no caller holds a cached buffer", async () => {
    const vector = recorded("c1");
    const cached = generationFor(vector);
    const uncached = generationFor(vector, { cache: false });

    assert.deepEqual(
      (await uncached.expansion(vector.accessGroup, vector.label)).map((entry) =>
        base64urlEncode(entry.key),
      ),
      (await cached.expansion(vector.accessGroup, vector.label)).map((entry) =>
        base64urlEncode(entry.key),
      ),
      "the cache is an optimisation and not a second construction",
    );

    const key = await cached.periodKey(vector.accessGroup, vector.label);
    key.fill(0);
    assert.equal(
      base64urlEncode(await cached.periodKey(vector.accessGroup, vector.label)),
      vector.periodKey,
      "a caller that overwrites what it was handed does not corrupt the cached period key",
    );

    const capability = await cached.chainCapability(vector.accessGroup, vector.label);
    capability.key.fill(0);
    assert.equal(
      base64urlEncode((await cached.chainCapability(vector.accessGroup, vector.label)).key),
      base64urlEncode((await uncached.chainCapability(vector.accessGroup, vector.label)).key),
    );
  });

  test("the handle exposes derivation, and no key-derivation secret, buffer or generation identifier", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector);

    // `constructionProfile` is the profile this generation was selected on:
    // its name, construction identifier and chain-key width, which is what a
    // composition planning around the handle reads instead of restating them.
    assert.deepEqual(Object.keys(generation).sort(), [
      "chainCapability",
      "constructionProfile",
      "coordinateFor",
      "expansion",
      "geometry",
      "periodKey",
    ]);
    assert.equal(Object.isFrozen(generation), true);
    assert.equal(Object.isFrozen(generation.geometry), true);
    assert.deepEqual(
      Object.values(generation).filter((value) => value instanceof Uint8Array),
      [],
      "nothing on the handle is key material",
    );
  });

  test("geometry comes from the handle and is never read off a collection of labels", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector);

    // The prototype supply took its spacing from the labels on the wire.
    // This handle validates each label against the geometry it holds, so a
    // collection is not a coordinate and a label at another spacing is a
    // refusal rather than a second geometry.
    assert.throws(
      () => generation.coordinateFor(/** @type {any} */ ([vector.label, recorded("e4").label])),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
    await assert.rejects(
      generation.periodKey(vector.accessGroup, "251023T1410"),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("every recorded rejection this handle can be asked for is a typed refusal", async () => {
    const reasons = {
      r1: () =>
        periodFamilyGeneration({
          keyDerivationSecret: bytes(recorded("r1").input.secretHex),
          geometry: { chainsPerDay: 2, periodMinutes: 15 },
        }),
      r7: () =>
        periodFamilyGeneration({
          keyDerivationSecret: new Uint8Array(32).fill(7),
          geometry: { chainsPerDay: recorded("r7").input.chainsPerDay, periodMinutes: 15 },
        }),
      r8: () =>
        periodFamilyGeneration({
          keyDerivationSecret: new Uint8Array(32).fill(7),
          geometry: { chainsPerDay: 2, periodMinutes: recorded("r8").input.periodMinutes },
        }),
      r9: () =>
        periodFamilyGeneration({
          keyDerivationSecret: new Uint8Array(32).fill(7),
          geometry: { chainsPerDay: 1, periodMinutes: 1 },
        }),
    };
    for (const [id, build] of Object.entries(reasons)) {
      assert.throws(
        build,
        (/** @type {any} */ error) => {
          assert.equal(error.name, "DcaError", `${id}: typed error`);
          assert.equal(error.code, "bad_config", `${id}: ${recorded(id).reason}`);
          return true;
        },
        `${id}: ${recorded(id).reason}`,
      );
    }

    for (const id of ["r2", "r3", "r4", "r5", "r6"]) {
      const { input } = recorded(id);
      const generation = periodFamilyGeneration({
        keyDerivationSecret: new Uint8Array(32).fill(7),
        geometry: { chainsPerDay: input.chainsPerDay, periodMinutes: input.periodMinutes },
      });
      await assert.rejects(
        generation.periodKey(input.accessGroup, input.label),
        (/** @type {any} */ error) => {
          assert.equal(error.name, "DcaError", `${id}: typed error`);
          assert.equal(error.code, "bad_config", `${id}: ${recorded(id).reason}`);
          return true;
        },
        `${id}: ${recorded(id).reason}`,
      );
    }
  });

  test("a configuration name the generation does not read is refused where it arrives", () => {
    const vector = recorded("c1");
    for (const config of [
      { secret: bytes(vector.secretHex), geometry: { chainsPerDay: 2, periodMinutes: 15 } },
      {
        keyDerivationSecret: bytes(vector.secretHex),
        geometry: { chainsPerDay: 2, periodMinutes: 15 },
        periodSecret: null,
      },
      {
        keyDerivationSecret: bytes(vector.secretHex),
        geometry: { chainsPerDay: 2, periodMinutes: 15, windowMinutes: 720 },
      },
    ]) {
      assert.throws(
        () => periodFamilyGeneration(/** @type {any} */ (config)),
        (/** @type {any} */ error) => error.code === "unsupported_option",
      );
    }
    assert.throws(
      () =>
        periodFamilyGeneration(
          /** @type {any} */ ({ keyDerivationSecret: bytes(vector.secretHex) }),
        ),
      (/** @type {any} */ error) => error.code === "bad_config",
      "there is no default geometry",
    );
    assert.throws(
      () =>
        periodFamilyGeneration(
          /** @type {any} */ ({
            keyDerivationSecret: bytes(vector.secretHex),
            geometry: { chainsPerDay: 2, periodMinutes: 15 },
            constructionId: CHAIN_KEY_CONSTRUCTION_ID,
          }),
        ),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      "the fixed KDF construction is not a runtime selector",
    );
  });

  test("an access group outside the wire grammar is refused before any derivation", async () => {
    const generation = generationFor(recorded("c1"));
    for (const accessGroup of ["", "premium|1", "x".repeat(65), null]) {
      await assert.rejects(
        generation.periodKey(/** @type {any} */ (accessGroup), recorded("c1").label),
        (/** @type {any} */ error) => error.code === "bad_name",
      );
    }
  });

  test("a non-string coordinate is refused as a typed configuration error", () => {
    const generation = generationFor(recorded("c1"));
    assert.throws(
      () => generation.coordinateFor(/** @type {any} */ (1n)),
      (/** @type {any} */ error) => error.name === "DcaError" && error.code === "bad_config",
    );
  });
});

describe("The period-key-only adapter the base publisher receives", () => {
  test("it derives the canonical period key and carries nothing else", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector);
    const supply = periodKeySupplyFor(generation);

    // The narrow view carries only the base derivation operation: width is
    // fixed by v1 and no profile selector crosses this boundary.
    assert.deepEqual(Object.keys(supply), ["derive"]);
    assert.equal(supply.derive.length, 2, "the base contract is derive(accessGroup, t)");
    assert.equal(/** @type {any} */ (supply).chainKeys, undefined);
    assert.equal(/** @type {any} */ (supply).chainCapability, undefined);
    assert.equal(/** @type {any} */ (supply).expansion, undefined);
    assert.equal(
      base64urlEncode(await supply.derive(vector.accessGroup, vector.label)),
      vector.periodKey,
      "the same bytes the handle answers with",
    );
  });

  test("it is made over a generation and refuses anything else", () => {
    assert.throws(
      () => periodKeySupplyFor(/** @type {any} */ ({ derive: () => {} })),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });
});

/**
 * A base publisher, a base issuer and a base client, with the chain profile
 * nowhere in the composition: the only extension code in the render path is the
 * adapter's `derive`.
 *
 * The geometry is `2/15` with fifteen-minute base periods, so the labels base
 * writes are already the profile's fixed eleven-character form. The hourly base
 * spelling is nine characters and is not a chain grammar; teaching it one is
 * per-family render planning, not this adapter.
 */
async function baseWorld(generation) {
  const issuerKeys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const signingKeys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 1 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    period: { length: 15, slots: 2 },
    periodKeySupply: periodKeySupplyFor(generation),
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: ["premium"] });

  const rendered = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
  );

  const keyStore = {
    get(issuerName, keyId) {
      if (issuerName !== ISSUER_NAME || keyId !== KEY_ID) return undefined;
      return { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey };
    },
  };
  const publisherRegistration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    },
  ]).get(SIGNING_KID);

  const processor = new IssuerProcessor(
    new IssuerEngine({ operatingIssuerNames: [ISSUER_NAME], accessPolicy: new AllowAllPolicy() }),
    {
      periodKeyInput: true,
    },
  );
  const endpoint = new UnlockEndpoint(processor);

  return {
    page,
    unlock: (body) => unlockThroughAdmission(processor, endpoint, body, publisherRegistration),
  };
}

describe("A base publisher on the period-key adapter alone", () => {
  test("it writes periodKeys, no chain carrier, and a client relaying period keys opens the render", async () => {
    const vector = recorded("c1");
    const generation = generationFor(vector);
    const { page, unlock } = await baseWorld(generation);
    const sealed = page.issuerData[ISSUER_NAME].sealed;

    assert.deepEqual(
      Object.keys(sealed.periodKeys.premium),
      ["251023T1415", "251023T1430"],
      "the render ships the base periods of a fifteen-minute publisher, in the profile label form",
    );
    assert.equal(sealed.chainKeys, undefined, "a period-key supply emits no chain carrier");
    assert.equal(
      JSON.stringify(page).includes("chainKeys"),
      false,
      "and nothing anywhere on the page announces one",
    );

    const cache = new PeriodKeyCache();
    const client = new Client({ publisherOrigin: PUB, cache, relayPeriodKeys: true });
    const dcaData = client.parse(page);
    const request = client.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    const answer = await unlock(request);
    assert.equal(answer.status, 200);
    assert.equal(answer.body.keys.chainKeys, undefined);
    assert.deepEqual(Object.keys(answer.body.keys.periodKeys.premium), [
      "251023T1415",
      "251023T1430",
    ]);

    await client.applyResponse(dcaData, ISSUER_NAME, answer.body);
    assert.deepEqual(await client.resolve(dcaData, ["bodytext"]), {
      covered: ["bodytext"],
      missing: [],
    });
    assert.equal(
      utf8Decode(await client.decrypt(dcaData, "bodytext", client.extract(page, "bodytext"))),
      ARTICLE,
    );

    const rawSecret = bytes(vector.secretHex);
    const publicArtifacts = JSON.stringify({
      page,
      request,
      response: answer.body,
      cache: await cache.entries(),
    });
    assert.equal(publicArtifacts.includes("keyDerivationSecret"), false);
    assert.equal(publicArtifacts.includes(vector.secretHex), false);
    assert.equal(publicArtifacts.includes(base64urlEncode(rawSecret)), false);
    const cached = await cache.entries();
    assert.equal(cached.length, 2, "the response filed both selected period keys");
    assert.ok(
      cached.every(({ key }) => key instanceof Uint8Array && key.length === 16),
      "the client cache contains only delivered period keys, never the retained 32-byte input",
    );
  });

  test("the render is wrapped under the period key the neutral vectors record", async () => {
    const vector = recorded("c1");
    assert.equal(vector.label, "251023T1415", "the fixture coordinate is the render period");
    const generation = generationFor(vector);
    const { page } = await baseWorld(generation);

    // No issuer in this one. The cache is filled with the fixture bytes
    // alone, so the article opens only if the publisher wrapped its content
    // key under the recorded period key.
    const cache = new PeriodKeyCache();
    await cache.put("premium", vector.label, base64urlDecode(vector.periodKey), {
      publisher: PUB,
      issuerName: ISSUER_NAME,
    });

    const client = new Client({ publisherOrigin: PUB, cache });
    const dcaData = client.parse(page);
    assert.equal(
      utf8Decode(await client.decrypt(dcaData, "bodytext", client.extract(page, "bodytext"))),
      ARTICLE,
    );
  });
});

/**
 * The position a label sits at inside its window, computed from the window
 * start and period length the fixture itself records. The test below pins it
 * against every (label, position) pair in the fixture, so the arithmetic here
 * is answerable from the recorded bytes and never from the module under test.
 *
 * @param {{ windowStart: number, periodMinutes: number }} vector
 * @param {string} label
 */
function positionOf(vector, label) {
  const parts = /^(\d{2})(\d{2})(\d{2})T(\d{2})(\d{2})$/.exec(label);
  assert.ok(parts, `${label} is an eleven-character profile label`);
  const [, yy, mm, dd, hh, mi] = parts;
  const minutes =
    Date.UTC(2000 + Number(yy), Number(mm) - 1, Number(dd), Number(hh), Number(mi)) / 60_000;
  return (minutes - vector.windowStart) / vector.periodMinutes;
}

/**
 * The canonical period key the fixture records at a coordinate. A case's `expansion`
 * is the whole window, indexed by position, so a coordinate the case does not
 * name in `label` still has its expected bytes written down.
 *
 * @param {{ windowStart: number, periodMinutes: number, expansion: string[] }} vector
 * @param {string} label
 */
function recordedPeriodKey(vector, label) {
  const position = positionOf(vector, label);
  assert.ok(
    Number.isInteger(position) && position >= 0 && position < vector.expansion.length,
    `${label} is a coordinate this case records`,
  );
  return vector.expansion[position];
}

const TEASER = "<p>Seven votes against two, after four hours.</p>";
const FACTBOX = "<p>The harbour plan covers 41 hectares.</p>";
const SIDEBAR = "<p>What the rezoning changes, block by block.</p>";

/**
 * One render of several items across two access groups, each family generated
 * under its own geometry and its own key-derivation secret. Base carries no geometry on the
 * period-key path, so what separates the two families is invisible to it: it asks
 * `derive(accessGroup, t)` and wraps whatever comes back.
 *
 * @param {{ derive: (accessGroup: string, t: string) => Promise<Uint8Array> }} supply
 * @param {{ name: string, accessGroups: string[], value: string }[]} items
 */
async function twoFamilyRender(supply, items) {
  const issuerKeys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const signingKeys = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);

  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 2 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    period: { length: 15, slots: 2 },
    periodKeySupply: supply,
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  for (const item of items) {
    sealer.content(item.name, item.value, "text/html", { accessGroups: item.accessGroups });
  }

  const rendered = await sealer.seal();
  return JSON.parse(JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }));
}

describe("A base publisher on two period-key adapters, one per family", () => {
  test("the recorded position of every recorded label is the one this window arithmetic gives", () => {
    const labelled = [...VECTORS.cases, ...VECTORS.edges, ...VECTORS.separation].filter(
      (entry) => typeof entry.label === "string" && typeof entry.position === "number",
    );
    assert.ok(labelled.length >= 5, "the fixture records label and position together");
    for (const vector of labelled) {
      assert.equal(
        positionOf(vector, vector.label),
        vector.position,
        `${vector.id}: recorded position`,
      );
    }
  });

  test("every wrap the render writes opens under the fixture period key for its own coordinate", async () => {
    // Two cases the fixture records under one window start: a 2/15 premium
    // family and a 4/5 locked-data family. The base publisher's fifteen-
    // minute periods fall on a coordinate of both.
    const premium = recorded("c1");
    const locked = recorded("c3");
    assert.notEqual(premium.accessGroup, locked.accessGroup);
    assert.notDeepEqual(
      [premium.chainsPerDay, premium.periodMinutes],
      [locked.chainsPerDay, locked.periodMinutes],
      "the two families are generated under different geometry",
    );

    /** @type {Record<string, { derive: (accessGroup: string, t: string) => Promise<Uint8Array> }>} */
    const families = {
      [premium.accessGroup]: periodKeySupplyFor(generationFor(premium)),
      [locked.accessGroup]: periodKeySupplyFor(generationFor(locked)),
    };
    const supply = {
      derive: (/** @type {string} */ g, /** @type {string} */ t) => families[g].derive(g, t),
    };

    const items = [
      { name: "bodytext", accessGroups: [premium.accessGroup], value: ARTICLE },
      { name: "teaser", accessGroups: [premium.accessGroup], value: TEASER },
      { name: "factbox", accessGroups: [locked.accessGroup], value: FACTBOX },
      { name: "sidebar", accessGroups: [premium.accessGroup, locked.accessGroup], value: SIDEBAR },
    ];
    const page = await twoFamilyRender(supply, items);

    const planned = ["251023T1415", "251023T1430"];
    for (const item of items) {
      assert.deepEqual(
        Object.keys(page.contentData[item.name].keys),
        item.accessGroups,
        `${item.name}: wrapped under the groups it named`,
      );
      for (const accessGroup of item.accessGroups) {
        assert.deepEqual(
          page.contentData[item.name].keys[accessGroup].map((/** @type {any} */ entry) => entry.t),
          planned,
          `${item.name}/${accessGroup}: one wrap per planned coordinate`,
        );
      }
    }

    // One coordinate at a time, and no issuer anywhere. The cache holds a
    // single fixture period key, so every item of that family opens only if the
    // publisher wrapped it under the canonical period key the vectors record.
    for (const vector of [premium, locked]) {
      for (const label of planned) {
        const cache = new PeriodKeyCache();
        await cache.put(
          vector.accessGroup,
          label,
          base64urlDecode(recordedPeriodKey(vector, label)),
          {
            publisher: PUB,
            issuerName: ISSUER_NAME,
          },
        );
        const client = new Client({ publisherOrigin: PUB, cache });
        const dcaData = client.parse(page);

        for (const item of items.filter((entry) =>
          entry.accessGroups.includes(vector.accessGroup),
        )) {
          assert.equal(
            utf8Decode(await client.decrypt(dcaData, item.name, client.extract(page, item.name))),
            item.value,
            `${vector.accessGroup} at ${label}: ${item.name}`,
          );
        }
      }
    }
  });

  test("a family opens under no other family's period key at the same coordinate", async () => {
    const premium = recorded("c1");
    const locked = recorded("c3");
    const families = {
      [premium.accessGroup]: periodKeySupplyFor(generationFor(premium)),
      [locked.accessGroup]: periodKeySupplyFor(generationFor(locked)),
    };
    const supply = {
      derive: (/** @type {string} */ g, /** @type {string} */ t) => families[g].derive(g, t),
    };
    const page = await twoFamilyRender(supply, [
      { name: "bodytext", accessGroups: [premium.accessGroup], value: ARTICLE },
      { name: "factbox", accessGroups: [locked.accessGroup], value: FACTBOX },
    ]);

    // The locked-data period key, filed under premium at the same label.
    const cache = new PeriodKeyCache();
    await cache.put(
      premium.accessGroup,
      "251023T1415",
      base64urlDecode(recordedPeriodKey(locked, "251023T1415")),
      {
        publisher: PUB,
        issuerName: ISSUER_NAME,
      },
    );
    const client = new Client({ publisherOrigin: PUB, cache });
    const dcaData = client.parse(page);
    await assert.rejects(
      client.decrypt(dcaData, "bodytext", client.extract(page, "bodytext")),
      (/** @type {any} */ error) => {
        assert.equal(
          error.code,
          "no_key",
          "a period key of another family does not unwrap this one",
        );
        assert.equal(
          error.message,
          'no key opens "bodytext"',
          "the refusal names the item it could not open",
        );
        return true;
      },
    );

    // `no_key` is also what an empty cache answers, so the same page and
    // the same label with premium's own recorded period key in the cache is what
    // puts the refusal above on the period key rather than on the lookup.
    const ownCache = new PeriodKeyCache();
    await ownCache.put(
      premium.accessGroup,
      "251023T1415",
      base64urlDecode(recordedPeriodKey(premium, "251023T1415")),
      {
        publisher: PUB,
        issuerName: ISSUER_NAME,
      },
    );
    const ownClient = new Client({ publisherOrigin: PUB, cache: ownCache });
    assert.equal(
      utf8Decode(
        await ownClient.decrypt(
          ownClient.parse(page),
          "bodytext",
          ownClient.extract(page, "bodytext"),
        ),
      ),
      ARTICLE,
      "premium's own period key at that label opens the same wrap",
    );
  });
});

describe("The chain access-group gate and the base name boundary agree", () => {
  // Two implementations of one grammar: `validateChainKeyAccessGroup`
  // copies the pattern and the 64-character cap that `names.js` defines. They
  // stay separate, since the construction binds the name into its contexts
  // and says so in its own refusal, so what a test can hold is that the same
  // strings pass and the same strings fail on both sides.
  const admitted = (/** @type {() => string} */ judge) => {
    try {
      judge();
      return { ok: true, code: null };
    } catch (error) {
      return { ok: false, code: /** @type {any} */ (error).code };
    }
  };

  test("the same names are admitted, and the same ones refused with the same code", () => {
    const names = [
      "premium",
      "locked-data",
      "premium:sport",
      "a",
      "A_9",
      "Z-9:x_y",
      "a".repeat(64),
      "",
      "9lives",
      "-lead",
      "_lead",
      ":lead",
      "premium|sport",
      "premium sport",
      "premium.sport",
      "sponsor/intro",
      "a".repeat(65),
      "préemium",
      // An embedded NUL and a trailing newline: an unanchored rewrite or
      // an added `m` flag on either side separates here and nowhere else
      // in this set.
      "prem\u0000ium",
      "premium\n",
      /** @type {any} */ (null),
      /** @type {any} */ (undefined),
      /** @type {any} */ (12),
      /** @type {any} */ ({}),
      /** @type {any} */ (["premium"]),
    ];

    const verdicts = names.map((name) => {
      const base = admitted(() => validateAccessGroup(name));
      const chain = admitted(() => validateChainKeyAccessGroup(name));
      assert.equal(chain.ok, base.ok, `${JSON.stringify(name)}: admission`);
      if (!base.ok) assert.equal(chain.code, base.code, `${JSON.stringify(name)}: refusal code`);
      return base.ok;
    });

    assert.ok(verdicts.includes(true), "the set carries names both sides admit");
    assert.ok(verdicts.includes(false), "and names both sides refuse");
  });
});

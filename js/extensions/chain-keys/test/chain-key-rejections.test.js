// @ts-check
//
// The recorded rejections of `fixtures/dca-profile-chain-keys.vectors.json`,
// driven at every layer that receives the input each row describes.
//
// The publisher half drives `r1`, and drives `r2` through `r9` against its own
// generation in `period-family-generation.test.js`. It has no surface for
// `r10`, `r11` or `r12`: a generation derives from its own key-derivation
// secret at a validated label and takes neither a caller-supplied position nor
// a caller-held chain key. Those three belong to the recipients, and so do second
// consumers of `r2` through `r9`: the issuer request carrier and the client
// response carrier both take a label and a geometry pair off the wire.
//
// `r1` records a key-derivation secret. Nothing on the recipient side holds
// one, and this file does not invent a carrier for it.
//
// Expected bytes are read from the fixture. Nothing here recomputes one
// through the construction it is testing.
//
// The recorded `r12` pair is driven by the primitives table alone. The issuer
// and cache rows substitute coordinates the fixture records chain keys for, and
// they hold the same cross-window rule at those layers.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlDecode, base64urlEncode } from "../../../core-shared/codec.js";
import { seal as sealKey } from "../../../core-shared--publisher-issuer/keySealing.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import {
  CHAIN_KEY_PROFILE,
  chainKeyCoordinate,
  periodKeysFromChainKey,
  chainKeyLabelAt,
  periodKeyFromChainKey,
  chainKeyFromChainKey,
  rootChainKey,
} from "../core-shared/chainKeyConstruction.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { chainKeyResponseInput } from "../core-client/chainKeyResponseInput.js";
import { chainKeyIssuerEngine } from "../core-issuer/chainKeyIssuerEngine.js";
import { chainKeyCapabilityEncoderFor } from "../core-issuer/chainKeyCapabilityEncoder.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { chainKeyClientProfileFor, referenceChainKeyProfileFor } from "../referenceProfile.js";
import { ChainKeyCache } from "../core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { issuerBlockOf } from "../../../test-lib/helpers/inspect.js";
import { contentKeyMap } from "../../../test-reference/support/namedRecords.js";

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
const C1 = VECTORS.cases.find((/** @type {any} */ entry) => entry.id === "c1");

const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const GROUP = "premium";
const NAME = "bodytext";
const AT = "2025-10-23T14:20:00Z";
const ARTICLE = "<p>The council voted 7-2 to rezone the harbour.</p>";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const CONTEXT = Object.freeze({ publisher: PUB, ...GEOMETRY });

/** @param {string} id */
function recorded(id) {
  const found = VECTORS.rejections.find((/** @type {any} */ entry) => entry.id === id);
  assert.ok(found, `the fixture records ${id}`);
  return found;
}

/** The publisher-side row this file deliberately leaves to the generation suite. */
const PUBLISHER_ONLY = ["r1", "r7", "r8", "r9"];

/** Every row driven below, filled in as each table runs. */
const driven = new Set();

/** @param {string} id */
function drive(id) {
  driven.add(id);
  return recorded(id);
}

/** The coordinate the recorded numeric position names. */
function labelOf(input, position) {
  return chainKeyLabelAt(input.windowStart + position * input.periodMinutes);
}

describe("supplied-chain-key primitives", () => {
  // A recipient holds a positioned chain key and a coordinate, never the family
  // key-derivation secret, so these three rows are the whole of what it can be asked for.
  const rows = [
    {
      id: "r11",
      supplied: (input) => labelOf(input, input.from),
      target: (input) => labelOf(input, input.to),
      // `labelOf` spells the coordinate through the module under test.
      // The fixture records the same coordinate as `c1.label`, so the
      // row checks the driving input against the fixture as well.
      crossCheck: (input) =>
        assert.equal(
          labelOf(input, input.from),
          C1.label,
          "r11: the recorded `from` names the coordinate the fixture records for c1",
        ),
    },
    {
      id: "r12",
      supplied: (input) => input.fromLabel,
      target: (input) => input.toLabel,
    },
    {
      // The recorded position is one past the window terminal. Its minute
      // spells the first coordinate of the next window instead, so the
      // supplied chain key that names it reaches back into no earlier window.
      id: "r10",
      supplied: (input) => labelOf(input, input.position),
      target: (input) => labelOf(input, input.N - 1),
    },
  ];

  for (const row of rows) {
    test(`${row.id} is refused by every supplied-chain-key primitive that takes it`, async () => {
      const { input, reason } = drive(row.id);
      const geometry = { chainsPerDay: input.chainsPerDay, periodMinutes: input.periodMinutes };
      const chainKey = base64urlDecode(C1.rootChainKey);
      const suppliedT = row.supplied(input);
      const targetT = row.target(input);
      row.crossCheck?.(input);

      for (const [name, run] of [
        [
          "chainKeyFromChainKey",
          () =>
            chainKeyFromChainKey({
              chainKey,
              accessGroup: input.accessGroup,
              suppliedT,
              targetT,
              geometry,
            }),
        ],
        [
          "periodKeysFromChainKey",
          () =>
            periodKeysFromChainKey({
              chainKey,
              accessGroup: input.accessGroup,
              suppliedT,
              cutoffT: targetT,
              geometry,
            }),
        ],
      ]) {
        await assert.rejects(
          /** @type {() => Promise<unknown>} */ (run),
          (/** @type {any} */ error) => {
            assert.equal(error.name, "DcaError", `${row.id}: ${name} is typed`);
            assert.equal(error.code, "bad_config", `${row.id}: ${name}: ${reason}`);
            return true;
          },
          `${row.id}: ${name}: ${reason}`,
        );
      }
    });
  }

  test("r10 has no spelling: the minute past the terminal is the next window at position zero", async () => {
    const { input } = drive("r10");
    const geometry = { chainsPerDay: input.chainsPerDay, periodMinutes: input.periodMinutes };
    const beyondT = labelOf(input, input.position);

    const coordinate = chainKeyCoordinate(beyondT, geometry);
    assert.equal(coordinate.position, 0, "the label grammar cannot name a position at or past N");
    assert.notEqual(coordinate.windowStart, input.windowStart, "it names the next window instead");
    assert.equal(
      input.position,
      input.N,
      "the recorded position is the one the window has no seat for",
    );

    // And the root operation refuses that coordinate outright, so the
    // recorded position cannot enter through the terminal either.
    await assert.rejects(
      rootChainKey({
        keyDerivationSecret: new Uint8Array(32).fill(7),
        accessGroup: input.accessGroup,
        terminalT: beyondT,
        geometry,
      }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("the same primitives answer the backward direction with the recorded bytes", async () => {
    // These refusals are positional: the same primitive answers a supplied
    // chain key whose target lies backward in its own window.
    const chainKey = base64urlDecode(C1.cutoffChainKeys[C1.label]);
    assert.equal(
      base64urlEncode(
        await periodKeyFromChainKey({
          chainKey,
          accessGroup: C1.accessGroup,
          t: C1.label,
          geometry: GEOMETRY,
        }),
      ),
      C1.periodKey,
      "the chain key at the recorded coordinate projects the recorded period key",
    );
    const expansion = await periodKeysFromChainKey({
      chainKey,
      accessGroup: C1.accessGroup,
      suppliedT: C1.label,
      cutoffT: C1.label,
      geometry: GEOMETRY,
    });
    assert.deepEqual(
      expansion.map((entry) => base64urlEncode(entry.key)),
      C1.expansion.slice(0, C1.position + 1),
      "and one backward walk reaches the recorded window prefix",
    );
  });
});

/**
 * One publisher, one issuer, and the chain family the fixture records.
 */
async function world() {
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: Uint8Array.from(C1.secretHex.match(/../g), (/** @type {string} */ pair) =>
      Number.parseInt(pair, 16),
    ),
    geometry: GEOMETRY,
  });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 }),
    issuerSupplyPlanFor: (issuer, render) => ({
      ...wholeRenderIssuerSupplyPlan(issuer, render),
      periodKeyDelivery: { [GROUP]: ["chain-keys"] },
    }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ecdh-p256",
        publicKey: issuerKeys.publicKey,
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, ARTICLE, "text/html", { accessGroups: [GROUP] });
  const rendered = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
  );
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(
        {
          /** @param {string} issuerName @param {string} keyId */
          get: (issuerName, keyId) =>
            issuerName === ISSUER && keyId === KEY_ID
              ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);

  /**
   * Relay one page through a client that selected chain relay, and return the
   * request the issuer parses.
   *
   * @param {any} carried
   */
  function relay(carried) {
    const client = new Client({
      publisherOrigin: PUB,
      requestBuilderFactory: (options) => new ChainKeyRequestBuilder(options),
    });
    return parseDcaRequest(
      JSON.stringify(client.buildRequest(client.parse(carried), ISSUER, [NAME])),
    );
  }

  /**
   * Replace the supplied chain family with one member holding the fixture's
   * recorded chain key at `t`, sealed under this render's chain BIND.
   *
   * @param {string} t
   */
  async function requestCarrying(t) {
    const carried = structuredClone(page);
    const sealed = issuerBlockOf(carried, ISSUER).sealed;
    sealed.chainKeys = [
      ...sealed.chainKeys.filter((/** @type {any} */ record) => record.accessGroup !== GROUP),
      {
        accessGroup: GROUP,
        cutoff: t,
        key: await sealKey(
          base64urlDecode(C1.cutoffChainKeys[t]),
          issuerKeys.publicKey,
          "ecdh-p256",
          {
            random: new Random({ seed: 71 }),
            binding: {
              renderId: page.resource.renderId,
              accessGroup: GROUP,
              suppliedT: t,
              chainKey: true,
              ...GEOMETRY,
            },
          },
        ),
      },
    ];
    return relay(carried);
  }

  return { page, relay, requestCarrying, registration };
}

/** @param {number} futurePeriodCount */
function policyGranting(futurePeriodCount) {
  return {
    /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
    decide(claims, requested) {
      void claims;
      return {
        contentNames: requested.contentNames,
        periodGrants: requested.accessGroups.map((accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod: () => true,
        })),
      };
    },
  };
}

describe("issuer selection over one supplied member", () => {
  // The issuer never calls a supplied-chain-key primitive with an out-of-reach
  // target: it filters the members it may start from first. These two rows
  // are that filter, driven with the recorded coordinates.
  const rows = [
    {
      id: "r11",
      carried: (input) => labelOf(input, input.from),
      refusedAt: (input) => labelOf(input, input.to),
      note: "one future period past the supplied cutoff, inside its own window",
    },
    {
      id: "r12",
      carried: () => "251024T0000",
      refusedAt: () => C1.label,
      note: "a coordinate in the window before the supplied member",
    },
  ];

  for (const row of rows) {
    test(`${row.id}: a member cannot be walked to ${row.note}`, async () => {
      const { input } = drive(row.id);
      const { requestCarrying, registration } = await world();
      const carriedT = row.carried(input);
      const refusedT = row.refusedAt(input);
      const request = await requestCarrying(carriedT);
      const engine = chainKeyIssuerEngine({
        operatingIssuerNames: [ISSUER],
        accessPolicy: policyGranting(1),
        representation: "chain-keys",
      });
      const instantOf = (/** @type {string} */ t) => {
        const at = chainKeyCoordinate(t, GEOMETRY);
        return { capturedAtMs: (at.windowStart + at.position * GEOMETRY.periodMinutes) * 60_000 };
      };

      const refused = await engine.unlock(request, registration, {}, instantOf(refusedT));
      assert.deepEqual(
        refused.capabilities.map((entry) => entry.entries),
        row.id === "r11" ? [[{ t: carriedT, key: C1.cutoffChainKeys[carriedT] }]] : [],
        `${row.id}: the explicit article target is served only when its supplied source reaches it`,
      );
      assert.deepEqual(refused.periodKeys, [], `${row.id}: and no period key leaks the same reach`);
      assert.deepEqual(
        Object.keys(contentKeyMap(refused.contentKeys)),
        [NAME],
        "the request itself is answered; only the unreachable period is declined",
      );

      const answered = await engine.unlock(request, registration, {}, instantOf(carriedT));
      assert.equal(answered.capabilities.length, 1);
      assert.deepEqual(
        answered.capabilities[0].entries,
        [{ t: carriedT, key: C1.cutoffChainKeys[carriedT] }],
        "the same member answers its own coordinate with the recorded chain key",
      );
    });
  }
});

describe("client cache over one filed cutoff", () => {
  const rows = [
    {
      id: "r11",
      filed: (input) => labelOf(input, input.from),
      chainKey: (input) => C1.cutoffChainKeys[labelOf(input, input.from)],
      refusedAt: (input) => labelOf(input, input.to),
      answered: ["251023T1400", 8],
    },
    {
      id: "r12",
      filed: () => "251023T2345",
      chainKey: () => C1.rootChainKey,
      refusedAt: (input) => input.toLabel,
      answered: ["251023T1200", 0],
    },
  ];

  for (const row of rows) {
    test(`${row.id}: a filed cutoff answers nothing at the refused coordinate`, async () => {
      const { input, reason } = drive(row.id);
      const cache = new ChainKeyCache();
      const filedT = row.filed(input);
      await cache.put(GROUP, filedT, base64urlDecode(row.chainKey(input)), CONTEXT);

      assert.deepEqual(
        await cache.candidates(GROUP, row.refusedAt(input), CONTEXT),
        [],
        `${row.id}: ${reason}`,
      );

      const [answeredT, position] = row.answered;
      assert.deepEqual(
        (await cache.candidates(GROUP, /** @type {string} */ (answeredT), CONTEXT)).map(
          base64urlEncode,
        ),
        [C1.expansion[position]],
        `${row.id}: while the backward direction answers the recorded period key`,
      );
    });
  }

  // The pending-lease path is a branch of its own with its own condition, and
  // that condition names both the window and the position. One row drives
  // each half.
  const leaseRows = [
    {
      id: "r11",
      filed: (input) => labelOf(input, input.from),
      refusedAt: (input) => labelOf(input, input.to),
      answered: () => C1.periodKey,
      note: "one period past the filed cutoff, inside its own window",
    },
    {
      id: "r12",
      filed: () => "251023T2345",
      refusedAt: (input) => input.toLabel,
      answered: () => C1.expansion[C1.N - 1],
      note: "a coordinate in the window before the filed cutoff",
    },
  ];

  for (const row of leaseRows) {
    test(`${row.id}: a response-private cutoff is filtered on the lease it was filed under`, async () => {
      const { input, reason } = drive(row.id);
      const cache = new ChainKeyCache();
      const lease = {};
      const filedT = row.filed(input);
      await cache.put(GROUP, filedT, base64urlDecode(C1.cutoffChainKeys[filedT]), {
        ...CONTEXT,
        lease,
      });

      assert.deepEqual(
        await cache.candidates(GROUP, row.refusedAt(input), { ...CONTEXT, lease }),
        [],
        `${row.id}: ${reason} on the pending path too, at ${row.note}`,
      );
      assert.deepEqual(
        (await cache.candidates(GROUP, filedT, { ...CONTEXT, lease })).map(base64urlEncode),
        [row.answered()],
        `${row.id}: while the same lease answers the coordinate it was filed at`,
      );
    });
  }
});

describe("wire carriers on the shared geometry pair", () => {
  for (const id of ["r2", "r3", "r4", "r5", "r6"]) {
    test(`${id} rejects only the malformed issuer member`, () => {
      const { input, reason } = drive(id);
      const request = new DcaRequest({
        version: "1",
        issuerName: ISSUER,
        periodGeometry: GEOMETRY,
        sealed: {
          chainKeys: [
            {
              accessGroup: input.accessGroup,
              cutoff: input.label ?? C1.label,
              key: "sealed-value",
            },
            { accessGroup: "archive", cutoff: C1.label, key: "sealed-value" },
          ],
        },
      });
      const resolved = chainKeyRequestInput(request);
      assert.equal(resolved.family(input.accessGroup).kind, "valid", `${id}: ${reason}`);
      assert.deepEqual(resolved.family(input.accessGroup).members, []);
      assert.equal(resolved.family("archive").kind, "valid");
    });

    test(`${id} rejects only the malformed response member`, () => {
      const { input, reason } = drive(id);
      const response = {
        periodGeometry: GEOMETRY,
        keys: {
          chainKeys: [
            {
              accessGroup: input.accessGroup,
              cutoff: input.label ?? C1.label,
              key: C1.rootChainKey,
            },
            { accessGroup: "archive", cutoff: C1.label, key: C1.rootChainKey },
          ],
        },
      };
      const resolved = chainKeyResponseInput(response, { periodGeometry: GEOMETRY });
      assert.equal(resolved.family(input.accessGroup).kind, "valid", `${id}: ${reason}`);
      assert.deepEqual(resolved.family(input.accessGroup).members, []);
      assert.equal(resolved.family("archive").kind, "valid");
    });
  }
});

describe("a present malformed document-wide accessGroups map", () => {
  // The scopes differ by carrier. In a delivery, a rejected `accessGroups`
  // map supplies no geometry to any chain family, and the valid document pair
  // beside it restores none (`docs/spec-profile--chain-keys.md` Section 12.1 (#document-member)), so a
  // relay sends no chain member for that delivery. In a request, the same
  // malformed named map is a whole-request admission failure under the core
  // request rule. In a response, the family stays invalid. The resolver
  // refuses every map that is not a non-array object in one test, so one value
  // stands for all of them; like null, an array passes a plain `typeof` check.
  const MALFORMED = [];

  test("the client relays no chain member and the issuer rejects the malformed named map", async () => {
    const { page, relay } = await world();
    const carrying = (/** @type {object} */ geometry) => {
      const carried = structuredClone(page);
      carried.periodGeometry = geometry;
      return relay(carried);
    };

    const valid = carrying({ ...GEOMETRY });
    const control = chainKeyRequestInput(valid).family(GROUP);
    assert.equal(control.kind, "valid", "the document pair alone resolves the supplied family");

    const relayed = carrying({ ...GEOMETRY, accessGroups: MALFORMED }).toObject();
    assert.equal(Object.hasOwn(relayed, "periodGeometry"), false, "the relay forwards no map");
    assert.equal(Object.hasOwn(relayed.sealed, "chainKeys"), false, "nor any chain family");
    assert.deepEqual(relayed.sealed.contentKeys, valid.toObject().sealed.contentKeys);

    const sent = valid.toObject();
    sent.periodGeometry = { ...GEOMETRY, accessGroups: MALFORMED };
    assert.throws(
      () => chainKeyRequestInput(parseDcaRequest(JSON.stringify(sent))),
      (/** @type {any} */ error) => error.code === "binding_failed",
      "the malformed request map is refused before per-family geometry resolution",
    );
  });

  test("the client response family stays invalid with malformed captured request geometry", () => {
    const keys = { chainKeys: [{ accessGroup: GROUP, cutoff: C1.label, key: C1.rootChainKey }] };

    const control = chainKeyResponseInput({ keys }, { periodGeometry: { ...GEOMETRY } }).family(
      GROUP,
    );
    assert.equal(control.kind, "valid", "the document pair alone resolves the returned family");

    assert.deepEqual(
      chainKeyResponseInput(
        { keys },
        { periodGeometry: { ...GEOMETRY, accessGroups: MALFORMED } },
      ).family(GROUP),
      { kind: "invalid" },
      "the response family recovers no geometry from malformed captured request context",
    );
  });
});

test("every recorded rejection is driven at a layer that receives it", () => {
  assert.deepEqual(
    [...driven, ...PUBLISHER_ONLY].sort(),
    VECTORS.rejections.map((/** @type {any} */ entry) => entry.id).sort(),
    "a row added to the fixture needs a consumer here or a stated publisher-only reason",
  );
});

test("the response encoder admits two positioned members and refuses a third", () => {
  const encoder = chainKeyCapabilityEncoderFor();
  const labels = ["251023T1145", "251023T2345", "251024T1145"];
  const recordFor = (/** @type {string[]} */ selected) => ({
    kind: "chain-keys",
    accessGroup: "premium",
    entries: selected.map((t) => ({ t, key: base64urlEncode(new Uint8Array(16).fill(3)) })),
    interpretation: {
      geometry: GEOMETRY,
      selections: selected.map((t) => ({ suppliedT: t, cutoffT: t })),
    },
  });

  assert.equal(encoder(recordFor(labels.slice(0, 2))).entries.length, 2);
  assert.throws(
    () => encoder(recordFor(labels)),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && /bounded resolved selections/.test(error.message),
  );
});

test("an unknown construction name is refused at every seam that composes one", () => {
  // Each of these names the construction its route or its store is on. A name
  // this build does not carry has no width and no derivations, so it is
  // refused where the composition is made rather than falling back to either
  // profile at the first request.
  for (const unknown of [
    "dca-construction-chain-keys-24",
    "dca-construction-chain-keys-invented",
  ]) {
    const composed = [
      [
        "a family generation",
        () =>
          periodFamilyGeneration({
            keyDerivationSecret: new Uint8Array(32).fill(7),
            geometry: GEOMETRY,
            construction: unknown,
          }),
      ],
      ["an issuer capability source", () => chainKeyCapabilitySource({ construction: unknown })],
      ["a capability encoder", () => chainKeyCapabilityEncoderFor(unknown)],
      [
        "an issuer route",
        () =>
          chainKeyIssuerEngine({
            operatingIssuerNames: [ISSUER],
            accessPolicy: policyGranting(1),
            representation: "chain-keys",
            construction: unknown,
          }),
      ],
      ["a client cache", () => new ChainKeyCache({ construction: unknown })],
      ["a client bundle", () => chainKeyClientProfileFor(unknown)],
      ["a whole reference composition", () => referenceChainKeyProfileFor(unknown)],
    ];

    for (const [label, compose] of composed) {
      assert.throws(
        /** @type {() => void} */ (compose),
        (/** @type {any} */ error) => error.code === "unsupported_option",
        `${label} refuses the unknown construction ${unknown}`,
      );
    }
  }
});

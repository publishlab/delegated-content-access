// @ts-check
//
// The recorded rejections of `fixtures/dca-period-chain-v1.vectors.json`,
// driven at every layer that receives the input each row describes.
//
// The publisher half drives `r1`, and drives `r2` through `r9` against its own
// generation in `period-family-generation.test.js`. It has no surface for
// `r10`, `r11` or `r12`: a generation derives from its own key-derivation
// secret at a validated label and takes neither a caller-supplied position nor
// a caller-held state. Those three belong to the recipients, and so do second
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
// and cache rows substitute coordinates the fixture records states for, and
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
  periodChainCoordinate,
  periodChainExpansionFromState,
  periodChainLabelAt,
  periodChainLeafFromState,
  periodChainStateFromState,
  periodChainTerminalState,
} from "../core-shared/periodChainConstruction.js";
import { periodChainRequestInput } from "../core-issuer/periodChainRequestInput.js";
import { periodChainResponseInput } from "../core-client/periodChainResponseInput.js";
import { periodChainIssuerEngine } from "../core-issuer/periodChainIssuerEngine.js";
import { periodChainCapabilityEncoderFor } from "../core-issuer/periodChainCapabilityEncoder.js";
import { periodChainCapabilitySource } from "../core-issuer/periodChainCapabilitySource.js";
import {
  periodChainClientProfileFor,
  referencePeriodChainProfileFor,
} from "../referenceProfile.js";
import { PeriodChainCache } from "../core-client/PeriodChainCache.js";
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";

const { subtle } = globalThis.crypto;

const VECTORS = JSON.parse(
  readFileSync(new URL("./fixtures/dca-period-chain-v1.vectors.json", import.meta.url), "utf8"),
);

// The vector set states its lifecycle before a byte of it is used: a set
// without `setIdentity`, `status` and `semanticWidths` is ambiguous about which
// width it records, and this loader does not accept one.
assert.equal(VECTORS.setIdentity, "dca-period-chain-v1");
assert.equal(VECTORS.status, "canonical-16");
assert.equal(VECTORS.semanticWidths.chainState, 16);
assert.equal(VECTORS.semanticWidths.exactLeaf, 16);
assert.equal(VECTORS.semanticWidths.exactWrapAlgorithm, "AES-128-GCM");
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
const PUBLISHER_ONLY = ["r1"];

/** Every row driven below, filled in as each table runs. */
const driven = new Set();

/** @param {string} id */
function drive(id) {
  driven.add(id);
  return recorded(id);
}

/** The coordinate the recorded numeric position names. */
function labelOf(input, position) {
  return periodChainLabelAt(input.windowStart + position * input.periodMinutes);
}

describe("supplied-state primitives", () => {
  // A recipient holds positioned state and a coordinate, never the family
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
      // supplied state that names it reaches back into no earlier window.
      id: "r10",
      supplied: (input) => labelOf(input, input.position),
      target: (input) => labelOf(input, input.N - 1),
    },
  ];

  for (const row of rows) {
    test(`${row.id} is refused by every supplied-state primitive that takes it`, async () => {
      const { input, reason } = drive(row.id);
      const geometry = { chainsPerDay: input.chainsPerDay, periodMinutes: input.periodMinutes };
      const state = base64urlDecode(C1.terminal);
      const suppliedT = row.supplied(input);
      const targetT = row.target(input);
      row.crossCheck?.(input);

      for (const [name, run] of [
        [
          "periodChainStateFromState",
          () =>
            periodChainStateFromState({
              state,
              accessGroup: input.accessGroup,
              suppliedT,
              targetT,
              geometry,
            }),
        ],
        [
          "periodChainExpansionFromState",
          () =>
            periodChainExpansionFromState({
              state,
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

    const coordinate = periodChainCoordinate(beyondT, geometry);
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
      periodChainTerminalState({
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
    // state whose target lies backward in its own window.
    const state = base64urlDecode(C1.cutoffStates[C1.label]);
    assert.equal(
      base64urlEncode(
        await periodChainLeafFromState({
          state,
          accessGroup: C1.accessGroup,
          t: C1.label,
          geometry: GEOMETRY,
        }),
      ),
      C1.leaf,
      "the state at the recorded coordinate projects the recorded leaf",
    );
    const expansion = await periodChainExpansionFromState({
      state,
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
    issuerSupplyPlanFor: () => ({ periodKeyDelivery: { [GROUP]: ["chain"] } }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
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
              ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);

  /**
   * Replace the supplied chain family with one member holding the fixture's
   * recorded state at `t`, sealed under this render's chain BIND.
   *
   * @param {string} t
   */
  async function requestCarrying(t) {
    const carried = structuredClone(page);
    carried.issuerData[ISSUER].sealed.periodChainKeys[GROUP] = {
      [t]: await sealKey(base64urlDecode(C1.cutoffStates[t]), issuerKeys.publicKey, "ECDH-P256", {
        random: new Random({ seed: 71 }),
        binding: {
          renderId: page.resource.renderId,
          accessGroup: GROUP,
          suppliedT: t,
          periodChain: true,
          ...GEOMETRY,
        },
      }),
    };
    const client = new Client({
      publisherOrigin: PUB,
      requestBuilderFactory: (options) => new PeriodChainRequestBuilder(options),
    });
    return parseDcaRequest(
      JSON.stringify(client.buildRequest(client.parse(carried), ISSUER, [NAME])),
    );
  }

  return { requestCarrying, registration };
}

/** @param {number} periodCount */
function policyGranting(periodCount) {
  return {
    /** @param {any} claims @param {{ contentNames: string[], accessGroups: string[] }} requested */
    decide(claims, requested) {
      void claims;
      return {
        contentNames: requested.contentNames,
        periodGrants: requested.accessGroups.map((accessGroup) => ({ accessGroup, periodCount })),
      };
    },
  };
}

describe("issuer selection over one supplied member", () => {
  // The issuer never calls a supplied-state primitive with an out-of-reach
  // target: it filters the members it may start from first. These two rows
  // are that filter, driven with the recorded coordinates.
  const rows = [
    {
      id: "r11",
      carried: (input) => labelOf(input, input.from),
      refusedAt: (input) => labelOf(input, input.to),
      note: "one period past the supplied cutoff, inside its own window",
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
      const { input, reason } = drive(row.id);
      const { requestCarrying, registration } = await world();
      const carriedT = row.carried(input);
      const refusedT = row.refusedAt(input);
      const request = await requestCarrying(carriedT);
      const engine = periodChainIssuerEngine({
        accessPolicy: policyGranting(1),
        representation: "chain",
      });
      const instantOf = (/** @type {string} */ t) => {
        const at = periodChainCoordinate(t, GEOMETRY);
        return { capturedAtMs: (at.windowStart + at.position * GEOMETRY.periodMinutes) * 60_000 };
      };

      const refused = await engine.unlock(request, registration, {}, instantOf(refusedT));
      assert.deepEqual(refused.capabilities, [], `${row.id}: ${reason}`);
      assert.deepEqual(refused.periodKeys, {}, `${row.id}: and no exact leaf leaks the same reach`);
      assert.deepEqual(
        Object.keys(refused.contentKeys),
        [NAME],
        "the request itself is answered; only the unreachable period is declined",
      );

      const answered = await engine.unlock(request, registration, {}, instantOf(carriedT));
      assert.equal(answered.capabilities.length, 1);
      assert.deepEqual(
        answered.capabilities[0].entries,
        { [carriedT]: C1.cutoffStates[carriedT] },
        "the same member answers its own coordinate with the recorded state",
      );
    });
  }
});

describe("client cache over one filed cutoff", () => {
  const rows = [
    {
      id: "r11",
      filed: (input) => labelOf(input, input.from),
      state: (input) => C1.cutoffStates[labelOf(input, input.from)],
      refusedAt: (input) => labelOf(input, input.to),
      answered: ["251023T1400", 8],
    },
    {
      id: "r12",
      filed: () => "251023T2345",
      state: () => C1.terminal,
      refusedAt: (input) => input.toLabel,
      answered: ["251023T1200", 0],
    },
  ];

  for (const row of rows) {
    test(`${row.id}: a filed cutoff answers nothing at the refused coordinate`, async () => {
      const { input, reason } = drive(row.id);
      const cache = new PeriodChainCache();
      const filedT = row.filed(input);
      await cache.put(GROUP, filedT, base64urlDecode(row.state(input)), CONTEXT);

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
        `${row.id}: while the backward direction answers the recorded leaf`,
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
      answered: () => C1.leaf,
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
      const cache = new PeriodChainCache();
      const lease = {};
      const filedT = row.filed(input);
      await cache.put(GROUP, filedT, base64urlDecode(C1.cutoffStates[filedT]), {
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

describe("wire carriers that resolve a label and a geometry pair", () => {
  // Both untrusted carriers take the same two inputs the publisher takes, so
  // r2 through r9 reach them as well. A family that cannot be resolved is
  // invalid rather than absent, and it never borrows a sibling's geometry.
  const LABELS = ["r2", "r3", "r4", "r5", "r6"];
  const GEOMETRIES = ["r7", "r8", "r9"];

  /** @param {any} input */
  function pairOf(input) {
    return { chainsPerDay: input.chainsPerDay, periodMinutes: input.periodMinutes };
  }

  for (const id of [...LABELS, ...GEOMETRIES]) {
    test(`${id} makes the issuer request family invalid without touching its sibling`, () => {
      const { input, reason } = drive(id);
      const group = input.accessGroup;
      const label = input.label ?? C1.label;
      const request = new DcaRequest({
        version: "1",
        issuerName: ISSUER,
        periodChain: {
          ...GEOMETRY,
          accessGroups: { [group]: pairOf(input) },
        },
        sealed: {
          periodChainKeys: {
            [group]: { [label]: "sealed-value" },
            archive: { [C1.label]: "sealed-value" },
          },
        },
      });

      const input_ = periodChainRequestInput(request);
      assert.equal(input_.family(group).kind, "invalid", `${id}: ${reason}`);
      assert.equal(
        input_.family("archive").kind,
        "valid",
        `${id}: the sibling family resolves its own document-wide pair`,
      );
    });

    test(`${id} makes the client response family invalid without touching its sibling`, () => {
      const { input, reason } = drive(id);
      const group = input.accessGroup;
      const label = input.label ?? C1.label;
      const response = {
        keys: {
          periodChainKeys: {
            [group]: { [label]: C1.terminal },
            archive: { [C1.label]: C1.terminal },
          },
        },
        periodChain: {
          ...GEOMETRY,
          accessGroups: { [group]: pairOf(input) },
        },
      };

      const resolved = periodChainResponseInput(response);
      assert.equal(resolved.family(group).kind, "invalid", `${id}: ${reason}`);
      assert.equal(
        resolved.family("archive").kind,
        "valid",
        `${id}: the sibling family resolves its own document-wide pair`,
      );
    });
  }
});

test("every recorded rejection is driven at a layer that receives it", () => {
  assert.deepEqual(
    [...driven, ...PUBLISHER_ONLY].sort(),
    VECTORS.rejections.map((/** @type {any} */ entry) => entry.id).sort(),
    "a row added to the fixture needs a consumer here or a stated publisher-only reason",
  );
});

test("the response encoder admits two positioned members and refuses a third", () => {
  const encoder = periodChainCapabilityEncoderFor();
  const labels = ["251023T1145", "251023T2345", "251024T1145"];
  const recordFor = (/** @type {string[]} */ selected) => ({
    kind: "period-chain",
    accessGroup: "premium",
    entries: Object.fromEntries(
      selected.map((t) => [t, base64urlEncode(new Uint8Array(16).fill(3))]),
    ),
    interpretation: {
      geometry: GEOMETRY,
      selections: selected.map((t) => ({ suppliedT: t, cutoffT: t })),
    },
  });

  assert.equal(Object.keys(encoder(recordFor(labels.slice(0, 2))).entries).length, 2);
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
  const unknown = "dca-period-chain-24-v1";
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
    ["an issuer capability source", () => periodChainCapabilitySource({ construction: unknown })],
    ["a capability encoder", () => periodChainCapabilityEncoderFor(unknown)],
    [
      "an issuer route",
      () =>
        periodChainIssuerEngine({
          accessPolicy: policyGranting(1),
          representation: "chain",
          construction: unknown,
        }),
    ],
    ["a client cache", () => new PeriodChainCache({ construction: unknown })],
    ["a client bundle", () => periodChainClientProfileFor(unknown)],
    ["a whole reference composition", () => referencePeriodChainProfileFor(unknown)],
  ];

  for (const [label, compose] of composed) {
    assert.throws(
      /** @type {() => void} */ (compose),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      `${label} refuses an unknown construction`,
    );
  }
});

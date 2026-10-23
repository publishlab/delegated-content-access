// @ts-check
//
// The request and the response carry the same chain collection under different
// member names, so the Capability collection rule in
// spec-profile--chain-keys.md holds on both sides.
// These cases fix the two readings that had drifted apart and the count of
// times each carrier is read.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { DcaRequest, parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { ChainKeyRequestBuilder } from "../core-client/ChainKeyRequestBuilder.js";
import { chainKeyResponseInput } from "../core-client/chainKeyResponseInput.js";
import { chainKeyCarrierReader } from "../core-shared--client-issuer/chainKeyCarrierReader.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { requireChainRepresentation } from "../core-issuer/chainKeyIssuerEngine.js";
import { chainKeyRequestInput } from "../core-issuer/chainKeyRequestInput.js";
import { periodFamilyGeneration } from "../core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import { explicitChainKeyClientProfile } from "../referenceProfile.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { periodKeyMap } from "../../../test-reference/support/namedRecords.js";
import { chainKeyRecords } from "./world.js";

const GROUP = "premium";
const OTHER = "archive";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const EARLY_T = "251023T1145";
const LATE_T = "251023T2345";
const CHAIN_KEY = base64urlEncode(new Uint8Array(16).fill(3));
const RIVAL_KEY = base64urlEncode(new Uint8Array(16).fill(4));

/**
 * Families in which no record holds a string cutoff. Their collection remains
 * admitted while none of the malformed labels names a source coordinate.
 */
const NO_CUTOFF_FAMILIES = Object.freeze([
  [{ accessGroup: GROUP }],
  [{ accessGroup: GROUP, key: CHAIN_KEY }],
  [{ accessGroup: GROUP, cutoff: null, key: CHAIN_KEY }],
  [{ accessGroup: GROUP, cutoff: 7, key: CHAIN_KEY }],
  [{ accessGroup: GROUP, cutoff: [LATE_T], key: CHAIN_KEY }],
]);

function associated(page, request) {
  return new ResponseAssociation(page, ISSUER, {
    version: page.version,
    issuerName: ISSUER,
    resourceJWT: page.resourceJWT,
    keyId: page.keyIdFor(ISSUER),
    ...request,
  });
}

/** @param {unknown} collection @param {unknown} geometry @param {unknown} requestedPeriodKeys */
function requestCarrier(collection, geometry = GEOMETRY, requestedPeriodKeys) {
  return new DcaRequest({
    version: "dca/1",
    issuerName: "issuer.example",
    sealed: { contentKeys: [], chainKeys: collection },
    periodGeometry: geometry,
    ...(requestedPeriodKeys === undefined ? {} : { requestedPeriodKeys }),
  });
}

/** @param {unknown} collection @param {unknown} geometry */
function responseCarrier(collection, geometry = GEOMETRY) {
  return { keys: { chainKeys: collection }, periodGeometry: geometry };
}

/**
 * Each carrier's own vocabulary over the one reading. `sharedRead` enters the
 * reader with the container the wrapper would have handed it, so one case can
 * state a rule that holds on both sides even for a collection the request
 * wrapper refuses outright: the issuer decides request admission of the
 * collection itself, and `carrier-corrections.test.js` holds that.
 */
const CARRIERS = [
  {
    carrier: "request",
    valueName: "sealed",
    read: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyRequestInput(requestCarrier(collection, geometry)),
    sharedRead: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyCarrierReader({
        container: { contentKeys: [], chainKeys: collection },
        context: geometry,
        valueName: "sealed",
      }),
  },
  {
    carrier: "response",
    valueName: "value",
    read: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyResponseInput(responseCarrier(collection), { periodGeometry: geometry }),
    sharedRead: (/** @type {unknown} */ collection, /** @type {unknown} */ geometry = GEOMETRY) =>
      chainKeyCarrierReader({
        container: { chainKeys: collection },
        context: geometry,
        valueName: "value",
      }),
  },
];

/** @param {Record<string, string[]>} table one `{accessGroup, periods}` record per group */
function hintRecords(table) {
  return Object.entries(table).map(([accessGroup, periods]) => ({ accessGroup, periods }));
}

/** One valid premium source member, the family the hints below are checked against. */
const PREMIUM_SOURCE = chainKeyRecords({ premium: { "251023T1415": CHAIN_KEY } });

test("requestedPeriodKeys normalizes order and duplicates without presenting hint-only groups", () => {
  const input = chainKeyRequestInput(
    requestCarrier(PREMIUM_SOURCE, GEOMETRY, [
      {
        accessGroup: "premium",
        periods: ["251023T1415", "251023T1200", "251023T1415", "251023T1400"],
      },
      { accessGroup: "absent", periods: ["251023T1000"] },
    ]),
  );
  assert.deepEqual(input.requestedPeriodKeys, {
    premium: ["251023T1200", "251023T1400", "251023T1415"],
    absent: ["251023T1000"],
  });
  assert.deepEqual(input.presented, ["premium"]);
  assert.equal(input.family("absent").kind, "absent");
});

test("requestedPeriodKeys checks raw bounds and grid before source selection", () => {
  const duplicated = Array(289).fill("251023T1415");
  assert.throws(
    () =>
      chainKeyRequestInput(
        requestCarrier(PREMIUM_SOURCE, GEOMETRY, hintRecords({ premium: duplicated })),
      ),
    (/** @type {any} */ error) => error.code === "binding_failed",
  );

  assert.throws(
    () =>
      chainKeyRequestInput(
        requestCarrier(
          PREMIUM_SOURCE,
          GEOMETRY,
          hintRecords({ premium: ["251023T1415", "251023T1410"] }),
        ),
      ),
    (/** @type {any} */ error) => error.code === "binding_failed",
    "a label off the admitted family grid is a request-structure failure",
  );

  const exactlyBounded = chainKeyRequestInput(
    requestCarrier(
      PREMIUM_SOURCE,
      GEOMETRY,
      hintRecords({
        premium: Array(288).fill("251023T1415"),
        archive: Array(224).fill("251023T1400"),
      }),
    ),
  );
  assert.deepEqual(exactlyBounded.requestedPeriodKeys, {
    premium: ["251023T1415"],
    archive: ["251023T1400"],
  });
  assert.throws(
    () =>
      chainKeyRequestInput(
        requestCarrier(
          PREMIUM_SOURCE,
          GEOMETRY,
          hintRecords({
            premium: Array(288).fill("251023T1415"),
            archive: Array(225).fill("251023T1400"),
          }),
        ),
      ),
    (/** @type {any} */ error) => error.code === "binding_failed",
    "the total raw input is bounded before duplicate normalization",
  );
});

test("requestedPeriodKeys records for one group request the union of their labels", () => {
  const input = chainKeyRequestInput(
    requestCarrier(PREMIUM_SOURCE, GEOMETRY, [
      { accessGroup: "premium", periods: ["251023T1415", "251023T1200"] },
      { accessGroup: "archive", periods: ["251023T1000"] },
      { accessGroup: "premium", periods: ["251023T1400", "251023T1415"] },
    ]),
  );
  assert.deepEqual(input.requestedPeriodKeys, {
    premium: ["251023T1200", "251023T1400", "251023T1415"],
    archive: ["251023T1000"],
  });
});

test("requestedPeriodKeys counts raw labels across records toward both bounds", () => {
  /** @param {{ accessGroup: string, periods: string[] }[]} hints */
  const admit = (hints) => chainKeyRequestInput(requestCarrier(PREMIUM_SOURCE, GEOMETRY, hints));
  const refused = (/** @type {any} */ error) => error.code === "binding_failed";

  assert.deepEqual(
    admit([
      { accessGroup: "premium", periods: Array(144).fill("251023T1415") },
      { accessGroup: "premium", periods: Array(144).fill("251023T1415") },
    ]).requestedPeriodKeys,
    { premium: ["251023T1415"] },
    "288 raw labels over two records fit the family bound",
  );
  assert.throws(
    () =>
      admit([
        { accessGroup: "premium", periods: Array(144).fill("251023T1415") },
        { accessGroup: "premium", periods: Array(145).fill("251023T1415") },
      ]),
    refused,
    "289 raw labels over two records of one group exceed the family bound of 288",
  );

  const spread = [
    { accessGroup: "premium", periods: Array(200).fill("251023T1415") },
    { accessGroup: "archive", periods: Array(200).fill("251023T1400") },
    { accessGroup: "premium", periods: Array(88).fill("251023T1415") },
  ];
  assert.deepEqual(
    admit([...spread, { accessGroup: "sport", periods: Array(24).fill("251023T1400") }])
      .requestedPeriodKeys,
    { premium: ["251023T1415"], archive: ["251023T1400"], sport: ["251023T1400"] },
    "512 raw labels over four records fit the request bound",
  );
  assert.throws(
    () => admit([...spread, { accessGroup: "sport", periods: Array(25).fill("251023T1400") }]),
    refused,
    "513 raw labels over four records exceed the request bound of 512",
  );
});

test("requestedPeriodKeys in any other shape refuses the request", () => {
  const record = { accessGroup: "premium", periods: ["251023T1415"] };
  for (const [shape, hints] of /** @type {[string, unknown][]} */ ([
    ["the former group map", { premium: ["251023T1415"] }],
    ["an empty collection", []],
    ["a non-record element beside a record", [record, "251023T1415"]],
    ["a null element", [null]],
    ["an array element", [["premium", ["251023T1415"]]]],
    ["empty periods", [{ accessGroup: "premium", periods: [] }]],
    ["periods that are not an array", [{ accessGroup: "premium", periods: "251023T1415" }]],
    ["a missing accessGroup", [{ periods: ["251023T1415"] }]],
    ["a bad accessGroup", [{ accessGroup: "bad name", periods: ["251023T1415"] }]],
  ])) {
    assert.throws(
      () => chainKeyRequestInput(requestCarrier(PREMIUM_SOURCE, GEOMETRY, hints)),
      (/** @type {any} */ error) => error.code === "binding_failed",
      shape,
    );
  }
});

test("requestedPeriodKeys cannot repair an already invalid source family", () => {
  const input = chainKeyRequestInput(
    requestCarrier(
      chainKeyRecords({ premium: { "251023T1415": CHAIN_KEY, "251023T1400": CHAIN_KEY } }),
      GEOMETRY,
      hintRecords({ premium: ["251023T1415"] }),
    ),
  );
  assert.equal(input.family("premium").kind, "invalid");
  assert.deepEqual(input.requestedPeriodKeys, { premium: ["251023T1415"] });
  for (const family of [
    [
      { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
      { accessGroup: GROUP, cutoff: "251023T2330", key: CHAIN_KEY },
    ],
    Array.from({ length: 3 }, () => ({ accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY })),
  ]) {
    const failed = chainKeyRequestInput(
      requestCarrier(family, GEOMETRY, hintRecords({ [GROUP]: ["251023T1410"] })),
    );
    assert.equal(
      failed.family(GROUP).kind,
      "invalid",
      "off-grid hints do not widen family failure",
    );
  }
});

describe("one decided reading of both chain carriers", () => {
  for (const { carrier, valueName, read, sharedRead } of CARRIERS) {
    test(`${carrier}: a non-string member is dropped while valid siblings survive`, () => {
      const input = read(
        chainKeyRecords({
          [GROUP]: { [LATE_T]: { key: 7 }, [EARLY_T]: CHAIN_KEY },
          [OTHER]: { [LATE_T]: CHAIN_KEY },
        }),
      );

      assert.equal(input.family(GROUP).kind, "valid", "one malformed value costs only that member");
      assert.deepEqual(
        input.family(GROUP).members.map((/** @type {any} */ member) => member.t),
        [EARLY_T],
      );
      assert.equal(
        input.family(OTHER).kind,
        "valid",
        "a malformed family does not reach its neighbour",
      );
      assert.equal(input.family(OTHER).members[0][valueName], CHAIN_KEY);
    });

    test(`${carrier}: positioned duplicates void a family before envelope admission`, () => {
      for (const value of ["AQ==", "AQ"]) {
        const input = read(
          chainKeyRecords({
            [GROUP]: { "251023T2330": value, [LATE_T]: CHAIN_KEY },
            [OTHER]: { [LATE_T]: CHAIN_KEY },
          }),
        );
        assert.equal(input.family(GROUP).kind, "invalid");
        assert.equal(input.family(OTHER).kind, "valid");
      }
    });

    test(`${carrier}: an invalid label costs one member and keeps a valid sibling`, () => {
      const input = read(
        chainKeyRecords({
          [GROUP]: { "251023T1410": CHAIN_KEY, [EARLY_T]: CHAIN_KEY },
          [OTHER]: { [LATE_T]: CHAIN_KEY },
        }),
      );

      assert.equal(input.family(GROUP).kind, "valid");
      assert.deepEqual(
        input.family(GROUP).members.map((/** @type {any} */ member) => member.t),
        [EARLY_T],
      );
      assert.equal(input.family(OTHER).kind, "valid");
    });

    test(`${carrier}: member order follows the label, not the wire`, () => {
      const view = read([
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
        { accessGroup: GROUP, cutoff: EARLY_T, key: CHAIN_KEY },
      ]).family(GROUP);

      assert.equal(view.kind, "valid");
      assert.deepEqual(
        view.members.map((/** @type {any} */ member) => member.t),
        [EARLY_T, LATE_T],
        "wire member order changes no derived byte and decides no member order",
      );
    });

    test(`${carrier}: invalid stays distinct from absent`, () => {
      const input = read(chainKeyRecords({ [GROUP]: { [LATE_T]: CHAIN_KEY } }));

      assert.deepEqual([...input.presented], [GROUP]);
      assert.equal(input.family(GROUP).kind, "valid");
      assert.equal(
        input.family(OTHER).kind,
        "absent",
        "a family nobody presented is absent, never invalid",
      );

      for (const family of NO_CUTOFF_FAMILIES) {
        const failed = read([...family, { accessGroup: OTHER, cutoff: LATE_T, key: CHAIN_KEY }]);
        assert.deepEqual([...failed.presented], [GROUP, OTHER]);
        assert.equal(failed.family(GROUP).kind, "valid", "label failures retain member scope");
        assert.deepEqual(failed.family(GROUP).members, []);
        assert.deepEqual(failed.family(GROUP).malformedMembers, []);
        assert.equal(failed.family(OTHER).kind, "valid");
      }
      for (const collection of ["not-a-collection", null, { [GROUP]: { [LATE_T]: CHAIN_KEY } }]) {
        const malformed = sharedRead(collection);
        assert.deepEqual([...malformed.presented], []);
        assert.equal(
          malformed.family(GROUP).kind,
          "invalid",
          "a collection that is not a record array invalidates every family it could have carried",
        );
      }
    });

    test(`${carrier}: a non-record element names no family and its siblings keep their scope`, () => {
      const input = read([
        null,
        "x",
        7,
        [GROUP, EARLY_T, CHAIN_KEY],
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
        { accessGroup: OTHER, cutoff: LATE_T, key: CHAIN_KEY },
      ]);
      assert.deepEqual([...input.presented], [GROUP, OTHER]);
      assert.deepEqual(
        input.family(GROUP).members.map((/** @type {any} */ member) => member.t),
        [LATE_T],
      );
      assert.equal(input.family(OTHER).kind, "valid");

      // The request refuses a record without a string accessGroup at
      // admission, which carrier-corrections.test.js holds; the shared reader
      // underneath skips it the way it skips a non-record.
      const nameless = sharedRead([
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
        { cutoff: EARLY_T, key: CHAIN_KEY },
        { accessGroup: 7, cutoff: EARLY_T, key: CHAIN_KEY },
      ]);
      assert.deepEqual([...nameless.presented], [GROUP]);
      assert.deepEqual(
        nameless.family(GROUP).members.map((/** @type {any} */ member) => member.t),
        [LATE_T],
        "a record without a string accessGroup lends no cutoff to a family",
      );

      const skippedUncounted = sharedRead([
        ...Array.from({ length: 16 }, (_, index) => ({
          accessGroup: `g${index}`,
          cutoff: LATE_T,
          key: CHAIN_KEY,
        })),
        null,
        "x",
        [],
        { cutoff: LATE_T, key: CHAIN_KEY },
      ]);
      assert.ok(
        skippedUncounted.presented.every(
          (/** @type {string} */ accessGroup) =>
            skippedUncounted.family(accessGroup).kind === "valid",
        ),
        "skipped elements count toward no bound",
      );
    });

    for (const [order, records] of [
      [
        "first value first",
        [
          { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
          { accessGroup: GROUP, cutoff: LATE_T, key: RIVAL_KEY },
        ],
      ],
      [
        "rival value first",
        [
          { accessGroup: GROUP, cutoff: LATE_T, key: RIVAL_KEY },
          { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
        ],
      ],
    ]) {
      test(`${carrier}: rival records at one cutoff are two candidate members, ${order}`, () => {
        const view = read(records).family(GROUP);

        assert.equal(view.kind, "valid", "rivals at one cutoff hold one position");
        assert.deepEqual(
          view.members.map((/** @type {any} */ member) => member.t),
          [LATE_T, LATE_T],
        );
        assert.deepEqual(
          view.members.map((/** @type {any} */ member) => member[valueName]).sort(),
          [CHAIN_KEY, RIVAL_KEY].sort(),
          "neither record overwrites the other",
        );
        assert.deepEqual(view.malformedMembers, []);
      });
    }

    test(`${carrier}: an identical duplicate record is one member`, () => {
      const view = read([
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
      ]).family(GROUP);

      assert.equal(view.kind, "valid");
      assert.deepEqual(
        view.members.map((/** @type {any} */ member) => [member.t, member[valueName]]),
        [[LATE_T, CHAIN_KEY]],
      );
    });

    test(`${carrier}: a cutoff with no valid value among its records is one malformed member`, () => {
      const allMalformed = read([
        { accessGroup: GROUP, cutoff: LATE_T, key: 7 },
        { accessGroup: GROUP, cutoff: LATE_T, key: "AQ==" },
      ]).family(GROUP);
      assert.equal(allMalformed.kind, "valid");
      assert.deepEqual(allMalformed.members, []);
      assert.deepEqual(
        allMalformed.malformedMembers.map((/** @type {any} */ member) => member.t),
        [LATE_T],
      );

      const oneValid = read([
        { accessGroup: GROUP, cutoff: LATE_T, key: 7 },
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
      ]).family(GROUP);
      assert.deepEqual(
        oneValid.members.map((/** @type {any} */ member) => member[valueName]),
        [CHAIN_KEY],
      );
      assert.deepEqual(oneValid.malformedMembers, [], "a valid rival leaves the cutoff no gap");
    });

    test(`${carrier}: rival records at two cutoffs of one window still void the family`, () => {
      const input = read([
        { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
        { accessGroup: GROUP, cutoff: LATE_T, key: RIVAL_KEY },
        { accessGroup: GROUP, cutoff: "251023T2330", key: CHAIN_KEY },
        { accessGroup: OTHER, cutoff: LATE_T, key: CHAIN_KEY },
      ]);
      assert.equal(input.family(GROUP).kind, "invalid");
      assert.equal(input.family(OTHER).kind, "valid");
    });

    test(`${carrier}: geometry resolves as a whole pair or the family fails`, () => {
      const records = chainKeyRecords({ [GROUP]: { [LATE_T]: CHAIN_KEY } });
      const partial = read(records, { chainsPerDay: 2 });
      assert.equal(
        partial.family(GROUP).kind,
        "invalid",
        "a partial root pair fails the family instead of inferring",
      );

      const reordered = read(records, { periodMinutes: 15, chainsPerDay: 2 });
      assert.deepEqual(reordered.family(GROUP).geometry, {
        chainsPerDay: 2,
        periodMinutes: 15,
        windowMinutes: 720,
        positionsPerWindow: 48,
      });

      const unresolved = read(records, null);
      assert.equal(
        unresolved.family(GROUP).kind,
        "invalid",
        "a chain-bearing family without a resolvable pair is invalid",
      );
    });

    test(`${carrier}: one window holds one member, within both bounds`, () => {
      const collision = read(
        chainKeyRecords({ [GROUP]: { [LATE_T]: CHAIN_KEY, "251023T2330": CHAIN_KEY } }),
      );
      assert.equal(
        collision.family(GROUP).kind,
        "invalid",
        "two positions from one window invalidate the family collection",
      );

      const two = ["251023T1145", "251023T2345"];
      const full = read(
        chainKeyRecords({ [GROUP]: Object.fromEntries(two.map((t) => [t, CHAIN_KEY])) }),
      );
      assert.equal(full.family(GROUP).kind, "valid");
      assert.equal(full.family(GROUP).members.length, 2);

      const overFamily = read(
        chainKeyRecords({
          [GROUP]: {
            [two[0]]: CHAIN_KEY,
            [two[1]]: CHAIN_KEY,
            "251024T1145": { malformed: true },
          },
          [OTHER]: { [LATE_T]: CHAIN_KEY },
        }),
      );
      assert.equal(overFamily.family(GROUP).kind, "invalid", "raw maxChainMembersPerFamily is 2");
      assert.equal(
        overFamily.family(OTHER).kind,
        "valid",
        "an over-limit family does not suppress its valid sibling",
      );

      const atMessageLimit = read(
        Array.from({ length: 16 }, (_, index) => ({
          accessGroup: `g${index}`,
          cutoff: LATE_T,
          key: CHAIN_KEY,
        })),
      );
      assert.ok(
        atMessageLimit.presented.every(
          (/** @type {string} */ accessGroup) =>
            atMessageLimit.family(accessGroup).kind === "valid",
        ),
        "maxChainMembersPerMessage admits 16 across all access groups",
      );

      const overMessage = read(
        Array.from({ length: 17 }, (_, index) => ({
          accessGroup: `g${index}`,
          cutoff: LATE_T,
          key: CHAIN_KEY,
        })),
      );
      assert.ok(
        overMessage.presented.every(
          (/** @type {string} */ accessGroup) => overMessage.family(accessGroup).kind === "invalid",
        ),
        "maxChainMembersPerMessage refuses the whole 17-member collection",
      );
    });

    test(`${carrier}: raw records count toward both bounds before identical copies merge`, () => {
      const copy = { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY };
      const twoCopies = read([copy, { ...copy }]);
      assert.equal(twoCopies.family(GROUP).kind, "valid", "two raw records fit the family bound");

      const threeCopies = read([copy, { ...copy }, { ...copy }]);
      assert.equal(
        threeCopies.family(GROUP).kind,
        "invalid",
        "three identical records are three raw records against MAX_CHAIN_MEMBERS_PER_FAMILY",
      );

      const copiedFamilies = (/** @type {number} */ count) =>
        Array.from({ length: count }, (_, index) => ({
          accessGroup: `g${Math.floor(index / 2)}`,
          cutoff: LATE_T,
          key: CHAIN_KEY,
        }));
      const atMessageLimit = read(copiedFamilies(16));
      assert.ok(
        atMessageLimit.presented.every(
          (/** @type {string} */ accessGroup) =>
            atMessageLimit.family(accessGroup).kind === "valid",
        ),
        "eight families of two identical records are 16 raw records",
      );
      const overMessage = read(copiedFamilies(17));
      assert.equal(overMessage.presented.length, 9, "nine distinct records after merging");
      assert.ok(
        overMessage.presented.every(
          (/** @type {string} */ accessGroup) => overMessage.family(accessGroup).kind === "invalid",
        ),
        "17 raw records exceed maxChainMembersPerMessage whatever merges",
      );
    });
  }
});

test("the response reader marks a grammar-failing family name invalid rather than absent", () => {
  const input = chainKeyResponseInput(
    responseCarrier(
      chainKeyRecords({ "bad name": { [LATE_T]: CHAIN_KEY }, [OTHER]: { [LATE_T]: CHAIN_KEY } }),
    ),
    { periodGeometry: GEOMETRY },
  );
  assert.ok(input.presented.includes("bad name"));
  assert.equal(input.family("bad name").kind, "invalid");
});

test("the response carrier leaves wrapped ciphertext spelling to transport admission", () => {
  const input = chainKeyResponseInput(
    {
      keys: { chainKeys: [{ accessGroup: GROUP, cutoff: "251023T2330", key: { key: "AQ==" } }] },
    },
    { periodGeometry: GEOMETRY },
  );

  assert.equal(input.family(GROUP).kind, "valid");
  assert.deepEqual(input.family(GROUP).members[0].value, { key: "AQ==" });
});

test("explicit local ingress capacity admits 16 chain members with ordinary base companions", () => {
  const chainGroups = chainKeyRecords(
    Object.fromEntries(
      Array.from({ length: 8 }, (_, index) => [
        `g${index}`,
        { [EARLY_T]: CHAIN_KEY, [LATE_T]: CHAIN_KEY },
      ]),
    ),
  );
  const document = JSON.stringify(
    new DcaRequest({
      version: "1",
      issuerName: "paywall",
      keyId: "2025-10",
      sealed: {
        contentKeys: [{ contentName: "bodytext", key: "sealed-content-key" }],
        periodKeys: [{ accessGroup: "ordinary", period: LATE_T, key: "sealed-period-key" }],
        chainKeys: chainGroups,
      },
      periodGeometry: GEOMETRY,
    }).toObject(),
  );
  const engine = {
    checkOperatingIssuerName() {},
    unlock: async () => ({ contentKeys: [], periodKeys: [], errors: [] }),
  };

  assert.equal(
    new IssuerProcessor(engine, {
      limits: { maxEntries: 18, maxEntriesPerGroup: 2 },
    }).admit(document).kind,
    "admitted",
    "16 chain members plus two base entries fit the provisioned cap",
  );
  assert.deepEqual(
    new IssuerProcessor(engine).admit(document),
    {
      kind: "failure",
      code: "too_many_entries",
    },
    "the stricter finite reference default may reject before the protocol maximum",
  );
});

const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const NAME = "bodytext";
const AT = "2025-10-23T14:20:00Z";

/** @param {object} payload */
function token(payload) {
  return `e30.${base64urlEncode(utf8Encode(JSON.stringify(payload)))}.c2lnbmF0dXJl`;
}

/** @param {number} futurePeriodCount */
function policy(futurePeriodCount) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          futurePeriodCount,
          authorizePeriod: () => true,
        })),
      };
    },
  };
}

/** One sealed page, its registration and a relay client, as the issuer lane builds them. */
async function world() {
  const { subtle } = globalThis.crypto;
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
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
  sealer.content(NAME, "<p>The council voted 7-2 to rezone the harbour.</p>", "text/html", {
    accessGroups: [GROUP],
  });
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
          get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
            issuerName === ISSUER && keyId === KEY_ID
              ? { algorithm: "ecdh-p256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);
  const client = new Client({
    publisherOrigin: PUB,
    cache: new PeriodKeyCache(),
    requestBuilderFactory: (/** @type {any} */ options) => new ChainKeyRequestBuilder(options),
  });
  return {
    registration,
    request: parseDcaRequest(
      JSON.stringify(client.buildRequest(client.parse(page), ISSUER, [NAME])),
    ),
  };
}

describe("each carrier is read once per message", () => {
  test("the issuer reads one request once, for presentation, selection and capability production", async () => {
    const { registration, request } = await world();
    let reads = 0;
    const document = request.toObject();
    const geometry = document.periodGeometry;
    Object.defineProperty(document, "periodGeometry", {
      enumerable: true,
      get() {
        reads++;
        return geometry;
      },
    });
    const engine = new IssuerEngine({
      operatingIssuerNames: [ISSUER],
      accessPolicy: policy(2),
      periodCapabilitySource: requireChainRepresentation(chainKeyCapabilitySource()),
    });

    const result = await engine.unlock(request, registration, {}, { capturedAtMs: Date.parse(AT) });

    assert.deepEqual(result.errors, []);
    assert.deepEqual(Object.keys(periodKeyMap(result.periodKeys)[GROUP]), [
      "251023T1415",
      "251023T1430",
    ]);
    assert.equal(reads, 1, "one unlock resolves the request carrier once");
  });

  test("the client never reads response geometry while filing access groups", async () => {
    const groups = ["premium", "archive", "sport"];
    let reads = 0;
    const response = {
      keys: {
        chainKeys: groups.map((accessGroup) => ({ accessGroup, cutoff: LATE_T, key: CHAIN_KEY })),
      },
    };
    Object.defineProperty(response, "periodGeometry", {
      enumerable: true,
      get() {
        reads++;
        return GEOMETRY;
      },
    });
    /** @type {any[][]} */
    const filed = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          filed.push(args);
        },
        candidates: () => [],
      },
      chainKeyProfile: explicitChainKeyClientProfile,
    });
    const page = new DcaData(
      {
        version: "1",
        resourceJWT: token({ renderId: "render-chain-carrier-reader" }),
        issuerData: [
          {
            issuerName: ISSUER,
            keyId: "k1",
            unlockUrl: "https://issuer.example/unlock",
            sealed: {},
          },
        ],
        contentData: [],
      },
      { publisherOrigin: PUB },
    );

    const request = {
      sealed: {
        chainKeys: groups.map((accessGroup) => ({ accessGroup, cutoff: LATE_T, key: CHAIN_KEY })),
      },
      periodGeometry: GEOMETRY,
    };
    const applied = await resolver.applyResponse(page, ISSUER, response, associated(page, request));

    assert.deepEqual(applied, { accepted: 3, errors: [], issues: [] });
    assert.deepEqual(
      filed.map(([accessGroup]) => accessGroup),
      groups,
    );
    assert.equal(reads, 0, "response metadata supplies no chain context");
  });
});

describe("the reading decides what the client files", () => {
  /** @param {unknown} lateMember */
  async function applyFamilies(lateMember) {
    /** @type {any[][]} */
    const filed = [];
    const resolver = new ContentKeyResolver({
      chainCache: {
        put(/** @type {any[]} */ ...args) {
          filed.push(args);
        },
        candidates: () => [],
      },
      chainKeyProfile: explicitChainKeyClientProfile,
    });
    const page = new DcaData(
      {
        version: "1",
        resourceJWT: token({ renderId: "render-chain-family-drop" }),
        issuerData: [
          {
            issuerName: ISSUER,
            keyId: "k1",
            unlockUrl: "https://issuer.example/unlock",
            sealed: {},
          },
        ],
        contentData: [],
      },
      { publisherOrigin: PUB },
    );

    const request = {
      sealed: {
        chainKeys: [
          { accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY },
          { accessGroup: OTHER, cutoff: LATE_T, key: CHAIN_KEY },
        ],
      },
      periodGeometry: GEOMETRY,
    };
    const applied = await resolver.applyResponse(
      page,
      ISSUER,
      {
        keys: {
          chainKeys: [
            { accessGroup: GROUP, cutoff: EARLY_T, key: CHAIN_KEY },
            { accessGroup: GROUP, cutoff: LATE_T, key: lateMember },
            { accessGroup: OTHER, cutoff: LATE_T, key: CHAIN_KEY },
          ],
        },
        periodGeometry: GEOMETRY,
      },
      associated(page, request),
    );
    return { applied, filed };
  }

  test("a family with a non-string member files none of its members", async () => {
    // EARLY_T lies outside the reach the request presented; the number is a
    // malformed member of an otherwise valid family. Neither is a string or
    // an object, so the other family's direct member is still filed.
    const { applied, filed } = await applyFamilies(7);

    assert.deepEqual(
      filed.map(([accessGroup, cutoffT]) => [accessGroup, cutoffT]),
      [[OTHER, LATE_T]],
      "the well-formed member goes down with the non-string member of its family",
    );
    assert.deepEqual(
      applied,
      {
        accepted: 1,
        errors: [],
        issues: [
          { section: "chainKeys", code: "malformed_key" },
          { section: "chainKeys", code: "malformed_key" },
        ],
      },
      "the unpresented cutoff and the malformed member are each a malformed key",
    );
  });

  test("an object member beside a direct member rejects the representation", async () => {
    // Response binding Section 3 classifies by JSON type: `{ key: 7 }` is a
    // client-bound object entry even though its key member is malformed, and
    // a string beside it in a supported section rejects the representation.
    const { applied, filed } = await applyFamilies({ key: 7 });

    assert.deepEqual(filed, [], "no family is filed from a rejected representation");
    assert.deepEqual(applied, {
      accepted: 0,
      errors: [],
      issues: [{ section: "response", code: "invalid_transport" }],
    });
  });
});

test("chain opening errors report only the presented source member while an item key survives", async () => {
  const page = new DcaData({
    version: "1",
    resourceJWT: token({ renderId: "render-chain-error-association" }),
    issuerData: [{ issuerName: ISSUER, keyId: "k1", sealed: {} }],
    contentData: [],
  });
  const resolver = new ContentKeyResolver({ chainKeyProfile: explicitChainKeyClientProfile });
  const application = await resolver.applyResponse(
    page,
    ISSUER,
    {
      keys: { contentKeys: [{ contentName: "bodytext", key: CHAIN_KEY }] },
      errors: [
        { coordinate: `${GROUP}|${LATE_T}`, error: "unseal_failed" },
        { coordinate: `${GROUP}|${EARLY_T}`, error: "unseal_failed" },
      ],
    },
    associated(page, {
      sealed: {
        contentKeys: [{ contentName: "bodytext", key: "sealed-item" }],
        chainKeys: [{ accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY }],
      },
      periodGeometry: GEOMETRY,
    }),
  );
  assert.deepEqual(application, {
    accepted: 1,
    errors: [{ coordinate: `${GROUP}|${LATE_T}`, error: "unseal_failed" }],
    issues: [{ section: "errors", code: "unsolicited_coordinate" }],
  });
  assert.deepEqual(await resolver.contentKeyFor(page, "bodytext"), new Uint8Array(16).fill(3));
});

// Response binding Section 3 admits response keys per record, as explicitly
// allowed by data-format Section 2.1. A bad identity leaves valid sibling
// records available; these tests pin that admission scope.

describe("a response chain record with a bad accessGroup costs only that record", () => {
  for (const [label, record] of /** @type {[string, object][]} */ ([
    ["a number", { accessGroup: 7, cutoff: LATE_T, key: CHAIN_KEY }],
    ["missing", { cutoff: LATE_T, key: CHAIN_KEY }],
    ["outside the grammar", { accessGroup: "2bad", cutoff: LATE_T, key: CHAIN_KEY }],
  ])) {
    test(`an accessGroup that is ${label} leaves its valid sibling filed`, async () => {
      /** @type {any[][]} */
      const filed = [];
      const resolver = new ContentKeyResolver({
        chainCache: {
          put(/** @type {any[]} */ ...args) {
            filed.push(args);
          },
          candidates: () => [],
        },
        chainKeyProfile: explicitChainKeyClientProfile,
      });
      const page = new DcaData(
        {
          version: "1",
          resourceJWT: token({ renderId: "render-chain-identity-scope" }),
          issuerData: [
            {
              issuerName: ISSUER,
              keyId: "k1",
              unlockUrl: "https://issuer.example/unlock",
              sealed: {},
            },
          ],
          contentData: [],
        },
        { publisherOrigin: PUB },
      );
      const request = {
        sealed: { chainKeys: [{ accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY }] },
        periodGeometry: GEOMETRY,
      };
      const applied = await resolver.applyResponse(
        page,
        ISSUER,
        {
          keys: { chainKeys: [{ accessGroup: GROUP, cutoff: LATE_T, key: CHAIN_KEY }, record] },
          periodGeometry: GEOMETRY,
        },
        associated(page, request),
      );

      assert.equal(applied.accepted, 1);
      assert.deepEqual(applied.issues, [{ section: "chainKeys", code: "malformed_key" }]);
      assert.deepEqual(
        filed.map(([accessGroup]) => accessGroup),
        [GROUP],
      );
    });
  }
});

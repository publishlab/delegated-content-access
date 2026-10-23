// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { chainKeyCapabilitySource } from "../core-issuer/chainKeyCapabilitySource.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../../../ports/UnlockEndpoint.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlDecode, utf8Decode } from "../../../core-shared/codec.js";
import { seal } from "../../../core-shared--publisher-issuer/keySealing.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { issuerKeypair, signingKeypair } from "../../../test-reference/support/keys.js";
import {
  requireChainRepresentation,
  chainKeyIssuerEngine,
} from "../core-issuer/chainKeyIssuerEngine.js";

const ORIGIN = "https://publisher.example";
const GEOMETRY = { chainsPerDay: 1, periodMinutes: 5 };
const INVOCATION = { capturedAtMs: Date.parse("2025-10-24T00:00:00Z") };
const labels = Array.from(
  { length: 288 },
  (_, i) =>
    `251023T${String(Math.floor((i * 5) / 60)).padStart(2, "0")}${String((i * 5) % 60).padStart(2, "0")}`,
);

async function world() {
  const signing = await signingKeypair();
  const pair = await issuerKeypair();
  const sealer = new Sealer({
    origin: ORIGIN,
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 5 }),
    signingKeys: { signing: signing.privateKey },
    issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
    issuers: [
      { issuerName: "issuer", keyId: "k", algorithm: "ecdh-p256", publicKey: pair.publicKey },
    ],
  });
  sealer.resource("resource", {});
  sealer.content("body", "text", "text/plain");
  const { dcaData } = await sealer.seal();
  const { renderId } = JSON.parse(utf8Decode(base64urlDecode(dcaData.resourceJWT.split(".")[1])));
  const registration = {
    kid: "signing",
    publicKey: signing.publicKey,
    origin: ORIGIN,
    openingKeys: { get: () => ({ algorithm: "ecdh-p256", privateKey: pair.privateKey }) },
  };
  /** @param {string} accessGroup @param {number} fill */
  const chain = async (accessGroup, fill) => ({
    accessGroup,
    cutoff: labels.at(-1),
    key: await seal(new Uint8Array(16).fill(fill), pair.publicKey, "ecdh-p256", {
      binding: { renderId, accessGroup, suppliedT: labels.at(-1), chainKey: true, ...GEOMETRY },
    }),
  });
  /** @param {string} accessGroup @param {string} period */
  const ordinary = async (accessGroup, period) => ({
    accessGroup,
    period,
    key: await seal(new Uint8Array(16).fill(9), pair.publicKey, "ecdh-p256", {
      binding: { renderId, accessGroup, t: period },
    }),
  });
  /** @param {any[]} chains @param {Record<string, number>} counts @param {any[]} [periods] */
  const request = (chains, counts, periods = []) =>
    new DcaRequest({
      version: "1",
      issuerName: "issuer",
      keyId: "k",
      resourceJWT: dcaData.resourceJWT,
      sealed: {
        contentKeys: dcaData.issuerData[0].sealed.contentKeys,
        chainKeys: chains,
        periodKeys: periods,
      },
      periodGeometry: GEOMETRY,
      requestedPeriodKeys: Object.keys(counts).length
        ? Object.entries(counts).map(([accessGroup, count]) => ({
            accessGroup,
            periods: labels.slice(0, count),
          }))
        : undefined,
    });
  /** @param {Record<string, number>} counts @param {'period-keys'|'chain-keys'} [representation] @param {string[]} [base] @param {string[]} [basePeriods] */
  const engine = (
    counts,
    representation = "period-keys",
    base = [],
    basePeriods = [labels[0]],
    source = undefined,
    futurePeriodCount = 0,
  ) => {
    const config = {
      operatingIssuerNames: ["issuer"],
      accessPolicy: {
        decide: () => ({
          contentNames: ["body"],
          periodGrants: [
            ...Object.keys(counts).map((accessGroup) => ({
              accessGroup,
              futurePeriodCount,
              authorizePeriod: () => true,
            })),
            ...base.map((accessGroup) => ({ accessGroup, periods: basePeriods })),
          ],
        }),
      },
    };
    return source
      ? new IssuerEngine({ ...config, periodCapabilitySource: source })
      : chainKeyIssuerEngine({ ...config, representation });
  };
  /** @param {any} engine @param {DcaRequest} request */
  const response = (engine, request, capturedAtMs = INVOCATION.capturedAtMs) =>
    new UnlockEndpoint(
      new IssuerProcessor(engine, {
        periodKeyInput: true,
        selectedExtensions: ["chain-keys"],
        capabilityEncoders: engine.capabilityEncoders,
      }),
    ).handleRequest({ request, registration, capturedAtMs });
  return { chain, ordinary, request, engine, registration, response };
}

function overflow(answer) {
  assert.notEqual(answer.response.status, 200);
  assert.equal(answer.response.body.error, "too_many_entries");
  assert.equal(
    Object.hasOwn(answer.response.body, "keys"),
    false,
    "no already-ready content key leaves",
  );
}

test("successful rivals at one label survive projection and chain representation", async () => {
  const w = await world();
  const rivals = await Promise.all([w.chain("premium", 1), w.chain("premium", 2)]);
  for (const representation of /** @type {const} */ (["period-keys", "chain-keys"])) {
    const counts = { premium: 1 };
    const result = await w
      .engine(counts, representation)
      .unlock(w.request(rivals, counts), w.registration, {}, INVOCATION);
    if (representation === "period-keys") {
      assert.equal(result.periodKeys.length, 2);
      assert.notEqual(result.periodKeys[0].key, result.periodKeys[1].key);
    } else {
      assert.equal(result.capabilities[0].entries.length, 2);
      assert.notEqual(result.capabilities[0].entries[0].key, result.capabilities[0].entries[1].key);
    }
    assert.deepEqual(result.errors, []);
  }
});

test("actual projected family output admits 288 candidates and refuses 290", async () => {
  const w = await world();
  const rivals = await Promise.all([w.chain("premium", 1), w.chain("premium", 2)]);
  const ok = await w.response(w.engine({ premium: 144 }), w.request(rivals, { premium: 144 }));
  assert.equal(ok.response.status, 200);
  assert.equal(ok.response.body.keys.periodKeys.length, 288);
  overflow(await w.response(w.engine({ premium: 145 }), w.request(rivals, { premium: 145 })));
});

test("identical opened rivals and failed rivals do not consume extra output capacity", async () => {
  const w = await world();
  const first = await w.chain("premium", 1);
  const identical = await w.chain("premium", 1);
  const broken = { ...first, key: "AA" };
  for (const rival of [identical, broken]) {
    const counts = { premium: 288 };
    const result = await w
      .engine(counts)
      .unlock(w.request([first, rival], counts), w.registration, {}, INVOCATION);
    assert.equal(result.periodKeys.length, 288);
    assert.deepEqual(result.errors, []);
  }
});

test("the final 512-key bound includes ordinary families and refuses all sibling keys at 513", async () => {
  const w = await world();
  const chains = await Promise.all([w.chain("premium", 1), w.chain("archive", 2)]);
  const periods = [await w.ordinary("base", labels[0])];
  const counts = { premium: 288, archive: 223 };
  const ok = await w.response(
    w.engine(counts, "period-keys", ["base"]),
    w.request(chains, counts, periods),
  );
  assert.equal(ok.response.status, 200);
  assert.equal(ok.response.body.keys.periodKeys.length, 512);
  assert.equal(ok.response.body.keys.contentKeys.length, 1);
  const over = { premium: 288, archive: 224 };
  overflow(
    await w.response(w.engine(over, "period-keys", ["base"]), w.request(chains, over, periods)),
  );
});

test("two in-bound projected families can overflow the aggregate through rivals", async () => {
  const w = await world();
  const chains = await Promise.all([
    w.chain("premium", 1),
    w.chain("premium", 2),
    w.chain("archive", 3),
    w.chain("archive", 4),
  ]);
  const counts = { premium: 129, archive: 129 };
  overflow(await w.response(w.engine(counts), w.request(chains, counts)));
});

test("an ordinary fallback family may return 289 keys below the aggregate limit", async () => {
  const w = await world();
  const ordinaryLabels = [...labels, "251024T0000"];
  const periods = await Promise.all(ordinaryLabels.map((period) => w.ordinary("base", period)));
  const counts = { premium: 1 };
  const answer = await w.response(
    w.engine(counts, "period-keys", ["base"], ordinaryLabels),
    w.request([await w.chain("premium", 1)], counts, periods),
  );
  assert.equal(answer.response.status, 200);
  assert.equal(
    answer.response.body.keys.periodKeys.filter((record) => record.accessGroup === "base").length,
    289,
  );
  assert.equal(answer.response.body.keys.periodKeys.length, 290);
});

test("direct source composition checks mixed final output at 512 and 513 automatically", async () => {
  const w = await world();
  const chains = await Promise.all([w.chain("premium", 1), w.chain("archive", 2)]);
  const periods = [await w.ordinary("base", labels[0])];
  for (const archive of [223, 224]) {
    const counts = { premium: 288, archive };
    const engine = w.engine(
      counts,
      "period-keys",
      ["base"],
      [labels[0]],
      chainKeyCapabilitySource(),
    );
    const answer = await w.response(engine, w.request(chains, counts, periods));
    if (archive === 223) {
      assert.equal(answer.response.status, 200);
      assert.equal(answer.response.body.keys.periodKeys.length, 512);
    } else overflow(answer);
  }
});

test("output check is captured and runs without selected chain coordinates", async () => {
  const w = await world();
  const seen = [];
  const source = chainKeyCapabilitySource();
  source.checkPeriodKeyOutput = (count) => {
    seen.push(count);
  };
  const engine = w.engine({}, "period-keys", ["base"], [labels[0]], source);
  source.checkPeriodKeyOutput = () => {
    throw new Error("replacement must not run");
  };
  const request = w.request([], {}, [await w.ordinary("base", labels[0])]);
  const result = await engine.unlock(request, w.registration, {}, INVOCATION);
  assert.equal(result.periodKeys.length, 1);
  assert.deepEqual(seen, [1]);
});

test("a period output check must be callable and return undefined synchronously", async () => {
  const w = await world();
  assert.throws(
    () =>
      w.engine({}, "period-keys", [], [], {
        ...chainKeyCapabilitySource(),
        checkPeriodKeyOutput: true,
      }),
    { code: "bad_config" },
  );
  const request = w.request([], {}, [await w.ordinary("base", labels[0])]);
  for (const checkPeriodKeyOutput of [
    () => false,
    async () => undefined,
    async () => {
      throw new Error("async fault");
    },
  ]) {
    const engine = w.engine({}, "period-keys", ["base"], [labels[0]], {
      ...chainKeyCapabilitySource(),
      checkPeriodKeyOutput,
    });
    await assert.rejects(engine.unlock(request, w.registration, {}, INVOCATION), {
      code: "bad_config",
    });
  }
});

test("empty successful results still run the source output check", async () => {
  const w = await world();
  const seen = [];
  const source = chainKeyCapabilitySource();
  source.checkPeriodKeyOutput = (count) => {
    seen.push(count);
  };
  const engine = new IssuerEngine({
    operatingIssuerNames: ["issuer"],
    accessPolicy: { decide: () => ({ contentNames: [], periodGrants: [] }) },
    notDeliveredReport: "complete",
    periodCapabilitySource: source,
  });
  const result = await engine.unlock(
    w.request([], {}, [await w.ordinary("base", labels[0])]),
    w.registration,
    {},
    INVOCATION,
  );
  assert.deepEqual(result.periodKeys, []);
  assert.deepEqual(seen, [0]);
});

test("source decoration refuses invalid optional output checks", () => {
  for (const value of [null, false, 0, true, {}]) {
    assert.throws(
      () =>
        requireChainRepresentation({ ...chainKeyCapabilitySource(), checkPeriodKeyOutput: value }),
      { code: "bad_config" },
    );
  }
});

const HORIZON_AT = Date.parse("2025-10-23T00:00:00Z");

test("a two-rival optional horizon stops at the complete 288-candidate family bound", async () => {
  const w = await world();
  const rivals = await Promise.all([w.chain("premium", 1), w.chain("premium", 2)]);
  const counts = { premium: 0 };
  const answer = await w.response(
    w.engine(counts, "period-keys", [], [], undefined, 145),
    w.request(rivals, {}),
    HORIZON_AT,
  );
  assert.equal(answer.response.status, 200);
  const records = answer.response.body.keys.periodKeys;
  assert.equal(records.length, 288);
  assert.deepEqual([...new Set(records.map((record) => record.period))], labels.slice(0, 144));
  assert.equal(answer.response.body.keys.contentKeys.length, 1);
});

test("optional horizons reserve actual ordinary fallback candidates before allocating families", async () => {
  const w = await world();
  const chains = await Promise.all([w.chain("archive", 1), w.chain("premium", 2)]);
  const counts = { archive: 0, premium: 0 };
  const ordinary = await w.ordinary("base", labels[0]);
  const periods = [ordinary, await w.ordinary("base", labels[0]), { ...ordinary, key: "AA" }];
  const answer = await w.response(
    w.engine(counts, "period-keys", ["base"], [labels[0]], undefined, 288),
    w.request(chains, {}, periods),
    HORIZON_AT,
  );
  assert.equal(answer.response.status, 200);
  const records = answer.response.body.keys.periodKeys;
  assert.equal(records.length, 512);
  for (const [group, count] of [
    ["archive", 288],
    ["premium", 223],
    ["base", 1],
  ])
    assert.equal(records.filter((record) => record.accessGroup === group).length, count);
  assert.equal(answer.response.body.keys.contentKeys.length, 1);
});

test("optional capacity never trims the rival set at the next label", async () => {
  const w = await world();
  const chains = await Promise.all([
    w.chain("archive", 1),
    w.chain("premium", 2),
    w.chain("premium", 3),
  ]);
  const counts = { archive: 0, premium: 0 };
  const answer = await w.response(
    w.engine(counts, "period-keys", ["base"], [labels[0]], undefined, 288),
    w.request(chains, {}, [await w.ordinary("base", labels[0])]),
    HORIZON_AT,
  );
  assert.equal(answer.response.status, 200);
  const records = answer.response.body.keys.periodKeys;
  assert.equal(records.length, 511);
  const premium = records.filter((record) => record.accessGroup === "premium");
  assert.equal(premium.length, 222);
  for (const period of labels.slice(0, 111))
    assert.equal(premium.filter((record) => record.period === period).length, 2);
  assert.equal(
    premium.some((record) => record.period === labels[111]),
    false,
  );
});

test("mandatory article overflow is refused even with an optional horizon", async () => {
  const w = await world();
  const rivals = await Promise.all([w.chain("premium", 1), w.chain("premium", 2)]);
  const counts = { premium: 145 };
  overflow(
    await w.response(
      w.engine(counts, "period-keys", [], [], undefined, 288),
      w.request(rivals, counts),
      HORIZON_AT,
    ),
  );
});

test("duplicate opened material and failed rivals do not shorten the optional horizon", async () => {
  const w = await world();
  const first = await w.chain("premium", 1);
  const duplicate = await w.chain("premium", 1);
  const broken = { ...first, key: "AA" };
  const counts = { premium: 0 };
  for (const rival of [duplicate, broken]) {
    const answer = await w.response(
      w.engine(counts, "period-keys", [], [], undefined, 288),
      w.request([first, rival], {}),
      HORIZON_AT,
    );
    assert.equal(answer.response.status, 200);
    assert.equal(answer.response.body.keys.periodKeys.length, 288);
    assert.equal(answer.response.body.errors?.length ?? 0, 0);
  }
});

test("a future-only family omitted after exhaustion emits no availability or error", async () => {
  const w = await world();
  const counts = { premium: 0, archive: 0, legacy: 0 };
  const chains = await Promise.all(Object.keys(counts).map((group, i) => w.chain(group, i + 1)));
  const answer = await w.response(
    w.engine(counts, "period-keys", [], [], undefined, 288),
    w.request(chains, {}),
    HORIZON_AT,
  );
  assert.equal(answer.response.status, 200);
  const records = answer.response.body.keys.periodKeys;
  assert.equal(records.length, 512);
  assert.equal(
    records.some((record) => record.accessGroup === "premium"),
    false,
  );
  assert.equal(answer.response.body.errors?.length ?? 0, 0);
  assert.equal(answer.response.body.notDelivered?.length ?? 0, 0);
  assert.equal(answer.response.body.keys.contentKeys.length, 1);
});

test("overlapping unlocks of one request own separate horizon budgets and captured times", async () => {
  const w = await world();
  const counts = { premium: 0 };
  const engine = w.engine(counts, "period-keys", [], [], undefined, 288);
  const request = w.request(await Promise.all([w.chain("premium", 1), w.chain("premium", 2)]), {});
  const answers = await Promise.all([
    w.response(engine, request, HORIZON_AT),
    w.response(engine, request, HORIZON_AT + 5 * 60_000),
  ]);
  for (const [index, answer] of answers.entries()) {
    assert.equal(answer.response.status, 200);
    const records = answer.response.body.keys.periodKeys;
    assert.equal(records.length, 288);
    assert.deepEqual(
      [...new Set(records.map((record) => record.period))],
      labels.slice(index, index + 144),
    );
  }
});

test("all families' mandatory article candidates precede the first optional family", async () => {
  const w = await world();
  const counts = { archive: 0, premium: 288 };
  const chains = await Promise.all([w.chain("archive", 1), w.chain("premium", 2)]);
  const request = w.request(chains, { premium: 288 });
  const answer = await w.response(
    w.engine(counts, "period-keys", [], [], undefined, 288),
    request,
    HORIZON_AT,
  );
  assert.equal(answer.response.status, 200);
  const records = answer.response.body.keys.periodKeys;
  assert.equal(records.length, 512);
  assert.deepEqual(
    records.filter((record) => record.accessGroup === "premium").map((record) => record.period),
    labels,
  );
  assert.equal(records.filter((record) => record.accessGroup === "archive").length, 224);
});

test("chain representation decoration preserves a stateful source receiver", () => {
  const request = {};
  const invocation = {};
  const source = {
    groups: ["premium"],
    presented(actualRequest, actualInvocation) {
      assert.equal(actualRequest, request);
      assert.equal(actualInvocation, invocation);
      return { accessGroups: this.groups };
    },
    selection() {
      return () => ({ miss: true });
    },
    capabilities() {
      return null;
    },
  };
  const wrapped = requireChainRepresentation(source);
  assert.deepEqual(wrapped.presented(request, invocation), source.presented(request, invocation));
});

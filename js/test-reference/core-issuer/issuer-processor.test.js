// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { IssuerEngine, checkVersion } from "../../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";

const PERIOD_KEY = "AAAAAAAAAAAAAAAAAAAAAA";

test("issuer core requires policy; publisher registration and key reach arrive per request", () => {
  assert.doesNotThrow(
    () => new IssuerEngine({ operatingIssuerNames: ["paywall"], accessPolicy: { decide() {} } }),
  );
  assert.throws(
    () => new IssuerEngine(/** @type {any} */ ({})),
    (/** @type {any} */ error) => error?.code === "bad_config",
  );
});

test("processor construction requires an engine and an object of limits", () => {
  assert.throws(
    () => new IssuerProcessor(/** @type {any} */ (null)),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
  assert.throws(
    () =>
      new IssuerProcessor(
        { checkOperatingIssuerName() {}, unlock: async () => ({ contentKeys: {}, errors: {} }) },
        { limits: /** @type {any} */ ("unbounded") },
      ),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
  // A list names no cap, so it would come up on all three defaults without the
  // deployment hearing that its object was never read.
  assert.throws(
    () => new IssuerProcessor(unreachableEngine(), { limits: /** @type {any} */ ([]) }),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
  assert.throws(
    () => new IssuerProcessor(unreachableEngine(), { limits: /** @type {any} */ (null) }),
    (/** @type {any} */ error) => error.code === "bad_config",
  );
  for (const limits of [{ maxEntries: 0 }, { maxEntriesPerGroup: -1 }, { maxBodyBytes: 0 }]) {
    assert.throws(
      () => new IssuerProcessor(unreachableEngine(), { limits }),
      (/** @type {any} */ error) => error.code === "bad_config",
      JSON.stringify(limits),
    );
  }
  // A member written as `undefined` is present, so it is a supplied value and
  // has to be a positive number like any other.
  assert.throws(
    () => new IssuerProcessor(unreachableEngine(), { limits: { maxEntries: undefined } }),
    (/** @type {any} */ error) =>
      error.code === "bad_config" && error.message.includes("maxEntries is a positive number"),
  );
});

test("an unknown option or limits member is refused rather than ignored", () => {
  // A misspelt cap would otherwise leave the default in force without the
  // deployment hearing about it.
  for (const options of [
    { limit: { maxEntries: 8 } },
    { encoders: {} },
    { limits: { maxEntry: 8 } },
    { limits: { maxEntries: 8, maxBytes: 1024 } },
  ]) {
    assert.throws(
      () => new IssuerProcessor(unreachableEngine(), /** @type {any} */ (options)),
      (/** @type {any} */ error) => error.code === "unsupported_option",
      JSON.stringify(options),
    );
  }
});

test("encoder and extension configuration of the wrong shape is refused at construction", () => {
  for (const options of [
    { capabilityEncoders: null },
    { capabilityEncoders: "chain-keys" },
    { capabilityEncoders: true },
    { capabilityEncoders: [() => ({})] },
    { capabilityEncoders: { "chain-keys": "encoder" } },
    { capabilityEncoders: { "chain-keys": () => ({}), other: null } },
    { selectedExtensions: "chain-keys" },
    { selectedExtensions: null },
    { selectedExtensions: [""] },
    { selectedExtensions: ["chain-keys", 7] },
    { periodKeyInput: "yes" },
  ]) {
    assert.throws(
      () => new IssuerProcessor(unreachableEngine(), /** @type {any} */ (options)),
      (/** @type {any} */ error) => error.code === "bad_config",
      JSON.stringify(options),
    );
  }
});

test("period-key request input is inactive until trusted issuer configuration selects it", async () => {
  const seen = [];
  const engine = {
    checkOperatingIssuerName() {},
    async unlock(request) {
      seen.push(request);
      return { contentKeys: {}, errors: {} };
    },
  };
  const mixed = new DcaRequest({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: {
      contentKeys: { bodytext: "direct" },
      periodKeys: { premium: { malformed: "period-key" } },
    },
  });

  const baseline = new IssuerProcessor(engine);
  const admitted = baseline.admit(mixed);
  assert.equal(admitted.kind, "admitted", "unselected period-key material has no parsing meaning");
  const result = await baseline.processMiss({ request: admitted.request, registration: {} });
  assert.equal(result.kind, "success");
  assert.equal(Object.hasOwn(seen[0].sealed, "periodKeys"), false);
  assert.equal(
    Object.hasOwn(mixed.sealed, "periodKeys"),
    true,
    "the retained admitted request is not mutated",
  );

  const periodKeysOnly = new DcaRequest({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { periodKeys: { premium: { "251023T1400": "period-key" } } },
  });
  assert.deepEqual(baseline.admit(periodKeysOnly), { kind: "failure", code: "binding_failed" });

  const selected = new IssuerProcessor(engine, { periodKeyInput: true });
  assert.deepEqual(
    selected.admit(periodKeysOnly),
    { kind: "failure", code: "binding_failed" },
    "the required request contentKeys container cannot be omitted",
  );
  const completePeriodRequest = new DcaRequest({
    ...periodKeysOnly.toObject(),
    sealed: { ...periodKeysOnly.sealed, contentKeys: {} },
  });
  assert.equal(
    selected.admit(completePeriodRequest).kind,
    "admitted",
    "an empty required contentKeys container is valid beside selected period coordinates",
  );
  assert.deepEqual(selected.admit(mixed), { kind: "failure", code: "binding_failed" });
});

test("admission parses the raw document once and does not reach the engine", async () => {
  const calls = [];
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock(request, registration, policyInput, at) {
      calls.push({ request, registration, policyInput, at });
      return {
        contentKeys: { bodytext: "content-key" },
        periodKeys: {},
        errors: {},
        policyData: { delivery: "host-owned" },
      };
    },
  });

  const originalParse = JSON.parse;
  let parses = 0;
  JSON.parse = (...args) => {
    parses++;
    return originalParse(...args);
  };

  let admission;
  let result;
  try {
    // One coordinate, because admission refuses a request that presents
    // none and this test is about the parse rather than about the ask.
    admission = processor.admit(
      '{"version":"first","version":"1","issuerName":"paywall","keyId":"2025-10",' +
        '"sealed":{"contentKeys":{"bodytext":"blob"}}}',
    );
    // Admission is the first operation: it structurally admits and returns
    // the request, and the engine has not been reached.
    assert.equal(admission.kind, "admitted");
    assert.equal(calls.length, 0, "admission does not call the engine");
    assert.equal(parses, 1, "the raw document is parsed exactly once, by admission");

    // Miss processing is the second operation: it takes the admitted request
    // and does not re-parse it.
    result = await processor.processMiss({
      request: admission.request,
      registration: {},
      policyInput: { principal: { user: "reader" } },
    });
  } finally {
    JSON.parse = originalParse;
  }

  assert.equal(parses, 1, "miss processing re-parses nothing");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].request, admission.request, "the admitted request is used unchanged");
  assert.deepEqual(calls[0].registration, {});
  assert.equal(calls[0].request.version, "1");
  assert.deepEqual(calls[0].policyInput, { principal: { user: "reader" } });
  assert.equal(
    calls[0].at,
    undefined,
    "a miss without the chain-key extension does not invent an issuer instant",
  );
  assert.deepEqual(result, {
    kind: "success",
    document: { keys: { contentKeys: { bodytext: "content-key" } } },
    policyData: { delivery: "host-owned" },
  });
  assert.equal(
    JSON.stringify(result.document),
    '{"keys":{"contentKeys":{"bodytext":"content-key"}}}',
    "a miss without the chain-key extension keeps its wire document byte-for-byte unchanged without an instant",
  );
  assert.equal(Object.hasOwn(result, "status"), false);
  assert.equal(Object.hasOwn(result, "response"), false);
});

test("a canonical invocation carries the host registration, default policy input, and one captured instant", async () => {
  const calls = [];
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock(request, registration, policyInput, invocation) {
      calls.push({ request, registration, policyInput, invocation });
      return { contentKeys: {}, errors: {} };
    },
  });
  const request = new DcaRequest({ version: "1", sealed: {} });
  const registration = Object.freeze({ hostSelected: true });
  const capturedAtMs = Date.parse("2025-10-23T14:20:00Z");

  const result = await processor.processMiss({ request, registration, capturedAtMs });

  assert.equal(result.kind, "success");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].request, request, "the admitted object reaches the engine unchanged");
  assert.equal(
    calls[0].registration,
    registration,
    "the host-selected registration reaches the engine unchanged",
  );
  assert.deepEqual(
    calls[0].policyInput,
    {},
    "omitted policy input keeps the core empty-object default",
  );
  assert.deepEqual(
    calls[0].invocation,
    { capturedAtMs },
    "the engine receives the unchanged canonical host context",
  );
});

test("a configured typed encoder preserves period keys beside its known capability section", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  const interpretation = Object.freeze({
    profile: "test-chain-profile",
    selections: [{ terminalT: "t", cutoffT: "t", parameters: {} }],
  });
  const capability = Object.freeze({
    kind: "chain-keys",
    accessGroup: "premium",
    entries: { t: "chain-key" },
    interpretation,
  });
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        return {
          contentKeys: {},
          periodKeys: { archive: { "251023T1400": PERIOD_KEY } },
          capabilities: [capability],
          errors: {},
          policyData: { unchanged: true },
        };
      },
    },
    {
      periodKeyInput: true,
      capabilityEncoders: {
        "chain-keys"(record) {
          assert.equal(
            record,
            capability,
            "the encoder receives the source-declared typed record unchanged",
          );
          return {
            section: "chainKeys",
            accessGroup: record.accessGroup,
            entries: record.entries,
            periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
          };
        },
      },
    },
  );

  const result = await processor.processMiss({ request, registration: {} });
  assert.deepEqual(result, {
    kind: "success",
    document: {
      keys: {
        contentKeys: {},
        periodKeys: { archive: { "251023T1400": PERIOD_KEY } },
        chainKeys: { premium: { t: "chain-key" } },
      },
    },
    policyData: { unchanged: true },
  });
});

test("a represented capability without its configured encoder fails closed instead of disappearing", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  const engine = {
    checkOperatingIssuerName() {},
    async unlock() {
      return {
        contentKeys: { bodytext: "content-key" },
        periodKeys: { archive: { old: "period-key" } },
        errors: {},
        capabilities: [
          {
            kind: "chain-keys",
            accessGroup: "premium",
            entries: { t: "chain-key" },
            interpretation: {},
          },
        ],
      };
    },
  };

  assert.deepEqual(
    await new IssuerProcessor(engine).processMiss({ request, registration: {} }),
    { kind: "failure", code: "internal_error" },
    "a nonempty unknown kind cannot become a partial success",
  );
  assert.deepEqual(
    await new IssuerProcessor(engine, {
      capabilityEncoders: { "other-kind": () => ({}) },
    }).processMiss({
      request,
      registration: {},
    }),
    { kind: "failure", code: "internal_error" },
    "an installed encoder for another kind cannot be guessed from entries or bytes",
  );
});

test("malformed typed records and legacy result fields cannot become a partial success", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  const plainResult = {
    contentKeys: { bodytext: "content-key" },
    periodKeys: { archive: { t: "period-key" } },
    errors: {},
  };
  const valid = {
    kind: "chain-keys",
    accessGroup: "premium",
    entries: { t: "chain-key" },
    interpretation: {},
  };
  const malformed = [
    { ...valid, kind: "" },
    { ...valid, accessGroup: "" },
    { ...valid, entries: {} },
    { ...valid, entries: { t: 7 } },
    { ...valid, entries: { t: "chain-key", u: 7 } },
    { ...valid, entries: "chain-key" },
    { ...valid, interpretation: null },
    { ...valid, interpretation: [] },
    { ...valid, interpretation: "interpretation" },
    Object.assign([], valid),
  ];

  for (const capability of malformed) {
    const processor = new IssuerProcessor(
      {
        checkOperatingIssuerName() {},
        async unlock() {
          return { ...plainResult, capabilities: [capability] };
        },
      },
      {
        capabilityEncoders: {
          "chain-keys": () => ({
            section: "chainKeys",
            accessGroup: "premium",
            entries: { t: "chain-key" },
            periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
          }),
        },
      },
    );
    assert.deepEqual(
      await processor.processMiss({ request, registration: {} }),
      { kind: "failure", code: "internal_error" },
      JSON.stringify(capability),
    );
  }

  for (const legacy of [{ periodCapabilities: { premium: { t: "legacy-key" } } }]) {
    const processor = new IssuerProcessor({
      checkOperatingIssuerName() {},
      async unlock() {
        return { ...plainResult, ...legacy };
      },
    });
    assert.deepEqual(
      await processor.processMiss({ request, registration: {} }),
      { kind: "failure", code: "internal_error" },
      Object.keys(legacy)[0],
    );
  }
});

test("a throwing or malformed encoder contribution cannot become a partial success", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  const engine = {
    checkOperatingIssuerName() {},
    async unlock() {
      return {
        contentKeys: { bodytext: "content-key" },
        periodKeys: { archive: { t: "period-key" } },
        errors: {},
        capabilities: [
          {
            kind: "chain-keys",
            accessGroup: "premium",
            entries: { t: "chain-key" },
            interpretation: {},
          },
        ],
      };
    },
  };
  // A complete contribution, so each case below changes one field only.
  const contribution = {
    section: "chainKeys",
    accessGroup: "premium",
    entries: { t: "chain-key" },
    periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
  };
  for (const encoder of [
    () => {
      throw new Error("broken encoder");
    },
    () => ({ ...contribution, section: "unknown-section" }),
    () => ({ ...contribution, accessGroup: "" }),
    () => ({ ...contribution, accessGroup: 7 }),
    () => ({ ...contribution, entries: {} }),
  ]) {
    const processor = new IssuerProcessor(engine, {
      capabilityEncoders: { "chain-keys": encoder },
    });
    assert.deepEqual(await processor.processMiss({ request, registration: {} }), {
      kind: "failure",
      code: "internal_error",
    });
  }
});

test("a capability composition fault maps to the endpoint internal-error refusal", async () => {
  const endpoint = new UnlockEndpoint(
    new IssuerProcessor({
      checkOperatingIssuerName() {},
      async unlock() {
        return {
          contentKeys: { bodytext: "content-key" },
          errors: {},
          periodCapabilities: { premium: { t: "legacy-key" } },
        };
      },
    }),
  );
  assert.deepEqual(
    await endpoint.handleRequest({
      request: new DcaRequest({ version: "1", sealed: {} }),
      registration: {},
    }),
    {
      response: { status: 500, body: { error: "internal_error" } },
      policyData: undefined,
      code: "internal_error",
    },
  );
});

test("colliding typed capability contributions fail closed rather than overwrite an earlier group", async () => {
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        return {
          contentKeys: {},
          errors: {},
          capabilities: [
            {
              kind: "chain-keys",
              accessGroup: "premium",
              entries: { t1: "first" },
              interpretation: {},
            },
            {
              kind: "chain-keys",
              accessGroup: "premium",
              entries: { t2: "second" },
              interpretation: {},
            },
          ],
        };
      },
    },
    {
      capabilityEncoders: {
        "chain-keys"(record) {
          return {
            section: "chainKeys",
            accessGroup: record.accessGroup,
            entries: record.entries,
            periodGeometry: { chainsPerDay: 2, periodMinutes: 15 },
          };
        },
      },
    },
  );

  assert.deepEqual(
    await processor.processMiss({
      request: new DcaRequest({ version: "1", sealed: {} }),
      registration: {},
    }),
    { kind: "failure", code: "internal_error" },
    "a later contribution cannot silently replace the first one",
  );
});

test("absent and empty typed capabilities preserve ordinary partial success", async () => {
  for (const capabilities of [undefined, []]) {
    const processor = new IssuerProcessor(
      {
        checkOperatingIssuerName() {},
        async unlock() {
          return {
            contentKeys: { bodytext: "content-key" },
            periodKeys: { archive: { "251023T1400": PERIOD_KEY } },
            ...(capabilities === undefined ? {} : { capabilities }),
            errors: {},
          };
        },
      },
      { periodKeyInput: true },
    );
    const result = await processor.processMiss({
      request: new DcaRequest({ version: "1", sealed: {} }),
      registration: {},
    });
    assert.deepEqual(result, {
      kind: "success",
      document: {
        keys: {
          contentKeys: { bodytext: "content-key" },
          periodKeys: { archive: { "251023T1400": PERIOD_KEY } },
        },
      },
      policyData: undefined,
    });
  }
});

test("chain geometry of zero or below from an encoder is refused", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  for (const periodGeometry of [
    { chainsPerDay: 0, periodMinutes: 15 },
    { chainsPerDay: -1, periodMinutes: 15 },
    { chainsPerDay: 2, periodMinutes: 0 },
    { chainsPerDay: 2, periodMinutes: -15 },
  ]) {
    const processor = new IssuerProcessor(
      {
        checkOperatingIssuerName() {},
        async unlock() {
          return {
            contentKeys: {},
            errors: {},
            capabilities: [
              {
                kind: "chain-keys",
                accessGroup: "premium",
                entries: { t: "chain-key" },
                interpretation: {},
              },
            ],
          };
        },
      },
      {
        capabilityEncoders: {
          "chain-keys": (record) => ({
            section: "chainKeys",
            accessGroup: record.accessGroup,
            entries: record.entries,
            periodGeometry,
          }),
        },
      },
    );
    assert.deepEqual(
      await processor.processMiss({ request, registration: {} }),
      { kind: "failure", code: "internal_error" },
      JSON.stringify(periodGeometry),
    );
  }
});

test("an empty legacy capability map leaves the answer a success", async () => {
  for (const legacy of [{ periodCapabilities: {} }]) {
    const processor = new IssuerProcessor({
      checkOperatingIssuerName() {},
      async unlock() {
        return { contentKeys: { bodytext: "content-key" }, errors: {}, ...legacy };
      },
    });
    assert.deepEqual(
      await processor.processMiss({
        request: new DcaRequest({ version: "1", sealed: {} }),
        registration: {},
      }),
      {
        kind: "success",
        document: { keys: { contentKeys: { bodytext: "content-key" } } },
        policyData: undefined,
      },
      Object.keys(legacy)[0],
    );
  }
});

test("an engine cannot bypass capability composition with a direct chainKeys result", async () => {
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      return {
        contentKeys: {},
        errors: {},
        chainKeys: { premium: { "251023T1400": "uncomposed-chain-key" } },
      };
    },
  });
  assert.deepEqual(
    await processor.processMiss({
      request: new DcaRequest({ version: "1", sealed: {} }),
      registration: {},
    }),
    { kind: "failure", code: "internal_error" },
  );
});

test("a legacy capability member that is not a map is refused", async () => {
  for (const field of ["periodCapabilities"]) {
    for (const value of [null, "legacy-key", 7, [], ["legacy-key"]]) {
      const processor = new IssuerProcessor({
        checkOperatingIssuerName() {},
        async unlock() {
          return { contentKeys: { bodytext: "content-key" }, errors: {}, [field]: value };
        },
      });
      assert.deepEqual(
        await processor.processMiss({
          request: new DcaRequest({ version: "1", sealed: {} }),
          registration: {},
        }),
        { kind: "failure", code: "internal_error" },
        `${field}: ${JSON.stringify(value)}`,
      );
    }
  }
});

test("processMiss refuses a missing invocation as a wiring fault", async () => {
  const processor = new IssuerProcessor(unreachableEngine());
  for (const invocation of [null, undefined, "invocation", []]) {
    await assert.rejects(
      () => processor.processMiss(/** @type {any} */ (invocation)),
      (/** @type {any} */ error) => error.code === "bad_config",
      JSON.stringify(invocation) ?? "undefined",
    );
  }
});

test("an engine throw that carries no code answers internal_error", async () => {
  for (const thrown of [new Error("engine broke"), undefined, null, "engine broke"]) {
    const processor = new IssuerProcessor({
      checkOperatingIssuerName() {},
      async unlock() {
        throw thrown;
      },
    });
    assert.deepEqual(
      await processor.processMiss({
        request: new DcaRequest({ version: "1", sealed: {} }),
        registration: {},
      }),
      { kind: "failure", code: "internal_error" },
      String(thrown),
    );
  }
});

test("a canonical invocation rejects malformed captured instants before engine work", async () => {
  let calls = 0;
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      calls++;
      return { contentKeys: {}, errors: {} };
    },
  });
  const request = new DcaRequest({ version: "1", sealed: {} });

  for (const capturedAtMs of [null, "2025-10-23T14:20:00Z", NaN, Infinity, 1e20]) {
    await assert.rejects(
      () => processor.processMiss({ request, registration: {}, capturedAtMs }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  }
  assert.equal(calls, 0, "invalid host context never reaches the engine");
});

test("the raw-document compatibility entry admits once into the same canonical invocation", async () => {
  const calls = [];
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock(request, registration, policyInput, invocation) {
      calls.push({ request, registration, policyInput, invocation });
      return { contentKeys: {}, errors: {} };
    },
  });
  const endpoint = new UnlockEndpoint(processor);
  const registration = Object.freeze({ hostSelected: true });
  const capturedAtMs = Date.parse("2025-10-23T14:20:00Z");

  const answer = await endpoint.handleDocument(
    '{"version":"1","issuerName":"paywall","keyId":"2025-10",' +
      '"sealed":{"contentKeys":{"bodytext":"blob"}}}',
    registration,
    undefined,
    capturedAtMs,
  );

  assert.equal(answer.response.status, 200);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].request instanceof DcaRequest);
  assert.equal(calls[0].registration, registration);
  assert.deepEqual(calls[0].policyInput, {});
  assert.deepEqual(calls[0].invocation, { capturedAtMs });
});

test("the entry cap counts a malformed group the engine would skip, at admission", async () => {
  let reached = 0;
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        reached++;
        return { contentKeys: {}, periodKeys: {}, errors: {} };
      },
    },
    { limits: { maxEntriesPerGroup: 2 } },
  );

  // An array is not the map the format says a group is, so the engine walks
  // none of it and would answer with nothing. Admission counts its indices and
  // refuses first. Both answers are safe; the cheap one runs.
  const admission = processor.admit(
    '{"version":"1","issuerName":"paywall","keyId":"2025-10",' +
      '"sealed":{"periodKeys":{"premium":["a","b","c"]}}}',
  );

  assert.deepEqual(admission, { kind: "failure", code: "too_many_entries" });
  assert.equal(reached, 0, "a refused admission never reaches the engine");
});

test("the per-group cap cannot be bypassed by splitting entries across period-key and chain-key fields", () => {
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        throw new Error("unreachable");
      },
    },
    { limits: { maxEntriesPerGroup: 2 } },
  );

  const admission = processor.admit(
    JSON.stringify({
      version: "1",
      issuerName: "paywall",
      keyId: "2025-10",
      sealed: {
        periodKeys: { premium: { a: "x" } },
        chainKeys: { premium: { b: "y", c: "z" } },
      },
    }),
  );

  assert.deepEqual(admission, { kind: "failure", code: "too_many_entries" });
});

test("miss processing does not re-admit: the caps are not checked again", async () => {
  let reached = 0;
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        reached++;
        return { contentKeys: {}, periodKeys: {}, errors: {} };
      },
    },
    { limits: { maxEntriesPerGroup: 2 } },
  );

  // A request that admission would have refused for size. Handed straight to
  // miss processing - as it would be after admission has already run - it is
  // processed, because miss processing does not re-run the caps. The
  // application admits once, ahead of the cache lookup, and never again.
  const overCap = new DcaRequest({
    version: "1",
    sealed: { periodKeys: { premium: { a: "x", b: "y", c: "z" } } },
  });

  const result = await processor.processMiss({ request: overCap, registration: {} });

  assert.equal(reached, 1, "miss processing reached the engine without re-admitting");
  assert.equal(result.kind, "success");
});

test("miss processing refuses an engine answer that is not an UnlockResult, rather than throwing", async () => {
  // Missing errors, no result, or a null content-key map are engine faults.
  // They return internal_error instead of throwing during response assembly
  // or passing malformed key material to the port as a success.
  const request = new DcaRequest({ version: "1", sealed: { contentKeys: { bodytext: "blob" } } });
  for (const malformed of [
    { contentKeys: { bodytext: "k" } },
    null,
    { contentKeys: null, errors: {} },
  ]) {
    const processor = new IssuerProcessor({
      checkOperatingIssuerName() {},
      unlock: async () => /** @type {any} */ (malformed),
    });
    const result = await processor.processMiss({ request, registration: {} });
    assert.deepEqual(
      result,
      { kind: "failure", code: "internal_error" },
      JSON.stringify(malformed),
    );
  }
});

test("a period-key-enabled processor refuses malformed engine period-key output", async () => {
  const request = new DcaRequest({
    version: "1",
    sealed: { contentKeys: { bodytext: "blob" } },
  });
  for (const periodKeys of [
    null,
    "leak",
    [],
    { premium: {} },
    { "bad group": { "251023T1400": "key" } },
    { premium: { bad: "key" } },
    { premium: { "251023T1400": 7 } },
    { premium: { "251023T1400": "key" } },
  ]) {
    const processor = new IssuerProcessor(
      {
        checkOperatingIssuerName() {},
        async unlock() {
          return { contentKeys: {}, periodKeys, errors: {} };
        },
      },
      { periodKeyInput: true },
    );
    assert.deepEqual(
      await processor.processMiss({ request, registration: {} }),
      { kind: "failure", code: "internal_error" },
      JSON.stringify(periodKeys),
    );
  }
});

test("an engine configuration option fault is an internal error, not caller input", async () => {
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      const error = new Error("deployment selected an unsupported engine option");
      /** @type {any} */ (error).code = "unsupported_option";
      throw error;
    },
  });
  const result = await processor.processMiss({
    request: new DcaRequest({ version: "1", sealed: {} }),
    registration: {},
  });
  assert.deepEqual(result, { kind: "failure", code: "internal_error" });
});

test("admit throws on a wrong runtime type: a caller-wiring fault, not an admission", () => {
  // Neither a DcaRequest nor a string reaches this branch by any admitted
  // external input - IssuerServer passes a DcaRequest, handleDocument a
  // string. A host wiring the processor wrong is a configuration to fix, so
  // it throws rather than returning a mappable failure.
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      throw new Error("unreachable");
    },
  });

  assert.throws(
    () => processor.admit(/** @type {any} */ (42)),
    (/** @type {any} */ e) => e.code === "bad_config",
  );
  assert.throws(
    () => processor.admit(/** @type {any} */ ({ version: "1", sealed: {} })),
    (/** @type {any} */ e) => e.code === "bad_config",
  );
});

test("processMiss throws on a non-DcaRequest: the same wrong-runtime-type fault", async () => {
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      throw new Error("unreachable");
    },
  });

  await assert.rejects(
    () =>
      processor.processMiss({
        request: /** @type {any} */ ({ version: "1", sealed: {} }),
        registration: {},
      }),
    (/** @type {any} */ e) => e.code === "bad_config",
  );
});

test("a plain document is not a request, and the seams say so", async () => {
  // Every fixed field would read off a plain object, so a caller that skipped
  // construction would pass the version and envelope checks and then present
  // no coordinates at all. Each seam refuses instead.
  const document = { version: "1", sealed: { contentKeys: { bodytext: "blob" } } };

  assert.throws(
    () => checkVersion(/** @type {any} */ (document), ["1"]),
    (/** @type {any} */ e) => e.code === "bad_config",
  );
  await assert.rejects(
    () =>
      new IssuerEngine({
        operatingIssuerNames: ["paywall"],
        accessPolicy: { decide: () => ({}) },
      }).unlock(/** @type {any} */ (document), {}),
    (/** @type {any} */ e) => e.code === "bad_config",
  );
  await assert.rejects(
    () =>
      new IssuerProcessor({
        checkOperatingIssuerName() {},
        unlock: async () => ({ contentKeys: {}, errors: {} }),
      }).processMiss({
        request: /** @type {any} */ (document),
        registration: {},
      }),
    (/** @type {any} */ e) => e.code === "bad_config",
  );
});

test("admission reports a code and leaves refusal presentation to the port", () => {
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      throw new Error("unreachable");
    },
  });

  const admission = processor.admit("{not json");

  assert.deepEqual(admission, { kind: "failure", code: "invalid_json" });
  assert.equal(Object.hasOwn(admission, "body"), false);
  assert.equal(Object.hasOwn(admission, "status"), false);
});

test("coordinate admission rejects unsafe names and period-key labels before engine work", () => {
  let reached = 0;
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        reached++;
        return { contentKeys: {}, errors: {} };
      },
    },
    { periodKeyInput: true },
  );
  const overLength = "a".repeat(65);
  const cases = [
    { sealed: { contentKeys: { "body|text": "blob" } } },
    { sealed: { periodKeys: { "premium|sport": { "251023T1400": "blob" } } } },
    { sealed: { periodKeys: { premium: { "251023T1400|junk": "blob" } } } },
    { sealed: { periodKeys: { premium: { notadate: "blob" } } } },
    { sealed: { periodKeys: { premium: { "251023T14": "blob", "251023T1400": "blob" } } } },

    // The grammar itself, not only the delimiter the four rows above
    // carry. A name that is empty, digit-initial, over the cap or spelled
    // with a character the identifier rules exclude is refused here, where
    // the request is all that has to be read, rather than travelling into
    // a policy decision as a coordinate nothing can be sealed at.
    { sealed: { contentKeys: { "": "blob" } } },
    { sealed: { contentKeys: { 1: "blob" } } },
    { sealed: { contentKeys: { "1body": "blob" } } },
    { sealed: { contentKeys: { "body text": "blob" } } },
    { sealed: { contentKeys: { "body.text": "blob" } } },
    { sealed: { contentKeys: { [overLength]: "blob" } } },
    { sealed: { periodKeys: { "": { "251023T1400": "blob" } } } },
    { sealed: { periodKeys: { "2025-10": { "251023T1400": "blob" } } } },
    { sealed: { periodKeys: { "premium sport": { "251023T1400": "blob" } } } },
    { sealed: { periodKeys: { [overLength]: { "251023T1400": "blob" } } } },
    { sealed: { periodKeys: { premium: null } } },
    { sealed: { periodKeys: { premium: "AAAA" } } },
    { sealed: { periodKeys: { premium: ["AAAA"] } } },
    { sealed: { periodKeys: { premium: 5 } } },
    { sealed: { periodKeys: { premium: true } } },
    { sealed: { contentKeys: { bodytext: "blob" }, periodKeys: {} } },
    { sealed: { contentKeys: { bodytext: "blob" }, periodKeys: { premium: {} } } },
    { sealed: { periodKeys: { premium: { "251023T1400": "blob", notadate: "blob" } } } },

    // A present section that is not a map refuses the whole request, even
    // when a well-formed sibling section could carry it.
    { sealed: { contentKeys: null, periodKeys: { premium: { "251023T1400": "blob" } } } },
    { sealed: { contentKeys: "AAAA", periodKeys: { premium: { "251023T1400": "blob" } } } },
    { sealed: { contentKeys: ["AAAA"], periodKeys: { premium: { "251023T1400": "blob" } } } },
    { sealed: { contentKeys: { bodytext: "blob" }, periodKeys: null } },
    { sealed: { contentKeys: { bodytext: "blob" }, periodKeys: "AAAA" } },
    { sealed: { contentKeys: { bodytext: "blob" }, periodKeys: ["AAAA"] } },

    // The two request-path identifiers beside the coordinates. An
    // `issuerName` that is not an identifier and a `keyId` that is empty
    // address no opening key, and the engine's own typeof check was the
    // only gate on either one. A keyId is opaque, so a non-empty string is
    // the whole of its rule and the test below records what that admits.
    { issuerName: "1paywall", sealed: { contentKeys: { bodytext: "blob" } } },
    { issuerName: "pay|wall", sealed: { contentKeys: { bodytext: "blob" } } },
    { issuerName: overLength, sealed: { contentKeys: { bodytext: "blob" } } },
    { issuerName: "paywall", keyId: "", sealed: { contentKeys: { bodytext: "blob" } } },
    { issuerName: undefined, sealed: { contentKeys: { bodytext: "blob" } } },
    { keyId: undefined, sealed: { contentKeys: { bodytext: "blob" } } },

    // And the request that presents nothing at all. At least one base or
    // selected-extension coordinate has to be there, so an empty ask is
    // refused here rather than reaching an opening key to be answered with
    // an empty map.
    {},
    { sealed: {} },
    { sealed: { contentKeys: {} } },
    { sealed: { contentKeys: {}, periodKeys: {}, chainKeys: {} } },
    { sealed: { contentKeys: {}, chainKeys: { premium: { "251023T1400": "AAAA" } } } },
  ];

  for (const request of cases) {
    assert.deepEqual(
      processor.admit(
        JSON.stringify({
          version: "1",
          issuerName: "paywall",
          keyId: "2025-10",
          ...request,
        }),
      ),
      { kind: "failure", code: "binding_failed" },
    );
  }
  assert.equal(reached, 0, "structural coordinate refusals never reach policy or opening work");
});

test("the chain section counts as an ask when the issuer selected the extension", () => {
  const chainOnly = JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: {}, chainKeys: { premium: { "251023T1400": "AAAA" } } },
  });
  const engine = {
    checkOperatingIssuerName() {},
    async unlock() {
      return { contentKeys: {}, errors: {} };
    },
  };

  // The relay issuer: it selected the chain-key extension and projects the
  // supplied families to period keys, so it publishes no chain response
  // encoder and the section is still a coordinate it recognizes.
  const relay = new IssuerProcessor(engine, { selectedExtensions: ["chain-keys"] });
  assert.equal(relay.admit(chainOnly).kind, "admitted");

  // A chain response encoder is a separate deployment choice. Selecting the
  // extension without one still recognizes the request section.
  const encoding = new IssuerProcessor(engine, {
    selectedExtensions: ["chain-keys"],
    capabilityEncoders: { "chain-keys": () => ({}) },
  });
  assert.equal(encoding.admit(chainOnly).kind, "admitted");

  // The issuer that selected nothing treats both members as unknown, which
  // leaves the request with no coordinate at all.
  const noExtension = new IssuerProcessor(engine);
  assert.deepEqual(noExtension.admit(chainOnly), { kind: "failure", code: "binding_failed" });
});

test("an opaque keyId is admitted at any length the body cap leaves room for", () => {
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    async unlock() {
      return { contentKeys: {}, errors: {} };
    },
  });

  // `spec--core-protocol.md` Section 5 types `keyId` as a required non-empty
  // opaque value, and the identifier grammar of `spec--data-format.md` §2.1
  // reaches `contentName`, `accessGroup` and `issuerName` and not this. The
  // 64-character ceiling belongs to that grammar, so a publisher naming its
  // issuer's key with a composite or prefixed value is admitted here and the
  // opening-key namespace answers for it.
  const admission = processor.admit(
    JSON.stringify({
      version: "1",
      issuerName: "paywall",
      keyId: `${"k".repeat(64)}-2025-10`,
      sealed: { contentKeys: { bodytext: "blob" } },
    }),
  );

  assert.equal(admission.kind, "admitted");
  assert.equal(admission.request.keyId.length, 72);
});

test("admission of an already-constructed request applies the coordinate caps only", async () => {
  let reached = 0;
  const processor = new IssuerProcessor(
    {
      checkOperatingIssuerName() {},
      async unlock() {
        reached++;
        return { contentKeys: {}, periodKeys: {}, errors: {} };
      },
    },
    { limits: { maxBodyBytes: 1, maxEntries: 4 } },
  );

  // A host that owns a parsed representation hands a DcaRequest. It owned the
  // parse and measured its bytes with it, so the byte cap does not re-measure
  // one here; only the coordinate caps apply, and this one is within them.
  const admission = processor.admit(
    new DcaRequest({
      version: "1",
      issuerName: "paywall",
      keyId: "2025-10",
      sealed: { contentKeys: { a: "x", b: "y" } },
    }),
  );

  assert.equal(admission.kind, "admitted");
  assert.equal(reached, 0, "admission never reaches the engine");

  // And the coordinate caps do apply to a constructed request: five entries
  // under a cap of four are refused on the same path.
  assert.deepEqual(
    processor.admit(
      new DcaRequest({
        version: "1",
        issuerName: "paywall",
        keyId: "2025-10",
        sealed: { contentKeys: { a: "x", b: "y", c: "z", d: "w", e: "v" } },
      }),
    ),
    { kind: "failure", code: "too_many_entries" },
  );
  assert.equal(reached, 0);

  const result = await processor.processMiss({ request: admission.request, registration: {} });
  assert.equal(result.kind, "success");
  assert.equal(reached, 1);
});

/** An engine that admission never reaches. */
function unreachableEngine() {
  return {
    checkOperatingIssuerName() {},
    async unlock() {
      throw new Error("unreachable");
    },
  };
}

/**
 * @param {number} count
 * @returns {string}
 */
function documentWithContentKeys(count) {
  /** @type {Record<string, string>} */
  const contentKeys = {};
  for (let index = 0; index < count; index++) contentKeys[`item${index}`] = "blob";
  return JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys },
  });
}

/**
 * @param {number} count
 * @returns {string}
 */
function documentWithGroupEntries(count) {
  /** @type {Record<string, string>} */
  const periods = {};
  for (let index = 0; index < count; index++)
    periods[`251023T${String(index).padStart(2, "0")}00`] = "blob";
  return JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: {}, periodKeys: { premium: periods } },
  });
}

/**
 * @param {number} bytes
 * @returns {string}
 */
function documentOfAtLeast(bytes) {
  const document = JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: { bodytext: "b".repeat(bytes) } },
  });
  assert.ok(document.length > bytes, "the padded document is longer than the padding alone");
  return document;
}

/** What a padded document spends on everything except its padding. */
const WRAPPER_BYTES = documentOfAtLeast(0).length;

/**
 * @param {string} text
 * @returns {number}
 */
function utf8Size(text) {
  return new TextEncoder().encode(text).length;
}

/**
 * A document of exactly `bytes` UTF-8 bytes, padded with single-byte text.
 *
 * @param {number} bytes
 * @returns {string}
 */
function documentOfExactly(bytes) {
  const padding = "b".repeat(bytes - WRAPPER_BYTES);
  const document = JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: { bodytext: padding } },
  });
  assert.equal(utf8Size(document), bytes, "the padded document measures what it was asked for");
  return document;
}

/** The engine double that answers an admitted request here. */
function answeringEngine() {
  return {
    checkOperatingIssuerName() {},
    async unlock() {
      return {
        contentKeys: { bodytext: "content-key" },
        errors: {},
        policyData: { delivery: "host-owned" },
      };
    },
  };
}

/** Caps far past anything these documents reach, so admission refuses nothing. */
const LIFTED = Object.freeze({
  maxBodyBytes: 4 * 1024 * 1024,
  maxEntries: 4096,
  maxEntriesPerGroup: 4096,
});

/**
 * @param {string} document
 * @param {{ maxBodyBytes?: number, maxEntries?: number, maxEntriesPerGroup?: number }} limits
 * @returns {Promise<any>}
 */
async function resultUnder(document, limits) {
  const processor = new IssuerProcessor(answeringEngine(), { limits });
  const admission = processor.admit(document);
  assert.equal(admission.kind, "admitted");
  return await processor.processMiss({ request: admission.request, registration: {} });
}

test("an omitted limits object still bounds the request body", () => {
  const oversized = documentOfAtLeast(64 * 1024);

  for (const options of [undefined, {}, { limits: {} }]) {
    const processor = new IssuerProcessor(unreachableEngine(), options);
    assert.deepEqual(
      processor.admit(oversized),
      { kind: "failure", code: "body_too_large" },
      `${JSON.stringify(options)} inherits the reference body cap`,
    );
  }

  const processor = new IssuerProcessor(unreachableEngine());
  assert.equal(
    processor.admit(documentOfExactly(64 * 1024)).kind,
    "admitted",
    "a document of exactly 65536 bytes is at the cap, not over it",
  );
  assert.deepEqual(
    processor.admit(documentOfExactly(64 * 1024 + 1)),
    { kind: "failure", code: "body_too_large" },
    "one byte more is over it",
  );

  // The cap counts bytes. Multi-byte text is over it at a code-unit length the
  // first of the two checks lets through, and the second one measures.
  const multiByte = JSON.stringify({
    version: "1",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: { bodytext: "\u00e9".repeat(64 * 1024 - WRAPPER_BYTES) } },
  });
  assert.equal(multiByte.length, 64 * 1024, "the code units are at the cap");
  assert.ok(utf8Size(multiByte) > 64 * 1024, "the bytes are past it");
  assert.deepEqual(
    processor.admit(multiByte),
    { kind: "failure", code: "body_too_large" },
    "the byte count refuses what the code-unit count admits",
  );
});

test("a request the caps admit is answered with the bytes it gets with the caps lifted", async () => {
  const atCap = documentOfExactly(64 * 1024);
  assert.deepEqual(
    await resultUnder(atCap, {}),
    await resultUnder(atCap, LIFTED),
    "the reference defaults decide admission and nothing about the answer",
  );

  const oversized = documentOfAtLeast(64 * 1024);
  assert.deepEqual(
    await resultUnder(oversized, { maxBodyBytes: 128 * 1024 }),
    await resultUnder(oversized, LIFTED),
    "a larger explicit override decides admission and nothing about the answer",
  );
});

test("an omitted limits object still bounds total entries", () => {
  for (const options of [undefined, {}, { limits: {} }]) {
    const processor = new IssuerProcessor(unreachableEngine(), options);
    assert.deepEqual(
      processor.admit(documentWithContentKeys(17)),
      { kind: "failure", code: "too_many_entries" },
      `${JSON.stringify(options)} inherits the reference entry cap`,
    );
  }

  assert.equal(
    new IssuerProcessor(unreachableEngine()).admit(documentWithContentKeys(16)).kind,
    "admitted",
    "a request at the entry bound is admitted",
  );
});

test("an omitted limits object still bounds entries in one access group", () => {
  for (const options of [undefined, {}, { limits: {} }]) {
    const processor = new IssuerProcessor(unreachableEngine(), options);
    assert.deepEqual(
      processor.admit(documentWithGroupEntries(5)),
      { kind: "failure", code: "too_many_entries" },
      `${JSON.stringify(options)} inherits the reference per-group cap`,
    );
  }

  assert.equal(
    new IssuerProcessor(unreachableEngine(), { periodKeyInput: true }).admit(
      documentWithGroupEntries(4),
    ).kind,
    "admitted",
    "a request at the per-group bound is admitted",
  );
});

test("a named cap replaces only itself, and the other defaults stay finite", () => {
  const wider = new IssuerProcessor(unreachableEngine(), {
    limits: { maxEntries: 32 },
    periodKeyInput: true,
  });

  assert.equal(
    wider.admit(documentWithContentKeys(17)).kind,
    "admitted",
    "the named cap is the deployment's",
  );
  assert.deepEqual(
    wider.admit(documentWithGroupEntries(5)),
    { kind: "failure", code: "too_many_entries" },
    "the unnamed per-group default still bounds one access group",
  );
  assert.deepEqual(
    wider.admit(documentOfAtLeast(64 * 1024)),
    { kind: "failure", code: "body_too_large" },
    "the unnamed body default still bounds the document",
  );
});

test("a deliberately larger finite override admits its request with the same result bytes", async () => {
  assert.equal(
    new IssuerProcessor(unreachableEngine(), {
      limits: { maxEntriesPerGroup: 8 },
      periodKeyInput: true,
    }).admit(documentWithGroupEntries(5)).kind,
    "admitted",
  );

  const oversized = documentOfAtLeast(64 * 1024);
  const processor = new IssuerProcessor(answeringEngine(), {
    limits: { maxBodyBytes: 128 * 1024 },
  });

  const admission = processor.admit(oversized);
  assert.equal(admission.kind, "admitted");

  const result = await processor.processMiss({ request: admission.request, registration: {} });
  assert.equal(
    JSON.stringify(result.document),
    '{"keys":{"contentKeys":{"bodytext":"content-key"}}}',
    "an override changes admission and nothing about the answer",
  );
});

test("a not-delivered report crosses into the document beside keys and errors", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  for (const [answer, document] of [
    [
      {
        contentKeys: { bodytext: "content-key" },
        errors: {
          summary: { error: "unseal_failed", message: "sealed value could not be opened" },
        },
        notDelivered: { premium: { reason: "denied" }, archive: { reason: "unavailable" } },
      },
      {
        keys: { contentKeys: { bodytext: "content-key" } },
        errors: {
          summary: { error: "unseal_failed", message: "sealed value could not be opened" },
        },
        notDelivered: { premium: { reason: "denied" }, archive: { reason: "unavailable" } },
      },
    ],
    // The no-key result of core Section 6.2: no key and no error, one family.
    [
      { contentKeys: {}, errors: {}, notDelivered: { premium: { reason: "denied" } } },
      { keys: { contentKeys: {} }, notDelivered: { premium: { reason: "denied" } } },
    ],
    // An empty report is no member: the document stays today's shape.
    [
      { contentKeys: { bodytext: "content-key" }, errors: {}, notDelivered: {} },
      { keys: { contentKeys: { bodytext: "content-key" } } },
    ],
  ]) {
    const processor = new IssuerProcessor({
      checkOperatingIssuerName() {},
      unlock: async () => answer,
    });
    assert.deepEqual(
      await processor.processMiss({ request, registration: {} }),
      { kind: "success", document, policyData: undefined },
      JSON.stringify(answer),
    );
  }
});

test("a not-delivered report the engine got wrong fails closed", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  for (const answer of [
    { contentKeys: {}, errors: {}, notDelivered: [] },
    { contentKeys: {}, errors: {}, notDelivered: { premium: "denied" } },
    { contentKeys: {}, errors: {}, notDelivered: { premium: { reason: "withheld" } } },
    { contentKeys: {}, errors: {}, notDelivered: { premium: { reason: "no_current_period" } } },
    { contentKeys: {}, errors: {}, notDelivered: { premium: { reason: "denied", message: 7 } } },
    { contentKeys: {}, errors: {}, notDelivered: { "bad group": { reason: "denied" } } },
    // A named family carries no period key, chain key or period error.
    {
      contentKeys: {},
      periodKeys: { premium: { "251023T1400": PERIOD_KEY } },
      errors: {},
      notDelivered: { premium: { reason: "unavailable" } },
    },
    {
      contentKeys: {},
      errors: { "premium|251023T1400": { error: "unseal_failed", message: "no" } },
      notDelivered: { premium: { reason: "denied" } },
    },
  ]) {
    const processor = new IssuerProcessor(
      { checkOperatingIssuerName() {}, unlock: async () => /** @type {any} */ (answer) },
      { periodKeyInput: true },
    );
    assert.deepEqual(
      await processor.processMiss({ request, registration: {} }),
      { kind: "failure", code: "internal_error" },
      JSON.stringify(answer),
    );
  }
});

test("an engine that obtained no policy decision leaves no document to carry a report", async () => {
  const request = new DcaRequest({ version: "1", sealed: {} });
  for (const code of ["bad_policy", "denied"]) {
    const processor = new IssuerProcessor({
      checkOperatingIssuerName() {},
      async unlock() {
        throw Object.assign(new Error(code), { code });
      },
    });
    assert.deepEqual(await processor.processMiss({ request, registration: {} }), {
      kind: "failure",
      code,
    });
  }
});

test("admission applies the engine's captured version set before member grammar", () => {
  const versions = ["2"];
  const engine = new IssuerEngine({
    operatingIssuerNames: ["paywall"],
    supportedVersions: versions,
    accessPolicy: {
      decide() {
        throw new Error("policy reached");
      },
    },
  });
  const processor = new IssuerProcessor(engine);
  versions.push("1");
  const input = {
    version: "2",
    issuerName: "paywall",
    keyId: "2025-10",
    sealed: { contentKeys: { bodytext: "blob" } },
  };
  assert.equal(processor.admit(JSON.stringify(input)).kind, "admitted");
  assert.deepEqual(
    processor.admit(JSON.stringify({ ...input, sealed: { contentKeys: 7 } })),
    { kind: "failure", code: "binding_failed" },
    "supported versions still undergo member grammar",
  );
  for (const sealed of [input.sealed, { contentKeys: 7 }])
    assert.deepEqual(processor.admit(JSON.stringify({ ...input, version: "1", sealed })), {
      kind: "failure",
      code: "bad_version",
    });
  const baseline = new IssuerProcessor(unreachableEngine());
  assert.deepEqual(
    baseline.admit(JSON.stringify(input)),
    { kind: "failure", code: "bad_version" },
    "unlock-only injected engines retain baseline version admission",
  );
  for (const carrier of [null, [], 7])
    assert.deepEqual(processor.admit(JSON.stringify(carrier)), {
      kind: "failure",
      code: "binding_failed",
    });
});

test("a version guard fault is not masked as an unsupported version", () => {
  const fault = new Error("guard fault");
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    checkVersion() {
      throw fault;
    },
    unlock: async () => ({ contentKeys: {}, errors: {} }),
  });
  assert.throws(
    () => processor.admit('{"version":"1"}'),
    (error) => error === fault,
  );
});

test("a custom engine guard cannot waive the common string version-selector shape", () => {
  let checks = 0;
  const processor = new IssuerProcessor({
    checkOperatingIssuerName() {},
    checkVersion() {
      checks++;
    },
    unlock: async () => ({ contentKeys: {}, errors: {} }),
  });
  for (const version of [undefined, null, 1, {}]) {
    const request = new DcaRequest({
      version,
      issuerName: "paywall",
      keyId: "2025-10",
      sealed: { contentKeys: { bodytext: "blob" } },
    });
    assert.deepEqual(processor.admit(request), { kind: "failure", code: "bad_version" });
  }
  assert.equal(checks, 0);
});

test("distinct encoded chain families share one geometry or refuse the whole response", async () => {
  for (const secondGeometry of [
    { chainsPerDay: 2, periodMinutes: 15 },
    { chainsPerDay: 4, periodMinutes: 15 },
    { chainsPerDay: 2, periodMinutes: 30 },
  ]) {
    const processor = new IssuerProcessor(
      {
        checkOperatingIssuerName() {},
        async unlock() {
          return {
            contentKeys: { bodytext: "content-key" },
            errors: {},
            capabilities: ["premium", "archive"].map((accessGroup) => ({
              kind: "chain-keys",
              accessGroup,
              entries: { t: `${accessGroup}-key` },
              interpretation: {},
            })),
          };
        },
      },
      {
        capabilityEncoders: {
          "chain-keys"(record) {
            return {
              section: "chainKeys",
              accessGroup: record.accessGroup,
              entries: record.entries,
              periodGeometry:
                record.accessGroup === "premium"
                  ? { chainsPerDay: 2, periodMinutes: 15 }
                  : secondGeometry,
            };
          },
        },
      },
    );
    const result = await processor.processMiss({
      request: new DcaRequest({ version: "1", sealed: {} }),
      registration: {},
    });
    if (secondGeometry.chainsPerDay === 2 && secondGeometry.periodMinutes === 15)
      assert.deepEqual(result, {
        kind: "success",
        document: {
          keys: {
            contentKeys: { bodytext: "content-key" },
            chainKeys: {
              premium: { t: "premium-key" },
              archive: { t: "archive-key" },
            },
          },
        },
        policyData: undefined,
      });
    else
      assert.deepEqual(
        result,
        { kind: "failure", code: "internal_error" },
        "mismatched families cannot release even the ordinary content key",
      );
  }
});

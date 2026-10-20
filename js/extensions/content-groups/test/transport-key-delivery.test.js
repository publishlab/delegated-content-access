// @ts-check
//
// Client-bound wrapping of composed response sections in the base issuer
// adapter, driven by this extension's section table and kinds. A recording
// profile stands in for a client-bound method: it tags each wrapped entry
// with its kind, so the test sees which entries were wrapped and under which
// kind. The real ECDH-P256 and RSA-OAEP methods with these kinds are composed
// in test-extensions/.

import test from "node:test";
import assert from "node:assert/strict";

import { KeyDelivery } from "../../../adapter-issuer/KeyDelivery.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import {
  composedKeys,
  mapComposedSections,
  settleComposedSections,
} from "../../../core-shared--client-issuer/responseKeys.js";
import {
  composedSectionEntries,
  composedSectionErrors,
} from "../../../core-client/responseSectionEntries.js";
import { base64urlEncode } from "../../../core-shared/codec.js";
import { KIND_DESCRIPTORS, RESPONSE_SECTIONS } from "../core-shared--client-issuer/request.js";

/** @param {number} n */
const b64 = (n, size = 16) => base64urlEncode(new Uint8Array(size).fill(n));
const request = new DcaRequest({
  version: "1",
  issuerName: "issuer",
  clientPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
  sealed: { contentKeys: {} },
});

/** A profile that wraps each key as `{kind, bytes}` and records the call. */
function recordingProfile() {
  /** @type {any[]} */
  const seals = [];
  /** @type {any[]} */
  const wraps = [];
  return {
    seals,
    wraps,
    profile: {
      METHOD: "TEST-METHOD",
      /** @param {any} _key @param {any} options */
      async seal(_key, options) {
        seals.push(options);
        return {
          transport: { publicKey: "transport" },
          /** @param {Uint8Array} bytes @param {string} keyKind */
          async wrap(bytes, keyKind) {
            const width = options.composedKinds?.[keyKind]?.width ?? 16;
            if (bytes.length !== width) throw new Error("width");
            wraps.push(keyKind);
            return { kind: keyKind, bytes: base64urlEncode(bytes) };
          },
        };
      },
    },
  };
}

function body() {
  return {
    keys: { contentKeys: { purchase: b64(1) }, periodKeys: { premium: { "261014T1500": b64(2) } } },
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    contentGroups: {
      chainKeys: { bodytext: { politics: { "261014T1800": b64(3) } } },
      periodKeys: { headline: { politics: { "261014T1500": b64(4) } } },
      contentKeys: { shoppingAd: b64(5) },
    },
    errors: {},
  };
}

/** @param {any} [options] */
async function prepared(
  options = { composedSections: RESPONSE_SECTIONS, composedKinds: KIND_DESCRIPTORS },
) {
  const recorder = recordingProfile();
  const delivery = new KeyDelivery({
    profile: recorder.profile,
    random: { bytes: (n) => new Uint8Array(n) },
    ...options,
  });
  const view = await delivery.preflight("client-bound", request);
  const input = body();
  // Without the declaration the section has no wrapping, so it stays out.
  if (options.composedSections === undefined) delete (/** @type {any} */ (input).contentGroups);
  return { ...recorder, out: await delivery.prepare(input, view) };
}

test("client-bound mode wraps every composed key under its section's kind", async () => {
  const { out, seals } = await prepared();
  for (const { key } of composedKeys(out, settleComposedSections(RESPONSE_SECTIONS)))
    assert.equal(typeof key, "object", "client-bound mode sent a contentGroups key unwrapped");
  assert.deepEqual(out.contentGroups, {
    chainKeys: {
      bodytext: {
        politics: {
          "261014T1800": { kind: "contentGroupChainKey", bytes: b64(3) },
        },
      },
    },
    periodKeys: {
      headline: { politics: { "261014T1500": { kind: "contentGroupPeriodKey", bytes: b64(4) } } },
    },
    contentKeys: { shoppingAd: { kind: "contentKey", bytes: b64(5) } },
  });
  assert.equal(seals[0].composedKinds, KIND_DESCRIPTORS, "the profile gets the composed kinds");
});

test("base sections wrap exactly as before, with or without composed sections", async () => {
  const composed = await prepared();
  const plain = await prepared({});
  assert.deepEqual(composed.out.keys, plain.out.keys);
  assert.deepEqual(plain.out.keys, {
    contentKeys: { purchase: { kind: "contentKey", bytes: b64(1) } },
    periodKeys: { premium: { "261014T1500": { kind: "periodKey", bytes: b64(2) } } },
  });
  assert.deepEqual(composed.out.transport, plain.out.transport);
  assert.deepEqual(composed.wraps.slice(0, 2), plain.wraps);
});

test("a composed key of the wrong width or spelling is refused before any wrap", async () => {
  for (const mutate of [
    (/** @type {any} */ b) =>
      (b.contentGroups.periodKeys.headline.politics["261014T1500"] = b64(4, 15)),
    (/** @type {any} */ b) => (b.contentGroups.chainKeys.bodytext.politics["261014T1800"] = "a="),
    (/** @type {any} */ b) =>
      (b.contentGroups.chainKeys.bodytext.politics["261014T1800"] = { position: 6, key: b64(3) }),
    (/** @type {any} */ b) => (b.contentGroups.contentKeys = [b64(5)]),
  ]) {
    const recorder = recordingProfile();
    const delivery = new KeyDelivery({
      profile: recorder.profile,
      random: { bytes: (n) => new Uint8Array(n) },
      composedSections: RESPONSE_SECTIONS,
      composedKinds: KIND_DESCRIPTORS,
    });
    const view = await delivery.preflight("client-bound", request);
    const input = body();
    mutate(input);
    await assert.rejects(delivery.prepare(input, view), { code: "bad_config" });
    assert.equal(recorder.wraps.length, 0);
  }
});

test("direct mode leaves composed sections alone", async () => {
  const delivery = new KeyDelivery({
    composedSections: RESPONSE_SECTIONS,
    composedKinds: KIND_DESCRIPTORS,
  });
  const view = await delivery.preflight("direct", request);
  const input = body();
  assert.equal(await delivery.prepare(input, view), input);
});

test("composed declarations are checked when the adapter is built", () => {
  for (const composedSections of [
    [{ path: ["keys", "x"], depth: 1, keyKind: "contentKey" }],
    [{ path: [], depth: 1, keyKind: "contentKey" }],
    [{ path: ["a"], depth: 0, keyKind: "contentKey" }],
    [{ path: ["a"], depth: 1 }],
    [{ path: ["a"], depth: 1, keyKind: "contentKey", extra: true }],
    [
      { path: ["a"], depth: 1, keyKind: "contentKey" },
      { path: ["a"], depth: 1, keyKind: "periodKey" },
    ],
    "contentGroups",
  ])
    assert.throws(() => new KeyDelivery({ composedSections, composedKinds: KIND_DESCRIPTORS }), {
      code: "bad_config",
    });
  assert.throws(
    () =>
      new KeyDelivery({
        composedSections: [{ path: ["a"], depth: 1, keyKind: "unknownKind" }],
        composedKinds: KIND_DESCRIPTORS,
      }),
    { code: "bad_config" },
  );
});

test("the client walk reads and maps a composed chain value at its label", async () => {
  const [chain] = settleComposedSections(RESPONSE_SECTIONS);
  const walked = composedSectionEntries(body(), chain);
  assert.deepEqual(walked.entries, [
    {
      path: ["bodytext", "politics", "261014T1800"],
      value: b64(3),
    },
  ]);
  const broken = body();
  /** @type {any} */ (broken.contentGroups.chainKeys.bodytext).politics = null;
  assert.equal(composedSectionEntries(broken, chain).malformed, 1);
  const mapped = await mapComposedSections(body(), [chain], (key, kind) => `${kind}:${key}`);
  assert.equal(
    mapped.contentGroups.chainKeys.bodytext.politics["261014T1800"],
    `contentGroupChainKey:${b64(3)}`,
  );
  assert.deepEqual(mapped.contentGroups.periodKeys, body().contentGroups.periodKeys);
});

test("client-bound mode refuses an undeclared child before wrapping any key", async () => {
  const recorder = recordingProfile();
  const delivery = new KeyDelivery({
    profile: recorder.profile,
    composedKinds: KIND_DESCRIPTORS,
    composedSections: RESPONSE_SECTIONS.slice(0, 1),
  });
  const view = await delivery.preflight("client-bound", request);
  await assert.rejects(delivery.prepare(body(), view), {
    code: "bad_config",
    message: /contentGroups\.periodKeys/,
  });
  assert.equal(recorder.wraps.length, 0);
});

test("composed section paths cannot overlap in either declaration order", () => {
  const parent = { path: ["extra"], depth: 1, keyKind: "contentKey" };
  const child = { ...parent, path: ["extra", "nested"] };
  for (const sections of [
    [parent, child],
    [child, parent],
  ])
    assert.throws(() => settleComposedSections(sections), { code: "bad_config" });
});

test("client-bound mode refuses a top-level member no composed section declares", async () => {
  for (const options of [{}, { composedSections: RESPONSE_SECTIONS.slice(0, 1) }]) {
    const recorder = recordingProfile();
    const delivery = new KeyDelivery({
      profile: recorder.profile,
      random: { bytes: (n) => new Uint8Array(n) },
      composedKinds: KIND_DESCRIPTORS,
      ...options,
    });
    const view = await delivery.preflight("client-bound", request);
    const input = body();
    if (options.composedSections !== undefined) {
      /** @type {any} */ (input).extraKeys = { shoppingAd: b64(5) };
      delete (/** @type {any} */ (input).contentGroups);
    }
    await assert.rejects(
      delivery.prepare(input, view),
      { code: "bad_config", message: /(contentGroups|extraKeys)/ },
      "an undeclared section left the issuer under client-bound transport",
    );
    assert.equal(recorder.wraps.length, 0, "nothing was wrapped before the refusal");
  }
});

const RETIRED = Object.freeze({ error: "key_retired" });
/** A body whose content-group answer also reports one retirement per section. */
function bodyWithErrors() {
  const input = /** @type {any} */ (body());
  input.contentGroups.errors = {
    chainKeys: { bodytext: { politics: { "261015T0600": { ...RETIRED } } } },
    periodKeys: { headline: { politics: { "261014T1400": { ...RETIRED } } } },
    contentKeys: { headline: { ...RETIRED } },
  };
  return input;
}

test("each content-group section declares its error map at its own coordinate depth", () => {
  const settled = settleComposedSections(RESPONSE_SECTIONS);
  assert.deepEqual(
    settled.map(({ errorPath, depth }) => [errorPath, depth]),
    [
      [["contentGroups", "errors", "chainKeys"], 3],
      [["contentGroups", "errors", "periodKeys"], 3],
      [["contentGroups", "errors", "contentKeys"], 1],
    ],
  );
  assert.ok(settled.every(({ errorPath }) => Object.isFrozen(errorPath)));
  const walked = composedSectionErrors(bodyWithErrors(), settled[0]);
  assert.deepEqual(walked, {
    present: true,
    entries: [{ path: ["bodytext", "politics", "261015T0600"], value: RETIRED }],
    malformed: 0,
  });
  assert.equal(composedSectionErrors(body(), settled[0]).present, false);
});

test("an errorPath is a non-base member path that overlaps no key path or other error path", () => {
  const key = { path: ["extra", "keys"], depth: 1, keyKind: "contentKey" };
  for (const sections of [
    [{ ...key, errorPath: [] }],
    [{ ...key, errorPath: "extra.errors" }],
    [{ ...key, errorPath: ["errors", "extra"] }],
    [{ ...key, errorPath: ["extra", "keys", "errors"] }],
    [{ ...key, errorPath: ["extra"] }],
    [
      { ...key, errorPath: ["extra", "errors"] },
      { ...key, path: ["extra", "errors", "inner"] },
    ],
    [
      { ...key, path: ["extra", "other"] },
      { ...key, errorPath: ["extra", "other", "errors"] },
    ],
    [
      { ...key, errorPath: ["extra", "errors"] },
      { ...key, path: ["extra", "more"], errorPath: ["extra", "errors"] },
    ],
  ])
    assert.throws(
      () => settleComposedSections(sections),
      { code: "bad_config" },
      JSON.stringify(sections),
    );
  assert.deepEqual(settleComposedSections([{ ...key, errorPath: ["extra", "errors"] }]), [
    { ...key, errorPath: ["extra", "errors"] },
  ]);
});

test("client-bound mode passes declared key_retired leaves through unwrapped", async () => {
  const recorder = recordingProfile();
  const delivery = new KeyDelivery({
    profile: recorder.profile,
    random: { bytes: (n) => new Uint8Array(n) },
    composedSections: RESPONSE_SECTIONS,
    composedKinds: KIND_DESCRIPTORS,
  });
  const out = await delivery.prepare(
    bodyWithErrors(),
    await delivery.preflight("client-bound", request),
  );
  assert.deepEqual(out.contentGroups.errors, bodyWithErrors().contentGroups.errors);
  // Only the five keys were wrapped; no error record reached the sealer.
  assert.equal(recorder.wraps.length, 5);
  assert.equal(typeof out.contentGroups.contentKeys.shoppingAd, "object");
  // An answer of errors alone is a body too.
  const only = {
    keys: { contentKeys: {} },
    contentGroups: { errors: { contentKeys: { a: RETIRED } } },
  };
  const view = await delivery.preflight("client-bound", request);
  assert.deepEqual((await delivery.prepare(only, view)).contentGroups, only.contentGroups);
});

test("client-bound mode refuses an error record that is not a fixed key_retired leaf at its depth", async () => {
  for (const mutate of [
    (/** @type {any} */ b) => (b.contentGroups.errors.contentKeys.headline.key = b64(7)),
    (/** @type {any} */ b) => (b.contentGroups.errors.contentKeys.headline = { error: b64(7) }),
    (/** @type {any} */ b) =>
      (b.contentGroups.errors.contentKeys.headline = { error: "unseal_failed" }),
    (/** @type {any} */ b) =>
      (b.contentGroups.errors.contentKeys.headline = { error: "key_retired", message: "m" }),
    (/** @type {any} */ b) => (b.contentGroups.errors.contentKeys.headline = b64(7)),
    (/** @type {any} */ b) => (b.contentGroups.errors.periodKeys.headline.politics = RETIRED),
    (/** @type {any} */ b) => (b.contentGroups.errors.periodKeys.headline = [RETIRED]),
    (/** @type {any} */ b) => (b.contentGroups.errors.seeds = { bodytext: b64(7) }),
    (/** @type {any} */ b) => (b.contentGroups.errors = [RETIRED]),
    (/** @type {any} */ b) => (b.contentGroups.errors = b64(7)),
  ]) {
    const recorder = recordingProfile();
    const delivery = new KeyDelivery({
      profile: recorder.profile,
      random: { bytes: (n) => new Uint8Array(n) },
      composedSections: RESPONSE_SECTIONS,
      composedKinds: KIND_DESCRIPTORS,
    });
    const view = await delivery.preflight("client-bound", request);
    const input = bodyWithErrors();
    mutate(input);
    await assert.rejects(delivery.prepare(input, view), { code: "bad_config" }, String(mutate));
    assert.equal(recorder.wraps.length, 0);
  }
});

test("client-bound mode refuses an error map no section declares", async () => {
  const undeclared = RESPONSE_SECTIONS.map(({ errorPath, ...section }) => section);
  const recorder = recordingProfile();
  const delivery = new KeyDelivery({
    profile: recorder.profile,
    random: { bytes: (n) => new Uint8Array(n) },
    composedSections: undeclared,
    composedKinds: KIND_DESCRIPTORS,
  });
  const view = await delivery.preflight("client-bound", request);
  await assert.rejects(delivery.prepare(bodyWithErrors(), view), {
    code: "bad_config",
    message: /contentGroups\.errors/,
  });
  assert.equal(recorder.wraps.length, 0);
});

test("client-bound mode keeps the base members and a declared section's root", async () => {
  const recorder = recordingProfile();
  const delivery = new KeyDelivery({
    profile: recorder.profile,
    random: { bytes: (n) => new Uint8Array(n) },
  });
  const view = await delivery.preflight("client-bound", request);
  const input = { ...body(), notDelivered: { contentKeys: ["x"] } };
  delete (/** @type {any} */ (input).contentGroups);
  const out = await delivery.prepare(input, view);
  assert.deepEqual(out.periodGeometry, input.periodGeometry);
  assert.deepEqual(out.errors, {});
  assert.deepEqual(out.notDelivered, input.notDelivered);
  const direct = new KeyDelivery({});
  const plain = { ...body(), extraKeys: {} };
  assert.equal(await direct.prepare(plain, await direct.preflight("direct", request)), plain);
});

// @ts-check
//
// Public shared primitives refuse configuration mistakes with DCA's typed
// vocabulary. These are grouped by caller operation rather than one test per
// branch: each group first proves an honest input reaches the intended result,
// then changes only the option or key the refusal is about.

import { test, portableTest } from "../support/portable-test.js";
import assert from "node:assert/strict";

import { seal, open } from "../../core-shared--publisher-issuer/keySealing.js";
import { sign, verify } from "../../core-shared--publisher-issuer/jwt.js";
import { periodsFor } from "../../core-shared--publisher-issuer/periodKeys.js";
import {
  BIND_IDENTIFIER,
  RENDER_ID_BYTES,
  bindValue,
} from "../../core-shared--publisher-issuer/bind.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { DcaError } from "../../core-shared/errors.js";
import { PERIOD_KEY_PROFILE, periodKeyProfile } from "../../core-shared/periodKeyProfiles.js";
import { generateEcdhKeyPair } from "../../core-shared/cryptoProvider.js";
import { periodGeometriesAgree } from "../../core-shared/geometryBounds.js";
import { isPeriodKeyLabel } from "../../core-shared/periodLabels.js";
import { issuerKeypair, signingKeypair } from "../support/keys.js";

const RENDER_ID = base64urlEncode(new Uint8Array(RENDER_ID_BYTES).fill(0x5a));
const BINDING = { renderId: RENDER_ID, contentName: "bodytext" };

/**
 * @param {() => unknown} run
 * @param {{ code: string, message?: RegExp }} expected
 */
async function refuses(run, expected) {
  await assert.rejects(
    async () => run(),
    (error) => {
      assert.ok(error instanceof DcaError, `expected DcaError, got ${error}`);
      assert.equal(error.code, expected.code);
      if (expected.message) assert.match(error.message, expected.message);
      return true;
    },
  );
}
const portableCoreTest = portableTest("portable-core");
const portableCoreDynamicTest = portableTest("portable-core-dynamic");

/** Period-key profile names that are strings and name no profile. */
const UNKNOWN_PROFILE_NAMES = [
  "dca-profile-period-keys-8",
  "dca-profile-period",
  "DCA-PROFILE-PERIOD-KEYS",
  "",
];

/**
 * Profile names that are not a string, which periodKeyProfile declares.
 * The direct case also passes `undefined`, which no shared crossing passes
 * across a reference API.
 */
const NOT_STRING_PROFILE_NAMES = [16, null];

/**
 * Asserts that periodKeyProfile refuses `name` as an unknown profile.
 *
 * @param {unknown} name
 */
function refusesProfileName(name) {
  assert.throws(
    () => periodKeyProfile(/** @type {any} */ (name)),
    (error) => {
      assert.ok(error instanceof DcaError, `expected DcaError, got ${error}`);
      assert.equal(error.code, "unsupported_option");
      assert.match(error.message, /period-key profile/);
      return true;
    },
    `profile name ${JSON.stringify(name)}`,
  );
}

test("JWT fixes its header and requires the signing and verification keys it uses", async () => {
  const pair = await signingKeypair();
  const wrongCurve = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["sign", "verify"],
  );
  const payload = { renderId: RENDER_ID };
  const token = await sign(payload, pair.privateKey, { kid: "signing-key" });
  assert.deepEqual(
    await verify(token, pair.publicKey),
    payload,
    "the valid sibling signs and verifies",
  );

  // The same token with one header member respelled. The signature still
  // covers the original header, so the fixed-header rule refuses this, not
  // the signature check behind it.
  const relabelled = [
    base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "DCA", kid: "signing-key" }))),
    ...token.split(".").slice(1),
  ].join(".");

  for (const [run, expected] of [
    [
      () => sign(payload, pair.privateKey, { typ: "DCA" }),
      { code: "unsupported_option", message: /no typ "DCA"/ },
    ],
    [() => verify(relabelled, pair.publicKey), { code: "bad_alg", message: /typ JWT/ }],
    [
      () => sign(payload, /** @type {any} */ (null)),
      { code: "bad_config", message: /sign needs a private key/ },
    ],
    [
      () => verify(token, /** @type {any} */ (null)),
      { code: "bad_config", message: /verify needs a public key/ },
    ],
    [() => verify(token, /** @type {any} */ (undefined)), { code: "bad_config" }],
    [() => verify(token, wrongCurve.publicKey), { code: "bad_config" }],
  ]) {
    await refuses(/** @type {() => unknown} */ (run), /** @type {any} */ (expected));
  }
});

portableCoreTest(
  "period and binding inputs refuse silent empty or ambiguous interpretations",
  async () => {
    const now = new Date("2025-10-23T14:20:00Z");
    assert.deepEqual(periodsFor(now, { length: 60, slots: 2 }), ["251023T1400", "251023T1500"]);
    await refuses(() => periodsFor(now, { length: 7, slots: 2 }), {
      code: "bad_config",
      message: /period length must divide one UTC day/,
    });
    await refuses(() => periodsFor(now, { length: 60, slots: 0 }), {
      code: "bad_config",
      message: /slots must be a positive integer/,
    });

    assert.equal(bindValue(BINDING), `${BIND_IDENTIFIER}|c|${RENDER_ID}|bodytext`);
    assert.equal(
      bindValue({ renderId: RENDER_ID, accessGroup: "premium", t: "251023T1400" }),
      `${BIND_IDENTIFIER}|p|${RENDER_ID}|premium|251023T1400`,
      "hourly period binding preserves the canonical minute spelling",
    );
    await refuses(
      () =>
        bindValue({
          renderId: RENDER_ID,
          accessGroup: "premium",
          suppliedT: "251023T1400",
          chainKey: true,
        }),
      { code: "binding_failed", message: /names its complete geometry/ },
    );
    assert.equal(
      bindValue({
        renderId: RENDER_ID,
        accessGroup: "premium",
        suppliedT: "251023T2345",
        chainKey: true,
        chainsPerDay: 2,
        periodMinutes: 15,
      }),
      `${BIND_IDENTIFIER}|pc|${RENDER_ID}|premium|251023T2345|2|15`,
      "the frozen chain carrier authenticates its complete resolved geometry",
    );
    for (const [binding, message] of [
      [{ ...BINDING, chainKey: true }, /contentKey binding cannot name a chain-key kind/],
      [
        { ...BINDING, chainsPerDay: 2, periodMinutes: 15 },
        /contentKey binding cannot name a chain-key kind/,
      ],
      [
        {
          renderId: RENDER_ID,
          accessGroup: "premium",
          t: "251023T1400",
          chainsPerDay: 2,
          periodMinutes: 15,
        },
        /geometry belongs only/,
      ],
      [
        {
          renderId: RENDER_ID,
          accessGroup: "premium",
          suppliedT: "251023T2345",
          chainKey: true,
          chainsPerDay: 2,
        },
        /periodMinutes is a positive integer/,
      ],
      [
        {
          renderId: RENDER_ID,
          accessGroup: "premium",
          suppliedT: "251023T2345",
          chainKey: true,
          chainsPerDay: 2,
          periodMinutes: 0,
        },
        /periodMinutes is a positive integer/,
      ],
      [{ renderId: RENDER_ID, chainKey: true }, null],
    ]) {
      await refuses(() => bindValue(/** @type {any} */ (binding)), {
        code: "binding_failed",
        ...(message === null ? {} : { message }),
      });
    }
  },
);

// A binding of `null` is not the Binding record bindValue declares, so this
// refusal of the case above runs under portable-core-dynamic.
portableCoreDynamicTest("bindValue refuses a binding that is not a record", async () => {
  await refuses(() => bindValue(/** @type {any} */ (null)), {
    code: "binding_failed",
    message: /binding is an object naming one coordinate/,
  });
});

test("ECDH sealing requires the fixed curve and an explicit nonce source", async () => {
  const p256 = await issuerKeypair();
  const p384 = await generateEcdhKeyPair("P-384");
  const key = new Uint8Array(16).fill(0x2a);
  const random = { bytes: (/** @type {number} */ n) => new Uint8Array(n).fill(0x19) };

  const blob = await seal(key, p256.publicKey, "ecdh-p256", { binding: BINDING, random });
  assert.deepEqual(
    await open(blob, p256.privateKey, "ecdh-p256", { binding: BINDING }),
    key,
    "the valid sibling seals and opens on P-256 with an explicit nonce source",
  );

  await refuses(() => seal(key, p384.publicKey, "ecdh-p256", { binding: BINDING, random }), {
    code: "bad_config",
    message: /fixes ECDH to P-256/,
  });
  await refuses(() => seal(key, p256.publicKey, "ecdh-p256", { binding: BINDING }), {
    code: "missing_random",
    message: /needs a Random for the blob nonce/,
  });
});

test("the period-key profile has one fixed width, and unknown names are refused", () => {
  assert.equal(periodKeyProfile(PERIOD_KEY_PROFILE).periodKeyBytes, 16);
  assert.equal(periodKeyProfile(PERIOD_KEY_PROFILE).wrapAlgorithm, "AES-128-GCM");

  for (const name of [
    "dca-profile-period-keys-8",
    "dca-profile-period",
    "DCA-PROFILE-PERIOD-KEYS",
    "",
    16,
    undefined,
    null,
  ]) {
    assert.throws(
      () => periodKeyProfile(/** @type {any} */ (name)),
      (error) => {
        assert.ok(error instanceof DcaError, `expected DcaError, got ${error}`);
        assert.equal(error.code, "unsupported_option");
        assert.match(error.message, /period-key profile/);
        return true;
      },
      `profile name ${JSON.stringify(name)}`,
    );
  }
});

// The portable twins of the case above. `undefined` runs only in the direct
// case, and the names that are not a string run in the dynamic twin.
portableCoreTest(
  "the period-key profile has one fixed width, and unknown string names are refused",
  () => {
    assert.equal(periodKeyProfile(PERIOD_KEY_PROFILE).periodKeyBytes, 16);
    assert.equal(periodKeyProfile(PERIOD_KEY_PROFILE).wrapAlgorithm, "AES-128-GCM");
    for (const name of UNKNOWN_PROFILE_NAMES) refusesProfileName(name);
  },
);

portableCoreDynamicTest("a period-key profile name that is not a string is refused", () => {
  for (const name of NOT_STRING_PROFILE_NAMES) refusesProfileName(name);
});

/** Values that are not a period-key label, all of them data a typed port can hold. */
const NOT_PERIOD_KEY_LABELS = [
  "",
  "251023T13",
  "251023T1",
  "251023T133",
  "251023T13300",
  "251023t13",
  "2510231300",
  " 251023T1300",
  ["251023T1300"],
  251023,
  null,
];

/**
 * Asserts the label shape: the check is lexical, and calendar ranges belong to
 * the producer, so month 13 passes here.
 *
 * @param {unknown[]} notLabels
 */
function checksPeriodKeyLabels(notLabels) {
  for (const label of ["251023T1300", "251023T1330", "251323T1300"]) {
    assert.equal(isPeriodKeyLabel(label), true, `${label} has the label shape`);
  }
  for (const value of notLabels) {
    assert.equal(
      isPeriodKeyLabel(value),
      false,
      `${JSON.stringify(value)} is not a period-key label, even where its string form is one`,
    );
  }
}

test("a period-key label is a string in the YYMMDDTHHMM shape", () => {
  checksPeriodKeyLabels([...NOT_PERIOD_KEY_LABELS, undefined]);
});

// The portable twin of the case above. `undefined` runs only in the direct
// case: a typed port has no argument that is present and undefined.
portableCoreTest("a period-key label is a string in the YYMMDDTHHMM shape, as data", () => {
  checksPeriodKeyLabels(NOT_PERIOD_KEY_LABELS);
});

// No portable twin: the cases turn on JavaScript value identity and on a present
// `undefined` member, which a bridge does not carry.
test("geometries agree by value identity, not by string form", () => {
  const numeric = { chainsPerDay: 2, periodMinutes: 60 };
  assert.equal(periodGeometriesAgree(numeric, { periodMinutes: 60, chainsPerDay: 2 }), true);
  assert.equal(periodGeometriesAgree(numeric, { chainsPerDay: "2", periodMinutes: "60" }), false);
  assert.equal(periodGeometriesAgree(numeric, { chainsPerDay: 2, periodMinutes: "60" }), false);
  assert.equal(
    periodGeometriesAgree({ periodMinutes: 60 }, { chainsPerDay: undefined, periodMinutes: 60 }),
    false,
    "a present undefined member is not an absent one",
  );
});

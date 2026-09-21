// @ts-check
//
// Public shared primitives refuse configuration mistakes with DCA's typed
// vocabulary. These are grouped by caller operation rather than one test per
// branch: each group first proves an honest input reaches the intended result,
// then changes only the option or key the refusal is about.

import test from "node:test";
import assert from "node:assert/strict";

import { seal, open } from "../../core-shared--publisher-issuer/keySealing.js";
import { sign, verify } from "../../core-shared--publisher-issuer/jwt.js";
import { periodsFor } from "../../core-shared--publisher-issuer/periodKeys.js";
import {
  BIND_VERSION,
  RENDER_ID_BYTES,
  bindValue,
} from "../../core-shared--publisher-issuer/bind.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";
import { DcaError } from "../../core-shared/errors.js";
import { EXACT_PERIOD_PROFILE, exactPeriodProfile } from "../../core-shared/exactPeriodProfiles.js";
import { generateEcdhKeyPair } from "../../core-shared/cryptoProvider.js";
import { isExactPeriodLabel } from "../../core-shared/periodLabels.js";
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

test("JWT fixes its header and requires the signing and verification keys it uses", async () => {
  const pair = await signingKeypair();
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
  ]) {
    await refuses(/** @type {() => unknown} */ (run), /** @type {any} */ (expected));
  }
});

test("period and binding inputs refuse silent empty or ambiguous interpretations", async () => {
  const now = new Date("2025-10-23T14:20:00Z");
  assert.deepEqual(periodsFor(now, { length: 60, slots: 2 }), ["251023T14", "251023T15"]);
  await refuses(() => periodsFor(now, { length: 60, slots: 0 }), {
    code: "bad_config",
    message: /slots must be a positive integer/,
  });

  assert.equal(bindValue(BINDING), `${BIND_VERSION}|c|${RENDER_ID}|bodytext`);
  await refuses(
    () =>
      bindValue({
        renderId: RENDER_ID,
        accessGroup: "premium",
        suppliedT: "251023T14",
        periodChain: true,
      }),
    { code: "binding_failed", message: /names its complete geometry/ },
  );
  assert.equal(
    bindValue({
      renderId: RENDER_ID,
      accessGroup: "premium",
      suppliedT: "251023T2345",
      periodChain: true,
      chainsPerDay: 2,
      periodMinutes: 15,
    }),
    `${BIND_VERSION}|pc|${RENDER_ID}|premium|251023T2345|2|15`,
    "the frozen chain carrier authenticates its complete resolved geometry",
  );
  for (const [binding, message] of [
    [{ ...BINDING, periodChain: true }, /contentKey binding cannot name a period-chain kind/],
    [
      { ...BINDING, chainsPerDay: 2, periodMinutes: 15 },
      /contentKey binding cannot name a period-chain kind/,
    ],
    [
      {
        renderId: RENDER_ID,
        accessGroup: "premium",
        t: "251023T14",
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
        periodChain: true,
        chainsPerDay: 2,
      },
      /periodMinutes is a positive integer/,
    ],
    [
      {
        renderId: RENDER_ID,
        accessGroup: "premium",
        suppliedT: "251023T2345",
        periodChain: true,
        chainsPerDay: 2,
        periodMinutes: 0,
      },
      /periodMinutes is a positive integer/,
    ],
    [{ renderId: RENDER_ID, periodChain: true }, null],
    [null, /binding is an object naming one coordinate/],
  ]) {
    await refuses(() => bindValue(/** @type {any} */ (binding)), {
      code: "binding_failed",
      ...(message === null ? {} : { message }),
    });
  }
});

test("ECDH sealing requires the fixed curve and an explicit nonce source", async () => {
  const p256 = await issuerKeypair();
  const p384 = await generateEcdhKeyPair("P-384");
  const key = new Uint8Array(16).fill(0x2a);
  const random = { bytes: (/** @type {number} */ n) => new Uint8Array(n).fill(0x19) };

  const blob = await seal(key, p256.publicKey, "ECDH-P256", { binding: BINDING, random });
  assert.deepEqual(
    await open(blob, p256.privateKey, "ECDH-P256", { binding: BINDING }),
    key,
    "the valid sibling seals and opens on P-256 with an explicit nonce source",
  );

  await refuses(() => seal(key, p384.publicKey, "ECDH-P256", { binding: BINDING, random }), {
    code: "bad_config",
    message: /fixes ECDH to P-256/,
  });
  await refuses(() => seal(key, p256.publicKey, "ECDH-P256", { binding: BINDING }), {
    code: "missing_random",
    message: /needs a Random for the blob nonce/,
  });
});

test("the canonical exact-period profile has one fixed width, and unknown names are refused", () => {
  assert.equal(exactPeriodProfile(EXACT_PERIOD_PROFILE).leafBytes, 16);
  assert.equal(exactPeriodProfile(EXACT_PERIOD_PROFILE).wrapAlgorithm, "AES-128-GCM");

  for (const name of [
    "dca-v1-exact-period-8",
    "dca-v1-exact",
    "DCA-V1-EXACT-PERIOD",
    "",
    16,
    undefined,
    null,
  ]) {
    assert.throws(
      () => exactPeriodProfile(/** @type {any} */ (name)),
      (error) => {
        assert.ok(error instanceof DcaError, `expected DcaError, got ${error}`);
        assert.equal(error.code, "unsupported_option");
        assert.match(error.message, /exact-period profile/);
        return true;
      },
      `profile name ${JSON.stringify(name)}`,
    );
  }
});

test("an exact-period label is a string in the YYMMDDTHH or YYMMDDTHHMM shape", () => {
  // The check is lexical. Calendar ranges belong to the producer, so month 13 passes here.
  for (const label of ["251023T13", "251023T1330", "251323T13"]) {
    assert.equal(isExactPeriodLabel(label), true, `${label} has the label shape`);
  }
  for (const value of [
    "",
    "251023T1",
    "251023T133",
    "251023T13300",
    "251023t13",
    "2510231300",
    " 251023T13",
    ["251023T13"],
    251023,
    null,
    undefined,
  ]) {
    assert.equal(
      isExactPeriodLabel(value),
      false,
      `${JSON.stringify(value)} is not an exact-period label, even where its string form is one`,
    );
  }
});

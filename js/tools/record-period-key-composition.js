#!/usr/bin/env node
// @ts-check
//
// Records one period-key composition, the period key path with no sealed
// content key, into
// verification/fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition/.
// From the repository root, run:
//
//     node js/tools/record-period-key-composition.js
//     node js/tools/record-period-key-composition.js --check
//
// The story has three steps on one browser. Render A carries period-key
// envelopes and item wraps for two periods; the issuer grants only the
// current one, and the client opens A and keeps that one period key. Render
// B, at the same instant, opens from the kept period key without an issuer
// call. An hour later render C needs the next period; the issuer grants
// nothing, answers 401, and the client caches and opens nothing. The real
// Sealer, IssuerServer and Browser run every step. The recorder writes what a
// replay needs: the issuer and client setup, the markup of each render, each
// unlock exchange and the observations after each step. The replay test,
// js/test-vectors/period-key-composition.test.js, holds the assertions.
//
// `--check` writes nothing. It exits 0 only when three separate checks hold:
// the directory holds exactly the declared members, each member's bytes
// match its recorded sha256, and a fresh recording writes the same text for
// every generated file. It exits 1 when one of them does not hold and 2 when
// it cannot read the package at all. The last output line is a summary,
// because the claim runner keeps only that line.
//
// Everything a render normally draws fresh comes from fixed test inputs
// here: a seeded Random, a fixed clock, fixed period keys and a recorded ECDH
// ephemeral pair per envelope. None of these is a production default; each is
// passed to the Sealer explicitly. ECDSA still draws a fresh `k` per signature,
// so a regeneration keeps a recorded resourceJWT only after it verifies over
// the same header and payload (`retainRecordedSignature`). The client copies
// the token into its request, so retention happens before the client runs.
//
// `provenance.sourceCommit` in the manifest names the HEAD the payload bytes
// were recorded at, and `provenance.sourceScenario` names the scenario file as
// that commit holds it. A regeneration that writes the same payloads, and
// every `--check`, keeps the recorded pair, so a later commit or a later move
// of the scenario file is not drift.
//
// The keypairs were generated once with subtle.generateKey over P-256 and
// pasted in. They are published test keys; nothing is sealed to them but the
// three articles below.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { Sealer } from "../core-publisher/Sealer.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { Network } from "../demo/actors/Network.js";
import { Storage } from "../demo/actors/Storage.js";
import { Browser } from "../demo/actors/Browser.js";
import { IssuerServer } from "../demo/actors/IssuerServer.js";
import { IssuerKeyStore } from "../demo/support/IssuerKeyStore.js";
import { openingKeysOver } from "../demo/support/PublisherRegistrations.js";
import { publisherRegistrationsOver } from "../demo/support/provisioning.js";
import { Page } from "../demo/support/Page.js";
import { readArticle } from "../demo/scenarios/world.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  AT,
  CONTENT_NAME,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  SIGNING_KID,
  T_NEXT,
  T_NOW,
  UNLOCK_URL,
  article,
} from "../demo/scenarios/fixtures.js";
import { CHECKSUM_FILE, checksumsText } from "./checksums.js";
import { deterministicEcdhFixtureSealing } from "./vector-fixtures/deterministicEcdhSealing.js";
import { retainRecordedSignature } from "./make-vectors.js";

const { subtle } = globalThis.crypto;

export const PACKAGE_ID = "fixtures/v1/profiles/dca-profile-period-keys/issuer-client-composition";
export const PACKAGE_DIR = fileURLToPath(
  new URL(`../../verification/${PACKAGE_ID}/`, import.meta.url),
);
const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));

/** The scenario a new recording names; a kept recording names the path at its own commit. */
const SOURCE_SCENARIO = "js/test-profiles/dca-profile-period-keys.test.js";

export const MANIFEST_SCHEMA = "dca-fixture-package-manifest/v1";
export const PAYLOAD_FORMAT = "period-key-composition/v1";
export const MANIFEST_FILE = "manifest.json";
export const README_FILE = "README.md";

/** The members this recorder writes and hashes, in name order. */
const PAYLOAD_FILES = ["exchange.json", "expected.json", "inputs.json", "renders.json"];

/** Present in every package, and never hashed: the manifest declares, the README explains. */
const METADATA_FILES = [CHECKSUM_FILE, MANIFEST_FILE, README_FILE];

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/** The period after T_NEXT, which render C ships beside it. */
const T_AFTER_NEXT = "251023T1600";

/** @typedef {{ kty: string, crv: string, x: string, y: string, d?: string }} EcJwk */

/** The issuer's onboarding keypair. The publisher seals to its public half. */
const ISSUER_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "9Clr-EnNZCpIn_ngytYUaKgaJp_6NGznARGs6KX7yQI",
  y: "H_Ykk33ssm73D020l_Ew658hzGiHIM7P6oUFExYaQUE",
  d: "hqR19bDK4x7z0oRRJSQ1egEvA0urFopNGwfgN0FoFQU",
};

/** The publisher's ES256 signing key. The issuer holds its public half under `SIGNING_KID`. */
const SIGNING_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "b_RMDUMPBZxKwUMfNnVWJ1hg-cjphGmIpsTTSG1px3c",
  y: "qilmllZcaYnhArNxzXuCWQwAq6NMyeWXX1PLB5PGK9I",
  d: "Yt0cTpKdASWE3rCjJ0xJglYqthKDCUsklvHjt4L383Q",
};

/**
 * One ephemeral pair per period-key envelope, keyed `render|accessGroup|t`.
 * The render is in the key because renders A, B and C all seal the next
 * period, and a pair reused across renders would read as a producer shortcut.
 */
const EPHEMERAL_PRIVATE_JWKS = {
  [`A|${ACCESS_GROUP}|${T_NOW}`]: {
    kty: "EC",
    crv: "P-256",
    x: "UDTIvS9jWRTAJY_siWDhCKSeIWh0Kzh1R0zdQaq5pFA",
    y: "5bXrHMqrkleSoPczFYq6uWq2OO_4OId3rCxkx7BoIZg",
    d: "2uMWYPBIIuVIRuk7ApsyVX3qbdyyXO-BJgHF0cbtNnU",
  },
  [`A|${ACCESS_GROUP}|${T_NEXT}`]: {
    kty: "EC",
    crv: "P-256",
    x: "sqQj4gzOmGfqT68VKnwXG64-7EgrlsERt0LGMVhG6e8",
    y: "S8cqITRkQZPZwMYIDg2tgIsYao28xeEnzZ_1DXvWop0",
    d: "dQQcprUMrSb-JpKf7sHyFj-NOFHQATFMglLC6lk4jfg",
  },
  [`B|${ACCESS_GROUP}|${T_NOW}`]: {
    kty: "EC",
    crv: "P-256",
    x: "dFBucYmVTktjpOYDmvXKlcJngKLS3yWZ9eFTAKB6chY",
    y: "94UD_4UqLErXga3gAPqTxvo7gIbP9xqu4Pd_1oWQKWA",
    d: "yHX5Lh6NrBOAgEf5YvHqhIGvSbgEevpsdan66SB6D3c",
  },
  [`B|${ACCESS_GROUP}|${T_NEXT}`]: {
    kty: "EC",
    crv: "P-256",
    x: "lNQG4yuaj-_B-xUKlbCX-jI9g9Fc8grMr1e9mf-Op74",
    y: "eCnGBJOh9VmiAxvCCGSKcDt4jZbEbTsT-rAiMvd7fJg",
    d: "8m6KH-3HSPQ8h_vTAlBfNbTb2HTNaSysmgTXj1oD9So",
  },
  [`C|${ACCESS_GROUP}|${T_NEXT}`]: {
    kty: "EC",
    crv: "P-256",
    x: "zy1f7nsm-dXCot1cUpFjmG-6RwMP0mtwZjKzv8pYKns",
    y: "TY3E8fSk0ixs5JvncAq5gHzz5cCp7EfSUKxFFcOBwGU",
    d: "VHTy8QDQe7fOXEtIVr-LouDkEQdT-a_ABYrXm5SXPFY",
  },
  [`C|${ACCESS_GROUP}|${T_AFTER_NEXT}`]: {
    kty: "EC",
    crv: "P-256",
    x: "kPTGDvhGLSidHyH8r1fJdigBtYILgAYPt6yvG4IwTPY",
    y: "N_jlbA9jdJkSQa_0hGALqYqQnmWtaj2NyOLqcFK52hw",
    d: "vsWo2dReZhLqe4iLC5wK9fgtHzHo_7nFjPS5uMF9rn0",
  },
};

/** Publisher-private period keys, 16 bytes each, for every coordinate the story seals. */
const PERIOD_KEYS = {
  [ACCESS_GROUP]: {
    [T_NOW]: "Etewfq8XLudt0AXLRs7gqA",
    [T_NEXT]: "c_eiNwPkMfiPCSM1JRGpvA",
    [T_AFTER_NEXT]: "RcJD_g2ru_g2LHk1bREIUQ",
  },
};

const SEED = 20251023;
const PERIOD = { length: 60, slots: 2 };

/** The publisher supplies period keys only: no sealed content key, no chain key. */
const SUPPLY_PLAN = { contentKeyNames: [], suppliedAccessGroups: [ACCESS_GROUP] };

/** One render per step; the clock moves before a step when `advanceMs` says so. */
const STEPS = /** @type {const} */ ([
  { label: "A", advanceMs: 0 },
  { label: "B", advanceMs: 0 },
  { label: "C", advanceMs: 60 * 60 * 1000 },
]);

/** @typedef {{ contentNames: string[], periodGrants: { accessGroup: string, periods: string[] }[] }} IssuerDecision */

/**
 * What the issuer's access policy answers, in call order: one period for the
 * first request, nothing for the second. Render B makes no request.
 *
 * @type {IssuerDecision[]}
 */
export const ISSUER_DECISIONS = [
  { contentNames: [], periodGrants: [{ accessGroup: ACCESS_GROUP, periods: [T_NOW] }] },
  { contentNames: [], periodGrants: [] },
];

/** @param {EcJwk} jwk */
const publicHalf = ({ kty, crv, x, y }) => ({ kty, crv, x, y });

/** @param {unknown} value */
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

/** @param {Uint8Array} bytes */
async function sha256Hex(bytes) {
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * What a regeneration may carry forward from the package on disk. Anything
 * unreadable counts as absent, so a damaged package regenerates fresh values
 * and shows up as drift rather than stopping the check.
 *
 * @typedef {object} Prior
 * @property {(string|undefined)[]} resourceJWTs - by step
 * @property {Map<string, string>} payloads - payload file name to text
 * @property {string|undefined} sourceCommit
 * @property {string|undefined} sourceScenario - the scenario path at sourceCommit
 */

/**
 * @param {string} dir
 * @returns {Prior}
 */
export function readPrior(dir) {
  /** @type {Map<string, string>} */
  const payloads = new Map();
  for (const file of PAYLOAD_FILES) {
    try {
      payloads.set(file, readFileSync(dir + file, "utf8"));
    } catch {
      // absent: nothing to carry forward
    }
  }
  /** @type {(string|undefined)[]} */
  let resourceJWTs;
  try {
    const renders = JSON.parse(payloads.get("renders.json") ?? "null");
    resourceJWTs = renders.steps.map((/** @type {any} */ step) => step.resourceJWT);
  } catch {
    resourceJWTs = [];
  }
  let sourceCommit;
  let sourceScenario;
  try {
    const { provenance } = JSON.parse(readFileSync(dir + MANIFEST_FILE, "utf8"));
    sourceCommit = provenance.sourceCommit;
    sourceScenario = provenance.sourceScenario;
  } catch {
    sourceCommit = undefined;
    sourceScenario = undefined;
  }
  return { resourceJWTs, payloads, sourceCommit, sourceScenario };
}

/** The HEAD the recording ran in, as provenance. */
function currentCommit() {
  return execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  }).trim();
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function hasChainGeometry(value) {
  return JSON.stringify(value).includes('"chainsPerDay"');
}

/**
 * Refuses a recording that does not show the story. These are guards so a
 * broken exchange can never be written; the replay test holds the evidence.
 *
 * @param {{ renders: any[], exchanges: any[], observations: any[] }} recording
 */
function guardScenario({ renders, exchanges, observations }) {
  /** @param {boolean} holds @param {string} what */
  const refuseUnless = (holds, what) => {
    if (!holds) throw new Error(`refusing to record: ${what}`);
  };
  const granted = exchanges.find((exchange) => exchange.step === 1);
  refuseUnless(
    granted?.status === 200 &&
      JSON.stringify(
        (granted.body.keys?.periodKeys ?? [])
          .filter((/** @type {any} */ record) => record.accessGroup === ACCESS_GROUP)
          .map((/** @type {any} */ record) => record.period),
      ) === JSON.stringify([T_NOW]) &&
      JSON.stringify(granted.body.keys?.contentKeys) === "[]",
    "step 1 must grant only the current period and no content key",
  );
  refuseUnless(
    observations[1].unlock === null && !exchanges.some((exchange) => exchange.step === 2),
    "step 2 must open from the kept period key",
  );
  const denied = exchanges.find((exchange) => exchange.step === 3);
  refuseUnless(
    denied?.status === 401 && denied.body.keys === undefined,
    "step 3 must be refused with no keys",
  );
  refuseUnless(exchanges.length === 2, "the story has exactly two issuer exchanges");
  const cached = observations[2].cache.map((/** @type {any} */ entry) => entry.t);
  refuseUnless(
    JSON.stringify(cached) === JSON.stringify([T_NOW]),
    "only the granted period key is cached",
  );
  refuseUnless(
    renders.every((render) => !hasChainGeometry(render.markup)) &&
      exchanges.every((exchange) => !hasChainGeometry(exchange)),
    "no chain geometry may appear",
  );
  refuseUnless(
    renders.every((render) => !render.markup.includes('"contentKeys"')),
    "no render may carry a sealed content key",
  );
}

/**
 * Runs the story through the real Sealer, IssuerServer and Browser and
 * returns the text of every generated file, by name.
 *
 * @param {object} [options]
 * @param {Prior} [options.prior] - what the package on disk already holds
 * @param {IssuerDecision[]} [options.issuerDecisions] - the policy answers, in
 *   call order; a test changes them to reach the guard
 * @param {() => string} [options.sourceCommit] - consulted only when the
 *   payload bytes changed
 * @param {() => string} [options.sourceScenario] - consulted only when the
 *   payload bytes changed
 * @returns {Promise<Map<string, string>>}
 */
export async function recordComposition(options = {}) {
  const prior = options.prior ?? {
    resourceJWTs: [],
    payloads: new Map(),
    sourceCommit: undefined,
    sourceScenario: undefined,
  };
  const issuerDecisions = options.issuerDecisions ?? ISSUER_DECISIONS;

  const issuerPublicKey = await subtle.importKey(
    "jwk",
    publicHalf(ISSUER_PRIVATE_JWK),
    ECDH_P256,
    true,
    [],
  );
  const issuerPrivateKey = await subtle.importKey("jwk", ISSUER_PRIVATE_JWK, ECDH_P256, false, [
    "deriveBits",
  ]);
  const signingPrivateKey = await subtle.importKey("jwk", SIGNING_PRIVATE_JWK, ECDSA_P256, false, [
    "sign",
  ]);
  const signingPublicKey = await subtle.importKey(
    "jwk",
    publicHalf(SIGNING_PRIVATE_JWK),
    ECDSA_P256,
    true,
    ["verify"],
  );
  /** @type {Map<string, CryptoKeyPair>} */
  const ephemeral = new Map();
  for (const [slot, jwk] of Object.entries(EPHEMERAL_PRIVATE_JWKS)) {
    ephemeral.set(slot, {
      publicKey: await subtle.importKey("jwk", publicHalf(jwk), ECDH_P256, true, []),
      privateKey: await subtle.importKey("jwk", jwk, ECDH_P256, false, ["deriveBits"]),
    });
  }

  const clock = new Clock(AT);
  const random = new Random({ seed: SEED });
  const network = new Network({ clock });

  const keyStore = new IssuerKeyStore([
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      privateKey: issuerPrivateKey,
      publicKey: issuerPublicKey,
    },
  ]);
  /** @type {object[]} */
  const presented = [];
  const server = new IssuerServer({
    clock,
    network,
    issuerName: ISSUER_NAME,
    unlockUrl: UNLOCK_URL,
    keyStore,
    publisherRegistrations: publisherRegistrationsOver(
      { [DOMAIN]: { [SIGNING_KID]: signingPublicKey } },
      openingKeysOver(keyStore, [{ issuerName: ISSUER_NAME, keyId: KEY_ID }]),
    ),
    accessPolicy: {
      decide(/** @type {unknown} */ _claims, /** @type {any} */ asked) {
        presented.push(JSON.parse(JSON.stringify(asked)));
        const decision = issuerDecisions[presented.length - 1];
        if (decision === undefined) throw new Error("the story has no further issuer decision");
        return structuredClone(decision);
      },
    },
    periodKeyInput: true,
    role: "primary",
  });

  /** @type {any[]} */
  const exchanges = [];
  let step = 0;
  const browser = new Browser({
    clock,
    storage: new Storage(),
    issuers: [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }],
    relayPeriodKeys: true,
    network: {
      async post(/** @type {string} */ url, /** @type {any} */ request, /** @type {any} */ opts) {
        const answer = await network.post(url, request, opts);
        exchanges.push({
          step,
          url,
          origin: opts?.origin ?? null,
          request: JSON.parse(JSON.stringify(request)),
          status: answer.status,
          body: JSON.parse(JSON.stringify(answer.body)),
        });
        return answer;
      },
    },
  });

  /** @type {any[]} */
  const renders = [];
  /** @type {any[]} */
  const observations = [];
  for (const [index, { label, advanceMs }] of STEPS.entries()) {
    step = index + 1;
    clock.advance(advanceMs);
    const content = article(label);
    const sealer = new Sealer({
      origin: ORIGIN,
      clock,
      random,
      signingKeys: { [SIGNING_KID]: signingPrivateKey },
      signingKid: SIGNING_KID,
      period: PERIOD,
      // Strict: a coordinate the story did not fix is an error, never a fresh key.
      periodKeySupply: {
        async derive(/** @type {string} */ accessGroup, /** @type {string} */ t) {
          const encoded = /** @type {Record<string, Record<string, string>>} */ (PERIOD_KEYS)[
            accessGroup
          ]?.[t];
          if (encoded === undefined) throw new Error(`no fixed period key for ${accessGroup}/${t}`);
          return base64urlDecode(encoded);
        },
      },
      issuerSupplyPlanFor: () => structuredClone(SUPPLY_PLAN),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuerPublicKey,
        },
      ],
      keySealing: deterministicEcdhFixtureSealing((_publicKey, /** @type {any} */ binding) =>
        binding.contentName === undefined && binding.chainKey !== true
          ? ephemeral.get(`${label}|${binding.accessGroup}|${binding.t}`)
          : undefined,
      ),
    });
    sealer.resource(content.resourceId, content.data);
    for (const item of content.items) {
      sealer.content(item.name, item.value, item.contentType, { accessGroups: item.accessGroups });
    }
    const { dcaData, sealedContent } = await sealer.seal();
    dcaData.resourceJWT = await retainRecordedSignature(
      dcaData.resourceJWT,
      prior.resourceJWTs[index],
      signingPublicKey,
    );

    const markup = writeMarkupDelivery({ dcaData, sealedContent });
    renders.push({
      step,
      label,
      clockIso: clock.now().toISOString(),
      publisherOrigin: ORIGIN,
      coordinates: dcaData.issuerData
        .find((entry) => entry.issuerName === ISSUER_NAME)
        .sealed.periodKeys.reduce((groups, { accessGroup, period }) => {
          (groups[accessGroup] ??= []).push(period);
          return groups;
        }, {}),
      resourceJWT: dcaData.resourceJWT,
      markup,
    });

    const decisionsBefore = presented.length;
    // The client here reads the render's values; the replay reads the recorded
    // markup, so the two delivery forms have to meet in the recorded request.
    const page = new Page({ publisherOrigin: ORIGIN, dcaData, sealedContent });
    const read = await readArticle(browser, page, [CONTENT_NAME]);
    const cache = (await browser.cache.entries()).map(({ familyName, t, key }) => {
      if (!(key instanceof Uint8Array)) throw new Error("the story expects raw cached period keys");
      return { familyName, t, key: base64urlEncode(key) };
    });
    const issuer = server.stats();
    observations.push({
      step,
      texts: read.texts,
      errors: read.errors,
      unlock: read.unlock,
      presented: presented.slice(decisionsBefore),
      cache,
      browserUnlocks: browser.stats().unlocks,
      issuer: { requests: issuer.requests, grants: issuer.grants, denials: issuer.denials },
    });
  }

  guardScenario({ renders, exchanges, observations });

  const inputs = {
    format: PAYLOAD_FORMAT,
    description:
      "Issuer and client setup for the replay. The publisher-side secrets that sealed the " +
      "renders (signing private key, ephemeral pairs, seed) stay in the recorder.",
    clock: { start: AT, steps: STEPS.map(({ label, advanceMs }) => ({ label, advanceMs })) },
    publisherOrigin: ORIGIN,
    issuer: {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      unlockUrl: UNLOCK_URL,
      publicKeyJwk: publicHalf(ISSUER_PRIVATE_JWK),
      privateKeyJwk: ISSUER_PRIVATE_JWK,
    },
    publisherRegistration: {
      domain: DOMAIN,
      kid: SIGNING_KID,
      publicKeyJwk: publicHalf(SIGNING_PRIVATE_JWK),
    },
    period: PERIOD,
    periodKeys: PERIOD_KEYS,
    supplyPlan: SUPPLY_PLAN,
    issuerDecisions,
    client: { relayPeriodKeys: true, contentNames: [CONTENT_NAME] },
  };

  /** @type {Map<string, string>} */
  const outputs = new Map([
    [
      "exchange.json",
      json({
        format: PAYLOAD_FORMAT,
        description: "Each unlock the client posted, with the issuer's status and body.",
        exchanges,
      }),
    ],
    [
      "expected.json",
      json({
        format: PAYLOAD_FORMAT,
        description:
          "What the client and issuer observed after each step: opened text, per-item error, " +
          "unlock result, what the policy was asked, the cached period keys and the counters.",
        steps: observations,
      }),
    ],
    ["inputs.json", json(inputs)],
    [
      "renders.json",
      json({
        format: PAYLOAD_FORMAT,
        description:
          "The markup delivery of each render. `resourceJWT` repeats the token in the markup " +
          "so a regeneration can retain its signature without parsing markup.",
        steps: renders,
      }),
    ],
  ]);

  const unchanged = PAYLOAD_FILES.every((file) => prior.payloads.get(file) === outputs.get(file));
  // The scenario path belongs to the commit: unchanged payloads keep the
  // recorded pair, and a new recording names today's path at today's HEAD.
  const carried = unchanged && prior.sourceCommit !== undefined;
  const sourceCommit = carried ? prior.sourceCommit : (options.sourceCommit ?? currentCommit)();
  const sourceScenario =
    (carried ? prior.sourceScenario : options.sourceScenario?.()) ?? SOURCE_SCENARIO;

  /** @type {{ path: string, sha256: string }[]} */
  const members = [];
  for (const path of PAYLOAD_FILES) {
    members.push({
      path,
      sha256: await sha256Hex(utf8Encode(/** @type {string} */ (outputs.get(path)))),
    });
  }
  outputs.set(MANIFEST_FILE, json(manifestFor(members, sourceCommit, sourceScenario)));
  outputs.set(
    CHECKSUM_FILE,
    await checksumsText(
      PAYLOAD_FILES.map((file) => ({
        file,
        bytes: utf8Encode(/** @type {string} */ (outputs.get(file))),
      })),
    ),
  );
  return outputs;
}

/**
 * @param {{ path: string, sha256: string }[]} members
 * @param {string} sourceCommit
 * @param {string} sourceScenario
 */
function manifestFor(members, sourceCommit, sourceScenario) {
  return {
    schema: MANIFEST_SCHEMA,
    package: PACKAGE_ID,
    profile: "dca-profile-period-keys",
    format: PAYLOAD_FORMAT,
    stability: "draft",
    scope: {
      roles: ["issuer", "client"],
      publisherSupply: "period-key envelopes and item wraps; no sealed content key; no chain key",
      transport: "direct",
      algorithms: ["ecdh-p256", "ES256", "AES-128-GCM"],
      issuers: 1,
      steps: [
        "render A: partial grant of the current period; the client opens A and keeps that period key",
        "render B: the kept period key opens B with no issuer call",
        "render C, an hour later: the next period is not granted; 401, nothing cached or opened",
      ],
    },
    provenance: {
      recorder: "js/tools/record-period-key-composition.js",
      sourceCommit,
      sourceScenario,
    },
    // The claim runner finds this package as a leaf directory, so the
    // directories above it hold no files of their own.
    discovery:
      "a leaf root found by discoverFixturePackageRoots (js/test-tools/claim-index.js); " +
      "verification/fixtures/v1/ and v1/profiles/ are path segments, not packages",
    members,
    consumers: [
      {
        path: "js/test-vectors/period-key-composition.test.js",
        role: "replay",
        description:
          "replays the recorded markup through the real Browser and IssuerServer and holds " +
          "the assertions",
      },
      {
        path: "js/test-tools/record-period-key-composition.test.js",
        role: "recorder self-test",
        description: "tests the package check: membership, checksums, regeneration and refusals",
      },
      {
        command: "node js/tools/record-period-key-composition.js --check",
        role: "package check",
        description:
          "membership both ways, per-member sha256 and a fresh recording; writes nothing",
      },
    ],
    limitations: [
      "All claim decisions are incomplete; this package decides no claim.",
      "It proves the period-key-only supply path through the real JavaScript issuer and client only.",
      "No chain keys, no client-bound transport and no independent conformance.",
      "The publisher is not replayed: renders are recorded markup, and ES256 signatures are " +
        "retained values, not reproducible bytes.",
      "One issuer, direct transport and ECDH-P256 envelopes only.",
    ],
  };
}

/**
 * What `--check` found. `status` is the exit code: 0 when every check held,
 * 1 when one did not, 2 when the package could not be read.
 *
 * @typedef {{ status: 0|1|2, findings: string[], summary: string }} CheckResult
 */

/**
 * Checks the package in `dir` without writing: membership both ways, each
 * member's bytes against its recorded sha256, then a fresh recording against
 * every generated file.
 *
 * @param {string} dir - with a trailing slash
 * @returns {Promise<CheckResult>}
 */
export async function checkPackage(dir) {
  /** @param {string} reason @returns {CheckResult} */
  const cannotRun = (reason) => ({
    status: 2,
    findings: [],
    summary: `period-key composition check could not run: ${reason}`,
  });
  if (!existsSync(dir)) return cannotRun(`no package directory at ${dir}`);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(dir + MANIFEST_FILE, "utf8"));
  } catch {
    return cannotRun(`${MANIFEST_FILE} is missing or not JSON`);
  }
  if (manifest?.schema !== MANIFEST_SCHEMA) {
    return cannotRun(`${MANIFEST_FILE} does not declare ${MANIFEST_SCHEMA}`);
  }
  if (!Array.isArray(manifest.members)) return cannotRun(`${MANIFEST_FILE} lists no members`);

  /** @type {string[]} */
  const findings = [];
  /** @type {string[]} */
  const declared = manifest.members.map((/** @type {any} */ member) => member?.path);
  const sorted = [...new Set(declared)].sort();
  if (JSON.stringify(sorted) !== JSON.stringify(declared)) {
    findings.push("membership: manifest members are not unique and in name order");
  }

  // Membership, both ways: every entry on disk is declared, every declared file is there.
  const expected = new Set([...METADATA_FILES, ...declared]);
  const entries = readdirSync(dir, { withFileTypes: true });
  const present = new Set();
  for (const entry of entries) {
    if (!entry.isFile()) {
      findings.push(`membership: extra ${entry.name}/ (a package holds files only)`);
    } else if (!expected.has(entry.name)) {
      findings.push(`membership: extra ${entry.name}`);
    } else {
      present.add(entry.name);
    }
  }
  for (const name of [...expected].sort()) {
    if (!present.has(name)) findings.push(`membership: missing ${name}`);
  }

  /** @type {Map<string, string>} */
  const sums = new Map();
  if (present.has(CHECKSUM_FILE)) {
    for (const line of readFileSync(dir + CHECKSUM_FILE, "utf8").split("\n")) {
      const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
      if (match) sums.set(match[2], match[1]);
      else if (line !== "") findings.push(`membership: ${CHECKSUM_FILE} has an unreadable line`);
    }
    for (const name of sums.keys()) {
      if (!declared.includes(name)) findings.push(`membership: ${CHECKSUM_FILE} names ${name}`);
    }
    for (const name of declared) {
      if (!sums.has(name)) findings.push(`membership: ${CHECKSUM_FILE} omits ${name}`);
    }
  }

  // Integrity: a hand edit shows up here even when a regeneration would repair it.
  for (const member of manifest.members) {
    if (!present.has(member?.path)) continue;
    const actual = await sha256Hex(readFileSync(dir + member.path));
    if (member.sha256 !== actual) findings.push(`checksum: ${member.path} (${MANIFEST_FILE})`);
    if (sums.has(member.path) && sums.get(member.path) !== actual) {
      findings.push(`checksum: ${member.path} (${CHECKSUM_FILE})`);
    }
  }

  // Regeneration: a fresh recording, keeping only signatures that still verify
  // over the same header and payload, must write the same text.
  const prior = readPrior(dir);
  let fresh;
  try {
    fresh = await recordComposition({
      prior,
      // A check never mints provenance: it compares against the recorded pair.
      sourceCommit: () => prior.sourceCommit ?? "(no recorded commit)",
      sourceScenario: () => prior.sourceScenario ?? "(no recorded scenario)",
    });
  } catch (cause) {
    findings.push(`drift: a fresh recording was refused: ${/** @type {Error} */ (cause).message}`);
  }
  if (fresh !== undefined) {
    for (const [name, text] of fresh) {
      if (!present.has(name)) continue;
      if (readFileSync(dir + name, "utf8") !== text) findings.push(`drift: ${name}`);
    }
  }

  if (findings.length > 0) {
    return {
      status: 1,
      findings,
      summary: `period-key composition check failed: ${findings.length} finding${findings.length === 1 ? "" : "s"}`,
    };
  }
  return {
    status: 0,
    findings,
    summary: `${present.size} recorded files match membership, checksums and a fresh recording`,
  };
}

/**
 * Writes a fresh recording into `dir`. A frozen package is never rewritten:
 * changed bytes after a freeze are a new package revision.
 *
 * @param {string} dir - with a trailing slash
 * @returns {Promise<string[]>} the files written
 */
export async function writePackage(dir) {
  if (existsSync(dir + MANIFEST_FILE)) {
    let stability;
    try {
      stability = JSON.parse(readFileSync(dir + MANIFEST_FILE, "utf8")).stability;
    } catch {
      stability = undefined;
    }
    if (stability === "frozen") {
      throw new Error(
        `${PACKAGE_ID} is frozen, and this run would overwrite it. ` +
          "Changed bytes after a freeze are a new revision, not a regeneration.",
      );
    }
  }
  const outputs = await recordComposition({ prior: readPrior(dir) });
  mkdirSync(dir, { recursive: true });
  for (const [name, text] of outputs) writeFileSync(dir + name, text);
  return [...outputs.keys()];
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
    console.error("usage: node js/tools/record-period-key-composition.js [--check]");
    process.exitCode = 2;
    return;
  }
  if (args[0] === "--check") {
    const result = await checkPackage(PACKAGE_DIR);
    for (const finding of result.findings) console.error(`  ${finding}`);
    (result.status === 0 ? console.log : console.error)(result.summary);
    process.exitCode = result.status;
    return;
  }
  for (const name of await writePackage(PACKAGE_DIR)) console.log(`wrote ${PACKAGE_ID}/${name}`);
  if (!existsSync(PACKAGE_DIR + README_FILE)) {
    console.error(`${PACKAGE_ID}/${README_FILE} is missing; --check requires it`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error);
    console.error(`period-key composition recorder could not run: ${error?.message ?? error}`);
    process.exitCode = 2;
  });
}

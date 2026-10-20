#!/usr/bin/env node
// @ts-check
//
// Records one chain-key prefix composition, chain-key-only publisher supply
// through a returned cutoff key, into
// verification/fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix/.
// From the repository root, run:
//
//     node js/tools/record-chain-keys-prefix.js
//     node js/tools/record-chain-keys-prefix.js --check
//
// The story runs on one browser and one issuer whose clock stays at 14:20 on
// 2025-10-23. The publisher renders one item at each period from 12:00 through
// 14:15, the window start through the cutoff, and one item at each of three
// coordinates the cutoff cannot reach: 14:30 in the same window, 11:45 in the
// preceding window and 00:00 in the next day's first window. Each render
// supplies one sealed chain member and wraps its item at its own coordinate
// only. The client reads the 14:15 item first; the issuer's policy answers one
// period and the issuer returns the chain key at 14:15. The client then opens
// every earlier prefix item from that retained key without an issuer call, and
// tries the three out-of-reach items with no unlock: each stays missing and
// unopened, and what the client retains does not change. The real Sealer,
// IssuerServer and Browser run every step. The recorder writes what a replay
// needs: the issuer and client setup, the markup of each render, the one
// unlock exchange, the expected facts and the observations after each read.
// The replay test, js/test-vectors/chain-keys-prefix.test.js, holds the
// assertions.
//
// The expected cutoff key, prefix period keys and Leaf context bytes are copied
// from case c1 of the frozen construction vectors,
// js/extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json.
// A generator that does not import the extension wrote that file, so those
// facts are a witness the code under test did not produce. The recorder refuses
// to write a story that disagrees with them.
//
// `--check` writes nothing. It exits 0 only when three separate checks hold:
// the directory holds exactly the declared members, each member's bytes
// match its recorded sha256, and a fresh recording writes the same text for
// every generated file. It exits 1 when one of them does not hold and 2 when
// it cannot read the package at all. The last output line is a summary,
// because the claim runner keeps only that line.
//
// Everything a render normally draws fresh comes from fixed test inputs
// here: a seeded Random, a fixed publisher clock per render, the fixed
// key-derivation secret of case c1 and a recorded ECDH ephemeral pair per chain
// envelope. None of these is a production default; each is passed to the
// Sealer explicitly. ECDSA still draws a fresh `k` per signature, so a
// regeneration keeps a recorded resourceJWT only after it verifies over the
// same header and payload (`retainRecordedSignature`). The client copies the
// token into its request, so retention happens before the client runs.
//
// `provenance.sourceCommit` in the manifest names the HEAD the payload bytes
// were recorded at, and `provenance.sourceScenario` names the scenario file as
// that commit holds it. A regeneration that writes the same payloads, and
// every `--check`, keeps the recorded pair, so a later commit or a later move
// of the scenario file is not drift.
//
// The keypairs were generated once with subtle.generateKey over P-256 and
// pasted in. They are published test keys; nothing is sealed to them but the
// thirteen bulletins below.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { Sealer } from "../core-publisher/Sealer.js";
import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../core-shared/codec.js";
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
import { rootFromPage } from "../demo/support/queryableRoot.js";
import {
  ACCESS_GROUP,
  ALGORITHM,
  CONTENT_NAME,
  CONTENT_TYPE,
  DOMAIN,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  SIGNING_KID,
  UNLOCK_URL,
  keyDerivationSecret,
} from "../demo/scenarios/fixtures.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import { periodFamilySupply } from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { ChainKeyCache } from "../extensions/chain-keys/core-client/ChainKeyCache.js";
import { ChainKeyRequestBuilder } from "../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { referenceChainKeyProfile } from "../extensions/chain-keys/referenceProfile.js";
import { CHECKSUM_FILE, checksumsText } from "./checksums.js";
import { deterministicEcdhFixtureSealing } from "./vector-fixtures/deterministicEcdhSealing.js";
import { retainRecordedSignature } from "./make-vectors.js";

const { subtle } = globalThis.crypto;

export const PACKAGE_ID = "fixtures/v1/profiles/dca-profile-chain-keys/issuer-client-prefix";
export const PACKAGE_DIR = fileURLToPath(
  new URL(`../../verification/${PACKAGE_ID}/`, import.meta.url),
);
const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));

/** The scenario a new recording names; a kept recording names the path at its own commit. */
const SOURCE_SCENARIO = "js/test-profiles/dca-profile-chain-keys.test.js";

/** The frozen construction vectors and the case whose facts this story must match. */
export const WITNESS_SOURCE =
  "js/extensions/chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json";
const WITNESS_CASE = "c1";

export const MANIFEST_SCHEMA = "dca-fixture-package-manifest/v1";
export const PAYLOAD_FORMAT = "chain-keys-prefix/v1";
export const MANIFEST_FILE = "manifest.json";
export const README_FILE = "README.md";

/** The members this recorder writes and hashes, in name order. */
const PAYLOAD_FILES = ["exchange.json", "expected.json", "inputs.json", "renders.json"];

/** Present in every package, and never hashed: the manifest declares, the README explains. */
const METADATA_FILES = [CHECKSUM_FILE, MANIFEST_FILE, README_FILE];

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/** The issuer's and client's clock for the whole story. */
const ISSUER_NOW = "2025-10-23T14:20:00Z";

/** Two windows a day of fifteen-minute periods, the geometry of case c1. */
const GEOMETRY = { chainsPerDay: 2, periodMinutes: 15 };

/**
 * The window start through the cutoff, spelled out rather than derived, so the
 * reach is pinned to the labels and not to the code that computes them.
 */
const PREFIX = [
  "251023T1200",
  "251023T1215",
  "251023T1230",
  "251023T1245",
  "251023T1300",
  "251023T1315",
  "251023T1330",
  "251023T1345",
  "251023T1400",
  "251023T1415",
];
const CUTOFF = "251023T1415";

/** Coordinates the cutoff key cannot reach, one per reason. */
const OUT_OF_REACH = [
  { t: "251023T1430", relation: "later position in the cutoff's window" },
  { t: "251023T1145", relation: "preceding window" },
  { t: "251024T0000", relation: "next window" },
];

/** The publisher renders in time order: the preceding window first, the next window last. */
const RENDER_ORDER = ["251023T1145", ...PREFIX, "251023T1430", "251024T0000"];

/**
 * What the client does, in order. The first read may unlock; every other
 * prefix read may too, and a read that does would show up as a second
 * exchange. The out-of-reach reads never unlock: they ask what the one
 * retained cutoff key opens, not what a new grant would add.
 */
const READS = [
  { t: CUTOFF, unlock: "when-missing" },
  ...PREFIX.filter((t) => t !== CUTOFF).map((t) => ({ t, unlock: "when-missing" })),
  ...OUT_OF_REACH.map(({ t }) => ({ t, unlock: "never" })),
];

/** @typedef {{ kty: string, crv: string, x: string, y: string, d?: string }} EcJwk */

/** The issuer's onboarding keypair. The publisher seals to its public half. */
const ISSUER_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "Ul-t3u3M3Dwft12wyY3lO_9wnx5nxQRwqRCx1LUMV7k",
  y: "nDQ831uDUHCbmx03qpCljzC-ACqHfUt1jdXsXsvKrH0",
  d: "WTBU2cvrufqZUYZZX1CLNh8bph1jxlz715tRo7BsTxw",
};

/** The publisher's ES256 signing key. The issuer holds its public half under `SIGNING_KID`. */
const SIGNING_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "ktBicRn-tH7QewFnS3Z7k08tb1HhdPp4LtT6KheWEkg",
  y: "UwSW7q_nM8Kv8KY24dip3Z1jWsuvZiebv5REQgSC_xE",
  d: "1vhRtcQHoAKKuiO4Wc_Ty1kqYFenL_hoyixkxc1Lsc0",
};

/**
 * One ephemeral pair per chain envelope, keyed `render|suppliedT`. Each render
 * supplies the terminal of its own window, so eleven renders seal the same
 * 23:45 member, and a pair reused across them would read as a producer
 * shortcut.
 */
const EPHEMERAL_PRIVATE_JWKS = {
  "251023T1145|251023T1145": {
    kty: "EC",
    crv: "P-256",
    x: "l46gjq-H66jCVPnKhjPRKJUYK2GSimmaDmFIyGUWCyU",
    y: "6oPu7ythZK3P1RqSOn3km-x4fVf3Q-GDDFMGHSfcFUU",
    d: "C3U5lTfcdLpUlzXef_EJsqGH3U2uSH2TMcTgrpzLDyQ",
  },
  "251023T1200|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "9DW-ZcM9L_VaOJLhZLM6GWB9zRAtQQve4c6PGY-HS7A",
    y: "KJ5OYa-CSmxTf5AtcWAXYJ1QF1gcYtH0-2PmaD9F3nI",
    d: "O2ydVwht3Yfj9iS5qdDOGb-uGPUTDhWzyP02dJsYCL8",
  },
  "251023T1215|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "P1ynrjvGYZtdX9IH0vg7t4B_ggrlnJTMicV4b_13TA0",
    y: "g3m7MQI23sBAGrRWgQhHGwmqNQ31LcSxsf7FxNhQvYM",
    d: "IDMnZQXWHKktR5q0UMDn1idm_QPjl17kySJniSV8YFs",
  },
  "251023T1230|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "RW0cSNjBopLak33T0kNDfncFv8xWDPZ13jq97po6ue0",
    y: "4ZUeD5LXEKeEYKgVfqxSFxTtdveSa6lcuF8d_7Rahc0",
    d: "5WrzzhvBlzzB-OUNBaN1eoaUGjiqMR3YvwU8KNuB1ec",
  },
  "251023T1245|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "I5ADvIubqY88aRQ6Gzo0AMLBCqjkz5B0m-StyETL0F0",
    y: "3Q9oljazyRVlAZOK9mB8uLb9CzMiaCcNQL2PPnf2gSo",
    d: "j1uQ-GexBuwzgkwlJ6pB6dgefAPYvLqwHCVJ0t4rD-w",
  },
  "251023T1300|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "6-d9dK32ZpBAiTjCfom8T-eRcXCwcqPeYBGL3SiOhQ0",
    y: "AKxOka33zx_jqqYlRWQSAHR1bITKa6-1cAcJYnB5Dcg",
    d: "3Cd_obuR-l3W5bUZqvOoiMM-yoLxwtGVPc7xKOfuyIU",
  },
  "251023T1315|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "Z6n23y2ZRX_rW60u03-8DQYhzWcjuk0qOkaSo29_nws",
    y: "LXYgnTCyJtQYRO-24OqsW-8iuFScEy9r53N4MjwGMkE",
    d: "Lk21R9K-IoLqqNqV1aXR7hRaozZFiUuvUT5OhBzKVEE",
  },
  "251023T1330|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "IAsOPzmnXZKg0grBaPkNHNSc4tSALNwKMGQlvFDrZsc",
    y: "L5RyRNw7KHozRTnHUx2eckcijcX3BFa9hqSyyWwO7jY",
    d: "jgu2Kp4xmlmq_lbLV1HDAu98PQOjoE2UEwLOiq6nGY0",
  },
  "251023T1345|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "XY_c4csozeGUSRPFNpK28PRviR7xLcYRVtbF8FEbp54",
    y: "Cy_QxleqRmi2Knb23DkAS6YPeWxjMWYuEQJhRWpozOM",
    d: "lH25nK8KFh-mCinRDXrGaCQPD8kzi1zWoB5C5GvCk0o",
  },
  "251023T1400|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "zmMFL38L0D-ml5-uvVnghoghc2H5VYvMlQlLTsIwYoU",
    y: "65rjDYm9QG_CA10A6IGFdm5DeIxo5y6sBburCxFsjTI",
    d: "S2UTaR51o0U5ui07K6sP_gJRwQubSwTCcA8RWWhg0Ls",
  },
  "251023T1415|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "au-Y-_lebTHNgeGafxYqgWoec2uVcT7mF8uE0T4AhNM",
    y: "QTsGLvKgbbrJhL2vw9TU03mcKUa5FegGFeAdUqnvVZY",
    d: "-LNC7AFj6GYRvYp6cMhH16wssECHIchexra1fvinl0I",
  },
  "251023T1430|251023T2345": {
    kty: "EC",
    crv: "P-256",
    x: "5kryQIc_cgbGOxllc94v6kDqO__N7fDr54d833V3Os0",
    y: "hgbq4rY1ujSFK9PvHiDOqLMKl35FA2VPkeQ36Jjjys0",
    d: "fKEbaHkUEQjvlswKxBgaSsooc7YX7YGlNeUaS1I0Fjw",
  },
  "251024T0000|251024T1145": {
    kty: "EC",
    crv: "P-256",
    x: "I63PDJ6nhnoGG8cxEeCMRtxt-UFy6ulzNxKpbyNtiYo",
    y: "wv1w7J96Ut59lYJfKGYQwJL6NhTLdxWpvk1qGVDAzHQ",
    d: "NvPXAxtWQ05zzYQaIp2lA1dnJySizlZ_84xRktNTbfk",
  },
};

const SEED = 20251023;

/** The fill of case c1's key-derivation secret, which stays in this recorder. */
const SECRET_FILL = 7;

/** One wrap per render: each item opens at its own coordinate and no other. */
const PERIOD = { slots: 1 };

/** Each render supplies one chain member, the terminal of its own window. */
const CHAIN_WINDOWS = 1;

/** The publisher supplies chain keys only: no sealed content key, no period-key member. */
const SUPPLY_PLAN = {
  contentKeyNames: [],
  suppliedAccessGroups: [ACCESS_GROUP],
  periodKeyDelivery: { [ACCESS_GROUP]: ["chain-keys"] },
};

/**
 * @typedef {{ contentNames: string[], periodGrants: { accessGroup: string, futurePeriodCount: number, authorizedPeriods: string[] }[] }}
 *   IssuerDecision
 */

/**
 * What the issuer's access policy answers, in call order: independent prefix authorization
 * with zero future horizon for the one request the story makes.
 *
 * @type {IssuerDecision[]}
 */
export const ISSUER_DECISIONS = [
  {
    contentNames: [],
    periodGrants: [
      { accessGroup: ACCESS_GROUP, futurePeriodCount: 0, authorizedPeriods: [...PREFIX] },
    ],
  },
];

/** @param {string} t - a fixed-form label, as the instant it starts */
const instant = (t) =>
  `20${t.slice(0, 2)}-${t.slice(2, 4)}-${t.slice(4, 6)}T${t.slice(7, 9)}:${t.slice(9, 11)}:00Z`;

/** @param {string} t - the known text the item sealed at `t` carries */
const bulletin = (t) => `<p>Harbour bulletin for period ${t}.</p>`;

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
 * Case c1 of the frozen construction vectors, refused unless it is this
 * story's family: the same access group, geometry, secret, window and cutoff.
 *
 * @returns {any}
 */
export function readWitness() {
  const vectors = JSON.parse(readFileSync(REPO_ROOT + WITNESS_SOURCE, "utf8"));
  const witness = vectors.cases.find((/** @type {any} */ entry) => entry.id === WITNESS_CASE);
  const matches =
    witness?.accessGroup === ACCESS_GROUP &&
    witness.chainsPerDay === GEOMETRY.chainsPerDay &&
    witness.periodMinutes === GEOMETRY.periodMinutes &&
    witness.secretHex === Buffer.from(keyDerivationSecret(SECRET_FILL)).toString("hex") &&
    witness.label === CUTOFF &&
    witness.position === PREFIX.length - 1 &&
    witness.windowStart * 60_000 === Date.parse(instant(PREFIX[0]));
  if (!matches)
    throw new Error(`${WITNESS_SOURCE} case ${WITNESS_CASE} is not this story's family`);
  return witness;
}

/**
 * What a regeneration may carry forward from the package on disk. Anything
 * unreadable counts as absent, so a damaged package regenerates fresh values
 * and shows up as drift rather than stopping the check.
 *
 * @typedef {object} Prior
 * @property {Map<string, string>} resourceJWTs - by render label
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
  /** @type {Map<string, string>} */
  let resourceJWTs;
  try {
    const renders = JSON.parse(payloads.get("renders.json") ?? "null");
    resourceJWTs = new Map(
      renders.renders.map((/** @type {any} */ render) => [render.t, render.resourceJWT]),
    );
  } catch {
    resourceJWTs = new Map();
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
 * What the client holds, by coordinate and kind: chain keys and their
 * memoized period keys, then base period keys. The family name stays out; it is a
 * reference cache key, not protocol data.
 *
 * @param {any} browser
 * @param {any} chainCache
 */
async function retainedBy(browser, chainCache) {
  return {
    chain: chainCache.entries().map(({ t, kind }) => ({ t, kind })),
    periodKeys: (await browser.cache.entries()).map(({ t }) => ({ t })),
  };
}

/**
 * Refuses a recording that does not show the story. These are guards so a
 * broken exchange can never be written; the replay test holds the evidence.
 *
 * @param {object} recording
 * @param {any[]} recording.renders
 * @param {any[]} recording.exchanges
 * @param {any[]} recording.observations
 * @param {any} recording.witness - case c1 of the frozen construction vectors
 * @param {Map<string, string>} recording.plantedPeriodKeys - the period key each render's wrap was made under
 */
function guardScenario({ renders, exchanges, observations, witness, plantedPeriodKeys }) {
  /** @param {boolean} holds @param {string} what */
  const refuseUnless = (holds, what) => {
    if (!holds) throw new Error(`refusing to record: ${what}`);
  };
  refuseUnless(
    renders.every(
      (render) =>
        JSON.stringify(render.wrapped) === JSON.stringify([render.t]) &&
        !render.markup.includes('"contentKeys"') &&
        !render.markup.includes('"periodKeys"') &&
        render.suppliedChain.length === 1,
    ),
    "every render wraps its item at its own coordinate and supplies one chain member only",
  );
  refuseUnless(exchanges.length === 1, "the story has exactly one issuer exchange");
  const [granted] = exchanges;
  refuseUnless(
    granted.step === 1 &&
      granted.status === 200 &&
      JSON.stringify(granted.body.keys) ===
        JSON.stringify({
          contentKeys: {},
          chainKeys: { [ACCESS_GROUP]: { [CUTOFF]: witness.cutoffChainKeys[CUTOFF] } },
        }),
    "the first read must return the witness chain key at the cutoff and nothing else",
  );
  for (const [position, t] of PREFIX.entries()) {
    refuseUnless(
      plantedPeriodKeys.get(t) === witness.expansion[position],
      `the publisher wrapped ${t} under a period key other than the witness period key`,
    );
    const read = observations.find((observation) => observation.t === t);
    refuseUnless(read?.texts[CONTENT_NAME] === bulletin(t), `${t} must open to its bulletin`);
  }
  // The prefix reads come first, so this is what the client holds after the last of them.
  const settled = JSON.stringify(observations[PREFIX.length - 1].retained);
  for (const { t } of OUT_OF_REACH) {
    const read = observations.find((observation) => observation.t === t);
    refuseUnless(
      read?.texts[CONTENT_NAME] === null &&
        read.errors[CONTENT_NAME] === "no_key" &&
        JSON.stringify(read.missing) === JSON.stringify([CONTENT_NAME]) &&
        JSON.stringify(read.retained) === settled,
      `${t} must stay missing and unopened with nothing retained`,
    );
  }
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
export async function recordPrefix(options = {}) {
  const prior = options.prior ?? {
    resourceJWTs: new Map(),
    payloads: new Map(),
    sourceCommit: undefined,
    sourceScenario: undefined,
  };
  const issuerDecisions = options.issuerDecisions ?? ISSUER_DECISIONS;
  const witness = readWitness();

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

  // The issuer and the client share one clock that never moves; the
  // publisher has its own, set to each render's coordinate.
  const clock = new Clock(ISSUER_NOW);
  const publisherClock = new Clock(ISSUER_NOW);
  const random = new Random({ seed: SEED });
  const network = new Network({ clock });

  const generation = periodFamilyGeneration({
    keyDerivationSecret: keyDerivationSecret(SECRET_FILL),
    geometry: GEOMETRY,
  });
  const supply = periodFamilySupply({
    families: { [ACCESS_GROUP]: generation },
    chainWindows: CHAIN_WINDOWS,
  });

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
        // The serialized horizon and authorized coordinates are independent
        // policy facts; neither response selection nor a nonzero count grants
        // the prefix.
        return {
          contentNames: [...decision.contentNames],
          periodGrants: decision.periodGrants.map(
            ({ accessGroup, futurePeriodCount, authorizedPeriods }) => ({
              accessGroup,
              futurePeriodCount,
              authorizePeriod: (t) => authorizedPeriods.includes(t),
            }),
          ),
        };
      },
    },
    periodKeyInput: false,
    periodGrantKind: "chain-keys",
    chainKeyProfile: referenceChainKeyProfile,
    role: "primary",
  });

  /** @type {any[]} */
  const exchanges = [];
  let step = 0;
  // No clock: the chain cache evicts nothing, so a refusal below is about reach.
  const chainCache = new ChainKeyCache({ strategy: "retain" });
  const browser = new Browser({
    clock,
    storage: new Storage(),
    issuers: [{ issuerName: ISSUER_NAME, unlockUrl: UNLOCK_URL }],
    relayPeriodKeys: false,
    chainKeyProfile: referenceChainKeyProfile,
    chainKeyCacheFactory: () => chainCache,
    chainKeyStrategy: "retain",
    requestBuilderFactory: (/** @type {object} */ opts) => new ChainKeyRequestBuilder(opts),
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
  /** @type {Map<string, Page>} */
  const pages = new Map();
  /** @type {Map<string, string>} the period key each render's wrap was made under */
  const plantedPeriodKeys = new Map();
  for (const t of RENDER_ORDER) {
    publisherClock.set(instant(t));
    const sealer = new Sealer({
      origin: ORIGIN,
      clock: publisherClock,
      random,
      signingKeys: { [SIGNING_KID]: signingPrivateKey },
      signingKid: SIGNING_KID,
      period: PERIOD,
      periodKeySupply: supply,
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
        binding.chainKey === true && binding.accessGroup === ACCESS_GROUP
          ? ephemeral.get(`${t}|${binding.suppliedT}`)
          : undefined,
      ),
    });
    sealer.resource(`bulletin-${t}`, { section: "harbour" });
    sealer.content(CONTENT_NAME, bulletin(t), CONTENT_TYPE, { accessGroups: [ACCESS_GROUP] });
    const { dcaData, sealedContent } = await sealer.seal();
    dcaData.resourceJWT = await retainRecordedSignature(
      dcaData.resourceJWT,
      prior.resourceJWTs.get(t),
      signingPublicKey,
    );
    plantedPeriodKeys.set(t, base64urlEncode(await generation.periodKey(ACCESS_GROUP, t)));

    const markup = writeMarkupDelivery({ dcaData, sealedContent });
    const relation = PREFIX.includes(t)
      ? "prefix"
      : /** @type {{ relation: string }} */ (OUT_OF_REACH.find((probe) => probe.t === t)).relation;
    renders.push({
      t,
      relation,
      renderedAt: publisherClock.now().toISOString(),
      publisherOrigin: ORIGIN,
      wrapped: dcaData.contentData[CONTENT_NAME].keys[ACCESS_GROUP].map(
        (/** @type {{ t: string }} */ wrap) => wrap.t,
      ),
      suppliedChain: Object.keys(dcaData.issuerData[ISSUER_NAME].sealed.chainKeys[ACCESS_GROUP]),
      resourceJWT: dcaData.resourceJWT,
      markup,
    });
    // The client here reads the render's values; the replay reads the recorded
    // markup, so the two delivery forms have to meet in the recorded request.
    pages.set(t, new Page({ publisherOrigin: ORIGIN, dcaData, sealedContent }));
  }

  /** @type {any[]} */
  const observations = [];
  for (const [index, { t, unlock: unlockMode }] of READS.entries()) {
    step = index + 1;
    const decisionsBefore = presented.length;
    const load = browser.load(rootFromPage(/** @type {Page} */ (pages.get(t))));
    const { missing } = await load.resolve([CONTENT_NAME]);
    const unlock = unlockMode === "when-missing" && missing.length > 0 ? await load.unlock() : null;
    const opened = await load.open(CONTENT_NAME);
    const issuer = server.stats();
    observations.push({
      step,
      t,
      missing,
      texts: { [CONTENT_NAME]: opened.bytes === null ? null : utf8Decode(opened.bytes) },
      errors: { [CONTENT_NAME]: opened.error },
      unlock,
      presented: presented.slice(decisionsBefore),
      retained: await retainedBy(browser, chainCache),
      browserUnlocks: browser.stats().unlocks,
      issuer: { requests: issuer.requests, grants: issuer.grants, denials: issuer.denials },
    });
  }

  guardScenario({ renders, exchanges, observations, witness, plantedPeriodKeys });

  const inputs = {
    format: PAYLOAD_FORMAT,
    description:
      "Issuer and client setup for the replay. The publisher-side secrets that sealed the " +
      "renders (key-derivation secret, signing private key, ephemeral pairs, seed) stay in " +
      "the recorder.",
    clock: { issuerAndClient: ISSUER_NOW },
    publisherOrigin: ORIGIN,
    issuer: {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      unlockUrl: UNLOCK_URL,
      publicKeyJwk: publicHalf(ISSUER_PRIVATE_JWK),
      privateKeyJwk: ISSUER_PRIVATE_JWK,
      input: "chain-keys",
      output: "chain-keys",
    },
    publisherRegistration: {
      domain: DOMAIN,
      kid: SIGNING_KID,
      publicKeyJwk: publicHalf(SIGNING_PRIVATE_JWK),
    },
    chainKeyConfiguration: { profile: "dca-profile-chain-keys", ...GEOMETRY },
    supplyPlan: SUPPLY_PLAN,
    issuerDecisions,
    client: {
      relay: "chain-keys",
      response: "chain-keys",
      chainRetention: "retain",
      contentNames: [CONTENT_NAME],
    },
    reads: READS,
  };

  const expected = {
    format: PAYLOAD_FORMAT,
    description:
      "Facts the replay asserts, then what the client and issuer observed after each read. " +
      "The witness, cutoff key and prefix period keys come from the frozen construction vectors, " +
      "not from the code under test.",
    witness: {
      source: WITNESS_SOURCE,
      case: WITNESS_CASE,
      accessGroup: ACCESS_GROUP,
      ...GEOMETRY,
      windowStart: witness.windowStart,
      cutoff: CUTOFF,
      position: witness.position,
      cutoffChainKey: witness.cutoffChainKeys[CUTOFF],
      leafInfoHex: witness.leafInfoHex,
    },
    response: {
      status: 200,
      contentKeys: {},
      periodKeys: "absent",
      chainKeys: { [ACCESS_GROUP]: { [CUTOFF]: witness.cutoffChainKeys[CUTOFF] } },
      geometry: { [ACCESS_GROUP]: GEOMETRY },
    },
    policyHorizon: {
      futurePeriodCount: issuerDecisions[0]?.periodGrants[0]?.futurePeriodCount ?? null,
      coordinates: [],
      note:
        "zero future periods selects no optional horizon; the cutoff article target is " +
        "authorized independently, and its returned chain key inherently reaches the " +
        "trusted-policy-authorized prefix below",
    },
    prefix: PREFIX.map((t, position) => ({
      t,
      position,
      periodKey: witness.expansion[position],
      plaintext: bulletin(t),
    })),
    outOfReach: OUT_OF_REACH.map(({ t, relation }) => ({
      t,
      relation,
      kind: "absence of reach: the retained cutoff key cannot derive this period key",
      missing: [CONTENT_NAME],
      plaintext: null,
      error: "no_key",
      retainedUnchanged: true,
      withheldPeriodKey: plantedPeriodKeys.get(t),
      withheldPeriodKeySource:
        t === "251023T1430"
          ? `${WITNESS_SOURCE} case ${WITNESS_CASE}, expansion position 10`
          : "the recorder's publisher generation; a control that the render is openable",
      sealedPlaintext: bulletin(t),
    })),
    retainedReuse: { issuerExchanges: 1, unlockedReads: [CUTOFF] },
    steps: observations,
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
    ["expected.json", json(expected)],
    ["inputs.json", json(inputs)],
    [
      "renders.json",
      json({
        format: PAYLOAD_FORMAT,
        description:
          "The markup delivery of each render, in render order. `resourceJWT` repeats the " +
          "token in the markup so a regeneration can retain its signature without parsing markup.",
        renders,
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
    profile: "dca-profile-chain-keys",
    format: PAYLOAD_FORMAT,
    stability: "draft",
    scope: {
      roles: ["issuer", "client"],
      publisherSupply:
        "chain-key-only: one sealed chain member per render and one item wrap at the render's own " +
        "coordinate; no sealed content key; no period-key member",
      transport: "direct",
      algorithms: ["ecdh-p256", "ES256", "AES-128-GCM", "HKDF-SHA-256"],
      geometry: GEOMETRY,
      issuers: 1,
      steps: [
        "thirteen renders: 12:00 through 14:15 (the prefix), 14:30, 11:45 and next-day 00:00",
        "read 14:15 at issuer time 14:20: policy authorizes the prefix independently and selects zero future periods; the issuer returns the chain key at 14:15",
        "read 12:00 through 14:00: each opens from the retained chain key with no issuer call",
        "try 14:30, 11:45 and next-day 00:00 with no unlock: each stays missing and unopened; nothing retained changes",
      ],
    },
    provenance: {
      recorder: "js/tools/record-chain-keys-prefix.js",
      sourceCommit,
      sourceScenario,
      witness: `${WITNESS_SOURCE} case ${WITNESS_CASE}`,
    },
    // The claim runner finds this package as a leaf directory, so the
    // directories above it hold no files of their own.
    discovery:
      "a leaf root found by discoverFixturePackageRoots (js/test-tools/claim-index.js); " +
      "verification/fixtures/v1/, v1/profiles/ and v1/profiles/dca-profile-chain-keys/ are path " +
      "segments, not packages",
    members,
    consumers: [
      {
        path: "js/test-vectors/chain-keys-prefix.test.js",
        role: "replay",
        description:
          "replays the recorded markup through the real Browser and IssuerServer, holds the " +
          "assertions, and checks the recorded bytes against the witness with stock WebCrypto",
      },
      {
        path: "js/test-tools/record-chain-keys-prefix.test.js",
        role: "recorder self-test",
        description: "tests the package check: membership, checksums, regeneration and refusals",
      },
      {
        command: "node js/tools/record-chain-keys-prefix.js --check",
        role: "package check",
        description:
          "membership both ways, per-member sha256 and a fresh recording; writes nothing",
      },
    ],
    limitations: [
      "All claim decisions are incomplete; this package decides no claim.",
      "It is regression and provenance evidence for the JavaScript issuer and client, not " +
        "independent conformance.",
      "The publisher is not replayed: renders are recorded markup, and ES256 signatures are " +
        "retained values, not reproducible bytes.",
      "One geometry, one window, one cutoff, one issuer, direct transport and ECDH-P256 " +
        "envelopes only; no client-bound transport and no rival generation.",
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
    summary: `chain-key prefix check could not run: ${reason}`,
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
    fresh = await recordPrefix({
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
      summary: `chain-key prefix check failed: ${findings.length} finding${findings.length === 1 ? "" : "s"}`,
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
  const outputs = await recordPrefix({ prior: readPrior(dir) });
  mkdirSync(dir, { recursive: true });
  for (const [name, text] of outputs) writeFileSync(dir + name, text);
  return [...outputs.keys()];
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
    console.error("usage: node js/tools/record-chain-keys-prefix.js [--check]");
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
    console.error(`chain-key prefix recorder could not run: ${error?.message ?? error}`);
    process.exitCode = 2;
  });
}

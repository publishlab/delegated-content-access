// @ts-check
//
// The construction entry point for one render's Sealer, for tests. It sits in
// `testing/` because its setup can fix the clock, the random bytes and the
// period keys; no production module imports from `testing/`, and production
// builds its Sealer through its own composition. A render gets its own
// stateful Sealer, so a caller asks this factory once per render, in a
// long-running process as much as in a per-request one. Each call builds a new
// Sealer and new collaborators, the random reader included. The factory builds
// the clock and the random source the Sealer reads, the period-key supply
// when the setup holds fixed period keys, and the issuer supply planner when
// the setup holds per-issuer plans as data; everything else in the setup is
// the Sealer's own configuration and passes through unchanged.
//
// A test member left out falls back to the runtime: the Sealer reads the wall
// clock, draws from the runtime's secure random source, asks the setup's own
// period-key supply and signs with the native keys the setup holds. A
// repeatable test supplies plain setup instead: a fixed instant, one random
// byte stream, a fixed key per period, and known test key documents. Those are
// trusted test setup, never publisher or request data. Each port maps this
// export to its own construction of its real Sealer.
//
// The stream is read front to back, however a port splits its reads, and only
// for the bytes the render draws itself: render ids, content keys and nonces.
// It never reaches a library's key generation or signing, such as an ECDH
// ephemeral key or an ECDSA signature; those draw from the platform's own
// source, so a test asserts only the drawn bytes.

import { base64urlDecode } from "../../core-shared/codec.js";
import { dcaError } from "../../core-shared/errors.js";
import { Sealer } from "../Sealer.js";
import { fixedPeriodKeySupply } from "./fixedPeriodKeySupply.js";

/**
 * Known test key documents, kept apart from the native keys a production
 * caller passes. `signingKeys` holds a PKCS#8 PEM ECDSA P-256 private key per
 * `kid`; `issuerPublicKeys` holds an SPKI PEM public key per issuer `keyId`,
 * for the issuer's configured algorithm.
 *
 * @typedef {object} TestKeyDocuments
 * @property {Record<string, string>} signingKeys
 * @property {Record<string, string>} issuerPublicKeys
 */

/**
 * The Sealer configuration without its clock and random source, plus the
 * setup the factory builds them from. `issuers` may leave `publicKey` out
 * when `testKeyDocuments` supplies it, and `signingKeys` may be left out when
 * `testKeyDocuments` supplies them.
 *
 * @typedef {object} SealerSetup
 * @property {string} origin
 * @property {boolean} [developmentHttpOrigin]
 * @property {object[]} issuers
 * @property {Record<string, CryptoKey>} [signingKeys]
 * @property {string} [signingKid]
 * @property {object} [period]
 * @property {object} [periodKeySupply]
 * @property {object} [keySealing]
 * @property {object} [contentKeyWrapStrategy]
 * @property {(issuer: import('../Sealer.js').IssuerConfig, render: { accessGroups: string[], contentNames: string[], now: Date }) => object|undefined} [issuerSupplyPlanFor]
 * @property {Record<string, object>} [issuerSupplyPlans] - each issuer's plan
 *   for this render as plain data, by issuerName, so a setup that crosses a
 *   test bridge or sits in a record can select scope. The factory answers the
 *   plan under the issuer's name and nothing for an issuer the map leaves out,
 *   which the Sealer refuses.
 * @property {Date} [fixedInstant] - the instant every clock read answers.
 *   Left out, the Sealer reads the wall clock.
 * @property {Uint8Array} [randomStream] - the bytes every `random.bytes(n)`
 *   reads in turn. Left out, the Sealer draws from the secure random source.
 * @property {Record<string, Record<string, Uint8Array>>} [fixedPeriodKeys] -
 *   the period key per access group and period label. The factory composes
 *   `fixedPeriodKeySupply` over them, which refuses any other coordinate.
 *   Left out, the setup's own `periodKeySupply`, if any, passes through.
 * @property {TestKeyDocuments} [testKeyDocuments]
 */

const BUILT_MEMBERS = ["clock", "random"];

const ECDSA_SIGNING = {
  algorithm: { name: "ECDSA", namedCurve: "P-256" },
  usages: /** @type {KeyUsage[]} */ (["sign"]),
};

/** @type {Record<string, { algorithm: any, usages: KeyUsage[] }>} */
const ISSUER_KEY_IMPORTS = {
  "ecdh-p256": { algorithm: { name: "ECDH", namedCurve: "P-256" }, usages: [] },
  "rsa-oaep": { algorithm: { name: "RSA-OAEP", hash: "SHA-256" }, usages: ["encrypt"] },
};

/**
 * A new Sealer for one render.
 *
 * @param {SealerSetup} setup
 * @returns {Promise<Sealer>}
 */
export async function sealerForRender(setup) {
  for (const name of BUILT_MEMBERS) {
    if (name in setup) {
      throw dcaError("bad_config", `the Sealer factory builds the ${name}; the setup holds none`);
    }
  }
  const {
    fixedInstant,
    randomStream,
    fixedPeriodKeys,
    testKeyDocuments,
    issuerSupplyPlans,
    ...setupConfig
  } = setup;
  const config =
    issuerSupplyPlans === undefined
      ? setupConfig
      : withIssuerSupplyPlans(setupConfig, issuerSupplyPlans);
  const clock = fixedInstant === undefined ? systemClock() : fixedClock(fixedInstant);
  const random = randomStream === undefined ? secureRandom() : streamSource(randomStream);
  const supplied =
    fixedPeriodKeys === undefined ? config : withFixedPeriodKeys(config, fixedPeriodKeys);
  const keyed =
    testKeyDocuments === undefined ? supplied : await withTestKeys(supplied, testKeyDocuments);
  return new Sealer(/** @type {any} */ ({ ...keyed, clock, random }));
}

function systemClock() {
  return { now: () => new Date() };
}

/** @param {Date} instant */
function fixedClock(instant) {
  const valid = instant instanceof Date && !Number.isNaN(instant.getTime());
  if (!valid) throw dcaError("bad_config", "a fixed instant is a valid Date");
  const time = instant.getTime();
  return { now: () => new Date(time) };
}

function secureRandom() {
  return {
    /** @param {number} n */
    bytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
  };
}

/**
 * A source that answers each draw with the next bytes of the stream, and
 * refuses a draw past its end.
 *
 * @param {unknown} stream
 */
function streamSource(stream) {
  if (!(stream instanceof Uint8Array)) throw dcaError("bad_config", "a random stream is bytes");
  const bytes = Uint8Array.from(stream);
  let offset = 0;
  return {
    /** @param {number} n */
    bytes(n) {
      const left = bytes.length - offset;
      if (n > left)
        throw dcaError("bad_config", `the random stream has ${left} bytes left, asked for ${n}`);
      const answer = bytes.slice(offset, offset + n);
      offset += n;
      return answer;
    },
  };
}

/**
 * The configuration with a planner that answers each issuer's recorded plan.
 *
 * @param {Omit<SealerSetup, "fixedInstant" | "randomStream" | "fixedPeriodKeys" | "testKeyDocuments" | "issuerSupplyPlans">} config
 * @param {unknown} plans
 */
function withIssuerSupplyPlans(config, plans) {
  if (config.issuerSupplyPlanFor !== undefined)
    throw dcaError(
      "bad_config",
      "issuer supply plans come from a planner or from per-issuer data, not both",
    );
  if (plans === null || typeof plans !== "object" || Array.isArray(plans))
    throw dcaError("bad_config", "issuer supply plans are an object keyed by issuerName");
  const byIssuer = /** @type {Record<string, object>} */ (plans);
  return {
    ...config,
    issuerSupplyPlanFor: (/** @type {{ issuerName: string }} */ issuer) =>
      Object.hasOwn(byIssuer, issuer.issuerName) ? byIssuer[issuer.issuerName] : undefined,
  };
}

/**
 * The configuration with a supply that answers the fixed period keys and
 * refuses any coordinate they do not list.
 *
 * @param {Omit<SealerSetup, "fixedInstant" | "randomStream" | "fixedPeriodKeys" | "testKeyDocuments">} config
 * @param {unknown} fixedPeriodKeys
 */
function withFixedPeriodKeys(config, fixedPeriodKeys) {
  if (config.periodKeySupply !== undefined)
    throw dcaError(
      "bad_config",
      "period keys come from a supply or from fixed test keys, not both",
    );
  return { ...config, periodKeySupply: fixedPeriodKeySupply(fixedPeriodKeys) };
}

/**
 * The configuration with the test key documents imported as native keys.
 *
 * @param {Omit<SealerSetup, "fixedInstant" | "randomStream" | "fixedPeriodKeys" | "testKeyDocuments">} config
 * @param {TestKeyDocuments} documents
 */
async function withTestKeys(config, documents) {
  if (config.signingKeys !== undefined)
    throw dcaError("bad_config", "signing keys come from native keys or test documents, not both");
  /** @type {Record<string, CryptoKey>} */
  const signingKeys = {};
  for (const [kid, pem] of Object.entries(documents.signingKeys)) {
    signingKeys[kid] = await importPem(pem, "PRIVATE KEY", "pkcs8", ECDSA_SIGNING);
  }
  const issuers = [];
  for (const issuer of /** @type {any[]} */ (config.issuers ?? [])) {
    const pem = documents.issuerPublicKeys[issuer?.keyId];
    if (pem === undefined) {
      issuers.push(issuer);
      continue;
    }
    if (issuer.publicKey !== undefined)
      throw dcaError(
        "bad_config",
        `issuer key ${issuer.keyId} comes from a native key or a test document, not both`,
      );
    const imports = ISSUER_KEY_IMPORTS[issuer.algorithm];
    if (imports === undefined)
      throw dcaError("bad_config", `no test key document import for ${issuer.algorithm}`);
    issuers.push({ ...issuer, publicKey: await importPem(pem, "PUBLIC KEY", "spki", imports) });
  }
  return { ...config, signingKeys, issuers };
}

/**
 * @param {string} pem @param {string} label @param {"pkcs8" | "spki"} format
 * @param {{ algorithm: any, usages: string[] }} imports
 * @returns {Promise<CryptoKey>}
 */
async function importPem(pem, label, format, imports) {
  const header = `-----BEGIN ${label}-----`;
  const footer = `-----END ${label}-----`;
  const text = typeof pem === "string" ? pem.trim() : "";
  const framed = text.startsWith(header) && text.endsWith(footer);
  if (!framed) throw dcaError("bad_config", `a test key document is a ${label} PEM`);
  const body = text.slice(header.length, text.length - footer.length).replace(/\s+/g, "");
  try {
    const der = Uint8Array.from(base64urlDecode(body));
    return await globalThis.crypto.subtle.importKey(
      format,
      der,
      imports.algorithm,
      false,
      /** @type {KeyUsage[]} */ (imports.usages),
    );
  } catch {
    throw dcaError("bad_config", `a ${label} test key document does not import`);
  }
}

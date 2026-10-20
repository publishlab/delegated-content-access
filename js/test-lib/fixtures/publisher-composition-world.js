// @ts-check
//
// One recorded publisher render, rebuilt from its record and compared with it.
// The records were written once from the publisher as it stood before
// composition existed; `recordedFrom` says so. Every test
// that reads one renders through today's code and compares, so a test never
// compares two calls through the same new path.
//
// Everything WebCrypto will not seed sits in the record as a JWK: the signing
// key, each issuer's public key and every ephemeral ECDH pair, keyed by the
// coordinate it seals. The Random seed, the clock and the period-key secret
// are recorded too. ECDSA still draws a fresh `k` per signature, so a test
// compares the resourceJWT's header and payload segments byte for byte and
// verifies its signature under the recorded public key.
//
// This module is base test support and imports no extension. A record's
// extension inputs, such as an issuer's omission members or a chain family,
// are plain data here; the extension's own test builds its contribution from
// them.

import assert from "node:assert/strict";

import { Clock } from "../../demo/actors/Clock.js";
import { Random } from "../../demo/actors/Random.js";
import { base64urlDecode, utf8Encode } from "../../core-shared/codec.js";
import { wholeRenderIssuerSupplyPlan } from "../../core-publisher/issuerSupplyPlan.js";
import { deterministicEcdhFixtureSealing } from "../../tools/vector-fixtures/deterministicEcdhSealing.js";

const { subtle } = globalThis.crypto;

export const PUBLISHER_COMPOSITION_RECORD = "publisher-composition-record-v1";

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/**
 * A wrap strategy that differs from the ordinary one in its bytes: every wrap
 * carries an aad over its coordinate. A render that silently fell back to the
 * ordinary wrap opens nothing the record holds.
 *
 * @type {import('../../core-publisher/contentKeyWrap.js').ContentKeyWrapStrategy}
 */
export const testAadContentKeyWrap = Object.freeze({
  aad: ({ renderId, contentName, accessGroup, t }) =>
    utf8Encode(`test-aad|${renderId}|${contentName}|${accessGroup}|${t}`),
  entry: ({ t, nonce, key }) => ({ t, nonce, key }),
});

/** The context string one ephemeral pair is recorded under. */
export function ephemeralContext(/** @type {string} */ issuerName, /** @type {object} */ binding) {
  return JSON.stringify({ issuerName, ...binding });
}

/**
 * The planners a record can name. `chain-delivery` asks for both period-key
 * and chain-key delivery on each recorded chain group the render carries.
 *
 * @param {any} input
 */
function plannerFor(input) {
  if (input.planner === "whole-render") return wholeRenderIssuerSupplyPlan;
  if (input.planner === "chain-delivery") {
    const chainGroups = input.chain.groups;
    return (
      /** @type {unknown} */ _issuer,
      /** @type {{ accessGroups: string[], contentNames: string[] }} */ render,
    ) => ({
      contentKeyNames: [...render.contentNames],
      suppliedAccessGroups: [...render.accessGroups],
      periodKeyDelivery: Object.fromEntries(
        render.accessGroups
          .filter((group) => chainGroups.includes(group))
          .map((group) => [group, ["period-keys", "chain-keys"]]),
      ),
    });
  }
  throw new Error(`no recorded planner "${input.planner}"`);
}

/**
 * A period-key supply that derives each key from the recorded secret, so the
 * same group and period give the same key in any order of calls.
 *
 * @param {Uint8Array} secret
 */
async function recordedPeriodKeySupply(secret) {
  const key = await subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return {
    /** @param {string} accessGroup @param {string} t */
    async derive(accessGroup, t) {
      const mac = await subtle.sign("HMAC", key, utf8Encode(`${accessGroup}|${t}`));
      return new Uint8Array(mac).slice(0, 16);
    },
  };
}

/**
 * The publisher inputs of one record, as live objects.
 *
 * @param {any} input - a record's `input`
 * @param {{ ephemeralFor?: (issuerName: string, binding: object) => CryptoKeyPair|undefined }} [options] -
 *   a pool for a first recording; left out, a replay reads the recorded pairs
 */
export async function recordedPublisherWorld(input, options = {}) {
  const signingKey = await subtle.importKey(
    "jwk",
    input.signingKey.privateKeyJwk,
    ECDSA_P256,
    false,
    ["sign"],
  );
  /** @type {Map<CryptoKey, string>} */
  const issuerByKey = new Map();
  /** @type {Record<string, CryptoKey>} */
  const issuerKeys = {};
  for (const issuer of input.issuers) {
    const publicKey = await subtle.importKey("jwk", issuer.publicKeyJwk, ECDH_P256, true, []);
    issuerKeys[issuer.issuerName] = publicKey;
    issuerByKey.set(publicKey, issuer.issuerName);
  }

  let ephemeralFor = options.ephemeralFor;
  if (ephemeralFor === undefined) {
    /** @type {Map<string, CryptoKeyPair>} */
    const recorded = new Map();
    for (const { context, publicKeyJwk, privateKeyJwk } of input.ephemeralKeys) {
      recorded.set(context, {
        publicKey: await subtle.importKey("jwk", publicKeyJwk, ECDH_P256, true, []),
        privateKey: await subtle.importKey("jwk", privateKeyJwk, ECDH_P256, false, ["deriveBits"]),
      });
    }
    ephemeralFor = (issuerName, binding) => recorded.get(ephemeralContext(issuerName, binding));
  }
  const pairFor = ephemeralFor;

  const periodKeySupply = await recordedPeriodKeySupply(base64urlDecode(input.periodKeySecret));
  const planner = plannerFor(input);

  /**
   * A fresh base configuration: a new seeded Random, a new clock and fresh
   * issuer records, so one test's render cannot move another's stream.
   *
   * @param {{ basePeriodKeySupply?: boolean }} [choice] - false leaves the
   *   supply out, for a render whose supply a contribution owns
   * @returns {Record<string, any>}
   */
  function config(choice = {}) {
    /** @type {Record<string, any>} */
    const base = {
      origin: input.origin,
      period: { length: input.chain?.geometry.periodMinutes ?? 60, slots: 2 },
      clock: new Clock(input.clockIso),
      random: new Random({ seed: input.seed }),
      signingKeys: { [input.signingKid]: signingKey },
      issuerSupplyPlanFor: planner,
      keySealing: deterministicEcdhFixtureSealing((issuerPublicKey, binding) => {
        const issuerName = issuerByKey.get(issuerPublicKey);
        return issuerName === undefined ? undefined : pairFor(issuerName, binding);
      }),
      issuers: input.issuers.map((/** @type {any} */ issuer) => ({
        issuerName: issuer.issuerName,
        keyId: issuer.keyId,
        algorithm: issuer.algorithm,
        publicKey: issuerKeys[issuer.issuerName],

        ...structuredClone(issuer.extra ?? {}),
      })),
    };
    if (choice.basePeriodKeySupply ?? input.basePeriodKeySupply) {
      base.periodKeySupply = periodKeySupply;
    }
    if (input.contentKeyWrap === "test-aad") base.contentKeyWrapStrategy = testAadContentKeyWrap;
    return base;
  }

  /** The recorded render, as `createPublisher().publish` takes it. */
  function article() {
    return {
      resourceId: input.resourceId,
      data: structuredClone(input.resourceData),
      items: input.items.map((/** @type {any} */ item) => ({ ...item })),
    };
  }

  /**
   * The recorded calls on a Sealer-shaped object, then its seal.
   *
   * @param {{ resource: Function, content: Function, seal: () => Promise<any> }} sealer
   */
  function sealed(sealer) {
    sealer.resource(input.resourceId, structuredClone(input.resourceData));
    for (const item of input.items) {
      sealer.content(item.name, item.value, item.contentType, {
        accessGroups: [...item.accessGroups],
      });
    }
    return sealer.seal();
  }

  return { config, article, sealed, periodKeySupply };
}

/**
 * The comparable form of one render: the JSON a page carries, with the
 * signature segment split off.
 *
 * @param {{ dcaData: any, sealedContent: Record<string, string> }} render
 */
export function recordedForm(render) {
  const { resourceJWT, ...dcaData } = JSON.parse(JSON.stringify(render.dcaData));
  const [header, payload, signature] = resourceJWT.split(".");
  return {
    form: {
      signingInput: `${header}.${payload}`,
      dcaData,
      sealedContent: JSON.parse(JSON.stringify(render.sealedContent)),
    },
    signature,
  };
}

/**
 * Assert that a render carries the recorded bytes: the same JSON, member order
 * included, and a signature that verifies under the recorded public key.
 *
 * @param {{ dcaData: any, sealedContent: Record<string, string> }} render
 * @param {any} record
 */
export async function assertRendersRecord(render, record) {
  const { form, signature } = recordedForm(render);
  assert.equal(JSON.stringify(form), JSON.stringify(record.expected));
  const verifyKey = await subtle.importKey(
    "jwk",
    record.input.signingKey.publicKeyJwk,
    ECDSA_P256,
    false,
    ["verify"],
  );
  assert.ok(
    await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      base64urlDecode(signature),
      utf8Encode(form.signingInput),
    ),
    "the resourceJWT signature verifies under the recorded public key",
  );
}

// @ts-check
//
// Builds the Sealer factory records under
// verification/fixtures/v1/reference/protocol-regressions/.
// `tools/make-vectors.js` writes them with the other fixtures.
//
// A record holds the plain setup a test hands `sealerForRender` in
// core-publisher/testing/sealerFactory.js, the calls that render one page, and the
// values the render must carry. A port can replay it in its own unit tests,
// with no test bridge. The setups and calls come from
// test-reference/support/sealerCases.js, the module the bridged Sealer
// selections read. The records and the bridged cases therefore render the same
// pages. A record spells bytes and instants as the tagged values of the test
// bridge frames, at any depth (js/test-bridges/_shared/CONTRACT.md), with
// the bridge's own encoder, and it holds calls as data, `[member, args]`. The
// refusal record holds the same module's refusal cases, each with the DCA code
// the Sealer or the factory refuses with.
//
// The expected values are not read off a render. Each drawn value is the
// stream slice at its offset, and the offsets follow the order in which the
// reference draws, which drawsOf below states. An RSA-OAEP envelope draws
// nothing and is opened rather than pinned. Each item's aad is the content AAD
// over the recorded renderId and content name.
// Each envelope opens to a drawn content key or a fixed period key. Its BIND follows
// docs/spec--sealed-key-envelopes.md, section 3. The replay in
// js/test-vectors/sealer-factory-records.test.js checks every one of them
// against the reference.

import {
  TEST_ISSUER_PRIVATE_KEY_PKCS8,
  TEST_ISSUER_PUBLIC_KEY_SPKI,
  TEST_RSA_ISSUER_PRIVATE_KEY_PKCS8,
  TEST_RSA_ISSUER_PUBLIC_KEY_SPKI,
  TEST_SIGNING_PUBLIC_KEY_SPKI,
} from "../test-reference/support/keys.js";
import {
  sealerIssuersRender,
  sealerIssuersSetup,
  sealerOriginRender,
  sealerOriginSetup,
  sealerPeriodKeysRender,
  sealerPeriodKeysSetup,
  sealerRefusalCases,
  sealerRefusalSetup,
  sealerRenderCalls,
} from "../test-reference/support/sealerCases.js";
import { contentAad } from "../core-shared--client-publisher/contentAad.js";
import { encodeValue } from "../test-bridges/_shared/serializer.mjs";
import { AT } from "../demo/scenarios/fixtures.js";

/**
 * The replay schema of a Sealer factory record. Version 3 records each
 * expected.content[*].aad as the derived content AAD octets, a tagged byte
 * string; version 2 recorded it as the string `resourceId|1|name`, so a
 * version 2 reader would misread the member. Version 2 spelled every byte string and
 * instant as a tagged value and held the render's calls as data; version 1 used
 * hex members, an ISO string and an input.resource and input.content a replay
 * turned into calls.
 */
export const SEALER_FACTORY_FORMAT = "sealer-factory-v3";

/** The replay schema of a Sealer factory refusal record. Version 2 spells
 * values as tagged values, as above; its setup is unchanged by version 3. */
export const SEALER_REFUSAL_FORMAT = "sealer-factory-refusal-v2";

/** How every record spells a value, said once in each description. */
const VALUES =
  "Values are JSON, with the tagged values of the test bridge frames at any depth " +
  "(js/test-bridges/_shared/CONTRACT.md): " +
  '{"$type":"Uint8Array","base64url":...} is a byte string in unpadded base64url, ' +
  '{"$type":"Date","iso":...} is a UTC instant with milliseconds, and ' +
  '{"$type":"Record","value":{...}} is an ordinary record that has a $type member. ' +
  "Decode the whole record with that one codec before a replay reads it.";

const REFUSAL_DESCRIPTION =
  "Refusals of Sealers built through the factory from plain setup. " +
  VALUES +
  ` input.setup is the setup of a ${SEALER_FACTORY_FORMAT} record; set and unset name members ` +
  "as the factory takes them. For each entry of cases, lay the members of set over " +
  "input.setup, remove the members named in unset, and build the Sealer with your " +
  "port's mapped factory. Then make the calls in order: each is [member, args] on the " +
  "Sealer. The last call must refuse, or the factory itself when calls is empty or " +
  "absent, with a DCA error whose code is expected.code; the calls before it must not " +
  "refuse. A port may refuse at once or through a promise. The message is the port's " +
  "own and is not pinned.";

const RENDER_ID_BYTES = 16;
const CONTENT_KEY_BYTES = 16;
const NONCE_BYTES = 12;

const DESCRIPTION =
  "One render built through the Sealer factory from plain setup. " +
  VALUES +
  " Replay: build the Sealer with your port's mapped factory from input.setup. " +
  "fixedInstant is the instant, randomStream is the random byte stream, " +
  "fixedPeriodKeys holds one 16-byte key per access group and period, and " +
  "testKeyDocuments holds PEM keys. A member the setup leaves out stays out of the " +
  "factory call, so the Sealer uses its default, such as its default period. Then make " +
  "input.calls in order: each is [member, args] on the Sealer, and the last, seal, " +
  "answers the render. Check the result against expected. The resourceJWT payload " +
  "decodes to expected.resource, which is the signed JSON as it is, not a tagged value. " +
  "Its signature is ES256 over header.payload, raw r||s, " +
  "and verifies under expected.signingPublicKey; a signature is not pinned. " +
  "expected.draws lists every value the render draws from the stream, in stream " +
  "order, with its offset, length and bytes. The draws cover the stream from its first " +
  "byte to its last, and the wire carries no nonce or wrap entry they do not list. " +
  "renderId is resource.renderId. Each content nonce is twelve zero octets, not a draw or wire member. " +
  "wrapNonce is the nonce of the " +
  "contentData[contentName].keys[accessGroup] entry for t, and that entry's key opens " +
  "under the fixed period key, with no aad, to the contentKey. envelopeNonce is bytes " +
  "65 to 77 of the ECDH envelope at issuerData[issuerName].sealed.contentKeys" +
  "[contentName] or .periodKeys[accessGroup][t]. The contentKey is not on the wire: " +
  "sealedContent[name] opens under it, with twelve zero nonce octets and expected.content[name].aad " +
  "as additionalData, to expected.content[name].plaintext. The item record carries no aad; " +
  "build it as the content AAD of docs/spec--content-protection.md Section 3.2 and compare " +
  "it with the recorded bytes: LP(resource.renderId) || LP(contentName), where " +
  "LP(s) is the four-octet big-endian octet length of UTF8(s) followed by those octets. " +
  "expected.envelopes lists every ECDH envelope with " +
  "its BIND and the key it opens to, opensTo. Open one as the issuer does: ECDH between " +
  "expected.issuerPrivateKeys[keyId] (PKCS#8 PEM, never part of the setup) and the " +
  "65-byte point at the envelope's start, the 32-byte x-coordinate as the AES-256-GCM " +
  "key with no KDF, bytes 65 to 77 as the nonce, the rest as ciphertext and tag, and " +
  "the BIND as aad. ECDH ephemeral keys and ECDSA signatures come from the platform, " +
  "not the stream, and are not pinned.";

/**
 * @typedef {object} Draw
 * @property {string} draw - renderId, contentKey, wrapNonce or envelopeNonce
 * @property {number} length
 * @property {string} [issuerName]
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t]
 */

/**
 * The draws of a render, in the order the reference makes them: the render
 * id; each item's content key; each item's wrap nonce per
 * access group and period; then, for each ECDH issuer in order, the nonce of
 * each item's content-key envelope and of each period envelope. An RSA-OAEP issuer
 * takes its padding randomness from the platform and draws nothing.
 *
 * @param {{ issuerName: string, algorithm: string }[]} issuers
 * @param {{ name: string, accessGroups: string[] }[]} items
 * @param {(accessGroup: string) => string[]} periodsOf - the periods an access group is sealed for
 * @returns {Draw[]}
 */
function drawsOf(issuers, items, periodsOf) {
  const groups = [...new Set(items.flatMap((item) => item.accessGroups))];
  return [
    { draw: "renderId", length: RENDER_ID_BYTES },
    ...items.map(({ name: contentName }) => ({
      draw: "contentKey",
      length: CONTENT_KEY_BYTES,
      contentName,
    })),
    ...items.flatMap(({ name: contentName, accessGroups }) =>
      accessGroups.flatMap((accessGroup) =>
        periodsOf(accessGroup).map((t) => ({
          draw: "wrapNonce",
          length: NONCE_BYTES,
          contentName,
          accessGroup,
          t,
        })),
      ),
    ),
    ...issuers
      .filter(({ algorithm }) => algorithm === "ecdh-p256")
      .flatMap(({ issuerName }) => [
        ...items.map(({ name: contentName }) => ({
          draw: "envelopeNonce",
          length: NONCE_BYTES,
          issuerName,
          contentName,
        })),
        ...groups.flatMap((accessGroup) =>
          periodsOf(accessGroup).map((t) => ({
            draw: "envelopeNonce",
            length: NONCE_BYTES,
            issuerName,
            accessGroup,
            t,
          })),
        ),
      ]),
  ];
}

/**
 * Said only in a record with an RSA-OAEP issuer, so the records without one
 * keep their bytes.
 */
const RSA_OAEP_NOTE =
  " An issuer whose input.setup.issuers entry has algorithm RSA-OAEP draws nothing " +
  "from the stream, so no envelopeNonce names it; its padding randomness comes from " +
  "the platform, and its envelope bytes are not pinned. expected.envelopes lists its " +
  "envelopes beside the ECDH ones. Open one as the issuer does: RSA-OAEP with SHA-256, " +
  "MGF1 with SHA-256 and an empty label, under expected.issuerPrivateKeys[keyId] " +
  "(PKCS#8 PEM). The plaintext is exactly the BIND followed by the 16-byte key it opens to.";

/** The private half of each known issuer test key, by its public half. */
const ISSUER_PRIVATE_KEYS = new Map([
  [TEST_ISSUER_PUBLIC_KEY_SPKI, TEST_ISSUER_PRIVATE_KEY_PKCS8],
  [TEST_RSA_ISSUER_PUBLIC_KEY_SPKI, TEST_RSA_ISSUER_PRIVATE_KEY_PKCS8],
]);

/**
 * A value as a record holds it: the test bridge frames' encoding, so bytes and
 * instants become tagged values at any depth. A case that crosses carries no
 * `undefined` (js/PORTING.md, "Absent values"), so one is an error here
 * rather than an `undefined` tag.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
function recordedValue(value) {
  /** @param {unknown} inner */
  const visit = (inner) => {
    if (inner === undefined) throw new Error("a record carries no undefined");
    if (Array.isArray(inner)) inner.forEach(visit);
    else if (inner !== null && Object.getPrototypeOf(inner) === Object.prototype)
      Object.values(/** @type {object} */ (inner)).forEach(visit);
  };
  visit(value);
  return encodeValue(value);
}

/**
 * The content AAD of one rendered item (docs/spec--content-protection.md,
 * Section 3.2). A string value renders with no content encodings.
 *
 * @param {string} renderId
 * @param {{ name: string, contentType: string, contentEncodings?: string[] }} item
 * @returns {Uint8Array}
 */
function itemAad(renderId, item) {
  const aad = contentAad({ renderId, contentName: item.name });
  if (aad === null) throw new Error(`${item.name}: the item forms no content AAD`);
  return aad;
}

/**
 * One record: the setup, the calls and the expected values.
 *
 * @param {string} name
 * @param {any} setup - a setup from sealerCases.js
 * @param {{ resource: { resourceId: string, data: object }, content: any[] }} render
 */
function record(name, setup, render) {
  const { fixedInstant, randomStream, fixedPeriodKeys } = setup;
  /** @type {{ issuerName: string, keyId: string, algorithm: string }[]} */
  const issuers = setup.issuers;
  const items = render.content;
  /** @param {string} accessGroup */
  const periodsOf = (accessGroup) => Object.keys(fixedPeriodKeys?.[accessGroup] ?? {});
  const layout = drawsOf(issuers, items, periodsOf);
  if (layout.reduce((sum, { length }) => sum + length, 0) !== randomStream.length)
    throw new Error(`${name}: the draw layout does not cover the setup's random stream`);

  let offset = 0;
  const draws = layout.map(({ draw, length, ...coordinate }) => {
    const entry = { draw, ...coordinate, offset, length };
    const bytes = randomStream.slice(offset, offset + length);
    offset += length;
    return { ...entry, bytes };
  });
  const renderId = Buffer.from(draws[0].bytes).toString("base64url");
  /** @param {string} contentName */
  const contentKey = (contentName) =>
    draws.find((draw) => draw.draw === "contentKey" && draw.contentName === contentName)?.bytes;
  const issuedAt = fixedInstant.toISOString();
  const groups = [...new Set(items.flatMap((item) => item.accessGroups))];

  const envelopes = issuers.flatMap(({ issuerName }) => [
    ...items.map((item) => ({
      issuerName,
      contentName: item.name,
      bind: `dca-bind-key-envelope|c|${renderId}|${item.name}`,
      opensTo: contentKey(item.name),
    })),
    ...groups.flatMap((accessGroup) =>
      Object.entries(fixedPeriodKeys?.[accessGroup] ?? {}).map(([t, key]) => ({
        issuerName,
        accessGroup,
        t,
        bind: `dca-bind-key-envelope|p|${renderId}|${accessGroup}|${t}`,
        opensTo: /** @type {Uint8Array} */ (key),
      })),
    ),
  ]);

  const issuerPrivateKeys = Object.fromEntries(
    issuers.map(({ keyId }) => {
      const privateKey = ISSUER_PRIVATE_KEYS.get(setup.testKeyDocuments.issuerPublicKeys[keyId]);
      if (privateKey === undefined) throw new Error(`${name}: no known private key for ${keyId}`);
      return [keyId, privateKey];
    }),
  );
  const rsa = issuers.some(({ algorithm }) => algorithm === "rsa-oaep");

  const resource = {
    renderId,
    origin: setup.origin,
    issuedAt,
    resourceId: render.resource.resourceId,
    data: render.resource.data,
  };

  return {
    file: `${name}.json`,
    vector: {
      name,
      vectorFormat: SEALER_FACTORY_FORMAT,
      description: rsa ? DESCRIPTION + RSA_OAEP_NOTE : DESCRIPTION,
      input: /** @type {object} */ (recordedValue({ setup, calls: sealerRenderCalls(render) })),
      expected: {
        resource,
        signingPublicKey: TEST_SIGNING_PUBLIC_KEY_SPKI,
        issuerPrivateKeys,
        draws: recordedValue(draws),
        envelopes: recordedValue(envelopes),
        content: Object.fromEntries(
          items.map((item) => [
            item.name,
            { aad: recordedValue(itemAad(renderId, item)), plaintext: item.value },
          ]),
        ),
      },
    },
  };
}

/**
 * The refusal record: every refusal in sealerCases.js, each on the refusal
 * setup, with its expected DCA code.
 *
 * @returns {{ file: string, vector: any }}
 */
export function makeSealerRefusalRecord() {
  const name = "seal-factory-refusals";
  const base = sealerRefusalSetup();
  const cases = Object.values(sealerRefusalCases())
    .flat()
    .map((refused) => {
      return {
        name: refused.name,
        ...(refused.set && { set: recordedValue(refused.set) }),
        ...(refused.unset && { unset: refused.unset }),
        ...(refused.calls && { calls: recordedValue(refused.calls) }),
        expected: { code: refused.code },
      };
    });
  if (new Set(cases.map((entry) => entry.name)).size !== cases.length)
    throw new Error(`${name}: case names are unique`);
  return {
    file: `${name}.json`,
    vector: {
      name,
      vectorFormat: SEALER_REFUSAL_FORMAT,
      description: REFUSAL_DESCRIPTION,
      input: { setup: recordedValue(base) },
      cases,
    },
  };
}

/**
 * The Sealer factory records: a content-key-only render, whose access group has no
 * period-key supply; a render sealed for two periods under fixed keys; and a
 * render of two items for an ECDH issuer and an RSA-OAEP issuer.
 *
 * @returns {{ file: string, vector: any }[]}
 */
export function makeSealerFactoryRecords() {
  return [
    record(
      "seal-factory-content-key-only",
      sealerOriginSetup(AT, "sealer-origin"),
      sealerOriginRender(),
    ),
    record("seal-factory-period-keys", sealerPeriodKeysSetup(), sealerPeriodKeysRender()),
    record("seal-factory-mixed-issuers", sealerIssuersSetup(true), sealerIssuersRender()),
  ];
}

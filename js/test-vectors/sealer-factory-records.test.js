// @ts-check
//
// Replays the Sealer factory records in
// verification/fixtures/v1/reference/protocol-regressions/ against the
// reference, the way a port replays them in its own unit tests.
//
// Each record holds plain factory setup, the calls of one render and the
// values the render must carry. Bytes and instants are tagged values at any
// depth, in the layouts of the test bridge frames
// (js/test-bridges/_shared/CONTRACT.md), so this file decodes a record
// with the bridge's own value codec and nothing else. It builds the Sealer
// from the decoded setup, makes the recorded calls, and checks the result:
//
//   a. the record's draws cover its random stream from the first byte to the
//      last, and each draw's bytes are the stream slice at its offset
//   b. the signed resource decodes to the recorded resource, and its ES256
//      signature verifies under the recorded public key
//   c. every drawn value sits on the wire where the record says, and the wire
//      carries no nonce or wrap entry the record does not list
//   d. the item records carry no aad; the recorded aad equals the content AAD
//      a hand-built transcript derives from the renderId and content name (test-reference/support/contentAadOctets.js); the sealed content
//      opens under the drawn content key and twelve zero nonce octets, with that aad, to the
//      recorded plaintext; and each wrap opens under its fixed period key to
//      the same content key
//   e. each issuer envelope opens under the recorded issuer private key, at a
//      BIND built from the specification's grammar, to the drawn content key
//      or the fixed period key the record names: an ECDH envelope as section 4
//      of docs/spec--sealed-key-envelopes.md states, an RSA-OAEP one as
//      section 5 does
//
// It also replays the refusal records, format `sealer-factory-refusal-v2`:
// each case builds a Sealer from the recorded setup with its changes, makes
// its calls, and expects the last one, or the factory, to refuse with the
// recorded DCA code.
//
// Only the render runs in the reference. The expected values come from the
// record, Node's Buffer, WebCrypto and the hand-built content AAD transcript,
// so no check here asks the reference for its own expected value.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { sealerForRender } from "../core-publisher/testing/sealerFactory.js";
import { decodeValue } from "../test-bridges/_shared/serializer.mjs";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";

const FIXTURE_DIR = fileURLToPath(
  new URL("../../verification/fixtures/v1/reference/protocol-regressions/", import.meta.url),
);

const SEALER_FACTORY_FORMAT = "sealer-factory-v3";
const SEALER_REFUSAL_FORMAT = "sealer-factory-refusal-v2";

/** An ECDH envelope carries its nonce after the 65-byte ephemeral point. */
const ENVELOPE_NONCE = [65, 77];

const { subtle } = globalThis.crypto;

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const RSA_OAEP_SHA256 = { name: "RSA-OAEP", hash: "SHA-256" };

/** @type {{ path: string, vectorFormat: string }[]} */
const manifestFiles = JSON.parse(readFileSync(`${FIXTURE_DIR}manifest.json`, "utf8")).files;
/** @param {string} format */
const recordsOf = (format) =>
  manifestFiles
    .filter(({ vectorFormat }) => vectorFormat === format)
    .map(({ path }) => {
      const text = readFileSync(FIXTURE_DIR + path, "utf8");
      return { file: path, text, record: /** @type {any} */ (decodeValue(JSON.parse(text))) };
    });
const records = recordsOf(SEALER_FACTORY_FORMAT);
const refusalRecords = recordsOf(SEALER_REFUSAL_FORMAT);

/** @param {string} text */
const fromBase64url = (text) => new Uint8Array(Buffer.from(text, "base64url"));
/** @param {Uint8Array} bytes */
const toBase64url = (bytes) => Buffer.from(bytes).toString("base64url");

/**
 * Builds the Sealer from the decoded setup and makes the recorded calls in
 * order. The last call, `seal`, answers the render.
 *
 * @param {any} input
 */
async function render(input) {
  const sealer = /** @type {any} */ (await sealerForRender(input.setup));
  let result;
  for (const [member, args] of input.calls) result = await sealer[member](...args);
  return result;
}

/** @param {string} pem */
function derOf(pem) {
  const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(body, "base64"));
}

/** @param {Uint8Array} key @param {Uint8Array} nonce @param {Uint8Array} sealed @param {Uint8Array} [aad] */
async function openGcm(key, nonce, sealed, aad) {
  const handle = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  const params =
    aad === undefined
      ? { name: "AES-GCM", iv: nonce }
      : { name: "AES-GCM", iv: nonce, additionalData: aad };
  return new Uint8Array(await subtle.decrypt(params, handle, sealed));
}

/**
 * The BIND of a sealed key: `dca-bind-key-envelope|c|renderId|contentName` for a
 * content key and `dca-bind-key-envelope|p|renderId|accessGroup|t` for a period key,
 * from docs/spec--sealed-key-envelopes.md, section 3.
 *
 * @param {string} renderId
 * @param {{ contentName?: string, accessGroup?: string, t?: string }} at
 */
function bindOf(renderId, at) {
  return at.contentName !== undefined
    ? `dca-bind-key-envelope|c|${renderId}|${at.contentName}`
    : `dca-bind-key-envelope|p|${renderId}|${at.accessGroup}|${at.t}`;
}

/**
 * Opens an ECDH P-256 envelope as the issuer does (section 4 of the same
 * specification): ECDH between the issuer's private key and the 65-byte point
 * at the start, the 32-byte x-coordinate as the AES-256-GCM key with no KDF,
 * the next 12 bytes as the nonce, and the BIND as the additional data.
 *
 * @param {string} envelope @param {string} bind @param {string} privateKeyPem
 */
async function openEcdhEnvelope(envelope, bind, privateKeyPem) {
  const bytes = fromBase64url(envelope);
  const der = Buffer.from(
    privateKeyPem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  const privateKey = await subtle.importKey("pkcs8", der, ECDH_P256, false, ["deriveBits"]);
  const point = await subtle.importKey("raw", bytes.subarray(0, 65), ECDH_P256, false, []);
  const shared = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: point }, privateKey, 256),
  );
  return openGcm(
    shared,
    bytes.subarray(...ENVELOPE_NONCE),
    bytes.subarray(ENVELOPE_NONCE[1]),
    new TextEncoder().encode(bind),
  );
}

/**
 * Opens an RSA-OAEP envelope as the issuer does (section 5): OAEP with SHA-256,
 * MGF1 with SHA-256 and an empty label, and a plaintext that is exactly the
 * BIND followed by the 16-byte key.
 *
 * @param {string} envelope @param {string} bind @param {string} privateKeyPem
 */
async function openRsaEnvelope(envelope, bind, privateKeyPem) {
  const der = Buffer.from(
    privateKeyPem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  const privateKey = await subtle.importKey("pkcs8", der, RSA_OAEP_SHA256, false, ["decrypt"]);
  const plaintext = new Uint8Array(
    await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, fromBase64url(envelope)),
  );
  const expectedBind = new TextEncoder().encode(bind);
  assert.equal(plaintext.length, expectedBind.length + 16, `${bind}: the BIND and a 16-byte key`);
  assert.equal(
    Buffer.from(plaintext.subarray(0, expectedBind.length)).toString("utf8"),
    bind,
    `${bind}: the plaintext carries that BIND`,
  );
  return plaintext.subarray(expectedBind.length);
}

/** @param {string} envelope */
const envelopeNonce = (envelope) =>
  toBase64url(fromBase64url(envelope).subarray(...ENVELOPE_NONCE));

test("the fixture manifest names the Sealer factory records this file replays", () => {
  assert.deepEqual(
    records.map(({ file }) => file),
    [
      "seal-factory-content-key-only.json",
      "seal-factory-mixed-issuers.json",
      "seal-factory-period-keys.json",
    ],
  );
  assert.deepEqual(
    refusalRecords.map(({ file }) => file),
    ["seal-factory-refusals.json"],
  );
  for (const { file, text, record } of [...records, ...refusalRecords]) {
    assert.ok(
      [SEALER_FACTORY_FORMAT, SEALER_REFUSAL_FORMAT].includes(record.vectorFormat),
      `${file}: format matches the manifest`,
    );
    assert.equal(record.name, file.replace(/\.json$/, ""), `${file}: name matches the file`);
    // Bytes and instants are tagged values, never a member of its own spelling.
    assert.doesNotMatch(text, /Hex"\s*:/, `${file}: no member spells bytes as hex`);
  }
});

for (const { file, record } of records) {
  describe(file, () => {
    const { input, expected } = record;
    /** @type {Uint8Array} */
    const stream = input.setup.randomStream;
    /** @type {any[]} */
    const draws = expected.draws;
    /** @param {string} kind @param {object} [at] */
    const drawsOf = (kind, at = {}) =>
      draws.filter(
        (draw) =>
          draw.draw === kind &&
          Object.entries(at).every(([member, value]) => draw[member] === value),
      );
    /** @param {string} kind @param {object} [at] */
    const drawOf = (kind, at = {}) => {
      const found = drawsOf(kind, at);
      assert.equal(found.length, 1, `one ${kind} draw at ${JSON.stringify(at)}`);
      return found[0].bytes;
    };

    test("the draws cover the random stream from its first byte to its last", () => {
      let offset = 0;
      for (const draw of draws) {
        assert.equal(draw.offset, offset, `${draw.draw} starts where the draw before it ended`);
        assert.equal(draw.bytes.length, draw.length, `${draw.draw} holds its length in bytes`);
        assert.deepEqual(
          draw.bytes,
          stream.subarray(draw.offset, draw.offset + draw.length),
          `${draw.draw} at ${draw.offset} is the stream slice there`,
        );
        offset += draw.length;
      }
      assert.equal(offset, stream.length, "the last draw ends on the stream's last byte");
    });

    test("the render carries every drawn value where the record says, and nothing unlisted", async () => {
      const { dcaData, sealedContent } = await render(input);
      const [headerSegment, payloadSegment, signatureSegment] = dcaData.resourceJWT.split(".");

      // The signed resource, and the signature over it.
      const header = JSON.parse(Buffer.from(headerSegment, "base64url").toString("utf8"));
      const payload = JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8"));
      assert.deepEqual(header, { alg: "ES256", typ: "JWT", kid: input.setup.signingKid });
      assert.deepEqual(payload, expected.resource);
      assert.equal(payload.renderId, toBase64url(drawOf("renderId")));
      const verifyKey = await subtle.importKey(
        "spki",
        derOf(expected.signingPublicKey),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      assert.ok(
        await subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          verifyKey,
          fromBase64url(signatureSegment),
          new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
        ),
        "the signature verifies under the recorded public key",
      );

      // Each item: its implicit nonce, plaintext, and wraps.
      assert.deepEqual(Object.keys(dcaData.contentData), Object.keys(expected.content));
      assert.deepEqual(Object.keys(sealedContent), Object.keys(expected.content));
      for (const [contentName, { aad, plaintext }] of Object.entries(expected.content)) {
        const item = dcaData.contentData[contentName];
        const contentKey = drawOf("contentKey", { contentName });
        const contentNonce = new Uint8Array(12);
        assert.equal(Object.hasOwn(item, "nonce"), false, "content nonce is implicit");
        assert.equal(
          Object.hasOwn(item, "aad"),
          false,
          `${contentName}: the record carries no aad`,
        );
        // The recorded AAD is the transcript a hand-built copy derives from
        // this render's token and item, not a value the reference hands back.
        assert.deepEqual(
          aad,
          contentAadOctets(dcaData, contentName),
          `${contentName}: the recorded aad is the derived content AAD`,
        );
        const opened = await openGcm(
          contentKey,
          contentNonce,
          fromBase64url(sealedContent[contentName]),
          aad,
        );
        assert.equal(new TextDecoder().decode(opened), plaintext);

        const wraps = Object.entries(item.keys ?? {}).flatMap(([accessGroup, entries]) =>
          /** @type {any[]} */ (entries).map((entry) => ({ accessGroup, ...entry })),
        );
        assert.equal(
          wraps.length,
          drawsOf("wrapNonce", { contentName }).length,
          `${contentName}: one wrap entry per recorded wrap nonce`,
        );
        for (const { accessGroup, t, nonce, key } of wraps) {
          const wrapNonce = drawOf("wrapNonce", { contentName, accessGroup, t });
          assert.equal(nonce, toBase64url(wrapNonce), `${accessGroup} ${t}: wrap nonce`);
          const periodKey = input.setup.fixedPeriodKeys[accessGroup][t];
          assert.equal(
            toBase64url(await openGcm(periodKey, wrapNonce, fromBase64url(key))),
            toBase64url(contentKey),
            `${accessGroup} ${t}: the wrap opens to the content key`,
          );
        }
      }

      // Each sealed key's envelope nonce.
      const envelopes = Object.entries(dcaData.issuerData).flatMap(([issuerName, issuer]) => {
        const { contentKeys = {}, periodKeys = {} } = /** @type {any} */ (issuer).sealed;
        return [
          ...Object.entries(contentKeys).map(([contentName, envelope]) => ({
            at: { issuerName, contentName },
            envelope,
          })),
          ...Object.entries(periodKeys).flatMap(([accessGroup, periods]) =>
            Object.entries(/** @type {Record<string, string>} */ (periods)).map(
              ([t, envelope]) => ({ at: { issuerName, accessGroup, t }, envelope }),
            ),
          ),
        ];
      });
      /** @param {string} issuerName */
      const algorithmOf = (issuerName) =>
        input.setup.issuers.find((/** @type {any} */ issuer) => issuer.issuerName === issuerName)
          .algorithm;
      // An RSA-OAEP issuer draws nothing, so only ECDH envelopes carry a drawn nonce.
      const ecdhEnvelopes = envelopes.filter(
        ({ at }) => algorithmOf(at.issuerName) === "ecdh-p256",
      );
      assert.equal(
        ecdhEnvelopes.length,
        drawsOf("envelopeNonce").length,
        "one ECDH sealed key per recorded envelope nonce",
      );
      for (const { at, envelope } of ecdhEnvelopes) {
        assert.equal(
          envelopeNonce(/** @type {string} */ (envelope)),
          toBase64url(drawOf("envelopeNonce", at)),
          `envelope nonce at ${JSON.stringify(at)}`,
        );
      }

      // Each envelope opens, under the issuer's private key and at its own
      // BIND, to the drawn content key or the fixed period key.
      /** @type {any[]} */
      const recordedEnvelopes = expected.envelopes;
      assert.equal(recordedEnvelopes.length, envelopes.length, "one recorded opening per envelope");
      for (const { at, envelope } of envelopes) {
        const found = recordedEnvelopes.filter((entry) =>
          ["issuerName", "contentName", "accessGroup", "t"].every(
            (member) => entry[member] === /** @type {any} */ (at)[member],
          ),
        );
        assert.equal(found.length, 1, `one recorded opening at ${JSON.stringify(at)}`);
        const [{ bind, opensTo }] = found;
        assert.equal(bind, bindOf(payload.renderId, at), `${bind}: the BIND grammar`);
        const expectedKey =
          "contentName" in at
            ? drawOf("contentKey", { contentName: at.contentName })
            : input.setup.fixedPeriodKeys[at.accessGroup][at.t];
        assert.equal(toBase64url(opensTo), toBase64url(expectedKey), `${bind}: its key`);
        const { keyId } = input.setup.issuers.find(
          (/** @type {any} */ issuer) => issuer.issuerName === at.issuerName,
        );
        const open = algorithmOf(at.issuerName) === "rsa-oaep" ? openRsaEnvelope : openEcdhEnvelope;
        const opened = await open(
          /** @type {string} */ (envelope),
          bind,
          expected.issuerPrivateKeys[keyId],
        );
        assert.equal(toBase64url(opened), toBase64url(opensTo), `${bind}: opens to its key`);
      }

      // And the record lists no draw the checks above did not reach.
      const items = Object.keys(expected.content).length;
      const wrapCount = drawsOf("wrapNonce").length;
      assert.equal(
        draws.length,
        1 + items + wrapCount + ecdhEnvelopes.length,
        "the render id, a key per item, the wrap nonces and the envelope nonces",
      );
    });
  });
}

for (const { file, text, record } of refusalRecords) {
  describe(file, () => {
    test("every case refuses with its recorded code, at its last call or at the factory", async () => {
      assert.ok(record.cases.length > 0, `${file}: holds refusal cases`);
      for (const index of record.cases.keys()) {
        // A fresh decoding per case, so no case sees bytes another one used.
        const fresh = /** @type {any} */ (decodeValue(JSON.parse(text)));
        const refused = fresh.cases[index];
        const setup = /** @type {Record<string, unknown>} */ ({
          ...fresh.input.setup,
          ...(refused.set ?? {}),
        });
        for (const name of refused.unset ?? []) delete setup[name];
        /** @type {[string, unknown[]][]} */
        const calls = refused.calls ?? [];
        /** @param {any} error */
        const check = (error) => {
          assert.equal(error?.code, refused.expected.code, `${refused.name}: ${error?.message}`);
          return true;
        };
        if (calls.length === 0) {
          await assert.rejects(async () => sealerForRender(/** @type {any} */ (setup)), check);
          continue;
        }
        const sealer = /** @type {any} */ (await sealerForRender(/** @type {any} */ (setup)));
        for (const [member, args] of calls.slice(0, -1)) await sealer[member](...args);
        const [member, args] = calls[calls.length - 1];
        await assert.rejects(async () => sealer[member](...args), check, refused.name);
      }
    });
  });
}

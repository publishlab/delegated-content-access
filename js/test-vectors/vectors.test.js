// Replays the three protocol fixture packages under verification/fixtures/v1/
// and the optional baseline RSA-OAEP open package.
//
// A fixture is shared recorded input, not this file: inputs on one side and
// recorded wire bytes on the other. What runs here is a reference replay
// against our own seal, so a wire change cannot pass silently -
// an intentional one breaks these tests, and regenerating the vectors
// diffs as the changelog.
//
// Three kinds, and `vectorFormat` says which. Format 1 is a render, replayed by
// sealing and diffing. Format 2 is an unlock request that must not be answered
// as asked, replayed by posting it through the port and reading what came back.
// Format 3 is an RSA-OAEP open vector: a recorded ciphertext decrypted with the
// private fixture key, the binding rebuilt from the recorded inputs and the
// recovered BIND-plus-key compared whole - the direction OAEP's self-randomized
// padding forces, since an RSA seal cannot be replayed byte for byte.
// A file whose format is none of these fails the run rather than being skipped -
// a replay that quietly ignores what it does not recognise reports green for
// vectors it never executed.
//
// Passes per seal vector, plus the retired-option check at the end:
//
//   a. re-seal from `input` and deep-equal `expected` - the wire, byte for byte
//      but for the JWT signature segment, which cannot be pinned
//   b. the recorded signature verifies under the recorded public JWK
//   c. the recorded binding values are what the grammar joins, and each blob
//      opens at its own coordinate and refuses every other
//   d. unseal each recorded blob with the issuer private key
//   e. decrypt each recorded ciphertext with the recovered contentKey
//   f. compare each publisher-private input periodKey with the recovered bytes
//   g. the cached path end to end: unseal a periodKey, trial-unwrap the
//      contentKey out of the item record's `keys`, decrypt with it
//   h. a recorded blob opens with the binding alone, and a stated `kdf` is
//      refused rather than read under a second construction
//
// Passes per reject vector:
//
//   a. `rawBody` is a string and it is JSON - the vector pins the check it
//      names, not a parse error
//   b. posted VERBATIM through the port it is answered the recorded way: the
//      recorded status and code, key material at exactly the recorded
//      coordinates and nowhere else, an error at exactly the recorded ones, and
//      the key store reached only as far as the refusal allows
//   c. the same issuer, holding the same keys, answers 200 to the honest
//      request built from the render it was cut from - so the refusal is the
//      attack and not a harness that says no to everything
//
// The vectors pin how far a refusal reaches. A request that fails integrity is
// refused whole before the key store is consulted. A blob presented at a
// coordinate it was not sealed at is one error beside the coordinates that did
// open: the issuer cannot tell it from a key rollover, and the untouched
// coordinates were never the attack.
//
// The replay posts the recorded string. `reject-duplicate-member-name` repeats
// a member name, which a parsed object cannot hold, so a replay that
// re-serializes the body before posting it has destroyed the vector before
// running it.
//
// These vectors record no signature bytes. ES256 draws a random `k` per
// signature, and WebCrypto has no way to supply one, so the third segment of
// the resourceJWT is different every run. Recording it and comparing would fail
// on a correct implementation. What is byte-stable is the header and payload
// segments, and those compare exactly; the signature is verified instead of
// compared. It is the only place in these files where a replay checks rather
// than diffs, and arithmetic forces it.
//
// The vector pins which check runs, and so does a test at the end that stands
// up an issuer taking the algorithm from the token header. That issuer refuses
// the forged and the tampered envelope like any other, since both name ES256
// and both fail an honest ECDSA verify, so nothing else in this directory
// touches it: the two reject-alg-substituted arms are what does, and the test
// is here to keep it that way.
//
// Reading the vectors needs the filesystem, which core, ports and actors
// never touch. This is a test file, so `node:fs` is at hand here the way
// `node:test` is.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  buildIssuer,
  buildSealer,
  importIssuerPrivateKey,
  importPublisherKeys,
  recoverContentKeys,
  recoverPeriodKeys,
} from "../tools/vectorWorld.js";
import { open as unseal } from "../core-shared--publisher-issuer/keySealing.js";
import {
  unseal as unbannedUnseal,
  unbannedBindValue,
} from "../tools/vector-fixtures/unbannedSealing.js";
import {
  bindValue,
  BIND_DELIMITER,
  RENDER_ID_BYTES,
} from "../core-shared--publisher-issuer/bind.js";
import { decrypt } from "../core-shared/aead.js";
import { contentAadOctets } from "../test-reference/support/contentAadOctets.js";
import { contentKeyWrapNonceOctets } from "../test-reference/support/contentKeyWrapNonceOctets.js";
import { isAccessGroup, isContentName, isIssuerName } from "../core-shared/names.js";
import { recordsByName } from "../core-shared--client-publisher/deliveryRecords.js";
import { verify, decodeHeader, sign } from "../core-shared--publisher-issuer/jwt.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { base64urlDecode, base64urlEncode, utf8Encode, utf8Decode } from "../core-shared/codec.js";
import { Client } from "../test-lib/harnesses/client.js";
import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { publisherRegistrationsOver } from "../demo/scenarios/world.js";
import { openingKeysOver } from "../demo/support/PublisherRegistrations.js";
import { AllowAllPolicy } from "../demo/support/AllowAllPolicy.js";
import { withoutSignatures } from "../test-lib/helpers/inspect.js";
import { refuses } from "../test-lib/helpers/refuses.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";

// The replay loads all three packages together: each reject vector names the
// render it was cut from in `derivedFrom`, and that render, seal-ecdh.json, sits
// in the period-key package while the rejects sit in all three.
const FIXTURE_DIRS = [
  "fixtures/v1/baseline/issuer-admission/",
  "fixtures/v1/profiles/dca-profile-period-keys/issuer-admission/",
  "fixtures/v1/reference/protocol-regressions/",
].map((path) => fileURLToPath(new URL(`../../verification/${path}`, import.meta.url)));
const VECTOR_DIR = fileURLToPath(
  new URL("../../verification/vectors/v1/baseline/rsa-oaep-envelope-open/", import.meta.url),
);

const { subtle } = globalThis.crypto;

/** What this replay can execute. Anything else on disk is a failure, not a skip. */
const SEAL_FORMAT = "1";
const REJECT_FORMAT = "2";

/**
 * An open vector: a recorded RSA-OAEP ciphertext with the private fixture key,
 * replayed by decrypting it and rebuilding the binding rather than by re-sealing.
 * OAEP draws its padding inside WebCrypto, so no RSA render is byte-reproducible
 * and a seal vector is impossible; what this pins is the unseal and the
 * `BIND ‖ key` plaintext an implementation in another runtime has to recover.
 */
const OPEN_FORMAT = "3";

/**
 * A render built through the Sealer factory from plain setup.
 * `sealer-factory-records.test.js` beside this file replays it, and checks
 * that it reaches every fixture of this format the manifest names.
 */
const SEALER_FACTORY_FORMAT = "sealer-factory-v3";

/** A set of Sealer factory refusals; the same file replays it. */
const SEALER_REFUSAL_FORMAT = "sealer-factory-refusal-v2";

/** Uncompressed P-256 point, the first field of an ECDH blob. */
const EPHEMERAL_BYTES = 65;

/**
 * Every token in one wire, with the path that reached it. One per vector here:
 * the resource is what the publisher signs, and the renderId under it is what
 * every sealed blob of the render is bound to.
 *
 * @param {any} dcaData
 * @returns {[string, string][]}
 */
function tokensOf(dcaData) {
  return [["resourceJWT", dcaData.resourceJWT]];
}

/** The resource is carried only by the compact JWT payload. */
function resourceOf(dcaData) {
  return decodeCompactJwt(dcaData.resourceJWT).payload;
}

/**
 * The set-level manifest, which names the set and its phase. Skipped by name
 * rather than by shape: every other .json in the directory is a vector, and a
 * loader that skips whatever it cannot read reports green for files it never
 * executed.
 */
const SET_MANIFEST = "set.json";
const FIXTURE_MANIFEST = "manifest.json";

const FORMAT_PROOFS = {
  3: { proofBoundary: "carrier", operation: "open", projection: "recovered-binding-and-key" },
};

/**
 * Every vector on disk, in name order so a run reports the same way twice.
 *
 * @returns {{ file: string, vector: any }[]}
 */
function loadVectors(dir, metadataFile) {
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json") && name !== metadataFile)
    .sort()
    .map((file) => ({ file, vector: JSON.parse(readFileSync(dir + file, "utf8")) }));
}

/**
 * Every string in the expected wire, with the path that reached it. What the
 * unpadded-base64url check walks.
 *
 * @param {any} node
 * @param {string} path
 * @returns {[string, string][]}
 */
function wireStrings(node, path = "") {
  if (typeof node === "string") return [[path, node]];
  if (node === null || typeof node !== "object") return [];
  return Object.entries(node).flatMap(([key, value]) => wireStrings(value, `${path}.${key}`));
}

/**
 * One issuer's block of a delivery. `issuerData` is an array of records named
 * by `issuerName`.
 *
 * @param {any} dcaData
 * @param {string} issuerName
 * @returns {any}
 */
function issuerBlock(dcaData, issuerName) {
  return recordsByName(dcaData.issuerData, "issuerName", isIssuerName)?.get(issuerName);
}

/**
 * One item record of a delivery. `contentData` is an array of records named by
 * `contentName`.
 *
 * @param {any} dcaData
 * @param {string} contentName
 * @returns {any}
 */
function contentRecord(dcaData, contentName) {
  return recordsByName(dcaData.contentData, "contentName", isContentName)?.get(contentName);
}

/** The identity fields of each key record kind, outermost first. */
const KEY_RECORD_COORDINATES = {
  contentKeys: ["contentName"],
  periodKeys: ["accessGroup", "period"],
  chainKeys: ["accessGroup", "cutoff"],
};

/**
 * A sealed section or a response `keys` section, read from its record arrays
 * into the nested shape the vectors' own `bindings`, `contentKeys` and
 * `periodKeys` projections use: `{ contentKeys: { name: key }, periodKeys:
 * { group: { period: key } } }`. Each render here seals one blob per
 * coordinate, so a repeated coordinate fails the test rather than fold into
 * one entry. Names are defined as own properties, so `__proto__` stays a name.
 *
 * @param {any} section
 * @returns {any}
 */
function keysByCoordinate(section) {
  /** @type {any} */
  const nested = {};
  for (const [kind, fields] of Object.entries(KEY_RECORD_COORDINATES)) {
    if (section?.[kind] === undefined) continue;
    nested[kind] = {};
    for (const record of section[kind]) {
      let level = nested[kind];
      for (const field of fields.slice(0, -1)) {
        if (!Object.hasOwn(level, record[field])) defineName(level, record[field], {});
        level = level[record[field]];
      }
      const name = record[fields.at(-1)];
      assert.ok(!Object.hasOwn(level, name), `${kind} repeats ${JSON.stringify(record)}`);
      defineName(level, name, record.key);
    }
  }
  return nested;
}

/**
 * @param {any} target
 * @param {string} name
 * @param {unknown} value
 */
function defineName(target, name, value) {
  Object.defineProperty(target, name, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

const fixtureVectors = FIXTURE_DIRS.flatMap((dir) => loadVectors(dir, FIXTURE_MANIFEST));
const primitiveVectors = loadVectors(VECTOR_DIR, SET_MANIFEST);
const vectors = [...fixtureVectors, ...primitiveVectors];
const sealVectors = vectors.filter(({ vector }) => vector.vectorFormat === SEAL_FORMAT);
const rejectVectors = vectors.filter(({ vector }) => vector.vectorFormat === REJECT_FORMAT);
const openVectors = vectors.filter(({ vector }) => vector.vectorFormat === OPEN_FORMAT);
const sealerFactoryVectors = vectors.filter(({ vector }) =>
  [SEALER_FACTORY_FORMAT, SEALER_REFUSAL_FORMAT].includes(vector.vectorFormat),
);

test("the optional baseline RSA-OAEP package records the open projection", () => {
  const manifest = JSON.parse(readFileSync(VECTOR_DIR + SET_MANIFEST, "utf8"));
  assert.deepEqual(manifest.formatProofs?.[OPEN_FORMAT], FORMAT_PROOFS[OPEN_FORMAT]);
});

test("the replay loads every payload of the three protocol fixture packages", () => {
  const files = fixtureVectors.map(({ file }) => file);
  assert.equal(files.length, 30, "17 baseline, 7 period-key and 6 reference payloads");
  assert.equal(new Set(files).size, files.length, "no payload sits in two packages");
});

test("every selected fixture and vector is a format this replay executes", () => {
  // The one check that has to run before the loops: a vector nobody replays
  // would pass without ever being executed.
  for (const { file, vector } of vectors) {
    assert.ok(
      [
        SEAL_FORMAT,
        REJECT_FORMAT,
        OPEN_FORMAT,
        SEALER_FACTORY_FORMAT,
        SEALER_REFUSAL_FORMAT,
      ].includes(vector.vectorFormat),
      `${file} is vectorFormat ${JSON.stringify(vector.vectorFormat)}, which no replay here executes`,
    );
  }
  assert.equal(
    sealVectors.length + rejectVectors.length + openVectors.length + sealerFactoryVectors.length,
    vectors.length,
  );
  assert.equal(
    primitiveVectors.length,
    readdirSync(VECTOR_DIR).filter((name) => name.endsWith(".json") && name !== SET_MANIFEST)
      .length,
    "every RSA-OAEP package vector on disk reaches the format guard",
  );
});

test("there are vectors to replay", () => {
  assert.ok(sealVectors.length >= 1, "the render the format specifies is pinned");
  assert.ok(rejectVectors.length >= 15, "and the requests an issuer has to refuse");
  assert.ok(openVectors.length >= 1, "and the base RSA-OAEP open vector");
});

test("the noncanonical-renderId rejection is signed, 16 decoded bytes, and not its own spelling", async () => {
  const { vector } = vectors.find(({ file }) => file === "reject-renderid-noncanonical.json") ?? {};
  assert.ok(vector, "the canonical-encoding clause has a generator-owned reject vector");

  const request = JSON.parse(vector.rawBody);
  const { publicKey } = (
    await importPublisherKeys({
      signingKeys: vector.publisher.signingKeys,
    })
  ).get(vector.publisher.signingKeys[0].kid);
  const resource = await verify(request.resourceJWT, publicKey);
  const decoded = base64urlDecode(resource.renderId);

  assert.equal(resource.renderId.length, 22, "the spelling has the normal 16-byte width");
  assert.equal(decoded.length, RENDER_ID_BYTES, "the spelling decodes to the normal width");
  assert.notEqual(
    base64urlEncode(decoded),
    resource.renderId,
    "only non-zero unused tail bits differ",
  );
  assert.equal(
    vector.expected.privateKeyReached,
    false,
    "canonical spelling is checked before a private key",
  );
});

describe("the open vectors", () => {
  for (const { file, vector } of openVectors) {
    test(`${file}: the recorded envelope follows its binding and payload width`, async () => {
      const { input, expected } = vector;

      // The private fixture key, imported the way the format fixes it:
      // RSA-OAEP over SHA-256, no label.
      assert.equal(input.algorithm, "rsa-oaep", "the fixture names its carrier");
      assert.equal(input.hash, "SHA-256", "and the hash the format fixes it to");
      const privateKey = await subtle.importKey(
        "jwk",
        input.rsa.privateKeyJwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"],
      );

      const ciphertext = base64urlDecode(expected.blob);
      assert.equal(ciphertext.length, 256, "one modulus wide, whatever it carries");

      assert.equal(
        bindValue(input.binding),
        expected.bind,
        "the recorded bind is the one the inputs build",
      );

      if (expected.error !== undefined) {
        assert.deepEqual(Object.keys(expected).sort(), ["bind", "blob", "error"]);
        assert.equal(expected.error, "unseal_failed");

        // The recorded ciphertext itself opens. The requested BIND is a
        // prefix of its plaintext, but the full plaintext is wider than the
        // required BIND || 16-byte key, and its trailing key is the fixture
        // key. This makes a prefix comparison or last-16-byte split fail the
        // case for a concrete reason rather than because the ciphertext is bad.
        const plaintext = new Uint8Array(
          await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, ciphertext),
        );
        const bindingBytes = utf8Encode(expected.bind);
        assert.deepEqual(plaintext.subarray(0, bindingBytes.length), bindingBytes);
        if (file === "open-rsa-oaep-prefix-confusion.json") {
          assert.equal(plaintext.length, bindingBytes.length + 4 + 16);
          assert.equal(
            utf8Decode(plaintext.subarray(0, plaintext.length - 16)),
            `${expected.bind}text`,
          );
        } else if (file === "open-rsa-oaep-long-tail.json") {
          assert.equal(plaintext.length, bindingBytes.length + 32);
          assert.equal(
            base64urlEncode(plaintext.subarray(bindingBytes.length, bindingBytes.length + 16)),
            input.contentKeyBase64url,
          );
        }
        assert.equal(
          base64urlEncode(plaintext.subarray(plaintext.length - 16)),
          input.contentKeyBase64url,
        );
        await refuses(
          () => unseal(expected.blob, privateKey, "rsa-oaep", { binding: input.binding }),
          expected.error,
          "the full BIND and exact payload width must be checked",
        );
        return;
      }

      assert.deepEqual(Object.keys(expected).sort(), ["bind", "blob", "plaintextBase64url"]);

      // Rebuild the binding from the recorded inputs and open with it. The
      // recovered value is the content key, and it is what the vector
      // records under contentKeyBase64url.
      const opened = await unseal(expected.blob, privateKey, "rsa-oaep", {
        binding: input.binding,
      });
      assert.equal(base64urlEncode(opened), input.contentKeyBase64url);

      // The recorded plaintext an implementation in another runtime
      // compares against without loading this code: the bind value, then
      // the 16-byte key.
      const plaintext = base64urlDecode(expected.plaintextBase64url);
      assert.equal(plaintext.length, utf8Encode(expected.bind).length + 16);
      assert.equal(
        utf8Decode(plaintext.subarray(0, plaintext.length - 16)),
        expected.bind,
        "the plaintext prefix is the bind value",
      );
      assert.equal(
        base64urlEncode(plaintext.subarray(plaintext.length - 16)),
        input.contentKeyBase64url,
      );

      // The prefix is checked after the unseal, and it is the whole
      // relabel defence on this carrier: the same blob rebuilt for another
      // coordinate does not open.
      const wrongBinding = { ...input.binding, contentName: "bodytext" };
      await refuses(
        () => unseal(expected.blob, privateKey, "rsa-oaep", { binding: wrongBinding }),
        "unseal_failed",
        "the same blob, rebuilt for another slot",
      );
    });
  }
});

for (const { file, vector } of sealVectors) {
  test(`${file}: re-sealing the input reproduces the wire byte for byte`, async () => {
    const sealer = await buildSealer(vector.input);
    const { dcaData, sealedContent } = await sealer.seal();

    assert.deepEqual(withoutSignatures(dcaData), withoutSignatures(vector.expected.dcaData));
    assert.deepEqual(sealedContent, vector.expected.sealedContent);

    // Said the other way round, so the exception cannot quietly widen: the
    // signature segment is the only thing that moved.
    const before = tokensOf(vector.expected.dcaData).map(([, token]) => token.split(".")[2]);
    const after = tokensOf(dcaData).map(([, token]) => token.split(".")[2]);

    assert.equal(after.length, 1, "one resourceJWT, and it is the only signature on the wire");
    for (let index = 0; index < after.length; index++) {
      assert.notEqual(after[index], before[index], "a fresh k, every signature");
    }
  });

  test(`${file}: two seals of one input differ in nothing but the signature`, async () => {
    // The determinism the generator promises, run twice in one process
    // rather than trusted. A draw that leaked back into a render - a fresh
    // ephemeral keypair, an unseeded render id - shows up here as a diff
    // outside the one segment that is allowed to move.
    const first = await (await buildSealer(vector.input)).seal();
    const second = await (await buildSealer(vector.input)).seal();

    assert.deepEqual(withoutSignatures(first.dcaData), withoutSignatures(second.dcaData));
    assert.deepEqual(first.sealedContent, second.sealedContent);
  });

  test(`${file}: the recorded signature verifies under the recorded public key`, async () => {
    // What replaces the byte compare. A vector whose signature was edited,
    // truncated or copied from its sibling fails here.
    const publisherKeys = await importPublisherKeys(vector.input);

    for (const [path, token] of tokensOf(vector.expected.dcaData)) {
      const header = decodeHeader(token);
      assert.equal(header.alg, "ES256", `${path} is ES256`);
      assert.equal(header.typ, "JWT");
      assert.equal(header.kid, vector.input.signingKid, `${path} names the signing key`);

      const entry = publisherKeys.get(header.kid);
      assert.ok(entry, `${path} names a key the vector carries`);

      const payload = await verify(token, entry.publicKey);
      assert.ok(payload, `${path} verifies`);

      // A signature that is not this one does not pass, so the check
      // above is doing work.
      const [head, body, signature] = token.split(".");
      const flipped = base64urlDecode(signature);
      flipped[0] ^= 0xff;
      await refuses(
        () => verify(`${head}.${body}.${base64urlEncode(flipped)}`, entry.publicKey),
        "bad_signature",
        `${path} rejects a changed signature`,
      );
    }
  });

  test(`${file}: the signed envelope carries the render and the anchor its blobs need`, async () => {
    const publisherKeys = await importPublisherKeys(vector.input);
    const { publicKey } = publisherKeys.get(vector.input.signingKid);

    const resource = await verify(vector.expected.dcaData.resourceJWT, publicKey);
    assert.deepEqual(
      resource,
      resourceOf(vector.expected.dcaData),
      "the payload is the resource, no wrapper",
    );

    // The renderId an issuer builds every binding from is this signed one,
    // never the request's own word for it, and it carries the entropy a
    // cross-render substitution has to guess.
    assert.equal(typeof resource.renderId, "string");
    assert.equal(base64urlDecode(resource.renderId).length, RENDER_ID_BYTES);
  });

  test(`${file}: the recorded binding values are what the grammar joins`, () => {
    // The value with no crypto in the way, which is the pass an
    // implementation runs first: a builder that is wrong here produces
    // blobs that open nowhere, and every later failure looks like a tag
    // mismatch with nothing to say why.
    const renderId = resourceOf(vector.expected.dcaData).renderId;
    const sealed = keysByCoordinate(
      issuerBlock(vector.expected.dcaData, vector.input.issuers[0].issuerName).sealed,
    );

    /** @type {any} */
    const rebuilt = { contentKeys: {}, periodKeys: {} };
    for (const contentName of Object.keys(sealed.contentKeys)) {
      rebuilt.contentKeys[contentName] = bindValue({ renderId, contentName });
    }
    for (const [accessGroup, periods] of Object.entries(sealed.periodKeys)) {
      rebuilt.periodKeys[accessGroup] = {};
      for (const t of Object.keys(/** @type {any} */ (periods))) {
        rebuilt.periodKeys[accessGroup][t] = bindValue({ renderId, accessGroup, t });
      }
    }

    assert.deepEqual(rebuilt, vector.expected.bindings);

    // Spelled out once, so the recorded strings are held to the layout and
    // not merely to whatever this codebase happens to join today.
    assert.equal(
      vector.expected.bindings.contentKeys.bodytext,
      `dca-bind-key-envelope|c|${renderId}|bodytext`,
    );
    assert.equal(
      vector.expected.bindings.periodKeys.premium["251023T1400"],
      `dca-bind-key-envelope|p|${renderId}|premium|251023T1400`,
    );
  });

  test(`${file}: a recorded blob opens at its own coordinate and refuses every other`, async () => {
    // The binding, executed against the wire it protects. Each of these
    // moves is a text edit on a page: relabel a blob, move it between
    // families or periods, lift it into another render.
    const [issuer] = vector.input.issuers;
    const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
    const renderId = resourceOf(vector.expected.dcaData).renderId;
    const sealed = keysByCoordinate(issuerBlock(vector.expected.dcaData, issuer.issuerName).sealed);

    /** A renderId of the right width that is not this render's. */
    const foreignRenderId = base64urlEncode(base64urlDecode(renderId).map((byte) => byte ^ 0xff));

    /**
     * @param {string} blob
     * @param {any} binding
     */
    const opens = (blob, binding) => unseal(blob, privateKey, issuer.algorithm, { binding });

    /**
     * Every move in this test is refused the same way, so the coordinate is
     * the argument and the code is not.
     *
     * @param {string} blob
     * @param {any} binding
     * @param {string} why
     */
    const refusesAt = (blob, binding, why) =>
      refuses(() => opens(blob, binding), "unseal_failed", why);

    const [first, second] = Object.keys(sealed.contentKeys);
    for (const [contentName, other] of [
      [first, second],
      [second, first],
    ]) {
      const blob = sealed.contentKeys[contentName];

      assert.equal(
        base64urlEncode(await opens(blob, { renderId, contentName })),
        vector.expected.contentKeys[contentName],
        `${contentName} opens at its own coordinate`,
      );
      await refusesAt(blob, { renderId, contentName: other }, `${contentName} read as ${other}`);
      await refusesAt(
        blob,
        { renderId: foreignRenderId, contentName },
        `${contentName} lifted into another render`,
      );
    }

    const [group, otherGroup] = Object.keys(sealed.periodKeys);
    const [period, otherPeriod] = Object.keys(sealed.periodKeys[group]);
    const periodBlob = sealed.periodKeys[group][period];

    assert.equal(
      base64urlEncode(await opens(periodBlob, { renderId, accessGroup: group, t: period })),
      vector.expected.periodKeys[group][period],
      "the periodKey opens at its own coordinate",
    );
    await refusesAt(
      periodBlob,
      { renderId, accessGroup: otherGroup, t: period },
      "a periodKey moved between families",
    );
    await refusesAt(
      periodBlob,
      { renderId, accessGroup: group, t: otherPeriod },
      "a periodKey moved between periods",
    );
    // The kind char and the field arity, which is what keeps a contentName
    // and an accessGroup that share a spelling from sharing a value.
    await refusesAt(
      periodBlob,
      { renderId, contentName: group },
      "a periodKey read as a contentKey of the same name",
    );
  });

  test(`${file}: the issuer unseals every recorded contentKey`, async () => {
    for (const issuer of vector.input.issuers) {
      const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
      const renderId = resourceOf(vector.expected.dcaData).renderId;
      const sealed = keysByCoordinate(
        issuerBlock(vector.expected.dcaData, issuer.issuerName).sealed,
      ).contentKeys;

      for (const [contentName, blob] of Object.entries(sealed)) {
        const contentKey = await unseal(
          /** @type {string} */ (blob),
          privateKey,
          issuer.algorithm,
          {
            binding: { renderId, contentName },
          },
        );

        assert.equal(contentKey.length, 16, "AES-128");
        assert.equal(
          base64urlEncode(contentKey),
          vector.expected.contentKeys[contentName],
          `${contentName} recovers the recorded contentKey`,
        );
      }
    }
  });

  test(`${file}: the recorded ciphertext decrypts to the input value`, async () => {
    const [issuer] = vector.input.issuers;
    const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
    const renderId = resourceOf(vector.expected.dcaData).renderId;
    const sealed = keysByCoordinate(
      issuerBlock(vector.expected.dcaData, issuer.issuerName).sealed,
    ).contentKeys;

    for (const item of vector.input.content) {
      const contentKey = await unseal(sealed[item.name], privateKey, issuer.algorithm, {
        binding: { renderId, contentName: item.name },
      });
      const record = contentRecord(vector.expected.dcaData, item.name);
      assert.equal(Object.hasOwn(record, "aad"), false, `${item.name}: the record carries no aad`);
      // The hand-built transcript, not the reference module, gives the AAD,
      // and the recorded projection a port checks its builder against agrees.
      const aad = contentAadOctets(vector.expected.dcaData, item.name);
      assert.equal(
        vector.expected.contentOpen[item.name].aadBase64url,
        base64urlEncode(aad),
        `${item.name}: the recorded aad projection is the derived content AAD`,
      );

      const plaintext = await decrypt(
        contentKey,
        new Uint8Array(12),
        base64urlDecode(vector.expected.sealedContent[item.name]),
        aad,
      );

      assert.equal(utf8Decode(plaintext), item.value);
      assert.equal(record.contentType, item.contentType);
    }
  });

  test(`${file}: recovered periodKeys equal the publisher's period-key inputs`, async () => {
    let checked = 0;
    for (const [accessGroup, periods] of Object.entries(vector.expected.periodKeys)) {
      for (const [t, recorded] of Object.entries(/** @type {any} */ (periods))) {
        const supplied = base64urlDecode(vector.input.periodKeys[accessGroup][t]);

        assert.equal(supplied.length, 16, "AES-128");
        assert.equal(base64urlEncode(supplied), recorded, `${accessGroup} ${t}`);
        checked++;
      }
    }
    assert.equal(checked, 4, "two accessGroups over two periods");
  });

  test(`${file}: a periodKey unwraps the contentKey, which decrypts the content`, async () => {
    // The cached path, the way a client walks it: the issuer unseals the
    // periodKey, the client trial-unwraps the wrapped contentKey out of
    // the item record, and that key opens the ciphertext. No contentKey
    // is handed over anywhere in this pass.
    const [issuer] = vector.input.issuers;
    const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
    const renderId = resourceOf(vector.expected.dcaData).renderId;
    const sealedPeriodKeys = keysByCoordinate(
      issuerBlock(vector.expected.dcaData, issuer.issuerName).sealed,
    ).periodKeys;

    for (const item of vector.input.content) {
      const entries = contentRecord(vector.expected.dcaData, item.name).keys;

      for (const entry of /** @type {any[]} */ (entries)) {
        const { accessGroup, period } = entry;
        const periodKey = await unseal(
          sealedPeriodKeys[accessGroup][period],
          privateKey,
          issuer.algorithm,
          { binding: { renderId, accessGroup, t: period } },
        );
        assert.equal(
          base64urlEncode(periodKey),
          vector.expected.periodKeys[accessGroup][period],
          "the sealed blob and the publisher-private input agree",
        );

        // No AAD - the periodKey is already accessGroup-specific. The entry
        // carries its coordinate and no nonce: the wrap nonce derives from
        // that coordinate.
        assert.deepEqual(Object.keys(entry).sort(), ["accessGroup", "key", "period"]);
        const contentKey = await decrypt(
          periodKey,
          contentKeyWrapNonceOctets({
            renderId,
            contentName: item.name,
            accessGroup,
            t: period,
          }),
          base64urlDecode(entry.key),
        );
        assert.equal(base64urlEncode(contentKey), vector.expected.contentKeys[item.name]);

        const plaintext = await decrypt(
          contentKey,
          new Uint8Array(12),
          base64urlDecode(vector.expected.sealedContent[item.name]),
          contentAadOctets(vector.expected.dcaData, item.name),
        );
        assert.equal(utf8Decode(plaintext), item.value);
      }
    }
  });

  test(`${file}: the client's periods and the issuer's name the same t`, () => {
    // The two sides of the cached path are separate sections of the wire
    // and have to agree, or the client holds keys for periods no entry was
    // wrapped under.
    const sealedPeriodKeys = keysByCoordinate(
      issuerBlock(vector.expected.dcaData, vector.input.issuers[0].issuerName).sealed,
    ).periodKeys;

    for (const { contentName, keys } of vector.expected.dcaData.contentData) {
      /** @type {Map<string, string[]>} */
      const periodsByGroup = new Map();
      for (const { accessGroup, period } of keys) {
        periodsByGroup.set(accessGroup, [...(periodsByGroup.get(accessGroup) ?? []), period]);
      }
      for (const [accessGroup, periods] of periodsByGroup) {
        assert.deepEqual(
          periods,
          Object.keys(sealedPeriodKeys[accessGroup]),
          `${contentName} under ${accessGroup}`,
        );
      }
    }
  });

  test(`${file}: every wire value is unpadded base64url`, () => {
    // The trap no schema expresses. A runtime whose encoder pads, or emits
    // standard base64, produces strings that decode to the same bytes and
    // still fail every binding they enter, since the renderId is bound as
    // the string the wire carries.
    // Records name their coordinate in identity fields beside `key`; the
    // encoded values are the `key` fields.
    const encoded = wireStrings(vector.expected.dcaData.contentData)
      .concat(wireStrings(vector.expected.dcaData.issuerData))
      .filter(([path]) => path.endsWith(".key"))
      .concat(wireStrings(vector.expected.sealedContent))
      .concat(wireStrings(vector.expected.contentKeys))
      .concat(wireStrings(vector.expected.periodKeys))
      .concat([[".resourceJWT.payload.renderId", resourceOf(vector.expected.dcaData).renderId]]);

    assert.ok(encoded.length > 0, "the walk found the encoded values");
    for (const [path, value] of encoded) {
      assert.match(value, /^[A-Za-z0-9_-]+$/, `${path} carries no padding and no + or /`);
    }
  });

  test(`${file}: the injected ephemeral public key is the blob's first 65 bytes`, () => {
    // What makes the run replayable, asserted rather than assumed: the
    // ephemeral keypair the vector supplies is the one that reached the
    // wire, so a fresh generateKey slipping back in fails here.
    for (const ephemeral of vector.input.ephemeralKeys) {
      const sealed = keysByCoordinate(
        issuerBlock(vector.expected.dcaData, ephemeral.issuerName).sealed,
      );
      const blob = base64urlDecode(
        ephemeral.contentName === undefined
          ? sealed[ephemeral.chainKey === true ? "chainKeys" : "periodKeys"][ephemeral.accessGroup][
              ephemeral.t
            ]
          : sealed.contentKeys[ephemeral.contentName],
      );
      const point = blob.subarray(0, EPHEMERAL_BYTES);

      assert.equal(point[0], 0x04, "uncompressed point");
      assert.equal(base64urlEncode(point.subarray(1, 33)), ephemeral.publicKeyJwk.x);
      assert.equal(base64urlEncode(point.subarray(33, 65)), ephemeral.publicKeyJwk.y);
    }
  });
}

test("a recorded blob opens on the binding alone, and a stated kdf is refused", async () => {
  // The retired reading, pinned where it used to be recorded. The envelope
  // uses the agreed x-coordinate as the AES key and nothing derives from it,
  // so `kdf` names nothing the module does and is refused rather than read.
  // The refusal is what keeps a caller that believes it asked for a
  // derivation from getting a blob built the other way.
  for (const { file, vector } of sealVectors) {
    const issuer = vector.input.issuers[0];
    assert.equal(
      Object.hasOwn(issuer, "kdf"),
      false,
      `${file}: the recorded issuer states no derivation setting`,
    );

    const privateKey = await importIssuerPrivateKey(issuer.privateKeyJwk);
    const renderId = resourceOf(vector.expected.dcaData).renderId;
    const sealed = keysByCoordinate(
      issuerBlock(vector.expected.dcaData, issuer.issuerName).sealed,
    ).contentKeys;

    for (const [contentName, blob] of Object.entries(sealed)) {
      assert.equal(
        base64urlEncode(
          await unseal(/** @type {string} */ (blob), privateKey, issuer.algorithm, {
            binding: { renderId, contentName },
          }),
        ),
        vector.expected.contentKeys[contentName],
        `${file}: ${contentName} opens on its binding alone`,
      );

      for (const kdf of ["none", "hkdf"]) {
        await refuses(
          () =>
            unseal(/** @type {string} */ (blob), privateKey, issuer.algorithm, {
              kdf,
              binding: { renderId, contentName },
            }),
          "unsupported_option",
          `${file}: ${contentName} presented with kdf ${JSON.stringify(kdf)}`,
        );
      }
    }
  }
});

test("the recorded keys are what the recovery helpers return", async () => {
  // The generator writes `expected.contentKeys` and `expected.periodKeys`
  // from these calls, so a vector whose keys were edited by hand rather than
  // regenerated shows up here.
  for (const { file, vector } of sealVectors) {
    assert.deepEqual(
      await recoverContentKeys(vector.input, vector.expected.dcaData),
      vector.expected.contentKeys,
      file,
    );
    assert.deepEqual(
      await recoverPeriodKeys(vector.input, vector.expected.dcaData),
      vector.expected.periodKeys,
      file,
    );
  }
});

describe("the refusals", () => {
  // Every test in here runs a format-2 vector: a request that must not be
  // answered as asked, posted through the same port a real one goes through.

  /**
   * The render a reject vector was cut from, so a test can hold the answer
   * against the keys that render really produced.
   *
   * @param {any} vector
   * @returns {any}
   */
  function baseOf(vector) {
    const found = sealVectors.find(({ vector: seal }) => seal.name === vector.derivedFrom);
    assert.ok(found, `${vector.name} names ${vector.derivedFrom}, which is not in this directory`);
    return found.vector;
  }

  /**
   * Every key the base render produced, in the encoding a response would carry
   * them in, keyed by the coordinate it belongs at. A key that comes back
   * anywhere else has been handed to the attacker.
   *
   * @param {any} base
   * @returns {Map<string, string>}
   */
  function keysOf(base) {
    /** @type {Map<string, string>} */
    const keys = new Map();
    for (const [contentName, key] of Object.entries(base.expected.contentKeys)) {
      keys.set(`contentKeys.${contentName}`, /** @type {string} */ (key));
    }
    for (const [accessGroup, periods] of Object.entries(base.expected.periodKeys)) {
      for (const [t, key] of Object.entries(/** @type {any} */ (periods))) {
        keys.set(`periodKeys.${accessGroup}.${t}`, /** @type {string} */ (key));
      }
    }
    return keys;
  }

  /**
   * The coordinates one recorded expectation says come back with key material.
   *
   * @param {any} expected
   * @returns {Set<string>}
   */
  function grantedCoordinates(expected) {
    const granted = new Set(
      expected.keys.contentKeys.map((/** @type {string} */ n) => `contentKeys.${n}`),
    );
    for (const [accessGroup, periods] of Object.entries(expected.keys.periodKeys ?? {})) {
      for (const t of /** @type {string[]} */ (periods))
        granted.add(`periodKeys.${accessGroup}.${t}`);
    }
    return granted;
  }

  /**
   * What one response actually handed over, by the same coordinate names, one
   * entry per response record. A coordinate answered twice appears twice, so
   * it cannot pass as the one recorded coordinate.
   *
   * @param {any} body
   * @returns {[string, string][]}
   */
  function answeredKeys(body) {
    /** @type {[string, string][]} */
    const answered = [];
    const keys = body?.keys ?? {};

    for (const { contentName, key } of keys.contentKeys ?? []) {
      answered.push([`contentKeys.${contentName}`, key]);
    }
    for (const { accessGroup, period, key } of keys.periodKeys ?? []) {
      answered.push([`periodKeys.${accessGroup}.${period}`, key]);
    }
    return answered;
  }

  /**
   * The coordinates one response reported as failed, one entry per error
   * record.
   *
   * @param {any} body
   * @returns {string[]}
   */
  function failedCoordinates(body) {
    return (body?.errors ?? []).map((/** @type {any} */ record) => record.coordinate);
  }

  for (const { file, vector } of rejectVectors) {
    test(`${file}: rawBody is the request verbatim, and it is JSON`, () => {
      assert.equal(typeof vector.rawBody, "string", "a request, not a parsed object");

      const parsed = JSON.parse(vector.rawBody);
      assert.equal(parsed.issuerName, vector.issuer.issuerName);
      assert.equal(parsed.keyId, vector.issuer.keyId);
      assert.equal(typeof parsed.resourceJWT, "string", "one envelope, and it carries the anchor");
    });

    test(`${file}: the port answers the recorded body the recorded way`, async () => {
      const { endpoint, processor, registration, asked } = await buildIssuer(vector);

      // Verbatim: the recorded string is what the vector pins, and
      // re-serializing it here would be the mistake the duplicate-member
      // vector exists to catch.
      const response = await unlockThroughAdmission(
        processor,
        endpoint,
        vector.rawBody,
        registration,
      );
      const body = /** @type {any} */ (response.body);

      if (vector.expected.code !== null) {
        // Refused whole: a code, and nothing that could be read as an
        // answer to any part of the request.
        assert.equal(body.error, vector.expected.code, file);
        assert.equal(body.keys, undefined, "no key section at all");
        assert.equal(body.errors, undefined, "nothing was asked, so nothing is reported per item");
      } else {
        assert.equal(body.error, undefined, "a per-item answer carries no whole-request code");
      }

      // Exactly the recorded coordinates come back, each carrying the key the
      // render really sealed there - so a smuggled key under an entitled name
      // fails here as loudly as a missing one.
      const granted = grantedCoordinates(vector.expected);
      const answered = answeredKeys(body);
      const renderKeys = keysOf(baseOf(vector));

      assert.deepEqual(
        answered.map(([coordinate]) => coordinate).sort(),
        [...granted].sort(),
        `${file}: what came back`,
      );
      for (const [coordinate, value] of answered) {
        assert.equal(
          value,
          renderKeys.get(coordinate),
          `${coordinate} carries its own key and no other`,
        );
      }

      // Said again over the whole body, so a key riding somewhere this walk
      // does not look cannot pass.
      const serialized = JSON.stringify(body);
      for (const [coordinate, key] of renderKeys) {
        if (granted.has(coordinate)) continue;
        assert.ok(!serialized.includes(key), `the answer carries no key for ${coordinate}`);
      }

      // Exactly the recorded coordinates fail, under the recorded codes.
      const errors = body.errors ?? [];
      assert.deepEqual(
        failedCoordinates(body).sort(),
        Object.keys(vector.expected.errors).sort(),
        `${file}: what failed per item`,
      );
      for (const [coordinate, code] of Object.entries(vector.expected.errors)) {
        assert.equal(
          errors.find((/** @type {any} */ record) => record.coordinate === coordinate)?.error,
          code,
          `${coordinate} failed with ${code}`,
        );
      }

      // How far the refusal got. An integrity failure is answered before the
      // key store is consulted; a blob that will not open can only be found
      // by consulting it.
      assert.equal(
        asked.keyStore,
        vector.expected.privateKeyReached ? 1 : 0,
        vector.expected.privateKeyReached
          ? "the private key is reached, because trying the blob is the only way to find out"
          : "refused before any private key was touched",
      );
    });

    test(`${file}: parsed and posted as an object, it is answered the same way`, async () => {
      // The port takes both, and a body whose attack survives parsing is
      // answered by the same checks. For the duplicate-member vector this is
      // the last-wins reading, which is the reading the reference implements.
      const { endpoint, processor, registration } = await buildIssuer(vector);
      const response = await unlockThroughAdmission(
        processor,
        endpoint,
        JSON.parse(vector.rawBody),
        registration,
      );
      const body = /** @type {any} */ (response.body);

      assert.equal(body.error, vector.expected.code ?? undefined);
      assert.deepEqual(
        answeredKeys(body)
          .map(([coordinate]) => coordinate)
          .sort(),
        [...grantedCoordinates(vector.expected)].sort(),
      );
    });

    test(`${file}: the same issuer answers the honest request`, async () => {
      // The control. Without it every assertion above is satisfied by an
      // endpoint that refuses everything, and the vector would prove nothing.
      const base = baseOf(vector);
      const { endpoint, processor, registration, asked } = await buildIssuer(vector);

      const honest = new Client({
        publisherOrigin: base.expected.dcaData.resource.origin,
      }).buildRequest(
        structuredClone(base.expected.dcaData),
        vector.issuer.issuerName,
        base.expected.dcaData.contentData.map((/** @type {any} */ record) => record.contentName),
      );
      const response = await unlockThroughAdmission(processor, endpoint, honest, registration);

      assert.equal(
        response.status,
        200,
        "the key material in this vector opens the render it was cut from",
      );
      assert.deepEqual(
        keysByCoordinate(/** @type {any} */ (response.body).keys).contentKeys,
        base.expected.contentKeys,
        "and the keys it hands back are the render's own",
      );
      assert.equal(
        /** @type {any} */ (response.body).errors,
        undefined,
        "nothing fails on the honest request",
      );
      assert.equal(asked.keyStore, 1, "the private key is reached once, after the checks passed");
    });
  }

  test("reject-relabeled: both blobs are genuine, and the coordinate is inside the ciphertext", async () => {
    const found = rejectVectors.find(({ vector }) => vector.name === "reject-relabeled");
    assert.ok(found, "the relabel vector is present");
    const { vector } = found;

    const base = baseOf(vector);
    const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));
    const arrived = keysByCoordinate(parsed.sealed).contentKeys;
    const sealed = keysByCoordinate(
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
    ).contentKeys;

    // The swap, spelled out against the render: each name carries the other's
    // blob, byte for byte, so nothing was forged and nothing was edited.
    assert.equal(arrived.bodytext, sealed["locked-data"]);
    assert.equal(arrived["locked-data"], sealed.bodytext);

    // And each of them does open - at the coordinate it was sealed
    // at. Every blob in this body is a blob the issuer can open; the label is
    // the whole of the attack, and the coordinate it has to match is inside the
    // ciphertext where an attacker who can rewrite the page cannot reach it.
    const privateKey = await importIssuerPrivateKey(vector.issuer.privateKeyJwk);
    const renderId = resourceOf(base.expected.dcaData).renderId;

    for (const [presentedAt, sealedAt] of [
      ["bodytext", "locked-data"],
      ["locked-data", "bodytext"],
    ]) {
      assert.equal(
        base64urlEncode(
          await unseal(arrived[presentedAt], privateKey, vector.issuer.algorithm, {
            binding: { renderId, contentName: sealedAt },
          }),
        ),
        base.expected.contentKeys[sealedAt],
        `${presentedAt}'s blob is the genuine ${sealedAt} blob`,
      );
    }
  });

  test("reject-foreign-render: the binding is the only thing between the two renders", async () => {
    const found = rejectVectors.find(({ vector }) => vector.name === "reject-foreign-render");
    assert.ok(found, "the cross-render vector is present");
    const { vector } = found;

    const base = baseOf(vector);
    const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));
    const arrived = keysByCoordinate(parsed.sealed).contentKeys;
    const mine = base64urlDecode(
      keysByCoordinate(issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed)
        .contentKeys.bodytext,
    );
    const theirs = base64urlDecode(arrived.bodytext);

    // Both renders were sealed with the same ephemeral keypair fixture, so the
    // issuer derives the same AES key from either blob's own point. What is
    // left between opening the foreign one and not is the value it was sealed
    // under, and that value is never on the wire.
    assert.deepEqual(
      theirs.subarray(0, EPHEMERAL_BYTES),
      mine.subarray(0, EPHEMERAL_BYTES),
      "one ephemeral point, so one wrapping key",
    );
    assert.notDeepEqual(
      theirs.subarray(EPHEMERAL_BYTES),
      mine.subarray(EPHEMERAL_BYTES),
      "a different render",
    );

    // The other coordinate of the same request is this render's own and opens,
    // so the refusal is the renderId and not the request.
    const privateKey = await importIssuerPrivateKey(vector.issuer.privateKeyJwk);
    const renderId = resourceOf(base.expected.dcaData).renderId;

    assert.equal(
      base64urlEncode(
        await unseal(arrived["locked-data"], privateKey, vector.issuer.algorithm, {
          binding: { renderId, contentName: "locked-data" },
        }),
      ),
      base.expected.contentKeys["locked-data"],
    );
    await refuses(
      () =>
        unseal(arrived.bodytext, privateKey, vector.issuer.algorithm, {
          binding: { renderId, contentName: "bodytext" },
        }),
      "unseal_failed",
      "the foreign blob is at the right name in the wrong render",
    );
  });

  test("reject-no-renderid: the envelope verifies, and there is still nothing to bind to", async () => {
    const found = rejectVectors.find(({ vector }) => vector.name === "reject-no-renderid");
    assert.ok(found, "the unanchored-render vector is present");
    const { vector } = found;

    const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));

    // The signature is good. That is what makes the refusal worth pinning: an
    // issuer that stops at "the publisher signed it" opens these blobs under a
    // binding it invented, and the same invented value would open every render
    // that publisher ever emitted.
    const publisherKeys = await importPublisherKeys(vector.publisher);
    const { publicKey } = publisherKeys.get(decodeHeader(parsed.resourceJWT).kid);
    const resource = await verify(parsed.resourceJWT, publicKey);

    assert.equal(
      Object.hasOwn(resource, "renderId"),
      false,
      "the signed resource carries no renderId",
    );

    // The blobs are intact - the request is ordinary in every other way.
    const base = baseOf(vector);
    assert.deepEqual(
      { resourceId: resource.resourceId, issuedAt: resource.issuedAt, data: resource.data },
      {
        resourceId: base.expected.dcaData.resource.resourceId,
        issuedAt: base.expected.dcaData.resource.issuedAt,
        data: base.expected.dcaData.resource.data,
      },
      "and is otherwise the render it was cut from",
    );
    assert.deepEqual(
      parsed.sealed.contentKeys,
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed.contentKeys,
    );
  });

  /**
   * The name and the accessGroup the two identifier vectors present, and the
   * admitted spelling each of them is one character away from. Neither carries
   * the binding delimiter, so what refuses them is the grammar.
   */
  const UNADMITTED_CONTENT_NAME = "2025-election";
  const UNADMITTED_ACCESS_GROUP = "premium sport";

  /**
   * One reject vector by name, with the render it was cut from and its body
   * already parsed. Every replay below reads the same three things.
   *
   * @param {string} name
   */
  function rejectVector(name) {
    const found = rejectVectors.find(({ vector }) => vector.name === name);
    assert.ok(found, `${name} is present`);

    const { vector } = found;
    return {
      vector,
      base: baseOf(vector),
      parsed: JSON.parse(/** @type {string} */ (vector.rawBody)),
    };
  }

  /**
   * A vector whose attack is one signed claim: the resource the publisher key
   * says it signed, beside the render's own resource. Reading it through
   * `verify` is the point - the signature is genuine in all three, so the
   * issuer refuses the member, not the signing key.
   *
   * @param {string} name
   */
  async function signedClaimVector(name) {
    const { vector, base, parsed } = rejectVector(name);
    const publisherKeys = await importPublisherKeys(vector.publisher);
    const { publicKey } = publisherKeys.get(decodeHeader(parsed.resourceJWT).kid);

    return {
      vector,
      base,
      parsed,
      resource: await verify(parsed.resourceJWT, publicKey),
      honest: resourceOf(base.expected.dcaData),
    };
  }

  /**
   * That the whole of the attack is the one member named, and that the sealed
   * section beside it is the render's own.
   *
   * @param {{ parsed: any, base: any, vector: any, resource: any, honest: any }} vector
   * @param {string} member
   */
  function oneClaimMoved({ parsed, base, vector, resource, honest }, member) {
    assert.notEqual(resource[member], honest[member], `${member} is not the publisher's own value`);
    assert.deepEqual(
      { ...resource, [member]: honest[member] },
      honest,
      "one member moved and nothing else",
    );
    assert.deepEqual(
      parsed.sealed,
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
      "and the blobs are the render's own, so an issuer that reads the claim answers with every key",
    );
  }

  test("reject-typ-substituted: the publisher's own token, relabelled as another envelope", async () => {
    const { vector, base, parsed } = rejectVector("reject-typ-substituted");

    // The payload and the signature are the honest token's, byte for byte, so
    // the edited header is the one thing the signature does not cover.
    const [head, body, signature] = parsed.resourceJWT.split(".");
    const [honestHead, honestBody, honestSignature] = base.expected.dcaData.resourceJWT.split(".");
    assert.equal(body, honestBody, "the payload is the publisher's");
    assert.equal(signature, honestSignature, "and so is the signature");
    assert.notEqual(head, honestHead, "the header is not");

    const header = JSON.parse(utf8Decode(base64urlDecode(head)));
    const honest = JSON.parse(utf8Decode(base64urlDecode(honestHead)));
    assert.equal(honest.typ, "JWT", "the one typ a publisher writes");
    assert.equal(
      header.typ,
      vector.substitution.typ,
      "and the one this vector records in its place",
    );
    assert.equal(
      header.alg,
      honest.alg,
      "the algorithm is untouched, so the typ is the whole of the attack",
    );
    assert.equal(header.kid, honest.kid, "under the same kid");

    // Refused where the algorithm is refused, and under the same code: the two
    // are one rule, and neither costs a key.
    const publisherKeys = await importPublisherKeys(vector.publisher);
    const { publicKey } = publisherKeys.get(header.kid);
    await refuses(
      () => verify(parsed.resourceJWT, publicKey),
      "bad_alg",
      "the format fixes one typ, and this token names another",
    );

    assert.deepEqual(
      parsed.sealed,
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
    );
  });

  test("reject-issuedat-malformed: a genuine signature over a stamp that is not a date-time", async () => {
    const vector = await signedClaimVector("reject-issuedat-malformed");

    assert.match(
      vector.honest.issuedAt,
      /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/,
      "the render writes RFC 3339",
    );
    assert.equal(
      vector.resource.issuedAt.includes("T"),
      false,
      "and this one writes a space in its place",
    );
    oneClaimMoved(vector, "issuedAt");
  });

  test("reject-resourceid-empty: a genuine signature over an article with no id", async () => {
    const vector = await signedClaimVector("reject-resourceid-empty");

    assert.equal(vector.resource.resourceId, "", "the member is present and empty");
    assert.equal(typeof vector.honest.resourceId, "string", "where the render carries an id");
    assert.ok(vector.honest.resourceId.length > 0);
    oneClaimMoved(vector, "resourceId");
  });

  test("reject-data-not-object: a genuine signature over policy input that is an array", async () => {
    const vector = await signedClaimVector("reject-data-not-object");

    assert.ok(Array.isArray(vector.resource.data), "the member is an array");
    assert.equal(Array.isArray(vector.honest.data), false, "where the render carries a map");
    assert.ok(Object.keys(vector.honest.data).length > 0);

    // The reading an issuer must not take: an array answers every lookup by
    // name with nothing, which is what a policy that grants on absence reads
    // as a page with no restriction on it.
    assert.equal(/** @type {any} */ (vector.resource.data)["date.published"], undefined);
    oneClaimMoved(vector, "data");
  });

  test("reject-forged-resourcejwt: the same words under the wrong pen", async () => {
    const found = rejectVectors.find(({ vector }) => vector.name === "reject-forged-resourcejwt");
    assert.ok(found, "the forged-envelope vector is present");
    const { vector } = found;

    const base = baseOf(vector);
    const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));

    // The construction, held to: header and payload are the honest token's
    // byte for byte, so the signature segment is the whole of the forgery.
    const [head, body, signature] = parsed.resourceJWT.split(".");
    const [honestHead, honestBody, honestSignature] = base.expected.dcaData.resourceJWT.split(".");
    assert.equal(head, honestHead, "the header still names the publisher's kid");
    assert.equal(body, honestBody, "the payload is the publisher's own resource");
    assert.notEqual(signature, honestSignature, "the pen is not");

    // A true forgery, not a damaged signature: the recorded attacker key
    // verifies it, so the refusal below is about who signed, not about shape.
    const attackerKey = await subtle.importKey(
      "jwk",
      vector.attacker.publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    assert.deepEqual(
      await verify(parsed.resourceJWT, attackerKey),
      resourceOf(base.expected.dcaData),
      "the attacker signed the honest payload",
    );

    // And no key the publisher holds does.
    const publisherKeys = await importPublisherKeys(vector.publisher);
    const { publicKey } = publisherKeys.get(decodeHeader(parsed.resourceJWT).kid);
    await refuses(
      () => verify(parsed.resourceJWT, publicKey),
      "bad_signature",
      "no key the publisher holds verifies the attacker's signature",
    );

    // Everything else in the body is the render it was cut from, so an issuer
    // that skips the check answers 200 with every key - the loud failure the
    // vector exists to force.
    assert.deepEqual(
      parsed.sealed,
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
    );
  });

  test("reject-tampered-resourcejwt: the publisher's own signature over bytes it never signed", async () => {
    const found = rejectVectors.find(({ vector }) => vector.name === "reject-tampered-resourcejwt");
    assert.ok(found, "the tampered-envelope vector is present");
    const { vector } = found;

    const base = baseOf(vector);
    const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));

    const [head, body, signature] = parsed.resourceJWT.split(".");
    const [honestHead, honestBody, honestSignature] = base.expected.dcaData.resourceJWT.split(".");
    assert.equal(head, honestHead, "the header is genuine");
    assert.equal(signature, honestSignature, "the signature is genuine");
    assert.notEqual(body, honestBody, "the payload between them is not");

    // The edit is exactly one signed claim, and it is not the anchor: the
    // renderId is untouched, so every blob would open if the request got past
    // the signature - what the tamper is after is the access decision.
    const edited = JSON.parse(utf8Decode(base64urlDecode(body)));
    const original = await verify(
      base.expected.dcaData.resourceJWT,
      (await importPublisherKeys(base.input)).get(base.input.signingKeys[0].kid).publicKey,
    );
    assert.notEqual(
      edited.data["date.published"],
      original.data["date.published"],
      "the article got younger",
    );
    assert.equal(edited.renderId, original.renderId, "the anchor is untouched");
    assert.deepEqual(
      { ...edited, data: { ...edited.data, "date.published": original.data["date.published"] } },
      original,
      "one field moved and nothing else",
    );

    const publisherKeys = await importPublisherKeys(vector.publisher);
    const { publicKey } = publisherKeys.get(decodeHeader(parsed.resourceJWT).kid);
    await refuses(
      () => verify(parsed.resourceJWT, publicKey),
      "bad_signature",
      "ES256 verifies the exact bytes, and these are not the ones signed",
    );
  });

  test("the signature refusal costs one verification and no private-key operation", async () => {
    // The honest cost line, counted rather than asserted in prose: rejecting a
    // forged or tampered envelope spends exactly the one subtle.verify, and no
    // ECDH happens anywhere in the pass. An issuer that unseals first and
    // verifies after would spend deriveBits before the refusal and fail here.
    for (const name of ["reject-forged-resourcejwt", "reject-tampered-resourcejwt"]) {
      const found = rejectVectors.find(({ vector }) => vector.name === name);
      assert.ok(found, `${name} is present`);
      const { endpoint, processor, registration, asked } = await buildIssuer(found.vector);

      const counts = { verify: 0, deriveBits: 0 };
      const realVerify = subtle.verify.bind(subtle);
      const realDeriveBits = subtle.deriveBits.bind(subtle);
      /** @type {any} */ (subtle).verify = (/** @type {any[]} */ ...args) => {
        counts.verify++;
        return realVerify(...args);
      };
      /** @type {any} */ (subtle).deriveBits = (/** @type {any[]} */ ...args) => {
        counts.deriveBits++;
        return realDeriveBits(...args);
      };

      let response;
      try {
        response = await unlockThroughAdmission(
          processor,
          endpoint,
          found.vector.rawBody,
          registration,
        );
      } finally {
        delete (/** @type {any} */ (subtle).verify);
        delete (/** @type {any} */ (subtle).deriveBits);
      }

      assert.equal(response.status, 400, name);
      assert.equal(counts.verify, 1, `${name}: the refusal costs the one signature check`);
      assert.equal(counts.deriveBits, 0, `${name}: and no ECDH before or after it`);
      assert.equal(asked.keyStore, 0, `${name}: the key store is never consulted`);
    }
  });

  /**
   * A P-256 public JWK as the point behind it: 0x04 || x || y, 65 bytes. What an
   * HS256 substitution MACs with - the verification key an issuer already holds,
   * read as bytes. Derived here rather than taken from the vector, so the
   * recorded MAC is checked against arithmetic and not against itself.
   *
   * @param {any} jwk
   * @returns {Uint8Array}
   */
  function uncompressedPoint(jwk) {
    const point = new Uint8Array(65);
    point[0] = 0x04;
    point.set(base64urlDecode(jwk.x), 1);
    point.set(base64urlDecode(jwk.y), 33);
    return point;
  }

  /**
   * The publisher key one `kid` names, out of the list a vector carries.
   *
   * @param {{ kid: string, publicKeyJwk: any }[]} signingKeys
   * @param {string|undefined} kid
   * @returns {any}
   */
  function publisherJwk(signingKeys, kid) {
    const found = signingKeys.find((key) => key.kid === kid);
    assert.ok(found, `the vector carries a signing key for kid ${JSON.stringify(kid)}`);
    return found.publicKeyJwk;
  }

  /**
   * A JWT check that reads the algorithm off the header instead of pinning it:
   * core-shared--publisher-issuer/jwt.js's `verify` with its one refusal taken out. Three arms, because
   * three is the number of algorithms a `header.alg` dispatch admits - ES256 against the
   * publisher's key, HS256 with the bytes of that same key as an HMAC secret,
   * and `none` with nothing at all.
   *
   * It is here and only here. core-shared--publisher-issuer/jwt.js is not touched: what this stands in for
   * is a foreign implementation, and a foreign implementation is what the vectors
   * are for.
   *
   * @param {string} token
   * @param {any} publicKeyJwk - the key the token's kid names
   * @returns {Promise<any|null>} the payload it accepted, or null
   */
  async function verifyTrustingHeader(token, publicKeyJwk) {
    const [head, body, signature] = token.split(".");
    const header = JSON.parse(utf8Decode(base64urlDecode(head)));
    const signingInput = utf8Encode(`${head}.${body}`);

    let ok = false;
    try {
      if (header.alg === "none") {
        ok = signature === "";
      } else if (header.alg === "HS256") {
        const key = await subtle.importKey(
          "raw",
          uncompressedPoint(publicKeyJwk),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"],
        );
        ok = await subtle.verify("HMAC", key, base64urlDecode(signature), signingInput);
      } else if (header.alg === "ES256") {
        const key = await subtle.importKey(
          "jwk",
          publicKeyJwk,
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        );
        ok = await subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          key,
          base64urlDecode(signature),
          signingInput,
        );
      }
    } catch {
      ok = false;
    }

    return ok ? JSON.parse(utf8Decode(base64urlDecode(body))) : null;
  }

  /**
   * This repository's issuer with that check in front of it and nothing else
   * moved: the same engine, the same port, the same key store, answering the same
   * way about everything but which algorithm a header may name.
   *
   * The shim reproduces the weakness. An implementation that accepts a
   * substituted token goes on to open blobs under the claims beneath it, so the
   * shim verifies the way the weakness verifies and then hands the engine a token
   * it will accept over that same payload, signed by a keypair made here. The
   * engine is then doing what a weak implementation does with a token it
   * believed. Where the weak check refuses - a wrong ES256 key, edited bytes -
   * the body goes through untouched and the strict engine refuses it for the
   * same reason, which is the point: this weakness only ever widens what is
   * accepted.
   *
   * The body is edited as a string, one token substituted for another, so a
   * duplicate member name survives the trip the way it survives a real one.
   *
   * @param {any} vector
   * @returns {Promise<{ post: (rawBody: string) => Promise<any> }>}
   */
  async function algTrustingIssuer(vector) {
    const privateKey = await importIssuerPrivateKey(vector.issuer.privateKeyJwk);
    const keyStore = {
      /**
       * @param {string} issuerName
       * @param {string} keyId
       */
      get(issuerName, keyId) {
        if (issuerName !== vector.issuer.issuerName || keyId !== vector.issuer.keyId)
          return undefined;
        return { algorithm: vector.issuer.algorithm, privateKey };
      },
    };

    const believed = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    // The onboarding state a real issuer holds, filed the real way - one
    // registration per kid the vector carries, addressing this issuer's one
    // opening-key coordinate - with the key this shim re-signs under in
    // place of the publisher's own. What is weakened here is which algorithm
    // a header may name, and nothing else is allowed to differ.
    const registrations = publisherRegistrationsOver(
      {
        [vector.publisher.origin]: Object.fromEntries(
          vector.publisher.signingKeys.map((/** @type {any} */ key) => [
            key.kid,
            believed.publicKey,
          ]),
        ),
      },
      openingKeysOver(keyStore, [
        { issuerName: vector.issuer.issuerName, keyId: vector.issuer.keyId },
      ]),
    );

    const processor = new IssuerProcessor(
      new IssuerEngine({
        operatingIssuerNames: [vector.issuer.issuerName],
        accessPolicy: new AllowAllPolicy(),
      }),
      { periodKeyInput: true },
    );
    const endpoint = new UnlockEndpoint(processor);

    return {
      async unlock(rawBody) {
        const token = JSON.parse(rawBody).resourceJWT;
        const header = decodeHeader(token);
        const registration = registrations.get(header.kid);
        const payload = await verifyTrustingHeader(
          token,
          publisherJwk(vector.publisher.signingKeys, header.kid),
        );
        if (payload === null)
          return unlockThroughAdmission(processor, endpoint, rawBody, registration);

        const reSigned = await sign(payload, believed.privateKey, { kid: header.kid });
        const quoted = JSON.stringify(token);
        assert.equal(rawBody.split(quoted).length, 2, "the token sits in the body exactly once");

        return unlockThroughAdmission(
          processor,
          endpoint,
          rawBody.replace(quoted, JSON.stringify(reSigned)),
          registration,
        );
      },
    };
  }

  /**
   * Whether one response is the answer a vector records, by the reading the
   * replay loop above uses: the whole-request code, the coordinates that came
   * back with key material, and the ones that came back as an error.
   *
   * @param {any} vector
   * @param {any} response
   * @returns {boolean}
   */
  function answersAsRecorded(vector, response) {
    const body = response.body ?? {};
    const same = (/** @type {string[]} */ left, /** @type {string[]} */ right) =>
      left.sort().join(",") === right.sort().join(",");

    return (
      body.error === (vector.expected.code ?? undefined) &&
      same(
        answeredKeys(body).map(([coordinate]) => coordinate),
        [...grantedCoordinates(vector.expected)],
      ) &&
      same(failedCoordinates(body), Object.keys(vector.expected.errors))
    );
  }

  test("reject-alg-substituted: the same payload under a header that names another check", async () => {
    const arms = ["reject-alg-substituted", "reject-alg-substituted-hs256"].map((name) => {
      const found = rejectVectors.find(({ vector }) => vector.name === name);
      assert.ok(found, `${name} is present`);
      return found.vector;
    });

    for (const vector of arms) {
      const base = baseOf(vector);
      const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));

      const [head, body, signature] = parsed.resourceJWT.split(".");
      const [honestHead, honestBody] = base.expected.dcaData.resourceJWT.split(".");
      const header = JSON.parse(utf8Decode(base64urlDecode(head)));

      // The payload is the publisher's own, byte for byte, so the header is
      // the whole of the attack: nothing about the render was edited, only
      // which check an issuer would run over it.
      assert.equal(body, honestBody, `${vector.name}: the payload is the publisher's`);
      assert.notEqual(head, honestHead, "the header is not");
      assert.equal(
        header.alg,
        vector.substitution.alg,
        "and it names the algorithm the vector records",
      );
      assert.equal(
        header.kid,
        JSON.parse(utf8Decode(base64urlDecode(honestHead))).kid,
        "under the same kid",
      );

      if (header.alg === "none") {
        assert.equal(signature, "", "nothing to check, which is what `none` means");
      } else {
        // A real MAC under the key an issuer holds, not 32 bytes of noise:
        // an implementation that HMACs with its verification key accepts
        // this token, the way the ES256 arm of reject-forged is a real
        // signature rather than a damaged one.
        const macKey = uncompressedPoint(publisherJwk(vector.publisher.signingKeys, header.kid));
        assert.equal(
          base64urlEncode(macKey),
          vector.substitution.macKey,
          "the recorded secret is that key",
        );

        const key = await subtle.importKey(
          "raw",
          macKey,
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"],
        );
        assert.ok(
          await subtle.verify(
            "HMAC",
            key,
            base64urlDecode(signature),
            utf8Encode(`${head}.${body}`),
          ),
          "the third segment is HMAC-SHA256 over the signing input, keyed by the public key",
        );
      }

      // Everything else in the body is the render it was cut from, so an
      // issuer that accepts the header hands over every key of the render.
      assert.deepEqual(
        parsed.sealed,
        issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
      );
    }
  });

  test("reject-alg-substituted: the refusal is the header, and it costs no key operation at all", async () => {
    // Cheaper than the forged and tampered refusals, and pinned for the same
    // reason those are: the algorithm is a string comparison against a
    // constant, so a conformant issuer spends no signature check either - the
    // token dies before a key is consulted.
    for (const name of ["reject-alg-substituted", "reject-alg-substituted-hs256"]) {
      const found = rejectVectors.find(({ vector }) => vector.name === name);
      assert.ok(found, `${name} is present`);
      const { endpoint, processor, registration, asked } = await buildIssuer(found.vector);

      const counts = { verify: 0, deriveBits: 0 };
      const realVerify = subtle.verify.bind(subtle);
      const realDeriveBits = subtle.deriveBits.bind(subtle);
      /** @type {any} */ (subtle).verify = (/** @type {any[]} */ ...args) => {
        counts.verify++;
        return realVerify(...args);
      };
      /** @type {any} */ (subtle).deriveBits = (/** @type {any[]} */ ...args) => {
        counts.deriveBits++;
        return realDeriveBits(...args);
      };

      let response;
      try {
        response = await unlockThroughAdmission(
          processor,
          endpoint,
          found.vector.rawBody,
          registration,
        );
      } finally {
        delete (/** @type {any} */ (subtle).verify);
        delete (/** @type {any} */ (subtle).deriveBits);
      }

      assert.equal(response.status, 400, name);
      assert.equal(
        /** @type {any} */ (response.body).error,
        "bad_alg",
        `${name}: refused on the header`,
      );
      assert.equal(
        counts.verify,
        0,
        `${name}: no signature check is spent on an algorithm we do not read`,
      );
      assert.equal(counts.deriveBits, 0, `${name}: and no ECDH`);
      assert.equal(asked.keyStore, 0, `${name}: the key store is never consulted`);
    }
  });

  test("a vector in this set catches an issuer that reads the algorithm off the header", async () => {
    // The third member of the signature family, run rather than argued. An
    // implementation that dispatches on `header.alg` still refuses
    // reject-forged-resourcejwt - a well-formed ES256 signature by the wrong
    // key - and reject-tampered-resourcejwt - the right key over edited bytes -
    // because both name ES256 and both fail an honest ECDSA verify. What it
    // accepts is a token headed `none`, or one headed HS256 and MAC'd with the
    // EC public key it already holds, and the renderId under that token is
    // whatever the attacker wrote: every blob the attacker holds then opens at
    // the coordinate the attacker chose.
    //
    // These files are the only artifact a foreign implementation conforms
    // against - our own tests are not shipped to anyone - so the weakness has
    // to fail one of them. The failure message names the ones it does not.
    const passed = [];
    const caught = [];

    for (const { file, vector } of sealVectors) {
      // A seal vector is replayed by verifying the recorded envelope, and a
      // check that reads the header verifies this one: it says ES256.
      const token = vector.expected.dcaData.resourceJWT;
      const jwk = publisherJwk(vector.input.signingKeys, decodeHeader(token).kid);

      ((await verifyTrustingHeader(token, jwk)) === null ? caught : passed).push(file);
    }

    for (const { file, vector } of rejectVectors) {
      const issuer = await algTrustingIssuer(vector);
      const response = await issuer.unlock(vector.rawBody);

      (answersAsRecorded(vector, response) ? passed : caught).push(file);
    }

    assert.notDeepEqual(
      caught,
      [],
      "an issuer that trusts header.alg replayed this whole directory the recorded way: " +
        `${passed.sort().join(", ")} - nothing here selects the algorithm`,
    );

    for (const file of caught) {
      const found = rejectVectors.find((entry) => entry.file === file);
      assert.ok(found?.vector.substitution, `${file} caught it, and records what was substituted`);
    }
  });

  test("reject-duplicate-member-name: the attack exists only in the string", async () => {
    const found = rejectVectors.find(
      ({ vector }) => vector.name === "reject-duplicate-member-name",
    );
    assert.ok(found, "the duplicate-member vector is present");
    const { vector } = found;

    // The witness is one record, `$.sealed.contentKeys[0]`, that names
    // bodytext once and writes its `key` member twice. It is not two rival
    // records: the string names one contentName.
    const raw = /** @type {string} */ (vector.rawBody);
    assert.equal([...raw.matchAll(/"contentName":/g)].length, 1, "one record names an item");
    const record = raw.match(/\{"contentName":\s*"bodytext"((?:,\s*"key":\s*"[^"]+")+)\s*\}/);
    assert.ok(record, "the bodytext record carries only key members after its name");
    const occurrences = [...record[1].matchAll(/"key":\s*"([^"]+)"/g)].map((match) => match[1]);
    assert.equal(occurrences.length, 2, "the member name is written twice");
    assert.notEqual(occurrences[0], occurrences[1], "and the two members disagree");

    // What a parser does with it: one member, the last one. This is the fact
    // the whole vector turns on, executed rather than asserted in prose.
    const parsed = JSON.parse(raw);
    assert.equal(parsed.sealed.contentKeys.length, 1, "one record, before and after the parse");
    const [parsedRecord] = parsed.sealed.contentKeys;
    assert.equal(parsedRecord.contentName, "bodytext");
    assert.deepEqual(
      Object.keys(parsedRecord),
      ["contentName", "key"],
      "a parsed object cannot hold the name twice",
    );
    assert.equal(parsedRecord.key, occurrences[1], "last wins");

    // The protocol permits rejecting duplicates or keeping the lexical-last
    // member. The first blob still demonstrates why a first-wins parser is
    // forbidden: it would open and answer a different request. No permitted
    // reading produces locked-data's key under the name bodytext.
    const base = baseOf(vector);
    const privateKey = await importIssuerPrivateKey(vector.issuer.privateKeyJwk);
    const renderId = resourceOf(base.expected.dcaData).renderId;
    const atBodytext = { renderId, contentName: "bodytext" };

    const open = (/** @type {string} */ blob, /** @type {any} */ binding) =>
      unseal(blob, privateKey, vector.issuer.algorithm, { binding });

    assert.equal(
      base64urlEncode(await open(occurrences[0], atBodytext)),
      base.expected.contentKeys.bodytext,
      "the first member is the blob the publisher sealed at bodytext",
    );
    await refuses(
      () => open(occurrences[1], atBodytext),
      "unseal_failed",
      "the second is not, and that is the refusal",
    );

    // The second member is a genuine blob, and it is worth exactly one thing:
    // locked-data's contentKey, at locked-data's coordinate, which this request
    // never asked for and cannot reach by writing the name twice.
    assert.equal(
      base64urlEncode(await open(occurrences[1], { renderId, contentName: "locked-data" })),
      base.expected.contentKeys["locked-data"],
    );
    assert.notEqual(base.expected.contentKeys["locked-data"], base.expected.contentKeys.bodytext);
  });

  /**
   * The coordinates the four delimiter vectors are written around, spelled from
   * the delimiter itself so a change to the separator moves these with it. The
   * two names are one character away from names the grammar admits - `bodytext`
   * and `premium:sport` - and that character is the one the binding joins on.
   */
  const DELIMITED_CONTENT_NAME = `body${BIND_DELIMITER}text`;
  const DELIMITED_ACCESS_GROUP = `premium${BIND_DELIMITER}sport`;
  const SEALED_PERIOD = "251023T1400";
  const RESPLIT_ACCESS_GROUP = "premium";
  const RESPLIT_PERIOD = `sport${BIND_DELIMITER}${SEALED_PERIOD}`;

  /**
   * One vector by name, with the render it was cut from and the issuer key that
   * has to answer it. Every delimiter test below opens a blob by hand, and each
   * of them needs the same three things.
   *
   * @param {string} name
   */
  async function delimiterVector(name) {
    const found = rejectVectors.find(({ vector }) => vector.name === name);
    assert.ok(found, `${name} is present`);

    const { vector } = found;
    const base = baseOf(vector);
    return {
      vector,
      base,
      parsed: JSON.parse(/** @type {string} */ (vector.rawBody)),
      renderId: resourceOf(base.expected.dcaData).renderId,
      privateKey: await importIssuerPrivateKey(vector.issuer.privateKeyJwk),
    };
  }

  test("the two presented-name delimiter vectors: the coordinate is empty whichever way it is read", async () => {
    // What they pin is containment: a coordinate the caller wrote is refused
    // where it is read, and every coordinate beside it is still answered.
    // What they cannot pin is the ban. Nothing of this render sits where a
    // delimited coordinate could reach, so an issuer that joins the fields
    // blindly builds a value nothing was sealed under and answers exactly
    // what a banning one answers. Both readings end here, and that is why
    // reject-delimiter-sealed-contentname and reject-delimiter-sealed-accessgroup
    // are in the set beside them.
    const cases = [
      ["reject-delimiter-contentname", { contentName: DELIMITED_CONTENT_NAME }],
      ["reject-delimiter-accessgroup", { accessGroup: DELIMITED_ACCESS_GROUP, t: SEALED_PERIOD }],
    ];

    for (const [name, coordinate] of cases) {
      const { vector, parsed, renderId, privateKey } = await delimiterVector(
        /** @type {string} */ (name),
      );
      const at = /** @type {any} */ (coordinate);
      const blob =
        at.contentName === undefined
          ? keysByCoordinate(parsed.sealed).periodKeys[at.accessGroup]?.[at.t]
          : keysByCoordinate(parsed.sealed).contentKeys[at.contentName];
      assert.equal(typeof blob, "string", `${name} presents the delimited coordinate`);

      const options = { binding: { renderId, ...at } };
      await refuses(
        () => unseal(blob, privateKey, vector.issuer.algorithm, options),
        "binding_failed",
        `${name}: the shipped grammar builds no value out of a field carrying the separator`,
      );
      await refuses(
        () => unbannedUnseal(blob, privateKey, vector.issuer.algorithm, options),
        "unseal_failed",
        `${name}: and a blind join builds a value this render sealed nothing under`,
      );
    }
  });

  test("identifier vectors refuse final LF and overlong names beside the existing grammar cases", () => {
    for (const [fixture, name] of [
      ["reject-identifier-contentname-final-lf", "bodytext\n"],
      ["reject-identifier-contentname-65-chars", `a${"a".repeat(64)}`],
    ]) {
      const vector = rejectVector(fixture);
      assert.equal(isContentName(name), false, fixture);
      assert.equal(name.includes(BIND_DELIMITER), false, fixture);
      assert.ok(Object.hasOwn(keysByCoordinate(vector.parsed.sealed).contentKeys, name), fixture);
      assert.equal(vector.vector.expected.code, "binding_failed", fixture);
      assert.equal(vector.vector.expected.privateKeyReached, false, fixture);
    }
    assert.equal(isContentName("a".repeat(64)), true, "the 64-character boundary is accepted");
  });

  test("the two original identifier vectors: the presented coordinate is outside the grammar, delimiter or no", () => {
    // The pair beside the four delimiter vectors above. Neither name carries
    // the separator, so neither is refused by the ban: what refuses them is
    // the grammar every name a publisher emits is written in, which is where
    // a coordinate two implementations read differently dies.
    const content = rejectVector("reject-identifier-contentname");
    const sealed = keysByCoordinate(
      issuerBlock(content.base.expected.dcaData, content.vector.issuer.issuerName).sealed,
    );
    const presented = keysByCoordinate(content.parsed.sealed);

    assert.equal(isContentName("bodytext"), true, "the render's own name is a name");
    assert.equal(isContentName(UNADMITTED_CONTENT_NAME), false, "a digit-initial one is not");
    assert.equal(
      UNADMITTED_CONTENT_NAME.includes(BIND_DELIMITER),
      false,
      "and there is no delimiter in it",
    );
    assert.equal(
      presented.contentKeys[UNADMITTED_CONTENT_NAME],
      sealed.contentKeys.bodytext,
      "the presented coordinate holds the render's own bodytext blob",
    );
    assert.equal(
      Object.hasOwn(sealed.contentKeys, UNADMITTED_CONTENT_NAME),
      false,
      "and the render sealed nothing there",
    );
    for (const name of ["bodytext", "locked-data"]) {
      assert.equal(presented.contentKeys[name], sealed.contentKeys[name], `${name} is untouched`);
    }

    const group = rejectVector("reject-identifier-accessgroup");
    const presentedGroups = keysByCoordinate(group.parsed.sealed).periodKeys;
    assert.equal(isAccessGroup("premium:sport"), true, "the colon spelling of the pair is a name");
    assert.equal(isAccessGroup(UNADMITTED_ACCESS_GROUP), false, "the spaced spelling is not");
    assert.equal(
      UNADMITTED_ACCESS_GROUP.includes(BIND_DELIMITER),
      false,
      "and there is no delimiter in it",
    );
    assert.deepEqual(
      presentedGroups[UNADMITTED_ACCESS_GROUP],
      presentedGroups.premium,
      "the presented family holds the render's own premium blobs",
    );
    assert.deepEqual(
      keysByCoordinate(
        issuerBlock(group.base.expected.dcaData, group.vector.issuer.issuerName).sealed,
      ).periodKeys.premium,
      presentedGroups.premium,
      "and the honest family beside it is untouched",
    );
  });

  test("reject-no-coordinate: the envelope is the render's own, and the request asks for nothing", async () => {
    const { vector, base, parsed } = rejectVector("reject-no-coordinate");

    assert.deepEqual(
      parsed.sealed,
      { contentKeys: [] },
      "an empty collection, and no periodKeys section beside it",
    );

    // The envelope is the publisher's, unedited and verifying, so what the
    // refusal is about is the ask. An issuer that answers this one spends a
    // signature verification and a policy call on a request for no key, as
    // often as a caller cares to post it.
    assert.equal(
      parsed.resourceJWT,
      base.expected.dcaData.resourceJWT,
      "the token is the render's own",
    );
    const publisherKeys = await importPublisherKeys(vector.publisher);
    const { publicKey } = publisherKeys.get(decodeHeader(parsed.resourceJWT).kid);
    assert.deepEqual(
      await verify(parsed.resourceJWT, publicKey),
      resourceOf(base.expected.dcaData),
      "and it verifies",
    );
  });

  test("reject-delimiter-sealed-contentname: the blob was sealed at the delimited name, and a blind join opens it", async () => {
    const { vector, base, parsed, renderId, privateKey } = await delimiterVector(
      "reject-delimiter-sealed-contentname",
    );

    // The two honest coordinates are the render's own, byte for byte, so
    // the added one is the whole of the attack.
    const sealed = keysByCoordinate(
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
    ).contentKeys;
    const presented = keysByCoordinate(parsed.sealed).contentKeys;
    assert.equal(presented.bodytext, sealed.bodytext);
    assert.equal(presented["locked-data"], sealed["locked-data"]);

    const blob = presented[DELIMITED_CONTENT_NAME];
    const binding = { renderId, contentName: DELIMITED_CONTENT_NAME };
    const options = { binding };

    // No run of the shipped sealer produced this blob, and no run of a
    // shipped issuer opens it: the name is a field that would become two.
    await refuses(
      () => unseal(blob, privateKey, vector.issuer.algorithm, options),
      "binding_failed",
      "the contentName carries the separator",
    );

    // An issuer that joins what it was handed arrives at the exact string
    // this blob was sealed under, the tag verifies, and a key comes back.
    assert.equal(
      unbannedBindValue(binding),
      `dca-bind-key-envelope|c|${renderId}|${DELIMITED_CONTENT_NAME}`,
    );
    const opened = base64urlEncode(
      await unbannedUnseal(blob, privateKey, vector.issuer.algorithm, options),
    );

    assert.ok(
      !vector.expected.keys.contentKeys.includes(DELIMITED_CONTENT_NAME),
      "and no key is listed here",
    );
    assert.ok(
      ![...keysOf(base).values()].includes(opened),
      "the key is one the render never sealed",
    );
    assert.ok(
      vector.description.includes(opened),
      "and the vector records what such an issuer hands over",
    );

    // The one value a replayer cannot rebuild for itself, recorded so it
    // can open the blob and see a real key rather than damaged bytes.
    assert.deepEqual(vector.sealedUnder, [
      {
        coordinate: `contentKeys/${DELIMITED_CONTENT_NAME}`,
        bind: unbannedBindValue(binding),
        keyBase64url: opened,
      },
    ]);
  });

  test("reject-delimiter-sealed-accessgroup: two pairs join to one string, and the blob opens at the other one", async () => {
    const { vector, base, parsed, renderId, privateKey } = await delimiterVector(
      "reject-delimiter-sealed-accessgroup",
    );

    // The honest families are untouched, and the render has no family by
    // the delimited name: the blob under the added period came from a
    // publisher that never ran the ban.
    const sealed = keysByCoordinate(
      issuerBlock(base.expected.dcaData, vector.issuer.issuerName).sealed,
    ).periodKeys;
    const presented = keysByCoordinate(parsed.sealed).periodKeys;
    assert.deepEqual(Object.keys(base.expected.periodKeys).sort(), ["locked-data", "premium"]);
    for (const t of Object.keys(sealed[RESPLIT_ACCESS_GROUP])) {
      assert.equal(presented[RESPLIT_ACCESS_GROUP][t], sealed[RESPLIT_ACCESS_GROUP][t]);
    }

    const blob = presented[RESPLIT_ACCESS_GROUP][RESPLIT_PERIOD];
    const sealedAt = { renderId, accessGroup: DELIMITED_ACCESS_GROUP, t: SEALED_PERIOD };
    const presentedAt = { renderId, accessGroup: RESPLIT_ACCESS_GROUP, t: RESPLIT_PERIOD };
    const options = { binding: presentedAt };

    // The collision itself: two pairs of caller-chosen fields, one string.
    assert.equal(
      unbannedBindValue(sealedAt),
      unbannedBindValue(presentedAt),
      "a pair the publisher sealed at and a pair the caller asks under join to one value",
    );
    assert.equal(
      unbannedBindValue(presentedAt),
      `dca-bind-key-envelope|p|${renderId}|${DELIMITED_ACCESS_GROUP}` +
        `${BIND_DELIMITER}${SEALED_PERIOD}`,
    );

    // The ban is the whole of the defence here, and t is where it fires:
    // the issuer never parses t, it joins the pair it was handed.
    await refuses(
      () => unseal(blob, privateKey, vector.issuer.algorithm, options),
      "binding_failed",
      "t carries the separator",
    );

    // Without it, a premium grant opens premium|sport's period key.
    const opened = base64urlEncode(
      await unbannedUnseal(blob, privateKey, vector.issuer.algorithm, options),
    );
    assert.equal(
      opened,
      vector.sealedUnder[0].keyBase64url,
      "the smuggled key is the delimited family's own periodKey",
    );
    assert.ok(
      !Object.hasOwn(vector.expected.keys.periodKeys, RESPLIT_ACCESS_GROUP),
      "and no key is listed at the pair it is presented under",
    );
    assert.ok(![...keysOf(base).values()].includes(opened), "nor is it a key of this render");
    assert.ok(
      vector.description.includes(opened),
      "the vector records what such an issuer hands over",
    );

    // And the value itself is on record, because no conformant builder
    // produces it: the coordinate it names is the one the blob was sealed
    // at, which is not the one the request presents it under.
    assert.deepEqual(vector.sealedUnder, [
      {
        coordinate: `periodKeys/${DELIMITED_ACCESS_GROUP}/${SEALED_PERIOD}`,
        bind: unbannedBindValue(sealedAt),
        keyBase64url: opened,
      },
    ]);
  });

  test("reject-prototype-name: the hazard is in the lookup and in the write, not in the parse", async () => {
    const found = rejectVectors.find(({ vector }) => vector.name === "reject-prototype-name");
    assert.ok(found, "the prototype-name vector is present");
    const { vector } = found;

    const parsed = JSON.parse(/** @type {string} */ (vector.rawBody));
    const arrived = parsed.sealed.contentKeys;

    // Each name arrives as the `contentName` value of its own record, and
    // JSON.parse leaves every record's prototype alone, so nothing is
    // polluted by reading the request in. The hazard waits for a reader that
    // indexes the records by name.
    /** @type {Record<string, string>} */
    const blobs = {};
    for (const name of ["constructor", "__proto__"]) {
      const named = arrived.filter((/** @type {any} */ record) => record.contentName === name);
      assert.equal(named.length, 1, `${name} arrived as one record's contentName`);
      assert.equal(
        Object.getPrototypeOf(named[0]),
        Object.prototype,
        "the parse did not move the prototype",
      );
      assert.equal(typeof named[0].key, "string", `${name} carries a wire string`);
      defineName(blobs, name, named[0].key);
    }

    // What the recorded answer is. `__proto__` is not letter-initial, so
    // identifier admission refuses the collection it arrived in and the whole
    // request comes back refused: no keys, no per-coordinate errors, and no
    // response record for either name to be written into.
    assert.equal(
      vector.expected.code,
      "binding_failed",
      "the vector records a whole-request refusal",
    );
    assert.deepEqual(vector.expected.errors, {}, "and no per-coordinate verdict beside it");
    assert.equal(vector.expected.privateKeyReached, false);

    // The blobs themselves are real, so the refusal is the coordinate and not
    // a malformed value: each opens at the coordinate it was sealed at.
    const base = baseOf(vector);
    const privateKey = await importIssuerPrivateKey(vector.issuer.privateKeyJwk);
    const renderId = resourceOf(base.expected.dcaData).renderId;

    for (const [name, sealedAt] of [
      ["constructor", "bodytext"],
      ["__proto__", "locked-data"],
    ]) {
      assert.equal(
        base64urlEncode(
          await unseal(blobs[name], privateKey, vector.issuer.algorithm, {
            binding: { renderId, contentName: sealedAt },
          }),
        ),
        base.expected.contentKeys[sealedAt],
        `${name} carries a blob this issuer can open - only the binding stands in the way`,
      );
    }

    // Nothing the run touched reached Object.prototype.
    assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, "bodytext"), undefined);
    assert.equal({}.constructor, Object);
  });
});

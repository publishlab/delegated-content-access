// @ts-check
// Writes the three protocol fixture packages under verification/fixtures/v1/
// and the four vector/profile sets configured below. From the repository root,
// run:
//
//     cd js && node tools/make-vectors.js
//
// With `--check` it writes nothing. It compares what it would write with the
// files on disk, names each one that differs, is missing or is left over, and
// exits 1 when there is one. `test-tools/make-vectors.test.js` runs it in
// `pnpm test`, so a generator input changed without a regeneration fails there.
//
// Two unchanged runs produce identical files. Everything a render normally
// draws fresh is a fixture below (the issuer keypair, the publisher's signing
// keypair, the ephemeral keypair per sealed blob, the Random seed, the clock).
//
// ECDSA still draws a random `k` per fresh signature, and WebCrypto offers no
// way to supply it. Before writing, this tool carries a recorded signature
// forward only when its exact header.payload is unchanged and it verifies under
// the current public JWK. A fixture regeneration then stays byte-stable while
// the runtime signer keeps drawing fresh randomness. A replayer still compares
// those two segments and verifies the recorded third one.
//
// The keypairs were generated once with subtle.generateKey over P-256 and
// pasted in. Publisher-private period keys are recorded as fixture input.
// They are demo fixtures published in a repository; nothing is sealed to them
// but the article below.
//
// This tool writes six kinds of record, and `vectorFormat` says which. Format 1 is a
// render: an input on one side and the wire it produces on the other, replayed by
// sealing and diffing. Format 2 is an unlock request an issuer must not answer as
// asked, replayed by posting it and reading what comes back. A seal vector pins
// what a conformant implementation produces, a reject vector pins what it must
// not hand over, and nothing about the first kind tells you anything about the
// second. Format 3 is an RSA-OAEP open vector: a recorded ciphertext decrypted
// with the private fixture key, the binding rebuilt from the recorded inputs and
// the recovered BIND-plus-key compared whole, since OAEP's self-randomized
// padding means an RSA seal cannot be replayed byte for byte. Format
// `sealer-factory-v3` is a render built through the Sealer factory from plain
// setup, and `sealer-factory-refusal-v2` a set of refusals of such Sealers;
// `sealerFactoryRecords.js` builds both.
//
// A reject vector also pins how far a refusal reaches, and the two reaches are
// different events. A request whose envelope does not verify, or that carries no
// renderId for its blobs to be bound to, leaves the issuer nothing to answer, so
// it refuses the request whole before it consults the key store. A blob presented
// at a coordinate it was not sealed at leaves the rest of the request ordinary:
// the issuer has to try that blob to find out, so it comes back as an error
// beside the coordinates that did open. Both are recorded in the same `expected`
// shape, because `code` and the per-coordinate `errors` already say which one it
// is.
//
// A reject vector carries its request as `rawBody`, a verbatim JSON string.
// `reject-duplicate-member-name` repeats a member name inside sealed.contentKeys,
// and a parsed object cannot hold the same key twice, so that attack exists only
// in the serialized text. Every reject body here is therefore built from an
// ordered pair list and serialized once, never from an object; see `renderBody`.
//
// The reject bodies are cut from the render vector in the same run, so the
// envelope inside `rawBody` is the one in seal-ecdh.json byte for
// byte, signature segment included. On an unchanged regeneration the retained
// signature keeps that relation byte-stable too.
//
// `node:fs` lives here and in test files. Nothing under core/, ports/ or
// demo/actors/ may reach for it: those run in a browser page unchanged.

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { CHECKSUM_FILE, checksumsText, vectorFilesIn } from "./checksums.js";
import { contentAad } from "../core-shared--client-publisher/contentAad.js";
import { makeSealerFactoryRecords, makeSealerRefusalRecord } from "./sealerFactoryRecords.js";
import {
  bindingValues,
  buildSealer,
  importSigningPrivateKey,
  recoverContentKeys,
  recoverPeriodKeys,
} from "./vectorWorld.js";
import {
  seal as unbannedSeal,
  unbannedBindValue,
  unseal as unbannedUnseal,
} from "./vector-fixtures/unbannedSealing.js";
import { NONCE_BYTES } from "../core-shared/aead.js";
import { BIND_DELIMITER, bindValue } from "../core-shared--publisher-issuer/bind.js";
import { base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from "../core-shared/codec.js";
import { sign, verify } from "../core-shared--publisher-issuer/jwt.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { open, seal } from "../core-shared--publisher-issuer/keySealing.js";
import * as clientBoundEcdh from "../extensions/client-bound-transport/ecdhP256.js";
import * as clientBoundRsa from "../extensions/client-bound-transport/rsaOaep.js";
import { keyKindContext } from "../extensions/client-bound-transport/core-shared--client-issuer/keyKind.js";
import { DcaData } from "../core-client/DcaData.js";
import { DcaRequestBuilder } from "../core-client/DcaRequestBuilder.js";

const { subtle } = globalThis.crypto;

/** Reads the resource out of the sole resourceJWT payload, the one place the wire carries it. */
function resourceOf(dcaData) {
  return decodeCompactJwt(dcaData.resourceJWT).payload;
}

/** ES256's WebCrypto import shape for a public verification key. */
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

/** The optional baseline RSA-OAEP envelope-open package. */
const RSA_OAEP_DIR = fileURLToPath(
  new URL("../../verification/vectors/v1/baseline/rsa-oaep-envelope-open/", import.meta.url),
);

/** This run writes the binding-carrier fixture beside the other vector sets. */
const BOUND_CARRIER_DIR = fileURLToPath(
  new URL("../../verification/vectors/v1/experiments/bind-on-renderId-and-slot/", import.meta.url),
);

/** The client-bound profile sets, separate from the base DCA format. */
const CLIENT_BOUND_ECDH_DIR = fileURLToPath(
  new URL(
    "../../verification/vectors/v1/profiles/dca-profile-client-bound-ecdh-p256/",
    import.meta.url,
  ),
);
const CLIENT_BOUND_RSA_DIR = fileURLToPath(
  new URL(
    "../../verification/vectors/v1/profiles/dca-profile-client-bound-rsa-oaep/",
    import.meta.url,
  ),
);

/** The set-level manifest, which carries the set name and its phase. */
const SET_MANIFEST = "set.json";
const FIXTURE_MANIFEST = "manifest.json";

/** What a replayer proves for each vector format in the RSA-OAEP set. */
const FORMAT_PROOFS = {
  3: { proofBoundary: "carrier", operation: "open", projection: "recovered-binding-and-key" },
};

/** The generated RSA-OAEP package metadata, naming its phase and format proofs. */
export function makeRsaOaepSetManifest(phase) {
  return {
    set: "rsa-oaep-envelope-open",
    phase,
    formatProofs: FORMAT_PROOFS,
  };
}

/**
 * The three whole-protocol fixture packages this run writes, by their path
 * under verification/. The two base-contract packages are what portable
 * contracts select; the reference package holds regressions and Sealer
 * factory records that only the JavaScript reference replay asserts from.
 */
const BASELINE_FIXTURES = "fixtures/v1/baseline/issuer-admission";
const PERIOD_KEYS_FIXTURES = "fixtures/v1/profiles/dca-profile-period-keys/issuer-admission";
const REFERENCE_FIXTURES = "fixtures/v1/reference/protocol-regressions";
export const FIXTURE_PACKAGES = [BASELINE_FIXTURES, PERIOD_KEYS_FIXTURES, REFERENCE_FIXTURES];

const BASELINE = { package: BASELINE_FIXTURES, consumer: "base-contract" };
// A member sits here when it tests an access-group coordinate or expects
// periodKeys beside a partial direct result; seal-ecdh.json seals both content
// keys and period keys. Mere presence of an unused periodKeys section is no reason.
const PERIOD_KEYS_ADMISSION = { package: PERIOD_KEYS_FIXTURES, consumer: "base-contract" };
const REFERENCE = { package: REFERENCE_FIXTURES, consumer: "reference" };

/**
 * The reviewed membership of every generated fixture: the package it is
 * written to, and the test tier that asserts from it. Output routing,
 * recorded-signature lookup and the manifests all read this one map.
 *
 * @type {Map<string, { package: string, consumer: string }>}
 */
const FIXTURE_MEMBERS = new Map([
  ["reject-alg-substituted-hs256.json", BASELINE],
  ["reject-alg-substituted.json", BASELINE],
  ["reject-data-not-object.json", BASELINE],
  ["reject-delimiter-accessgroup.json", PERIOD_KEYS_ADMISSION],
  ["reject-delimiter-contentname.json", BASELINE],
  ["reject-delimiter-sealed-accessgroup.json", PERIOD_KEYS_ADMISSION],
  ["reject-delimiter-sealed-contentname.json", BASELINE],
  ["reject-duplicate-member-name.json", REFERENCE],
  ["reject-foreign-render.json", PERIOD_KEYS_ADMISSION],
  ["reject-forged-resourcejwt.json", BASELINE],
  ["reject-identifier-accessgroup.json", PERIOD_KEYS_ADMISSION],
  ["reject-identifier-contentname.json", BASELINE],
  ["reject-identifier-contentname-final-lf.json", BASELINE],
  ["reject-identifier-contentname-65-chars.json", BASELINE],
  ["reject-issuedat-malformed.json", BASELINE],
  ["reject-no-coordinate.json", BASELINE],
  ["reject-no-renderid.json", BASELINE],
  ["reject-prototype-name.json", REFERENCE],
  ["reject-relabeled.json", PERIOD_KEYS_ADMISSION],
  ["reject-renderid-noncanonical.json", BASELINE],
  ["reject-renderid-wrong-width.json", BASELINE],
  ["reject-resourceid-empty.json", BASELINE],
  ["reject-tampered-resourcejwt.json", BASELINE],
  ["reject-typ-substituted.json", BASELINE],
  ["reject-unknown-contentname.json", PERIOD_KEYS_ADMISSION],
  ["seal-ecdh.json", PERIOD_KEYS_ADMISSION],
  ["seal-factory-content-key-only.json", REFERENCE],
  ["seal-factory-mixed-issuers.json", REFERENCE],
  ["seal-factory-period-keys.json", REFERENCE],
  ["seal-factory-refusals.json", REFERENCE],
]);

/**
 * A fixture package's directory, with a trailing slash.
 *
 * @param {string} fixturePackage - a package path under verification/
 * @returns {string}
 */
function fixturePackageDir(fixturePackage) {
  return fileURLToPath(new URL(`../../verification/${fixturePackage}/`, import.meta.url));
}

/**
 * The directory a generated fixture is written to and its recorded signature read from.
 *
 * @param {string} file
 * @returns {string}
 */
function fixtureDirOf(file) {
  const member = FIXTURE_MEMBERS.get(file);
  if (!member) throw new Error(`${file}: generated fixture has no reviewed consumer`);
  return fixturePackageDir(member.package);
}

/**
 * Lists one package's generated fixtures: each path, the format it uses and
 * the consumer that reads it. Throws on a file no package claims, a file of
 * another package, or an inventory that differs from the package's members.
 *
 * @param {string} fixturePackage - one of FIXTURE_PACKAGES
 * @param {{ file: string, vector: { vectorFormat: string } }[]} entries
 */
export function makeProtocolFixtureManifest(fixturePackage, entries) {
  if (!FIXTURE_PACKAGES.includes(fixturePackage)) {
    throw new Error(`unknown protocol fixture package ${fixturePackage}`);
  }
  const members = [...FIXTURE_MEMBERS]
    .filter(([, member]) => member.package === fixturePackage)
    .map(([file]) => file);
  const files = entries.map(({ file, vector }) => {
    const member = FIXTURE_MEMBERS.get(file);
    if (!member) throw new Error(`${file}: generated fixture has no reviewed consumer`);
    if (member.package !== fixturePackage) {
      throw new Error(`${file}: generated fixture belongs to ${member.package}`);
    }
    return {
      path: file,
      vectorFormat: vector.vectorFormat,
      consumers: [member.consumer],
    };
  });
  if (
    files.length !== members.length ||
    new Set(files.map(({ path }) => path)).size !== members.length ||
    files.some(({ path }) => !members.includes(path))
  ) {
    throw new Error(
      `${fixturePackage}: generated fixture inventory differs from its reviewed consumer map`,
    );
  }
  return {
    schema: "dca-protocol-fixture-manifest/v1",
    protocol: "dca",
    version: "1",
    stability: "draft",
    files: files.sort((a, b) => a.path.localeCompare(b.path)),
  };
}

/**
 * A fixture package's stability, out of its manifest. A package with no
 * manifest is `draft`: a refusal has to name fixtures frozen on purpose, and
 * a missing file is not that.
 *
 * @param {string} fixturePackage - named in the error
 * @param {string} dir - the package directory, with a trailing slash
 * @returns {string}
 */
function fixtureStabilityOf(fixturePackage, dir) {
  if (!existsSync(dir + FIXTURE_MANIFEST)) return "draft";
  const stability = JSON.parse(readFileSync(dir + FIXTURE_MANIFEST, "utf8")).stability;
  if (!["draft", "frozen"].includes(stability)) {
    throw new Error(
      `${fixturePackage} has unsupported fixture stability ${JSON.stringify(stability)}`,
    );
  }
  return stability;
}

/**
 * Refuses a write over a frozen fixture package. A frozen package is
 * immutable; a compatible change publishes a separate fixture revision.
 *
 * @param {string} fixturePackage - one of FIXTURE_PACKAGES, named in the error
 * @param {string} [dir] - the package directory; a test passes a temporary one
 */
export function assertFixturePackageWritable(
  fixturePackage,
  dir = fixturePackageDir(fixturePackage),
) {
  if (fixtureStabilityOf(fixturePackage, dir) !== "frozen") return;
  throw new Error(
    `${fixturePackage} is frozen, and this run would overwrite it. ` +
      "Changed bytes after a freeze are a new version, not a regeneration.",
  );
}

/** The run trims this prefix off the paths it prints, so no absolute path reaches the log. */
const VERIFICATION_DIR = fileURLToPath(new URL("../../verification/", import.meta.url));

/** The schema version of a render vector, apart from the DCA version. */
const VECTOR_FORMAT = "1";

/**
 * The schema version of a refusal vector. A separate number because it is a
 * separate shape read by a separate loop: `rawBody` and `expected.code`
 * where a render vector has `input` and `expected.dcaData`. A replay that knows
 * only format 1 has to be able to tell it is holding something else and skip it
 * loudly: a format 2 file has no `input` for it to read.
 */
const REJECT_FORMAT = "2";

/** The RFC 4648 URL alphabet, used to make one deliberately noncanonical tail. */
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * The schema version of an open vector: a recorded RSA-OAEP ciphertext with the
 * private fixture key, replayed by decrypting it and rebuilding the binding
 * rather than by re-sealing. This third number marks a third shape: the vector
 * carries a `blob` the private key decrypts, where format 1 carries an `input` a
 * run re-seals and format 2 a `rawBody` a request posts. OAEP draws its padding
 * inside WebCrypto, so an RSA seal cannot be made to repeat and a format-1 render
 * vector is impossible; an open vector pins the unseal and the recovered
 * `BIND ‖ key` plaintext.
 */
const OPEN_FORMAT = "3";

/** The schema version of the deterministic binding-carrier fixture. */
const BOUND_CARRIER_FORMAT = "4";

/** Profile vectors carry this word where the base render, request and open kinds take a number. */
const PROFILE_FORMAT = "profile";
const CLIENT_BOUND_ECDH_PROFILE = "dca-profile-client-bound-ecdh-p256";
const CLIENT_BOUND_RSA_PROFILE = "dca-profile-client-bound-rsa-oaep";

/** Trims an exported JWK to the four members the profile wire spells: kty, crv, x and y. */
function p256PublicJwk(jwk) {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

const ISSUER_NAME = "paywall_subscription_service";

/** The issuer's onboarding keypair. The publisher seals to its public half. */
const ISSUER_KEY = {
  publicKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "KnsL031lVTbNxwtMq3OQmFq-fyPVh3k1__Adl4ieLXw",
    y: "-aNkTV8wd6O2rTWc2jkpJgez4Cuvas4J8_Styi-cdsE",
  },
  privateKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "KnsL031lVTbNxwtMq3OQmFq-fyPVh3k1__Adl4ieLXw",
    y: "-aNkTV8wd6O2rTWc2jkpJgez4Cuvas4J8_Styi-cdsE",
    d: "iWEhz6AHq-n4l_YzhTZcyQH7O9B1A1AKl4maOJh3z5g",
  },
};

/**
 * The publisher's ES256 signing key. The issuer holds its public half for
 * `www.news-site.example`, and the JWT header names `kid`, so an issuer that has
 * already collected the next key can still verify this markup.
 */
const SIGNING_KEY = {
  kid: "sign-2025-10",
  publicKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "wjapTnuqn7FYYz7TbSiG283dToV0I1zpHoiVpbYGUYU",
    y: "9vgUr7XBOhco_Pf-7CczUPW8tmscQKhkiK0zybXWVCI",
  },
  privateKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "wjapTnuqn7FYYz7TbSiG283dToV0I1zpHoiVpbYGUYU",
    y: "9vgUr7XBOhco_Pf-7CczUPW8tmscQKhkiK0zybXWVCI",
    d: "yEB3Y-dXMSyFCoarJYWXaM6c0R82R-y_NgGNDV4vX10",
  },
};

/**
 * The base RSA-OAEP open vector, generated once through the base keySealing seal
 * path and pasted in. OAEP draws its padding seed inside WebCrypto, so an RSA
 * seal cannot be made to repeat, so this run emits the recorded ciphertext
 * rather than re-encrypting, which keeps a regeneration byte-stable and the
 * double-run diff clean. The render values are canonical, the
 * fixed 16-byte renderId and an ordinary content name, because an implementer
 * copies a vector and it should look like a normal render; the unit tests prove
 * the format maxima.
 */
const OPEN_RSA_FIXTURE = {
  renderId: "ESIzRFVmd4iZqrvM3e7_AA",
  contentName: "premiumtext",
  contentKeyBase64url: "AwoRGB8mLTQ7QklQV15lbA",
  bind: "dca-bind-key-envelope|c|ESIzRFVmd4iZqrvM3e7_AA|premiumtext",
  blob: "Y9LrlFPYx6kAukVlOjHyDW3BPK65OIzZQ35vwLlebpEiHcEwcBdGyHEdsDxr3B0ycpavZXwQPcYIj_m63KAsoPMfg11Y2GfgLJd0CqrfChCe0HKoO5HGq1VG7yzseLosgt_tWlMZukzHECx-lRkXpLnXpd86MCmOeFGQK2GjIGxQTio8d31pHUjTDfLfmRkwDulKxx_4FN5AqI1_-yazOmf3j_AAXlliITs1X-pVdN5mhvapZJ2fHbhSL-OA_NT6l71GtzZu6wVh_pMuXcj8hQ0WZQsukMLOjXDdaKQR5ChBCQpWT9S6yT8yGv0odW8iOY9U8oU7jryJOEKb5Sg9Bg",
  plaintextBase64url:
    "ZGNhLWJpbmQta2V5LWVudmVsb3BlfGN8RVNJelJGVm1kNGlacXJ2TTNlN19BQXxwcmVtaXVtdGV4dAMKERgfJi00O0JJUFdeZWw",
  publicKeyJwk: {
    kty: "RSA",
    n: "tZqcXwvLYArS9n-wfbtSO9zNbSWBaPIV8rTOb8luS-g9UaRF1j3Av-R-5Yg1F_qQAH-pkOkV_MVYkuS2CCpa6gBsZFu76BVtvceOnFncJZdK6TBES9YCmX_Wu_kWN_dk-AeqPMf3ThxoEmI37OB1pRDjZeoR1ujzK2ogmb2314uv3Xh_u3XWca211AiAMqndd_JbgjCBSpTLicQmHu0WIuLBe2Px6RIHRZqWDcQQMOM56GeERwms728WU5kKg6pGEbssqTwaT_8vLbk_W28Gm6Cct4UGVTZr4P5_irno3155ALu3ngTKeowa7cuo7Z2AOppO140gRa0TK-iKQMi2VQ",
    e: "AQAB",
    alg: "RSA-OAEP-256",
  },
  privateKeyJwk: {
    kty: "RSA",
    n: "tZqcXwvLYArS9n-wfbtSO9zNbSWBaPIV8rTOb8luS-g9UaRF1j3Av-R-5Yg1F_qQAH-pkOkV_MVYkuS2CCpa6gBsZFu76BVtvceOnFncJZdK6TBES9YCmX_Wu_kWN_dk-AeqPMf3ThxoEmI37OB1pRDjZeoR1ujzK2ogmb2314uv3Xh_u3XWca211AiAMqndd_JbgjCBSpTLicQmHu0WIuLBe2Px6RIHRZqWDcQQMOM56GeERwms728WU5kKg6pGEbssqTwaT_8vLbk_W28Gm6Cct4UGVTZr4P5_irno3155ALu3ngTKeowa7cuo7Z2AOppO140gRa0TK-iKQMi2VQ",
    e: "AQAB",
    d: "Abe1fWk-fyLMrBpFxTapmGY_xvKMUHDW6zP-SAyv0p94cjNIM5z9AioE1wjS0CGyTXlOCJ0WJ5ntOvxw47X7Pj9xRwGE6JtiE_t7pys3zt8Cs7hqMozSx8Vi0Ew5KdMMI5PQLofjC3XVnsDkXJ6JD-qpBlYW3TSLiKOJE3_5tmi4O3IbIzxXCX_7LiwL2nck74jQmQyjotgg3R2DZKIugRz383Z2FjzZ7KozPHyFaBuAtRnOv3amgDKkLx1iXtWLLBCXGPvU5EPDfO_U3YR5OTyYyxn9biGFzdplpD0YvVDredMlIU5MjIGDMdFq4Ky0VX5goTyjAiXm_96rDg_ziQ",
    p: "_SJfXspdbD9ZdN1QDDfhl-2yHSs9Ftp6rIQ81OkBrATWHal24CfppmJEH9yfVrR9Z_SncoIEgJxyNfw3HSURdHcnvGADTo1d7K3fJmJhG0TBJGyAJKMG2Q9Da997LOD3I-OBBX5trWFfYZ7Tad--ff8d49-HxvGTMe5-WJqt-bk",
    q: "t6juTp-T6fvjQ6WdyH7xvJjUamv_qtT42bjnxUlXVlYwDJC6egSAtv4XFf0KQQBJURf8LruqmH2NEC9quvRzBsD66VPNpwZxXvSEa04zF-CkcHehWvyGdHPv8YT8NWQKNB4ROm9JsbxzaL1W_bMfAADAkwYzYU5F-AyXLjALf30",
    dp: "jyOXsF9YUrTD3hyjfjU_QQ0tMedYZQroYZNpXq_fvSkC9sT0Lq8DJY3dnfLAu2PWoikrYsn4x80vnC1h8P4cD7Ktao0UcZ_o48QyMl9hL-1CFlmwYIc7gRRreJ1n5qnTtpyYQcYLOQady_Lm87CM5GyVt1yYR7wlExAcq_fTtyk",
    dq: "nUAN8tGdQt0BxFzcUNuoPPOaBBi-SlWZUEmKYJggKHMZJtkQYQLT9lpuB8ylZ-xH2iAwMw9JzNDK5A3FU5eTmTfIXdj8H0Nb9JJlgr7s7kfQY996Dz5iHPlbey6DB2_FcMRBugepUH3rTsW24vfn1gfO2tOXUHxFWlHla42Fer0",
    qi: "ND9CMV48VNCEayq4x0rAWYa1ZwPOofP2lefawlLja4A2IYo31s3AAtBUCMIwR3ZFDhKyUJN_hrrSdxdNfoO9RlxYTPddY6F36yFUA7spZKxZ1PuukqRdwS9TQnHU8BqZWIW59ofJxG6lXmXMG4k7rghLMNru9Y4zaD2X4BZVGo0",
    alg: "RSA-OAEP-256",
  },
};

/**
 * A signing keypair the publisher does not hold. It signs the forged envelope
 * in reject-forged-resourcejwt, and its public half rides in that vector so a
 * replay can confirm the forgery is a well-formed ES256 signature by the wrong
 * key rather than a damaged one. Nothing else touches it.
 */
const ATTACKER_KEY = {
  publicKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "W1MP_GCjSOxj-G8nJJfe78IybvQ4k-EH1B8nwRAl69g",
    y: "o8PZ1rWwuq5RGPYRb01H1CLPnDQuhE3_KUbFl5YkTGQ",
  },
  privateKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "W1MP_GCjSOxj-G8nJJfe78IybvQ4k-EH1B8nwRAl69g",
    y: "o8PZ1rWwuq5RGPYRb01H1CLPnDQuhE3_KUbFl5YkTGQ",
    d: "rRsV422e9vb_TTNCZZ3zqZgZvUCY5zdurkUpVGH_9Tk",
  },
};

/** Publisher-private period keys. The base protocol says nothing about deriving them. */
const PERIOD_KEYS = {
  premium: {
    "251023T1400": "RHITQ8LXhA9LX2eO-sGrgQ",
    "251023T1500": "Ny_ybN8p7Kx5a3EeWqZcYQ",
  },
  "locked-data": {
    "251023T1400": "DnOWRziRyJG4dyLY3NAHAw",
    "251023T1500": "pqhx7Xri7OgrCdP6TtUQ2w",
  },
};

/** Period key used only by the hostile publisher delimiter fixture. */
const UNBANNED_PERIOD_KEY = "34Km1WWQdqhxKqDhUkuCMA";

/**
 * Hourly periods, current and next. At the pinned clock that is 251023T1400 and
 * 251023T1500: the two overlap, so a page cached across the boundary still reads.
 */
const PERIOD = { length: 60, slots: 2 };

/**
 * One per sealed blob, in seal order: per issuer, then the contentKeys per
 * content item, then the periodKeys per accessGroup per period.
 */
const EPHEMERAL_KEYS = [
  {
    issuerName: ISSUER_NAME,
    contentName: "bodytext",
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "_-uukcCcIVx_w156EOBQbfD2S1QJtv_Us08hfmlPy7s",
      y: "s5xZErWJNnNAJfmyMYNXO4LYDDMaasFJMMGHk63Fqho",
    },
    privateKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "_-uukcCcIVx_w156EOBQbfD2S1QJtv_Us08hfmlPy7s",
      y: "s5xZErWJNnNAJfmyMYNXO4LYDDMaasFJMMGHk63Fqho",
      d: "8bOnBLg9jBNNA0DcpVKLwa74Lp_0Ld1NwYxeFMPslSY",
    },
  },
  {
    issuerName: ISSUER_NAME,
    contentName: "locked-data",
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "U78MhHxi8EXsoMLpyws47LCBG--CStcZmGC9f7hQRuk",
      y: "jbcExTFUDum7lWRXU21llsS3dQpzLxiJJptmVbY-4g8",
    },
    privateKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "U78MhHxi8EXsoMLpyws47LCBG--CStcZmGC9f7hQRuk",
      y: "jbcExTFUDum7lWRXU21llsS3dQpzLxiJJptmVbY-4g8",
      d: "pVLWFcQQe54w3fTbXEeMdHrQsp022PSzdEJ4cXelvFg",
    },
  },
  {
    issuerName: ISSUER_NAME,
    accessGroup: "premium",
    t: "251023T1400",
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "g0aRijquqGBYFVV0mIzRCIuHSyXs9EAOiPWxTLCHVVg",
      y: "30j8-6vfS2mXZ0KkOXUnF29fVZLF1YKUUPyeUhpwI44",
    },
    privateKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "g0aRijquqGBYFVV0mIzRCIuHSyXs9EAOiPWxTLCHVVg",
      y: "30j8-6vfS2mXZ0KkOXUnF29fVZLF1YKUUPyeUhpwI44",
      d: "tf8SxGwDTqEdSWZgwsHmsxePi5_OdgELGnin1Id894c",
    },
  },
  {
    issuerName: ISSUER_NAME,
    accessGroup: "premium",
    t: "251023T1500",
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "BZowtpYVMq7WIPnmimluztIJ6OXLEg5EQyZLui0A7Hc",
      y: "ZIAWv7cpyI0pH_U12MO4MTIUaBhuLkF0EVTFuneETto",
    },
    privateKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "BZowtpYVMq7WIPnmimluztIJ6OXLEg5EQyZLui0A7Hc",
      y: "ZIAWv7cpyI0pH_U12MO4MTIUaBhuLkF0EVTFuneETto",
      d: "SqeHO93UgSSFVarxYhUvtrxxgTILYqW_ez6XuYsX2EY",
    },
  },
  {
    issuerName: ISSUER_NAME,
    accessGroup: "locked-data",
    t: "251023T1400",
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "JTU43mJjv55pu96IFyBakmtbNz_m9YCmbaSi2MQGRU8",
      y: "XEeyvi2q1CZQgghDAdZds0Le4a0zopxM_a0OZrDEUJQ",
    },
    privateKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "JTU43mJjv55pu96IFyBakmtbNz_m9YCmbaSi2MQGRU8",
      y: "XEeyvi2q1CZQgghDAdZds0Le4a0zopxM_a0OZrDEUJQ",
      d: "HvBPy3Yppk3hKh9IijHOu-MDY0afnPtPFZreYGqCrpU",
    },
  },
  {
    issuerName: ISSUER_NAME,
    accessGroup: "locked-data",
    t: "251023T1500",
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "z4blPb0udnXhgGrGbpIAwJsodzB1fnC_-IsvQURv8PQ",
      y: "C-MPak9ZNDvcMsAOHjaiKcg9spCJnuVa-PDS7RcExw4",
    },
    privateKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: "z4blPb0udnXhgGrGbpIAwJsodzB1fnC_-IsvQURv8PQ",
      y: "C-MPak9ZNDvcMsAOHjaiKcg9spCJnuVa-PDS7RcExw4",
      d: "WJ4UOECHzxCufvq44bR8vlUQHonEdFnnS7zku2ruSE0",
    },
  },
];

/** Two items, two contentTypes, two accessGroups, so one nonce cannot pass for another. */
const CONTENT = [
  {
    name: "bodytext",
    value: "<p>The council voted 7-2 to rezone the harbour.</p>",
    contentType: "text/html",
    accessGroups: ["premium"],
  },
  {
    name: "locked-data",
    value: '{"vote":{"for":7,"against":2},"passed":true}',
    contentType: "application/json",
    accessGroups: ["locked-data"],
  },
];

/**
 * The render every fixture in this package is cut from.
 *
 * @returns {import('./vectorWorld.js').VectorInput}
 */
function inputFor() {
  return {
    seed: 20251023,
    clockIso: "2025-10-23T14:00:00Z",
    origin: "https://www.news-site.example",
    resourceId: "123456",
    resourceData: {
      "date.published": "2025-10-20T10:30:00Z",
      section: "politics",
      tags: ["breaking", "elections"],
    },
    periodKeys: PERIOD_KEYS,
    period: PERIOD,
    content: CONTENT,
    issuers: [
      {
        issuerName: ISSUER_NAME,
        keyId: "2025-10",
        algorithm: "ecdh-p256",

        publicKeyJwk: ISSUER_KEY.publicKeyJwk,
        privateKeyJwk: ISSUER_KEY.privateKeyJwk,
      },
    ],
    signingKeys: [SIGNING_KEY],
    signingKid: SIGNING_KEY.kid,
    ephemeralKeys: EPHEMERAL_KEYS,
  };
}

/**
 * Byte projections for opening the recorded content carriers. These live
 * beside `dcaData`, never inside it: `dcaData` remains the exact wire output.
 * The wire carries no content AAD; `aadBase64url` is the one each item derives
 * from the token's renderId and the content name, so a port can check its
 * transcript builder against it.
 *
 * @param {any} input
 * @param {any} dcaData
 * @returns {Record<string, { aadBase64url: string, valueBase64url: string }>}
 */
function contentOpenOf(input, dcaData) {
  const renderId = decodeCompactJwt(dcaData.resourceJWT)?.payload?.renderId;
  return Object.fromEntries(
    input.content.map((content) => {
      const record = dcaData.contentData[content.name];
      const aad =
        record &&
        contentAad({
          renderId,
          contentName: content.name,
        });
      if (!aad) throw new Error(`the render forms no content AAD for ${content.name}`);
      return [
        content.name,
        {
          aadBase64url: base64urlEncode(aad),
          valueBase64url: base64urlEncode(utf8Encode(content.value)),
        },
      ];
    }),
  );
}

/**
 * What every render description says about the binding, the one thing an
 * implementation needs that the wire never carries.
 */
const BINDING = [
  "THE BINDING, which an implementation needs before a single blob opens. Each sealed key commits to the",
  "coordinate it sits at, and that commitment is never transmitted - the issuer rebuilds it from what it has",
  'already verified. "dca-bind-key-envelope|c|" + renderId + "|" + contentName for a blob in sealed.contentKeys, and',
  '"dca-bind-key-envelope|p|" + renderId + "|" + accessGroup + "|" + t for one in sealed.periodKeys: joined on 0x7C,',
  "with that byte banned inside every field it separates, and renderId taken as the base64url string the wire",
  "carries rather than the bytes behind it. renderId is exactly 16 bytes here, encoded as 22 unpadded",
  "base64url characters. expected.bindings records every one of those strings, so a runtime can check its builder against",
  "them with no crypto in the way.",
  "ON ECDH THE VALUE IS THE AES-256-GCM additionalData. The blob layout is exactly 109 bytes,",
  "and a rebuilt value that differs anywhere is an auth tag failure with nothing on the wire to say why - the",
  "same failure a wrong private key gives. The renderId comes from the verified resourceJWT and the rest of",
  "the coordinate from the map keys being walked; a value built from anything a request said about itself",
  "would be built from what the attacker wrote.",
].join(" ");

const SEAL_DEFINITIONS = [
  {
    file: "seal-ecdh.json",
    description: [
      "One render, two content items, two accessGroups, two periods, one issuer, ECDH P-256,",
      "one signed envelope.",
      "The raw shared secret - the P-256 x-coordinate, 32 bytes - is the AES-256-GCM key with no KDF,",
      'which is what spec--sealed-key-envelopes.md specifies under "4. ECDH P-256 envelope".',
      "Replay: seal `input` and compare against `expected` byte for byte, with one exception.",
      "A FRESH SIGNATURE CANNOT BE PINNED: ES256 draws a random k per signature, so the third segment of",
      "a freshly sealed resourceJWT differs. Compare the first two segments (header and payload)",
      "byte for byte, and check the recorded signature cryptographically: ECDSA P-256 with SHA-256 over the",
      'UTF-8 bytes of "<header>.<payload>", with the signature the base64url-decoded third segment (raw r||s,',
      "64 bytes, no DER) and the key input.signingKeys[].publicKeyJwk selected by the kid in the header.",
      "Everything else - every sealed blob, every nonce and every ciphertext - is byte-stable and compares",
      "exactly.",
      "THE ENVELOPE. The resourceJWT payload is the resource, and its header is",
      '{"alg":"ES256","typ":"JWT","kid":...} and any other alg is rejected. It is the only signature on the',
      "wire, and the renderId under it is what every sealed blob of this render is bound to, which is why one",
      "signed copy of it is enough.",
      BINDING,
      "Publisher-private period-key input is recorded under input.periodKeys, keyed by accessGroup and t.",
      "Base assigns no derivation meaning to these opaque 16-byte values. expected.periodKeys records the same",
      "keys after recovery from the sealed wire, so input and recovery can be checked independently.",
      "The t values come from the clock and input.period ({length: 60 minutes, slots: 2}, current then next).",
      "Content-key path: unseal each blob in expected.dcaData.issuerData[issuerName].sealed.contentKeys with the",
      "issuer private JWK and the binding value for that contentName as additionalData, and compare against",
      "expected.contentKeys; then AES-128-GCM-decrypt expected.sealedContent[name] with that key, twelve zero",
      "nonce octets and the content AAD as additionalData, and compare against",
      "input.content[].value. The wire carries no content AAD: build it as docs/spec--content-protection.md",
      "Section 3.2 states: LP(renderId) || LP(contentName), where renderId is the token payload's value and",
      "LP(s) is the four-octet big-endian octet length of UTF8(s) followed by those octets.",
      "expected.contentOpen[name].aadBase64url records the result, so a",
      "runtime can check its builder with no crypto in the way. It has nothing to do with the binding value",
      "above - the two ride on different ciphertexts.",
      "Cached path: unseal issuerData[issuerName].sealed.periodKeys[accessGroup][t] the same way, with the",
      "period binding value for that pair, and compare against expected.periodKeys; then for each entry in",
      "expected.dcaData.contentData[contentName].keys[accessGroup] (an array of {t, nonce, key}) AES-128-GCM-",
      "decrypt entry.key with the periodKey for that same t, entry.nonce and NO additionalData - the contentKey",
      "comes back, equal to expected.contentKeys[contentName] - and decrypt the content with it as above.",
      "Every wire value is base64url with no padding.",
    ].join(" "),
  },
];

/**
 * The exact JWS signing input, or null when this is not a signed compact JWS.
 * A comparison stays on these encoded bytes rather than on parsed JSON, because
 * an ES256 signature covers the bytes, their member order and their encoding.
 *
 * @param {unknown} token
 * @returns {string|null}
 */
function signingInputOf(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) return null;
  return `${parts[0]}.${parts[1]}`;
}

/**
 * The previous vector, if it exists and is readable. A first generation has no
 * prior fixture, and this run overwrites a malformed prior file.
 *
 * @param {string} dir
 * @param {string} file
 * @returns {any|null}
 */
function recordedVector(dir, file) {
  if (!existsSync(dir + file)) return null;
  try {
    return JSON.parse(readFileSync(dir + file, "utf8"));
  } catch {
    return null;
  }
}

/**
 * A recorded render's signed resource, if that is the shape on disk.
 *
 * @param {string} dir
 * @param {string} file
 * @returns {unknown}
 */
function recordedRenderToken(dir, file) {
  return recordedVector(dir, file)?.expected?.dcaData?.resourceJWT;
}

/**
 * A recorded rejection body's signed resource, if that is the shape on disk.
 *
 * @param {string} file
 * @returns {unknown}
 */
function recordedRequestToken(file) {
  const rawBody = recordedVector(fixtureDirOf(file), file)?.rawBody;
  if (typeof rawBody !== "string") return null;
  try {
    return JSON.parse(rawBody).resourceJWT;
  } catch {
    return null;
  }
}

/**
 * The current public key that verifies an ES256 fixture signature.
 *
 * @param {import('./vectorWorld.js').EcJwk} jwk
 * @returns {Promise<CryptoKey>}
 */
function importSigningPublicKey(jwk) {
  return subtle.importKey("jwk", jwk, ECDSA_P256, false, ["verify"]);
}

/**
 * Keep a prior fixture signature only when it authenticates the exact bytes
 * this run generated under the current public key. An ECDSA signature has many
 * valid values for one signing input, so keeping a valid prior one changes no
 * cryptographic claim and keeps a meaningless diff out of the fixtures.
 *
 * @param {string} candidate
 * @param {unknown} recorded
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function retainRecordedSignature(candidate, recorded, publicKey) {
  const candidateInput = signingInputOf(candidate);
  if (candidateInput === null || candidateInput !== signingInputOf(recorded)) return candidate;

  try {
    await verify(recorded, publicKey);
    return /** @type {string} */ (recorded);
  } catch {
    return candidate;
  }
}

/**
 * @param {object} definition
 * @param {string} definition.file
 * @param {string} definition.description
 * @param {string} [definition.dir] - the file's fixture package when left out
 * @param {import('../core-publisher/Sealer.js').PeriodKeySupply} [definition.periodKeySupply] -
 *   explicit input keys when left out
 * @param {(input: any, dcaData: any) => Promise<object>} [definition.extra] - the
 *   sections a variant vector pins beyond the wire, merged into `expected`
 */
async function makeVector({ file, description, dir = fixtureDirOf(file), periodKeySupply, extra }) {
  const input = inputFor();
  const sealer = await buildSealer(input, { periodKeySupply });
  const { dcaData, sealedContent } = await sealer.seal();
  const signingKey = input.signingKeys.find(({ kid }) => kid === input.signingKid);
  if (!signingKey) throw new Error(`the vector has no public signing key for ${input.signingKid}`);

  dcaData.resourceJWT = await retainRecordedSignature(
    dcaData.resourceJWT,
    recordedRenderToken(dir, file),
    await importSigningPublicKey(signingKey.publicKeyJwk),
  );

  return {
    dir,
    file,
    vector: {
      name: file.replace(/\.json$/, ""),
      vectorFormat: VECTOR_FORMAT,
      description,
      input,
      expected: {
        dcaData,
        sealedContent,
        contentOpen: contentOpenOf(input, dcaData),
        bindings: bindingValues(input, dcaData),
        contentKeys: await recoverContentKeys(input, dcaData),
        periodKeys: await recoverPeriodKeys(input, dcaData),
        ...(extra ? await extra(input, dcaData) : {}),
      },
    },
  };
}

/**
 * The base RSA-OAEP open vector, assembled from the pasted fixture. This run
 * emits `OPEN_RSA_FIXTURE.blob` as the ciphertext rather than encrypting again,
 * so two runs write the same bytes and the sums file does not move for a
 * regeneration. The replayer decrypts the blob with the private fixture key,
 * rebuilds the binding from the recorded inputs, and compares the recovered
 * `BIND ‖ key` whole. The recorded fields pin the successful open. The
 * description also explains the wrong-binding refusal a replayer should test;
 * unlike the bound-carrier format, this record has no expected refusal field.
 *
 * @returns {{ dir: string, file: string, vector: any }}
 */
function makeOpenVector() {
  const f = OPEN_RSA_FIXTURE;
  const binding = { renderId: f.renderId, contentName: f.contentName };
  return {
    dir: RSA_OAEP_DIR,
    file: "open-rsa-oaep.json",
    vector: {
      name: "open-rsa-oaep",
      vectorFormat: OPEN_FORMAT,
      description: [
        "One RSA-OAEP sealed key blob, recorded with the private fixture key that opens it.",
        "RSA-OAEP is a base sealed-blob carrier beside ECDH P-256: the key is wrapped by OAEP directly, with",
        "the binding value ahead of it inside the one plaintext, so the blob is exactly one modulus wide -",
        "256 bytes at 2048 bits, base64url to 342 characters - whatever the plaintext holds.",
        "THIS IS AN OPEN VECTOR, NOT A SEAL VECTOR. OAEP draws its padding seed inside the crypto library with",
        "nothing to inject, so an RSA render is not reproducible and re-sealing input.contentKeyBase64url would",
        "produce a different blob every run. What is pinned is the unseal: expected.blob is the fixture, and a",
        "regeneration re-emits it verbatim.",
        "REPLAY. Import input.rsa.privateKeyJwk as RSA-OAEP over SHA-256 with no label; decrypt expected.blob",
        "with a single decrypt call (no internal structure to parse); the plaintext is expected.bind as UTF-8",
        "followed by the 16-byte key. Rebuild the binding from input.binding",
        "(dca-bind-key-envelope|c|renderId|contentName, which is expected.bind), take everything ahead of the last 16",
        "bytes as the recovered binding and compare it WHOLE against that value - a prefix compare would open",
        "the premiumtext blob under a premium grant - then the last 16 bytes are the key, equal to",
        "input.contentKeyBase64url.",
        "WRONG-BINDING REFUSAL. The prefix is the whole relabel defence on this carrier: the same blob rebuilt",
        "for another coordinate (contentName bodytext) recovers a plaintext whose prefix is not the rebuilt",
        "binding, and the open fails closed.",
        "The values are canonical, the fixed 16-byte renderId and an ordinary content name, because a vector is what an",
        "implementer copies; the format maxima are proved in the unit tests. Every wire value is base64url with",
        "no padding.",
      ].join(" "),
      input: {
        algorithm: "rsa-oaep",
        hash: "SHA-256",
        binding,
        contentKeyBase64url: f.contentKeyBase64url,
        rsa: {
          publicKeyJwk: f.publicKeyJwk,
          privateKeyJwk: f.privateKeyJwk,
        },
      },
      expected: {
        bind: f.bind,
        blob: f.blob,
        plaintextBase64url: f.plaintextBase64url,
      },
    },
  };
}

/**
 * Recorded negative opens for the same RSA-OAEP carrier. The prefix-confusion
 * record reuses the positive vector's fixed ciphertext; only its requested
 * binding differs. The long-tail ciphertext was recorded once because OAEP
 * padding is randomized, and is retained verbatim here.
 *
 * @returns {{ dir: string, file: string, vector: any }[]}
 */
export function makeOpenNegativeVectors() {
  const f = OPEN_RSA_FIXTURE;
  const binding = { renderId: f.renderId, contentName: "premium" };
  const bind = bindValue(binding);
  const rsa = { publicKeyJwk: f.publicKeyJwk, privateKeyJwk: f.privateKeyJwk };
  const sharedInput = {
    algorithm: "rsa-oaep",
    hash: "SHA-256",
    binding,
    contentKeyBase64url: f.contentKeyBase64url,
    rsa,
  };

  return [
    {
      file: "open-rsa-oaep-prefix-confusion.json",
      description:
        "docs/spec--sealed-key-envelopes.md sections 5 and 6 require whole-BIND comparison and a generic unseal_failed refusal. This valid OAEP ciphertext for premiumtext is presented at the shorter premium binding; the requested binding is a prefix of the recovered value, and the final 16 octets are the fixture key. A prefix-only comparison would release it.",
      blob: f.blob,
    },
    {
      file: "open-rsa-oaep-long-tail.json",
      description:
        "docs/spec--sealed-key-envelopes.md sections 5 and 6 require an exact BIND followed by one 16-byte key and a generic unseal_failed refusal. This valid OAEP ciphertext carries the requested binding and two 16-byte keys; a last-16-byte split would release a key from an over-width payload.",
      blob: "F3XfPz7ezaRxKJdBLG961DGfoshpoIkU1Ntd9kF2LCliVNipNNTdq98wDrCECMq79L02ndjU3_nPssVymKtJQt090WBVYzTII6zluBv-QYnGsG9mSUHVv9D3gckK_S47EzlQyj0t0bpcEm2tr-ZmdxRILpwx-HC0fUUZDMtSL2uG8W8_kNewdaM1HPXdeh7GpVU6W4C8_2JH3TkPcfH-r2ApMo-UUDCknOxCM0vw2egiwb0Dz0w70vRPRo8H8m97nRQLWdfihOgJPVa3uXi_c1YRVly8bNAu2Qjj7UBD8tV6pmtt80qnXEcM2GNi0IMWdrYDlW2g5FoU9IcfsPeQdw",
    },
  ].map(({ file, description, blob }) => ({
    dir: RSA_OAEP_DIR,
    file,
    vector: {
      name: file.replace(/\.json$/, ""),
      vectorFormat: OPEN_FORMAT,
      description,
      input: sharedInput,
      expected: { bind, blob, error: "unseal_failed" },
    },
  }));
}

/** @param {{ publicKeyJwk: any, privateKeyJwk: any }} fixture */
async function importEcdhFixture(fixture) {
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  return {
    publicKey: await subtle.importKey("jwk", fixture.publicKeyJwk, algorithm, true, []),
    // Both usages, because the two ECDH callers derive different things: the base
    // seal derives raw bits, and the client-bound transport derives a key
    // handle. WebCrypto refuses deriveKey on a base key imported for
    // deriveBits alone, which stopped this generator at the client-bound
    // ECDH profile vector before it wrote anything.
    privateKey: await subtle.importKey("jwk", fixture.privateKeyJwk, algorithm, false, [
      "deriveBits",
      "deriveKey",
    ]),
  };
}

/**
 * Generate the binding-carrier alternative from fixed inputs. ECDH is entirely
 * reproducible when its ephemeral keypairs and nonces are fixtures. RSA-OAEP
 * cannot be reproduced, so this retains the recorded ciphertext only after
 * opening it with the fixture private key under the same binding and checking
 * the recovered key.
 *
 * @returns {Promise<{ dir: string, file: string, vector: any }>}
 */
export async function makeBoundCarrierVector() {
  const renderId = OPEN_RSA_FIXTURE.renderId;
  const contentName = OPEN_RSA_FIXTURE.contentName;
  const accessGroup = "premium";
  const t = "251023T1300";
  const contentKeyBase64url = OPEN_RSA_FIXTURE.contentKeyBase64url;
  const periodKeyBase64url = "HSo3RFFea3iFkp-sucbT4A";
  const contentNonceBase64url = "AQYLEBUaHyQpLjM4";
  const periodNonceBase64url = "AgsUHSYvOEFKU1xl";
  const contentBinding = { renderId, contentName };
  const periodBinding = { renderId, accessGroup, t };
  const issuer = ISSUER_KEY;
  const contentEphemeral = EPHEMERAL_KEYS[0];
  const periodEphemeral = EPHEMERAL_KEYS[2];
  const issuerPublicKey = (await importEcdhFixture(issuer)).publicKey;

  async function deterministicEcdhBlob(keyBase64url, nonceBase64url, binding, ephemeral) {
    return seal(base64urlDecode(keyBase64url), issuerPublicKey, "ecdh-p256", {
      binding,
      random: { bytes: () => base64urlDecode(nonceBase64url) },
      ephemeralKeyPair: await importEcdhFixture(ephemeral),
    });
  }

  const contentBlob = await deterministicEcdhBlob(
    contentKeyBase64url,
    contentNonceBase64url,
    contentBinding,
    contentEphemeral,
  );
  const periodBlob = await deterministicEcdhBlob(
    periodKeyBase64url,
    periodNonceBase64url,
    periodBinding,
    periodEphemeral,
  );

  const rsaPrivateKey = await subtle.importKey(
    "jwk",
    OPEN_RSA_FIXTURE.privateKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
  const recoveredRsaKey = await open(OPEN_RSA_FIXTURE.blob, rsaPrivateKey, "rsa-oaep", {
    binding: contentBinding,
  });
  if (base64urlEncode(recoveredRsaKey) !== contentKeyBase64url) {
    throw new Error("the recorded RSA-OAEP fixture does not open to its bound content key");
  }

  return {
    dir: BOUND_CARRIER_DIR,
    file: "bind-blobs.json",
    vector: {
      name: "bind-blobs",
      vectorFormat: BOUND_CARRIER_FORMAT,
      description: [
        "A generator-owned format-4 bound-carrier fixture: two deterministic ECDH P-256 blobs and one",
        "recorded RSA-OAEP blob. The bindings are dca-bind-key-envelope|c|renderId|contentName and",
        "dca-bind-key-envelope|p|renderId|accessGroup|t, with an exact 16-byte renderId carried as 22 canonical",
        "unpadded base64url characters. The ECDH blobs are re-sealed from the fixed issuer and ephemeral",
        "keypairs, 12-byte nonces, keys and coordinates below. RSA-OAEP cannot be reproduced byte for byte,",
        "so its recorded ciphertext is retained only after the generator opens it under the fixture private",
        "key and confirms the same binding and content key. Replayers also refuse a relabelled contentName",
        "and an ECDH open with no additionalData.",
      ].join(" "),
      input: {
        algorithm: "ecdh-p256",
        renderId,
        contentName,
        accessGroup,
        t,
        contentKeyBase64url,
        periodKeyBase64url,
        ecdh: {
          issuer,
          contentEphemeral: {
            publicKeyJwk: contentEphemeral.publicKeyJwk,
            privateKeyJwk: contentEphemeral.privateKeyJwk,
          },
          periodEphemeral: {
            publicKeyJwk: periodEphemeral.publicKeyJwk,
            privateKeyJwk: periodEphemeral.privateKeyJwk,
          },
          contentNonceBase64url,
          periodNonceBase64url,
        },
        rsa: {
          publicKeyJwk: OPEN_RSA_FIXTURE.publicKeyJwk,
          privateKeyJwk: OPEN_RSA_FIXTURE.privateKeyJwk,
        },
      },
      expected: {
        bind: {
          content: OPEN_RSA_FIXTURE.bind,
          period: `dca-bind-key-envelope|p|${renderId}|${accessGroup}|${t}`,
        },
        ecdh: {
          contentBlob,
          periodBlob,
          unsealWithoutAad: { fails: true, reason: "aes-gcm-tag" },
        },
        rsa: {
          contentBlob: OPEN_RSA_FIXTURE.blob,
          plaintextBase64url: OPEN_RSA_FIXTURE.plaintextBase64url,
        },
      },
    },
  };
}

/**
 * The three delivered keys each client-bound profile vector records, one per
 * result section. The section fixes the key kind the issuer binds into the wrapped key
 * (docs/spec--response-binding.md section 6), so a replayer that binds the
 * wrong kind, an empty context or a misspelled kind string fails the key it
 * got wrong. The nonces are ECDH-only inputs.
 */
const CLIENT_BOUND_DELIVERED_KEYS = [
  {
    section: "contentKeys",
    keyKind: "contentKey",
    deliveryKeyBase64url: "HSo3RFFea3iFkp-sucbT4A",
    nonceBase64url: "Aw0VFyEjKTM5Q0tT",
  },
  {
    section: "periodKeys",
    keyKind: "periodKey",
    deliveryKeyBase64url: "UVRXWl1gY2ZpbG9ydXh7fg",
    nonceBase64url: "ISMlJykrLS8xMzU3",
  },
  {
    section: "chainKeys",
    keyKind: "chainKey",
    deliveryKeyBase64url: "oqessba7wMXKz9TZ3uPo7Q",
    nonceBase64url: "cXR3en2Ag4aJjI-S",
  },
];

/**
 * Opens one recorded client-bound key through the profile opener as the kind
 * its section fixes, and checks it carries the delivery key: a handle for a
 * content or period key, the 16 raw octets for a chain key.
 *
 * @param {any} opener
 * @param {any} wrappedKey
 * @param {{ keyKind: 'contentKey'|'periodKey'|'chainKey', deliveryKeyBase64url: string }} deliveredKey
 * @param {string} method
 */
async function checkClientBoundOpen(opener, wrappedKey, deliveredKey, method) {
  const usages = deliveredKey.keyKind === "periodKey" ? ["unwrapKey"] : ["decrypt"];
  const opened = await opener.open(wrappedKey, usages, deliveredKey.keyKind);
  if (deliveredKey.keyKind === "chainKey") {
    if (
      !(opened instanceof Uint8Array) ||
      base64urlEncode(opened) !== deliveredKey.deliveryKeyBase64url
    ) {
      throw new Error(`the client-bound ${method} chain key did not open to its 16 raw octets`);
    }
    return;
  }
  if (!opened || opened.extractable || opened.algorithm.name !== "AES-GCM") {
    throw new Error(
      `the client-bound ${method} ${deliveredKey.keyKind} did not open to a non-extractable AES-GCM handle`,
    );
  }
}

/**
 * One profile vector for issuer-to-client ECDH delivery. Unlike a base ECDH
 * blob, this one runs its shared secret through the client-bound HKDF, and its
 * response carries the issuer's ephemeral public key beside a per-key AES-GCM
 * nonce. This injects both entropy sources, so the issuer seal and the client
 * open replay byte for byte across runtimes.
 *
 * @returns {Promise<{ dir: string, file: string, vector: any }>}
 */
async function makeClientBoundEcdhVector() {
  const client = ISSUER_KEY;
  const ephemeral = EPHEMERAL_KEYS[0];
  const nonces = CLIENT_BOUND_DELIVERED_KEYS.map(({ nonceBase64url }) =>
    base64urlDecode(nonceBase64url),
  );
  let drawn = 0;
  const sealer = await clientBoundEcdh.seal(client.publicKeyJwk, {
    ephemeralKeyPair: await importEcdhFixture(ephemeral),
    random: {
      bytes: (n) => {
        const nonce = nonces[drawn++];
        if (!nonce || n !== nonce.length) {
          throw new Error(`client-bound ECDH asked for nonce ${drawn} of ${n} bytes`);
        }
        return nonce;
      },
    },
  });
  const opener = await clientBoundEcdh.open(
    sealer.transport,
    (await importEcdhFixture(client)).privateKey,
  );
  const deliveredKeys = [];
  for (const deliveredKey of CLIENT_BOUND_DELIVERED_KEYS) {
    const wrappedKey = await sealer.wrap(
      base64urlDecode(deliveredKey.deliveryKeyBase64url),
      deliveredKey.keyKind,
    );
    await checkClientBoundOpen(opener, wrappedKey, deliveredKey, clientBoundEcdh.METHOD);
    deliveredKeys.push({
      keyKind: deliveredKey.keyKind,
      kindContextBase64url: base64urlEncode(keyKindContext(deliveredKey.keyKind)),
      wrappedKey,
      openedKeyBase64url: deliveredKey.deliveryKeyBase64url,
    });
  }

  return {
    dir: CLIENT_BOUND_ECDH_DIR,
    file: "client-bound-ecdh-p256.json",
    vector: {
      name: "client-bound-ecdh-p256",
      vectorFormat: PROFILE_FORMAT,
      profile: CLIENT_BOUND_ECDH_PROFILE,
      description: [
        "A client-bound ECDH-P256 delivery profile vector. The issuer uses the injected P-256",
        "ephemeral pair and the nonces below to wrap one 16-byte delivered key per result section for the",
        "client public JWK: a contentKeys entry, a periodKeys entry and a chainKeys entry. The wire contract is",
        "expected.transport (the client-bound method and semantic ephemeral public JWK) plus each",
        "expected.deliveredKeys[].wrappedKey ({key, nonce}); the client combines that public key with its private",
        "fixture key, runs HKDF-SHA256 with empty salt and UTF-8 info dca-derivation-client-bound-transport, and opens",
        "each AES-256-GCM value with its kind context as additional data: UTF-8 dca-bind-client-bound-key-kind, one",
        "zero octet, then UTF-8 of the kind its section fixes (kindContextBase64url). Both seal and open are",
        "deterministic here because the ephemeral keypair and nonces are inputs rather than fresh draws. A",
        "content or period key opens to an AES-GCM handle in WebCrypto and a chain key to its 16 raw",
        "octets; openedKeyBase64url states the raw value another runtime must recover.",
      ].join(" "),
      input: {
        client: client,
        issuerEphemeralKeyPair: {
          publicKeyJwk: ephemeral.publicKeyJwk,
          privateKeyJwk: ephemeral.privateKeyJwk,
        },
        deliveredKeys: CLIENT_BOUND_DELIVERED_KEYS,
      },
      expected: {
        transport: {
          publicKey: p256PublicJwk(sealer.transport.publicKey),
          method: clientBoundEcdh.METHOD,
        },
        deliveredKeys,
      },
    },
  };
}

/**
 * The recorded RSA-OAEP ciphertext of each CLIENT_BOUND_DELIVERED_KEYS entry, sealed
 * once under the fixture public key with its kind context as the OAEP label.
 */
const CLIENT_BOUND_RSA_WRAPPED = {
  contentKey:
    "ODwwz8T-l46E7z9e9s1cgqnoRm2RCQncZYY6wH0KxJshpx5c-lVifsPTdxeCEvulcnIVjg2Lggu2_LOplBpICIZ6PtP8R_r3gZsnNoocGGJctHC1BITngxebCh0aX1D3UEdSKN0FQ7Y8f3aC8RR4hDqu698A0EmgC3xWsHZ-oSJJJKaJnBpV28a0B4lPyUOsWg8KGxJuoK5tVcAb3uYCW4z8DvmmAtIuSk9n7biERlO4VufOGtR5K1aWog94xG_rH70Q-Q6qYERPTbqzQ0YEk3KfQmZfdXJm8DV6IpCWNt5R--K5D96kOYltu5UsA2L3sNaybAYOp9A7br0vC_ZXsg",
  periodKey:
    "N_pf39B9fSeSEWJj_cckWJMNOlrE2DevjT-Z8_a1KGbxfhvQ0p8AN5mdbguHx6JX2g_DhmZ_INJfWwA4xKMeSfr5lSkAZroOIVztowYge4sielhpa3Hmo3NVLJ_FmQY9-LQNayF1KgDyQFyaWVsZeRGIZt7SoD6Ye-F2qQ0lCWEyZTU7yyYJBqVoaU1UPmoG7vI7kw76YWKkSVSi6ctvgHd3rmT9PIWRXdMjNfmZATiH6XC22DObrh28HQFUS11M_8NOa3B9-AEXrjRUTaUTzVUlQXkH3MwBtIZOlhlMXJ97rAHSO3eZbKDmHza9mSVARJ1yfF_qgZvdHZfujAWtZA",
  chainKey:
    "ehBxgxBv-qTX0jWbr3yHRdeIVEm8j15DXaLIsoIg6NZo8J-bvSTFdMemHzmZKgpK0KIkazuyyhQmaDKIfnDFR__-jOmQ0AkcufqWdmb1fqR28j1b09WnIfHbUz5Hhc2Pw30kwdzepEUs62gVBFcGjNNDJqPKxE39uF1hQMxqLP5AUEQdT2CgdrIunuyFnryNHQuQFyVy4sL-44nP3GMz3uUfnJs94AmIKSK6s1P7leQnWHu_cSi6fbKbGppKXhc6WkVKJi1LqYIK7Q7KQzjxulPrcCMLSeDKD-CJtFIr2hmDaxp7YRncRPV4HKB1XFKcZBsr1uSZ5DkzchLwjtUFWA",
};

/**
 * One profile vector for issuer-to-client RSA-OAEP delivery. OAEP padding is
 * random inside WebCrypto, so its recorded ciphertexts are deliberately open
 * fixtures: a regeneration decrypts each one under its kind label, checks it
 * and re-emits it verbatim rather than sealing it again.
 *
 * @returns {Promise<{ dir: string, file: string, vector: any }>}
 */
async function makeClientBoundRsaVector() {
  const client = {
    publicKeyJwk: OPEN_RSA_FIXTURE.publicKeyJwk,
    privateKeyJwk: OPEN_RSA_FIXTURE.privateKeyJwk,
  };
  const privateKey = await subtle.importKey(
    "jwk",
    client.privateKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt", "unwrapKey"],
  );
  const opener = await clientBoundRsa.open({}, privateKey);
  const inputKeys = CLIENT_BOUND_DELIVERED_KEYS.map(
    ({ section, keyKind, deliveryKeyBase64url }) => ({
      section,
      keyKind,
      deliveryKeyBase64url,
    }),
  );
  const deliveredKeys = [];
  for (const deliveredKey of inputKeys) {
    const wrappedKey = { key: CLIENT_BOUND_RSA_WRAPPED[deliveredKey.keyKind] };
    const label = keyKindContext(deliveredKey.keyKind);
    const recovered = new Uint8Array(
      await subtle.decrypt(
        { name: "RSA-OAEP", label },
        privateKey,
        base64urlDecode(wrappedKey.key),
      ),
    );
    if (base64urlEncode(recovered) !== deliveredKey.deliveryKeyBase64url) {
      throw new Error(
        `the recorded client-bound RSA-OAEP ${deliveredKey.keyKind} ciphertext does not recover its fixture key`,
      );
    }
    await checkClientBoundOpen(opener, wrappedKey, deliveredKey, clientBoundRsa.METHOD);
    deliveredKeys.push({
      keyKind: deliveredKey.keyKind,
      kindContextBase64url: base64urlEncode(label),
      wrappedKey,
      openedKeyBase64url: deliveredKey.deliveryKeyBase64url,
    });
  }

  return {
    dir: CLIENT_BOUND_RSA_DIR,
    file: "client-bound-rsa-oaep.json",
    vector: {
      name: "client-bound-rsa-oaep",
      vectorFormat: PROFILE_FORMAT,
      profile: CLIENT_BOUND_RSA_PROFILE,
      description: [
        "A client-bound RSA-OAEP delivery profile open vector. The wire contract is the",
        "RSA-OAEP method in expected.transport, with no ephemeral public key or nonce,",
        "and each expected.deliveredKeys[].wrappedKey ({key}) carrying one RSA-OAEP-SHA256 ciphertext for the client",
        "public JWK: a contentKeys entry, a periodKeys entry and a chainKeys entry. Each ciphertext carries its",
        "kind context as the OAEP label: UTF-8 dca-bind-client-bound-key-kind, one zero octet, then UTF-8 of the kind",
        "its section fixes (kindContextBase64url). RSA-OAEP padding is randomized inside WebCrypto, so this is",
        "deliberately an open-only fixture: regeneration decrypts each recorded ciphertext and re-emits it",
        "verbatim rather than claiming a repeatable seal. The client opens a content or period key to a",
        "non-extractable AES-GCM handle and a chain key to its 16 raw octets; openedKeyBase64url states the",
        "raw 16-byte key an environment replayer must recover.",
      ].join(" "),
      input: { client, deliveredKeys: inputKeys },
      expected: {
        transport: { method: clientBoundRsa.METHOD },
        deliveredKeys,
      },
    },
  };
}

/** Which render every reject body below is cut from. */
const REJECT_BASE = "seal-ecdh";

/**
 * Stands in for sealed.contentKeys while the body is serialized, and `renderBody`
 * replaces it with text afterwards. A member name cannot repeat inside an object,
 * so the one section an attack needs to control is rendered from an ordered pair
 * list instead, which keeps both members in order for a parser to choose between.
 */
const CONTENT_KEYS_SLOT = "@@sealed.contentKeys@@";

/**
 * One unlock request as it crosses the wire, with sealed.contentKeys rendered
 * from `pairs` rather than from an object.
 *
 * Two-space JSON puts `sealed` at depth 1, `contentKeys` at depth 2 and its
 * members at depth 3. The literal indentation below spells that out, because the
 * block is text by the time it gets here.
 *
 * @param {any} request - what the client built, minus the section under attack
 * @param {[string, string][]} pairs - contentName to blob, duplicates allowed
 * @returns {string}
 */
function renderBody(request, pairs) {
  const body = {
    ...request,
    sealed: {
      contentKeys: CONTENT_KEYS_SLOT,
      ...(request.sealed.periodKeys ? { periodKeys: request.sealed.periodKeys } : {}),
    },
  };

  const text = JSON.stringify(body, null, 2);
  const slot = JSON.stringify(CONTENT_KEYS_SLOT);
  if (text.split(slot).length !== 2) {
    throw new Error("the contentKeys slot is not in the body exactly once");
  }

  const members = pairs
    .map(([name, blob]) => `      ${JSON.stringify(name)}: ${JSON.stringify(blob)}`)
    .join(",\n");

  return text.replace(slot, pairs.length === 0 ? "{}" : `{\n${members}\n    }`);
}

/**
 * The blob the honest request carries at one coordinate, read by name rather
 * than by position, so a definition below can say what it swaps.
 *
 * @param {[string, string][]} pairs
 * @param {string} contentName
 * @returns {string}
 */
function blobAt(pairs, contentName) {
  const found = pairs.find(([name]) => name === contentName);
  if (!found) throw new Error(`the honest request carries no ${contentName}`);
  return found[1];
}

/**
 * The render's ephemeral keypair fixture for one coordinate, read by the
 * coordinate rather than by position in the list. The generator seals two blobs
 * the render never sealed and reuses a fixture for each, so the issuer derives
 * the same wrapping key from the honest blob and the hostile one beside it and
 * the bound value is the only thing left between opening one and not.
 *
 * @param {{ contentName?: string, accessGroup?: string, t?: string }} coordinate
 * @returns {{ publicKeyJwk: any, privateKeyJwk: any }}
 */
function ephemeralAt({ contentName, accessGroup, t }) {
  const found = EPHEMERAL_KEYS.find(
    (key) => key.contentName === contentName && key.accessGroup === accessGroup && key.t === t,
  );
  if (!found)
    throw new Error(
      `the render seals nothing at ${JSON.stringify({ contentName, accessGroup, t })}`,
    );
  return found;
}

/**
 * The nonce an ECDH blob carries, so two blobs sharing an ephemeral point can
 * be held apart. One AES key with one nonce covers one message, and reusing a
 * keypair fixture puts two blobs under one key.
 *
 * @param {string} blob - base64url, as the wire carries it
 * @returns {string}
 */
function nonceOf(blob) {
  return base64urlEncode(
    base64urlDecode(blob).subarray(ECDH_POINT_BYTES, ECDH_POINT_BYTES + NONCE_BYTES),
  );
}

/**
 * The two coordinates the delimiter vectors present, written from the delimiter
 * itself so a change to the grammar's separator moves the attack with it. Both
 * are one character away from a name `core-shared/names` admits, `bodytext` and
 * `premium:sport`, and that character is the one the binding joins on.
 */
const DELIMITED_CONTENT_NAME = `body${BIND_DELIMITER}text`;
const DELIMITED_ACCESS_GROUP = `premium${BIND_DELIMITER}sport`;

/**
 * The two names the identifier vectors present. Neither carries the binding
 * delimiter, so the identifier grammar refuses them rather than the separator
 * ban the four delimiter vectors above already cover.
 * `2025-election` is digit-initial and `premium sport` contains a space. Both
 * are close to ordinary names while still outside the identifier grammar.
 */
const UNADMITTED_CONTENT_NAME = "2025-election";
const FINAL_LF_CONTENT_NAME = "bodytext\n";
const OVERLONG_CONTENT_NAME = `a${"a".repeat(64)}`;
const UNADMITTED_ACCESS_GROUP = "premium sport";

/** The one `typ` the format admits, and the value the substitution arm writes. */
const ADMITTED_TYP = "JWT";
const SUBSTITUTED_TYP = "DCA";

/**
 * The three signed members the payload vectors present unadmitted. Each is the
 * base render's own value put in the shape a producer that never ran the format
 * emits: a space where RFC 3339 fixes `T`, an identifier with nothing in it,
 * and the empty map as the empty array, which is what `json_encode` writes for
 * a PHP array a producer never filled.
 */
const UNADMITTED_ISSUED_AT = "2025-10-23 14:00:00.000Z";
const UNADMITTED_RESOURCE_ID = "";
const UNADMITTED_DATA = [];

/**
 * The period the hostile-publisher blob is sealed at, and the pair the request
 * presents it under. Two of a period binding's five fields are the caller's, so
 * with the ban gone the pair the blob was sealed at and the pair below join to
 * one string, and an issuer hands a reader granted `premium` the periodKey of
 * the family called `premium|sport`. These are written from the delimiter for the
 * same reason the two names above are: a change to the separator moves the
 * collision with it.
 */
const SEALED_PERIOD = "251023T1400";
const RESPLIT_ACCESS_GROUP = "premium";
const RESPLIT_PERIOD = `sport${BIND_DELIMITER}${SEALED_PERIOD}`;

/** How the wire reports a periodKey failure: the pair, joined on that character. */
const RESPLIT_LABEL = `${RESPLIT_ACCESS_GROUP}${BIND_DELIMITER}${RESPLIT_PERIOD}`;

/**
 * The nonces for the two blobs no Sealer run produces, fixed the way
 * `makeBoundCarrierVector` fixes its two. Each shares an ephemeral keypair
 * fixture with a blob of the honest render, so the wrapping key is the same one
 * and the nonce keeps the two ciphertexts apart.
 */
const UNBANNED_PERIOD_NONCE = "AxAdKjdEUV5reIWS";
const UNBANNED_CONTENT_NONCE = "BBUmN0hZanuMna6_";

/**
 * The contentKey the hostile render sealed at the delimited name. A contentKey
 * is drawn at random per render, so this one was drawn once with getRandomValues
 * and pasted in, like the keypairs above. It appears nowhere else in the corpus,
 * so a response carrying it is unmistakable.
 */
const UNBANNED_CONTENT_KEY = "vYZegsRp8YfEF07iU63Ct15wjcEaITGXvuDMDZuzk3E";

/** Uncompressed P-256 point: the first field of an ECDH blob, ahead of the nonce. */
const ECDH_POINT_BYTES = 65;

/** Both periods of both families, the answer an untouched periodKeys section gets. */
const EVERY_PERIOD = {
  premium: ["251023T1400", "251023T1500"],
  "locked-data": ["251023T1400", "251023T1500"],
};

/** What every reject description ends with: how to run it, and what counts as a pass. */
const REPLAY = [
  "REPLAY. Post `rawBody` VERBATIM - the string as it sits in this file, never a re-serialization of it -",
  "to the unlock endpoint, with `issuer` as the key material the issuer holds for its own name and keyId,",
  "and `publisher.signingKeys` as the public verification halves, read straight from this file rather than",
  "resolved by a deployment lookup.",
  "A pass is: expected.code where there is one; key material back for",
  "exactly the coordinates in expected.keys and no others; and an error back for exactly the coordinates in",
  "expected.errors, under the codes recorded there. No publisher private key is in this file, on purpose: an",
  "issuer never holds one, so everything a reject vector asks for is checkable with what a real issuer has.",
  "HOW FAR THE REFUSAL REACHES IS PART OF WHAT IS PINNED, and expected.privateKeyReached says which side of",
  "the line this body lands on. A request that fails integrity - a signature that does not verify, a signed",
  "resource with no renderId to bind to - has asked nothing that could be answered, so it is refused whole and",
  "before the key store is consulted at all. A blob presented at a coordinate it was not sealed at is one bad",
  "blob in an ordinary request: the only way to find out is to try it, so the key store is reached, the blob",
  "comes back as an error, and everything else the request carried is answered beside it. The untouched",
  "coordinates were never the attack, and a page has to keep working around one bad blob, so they are answered.",
  "Everything in the body but the attack is the render this vector was cut from - the envelope, the periodKeys",
  "section and the untouched blobs are what the publisher emitted.",
  "An unchanged regeneration retains the valid resourceJWT signature segment inside rawBody, so the body is",
  `byte-stable with ${REJECT_BASE}.json. A fresh seal still draws a new k, which is why a replayer verifies`,
  "the segment rather than comparing it. The token is the one in the base vector from the same run, byte for",
  "byte, except in reject-no-renderid, reject-renderid-noncanonical and reject-renderid-wrong-width, whose",
  "envelopes are second tokens signed over resources with the renderId removed, given a noncanonical spelling,",
  "or resized, which is each vector's whole subject; in",
  "reject-forged-resourcejwt, whose signature",
  "segment was drawn by a key the publisher does not hold; in reject-tampered-resourcejwt, which carries",
  `the ${REJECT_BASE} token's own signature segment under a payload edited after signing; and in the two`,
  "reject-alg-substituted arms, which carry that token's payload segment under a header rewritten to name",
  "another algorithm, with a third segment that is empty or a MAC - neither of which moves between runs.",
].join(" ");

const REJECT_DEFINITIONS = [
  {
    file: "reject-relabeled.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) =>
      /** @type {[string, string][]} */ ([
        ["bodytext", blobAt(pairs, "locked-data")],
        ["locked-data", blobAt(pairs, "bodytext")],
      ]),
    expected: {
      code: null,
      keys: { contentKeys: [], periodKeys: EVERY_PERIOD },
      errors: { bodytext: "unseal_failed", "locked-data": "unseal_failed" },
      privateKeyReached: true,
    },
    description: () =>
      [
        "An unlock request an issuer must not answer as asked: two sealed blobs swapped between their",
        "contentNames.",
        "THE ATTACK. sealed.contentKeys.bodytext carries the blob the publisher sealed under locked-data, and",
        "sealed.contentKeys[locked-data] carries the one sealed under bodytext. Both blobs are genuine, both were",
        "sealed to the issuer key in this file, and neither is at the coordinate the publisher sealed it at.",
        "Relabeling costs an attacker nothing - the blobs are on the page, in the markup, and moving one to",
        "another name is a text edit. This is the attack the binding exists for.",
        'WHY NEITHER OPENS. The issuer rebuilds "dca-bind-key-envelope|c|" + renderId + "|" + contentName from the renderId',
        "in the verified resourceJWT and the member name it is walking, and passes it as AES-256-GCM",
        'additionalData. The blob under "bodytext" was sealed under the locked-data value, so the tag fails, and',
        "the same the other way. There is nothing beside the blob saying where it belongs and so nothing to",
        "relabel: the coordinate is inside the ciphertext.",
        "WHAT A CONFORMANT ISSUER ANSWERS. 200, no contentKey of any kind, and an error at each of the two",
        "coordinates. The periodKeys section of this body is untouched and comes back in full - it was asked for",
        "honestly and granted honestly, and refusing it would refuse the client something the relabel never",
        "reached. What must not happen is a key: an implementation that unseals what it was sent without",
        "rebuilding the coordinate hands back locked-data's contentKey under the name bodytext, which is the",
        "paywall bypass this vector is here to catch. It passes every positive vector in this directory and fails",
        "this one.",
        "The issuer cannot tell this apart from a key rollover the markup outlived - both are a blob that will not",
        "open - and it does not need to. The answer is the same either way: this caller gets no key here.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-foreign-render.json",
    needed: ["bodytext", "locked-data"],
    /**
     * @param {[string, string][]} pairs
     * @param {any} facts
     */
    attack: (pairs, facts) =>
      /** @type {[string, string][]} */ ([
        ["bodytext", facts.foreignRender.contentKeys.bodytext],
        ["locked-data", blobAt(pairs, "locked-data")],
      ]),
    expected: {
      code: null,
      keys: { contentKeys: ["locked-data"], periodKeys: EVERY_PERIOD },
      errors: { bodytext: "unseal_failed" },
      privateKeyReached: true,
    },
    /** @param {{ foreignRender: { renderId: string } }} facts */
    description: (facts) =>
      [
        "An unlock request an issuer must not answer as asked: a sealed blob lifted out of a different render of",
        "the same article.",
        "THE ATTACK. sealed.contentKeys.bodytext carries the bodytext blob from a SECOND render of this page -",
        "same publisher, same issuer, same contentName, same article, different render. Its renderId is",
        `${facts.foreignRender.renderId} and this request's is the one in its resourceJWT. Everything else in the`,
        "body is this render's. Reloading an article is all it takes to hold two renders at once, so an attacker",
        "who can open one blob under one render would otherwise be able to reuse it against every later one.",
        "WHY IT DOES NOT OPEN, and this vector is built so that the binding is the only thing standing there. The",
        "two renders were sealed with the same ephemeral keypair fixture, so the issuer derives the same",
        "AES-256-GCM key from the blob's own ephemeral point, and the nonce is carried in the blob. The one",
        "difference between opening it and not is the additionalData: renderId sits inside",
        '"dca-bind-key-envelope|c|" + renderId + "|" + contentName, the issuer builds it from the renderId in the verified',
        "resourceJWT, and it does not match the one this blob was sealed under. Tag failure. In a real pair of",
        "renders the ephemeral keypairs differ too; that would hide the point this vector is making.",
        "WHY THE RENDERID IS 16 BYTES. It is the only field in the value an attacker cannot choose and cannot",
        "reuse, so guessing a renderId is what a cross-render substitution costs. Freshness per render is the",
        "other half of it and no code can check that one: the issuer has never seen the render before.",
        "A CONFORMANT ISSUER answers 200 with an error at bodytext, the locked-data contentKey it did ask for",
        "honestly, and the untouched periodKeys section.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-duplicate-member-name.json",
    needed: ["bodytext"],
    /**
     * @param {[string, string][]} pairs
     * @param {any} facts
     */
    attack: (pairs, facts) =>
      /** @type {[string, string][]} */ ([
        ["bodytext", blobAt(pairs, "bodytext")],
        ["bodytext", facts.foreign],
      ]),
    expected: {
      code: null,
      keys: { contentKeys: [], periodKeys: { premium: ["251023T1400", "251023T1500"] } },
      errors: { bodytext: "unseal_failed" },
      privateKeyReached: true,
      alsoConformant: [
        {
          code: "invalid_json",
          when: "a parser that refuses a body carrying the same member name twice, before any DCA check runs",
        },
      ],
    },
    /** @param {{ contentKeys: Record<string, string> }} facts */
    description: (facts) =>
      [
        'An unlock request whose sealed.contentKeys carries the member name "bodytext" TWICE.',
        "THE SHAPE, which is a paywall-bypass shape. The first occurrence is the blob the publisher sealed",
        "under bodytext. The second is the blob sealed under locked-data, which this request never mentions by",
        "name. The client asks for bodytext and nothing else, so a policy keyed by contentName - which is where",
        "DCA puts one - sees a request for bodytext.",
        "IT ONLY EXISTS IN THE STRING. JSON.parse and PHP json_decode both keep the last member and hand back",
        'an object with one "bodytext", so a request object cannot express this and a replay that re-serializes',
        "rawBody before posting it has already destroyed the vector. Post the string.",
        "WHAT THE BINDING DOES TO IT. If parsing accepts the body, the lexical-last member is unsealed with",
        '"dca-bind-key-envelope|c|" + renderId + "|bodytext" as additionalData, because "bodytext" is the name it was read',
        `under. Last wins, which is what every parser in reach does: the locked-data blob is at bodytext, it was`,
        `not sealed there, and it does not open. The key it would otherwise have yielded is`,
        `${facts.contentKeys["locked-data"]} - the contentKey for locked-data, handed back under the name the`,
        "caller was entitled to. Keeping the first occurrence would instead open the bodytext blob, but that is",
        "not an allowed parser reading. The protocol permits exactly two outcomes: refuse duplicate members, or",
        "keep the lexical-last member and produce the recorded per-coordinate refusal.",
        "IT IS STILL WORTH A PUBLISHER-SIDE LINT. A duplicate member in rendered output is a publisher bug",
        "wherever it lands.",
        "js/tools/duplicateMembers.js is that lint.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-unknown-contentname.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) =>
      /** @type {[string, string][]} */ ([...pairs, ["editors-note", blobAt(pairs, "bodytext")]]),
    expected: {
      code: null,
      keys: { contentKeys: ["bodytext", "locked-data"], periodKeys: EVERY_PERIOD },
      errors: { "editors-note": "unseal_failed" },
      privateKeyReached: true,
    },
    description: () =>
      [
        "An unlock request carrying a sealed blob under a contentName this render never sealed anything under.",
        'THE ATTACK. sealed.contentKeys carries "editors-note", holding the genuine bodytext blob. Both real',
        "coordinates are untouched and correct. This ADDS a coordinate rather than moving one, which is the case",
        "an issuer misses when it walks a list of what the publisher sealed instead of walking what arrived - a",
        "name that is not on such a list is a name that loop never looks at.",
        "WHY IT DOES NOT OPEN. There is no list to walk past. The issuer walks the request, and for every",
        'contentName in it rebuilds "dca-bind-key-envelope|c|" + renderId + "|" + contentName and unseals under that value.',
        'For "editors-note" that is a value nothing was ever sealed under, so the tag fails. A name the publisher',
        "never used is refused by the same machinery that refuses a name it used elsewhere, and there is no",
        "unknown-name check to forget: a coordinate nothing was sealed at IS a binding nothing matches.",
        "A CONFORMANT ISSUER answers 200 with the two honest contentKeys, the untouched periodKeys section, and an",
        "error at editors-note. That partial answer is the point of the shape: a publisher can put a name on the",
        "page that this issuer has never been told about, and the rest of the page still opens.",
        "NOT CONFORMANT: a key of any kind under editors-note.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-prototype-name.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) =>
      /** @type {[string, string][]} */ ([
        ...pairs,
        ["constructor", blobAt(pairs, "bodytext")],
        ["__proto__", blobAt(pairs, "locked-data")],
      ]),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request carrying contentNames that are inherited member names in JavaScript.",
        'THE ATTACK. sealed.contentKeys carries "constructor" and "__proto__", each holding a genuine sealed blob',
        "of this render. On the wire they are two ordinary strings, since a contentName is whatever the publisher",
        'called a field. In JavaScript, map["constructor"] answers out of',
        'Object.prototype with a function rather than missing, "__proto__" read on a plain object reaches the',
        'prototype chain, and "__proto__" WRITTEN on one moves the prototype instead of adding a member.',
        'WHY THE REQUEST IS REFUSED WHOLE. The identifier grammar is letter-initial, so "__proto__" is not a name',
        "any consumer admits, and the format says a map keyed by identifiers is rejected whole when one member",
        "name violates that grammar rather than having the invalid name skipped beside its siblings. The issuer",
        "admits every request identifier before policy, BIND construction or private-key work, so this body is a",
        "whole-request binding_failed refusal: no key, no per-coordinate error, and the private key untouched.",
        '"constructor" is a different case and the grammar admits it - it is letter-initial and carries no',
        "reserved character - which is why it travels here beside the name that is refused.",
        "WHAT THIS VECTOR PINS BESIDE THE REFUSAL. Every map that comes off the wire is keyed by a name",
        "the client chose, so core/IssuerEngine.js and ports/UnlockEndpoint.js read them with",
        "Object.hasOwn or off Object.keys (and the port's status table is a Map, for the same reason). The",
        "response side is the same hazard pointed the other way: an issuer that builds its errors map or its keys",
        'map by plain assignment writes a prototype instead of a member for "__proto__", and a coordinate can',
        "then go back unreported. Identifier admission closes the request path to that name, and the map-building",
        "discipline is what keeps a runtime difference from appearing anywhere else, since PHP has no prototype",
        "chain and both names are unremarkable array keys there.",
        "NOT CONFORMANT: a TypeError or a 500 anywhere in the pass; a key of any kind; a 200 carrying either name",
        "in keys or in errors; a response map whose prototype was moved.",
        "Note JSON.parse makes both names OWN properties of the parsed object, so the refusal is a rule about the",
        "name and not a lookup accident.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-delimiter-contentname.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) =>
      /** @type {[string, string][]} */ ([
        ...pairs,
        [DELIMITED_CONTENT_NAME, blobAt(pairs, "bodytext")],
      ]),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request carrying a sealed blob under a contentName with the binding delimiter inside it.",
        `THE ATTACK. sealed.contentKeys carries "${DELIMITED_CONTENT_NAME}", holding the genuine bodytext blob.`,
        "Both real coordinates are untouched and correct. The delimiter is what separates the fields of a binding",
        "value, and core-shared/names bans it inside every name a publisher emits, so this coordinate never came",
        "off a render: the caller wrote it, and the one character in it is the one the grammar reserves.",
        "The issuer admits every request coordinate before policy, BIND construction or private-key work. A field",
        "carrying the delimiter cannot be represented in BIND or in an unambiguous error coordinate, so this is a",
        "whole-request binding_failed refusal. No honest sibling and no per-coordinate error is returned.",
        "NOT CONFORMANT: reaching the issuer private key, returning any key, or copying the malformed name into",
        "an errors member.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-delimiter-accessgroup.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * This attack adds a family to sealed.periodKeys, so it happens here rather
     * than in the contentKeys pair list `attack` reshapes.
     *
     * @param {any} request
     */
    request: async (request) => ({
      ...request,
      sealed: {
        ...request.sealed,
        periodKeys: {
          ...request.sealed.periodKeys,
          [DELIMITED_ACCESS_GROUP]: { ...request.sealed.periodKeys.premium },
        },
      },
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request whose sealed.periodKeys carries an accessGroup with the binding delimiter inside it.",
        `THE ATTACK. sealed.periodKeys carries "${DELIMITED_ACCESS_GROUP}" beside premium and locked-data,`,
        "holding the two genuine premium periodKey blobs of this render. The two honest families are untouched.",
        '"premium:sport" is a name the grammar allows, and this is the same name spelled with the one character',
        "the grammar reserves, which is what makes it the near miss rather than the obvious one.",
        'WHY IT DOES NOT OPEN, AND WHAT THE DELIMITER IS FOR. A period binding is five fields - "dca-bind-key-envelope",',
        '"p", the renderId, the accessGroup and t - joined on the delimiter. Two of those fields are the',
        "caller's, and an issuer never parses t: it takes the pair it was handed and joins. So with the",
        `delimiter allowed inside either field, the pair ("premium", "sport${BIND_DELIMITER}251023T1400") and the`,
        `pair ("${DELIMITED_ACCESS_GROUP}", "251023T1400") join to one string, and the value stops naming one`,
        "coordinate. The ban is what keeps the join a boundary. Without one the encoding is concatenation, where",
        '"premium1" with t "251023T1300" and "premium" with t "1251023T1300" are also one string. The issuer builds',
        "no value out of a field carrying the separator, so neither blob under this family is opened.",
        "The issuer admits every request coordinate before policy, BIND construction or private-key work. A field",
        "carrying the delimiter cannot be represented in BIND or in an unambiguous error coordinate, so this is a",
        "whole-request binding_failed refusal. No honest sibling and no per-coordinate error is returned.",
        "NOT CONFORMANT: reaching the issuer private key, returning any key, or copying the malformed coordinate",
        "into the response.",
        "WHAT AN IMPLEMENTATION THAT SKIPS THE BAN HANDS THE ATTACKER: two coordinates that are one. No key falls",
        "out of THIS body - the publisher's own sealer bans the delimiter, so nothing of this render was sealed",
        "at a coordinate a re-split could reach - and the two readings above are two names a policy decides",
        "separately, so neither is a grant the other carries. What is handed over is the property every later",
        "argument rests on: the decision is made on one reading of the pair and the blob is opened under the",
        "other, with nothing on the wire to say which pair was asked for. An implementation that joins whatever",
        "it was handed keeps that open in every deployment where a name with the delimiter in it reaches the wire",
        "at all - a CMS that never ran the sealer's name check, a second implementation of the sealer, markup",
        "written by hand.",
        "WHAT THIS VECTOR DOES NOT PIN. It does not separate an issuer that runs the ban from one that does not.",
        "Both build no key here, both report the same two errors, and a tree with the ban deleted replays this",
        "body byte for byte the way a conformant one does. The separation needs a blob sealed at a coordinate",
        "the ban refuses, and this render has none. reject-delimiter-sealed-accessgroup presents such a blob at",
        "the pair its own coordinate re-splits into, which is the collision the paragraph above describes, and",
        "reject-delimiter-sealed-contentname does the same on the content grammar.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-delimiter-sealed-contentname.json",
    needed: ["bodytext", "locked-data"],
    /**
     * @param {[string, string][]} pairs
     * @param {any} facts
     */
    attack: (pairs, facts) =>
      /** @type {[string, string][]} */ ([
        ...pairs,
        [DELIMITED_CONTENT_NAME, facts.unbanned.contentBlob],
      ]),
    /** @param {any} facts */
    extra: (facts) => ({
      sealedUnder: [
        {
          coordinate: facts.unbanned.contentCoordinate,
          bind: facts.unbanned.contentBind,
          keyBase64url: facts.unbanned.contentKeyBase64url,
        },
      ],
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    /** @param {{ unbanned: { contentKeyBase64url: string } }} facts */
    description: (facts) =>
      [
        "An unlock request carrying a blob that WAS SEALED under a contentName with the binding delimiter",
        "inside it.",
        `THE ATTACK. sealed.contentKeys carries "${DELIMITED_CONTENT_NAME}" beside the two honest coordinates,`,
        'and the blob under it is one no run of this sealer produced: it was sealed under "dca-bind-key-envelope|c|" +',
        `renderId + "|${DELIMITED_CONTENT_NAME}" by a publisher that never ran the ban on the name it was`,
        "handed. That is a CMS that skipped the name check, a second implementation of the sealer, or markup",
        "written by hand, and once such a blob is on a page, anyone who can read the page can post it back.",
        "It carries the same ephemeral point as the honest bodytext blob beside it, so an issuer agrees the same",
        "wrapping key from either, and the value it was sealed under is the only thing between opening it and",
        "not.",
        'WHY A BANNING ISSUER REFUSES IT. A content binding is four fields - "dca-bind-key-envelope", "c", the renderId',
        "and the contentName - joined on the delimiter. Structural admission rejects a name carrying that",
        "character before policy, BIND construction or private-key work.",
        "WHAT AN IMPLEMENTATION THAT SKIPS THE BAN HANDS THE ATTACKER: the key. It joins the four fields it was",
        "handed, arrives at the exact string this blob was sealed under, the tag VERIFIES, and",
        `${facts.unbanned.contentKeyBase64url} comes back under a name expected.keys does not list.`,
        "The matching honest-blob vector proves the same admission happens regardless of blob contents. This",
        "sealed-at vector additionally records the key a blind delimiter join would release, so it distinguishes",
        "structural admission from an implementation that merely tries authentication at the malformed name.",
        "A CONFORMANT ISSUER rejects the whole request with binding_failed and returns no key or error member.",
        "NOT CONFORMANT: reaching the private key, or returning a key of any kind under that name.",
        "THE VALUE IS ON RECORD, in `sealedUnder`: the coordinate the blob was sealed at, the exact string it",
        "was sealed under, and the key inside it. A replayer cannot rebuild that string, because its own",
        "builder refuses the field that carries the delimiter, which is the whole of what this vector pins. So",
        "the string is recorded, and with it a replay can open the blob, see a real key at a real coordinate",
        "rather than damaged bytes, and hold what it recovers to the key recorded here.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-delimiter-sealed-accessgroup.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * This attack adds a period to an honest family, so it happens here rather
     * than in the contentKeys pair list `attack` reshapes.
     *
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      sealed: {
        ...request.sealed,
        periodKeys: {
          ...request.sealed.periodKeys,
          [RESPLIT_ACCESS_GROUP]: {
            ...request.sealed.periodKeys[RESPLIT_ACCESS_GROUP],
            [RESPLIT_PERIOD]: facts.unbanned.periodBlob,
          },
        },
      },
    }),
    /** @param {any} facts */
    extra: (facts) => ({
      sealedUnder: [
        {
          coordinate: facts.unbanned.periodCoordinate,
          bind: facts.unbanned.periodBind,
          keyBase64url: facts.unbanned.periodKeyBase64url,
        },
      ],
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    /** @param {{ unbanned: { periodKeyBase64url: string } }} facts */
    description: (facts) =>
      [
        "An unlock request presenting a sealed periodKey under a pair of fields that joins to the pair it was",
        "sealed at. This is the collision the delimiter ban exists for.",
        `THE ATTACK. sealed.periodKeys.${RESPLIT_ACCESS_GROUP} carries a third period, "${RESPLIT_PERIOD}",`,
        `beside the two honest ones. The blob under it was sealed at accessGroup "${DELIMITED_ACCESS_GROUP}"`,
        `with t "${SEALED_PERIOD}" by a publisher that never ran the ban, and it holds the genuine periodKey of`,
        `that family, ${facts.unbanned.periodKeyBase64url}, which this render's premium family never had.`,
        `THE TWO READINGS. ("${DELIMITED_ACCESS_GROUP}", "${SEALED_PERIOD}") and ("${RESPLIT_ACCESS_GROUP}",`,
        `"${RESPLIT_PERIOD}") join to one string: "dca-bind-key-envelope|p|" + renderId + "|${RESPLIT_LABEL}". The caller`,
        `asks under ${RESPLIT_ACCESS_GROUP}, a family a reader can hold a grant for, and the blob it presents`,
        `belongs to one nobody granted. accessGroups are flat: ${RESPLIT_ACCESS_GROUP} is not the parent of`,
        `${DELIMITED_ACCESS_GROUP}, and a grant for one has never been a grant for the other.`,
        "WHY A BANNING ISSUER REFUSES IT. Structural admission checks the exact t grammar before policy, BIND",
        "construction or private-key work. Here t carries the separator, so the whole request is refused.",
        `WHAT AN IMPLEMENTATION THAT SKIPS THE BAN HANDS THE ATTACKER: ${DELIMITED_ACCESS_GROUP}'s periodKey`,
        `under a ${RESPLIT_ACCESS_GROUP} grant. It joins the pair it was handed, arrives at the string above,`,
        "the tag VERIFIES, and the key comes back at a coordinate expected.keys does not list. The decision was",
        "made on one reading of the pair and the blob was opened under the other, with nothing on the wire to",
        "say which pair was asked for.",
        "The blob carries the same ephemeral point as the honest premium 251023T1400 blob beside it, so an issuer",
        "agrees the same wrapping key from either, and the value it was sealed under is the only thing between",
        "opening it and not.",
        "The matching honest-blob vector proves the same admission happens regardless of blob contents. This",
        "sealed-at vector additionally records the key a blind delimiter join would release under the other",
        "reading of the pair, so it distinguishes structural admission from trial authentication.",
        "A CONFORMANT ISSUER rejects the whole request with binding_failed and returns no key or error member.",
        `NOT CONFORMANT: a periodKey at ("${RESPLIT_ACCESS_GROUP}", "${RESPLIT_PERIOD}"), reaching the private`,
        "key, or copying the ambiguous coordinate into the response.",
        "THE VALUE IS ON RECORD, in `sealedUnder`: the coordinate the blob was sealed at, the exact string it",
        "was sealed under, and the key inside it. A replayer cannot rebuild that string, because its own",
        "builder refuses the field that carries the delimiter, which is the whole of what this vector pins. So",
        "the string is recorded, and with it a replay can open the blob, see a real key at a real coordinate",
        "rather than damaged bytes, and hold what it recovers to the key recorded here.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-no-coordinate.json",
    needed: [],
    attack: () => [],
    /**
     * This attack empties the sealed section, so it happens here rather than in
     * the contentKeys pair list `attack` reshapes.
     *
     * @param {any} request
     */
    request: async (request) => ({ ...request, sealed: { contentKeys: {} } }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request that asks for no coordinate at all: a verified envelope, the issuerName and keyId",
        "of this issuer, and sealed.contentKeys as the empty map with no periodKeys section beside it.",
        "WHERE IT COMES FROM. A client that resolved every contentName out of its own cache and posted anyway,",
        "a request whose sealed section a proxy stripped, and a caller probing the endpoint for what it will",
        "verify for free. The first is the one that happens: the shipped client sends no request when it needs",
        "nothing, so a body like this is a second implementation of the client or a hand-written one.",
        "The issuer admits the request shape before policy, BIND construction or private-key work, and a",
        "request with no coordinate in it has nothing to admit. It is refused whole with binding_failed, the",
        "same code every other unrepresentable coordinate in this directory is refused with.",
        "WHAT THE REFUSAL IS WORTH. An answered empty request is a signature verification and a policy call",
        "the caller gets for nothing, repeatable as fast as it can post, and an empty 200 a client cannot tell",
        "apart from a grant of nothing. Refusing it keeps the endpoint answering requests for keys.",
        "NOT CONFORMANT: 200 with an empty keys section, and reaching the issuer private key.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-identifier-contentname.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) =>
      /** @type {[string, string][]} */ ([
        ...pairs,
        [UNADMITTED_CONTENT_NAME, blobAt(pairs, "bodytext")],
      ]),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request carrying a sealed blob under a contentName the identifier grammar does not admit.",
        `THE ATTACK. sealed.contentKeys carries "${UNADMITTED_CONTENT_NAME}", holding the genuine bodytext blob.`,
        "Both real coordinates are untouched and correct. The name carries no binding delimiter, so what refuses",
        "it is the grammar itself rather than the separator ban the four delimiter vectors beside it cover: a",
        "name starts with a letter and continues in letters, digits, underscore, colon and hyphen.",
        "WHY DIGIT-INITIAL IS THE ONE PRESENTED. It is the class that stops being the name it was written as.",
        "A JS engine reorders an integer-like member to the front of the object it sits in, whatever order the",
        "JSON carried, and a PHP producer emits such a member out of an array rather than a map. A coordinate",
        "whose position and spelling depend on which implementation read it is a coordinate two sides disagree",
        "about, and a bound value cannot be built over that disagreement.",
        "The issuer admits every request coordinate before policy, BIND construction or private-key work, so",
        "this is a whole-request binding_failed refusal. No honest sibling and no per-coordinate error is",
        "returned, because an unadmitted name is a name the response cannot repeat either.",
        "NOT CONFORMANT: reaching the issuer private key, returning any key, or copying the name into an errors",
        "member.",
        REPLAY,
      ].join(" "),
  },
  ...[
    {
      file: "reject-identifier-contentname-final-lf.json",
      name: FINAL_LF_CONTENT_NAME,
      reason: "a final LF after an otherwise valid name",
    },
    {
      file: "reject-identifier-contentname-65-chars.json",
      name: OVERLONG_CONTENT_NAME,
      reason: "65 ASCII characters, one above the 64-character bound",
    },
  ].map(({ file, name, reason }) => ({
    file,
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) =>
      /** @type {[string, string][]} */ ([...pairs, [name, blobAt(pairs, "bodytext")]]),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        `An unlock request with ${reason} as a sealed contentName.`,
        `THE ATTACK. The key spelling is ${JSON.stringify(name)} and holds the genuine bodytext blob.`,
        "The sibling coordinates remain valid. Identifier admission refuses the whole request before policy,",
        "BIND construction or issuer private-key access; a regex that accepts the final LF or overlong name",
        "would cross that boundary. A conforming issuer answers binding_failed with no keys or local errors.",
        REPLAY,
      ].join(" "),
  })),
  {
    file: "reject-identifier-accessgroup.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * This attack adds a family to sealed.periodKeys, so it happens here rather
     * than in the contentKeys pair list `attack` reshapes.
     *
     * @param {any} request
     */
    request: async (request) => ({
      ...request,
      sealed: {
        ...request.sealed,
        periodKeys: {
          ...request.sealed.periodKeys,
          [UNADMITTED_ACCESS_GROUP]: { ...request.sealed.periodKeys.premium },
        },
      },
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [], periodKeys: {} },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request whose sealed.periodKeys carries an accessGroup the identifier grammar does not",
        "admit.",
        `THE ATTACK. sealed.periodKeys carries "${UNADMITTED_ACCESS_GROUP}" beside premium and locked-data,`,
        "holding the two genuine premium periodKey blobs of this render. The two honest families are untouched.",
        '"premium:sport" is the name the grammar admits for this pair of words, and this is the same pair with',
        "a space between them: one character outside the grammar, and no binding delimiter anywhere in it.",
        "WHY A SPACE IS WORTH A VECTOR. An accessGroup is an entitlement name a policy decides on and a log",
        "line records. Whitespace inside one is a name that a trimming reader, a URL-encoded copy and a log",
        "consumer each read differently, so the name a policy granted stops being provably the name a blob was",
        "opened under. The grammar is what makes those one string.",
        "The issuer admits every request coordinate before policy, BIND construction or private-key work, so",
        "this is a whole-request binding_failed refusal. No honest sibling and no per-coordinate error is",
        "returned.",
        "NOT CONFORMANT: reaching the issuer private key, returning any key, or copying the name into the",
        "response.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-forged-resourcejwt.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.forgedJwt,
    }),
    extra: () => ({ attacker: { publicKeyJwk: ATTACKER_KEY.publicKeyJwk } }),
    expected: {
      code: "bad_signature",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a resourceJWT signed by a key the publisher does not",
        "hold.",
        "THE ATTACK. Every byte of this body except one segment is the honest render - the blobs, the periodKeys",
        "section and the token's own header and payload are the publisher's, byte for",
        "byte. The signature segment is not: it was drawn over those same two segments by attacker.publicKeyJwk's",
        "private half, a key that appears nowhere in publisher.signingKeys. The header still names the",
        "publisher's kid, because an attacker writes whatever selects the key most likely to be skipped.",
        "WHY THE CHECK IS ALL THERE IS. The renderId is the binding's only unguessable field and it comes out of",
        "this payload alone. An issuer that skips verification accepts a self-minted token naming any renderId,",
        "and every blob the attacker holds then opens at the coordinate the attacker chose. This body is the",
        "least version of that: the token is self-minted and everything else is honest, so an issuer that skips",
        "the check answers every key of the render - the loudest possible failure against the recorded",
        "bad_signature refusal. An issuer that checks spends one signature verification and refuses.",
        "WHY THE FORGERY IS WELL-FORMED. attacker.publicKeyJwk verifies this token, so a replay can confirm the",
        "signature is a valid ES256 signature by the wrong key and not 64 damaged bytes - the damaged case is",
        "reject-tampered-resourcejwt's. A refusal that only fires on malformed signatures would pass here and",
        "fail there.",
        "A CONFORMANT ISSUER answers 400 with bad_signature and no key of any kind, before its private key is",
        "touched: the refusal costs the one verification and zero ECDH operations. expected.privateKeyReached is",
        "false and a replay that can count asymmetric operations should hold it to that.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-tampered-resourcejwt.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.tamperedJwt,
    }),
    expected: {
      code: "bad_signature",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    /** @param {any} facts */
    description: (facts) =>
      [
        "An unlock request an issuer must refuse whole: a genuine resourceJWT whose payload was edited after",
        "signing.",
        "THE ATTACK. The token's header and signature segments are the publisher's own, byte for byte the ones",
        `in ${REJECT_BASE}.json from the same run. Between them, date.published in the payload was moved from`,
        `${JSON.stringify(facts.originalPublished)} to ${JSON.stringify(facts.tamperedResource.data["date.published"])} - one minute`,
        "before the pinned clock. The",
        "renderId is untouched, so every blob in the body would open if the request got that far: what the edit",
        "buys, on an issuer that does not verify over the edited bytes, is an access decision made on the",
        "attacker's claims - a metered policy that grants by article age reads a three-day-old article as",
        "published a minute ago.",
        'WHY IT IS REFUSED. ES256 verifies over the exact bytes of "<header>.<payload>". The signature was drawn',
        "over the original payload and does not verify over this one, and there is no field-level integrity to",
        "appeal to: one edited byte anywhere in the payload is this same refusal.",
        "THE FAMILY. reject-forged-resourcejwt is the wrong key over the right bytes; this is the right key over",
        "the wrong bytes; reject-alg-substituted and its HS256 arm are neither, because the header there names a",
        "different check and the ECDSA verify these two fail is never run at all. The three are the negative",
        "space of the one signature check on the wire: an issuer that pins the key and pins the bytes but reads",
        "the algorithm off the header refuses this vector and its forged sibling, and hands the whole render to",
        "the third. This tamper changes the only resource representation on the wire, so editing the signed",
        "copy kills the whole request.",
        "A CONFORMANT ISSUER answers 400 with bad_signature and no key of any kind, before its private key is",
        "touched: one verification spent, zero ECDH operations. expected.privateKeyReached is false.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-alg-substituted.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.algNoneJwt,
    }),
    extra: () => ({ substitution: { alg: "none" } }),
    expected: {
      code: "bad_alg",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: the publisher's own signed resource behind a header",
        'that says alg "none".',
        `THE ATTACK. The payload segment is the publisher's, byte for byte the one in ${REJECT_BASE}.json. The`,
        'header in front of it was rewritten to {"alg":"none","typ":"JWT","kid":...}, keeping the kid, and the',
        "third segment is empty, which is what that algorithm means: there is nothing to check. The blobs, the",
        "periodKeys section are the render's own.",
        "WHY IT IS NOT THE FORGERY AGAIN. reject-forged-resourcejwt and reject-tampered-resourcejwt both name",
        "ES256 and both fail an honest ECDSA verify, so an implementation that pins the key and pins the bytes",
        "and takes the algorithm from the header refuses both of them and accepts this one. The header selects",
        "WHICH check runs, and it is the check an implementation forgets to make: the key and the bytes are",
        "checked by code somebody wrote, the algorithm by code nobody did.",
        "WHAT IT BUYS. An accepted token is a payload the attacker wrote - any renderId, and any claim an access",
        "decision reads. With the renderId chosen, every sealed blob the attacker holds is presented at a",
        "coordinate whose binding the issuer rebuilds from that same chosen renderId, so it opens: the relabel,",
        "the cross-render lift and the unknown name in this directory are all refused by a value that is only",
        "unguessable while the envelope holding it is. This body is the least version of that - only the header",
        "moved, so an implementation that reads it answers 200 with the whole render.",
        "A CONFORMANT ISSUER answers 400 with bad_alg. The algorithm is a string comparison against a constant",
        "and it comes before the key is fetched, so the refusal costs no signature verification, no ECDH and no",
        "key-store lookup - expected.privateKeyReached is false, and a replay that can count operations should",
        "see zero of all three.",
        "NOT CONFORMANT: reading this payload at all, whatever is done with it afterwards.",
        "substitution.alg is the header this arm names. Its sibling reject-alg-substituted-hs256 names a check",
        'the issuer can genuinely run, which is the arm that survives a "none" special case.',
        "NOTHING IN THIS rawBody MOVES BETWEEN RUNS: there is no ECDSA signature in it, so the exception the",
        "other reject vectors make for the third segment does not apply here.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-alg-substituted-hs256.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.hs256Jwt,
    }),
    /** @param {any} facts */
    extra: (facts) => ({
      substitution: {
        alg: "HS256",
        macKey: facts.macKeyBase64url,
        macKeyIs:
          "publisher.signingKeys[0].publicKeyJwk as the uncompressed P-256 point, 0x04 || x || y," +
          " 65 bytes",
      },
    }),
    expected: {
      code: "bad_alg",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: the same signed resource behind a header that says",
        "HS256, MAC'd with the publisher's public key.",
        "THE ATTACK. The payload segment is the publisher's again, and the header names",
        '{"alg":"HS256","typ":"JWT","kid":...} under the publisher\'s own kid. The third segment is',
        'HMAC-SHA256 over the UTF-8 bytes of "<header>.<payload>", keyed by substitution.macKey - the public',
        "key that kid names, taken as the uncompressed P-256 point. Those bytes are published: they are in this",
        "file, and an issuer holds them because holding them is how it verifies anything at all.",
        'WHY THE SECOND ARM. An implementation can refuse "none" as a special case, since it reads like an',
        "obvious hole, and go on dispatching on the header for everything else. This token names an algorithm",
        "such an implementation can genuinely run, over a key it genuinely holds, and it verifies - HMAC does",
        "not care that its secret was published, only that both sides used the same bytes. The MAC is real; the",
        "algorithm is the lie. What the ES256 arm of reject-forged-resourcejwt is to a damaged signature, this",
        "is to a token that merely carries none.",
        "WHICH BYTES, and it matters to a replay: an implementation confusing the two key types MACs with",
        "whatever serialization of the public key it has in hand - the point, a PEM, the JWK as text. This",
        "vector uses the point and records exactly those bytes, so an implementation that keeps its key that",
        "way is caught here, and one that keeps it another way is caught by the header check that should have",
        "run before any of this. The rule covers every serialization: the algorithm comes from the issuer,",
        "never from the token.",
        "A CONFORMANT ISSUER answers 400 with bad_alg, on the header, before a key is consulted - the same",
        "refusal its sibling gets, at the same cost of nothing. expected.privateKeyReached is false.",
        "NOT CONFORMANT: verifying this MAC and reading the payload, however carefully the payload is treated",
        "afterwards.",
        "NOTHING IN THIS rawBody MOVES BETWEEN RUNS: a MAC over stable bytes is stable, so this file, like its",
        "sibling, has no segment that changes when the vectors are regenerated.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-typ-substituted.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.typSubstitutedJwt,
    }),
    extra: () => ({ substitution: { typ: SUBSTITUTED_TYP } }),
    expected: {
      code: "bad_alg",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: the publisher's own signed resource, signature and",
        `all, behind a header that says typ "${SUBSTITUTED_TYP}".`,
        `THE ATTACK. The payload and signature segments are the publisher's, byte for byte the ones in`,
        `${REJECT_BASE}.json, so the ES256 signature over the ORIGINAL signing input is in the file and the`,
        "edited header is what it no longer covers. The header in front of them was rewritten to",
        `{"alg":"ES256","typ":"${SUBSTITUTED_TYP}","kid":...}, keeping the algorithm and the kid. The blobs and`,
        "the periodKeys section are the render's own.",
        `WHY THE FORMAT FIXES ONE VALUE. ${ADMITTED_TYP} is the only typ a DCA resourceJWT carries, on both`,
        "sides: a publisher writes it and an issuer requires it. A token is a signed JSON envelope, and the",
        "typ is what says which envelope it is. An issuer that reads whatever typ arrives is an issuer another",
        "protocol can hand a token to - anything this publisher signs under this kid for any other purpose",
        "becomes a resource claim, and the renderId in it is whatever that other document happened to carry.",
        "The signature is genuine there, so nothing downstream of verification catches it.",
        "A CONFORMANT ISSUER answers 400 with bad_alg. The algorithm and the type are one rule in one order,",
        "checked by string comparison against a constant before a verification key is fetched, so the refusal",
        "costs no signature verification, no ECDH and no key-store lookup: expected.privateKeyReached is false,",
        "and a replay that can count operations should see zero of all three.",
        "NOT CONFORMANT: verifying this token, whatever is done with the claims afterwards.",
        "substitution.typ is the header this vector names, the way substitution.alg names it in the two",
        "reject-alg-substituted arms beside it.",
        "NOTHING IN THIS rawBody MOVES BETWEEN RUNS: the third segment is the base vector's recorded one, so",
        "the exception the other reject vectors make for a freshly made ECDSA signature does not apply here.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-renderid-wrong-width.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /** @param {any} request @param {any} facts */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.wrongWidthJwt,
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a correctly signed resource whose renderId is 17",
        "bytes (23 canonical unpadded base64url characters), rather than the one v1 width of 16 bytes and",
        "22 characters. The signature is valid, so this reaches the binding-shape check; it is refused before",
        "the issuer consults a private key or opens any blob. This fixture makes the exact-width rule executable",
        "in every replayer instead of leaving it only in prose.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-renderid-noncanonical.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /** @param {any} request @param {any} facts */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.noncanonicalJwt,
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a correctly signed resource whose renderId is 22",
        "base64url characters and decodes to 16 bytes, but whose final character has non-zero unused trailing",
        "bits. It therefore decodes to the same bytes as its canonical spelling, but re-encodes differently.",
        "The signature is valid, so this reaches the canonical-binding-spelling check; it is refused before",
        "the issuer consults a private key or opens any blob. This fixture makes the canonical-encoding clause",
        "executable in every replayer instead of leaving it only in prose.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-no-renderid.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /**
     * The one whole-request binding failure, and the only way to reach it is
     * a signed resource with no renderId under it. The generator holds the
     * publisher signing key and the vector carries only public halves, so
     * replaying this needs only what an issuer already holds.
     *
     * @param {any} request
     * @param {any} facts
     */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.unanchoredJwt,
    }),
    expected: {
      code: "binding_failed",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a correctly signed resource with no renderId in it.",
        "WHERE IT COMES FROM. Not from an attacker - the signature verifies, so the payload is the publisher's",
        "own words - but from a publisher implementation that has not filled the field in. The format's renderId",
        "is what every sealed blob of a render is bound to, and the binding is the only thing tying a blob to the",
        "render it came from, so a render with no renderId ships blobs with no anchor.",
        "WHY IT IS THE WHOLE REQUEST AND NOT ONE BLOB. Every other binding failure is one coordinate failing to",
        "open beside coordinates that did. This one is upstream of all of them: there is no value to build any",
        "coordinate from, so no blob in the body could be opened and there is no partial answer to give. It is",
        "checked where the rest of the integrity checks are, before the key store is consulted at all -",
        "expected.privateKeyReached is false.",
        "WHAT AN ISSUER MUST NOT DO is open the blobs under a binding it invented: a value built from an empty",
        "renderId, or a value with the renderId field left out, would be a value an attacker can reproduce",
        "across every render of that publisher, and it would open every one of them.",
        "A CONFORMANT ISSUER answers 400 with binding_failed and no key of any kind. The same rule covers a",
        "renderId that is not exactly 16 bytes, is not its own canonical 22-character unpadded base64url",
        "spelling, or carries the delimiter, which would make one field into two.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-issuedat-malformed.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /** @param {any} request @param {any} facts */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.malformedIssuedAtJwt,
    }),
    expected: {
      code: "bad_jwt",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a correctly signed resource whose issuedAt is not the",
        "one date-time format the wire admits.",
        `THE BODY. The claims are this render's own, with issuedAt written "${UNADMITTED_ISSUED_AT}" - a space`,
        "where RFC 3339 fixes T. The signature verifies, so this is the publisher's own producer rather than",
        "an attacker: a formatter that wrote a human-readable stamp, which is the one mistake this member",
        "invites.",
        "WHAT IS ADMITTED. issuedAt is an RFC 3339 date-time with the Z offset, and admitting it is admitting a",
        "FORMAT. A conformant issuer reads no validity window out of it: it does not compare issuedAt to a",
        "clock, and iat and exp beside it are not read at all. The refusal here is the shape of the member, so",
        "that a claim two implementations parse differently never reaches a policy that reads it.",
        "A CONFORMANT ISSUER answers 400 with bad_jwt, after the signature check and before any coordinate is",
        "opened: expected.privateKeyReached is false.",
        "NOT CONFORMANT: answering 200, and refusing an honest issuedAt because it is old.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-resourceid-empty.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /** @param {any} request @param {any} facts */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.emptyResourceIdJwt,
    }),
    expected: {
      code: "bad_jwt",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a correctly signed resource whose resourceId is the",
        "empty string.",
        "THE BODY. The claims are this render's own, with resourceId emptied. The signature verifies, so what",
        "produced it is the publisher: a CMS that rendered a page before its article had an id, or a template",
        "that wrote the member whether or not it had a value.",
        "WHY IT IS REFUSED RATHER THAN CARRIED. resourceId is what a policy keyed by article decides on and",
        "what a metering record is filed under. The empty string is a value every such consumer reads as one",
        "article, so every page rendered without an id shares whatever grant and whatever count the first of",
        "them established. The member is present or it is absent; it is never present and empty.",
        "A CONFORMANT ISSUER answers 400 with bad_jwt, after the signature check and before any coordinate is",
        "opened: expected.privateKeyReached is false.",
        "NOT CONFORMANT: answering 200 and handing the claims to a policy.",
        REPLAY,
      ].join(" "),
  },
  {
    file: "reject-data-not-object.json",
    needed: ["bodytext", "locked-data"],
    /** @param {[string, string][]} pairs */
    attack: (pairs) => pairs,
    /** @param {any} request @param {any} facts */
    request: async (request, facts) => ({
      ...request,
      resourceJWT: facts.unmappedDataJwt,
    }),
    expected: {
      code: "bad_jwt",
      keys: { contentKeys: [] },
      errors: {},
      privateKeyReached: false,
    },
    description: () =>
      [
        "An unlock request an issuer must refuse whole: a correctly signed resource whose data is an array.",
        "THE BODY. The claims are this render's own, with data written as [] rather than as a map. The",
        "signature verifies, and the shape is what a PHP producer emits for an array it never filled:",
        "json_encode writes [] for the empty array and {} only for an object, so a publisher whose page",
        "carried no policy input at all ships this without editing a line.",
        "WHY THE SHAPE IS CHECKED. data is the publisher's policy input, read by name: a policy asks it for",
        "date.published, for section, for whatever that deployment agreed on. An array answers every such",
        "lookup with nothing, and a policy written to read a member and grant on its absence grants here. A",
        "map with no members in it is the honest way to say there is no policy input, and it is admitted.",
        "A CONFORMANT ISSUER answers 400 with bad_jwt, after the signature check and before any coordinate is",
        "opened: expected.privateKeyReached is false.",
        "NOT CONFORMANT: reading an array as an empty map, and answering 200.",
        REPLAY,
      ].join(" "),
  },
];

/**
 * One reject vector, cut from a render this run already produced.
 *
 * The client's own `DcaRequestBuilder` builds the request, so the wire carries
 * what a conformant client emits, with one deliberate change to the one section
 * under attack. A body hand-written here would be refused for reasons the vector
 * never named.
 *
 * @param {object} definition
 * @param {string} definition.file
 * @param {string[]} definition.needed - the contentNames the client asks for
 * @param {(pairs: [string, string][], facts: any) => [string, string][]} definition.attack
 * @param {(request: any, facts: any) => Promise<any>} [definition.request] - for a
 *   definition whose attack is somewhere other than sealed.contentKeys
 * @param {(facts: any) => object} [definition.extra] - sections of the vector
 *   beyond the standard ones, for a definition whose attack needs its own
 *   material on record: the forger's public key, and `sealedUnder`, which is
 *   the value a blob the shipped sealer refuses to make was sealed under. A
 *   replayer cannot rebuild that value, because its own builder refuses the field
 *   that carries the delimiter, so the vector records it and a replay can check
 *   the blob as a real key rather than as damaged bytes
 * @param {(facts: any) => string} definition.description
 * @param {import('./vectorWorld.js').RejectExpectation} definition.expected
 * @param {{ input: any, expected: any }} base - the render it is cut from
 * @param {any} facts - what the definitions cut their attacks from
 * @returns {Promise<{ dir: string, file: string, vector: object }>}
 */
async function makeRejectVector(
  { file, needed, attack, request, extra, description, expected },
  base,
  facts,
) {
  const [issuer] = base.input.issuers;
  const built = new DcaRequestBuilder({ relayPeriodKeys: true })
    .build(new DcaData(base.expected.dcaData), issuer.issuerName, needed)
    .toObject();
  const honest = request ? await request(built, facts) : built;
  const pairs = /** @type {[string, string][]} */ (Object.entries(built.sealed.contentKeys));

  const rawBody = renderBody(honest, attack(pairs, facts));

  // The body has to be JSON, or the vector pins a parse error rather than the
  // check it names. The generator parses it here so it never writes a body it
  // broke; the replay posts the string instead.
  JSON.parse(rawBody);

  return {
    dir: fixtureDirOf(file),
    file,
    vector: {
      name: file.replace(/\.json$/, ""),
      vectorFormat: REJECT_FORMAT,
      derivedFrom: REJECT_BASE,
      description: description(facts),
      issuer: {
        issuerName: issuer.issuerName,
        keyId: issuer.keyId,
        algorithm: issuer.algorithm,
        publicKeyJwk: issuer.publicKeyJwk,
        privateKeyJwk: issuer.privateKeyJwk,
      },
      publisher: {
        origin: base.input.origin,
        // Public halves only. An issuer holds no publisher private key, so
        // only a non-issuer could check a vector that carried one.
        signingKeys: base.input.signingKeys.map((/** @type {any} */ key) => ({
          kid: key.kid,
          publicKeyJwk: key.publicKeyJwk,
        })),
      },
      ...(extra ? extra(facts) : {}),
      rawBody,
      expected,
    },
  };
}

/**
 * A P-256 public JWK as the point behind it: 0x04 || x || y, 65 bytes. An
 * alg-substituted token MACs with exactly these bytes. The confusion is between
 * the two ways one key can be used, so this works from the publisher's own key.
 *
 * @param {{ x: string, y: string }} jwk
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
 * A token with a header of its own over a payload segment already signed.
 * `sign` will not write one, since it emits ES256 and refuses every other alg in
 * both directions, so the segments are assembled here the way an attacker
 * assembles them: copy the payload, write the header, and put in the third
 * segment whatever the algorithm named there calls for.
 *
 * @param {string} alg
 * @param {string} kid - the publisher's, because the header is still selecting a key
 * @param {string} payloadSegment - the base token's, byte for byte
 * @param {Uint8Array} [macKey] - HMAC-SHA256 secret, for a header that names a MAC
 * @returns {Promise<string>}
 */
async function reHeaderedToken(alg, kid, payloadSegment, macKey) {
  const head = base64urlEncode(utf8Encode(JSON.stringify({ alg, typ: "JWT", kid })));
  const signingInput = `${head}.${payloadSegment}`;
  if (!macKey) return `${signingInput}.`;

  const key = await subtle.importKey("raw", macKey, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return `${signingInput}.${base64urlEncode(await subtle.sign("HMAC", key, utf8Encode(signingInput)))}`;
}

/**
 * A token whose header names another `typ`, over the publisher's own payload
 * and signature segments. The segments are assembled here for the reason the
 * algorithm arms are: `sign` writes one `typ` and refuses every other, in both
 * directions, so this header reaches the wire only the way an attacker puts it
 * there, rewritten in front of segments it never covered.
 *
 * @param {string} typ
 * @param {string} kid - the publisher's, because the header is still selecting a key
 * @param {string} payloadSegment - the base token's, byte for byte
 * @param {string} signature - the base token's third segment, kept so the body
 *   is byte-stable across runs and so the only edited byte is in the header
 * @returns {string}
 */
function reTypedToken(typ, kid, payloadSegment, signature) {
  const head = base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ, kid })));
  return `${head}.${payloadSegment}.${signature}`;
}

/**
 * The other spelling of one 16-byte base64url value. Sixteen bytes leave four
 * unused bits in character 22; a decoder discards them, while a canonical
 * encoder writes zero. This changes only those unused bits, so a decoder accepts
 * the spelling although it cannot be a DCA renderId.
 *
 * @param {string} canonical
 * @returns {string}
 */
function noncanonical16ByteBase64url(canonical) {
  const decoded = base64urlDecode(canonical);
  if (decoded.length !== 16 || base64urlEncode(decoded) !== canonical || canonical.length !== 22) {
    throw new Error("the base renderId must be a canonical 16-byte base64url value");
  }
  const tail = BASE64URL_ALPHABET.indexOf(canonical[canonical.length - 1]);
  if (tail < 0 || (tail & 0x0f) !== 0) {
    throw new Error("the canonical 16-byte base64url tail must leave four zero bits");
  }
  const noncanonical = `${canonical.slice(0, -1)}${BASE64URL_ALPHABET[tail | 0x01]}`;
  if (base64urlEncode(base64urlDecode(noncanonical)) === noncanonical) {
    throw new Error("the noncanonical renderId unexpectedly re-encodes to itself");
  }
  return noncanonical;
}

/**
 * What the reject definitions cut their attacks from: the base render's keys,
 * a blob from a coordinate the attacked request never asks for, a second render
 * of the same article, and a signed resource with no renderId under it.
 *
 * The second render is the same input under another seed, so its renderId,
 * content keys are different while its supplied period keys
 * and every fixed keypair remain the same. That leaves the binding as the only
 * reason a blob of one render will not open in the other.
 *
 * @param {{ input: any, expected: any }} base
 * @returns {Promise<any>}
 */
async function rejectFacts(base) {
  const [issuer] = base.input.issuers;

  const foreignInput = { ...base.input, seed: base.input.seed + 1 };
  const { dcaData: foreign } = await (await buildSealer(foreignInput)).seal();

  // The destructure below splits the resource in two: `unanchoredResource` is the
  // render's resource without the renderId, and the two hostile-publisher blobs
  // below are bound to `renderId`.
  const baseResource = resourceOf(base.expected.dcaData);
  const { renderId, ...unanchoredResource } = baseResource;
  const wrongWidthResource = {
    ...baseResource,
    renderId: base64urlEncode(new Uint8Array(17).fill(0x17)),
  };
  const noncanonicalResource = {
    ...baseResource,
    renderId: noncanonical16ByteBase64url(baseResource.renderId),
  };

  /** @type {Record<string, CryptoKey>} */
  const signingKeys = {};
  for (const key of base.input.signingKeys) {
    signingKeys[key.kid] = await importSigningPrivateKey(key.privateKeyJwk);
  }
  const publisherSigningKey = base.input.signingKeys.find(
    ({ kid }) => kid === base.input.signingKid,
  );
  if (!publisherSigningKey)
    throw new Error(`the vector has no public signing key for ${base.input.signingKid}`);
  const publisherPublicKey = await importSigningPublicKey(publisherSigningKey.publicKeyJwk);

  // The forgery: the honest resource, re-signed by the key the publisher
  // does not hold, under the publisher's own kid. The signing input is the
  // base token's, byte for byte; only the signing key differs.
  const forgedJwt = await retainRecordedSignature(
    await sign(baseResource, await importSigningPrivateKey(ATTACKER_KEY.privateKeyJwk), {
      kid: base.input.signingKid,
    }),
    recordedRequestToken("reject-forged-resourcejwt.json"),
    await importSigningPublicKey(ATTACKER_KEY.publicKeyJwk),
  );

  // The tamper: the base token's own segments, with one signed claim edited
  // between signing and presenting. A text edit on the payload segment, so
  // everything else in it, member order included, stays byte-stable and the
  // edit covers exactly one field.
  const [head, payloadSegment, signature] = base.expected.dcaData.resourceJWT.split(".");
  const originalPublished = base.input.resourceData["date.published"];
  const payloadText = utf8Decode(base64urlDecode(payloadSegment));
  const editedText = payloadText.replace(
    JSON.stringify(originalPublished),
    // One minute before the pinned clock: the freshness an age-metered
    // policy would grant.
    JSON.stringify("2025-10-23T13:59:00Z"),
  );
  if (editedText === payloadText) {
    throw new Error(
      "the tamper found nothing to edit - the payload no longer carries date.published",
    );
  }

  // The two substitutions: the base token's payload segment, unedited, behind
  // a header naming another algorithm. Nothing about the render moves, which
  // leaves the header as the whole of the attack. Neither third segment is drawn
  // from randomness, so both bodies stay byte-stable across runs.
  const macKey = uncompressedPoint(SIGNING_KEY.publicKeyJwk);

  // These two blobs come from outside the shipped sealer. Everything else in
  // the reject bodies came off the render above. The shipped sealer refuses
  // the coordinates these two sit at, and a publisher that never ran the name
  // check emits blobs without that refusal: a CMS that skipped it, a second
  // implementation of the sealer, markup written by hand. They are also the
  // only thing that tells a banning issuer apart from one that joins whatever
  // it was handed. Against a body whose delimited coordinate holds an honest
  // blob the two write the same answer: one builds no value, the other builds
  // a value nothing was sealed under, and both report an error. Against these two
  // blobs, the second implementation opens them.
  const issuerKeys = await importEcdhFixture(issuer);
  const sealedByRender = base.expected.dcaData.issuerData[issuer.issuerName].sealed;

  if (`${DELIMITED_ACCESS_GROUP}${BIND_DELIMITER}${SEALED_PERIOD}` !== RESPLIT_LABEL) {
    throw new Error(
      "the two pairs no longer join to one string, and the collision vector has no attack in it",
    );
  }

  const unbannedPeriodKey = base64urlDecode(UNBANNED_PERIOD_KEY);
  const unbannedPeriodBlob = await unbannedSeal(
    unbannedPeriodKey,
    issuerKeys.publicKey,
    issuer.algorithm,
    {
      binding: { renderId, accessGroup: DELIMITED_ACCESS_GROUP, t: SEALED_PERIOD },
      random: { bytes: () => base64urlDecode(UNBANNED_PERIOD_NONCE) },
      ephemeralKeyPair: await importEcdhFixture(
        ephemeralAt({ accessGroup: RESPLIT_ACCESS_GROUP, t: SEALED_PERIOD }),
      ),
    },
  );
  const unbannedContentBlob = await unbannedSeal(
    base64urlDecode(UNBANNED_CONTENT_KEY),
    issuerKeys.publicKey,
    issuer.algorithm,
    {
      binding: { renderId, contentName: DELIMITED_CONTENT_NAME },
      random: { bytes: () => base64urlDecode(UNBANNED_CONTENT_NONCE) },
      ephemeralKeyPair: await importEcdhFixture(ephemeralAt({ contentName: "bodytext" })),
    },
  );

  // Each shares its ephemeral point with a blob of the render, so the issuer
  // agrees one wrapping key for the pair and the nonces have to differ.
  for (const [hostile, honest] of [
    [unbannedPeriodBlob, sealedByRender.periodKeys[RESPLIT_ACCESS_GROUP][SEALED_PERIOD]],
    [unbannedContentBlob, sealedByRender.contentKeys.bodytext],
  ]) {
    if (nonceOf(hostile) === nonceOf(honest)) {
      throw new Error(
        "a hostile blob shares an ephemeral point AND a nonce with the render blob beside it",
      );
    }
  }

  // The asymmetry, checked where it is made: the period blob was sealed at one
  // pair and opens at the other for a reader that joins without the ban. The
  // vector records that key as what such an implementation hands over, so the
  // generator refuses to write the vector if the key does not come back.
  const resplitKey = await unbannedUnseal(
    unbannedPeriodBlob,
    issuerKeys.privateKey,
    issuer.algorithm,
    {
      binding: { renderId, accessGroup: RESPLIT_ACCESS_GROUP, t: RESPLIT_PERIOD },
    },
  );
  if (base64urlEncode(resplitKey) !== base64urlEncode(unbannedPeriodKey)) {
    throw new Error(
      "the blob sealed at one pair does not open at the other, so there is no collision to pin",
    );
  }

  return {
    unbanned: {
      periodBlob: unbannedPeriodBlob,
      periodKeyBase64url: base64urlEncode(unbannedPeriodKey),
      periodCoordinate: `periodKeys/${DELIMITED_ACCESS_GROUP}/${SEALED_PERIOD}`,
      periodBind: unbannedBindValue({
        renderId,
        accessGroup: DELIMITED_ACCESS_GROUP,
        t: SEALED_PERIOD,
      }),
      contentBlob: unbannedContentBlob,
      contentKeyBase64url: UNBANNED_CONTENT_KEY,
      contentCoordinate: `contentKeys/${DELIMITED_CONTENT_NAME}`,
      contentBind: unbannedBindValue({ renderId, contentName: DELIMITED_CONTENT_NAME }),
    },
    algNoneJwt: await reHeaderedToken("none", base.input.signingKid, payloadSegment),
    hs256Jwt: await reHeaderedToken("HS256", base.input.signingKid, payloadSegment, macKey),
    typSubstitutedJwt: reTypedToken(
      SUBSTITUTED_TYP,
      base.input.signingKid,
      payloadSegment,
      signature,
    ),
    macKeyBase64url: base64urlEncode(macKey),
    forgedJwt,
    tamperedJwt: `${head}.${base64urlEncode(utf8Encode(editedText))}.${signature}`,
    tamperedResource: JSON.parse(editedText),
    originalPublished,
    contentKeys: base.expected.contentKeys,
    // The blob for the item a request does not ask for, which a duplicate member
    // smuggles in.
    foreign: base.expected.dcaData.issuerData[issuer.issuerName].sealed.contentKeys["locked-data"],
    foreignRender: {
      renderId: foreign.resource.renderId,
      contentKeys: foreign.issuerData[issuer.issuerName].sealed.contentKeys,
    },
    unanchoredResource,
    wrongWidthResource,
    wrongWidthJwt: await retainRecordedSignature(
      await sign(wrongWidthResource, signingKeys[base.input.signingKid], {
        kid: base.input.signingKid,
      }),
      recordedRequestToken("reject-renderid-wrong-width.json"),
      publisherPublicKey,
    ),
    noncanonicalResource,
    noncanonicalJwt: await retainRecordedSignature(
      await sign(noncanonicalResource, signingKeys[base.input.signingKid], {
        kid: base.input.signingKid,
      }),
      recordedRequestToken("reject-renderid-noncanonical.json"),
      publisherPublicKey,
    ),
    unanchoredJwt: await retainRecordedSignature(
      await sign(unanchoredResource, signingKeys[base.input.signingKid], {
        kid: base.input.signingKid,
      }),
      recordedRequestToken("reject-no-renderid.json"),
      publisherPublicKey,
    ),
    ...(await unadmittedClaimTokens(baseResource, signingKeys[base.input.signingKid], {
      kid: base.input.signingKid,
      publicKey: publisherPublicKey,
    })),
  };
}

/**
 * The three correctly signed resources whose claims the format does not admit.
 * Each is the base render's resource with one member replaced, signed by the
 * publisher's own key, so they are refused for the member rather than for the
 * signing key. They are made together because each puts an inadmissible value
 * in a different member.
 *
 * @param {any} baseResource - the render's own signed resource
 * @param {CryptoKey} privateKey - the publisher's signing key
 * @param {{ kid: string, publicKey: CryptoKey }} publisher
 * @returns {Promise<Record<string, string>>}
 */
async function unadmittedClaimTokens(baseResource, privateKey, publisher) {
  /** @type {[string, string, any][]} */
  const arms = [
    ["malformedIssuedAtJwt", "reject-issuedat-malformed.json", { issuedAt: UNADMITTED_ISSUED_AT }],
    ["emptyResourceIdJwt", "reject-resourceid-empty.json", { resourceId: UNADMITTED_RESOURCE_ID }],
    ["unmappedDataJwt", "reject-data-not-object.json", { data: UNADMITTED_DATA }],
  ];

  /** @type {Record<string, string>} */
  const tokens = {};
  for (const [fact, file, member] of arms) {
    tokens[fact] = await retainRecordedSignature(
      await sign({ ...baseResource, ...member }, privateKey, { kid: publisher.kid }),
      recordedRequestToken(file),
      publisher.publicKey,
    );
  }
  return tokens;
}

/**
 * How the files on disk differ from the ones a run would write. A file in
 * `outputs` that is absent on disk is missing, one whose text differs differs,
 * and a vector file in an owned directory that `outputs` does not hold is left
 * over, since a writing run removes it. Sorted by path.
 *
 * @param {Map<string, string>} outputs  each path this run writes, and its text
 * @param {Iterable<string>} dirs  the directories whose vector files this run owns, each with a trailing slash
 * @returns {{ path: string, kind: "differs"|"missing"|"left over" }[]}
 */
export function driftFrom(outputs, dirs) {
  /** @type {{ path: string, kind: "differs"|"missing"|"left over" }[]} */
  const drift = [];
  for (const [path, text] of outputs) {
    if (!existsSync(path)) drift.push({ path, kind: "missing" });
    else if (readFileSync(path, "utf8") !== text) drift.push({ path, kind: "differs" });
  }
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    for (const file of vectorFilesIn(dir)) {
      if (!outputs.has(dir + file)) drift.push({ path: dir + file, kind: "left over" });
    }
  }
  return drift.sort((a, b) => (a.path < b.path ? -1 : 1));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  /** @type {{ dir: string, file: string, vector: any }[]} */
  const written = [];

  for (const definition of SEAL_DEFINITIONS) written.push(await makeVector(definition));

  for (const record of [...makeSealerFactoryRecords(), makeSealerRefusalRecord()]) {
    written.push({ dir: fixtureDirOf(record.file), ...record });
  }
  written.push(makeOpenVector());
  written.push(...makeOpenNegativeVectors());
  written.push(await makeBoundCarrierVector());
  written.push(await makeClientBoundEcdhVector());
  written.push(await makeClientBoundRsaVector());

  const base = written.find(({ vector }) => vector.name === REJECT_BASE);
  if (!base)
    throw new Error(`the reject vectors are cut from ${REJECT_BASE}, and this run did not make it`);

  const facts = await rejectFacts(base.vector);
  for (const definition of REJECT_DEFINITIONS) {
    written.push(await makeRejectVector(definition, base.vector, facts));
  }

  function phaseOf(dir) {
    if (!existsSync(dir + SET_MANIFEST)) return "devel";
    return JSON.parse(readFileSync(dir + SET_MANIFEST, "utf8")).phase ?? "devel";
  }

  const dirs = [...new Set(written.map(({ dir }) => dir))];

  // Every file this run writes, by path. The sums file moves with the bytes,
  // so a devel match means "these are the bytes the generator last wrote". Any
  // hash tool checks it afterwards, and `sh verification/vectors/check-sums.sh`,
  // run from the repository root, prints the phase beside the answer. It
  // catches what the stable refusal below cannot: a hand edit or a bad merge,
  // neither of which runs this file.
  /** @type {Map<string, string>} */
  const outputs = new Map();
  for (const { dir, file, vector } of written) {
    outputs.set(dir + file, `${JSON.stringify(vector, null, 2)}\n`);
  }
  // This run writes the RSA package manifest beside its vector, so its proof index cannot
  // drift from the schema this generator emits. It stays outside SHA256SUMS on
  // purpose; the manifest declares the set rather than payload bytes.
  outputs.set(
    RSA_OAEP_DIR + SET_MANIFEST,
    `${JSON.stringify(makeRsaOaepSetManifest(phaseOf(RSA_OAEP_DIR)), null, 2)}\n`,
  );
  // One manifest per fixture package, each over that package's members only.
  /** @type {Map<string, string>} the fixture package of each fixture directory */
  const fixturePackageOf = new Map(FIXTURE_PACKAGES.map((id) => [fixturePackageDir(id), id]));
  for (const [dir, fixturePackage] of fixturePackageOf) {
    const entries = written.filter((entry) => entry.dir === dir);
    outputs.set(
      dir + FIXTURE_MANIFEST,
      `${JSON.stringify(makeProtocolFixtureManifest(fixturePackage, entries), null, 2)}\n`,
    );
  }
  for (const dir of dirs) {
    const vectors = written
      .filter((entry) => entry.dir === dir)
      .map(({ file }) => ({
        file,
        bytes: utf8Encode(/** @type {string} */ (outputs.get(dir + file))),
      }));
    outputs.set(dir + CHECKSUM_FILE, await checksumsText(vectors));
  }

  if (process.argv.includes("--check")) {
    const drift = driftFrom(outputs, dirs);
    if (drift.length > 0) {
      console.error(
        `${drift.length} generated file${drift.length === 1 ? " differs" : "s differ"} from a fresh generation. ` +
          "Run `node js/tools/make-vectors.js` from the repository root and commit the result.",
      );
      for (const { path, kind } of drift) {
        console.error(`  ${kind}: ${path.slice(VERIFICATION_DIR.length)}`);
      }
      process.exitCode = 1;
    } else {
      console.log(`${outputs.size} generated files match a fresh generation`);
    }
  } else {
    for (const dir of dirs) {
      const fixturePackage = fixturePackageOf.get(dir);
      if (fixturePackage) {
        assertFixturePackageWritable(fixturePackage, dir);
        continue;
      }
      if (phaseOf(dir) !== "stable") continue;
      throw new Error(
        `${dir.slice(VERIFICATION_DIR.length)} is stable, and this run would overwrite it. ` +
          "Changed bytes after a freeze are a new version, not a regeneration.",
      );
    }

    for (const { dir, file } of written) {
      mkdirSync(dir, { recursive: true });
      writeFileSync(dir + file, /** @type {string} */ (outputs.get(dir + file)));
      const fixturePackage = fixturePackageOf.get(dir);
      const lifecycle = fixturePackage ? fixtureStabilityOf(fixturePackage, dir) : phaseOf(dir);
      console.log(`wrote ${(dir + file).slice(VERIFICATION_DIR.length)} [${lifecycle}]`);
    }
    const fixtureManifests = [...fixturePackageOf.keys()].map((dir) => dir + FIXTURE_MANIFEST);
    for (const path of [RSA_OAEP_DIR + SET_MANIFEST, ...fixtureManifests]) {
      writeFileSync(path, /** @type {string} */ (outputs.get(path)));
    }

    // A vector this run did not write is one nothing here produces any more.
    // Leaving it would leave a replayer running a coordinate the format no longer
    // has, and that run would keep passing. A rename is the ordinary way to get
    // one, and only the generator knows which names it still makes.
    for (const { path } of driftFrom(outputs, dirs)) {
      if (outputs.has(path)) continue;
      rmSync(path);
      console.log(
        `removed ${path.slice(VERIFICATION_DIR.length)}, which this run no longer produces`,
      );
    }

    for (const dir of dirs) {
      writeFileSync(dir + CHECKSUM_FILE, /** @type {string} */ (outputs.get(dir + CHECKSUM_FILE)));
      const hashed = written.filter((entry) => entry.dir === dir).length;
      console.log(
        `wrote ${(dir + CHECKSUM_FILE).slice(VERIFICATION_DIR.length)}` +
          ` over ${hashed} vector${hashed === 1 ? "" : "s"}`,
      );
    }
  }
}

//
// What WebCrypto will and will not do, and which primitives the core is allowed
// to need. Neither claim here is about our behaviour, and a reader has to know
// that before reading a single assertion:
//
//   - Environment pins (unwrapKey semantics). These assert what the runtime
//     does, not what our code does. They are here because the deriveKey bridge
//     in core-shared--publisher-issuer/keySealing.js exists only because of them: WebCrypto will not
//     take `{name:"ECDH"}` as an unwrap algorithm, so a shared secret has to
//     become an AES key before it can unwrap anything. If a runtime ever
//     changed these answers, the bridge would be dead weight - or worse, the
//     code would be building around a limit that had moved. They drive
//     `crypto.subtle` directly for that reason: a pin that ran through our own
//     wrappers would be pinning the wrapper. What the bridge then has to keep
//     doing across page loads is crypto-chain.test.js.
//
//   - A static scan (the primitive set). It reads core/ as text and asserts
//     which WebCrypto algorithm names appear there. It executes nothing, and it
//     is the right shape for the claim: "the issuer never needs libsodium" is a
//     statement about what the source is allowed to reach for, and a runtime
//     test can only ever show that today's path did not reach for it.
//
// Every refusal below comes with the honest path beside it, so a test that
// passed because nothing worked at all would be visible.
//
// Reading core/ needs the filesystem, which core, ports and actors never touch.
// This is a test file, so `node:fs` is at hand here the way `node:test` is.
//
// Every test that draws bytes takes a seeded byte stream of its own, from a seed of its
// own. One at module scope would make each test's nonces depend on how many
// draws the tests above it had made, so moving or skipping one would change its
// neighbours' bytes and a failing run could not be replayed on its own.
//
// Nothing here stands up a world: these tests sit underneath the actors, at the
// WebCrypto calls and the source text, so `demo/scenarios/` has nothing they need.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { encrypt, decrypt, NONCE_BYTES } from "../../core-shared/aead.js";
import { seededRandom } from "../support/keys.js";

const { subtle } = globalThis.crypto;

// The core, now split into base, role and pairwise-slice directories. The scan
// reads every .js under each declared directory, so the claim covers the whole
// reusable core and a new module is covered when it lands in one of them.
const CORE_DIRS = [
  "core-shared/",
  "core-publisher/",
  "core-issuer/",
  "core-client/",
  "core-shared--client-issuer/",
  "core-shared--client-publisher/",
  "core-shared--publisher-issuer/",
].map((dir) => fileURLToPath(new URL("../../" + dir, import.meta.url)));

/**
 * An ECDH pair with the usages a pin needs. Local rather than
 * `test-reference/support/keys.js`'s `issuerKeypair`, which hands out `deriveBits` alone: the
 * bridge below is a `deriveKey` call, and a key without that usage is refused
 * before it reaches the check under test.
 *
 * @returns {Promise<CryptoKeyPair>}
 */
function ecdhPair(usages = /** @type {KeyUsage[]} */ (["deriveBits", "deriveKey"])) {
  return /** @type {Promise<CryptoKeyPair>} */ (
    subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, usages)
  );
}

/**
 * An AES-GCM key with exactly the usages a test wants to hold it to. Generated
 * rather than derived: these tests are about what `unwrapKey` checks, and a
 * generated key reaches that check the same way a derived one does.
 *
 * @param {KeyUsage[]} usages
 * @param {boolean} [extractable]
 * @returns {Promise<CryptoKey>}
 */
function aesKey(usages, extractable = false) {
  return /** @type {Promise<CryptoKey>} */ (
    subtle.generateKey({ name: "AES-GCM", length: 256 }, extractable, usages)
  );
}

/**
 * A refusal from the runtime rather than from our code, so it is asserted on
 * the DOMException name: `test-lib/helpers/refuses.js` reads the `code` our own errors
 * carry, and a WebCrypto rejection has none.
 *
 * @param {() => Promise<unknown>} run
 * @param {string} name - the DOMException name the spec calls for
 */
function rejectsWithDomName(run, name) {
  return assert.rejects(run, (/** @type {any} */ err) => {
    assert.equal(err.name, name, `expected ${name}, got ${err.name}: ${err.message}`);
    return true;
  });
}

test("environment pin: client private keys generated non-extractable cannot be exported", async () => {
  for (const [label, algorithm, usages] of [
    ["ECDH-P256", { name: "ECDH", namedCurve: "P-256" }, ["deriveKey"]],
    [
      "RSA-OAEP",
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      ["unwrapKey"],
    ],
  ]) {
    const pair = /** @type {CryptoKeyPair} */ (
      await subtle.generateKey(
        /** @type {any} */ (algorithm),
        false,
        /** @type {KeyUsage[]} */ (usages),
      )
    );
    assert.equal(pair.privateKey.extractable, false, `${label} private key stays non-extractable`);
    for (const format of ["pkcs8", "jwk"]) {
      await assert.rejects(
        () => subtle.exportKey(/** @type {any} */ (format), pair.privateKey),
        `${label} private key refuses ${format} export`,
      );
    }
  }
});

describe("Environment pins: what unwrapKey checks, and what it refuses", () => {
  // W3C WebCrypto Level 2, unwrapKey: "If the [[usages]] internal slot of key
  // does not contain an entry that is 'unwrapKey', then throw an
  // InvalidAccessError." No check on extractable. MDN's unwrapKey algorithm list
  // is RSA-OAEP, AES-CTR, AES-CBC, AES-GCM, AES-KW - ECDH is not on it.

  test("environment pin: unwrapKey works with an unwrapping key whose own bytes are unreadable", async () => {
    const random = seededRandom(41);

    // The whole client-bound design rests on this line. The transport key is
    // derived non-extractable and is never exported; if unwrapKey demanded an
    // extractable unwrapping key, the key material would have to pass through
    // JavaScript and there would be nothing left to protect.
    const wrapping = await aesKey(["wrapKey", "unwrapKey"]);
    assert.equal(wrapping.extractable, false, "the unwrapping key cannot be read out");

    const nonce = random.bytes(NONCE_BYTES);
    const payload = await aesKey(["encrypt", "decrypt"], true);
    const blob = await subtle.wrapKey("raw", payload, wrapping, { name: "AES-GCM", iv: nonce });

    const unwrapped = await subtle.unwrapKey(
      "raw",
      blob,
      wrapping,
      { name: "AES-GCM", iv: nonce },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );

    // What came out is a key, and it is the key that went in: the same
    // ciphertext opens under both.
    assert.equal(unwrapped.algorithm.name, "AES-GCM");
    assert.equal(unwrapped.extractable, false);
    const message = new Uint8Array([1, 2, 3, 4]);
    const sealed = await encrypt(payload, nonce, message, undefined, 32);
    assert.deepEqual(await decrypt(unwrapped, nonce, sealed, undefined, 32), message);
  });

  test("environment pin: unwrapKey throws InvalidAccessError when the key lacks the unwrapKey usage", async () => {
    const random = seededRandom(42);
    const nonce = random.bytes(NONCE_BYTES);
    const payload = await aesKey(["decrypt"], true);

    // One key with the usage, one without, and nothing else different between
    // them - so the refusal below can only be the usage check.
    const allowed = await aesKey(["wrapKey", "unwrapKey"]);
    const blob = await subtle.wrapKey("raw", payload, allowed, { name: "AES-GCM", iv: nonce });

    for (const usages of [["encrypt", "decrypt"], ["decrypt"], ["wrapKey"]]) {
      const refused = await aesKey(/** @type {KeyUsage[]} */ (usages));
      await rejectsWithDomName(
        () =>
          subtle.unwrapKey(
            "raw",
            blob,
            refused,
            { name: "AES-GCM", iv: nonce },
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"],
          ),
        "InvalidAccessError",
      );
    }

    // The control: the identical call against the key that carries the usage.
    // Without it, a runtime that refused every unwrapKey call would pass the
    // loop above.
    const unwrapped = await subtle.unwrapKey(
      "raw",
      blob,
      allowed,
      { name: "AES-GCM", iv: nonce },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    assert.equal(unwrapped.algorithm.name, "AES-GCM");

    // And the usage check is on the unwrapping key, not on the material: the
    // key that comes out is asked for usages of its own and gets exactly those.
    assert.deepEqual(unwrapped.usages, ["decrypt"]);
  });

  test('environment pin: unwrapKey refuses {name:"ECDH"}, which is what forces the deriveKey bridge', async () => {
    const random = seededRandom(43);

    // Two static pairs, one agreement. If ECDH were an unwrap algorithm, an
    // issuer could wrap straight to the client's public key and the client
    // could unwrap straight with its private one - no AES key in between, and
    // core-shared--publisher-issuer/keySealing.js would have no `agreeTransport`.
    const client = await ecdhPair();
    const issuer = await ecdhPair();
    const nonce = random.bytes(NONCE_BYTES);

    const payload = await aesKey(["encrypt", "decrypt"], true);
    const scratch = await aesKey(["wrapKey", "unwrapKey"]);
    const blob = await subtle.wrapKey("raw", payload, scratch, { name: "AES-GCM", iv: nonce });

    await rejectsWithDomName(
      () =>
        subtle.unwrapKey(
          "raw",
          blob,
          client.privateKey,
          { name: "ECDH", public: issuer.publicKey },
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"],
        ),
      "NotSupportedError",
    );

    // The bridge, and the reason it is shaped the way it is: the same ECDH
    // agreement run through deriveKey lands on an AES-GCM key, and that key
    // unwraps. Both ends derive it independently - this is the two-sided
    // version of what clientTransport and transportKeyFor do.
    const issuerSide = await subtle.deriveKey(
      { name: "ECDH", public: client.publicKey },
      issuer.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey"],
    );
    const clientSide = await subtle.deriveKey(
      { name: "ECDH", public: issuer.publicKey },
      client.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["unwrapKey"],
    );

    const bridged = await subtle.wrapKey("raw", payload, issuerSide, {
      name: "AES-GCM",
      iv: nonce,
    });
    const unwrapped = await subtle.unwrapKey(
      "raw",
      bridged,
      clientSide,
      { name: "AES-GCM", iv: nonce },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );

    const message = new Uint8Array([9, 9, 9]);
    assert.deepEqual(
      await decrypt(
        unwrapped,
        nonce,
        await encrypt(payload, nonce, message, undefined, 32),
        undefined,
        32,
      ),
      message,
      "the bridged key carried the same material across",
    );
  });
});

describe("The primitive set core/ is allowed to need", () => {
  // The issuer's crypto has to run in constrained serverless/edge V8, where
  // ECDH P-256 and AES-GCM are native and libsodium's X25519-sealedbox is not
  // present at all. This scans the source text of core/ rather than tracing an
  // execution: the claim is about what the code is allowed to reach for, and a
  // run can only ever show which branch it took today. It reads every .js in core/,
  // so a new module is covered the moment it lands.

  /** @returns {{ file: string, source: string }[]} */
  function coreSources() {
    return CORE_DIRS.flatMap((dir) =>
      readdirSync(dir)
        .filter((file) => file.endsWith(".js"))
        .map((file) => ({ file, source: readFileSync(dir + file, "utf8") })),
    ).sort((a, b) => a.file.localeCompare(b.file));
  }

  /**
   * The WebCrypto registry, whole, plus the named curves. Matching against the
   * registry rather than against a wish-list lets the scan report which members
   * of the full set the core actually names.
   */
  const WEBCRYPTO_NAMES = new Set([
    "RSASSA-PKCS1-v1_5",
    "RSA-PSS",
    "RSA-OAEP",
    "ECDSA",
    "ECDH",
    "Ed25519",
    "X25519",
    "AES-CTR",
    "AES-CBC",
    "AES-GCM",
    "AES-KW",
    "HMAC",
    "HKDF",
    "PBKDF2",
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "P-256",
    "P-384",
    "P-521",
  ]);

  /**
   * What an edge V8 runtime has, and nothing beyond it. Two members are wider
   * than the entry's "ECDH P-256 and AES-GCM" and are here deliberately: RSA-OAEP
   * is the spec's second seal carrier, and ECDSA is the publisher's envelope
   * signature rather than anything on the issuer's unseal path. Both are as
   * native in edge V8 as ECDH is, so neither moves the deployability bar the way
   * X25519 would. SHA-256 is the OAEP digest and the envelope signature's hash.
   * No derivation primitive is here: the sealed envelope uses the agreed
   * x-coordinate as the AES key, and the constructions that do derive live in
   * extensions rather than in core.
   */
  const ALLOWED = new Set(["ECDH", "P-256", "AES-GCM", "SHA-256", "ECDSA", "RSA-OAEP"]);

  test("core names only the primitives a constrained edge V8 runtime already has", async () => {
    /** @type {Map<string, string[]>} */
    const found = new Map();

    for (const { file, source } of coreSources()) {
      // String literals only. An algorithm name reaches WebCrypto as a
      // string; prose about SHA-1 in a comment is a warning to a reader, not
      // a call, and scanning it would make the check unrunnable.
      for (const match of source.matchAll(/'([^'\\\n]*)'|"([^"\\\n]*)"/g)) {
        const literal = match[1] ?? match[2];
        if (!WEBCRYPTO_NAMES.has(literal)) continue;
        found.set(literal, [...new Set([...(found.get(literal) ?? []), file])]);
      }
    }

    // Snapshot, so an addition has to be argued rather than absorbed.
    assert.deepEqual(
      [...found.keys()].sort(),
      ["AES-GCM", "ECDH", "ECDSA", "P-256", "RSA-OAEP", "SHA-256"],
      "the whole set of WebCrypto names the core reaches for",
    );

    for (const [name, files] of found) {
      assert.ok(
        ALLOWED.has(name),
        `core/${files.join(", ")} names ${name}, which is outside the primitive set`,
      );
    }

    // The named exclusions, called out one by one: each is a WebCrypto member
    // an implementation could plausibly have picked, and each would move the
    // deployability bar. Ed25519 and X25519 are the sharp ones - both are
    // WebCrypto Level 2 additions that edge runtimes are still catching up on,
    // and X25519 is the sealedbox construction's curve. HKDF is here because
    // the envelope applies no KDF at all, so a core that named one would be a
    // second construction arriving quietly.
    for (const excluded of [
      "Ed25519",
      "X25519",
      "HKDF",
      "AES-KW",
      "AES-CBC",
      "AES-CTR",
      "RSA-PSS",
      "SHA-1",
      "P-384",
      "P-521",
    ]) {
      assert.equal(found.has(excluded), false, `${excluded} has no business in the core`);
    }

    // The one curve and the one hash: "ECDH P-256" is a narrower claim than
    // "ECDH", and the scan should be able to tell them apart.
    assert.deepEqual(
      [...found.keys()].filter((name) => name.startsWith("P-")),
      ["P-256"],
    );
    assert.deepEqual(
      [...found.keys()].filter((name) => name.startsWith("SHA-")),
      ["SHA-256"],
    );
  });

  test("core reaches for no library at all, and libsodium is nowhere in it", async () => {
    for (const { file, source } of coreSources()) {
      // Every import is a relative path inside the core: a module in its own
      // role or pairwise directory (`./Name.js`) or another declared core
      // slice (`../core-*/Name.js`), and nothing else. A bare
      // specifier is how libsodium would arrive, so the absence of one is the
      // strongest form of the claim: there is no dependency to be unavailable
      // on an edge runtime, because there is no dependency.
      for (const match of source.matchAll(/^\s*import\b[^'"]*['"]([^'"]+)['"]/gm)) {
        assert.match(
          match[1],
          /^(\.\/|\.\.\/core-[A-Za-z-]+\/)[A-Za-z]+\.js$/,
          `${file} imports ${match[1]}`,
        );
      }

      // The vocabulary, over the whole text including comments this time: a
      // core that had X25519-sealedbox as a plan, a TODO or a half-landed
      // branch would say so somewhere, and this is the entry that says it
      // never becomes one quietly.
      assert.doesNotMatch(
        source,
        /sodium|nacl|x25519|curve25519|ed25519|sealedbox|secretbox|chacha|poly1305/i,
        `core/${file} mentions a primitive outside WebCrypto`,
      );
    }
  });
});

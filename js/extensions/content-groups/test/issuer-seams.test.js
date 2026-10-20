// The base issuer's generic seams, exercised with fake extension parts: request
// bounds that run during admission, before the signature is verified; extension
// coordinates in place of a named section; and response section sources that
// receive verified claims and an auxiliary opener but never the private key.
import test from "node:test";
import assert from "node:assert/strict";
import { createIssuerCore } from "../../../integration-issuer/createIssuerCore.js";
import { IssuerProcessor } from "../../../core-issuer/IssuerProcessor.js";
import { sign } from "../../../core-shared--publisher-issuer/jwt.js";
import { seal as sealKey } from "../../../core-shared--publisher-issuer/keySealing.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";
import { encrypt } from "../../../core-shared/aead.js";
import { deriveAesGcmKey, generateEcdhKeyPair } from "../../../core-shared/cryptoProvider.js";

const subtle = globalThis.crypto.subtle;
const ORIGIN = "https://news.example";
const RENDER_ID = "AAECAwQFBgcICQoLDA0ODw";
const random = {
  bytes: (/** @type {number} */ n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
};

async function world() {
  const signing = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const issuer = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const resourceJWT = await sign(
    {
      renderId: RENDER_ID,
      origin: ORIGIN,
      issuedAt: "2026-10-14T12:20:00Z",
      resourceId: "story1",
      data: {},
      fakeClaim: { bodytext: "c1" },
    },
    signing.privateKey,
    { kid: "p1" },
  );
  let verifierReads = 0;
  const registration = {
    kid: "p1",
    get publicKey() {
      verifierReads++;
      return signing.publicKey;
    },
    openingKeys: { get: () => ({ algorithm: "ecdh-p256", privateKey: issuer.privateKey }) },
  };
  const sealedContentKey = await sealKey(
    new Uint8Array(16).fill(7),
    issuer.publicKey,
    "ecdh-p256",
    {
      random,
      binding: { renderId: RENDER_ID, contentName: "purchase" },
    },
  );
  return {
    issuer,
    resourceJWT,
    registration,
    sealedContentKey,
    verifierReads: () => verifierReads,
  };
}

/** @param {any} w @param {Record<string, unknown>} [extra] @param {Record<string, string>} [contentKeys] */
function requestText(w, extra = {}, contentKeys = {}) {
  return JSON.stringify({
    version: "1",
    issuerName: "issuerA",
    keyId: "a1",
    resourceJWT: w.resourceJWT,
    sealed: { contentKeys },
    ...extra,
  });
}

/** An envelope that the fake opener below opens: a raw-x ECDH AES-GCM seal. */
async function fakeEnvelope(/** @type {CryptoKey} */ publicKey, /** @type {Uint8Array} */ aad) {
  const ephemeral = await generateEcdhKeyPair("P-256");
  const point = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const key = await deriveAesGcmKey(publicKey, ephemeral.privateKey);
  const nonce = new Uint8Array(12);
  const body = await encrypt(key, nonce, new Uint8Array(32).fill(9), aad, 32);
  return base64urlEncode(new Uint8Array([...point, ...body]));
}

/** @type {(sealed: unknown, privateKey: CryptoKey, aad: Uint8Array) => Promise<Uint8Array>} */
async function fakeOpener(sealed, privateKey, aad) {
  const bytes = Buffer.from(/** @type {string} */ (sealed), "base64url");
  const point = await subtle.importKey(
    "raw",
    bytes.subarray(0, 65),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const key = await deriveAesGcmKey(point, privateKey);
  const { decrypt } = await import("../../../core-shared/aead.js");
  return decrypt(key, new Uint8Array(12), bytes.subarray(65), aad, 32);
}

/** A fake section source; `seen` records what it was handed. */
/** The fake source's one key-bearing section, declared for client-bound wrapping. */
const FAKE_SECTIONS = [{ path: ["fakeSection"], depth: 1, keyKind: "contentKey" }];

function fakeSource(/** @type {any[]} */ seen, overrides = {}) {
  return {
    name: "fake",
    members: ["fakeSection", "periodGeometry"],
    // Keyed by base procedure: the engine picks the procedure, the source
    // brings only its payload and AAD contract.
    envelopeOpeners: { "ecdh-p256": fakeOpener },
    presented: (/** @type {any} */ request) => Object.hasOwn(request.toObject(), "fakeAsk"),
    async respond(/** @type {any} */ unlock) {
      seen.push(unlock);
      const ask = unlock.request.toObject().fakeAsk;
      if (ask.refuse) throw dcaError("binding_failed", "fake refusal");
      if (ask.deny) return {};
      const opened = await unlock.openAuxiliary(ask.envelope, {
        aad: utf8Encode("fake-aad"),
        ...(ask.algorithm === undefined ? {} : { algorithm: ask.algorithm }),
      });
      return {
        fakeSection: { opened: "bytes" in opened ? opened.bytes.length : opened.error.error },
        periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
      };
    },
    ...overrides,
  };
}

const allowAll = {
  decide: (/** @type {any} */ _c, /** @type {any} */ requested) => ({
    contentNames: requested.contentNames,
  }),
};
const denyAll = { decide: () => ({}) };

/** @param {any} source @param {any} [policy] @param {any} [extra] */
function issuerWith(source, policy = allowAll, extra = {}) {
  return createIssuerCore(
    { operatingIssuerNames: ["issuerA"], accessPolicy: policy, ...extra },
    {
      name: "fake",
      responseSectionSource: source,
      responseSections: FAKE_SECTIONS,
      requestBounds: [
        (/** @type {any} */ request) => {
          if (request.toObject().fakeAsk?.tooMany) throw dcaError("too_many_entries", "fake bound");
        },
      ],
    },
  );
}

test("a request bound refuses during admission, before the signature verifier runs", async () => {
  const w = await world();
  const seen = /** @type {any[]} */ ([]);
  const { endpoint } = issuerWith(fakeSource(seen));
  const refused = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { tooMany: true } }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(refused.code, "too_many_entries");
  assert.equal(w.verifierReads(), 0);
  assert.equal(seen.length, 0);

  // Positive control: the same request under the bound verifies and answers.
  const envelope = await fakeEnvelope(w.issuer.publicKey, utf8Encode("fake-aad"));
  const answered = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope } }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(answered.code, undefined);
  assert.ok(w.verifierReads() > 0);
});

test("a bound that throws a non-request code is a server fault, not a refusal code", () => {
  const engine = {
    checkOperatingIssuerName() {},
    unlock: async () => ({ contentKeys: {}, errors: {} }),
  };
  const processor = new IssuerProcessor(/** @type {any} */ (engine), {
    requestBounds: [
      () => {
        throw new Error("bug");
      },
    ],
  });
  assert.throws(
    () =>
      processor.admit(
        JSON.stringify({
          version: "1",
          issuerName: "issuerA",
          keyId: "a1",
          sealed: { contentKeys: { a: "x" } },
        }),
      ),
    /bug/,
  );
});

test("an extension coordinate admits a request with no base coordinate; without it admission refuses", async () => {
  const w = await world();
  const text = requestText(w, { fakeAsk: {} });
  const engine = {
    checkOperatingIssuerName() {},
    unlock: async () => ({ contentKeys: {}, errors: {} }),
  };
  const plain = new IssuerProcessor(/** @type {any} */ (engine), { selectedExtensions: ["fake"] });
  assert.deepEqual(plain.admit(text), { kind: "failure", code: "binding_failed" });
  const selected = new IssuerProcessor(/** @type {any} */ (engine), {
    selectedExtensions: ["fake"],
    extensionCoordinates: {
      fake: (/** @type {any} */ request) => Object.hasOwn(request.toObject(), "fakeAsk"),
    },
  });
  assert.equal(selected.admit(text).kind, "admitted");
  assert.throws(
    () =>
      new IssuerProcessor(/** @type {any} */ (engine), {
        extensionCoordinates: { fake: () => true },
      }),
    /selected/,
  );
});

test("a contribution's source presence is its admission coordinate unless it names another", async () => {
  const w = await world();
  const envelope = await fakeEnvelope(w.issuer.publicKey, utf8Encode("fake-aad"));
  // The request carries only the source's member, no base coordinate.
  const text = requestText(w, { fakeAsk: { envelope } });
  const config = { operatingIssuerNames: ["issuerA"], accessPolicy: allowAll };
  const byDefault = createIssuerCore(config, {
    name: "fake",
    responseSectionSource: fakeSource([]),
    responseSections: FAKE_SECTIONS,
  });
  const { response } = await byDefault.endpoint.handleDocument(
    text,
    /** @type {any} */ (w.registration),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(/** @type {any} */ (response.body).fakeSection, { opened: 32 });
  // An input-only reading that differs replaces the default.
  const overridden = createIssuerCore(config, {
    name: "fake",
    responseSectionSource: fakeSource([]),
    responseSections: FAKE_SECTIONS,
    extensionCoordinate: () => false,
  });
  const refused = await overridden.endpoint.handleDocument(
    text,
    /** @type {any} */ (w.registration),
  );
  assert.equal(refused.code, "binding_failed");
});

test("a section source gets verified frozen claims and an opener, never the private key", async () => {
  const w = await world();
  const seen = /** @type {any[]} */ ([]);
  const { endpoint } = issuerWith(fakeSource(seen));
  const envelope = await fakeEnvelope(w.issuer.publicKey, utf8Encode("fake-aad"));
  const { response } = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope } }, { purchase: w.sealedContentKey }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(response.status, 200);
  const body = /** @type {any} */ (response.body);
  assert.deepEqual(Object.keys(body), ["keys", "fakeSection", "periodGeometry"]);
  assert.deepEqual(body.fakeSection, { opened: 32 });
  assert.equal(body.keys.contentKeys.purchase, base64urlEncode(new Uint8Array(16).fill(7)));

  const [unlock] = seen;
  assert.deepEqual(Object.keys(unlock).sort(), [
    "claims",
    "invocation",
    "openAuxiliary",
    "policyInput",
    "request",
  ]);
  assert.deepEqual(unlock.claims.fakeClaim, { bodytext: "c1" });
  assert.equal(unlock.claims.renderId, RENDER_ID);
  assert.ok(Object.isFrozen(unlock.claims) && Object.isFrozen(unlock.claims.fakeClaim));
  assert.deepEqual(unlock.policyInput.publisher, { origin: ORIGIN });
  const text = JSON.stringify(unlock, (_key, value) =>
    value instanceof CryptoKey ? "CryptoKey" : value,
  );
  assert.ok(!text.includes("CryptoKey"));

  // A tampered envelope reports an unopened value, not bytes.
  const broken = envelope.slice(0, -2) + (envelope.endsWith("AA") ? "AB" : "AA");
  const { response: failed } = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope: broken } }),
    /** @type {any} */ (w.registration),
  );
  assert.deepEqual(/** @type {any} */ (failed.body).fakeSection, { opened: "unseal_failed" });
});

test("the engine selects the envelope procedure from the trusted key entry; a source cannot name one", async () => {
  const w = await world();
  const envelope = await fakeEnvelope(w.issuer.publicKey, utf8Encode("fake-aad"));
  let opens = 0;
  const source = fakeSource([], {
    envelopeOpeners: {
      "ecdh-p256": async (/** @type {any[]} */ ...args) => {
        opens++;
        return fakeOpener(...args);
      },
    },
  });
  const { endpoint } = issuerWith(source);

  // A source that names a procedure is a server fault, whatever it names.
  const named = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope, algorithm: "ecdh-p256" } }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(named.response.status, 500);
  assert.equal(opens, 0);

  // Under an entry whose procedure the source brings no opener for, nothing
  // opens and the source's opener never runs.
  const rsaEntry = {
    kid: "p1",
    publicKey: w.registration.publicKey,
    openingKeys: { get: () => ({ algorithm: "rsa-oaep", privateKey: w.issuer.privateKey }) },
  };
  const other = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope } }),
    /** @type {any} */ (rsaEntry),
  );
  assert.equal(other.response.status, 200);
  assert.deepEqual(/** @type {any} */ (other.response.body).fakeSection, {
    opened: "unseal_failed",
  });
  assert.equal(opens, 0);

  // The same source under the ecdh-p256 entry opens.
  const opened = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope } }),
    /** @type {any} */ (w.registration),
  );
  assert.deepEqual(/** @type {any} */ (opened.response.body).fakeSection, { opened: 32 });
  assert.equal(opens, 1);
});

test("a source refusal withholds the whole answer, base keys included", async () => {
  const w = await world();
  const { endpoint } = issuerWith(fakeSource([]));
  const result = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { refuse: true } }, { purchase: w.sealedContentKey }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(result.code, "binding_failed");
});

test("a base denial is no whole-request denial while a source answers; nothing at all is denied", async () => {
  const w = await world();
  const envelope = await fakeEnvelope(w.issuer.publicKey, utf8Encode("fake-aad"));
  const { endpoint } = issuerWith(fakeSource([]), denyAll);
  const partial = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { envelope } }, { purchase: w.sealedContentKey }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(partial.response.status, 200);
  assert.deepEqual(/** @type {any} */ (partial.response.body).keys, { contentKeys: {} });
  const denied = await endpoint.handleDocument(
    requestText(w, { fakeAsk: { deny: true } }, { purchase: w.sealedContentKey }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(denied.code, "denied");
});

/** A second source that writes only the shared geometry, as given. */
function geometrySource(/** @type {any} */ periodGeometry) {
  return {
    name: "fake2",
    members: ["periodGeometry"],
    presented: (/** @type {any} */ request) => Object.hasOwn(request.toObject(), "fakeAsk"),
    respond: async () => ({ periodGeometry }),
  };
}

test("two sources agree on periodGeometry by field, not by member order", async () => {
  const w = await world();
  const envelope = await fakeEnvelope(w.issuer.publicKey, utf8Encode("fake-aad"));
  for (const [geometry, agrees] of /** @type {[any, boolean][]} */ ([
    [{ periodMinutes: 60, chainsPerDay: 2 }, true],
    [{ chainsPerDay: 2, periodMinutes: 30 }, false],
    [{ chainsPerDay: 4, periodMinutes: 60 }, false],
    [{ periodMinutes: 60 }, false],
    [{ chainsPerDay: 2, periodMinutes: 60, extra: 1 }, false],
  ])) {
    const source = geometrySource(geometry);
    const { endpoint } = createIssuerCore(
      { operatingIssuerNames: ["issuerA"], accessPolicy: allowAll },
      { name: "fake", responseSectionSource: fakeSource([]), responseSections: FAKE_SECTIONS },
      { name: "fake2", responseSectionSource: source },
    );
    const result = await endpoint.handleDocument(
      requestText(w, { fakeAsk: { envelope } }, { purchase: w.sealedContentKey }),
      /** @type {any} */ (w.registration),
    );
    const label = JSON.stringify(geometry);
    if (agrees) {
      assert.equal(result.response.status, 200, label);
      assert.deepEqual(/** @type {any} */ (result.response.body).periodGeometry, {
        chainsPerDay: 2,
        periodMinutes: 60,
      });
    } else assert.notEqual(result.response.status, 200, label);
  }
});

test("a source that is not presented is not asked", async () => {
  const w = await world();
  const seen = /** @type {any[]} */ ([]);
  const { endpoint } = issuerWith(fakeSource(seen));
  const result = await endpoint.handleDocument(
    requestText(w, {}, { purchase: w.sealedContentKey }),
    /** @type {any} */ (w.registration),
  );
  assert.equal(result.response.status, 200);
  assert.deepEqual(Object.keys(/** @type {any} */ (result.response.body)), ["keys"]);
  assert.equal(seen.length, 0);
});

test("section declarations are checked when the issuer is built", () => {
  for (const [members, pattern] of /** @type {[string[], RegExp][]} */ ([
    [["keys"], /keys/],
    [["errors"], /errors/],
    [[], /members/],
  ])) {
    assert.throws(() => issuerWith(fakeSource([], { members })), pattern);
  }
  assert.throws(
    () =>
      createIssuerCore(
        { operatingIssuerNames: ["issuerA"], accessPolicy: allowAll },
        { name: "one", responseSectionSource: fakeSource([]), responseSections: FAKE_SECTIONS },
        {
          name: "two",
          responseSectionSource: fakeSource([], { name: "fake2", members: ["fakeSection"] }),
        },
      ),
    /fakeSection/,
  );
  const undeclared = fakeSource([], {
    respond: async () => ({ other: {} }),
  });
  return (async () => {
    const w = await world();
    const { endpoint } = issuerWith(undeclared);
    const result = await endpoint.handleDocument(
      requestText(w, { fakeAsk: {} }),
      /** @type {any} */ (w.registration),
    );
    assert.equal(result.response.status, 500);
  })();
});

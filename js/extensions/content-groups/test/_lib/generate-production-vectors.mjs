// Writes ../fixtures/production.vectors.json: one seed envelope per content
// name, one complete publication, the request the composed client sends for it
// and the issuer's direct response, all under the production content-groups
// names.
//
// It imports no code from this extension and no sibling extension, so the
// fixture checks the implementation instead of repeating it. HKDF, SHA-256,
// P-256 ECDH, ES256 and AES-GCM come from node:crypto. The F transcript, the
// seed and item-pad derivations, the content AAD, the 113-byte envelope layout,
// the stock chain-key Root/Step/Leaf and every wire object are written out
// here from the specifications:
//   docs/spec-profile--content-groups.md     seed, seed AAD, item pad, wire
//   docs/spec-profile--chain-keys.md         Sections 6.3-6.5 and 7.3: Root/Step/Leaf
//   docs/spec--content-protection.md         Section 3.2: the content AAD
// Before it writes anything, the run proves its Root/Step/Leaf against the
// published stock vectors and its seed, envelope, pad and connector fixed anchors,
// and throws on the first difference.
//
// ECDSA signatures are randomized, so the resourceJWT carries one stored
// signature. A normal run verifies it and fails when the signing input changed;
// `--resign` signs the new input once and prints the value to store below.
//
// Run from js/:
//   node extensions/content-groups/test/_lib/generate-production-vectors.mjs
import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign,
  verify,
} from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

/** A fixed P-256 scalar, stated by the label it hashes. */
const scalar = (/** @type {string} */ label) =>
  createHash("sha256").update(label, "utf8").digest("hex");

const W12 = "261014T1200";
const T15 = "261014T1500";
const T18 = "261014T1800";

const inputs = {
  origin: "https://news.example",
  retainedSecretHex: Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("hex"),
  periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
  // 15:05 renders at period T1500 inside the window that starts at T1200.
  issuedAt: "2026-10-14T15:05:00.000Z",
  renderPeriod: T15,
  windowStart: W12,
  renderId: Buffer.from(Array.from({ length: 16 }, (_, i) => i)).toString("base64url"),
  resourceId: "story1",
  publisherKid: "publisher-k1",
  publisherSigningScalarHex: scalar("dca production vector: publisher signing key"),
  issuerName: "issuerA",
  issuerKeyId: "a1",
  issuerPrivateScalarHex: scalar("dca production vector: issuer opening key"),
  items: {
    bodytext: {
      contentType: "text/plain",
      contentKeyHex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
      groups: ["politics", "sports"],
      plaintext: "body text",
    },
    headline: {
      contentType: "text/plain",
      contentKeyHex: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
      groups: ["politics"],
      plaintext: "head line",
    },
    shoppingAd: {
      contentType: "text/plain",
      contentKeyHex: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
      groups: ["shopping"],
      plaintext: "buy now",
    },
  },
  // One seed envelope per content name, each with its own ephemeral key. The
  // nonce is twelve implicit zero bytes, so no envelope may share a key.
  envelopes: {
    bodytext: {
      ephemeralPrivateScalarHex: scalar("dca production vector: ephemeral key for bodytext"),
    },
    headline: {
      ephemeralPrivateScalarHex: scalar("dca production vector: ephemeral key for headline"),
    },
    shoppingAd: {
      ephemeralPrivateScalarHex: scalar("dca production vector: ephemeral key for shoppingAd"),
    },
  },
  // The client's trusted local narrowing. Only the builder relays the connector.
  narrowing: {
    requestedContentGroups: { bodytext: ["politics"], headline: ["politics"] },
    requestedContentKeys: { shoppingAd: "shopping" },
  },
  // The issuer policy's grants: one of each kind.
  grants: [
    { kind: "chain", contentName: "bodytext", group: "politics", windowStart: W12, cutoffT: T18 },
    { kind: "period", contentName: "headline", group: "politics", t: T15 },
    { kind: "item", contentName: "shoppingAd" },
  ],
};
/** ES256 over the resourceJWT signing input, made once with `--resign`. */
const STORED_SIGNATURE =
  "SF5CgH42d2O_4YAVn7OHBPFedUowNbS7bLdnuYrAvT17PA25wbLNH5EaWN5JBgb6I8AdQyseSb9aH3wh8RLjoQ";

/** Fail the run loudly; nothing is written. */
const check = (/** @type {boolean} */ ok, /** @type {string} */ what) => {
  if (!ok) throw new Error(`generate-production-vectors: ${what}`);
};
const b64u = (/** @type {Uint8Array|string} */ bytes) => Buffer.from(bytes).toString("base64url");
const unb64u = (/** @type {string} */ text) => Buffer.from(text, "base64url");
const hexOf = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("hex");
const jsonBytes = (/** @type {unknown} */ value) =>
  Buffer.byteLength(JSON.stringify(value), "utf8");

/** F: JSON array punctuation, literal admitted ASCII strings, shortest nonnegative integers. */
const F = (/** @type {(string|number)[]} */ parts) =>
  Buffer.from(
    `[${parts.map((p) => (typeof p === "number" ? String(p) : `"${p}"`)).join(",")}]`,
    "ascii",
  );
/** HKDF-SHA256; the stock chain-key construction passes an empty salt. */
const hkdf = (
  /** @type {Uint8Array} */ ikm,
  /** @type {Uint8Array} */ salt,
  /** @type {Uint8Array} */ info,
  /** @type {number} */ length,
) => Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
const ascii = (/** @type {string} */ text) => Buffer.from(text, "ascii");
/** AES-GCM as DCA writes it: ciphertext, then the 16-byte tag. */
const gcm = (
  /** @type {Buffer} */ key,
  /** @type {Buffer} */ nonce,
  /** @type {Buffer} */ plaintext,
  /** @type {Buffer} */ aad,
) => {
  const cipher = createCipheriv(`aes-${key.length * 8}-gcm`, key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
};
const ungcm = (
  /** @type {Buffer} */ key,
  /** @type {Buffer} */ nonce,
  /** @type {Buffer} */ sealed,
  /** @type {Buffer} */ aad,
) => {
  const decipher = createDecipheriv(`aes-${key.length * 8}-gcm`, key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(-16));
  return Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
};
/** A P-256 key from its scalar: the uncompressed point and both JWK forms. */
const p256 = (/** @type {string} */ scalarHex) => {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(scalarHex, "hex"));
  const point = ecdh.getPublicKey();
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: b64u(point.subarray(1, 33)),
    y: b64u(point.subarray(33)),
  };
  return { ecdh, point, jwk, privateJwk: { ...jwk, d: b64u(Buffer.from(scalarHex, "hex")) } };
};

// ---------------------------------------------------------------------------
// Stock chain keys, docs/spec-profile--chain-keys.md Sections 6.3-6.5 and 7.3.
// Root and Step give 16-byte chain keys, Leaf the 16-byte period key; every
// call is HKDF-SHA-256 with an empty salt over a binary context.

const CHAIN_CONSTRUCTION = "dca-construction-chain-keys";
const u16 = (/** @type {number} */ n) => {
  check(Number.isInteger(n) && n >= 0 && n <= 0xffff, `u16 ${n}`);
  const out = Buffer.alloc(2);
  out.writeUInt16BE(n);
  return out;
};
const u32 = (/** @type {number} */ n) => {
  check(Number.isInteger(n) && n >= 0 && n <= 0xffffffff, `u32 ${n}`);
  const out = Buffer.alloc(4);
  out.writeUInt32BE(n);
  return out;
};
const str = (/** @type {string} */ text) => {
  const octets = Buffer.from(text, "utf8");
  return Buffer.concat([u16(octets.length), octets]);
};
/**
 * One Root (0x01), Step (0x02) or Leaf (0x03) context.
 * @param {number} domain @param {string} group @param {{chainsPerDay:number,periodMinutes:number}} geometry
 * @param {number} windowStart @param {number} position
 */
const chainContext = (domain, group, geometry, windowStart, position) =>
  Buffer.concat([
    Buffer.of(domain),
    str(CHAIN_CONSTRUCTION),
    str(group),
    u16(geometry.chainsPerDay),
    u16(geometry.periodMinutes),
    u32(windowStart),
    u16(position),
  ]);
const EMPTY_SALT = Buffer.alloc(0);
/** YYMMDDTHHMM in UTC to the window coordinate of Section 7.3. */
const coordinate = (
  /** @type {string} */ label,
  /** @type {{chainsPerDay:number,periodMinutes:number}} */ geometry,
) => {
  const match = /^(\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)$/.exec(label);
  check(match !== null, `label ${label}`);
  const [, yy, mo, dd, hh, mi] = /** @type {RegExpExecArray} */ (match).map(Number);
  const minutes = Date.UTC(2000 + yy, mo - 1, dd, hh, mi) / 60_000;
  const windowMinutes = 1440 / geometry.chainsPerDay;
  const windowStart = minutes - (minutes % windowMinutes);
  check((minutes - windowStart) % geometry.periodMinutes === 0, `label ${label} off the grid`);
  return {
    windowStart,
    position: (minutes - windowStart) / geometry.periodMinutes,
    N: windowMinutes / geometry.periodMinutes,
  };
};
/** C[position] of the window holding `label`: Root, then Step down to position. */
const chainKeyAt = (
  /** @type {Uint8Array} */ secret,
  /** @type {string} */ group,
  /** @type {{chainsPerDay:number,periodMinutes:number}} */ geometry,
  /** @type {string} */ label,
) => {
  const { windowStart, position, N } = coordinate(label, geometry);
  check(secret.length === 32, "a key-derivation secret is 32 bytes");
  let key = hkdf(secret, EMPTY_SALT, chainContext(0x01, group, geometry, windowStart, N - 1), 16);
  for (let i = N - 2; i >= position; i--)
    key = hkdf(key, EMPTY_SALT, chainContext(0x02, group, geometry, windowStart, i), 16);
  return { position, key };
};
/** P[position] = Leaf(C[position]). */
const periodKeyAt = (
  /** @type {Uint8Array} */ secret,
  /** @type {string} */ group,
  /** @type {{chainsPerDay:number,periodMinutes:number}} */ geometry,
  /** @type {string} */ label,
) => {
  const { windowStart } = coordinate(label, geometry);
  const { position, key } = chainKeyAt(secret, group, geometry, label);
  return hkdf(key, EMPTY_SALT, chainContext(0x03, group, geometry, windowStart, position), 16);
};

// Prove the stock derivation above against the published chain-key vectors.
{
  const read = (/** @type {string} */ path) =>
    JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
  const canonical = read("../../../chain-keys/test/fixtures/dca-profile-chain-keys.vectors.json");
  check(canonical.constructionIdentity === CHAIN_CONSTRUCTION, "stock construction identity");
  for (const row of canonical.cases) {
    const secret = Buffer.from(row.secretHex, "hex");
    const geometry = { chainsPerDay: row.chainsPerDay, periodMinutes: row.periodMinutes };
    const at = coordinate(row.label, geometry);
    check(
      at.windowStart === row.windowStart && at.position === row.position && at.N === row.N,
      `${row.id} coordinate`,
    );
    const contexts = [
      [0x01, row.N - 1, row.rootInfoHex],
      [0x02, row.N - 2, row.stepInfoHex],
      [0x03, row.position, row.leafInfoHex],
    ];
    for (const [domain, position, infoHex] of contexts)
      check(
        hexOf(chainContext(domain, row.accessGroup, geometry, row.windowStart, position)) ===
          infoHex,
        `${row.id} context ${domain}`,
      );
    const labelOf = (/** @type {number} */ position) => {
      const date = new Date((row.windowStart + position * row.periodMinutes) * 60_000);
      const two = (/** @type {number} */ n) => String(n).padStart(2, "0");
      return (
        two(date.getUTCFullYear() % 100) +
        two(date.getUTCMonth() + 1) +
        two(date.getUTCDate()) +
        "T" +
        two(date.getUTCHours()) +
        two(date.getUTCMinutes())
      );
    };
    const group = row.accessGroup;
    check(
      b64u(chainKeyAt(secret, group, geometry, labelOf(row.N - 1)).key) === row.rootChainKey,
      `${row.id} Root`,
    );
    check(
      b64u(chainKeyAt(secret, group, geometry, labelOf(row.N - 2)).key) ===
        row.chainKeyAfterOneStep,
      `${row.id} one Step`,
    );
    check(
      b64u(periodKeyAt(secret, group, geometry, row.label)) === row.periodKey,
      `${row.id} Leaf`,
    );
    row.expansion.forEach((/** @type {string} */ expected, /** @type {number} */ position) =>
      check(
        b64u(periodKeyAt(secret, group, geometry, labelOf(position))) === expected,
        `${row.id} period key at position ${position}`,
      ),
    );
    for (const [label, expected] of Object.entries(row.cutoffChainKeys ?? {}))
      check(
        b64u(chainKeyAt(secret, group, geometry, label).key) === expected,
        `${row.id} chain key at ${label}`,
      );
  }
  // The conformance corpus records HKDF rows over these same contexts.
  const primitives = read(
    "../../../../../verification/vectors/v1/profiles/dca-profile-chain-keys/chain-key-primitives.json",
  );
  primitives.input.operations.forEach(
    (/** @type {any} */ { op, input }, /** @type {number} */ i) => {
      check(op === "hkdf-sha256", `primitive row ${i} operation`);
      const okm = hkdf(
        unb64u(input.ikmBase64url),
        EMPTY_SALT,
        unb64u(input.infoBase64url),
        input.length,
      );
      check(b64u(okm) === primitives.expected.observations[i].okmBase64url, `primitive row ${i}`);
    },
  );
  const c1 = canonical.cases[0];
  check(
    hexOf(unb64u(primitives.input.operations[0].input.infoBase64url)) === c1.rootInfoHex,
    "primitive row 0 is the c1 Root context",
  );
}

// ---------------------------------------------------------------------------
// Content groups under the production names.

const geometry = inputs.periodGeometry;
const secret = Buffer.from(inputs.retainedSecretHex, "hex");
const namespace = createHash("sha256").update(inputs.origin, "utf8").digest("hex");
/** HKDF(retainedSecret, "dca-construction-content-name-seeds", F(["content-name-window", ...]), 32). */
const seedOf = (/** @type {string} */ contentName, /** @type {string} */ window) =>
  hkdf(
    secret,
    ascii("dca-construction-content-name-seeds"),
    F([
      "content-name-window",
      namespace,
      contentName,
      geometry.chainsPerDay,
      geometry.periodMinutes,
      window,
    ]),
    32,
  );
/** HKDF(periodKey, "dca-construction-content-connectors", F(["item-pad", renderId, contentName]), 16). */
const padOf = (/** @type {Buffer} */ periodKey, /** @type {string} */ contentName) =>
  hkdf(
    periodKey,
    ascii("dca-construction-content-connectors"),
    F(["item-pad", inputs.renderId, contentName]),
    16,
  );

// The annex anchors, computed independently of this generator.
{
  check(
    namespace === "2d0a016473ff75fd2afa3cc1dac401896235215a4a61e06d11129ff3442837a7",
    "publisherNamespace anchor",
  );
  check(
    hexOf(seedOf("bodytext", W12)) ===
      "d9b1274900e75c2ddcf90b8015ffc87d4bd60eb8b84298d5ec9d57e26223a8f3",
    "contentNameSeedHex anchor",
  );
}

const at = coordinate(inputs.renderPeriod, geometry);
check(
  coordinate(inputs.windowStart, geometry).position === 0 &&
    coordinate(inputs.windowStart, geometry).windowStart === at.windowStart,
  "the render period lies in the seed window",
);
{
  const intoPeriod =
    new Date(inputs.issuedAt).getTime() / 60_000 -
    (at.windowStart + at.position * geometry.periodMinutes);
  check(
    intoPeriod >= 0 && intoPeriod < geometry.periodMinutes,
    "the render period is the period of issuedAt",
  );
}

// Seeds and their 113-byte envelopes: ephemeral point (65) || AES-256-GCM(seed)
// with tag (48). The AES key is the raw 32-byte ECDH x-coordinate, with no KDF,
// and the nonce is twelve zero bytes that the envelope does not carry. The AAD
// binds the publisher namespace, render, issuer, content name, window and geometry.
const issuer = p256(inputs.issuerPrivateScalarHex);
/** @type {Record<string, any>} */
const seedEnvelopes = {};
/** @type {Record<string, Buffer>} */
const seeds = {};
const ZERO_NONCE = Buffer.alloc(12);
for (const [contentName, { ephemeralPrivateScalarHex }] of Object.entries(inputs.envelopes)) {
  const seed = seedOf(contentName, inputs.windowStart);
  seeds[contentName] = seed;
  const aad = F([
    "dca-bind-content-name-seed",
    namespace,
    inputs.renderId,
    inputs.issuerName,
    contentName,
    inputs.windowStart,
    geometry.chainsPerDay,
    geometry.periodMinutes,
  ]);
  const ephemeral = p256(ephemeralPrivateScalarHex);
  const shared = ephemeral.ecdh.computeSecret(issuer.point);
  check(shared.length === 32, "raw ECDH x-coordinate is 32 bytes");
  const envelope = Buffer.concat([ephemeral.point, gcm(shared, ZERO_NONCE, seed, aad)]);
  check(envelope.length === 113, `${contentName} envelope is 113 bytes`);
  // The issuer side: its own ECDH over the carried point opens the seed.
  const opened = ungcm(
    issuer.ecdh.computeSecret(envelope.subarray(0, 65)),
    ZERO_NONCE,
    envelope.subarray(65),
    aad,
  );
  check(opened.equals(seed), `${contentName} envelope opens`);
  seedEnvelopes[contentName] = {
    windowStart: inputs.windowStart,
    ephemeralPublicJwk: ephemeral.jwk,
    sharedSecretHex: hexOf(shared),
    aadText: aad.toString("ascii"),
    aadHex: hexOf(aad),
    seedHex: hexOf(seed),
    sealed: b64u(envelope),
  };
}

// Connectors: each item's random content key XOR the pad of its group's
// period key at the render period, from the seed of its own content name.
/** @type {Record<string, any>} */
const itemKeys = {};
for (const [contentName, item] of Object.entries(inputs.items)) {
  const contentKey = Buffer.from(item.contentKeyHex, "hex");
  /** @type {Record<string, any>} */
  const connectors = {};
  for (const group of item.groups) {
    const periodKey = periodKeyAt(seeds[contentName], group, geometry, inputs.renderPeriod);
    const pad = padOf(periodKey, contentName);
    const connector = Buffer.from(contentKey.map((b, i) => b ^ pad[i]));
    connectors[group] = {
      periodKeyHex: hexOf(periodKey),
      itemPadInputText: F(["item-pad", inputs.renderId, contentName]).toString("ascii"),
      itemPadHex: hexOf(pad),
      connector: b64u(connector),
    };
  }
  itemKeys[contentName] = { connectors };
}

// The signed resource: the base claims in the order the publisher signs them.
const publisher = p256(inputs.publisherSigningScalarHex);
const header = { alg: "ES256", typ: "JWT", kid: inputs.publisherKid };
const resource = {
  renderId: inputs.renderId,
  origin: inputs.origin,
  issuedAt: inputs.issuedAt,
  resourceId: inputs.resourceId,
  data: {},
};
const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(resource))}`;
const ieee = /** @type {const} */ ({ dsaEncoding: "ieee-p1363" });
if (process.argv.includes("--resign")) {
  const signingKey = createPrivateKey({ key: publisher.privateJwk, format: "jwk" });
  console.log(b64u(sign("sha256", Buffer.from(signingInput), { key: signingKey, ...ieee })));
  process.exit(0);
}
check(
  verify(
    "sha256",
    Buffer.from(signingInput),
    { key: createPublicKey({ key: publisher.jwk, format: "jwk" }), ...ieee },
    unb64u(STORED_SIGNATURE),
  ),
  "signing input changed: run with --resign and store the printed signature",
);
const resourceJWT = `${signingInput}.${STORED_SIGNATURE}`;

// Item bodies use twelve zero nonce octets and AAD LP(renderId)||LP(name).
const lp = (/** @type {string} */ text) => {
  const octets = Buffer.from(text, "utf8");
  return Buffer.concat([u32(octets.length), octets]);
};
// The wire carries item records; the render hands its ciphertexts to the
// JSON writer by name, as the Sealer returns them.
/** @type {Record<string, any>[]} */
const contentData = [];
/** @type {Record<string, string>} */
const sealedContent = {};
for (const [contentName, item] of Object.entries(inputs.items)) {
  const aad = Buffer.concat([lp(inputs.renderId), lp(contentName)]);
  itemKeys[contentName].contentAadHex = hexOf(aad);
  const nonce = Buffer.alloc(12);
  sealedContent[contentName] = b64u(
    gcm(Buffer.from(item.contentKeyHex, "hex"), nonce, Buffer.from(item.plaintext, "utf8"), aad),
  );
  contentData.push({
    contentName,
    contentType: item.contentType,
    connectors: Object.entries(itemKeys[contentName].connectors).map(([group, { connector }]) => ({
      group,
      connector,
    })),
  });
}
/** One item's connector for one group, read off the wire records. */
const connectorOf = (/** @type {string} */ contentName, /** @type {string} */ group) =>
  contentData
    .find((record) => record.contentName === contentName)
    ?.connectors.find((/** @type {any} */ record) => record.group === group)?.connector;

// The delivery, its members in the order the publisher writes them.
const sealedSeeds = Object.entries(seedEnvelopes).map(([contentName, { sealed }]) => ({
  contentName,
  windowStart: inputs.windowStart,
  key: sealed,
}));
const publication = {
  dcaData: {
    version: "1",
    resource,
    resourceJWT,
    periodGeometry: geometry,
    renderPeriod: inputs.renderPeriod,
    contentData,
    issuerData: [
      {
        issuerName: inputs.issuerName,
        sealed: { contentWindowSeeds: sealedSeeds },
        keyId: inputs.issuerKeyId,
      },
    ],
  },
  sealedContent,
};

// The request: the base members, then the content-group members for the
// narrowed names. Seeds go only for names the request asks about; the builder
// relays every connector record of each requested content key's group.
const requestedNames = [
  ...Object.keys(inputs.narrowing.requestedContentGroups),
  ...Object.keys(inputs.narrowing.requestedContentKeys),
];
const request = {
  version: "1",
  issuerName: inputs.issuerName,
  resourceJWT,
  keyId: inputs.issuerKeyId,
  sealed: {
    contentKeys: [],
    contentWindowSeeds: sealedSeeds.filter((record) => requestedNames.includes(record.contentName)),
  },
  renderPeriod: inputs.renderPeriod,
  periodGeometry: geometry,
  requested: {
    contentGroups: Object.entries(inputs.narrowing.requestedContentGroups).map(
      ([contentName, groups]) => ({ contentName, groups }),
    ),
    contentKeys: Object.entries(inputs.narrowing.requestedContentKeys).map(
      ([contentName, group]) => ({
        contentName,
        group,
        connector: connectorOf(contentName, group),
      }),
    ),
  },
};

// The direct response to the three grants. A chain grant returns C[cutoff];
// a period grant P[t]; an item grant the key recovered from the relayed
// connector; genuine content authentication remains the client's check.
/** @type {Record<string, any>} */
const chainKeys = {};
/** @type {Record<string, any>} */
const periodKeys = {};
/** @type {Record<string, string>} */
const contentKeys = {};
for (const grant of inputs.grants) {
  const seed = seeds[grant.contentName];
  if (grant.kind === "chain") {
    const { key } = chainKeyAt(seed, grant.group, geometry, grant.cutoffT);
    ((chainKeys[grant.contentName] ??= {})[grant.group] ??= {})[grant.cutoffT] = b64u(key);
    // The client steps the chain key down to the render period.
    check(
      grant.cutoffT >= inputs.renderPeriod &&
        hexOf(periodKeyAt(seed, grant.group, geometry, inputs.renderPeriod)) ===
          itemKeys[grant.contentName].connectors[grant.group].periodKeyHex,
      "the chain grant reaches the render period",
    );
  } else if (grant.kind === "period") {
    ((periodKeys[grant.contentName] ??= {})[grant.group] ??= {})[grant.t] = b64u(
      periodKeyAt(seed, grant.group, geometry, grant.t),
    );
  } else {
    const route = request.requested.contentKeys.find(
      (record) => record.contentName === grant.contentName,
    );
    check(route !== undefined, `the request relays a route for ${grant.contentName}`);
    const { group, connector } = /** @type {{ group: string, connector: string }} */ (route);
    const pad = padOf(periodKeyAt(seed, group, geometry, inputs.renderPeriod), grant.contentName);
    const recovered = Buffer.from(unb64u(connector).map((b, i) => b ^ pad[i]));
    contentKeys[grant.contentName] = b64u(recovered);
  }
}
// The core result's required `keys.contentKeys` comes first and stays empty:
// the request presents no ordinary item envelope (docs/spec--core-protocol.md
// Section 7; docs/spec--response-binding.md Section 3 keeps it in the direct
// response). The extension adds its top-level members after it.
// The pin below hashes these outputs in their earlier nested spelling, under
// the earlier member name `contentGroups`, so neither the move to records nor
// the rename to `contentGroupKeys` can move it; the wire response is built
// from them.
const pinnedResponse = {
  keys: { contentKeys: {} },
  contentGroups: { chainKeys, periodKeys, contentKeys },
};
/** `{name: {group: {label: key}}}` as records naming `label` under `field`. */
const groupRecordsOf = (/** @type {Record<string, any>} */ nested, /** @type {string} */ field) =>
  Object.entries(nested).flatMap(([contentName, groups]) =>
    Object.entries(groups).flatMap(([group, labels]) =>
      Object.entries(/** @type {Record<string, string>} */ (labels)).map(([label, key]) => ({
        contentName,
        group,
        [field]: label,
        key,
      })),
    ),
  );
const response = {
  keys: { contentKeys: [] },
  contentGroupKeys: {
    chainKeys: groupRecordsOf(chainKeys, "cutoff"),
    periodKeys: groupRecordsOf(periodKeys, "period"),
    contentKeys: Object.entries(contentKeys).map(([contentName, key]) => ({ contentName, key })),
  },
};

// Fixed-input outputs pinned before the resource claim was removed. This
// covers seed/AAD/envelope bytes, stock-derived chain and period keys, item
// pads and connectors; JWT signing input and encrypted bodies are excluded.
check(
  createHash("sha256")
    .update(
      JSON.stringify({
        publisherNamespace: namespace,
        seedEnvelopes,
        items: Object.fromEntries(
          Object.entries(itemKeys).map(([name, item]) => [name, { connectors: item.connectors }]),
        ),
        response: pinnedResponse,
      }),
    )
    .digest("hex") === "17b0080d18c4c88dd74ca832b838348a415d4b2ad071822f6ca9dcec2ad14b50",
  "fixed seed/pad/chain/connector outputs changed",
);

const vectors = {
  provenance:
    "generate-production-vectors.mjs: node:crypto HKDF-SHA256, SHA-256, P-256 ECDH, ES256 and " +
    "AES-GCM with a locally written F transcript, stock chain-key Root/Step/Leaf, seed, item " +
    "pad, content AAD, envelope layout and wire objects. The stock " +
    "derivation is checked against js/extensions/chain-keys/test/fixtures/" +
    "dca-profile-chain-keys.vectors.json and verification/vectors/v1/profiles/" +
    "dca-profile-chain-keys/chain-key-primitives.json on every run. The ES256 signature is " +
    "stored once (ECDSA is randomized) and verified on every run. No code from the content-groups " +
    "or chain-keys implementation.",
  inputs,
  expected: {
    publisherNamespace: namespace,
    issuer: { publicJwk: issuer.jwk, privateJwk: issuer.privateJwk },
    publisher: { publicJwk: publisher.jwk, signingInput },
    seedEnvelopes,
    items: itemKeys,
    publication,
    request,
    response,
    jsonBytes: {
      publication: jsonBytes(publication),
      request: jsonBytes(request),
      response: jsonBytes(response),
    },
  },
};
writeFileSync(
  new URL("../fixtures/production.vectors.json", import.meta.url),
  `${JSON.stringify(vectors, null, 2)}\n`,
);

import assert from "node:assert/strict";
import { encrypt, decrypt } from "../../../core-shared/aead.js";
import { test } from "node:test";
import { createCipheriv, createECDH, hkdfSync } from "node:crypto";
import { preflight } from "../core-issuer/prepare.js";
import { open, entryInfo } from "../core-shared--client-issuer/entry.js";
import { settleKindDescriptors } from "../../client-bound-transport/core-shared--client-issuer/keyKind.js";
import { responseBehavior, bytes, at } from "../test-lib/behavior.js";

const { subtle } = globalThis.crypto;
const composedKinds = settleKindDescriptors({
  contentGroupPeriodKey: { width: 16, open: "raw" },
  contentGroupChainKey: { width: 16, open: "raw" },
});
const composedSections = [
  { path: ["contentGroupKeys", "contentKeys"], fields: ["contentName"], keyKind: "contentKey" },
  {
    path: ["contentGroupKeys", "periodKeys"],
    fields: ["contentName", "accessGroup", "period"],
    keyKind: "contentGroupPeriodKey",
  },
  {
    path: ["contentGroupKeys", "chainKeys"],
    fields: ["contentName", "accessGroup", "cutoff"],
    keyKind: "contentGroupChainKey",
  },
];
const client = async () => {
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveKey",
  ]);
  return { privateKey: pair.privateKey, publicKey: await subtle.exportKey("jwk", pair.publicKey) };
};
responseBehavior({
  client,
  preflight: (publicKey, options = {}) =>
    preflight(publicKey, { composedKinds, composedSections, ...options }),
  open: (transport, privateKey) => open(transport, privateKey, composedKinds),
});

const simple = () => ({ keys: { contentKeys: [{ contentName: "bodytext", key: bytes(1) }] } });
const path = ["keys", "contentKeys", "bodytext"];

test("fixture lookup refuses absent coordinates before opening", () => {
  assert.throws(
    () => at(simple(), ["keys", "contentKeys", "missing"]),
    /missing fixture coordinate/,
  );
  assert.throws(
    () => at({ keys: { contentKeys: [{ contentName: "bodytext" }] } }, path),
    /fixture coordinate has no key/,
  );
});

test("prototype: repeat, concurrent and empty prepare consume response agreement", async () => {
  const recipient = await client();
  const view = await preflight(recipient.publicKey);
  const first = view.prepare(simple());
  await assert.rejects(view.prepare(simple()), /already consumed/);
  await first;
  await assert.rejects(view.prepare(simple()), /already consumed/);
  const empty = await preflight(recipient.publicKey);
  await empty.prepare({});
  await assert.rejects(empty.prepare(simple()), /already consumed/);
});

test("prototype: failed preparation discards agreement; fresh preflight succeeds", async () => {
  const recipient = await client();
  const view = await preflight(recipient.publicKey);
  await assert.rejects(
    view.prepare({ keys: { contentKeys: [{ contentName: "bodytext", key: bytes(1).slice(1) }] } }),
    /width/,
  );
  await assert.rejects(view.prepare(simple()), /already consumed/);
  const next = await (await preflight(recipient.publicKey)).prepare(simple());
  const opener = await open(next.transport, recipient.privateKey);
  assert.equal(
    (await opener.open(at(next, path), ["decrypt"], "contentKey", path)).extractable,
    false,
  );
});

test("prototype: mutable bytes, coordinates and declarations are captured before awaits", async () => {
  const recipient = await client();
  const sections = [{ path: ["extra", "entries"], fields: ["name"], keyKind: "chainKey" }];
  const view = await preflight(recipient.publicKey, { composedSections: sections });
  sections[0].path[0] = "changed";
  sections[0].fields[0] = "changed";
  const body = {
    keys: {
      contentKeys: [
        { contentName: "bodytext", key: bytes(1) },
        { contentName: "sidebar", key: bytes(2) },
      ],
    },
    extra: { entries: [{ name: "last", key: bytes(3) }] },
  };
  const pending = view.prepare(body);
  body.keys.contentKeys[0].key.fill(99);
  body.keys.contentKeys[1].key.fill(99);
  body.extra.entries[0].key.fill(99);
  body.keys.contentKeys[0].contentName = "relabelled";
  body.keys.contentKeys.shift();
  const response = await pending;
  const opener = await open(response.transport, recipient.privateKey);
  assert.deepEqual(
    await opener.open(response.extra.entries[0].key, [], "chainKey", ["extra", "entries", "last"]),
    bytes(3),
  );
  const handle = await opener.open(at(response, path), ["decrypt"], "contentKey", path);
  const originalPlaintext = new TextEncoder().encode("captured original bytes");
  const nonce = new Uint8Array(12);
  assert.deepEqual(
    await decrypt(handle, nonce, await encrypt(bytes(1), nonce, originalPlaintext)),
    originalPlaintext,
  );
  assert.throws(
    () => at(response, ["keys", "contentKeys", "relabelled"]),
    /missing fixture coordinate/,
  );
  // Open in-flight captures its own path and ciphertext before yielding too.
  const originalPath = ["extra", "entries", "last"];
  const value = response.extra.entries[0].key;
  const opening = opener.open(value, [], "chainKey", originalPath);
  originalPath[2] = "alias";
  value.key = "AAAA";
  assert.deepEqual(await opening, bytes(3));
});

test("prototype: length framing separates delimiter and Unicode spellings", async () => {
  assert.notDeepEqual(entryInfo("contentKey", ["a|b", "c"]), entryInfo("contentKey", ["a", "b|c"]));
  assert.notDeepEqual(
    entryInfo("contentKey", ["a\0b", "c"]),
    entryInfo("contentKey", ["a", "b\0c"]),
  );
  assert.notDeepEqual(entryInfo("contentKey", ["é"]), entryInfo("contentKey", ["e\u0301"]));
  assert.notDeepEqual(entryInfo("contentKey", ["😀"]), entryInfo("contentKey", ["�"]));
  assert.throws(() => entryInfo("contentKey", ["\ud800"]), /scalar/);
  assert.throws(() => entryInfo("contentKey", ["\udc00"]), /scalar/);
  const recipient = await client();
  const names = ["a|b", "a\0b", "é", "e\u0301", "😀", "�", "__proto__"];
  const response = await (
    await preflight(recipient.publicKey, {
      composedSections: [{ path: ["extra"], fields: ["name"], keyKind: "chainKey" }],
    })
  ).prepare({ extra: names.map((name, i) => ({ name, key: bytes(i) })) });
  const opener = await open(response.transport, recipient.privateKey);
  for (const [i, name] of names.entries())
    assert.deepEqual(
      await opener.open(response.extra[i].key, [], "chainKey", ["extra", name]),
      bytes(i),
    );
  await assert.rejects(opener.open(response.extra[2].key, [], "chainKey", ["extra", "e\u0301"]), {
    name: "OperationError",
  });
});

test("prototype: record metadata and errors are not wrapped or included in the semantic path", async () => {
  const recipient = await client();
  const sections = [
    {
      path: ["extra", "entries"],
      fields: ["name"],
      keyKind: "chainKey",
      errorPath: ["extra", "errors"],
    },
  ];
  const response = await (
    await preflight(recipient.publicKey, { composedSections: sections })
  ).prepare({
    extra: {
      entries: [{ name: "one", key: bytes(7), note: "retained" }],
      errors: [{ name: "two", error: "key_retired" }],
    },
  });
  const opener = await open(response.transport, recipient.privateKey);
  const record = response.extra.entries[0];
  assert.equal(record.name, "one");
  assert.equal(record.note, "retained");
  assert.deepEqual(response.extra.errors, [{ name: "two", error: "key_retired" }]);
  assert.deepEqual(
    await opener.open(record.key, [], "chainKey", ["extra", "entries", "one"]),
    bytes(7),
  );
  await assert.rejects(
    opener.open(record.key, [], "chainKey", ["extra", "entries", "one", "key"]),
    {
      name: "OperationError",
    },
  );
  await assert.rejects(
    preflight(recipient.publicKey, {
      composedSections: [
        ...sections,
        { path: ["extra", "entries", "nested"], fields: ["name"], keyKind: "chainKey" },
      ],
    }),
    /overlapping/,
  );
});

// Independent OpenSSL-backed Node path: no prototype framing, agreement,
// KDF, kind-context or encryption helpers are used to calculate expected bytes.
test("prototype: independent transcript agrees on exact info and ciphertext", async () => {
  const make = async (scalar) => {
    const dh = createECDH("prime256v1");
    dh.setPrivateKey(Buffer.from(scalar.toString(16).padStart(64, "0"), "hex"));
    const point = dh.getPublicKey(undefined, "uncompressed");
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: point.subarray(1, 33).toString("base64url"),
      y: point.subarray(33).toString("base64url"),
      d: dh.getPrivateKey().toString("base64url"),
    };
    const privateKey = await subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"],
    );
    const publicKey = await subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      { name: "ECDH", namedCurve: "P-256" },
      true,
      [],
    );
    return { dh, point, privateKey, publicKey, jwk };
  };
  const recipient = await make(1);
  const issuer = await make(2);
  const kind = "chainKey";
  // Literal UTF-8 frames: "paid" is four octets; "é😀" is six octets,
  // although JavaScript string.length counts three UTF-16 code units.
  for (const [group, groupFrameHex] of [
    ["paid", "0000000470616964"],
    ["é😀", "00000006c3a9f09f9880"],
  ]) {
    const coordinates = ["keys", "chainKeys", group, "2026-10-21"];
    const expectedInfoHex =
      "6463612d64657269766174696f6e2d636c69656e742d626f756e642d656e7472792d6b65790000000008636861696e4b657900000004000000046b65797300000009636861696e4b657973" +
      groupFrameHex +
      "0000000a323032362d31302d3231";
    assert.equal(Buffer.from(entryInfo(kind, coordinates)).toString("hex"), expectedInfoHex);
    const shared = issuer.dh.computeSecret(recipient.point);
    const key = Buffer.from(
      hkdfSync("sha256", shared, Buffer.alloc(0), Buffer.from(expectedInfoHex, "hex"), 32),
    );
    const cipher = createCipheriv("aes-256-gcm", key, Buffer.alloc(12));
    cipher.setAAD(Buffer.from("dca-bind-client-bound-key-kind\0chainKey", "utf8"));
    const expected = Buffer.concat([cipher.update(bytes(9)), cipher.final(), cipher.getAuthTag()]);
    const { d: _secret, ...publicJwk } = recipient.jwk;
    const view = await preflight(publicJwk, { ephemeralKeyPair: issuer });
    const response = await view.prepare({
      keys: { chainKeys: [{ accessGroup: group, cutoff: "2026-10-21", key: bytes(9) }] },
    });
    assert.deepEqual(at(response, coordinates), { key: expected.toString("base64url") });
    const opener = await open(response.transport, recipient.privateKey);
    assert.deepEqual(
      await opener.open({ key: expected.toString("base64url") }, [], kind, coordinates),
      bytes(9),
    );
  }
});

test("prototype: same-kind sibling, full namespace, original cache path and kind relabeling fail", async () => {
  const recipient = await client();
  const response = await (
    await preflight(recipient.publicKey, { composedKinds, composedSections })
  ).prepare({
    keys: {
      contentKeys: [
        { contentName: "bodytext", key: bytes(1) },
        { contentName: "sidebar", key: bytes(2) },
      ],
      periodKeys: [{ accessGroup: "paid", period: "day", key: bytes(3) }],
    },
    contentGroupKeys: {
      contentKeys: [{ contentName: "bodytext", key: bytes(4) }],
      periodKeys: [{ contentName: "bodytext", accessGroup: "paid", period: "day", key: bytes(5) }],
    },
  });
  const opener = await open(response.transport, recipient.privateKey, composedKinds);
  const entry = at(response, path);
  for (const wrongPath of [
    ["keys", "contentKeys", "sidebar"],
    ["contentGroupKeys", "contentKeys", "bodytext"],
  ])
    await assert.rejects(opener.open(entry, ["decrypt"], "contentKey", wrongPath), {
      name: "OperationError",
    });
  await assert.rejects(opener.open(entry, ["unwrapKey"], "periodKey", path), {
    name: "OperationError",
  });
  const original = ["keys", "periodKeys", "paid", "day"];
  await assert.rejects(
    opener.open(at(response, original), ["unwrapKey"], "periodKey", [
      "keys",
      "periodKeys",
      "cacheAlias",
      "day",
    ]),
    { name: "OperationError" },
  );
  const groupPath = ["contentGroupKeys", "periodKeys", "bodytext", "paid", "day"];
  await assert.rejects(
    opener.open(at(response, groupPath), [], "contentGroupChainKey", groupPath),
    {
      name: "OperationError",
    },
  );
});

test("prototype: preflight captures the client offer before generating an agreement", async () => {
  const recipient = await client();
  const other = await client();
  const offer = structuredClone(recipient.publicKey);
  const pending = preflight(offer);
  Object.assign(offer, other.publicKey);
  const response = await (await pending).prepare(simple());
  const opener = await open(response.transport, recipient.privateKey);
  assert.equal(
    (await opener.open(at(response, path), ["decrypt"], "contentKey", path)).extractable,
    false,
  );
});

test("prototype: nonce-bearing legacy entries and non-scalar paths are rejected explicitly", async () => {
  const recipient = await client();
  const response = await (await preflight(recipient.publicKey)).prepare(simple());
  const opener = await open(response.transport, recipient.privateKey);
  await assert.rejects(
    opener.open(
      { ...at(response, path), nonce: "AAAAAAAAAAAAAAAA" },
      ["decrypt"],
      "contentKey",
      path,
    ),
    /invalid nonce-free/,
  );
  await assert.rejects(
    opener.open(at(response, path), ["decrypt"], "contentKey", ["keys", "contentKeys", "\ud800"]),
    /scalar/,
  );
  const view = await preflight(recipient.publicKey);
  await assert.rejects(
    view.prepare({ keys: { contentKeys: [{ contentName: "\ud800", key: bytes(1) }] } }),
    /scalar/,
  );
});

test("prototype: aliased issuer arrays and key bytes keep independent ciphertext at each full path", async () => {
  const recipient = await client();
  const sharedContent = [{ contentName: "bodytext", key: bytes(7) }];
  const sharedSeed = bytes(9);
  const body = {
    keys: {
      contentKeys: sharedContent,
      chainKeys: [
        { accessGroup: "paid", cutoff: "261021T1200", key: sharedSeed },
        { accessGroup: "bonus", cutoff: "261021T1200", key: sharedSeed },
      ],
    },
    contentGroupKeys: { contentKeys: sharedContent },
  };
  const response = await (
    await preflight(recipient.publicKey, {
      composedSections: [
        {
          path: ["contentGroupKeys", "contentKeys"],
          fields: ["contentName"],
          keyKind: "contentKey",
        },
      ],
    })
  ).prepare(body);
  const opener = await open(response.transport, recipient.privateKey);
  const plaintext = new TextEncoder().encode("original granted content");
  const nonce = new Uint8Array(12);
  const ciphertext = await encrypt(bytes(7), nonce, plaintext);
  for (const fullPath of [
    ["keys", "contentKeys", "bodytext"],
    ["contentGroupKeys", "contentKeys", "bodytext"],
  ]) {
    const handle = await opener.open(at(response, fullPath), ["decrypt"], "contentKey", fullPath);
    assert.deepEqual(await decrypt(handle, nonce, ciphertext), plaintext);
  }
  for (const group of ["paid", "bonus"]) {
    const fullPath = ["keys", "chainKeys", group, "261021T1200"];
    assert.deepEqual(await opener.open(at(response, fullPath), [], "chainKey", fullPath), bytes(9));
  }
  assert.notEqual(response.keys.contentKeys, response.contentGroupKeys.contentKeys);
  assert.notEqual(response.keys.chainKeys[0].key, response.keys.chainKeys[1].key);
  assert.ok(Array.isArray(response.keys.contentKeys));
  assert.ok(Array.isArray(response.keys.chainKeys));
  assert.equal(body.keys.contentKeys, body.contentGroupKeys.contentKeys);
  assert.deepEqual(body.keys.contentKeys[0].key, bytes(7));
  assert.equal(body.keys.chainKeys[0].key, body.keys.chainKeys[1].key);
  assert.deepEqual(body.keys.chainKeys[0].key, bytes(9));
});

test("prototype: duplicate semantic coordinates fail before any encryption and consume the agreement", async (t) => {
  const recipient = await client();
  const encrypt = t.mock.method(subtle, "encrypt", () => {
    throw new Error("unexpected encryption before admission");
  });
  for (const section of ["base", "composed"]) {
    for (const values of [
      [bytes(1), bytes(2)],
      [bytes(2), bytes(1)],
      [bytes(1), bytes(1)],
    ]) {
      const records = [
        { contentName: "valid-prefix", key: bytes(3) },
        ...values.map((key) => ({ contentName: "bodytext", key })),
      ];
      const body =
        section === "base"
          ? { keys: { contentKeys: records } }
          : { contentGroupKeys: { contentKeys: records } };
      const original = structuredClone(body);
      const view = await preflight(recipient.publicKey, { composedSections });
      await assert.rejects(view.prepare(body), /duplicate response entry coordinate/);
      assert.equal(encrypt.mock.callCount(), 0);
      assert.deepEqual(body, original);
      await assert.rejects(view.prepare(simple()), /already consumed/);
    }
  }
  encrypt.mock.restore();
  const response = await (await preflight(recipient.publicKey)).prepare(simple());
  const opener = await open(response.transport, recipient.privateKey);
  assert.equal(
    (await opener.open(at(response, path), ["decrypt"], "contentKey", path)).extractable,
    false,
  );
});

test("prototype: malformed selected key collections refuse before entry crypto and consume the agreement", async (t) => {
  const recipient = await client();
  const encrypt = t.mock.method(subtle, "encrypt", () => {
    throw new Error("unexpected encryption before admission");
  });
  const derive = t.mock.method(subtle, "deriveKey");
  const sections = [
    { path: ["keys", "contentKeys"], fields: ["contentName"] },
    { path: ["keys", "periodKeys"], fields: ["accessGroup", "period"] },
    { path: ["keys", "chainKeys"], fields: ["accessGroup", "cutoff"] },
    ...composedSections,
  ];
  for (const section of sections) {
    const identity = Object.fromEntries(section.fields.map((field) => [field, "coordinate"]));
    const valid = { ...identity, [section.fields[0]]: "valid-prefix", key: bytes(3) };
    for (const [collection, message] of [
      [{ coordinate: bytes(1) }, /collection must be an array/],
      [null, /collection must be an array/],
      [undefined, /collection must be an array/],
      [[valid, { key: bytes(1) }], /invalid delivered key record/],
      [
        [valid, { ...identity, [section.fields[0]]: 7, key: bytes(1) }],
        /invalid delivered key record/,
      ],
      [[valid, { ...identity }], /invalid delivered key record/],
      [[valid, null], /invalid delivered key record/],
      [[valid, { ...identity, key: undefined }], /wrong delivered key width/],
      [[valid, { ...identity, key: "AB" }], /wrong delivered key width/],
      [[valid, { ...identity, key: bytes(1).slice(1) }], /wrong delivered key width/],
      [[valid, { ...identity, [section.fields[0]]: "", key: bytes(1) }], /scalar/],
    ]) {
      const body = { note: "unchanged" };
      let parent = body;
      for (const member of section.path.slice(0, -1)) parent = parent[member] = {};
      parent[section.path.at(-1)] = collection;
      const original = structuredClone(body);
      const view = await preflight(recipient.publicKey, { composedKinds, composedSections });
      const beforeDerivation = derive.mock.callCount();
      await assert.rejects(view.prepare(body), message);
      assert.equal(
        derive.mock.callCount(),
        beforeDerivation,
        "no entry key is derived before complete admission",
      );
      assert.equal(encrypt.mock.callCount(), 0);
      assert.deepEqual(body, original);
      await assert.rejects(view.prepare(simple()), /already consumed/);
    }
  }
});

test("prototype: absent optional key sections and unrelated metadata stay untouched", async () => {
  const recipient = await client();
  const metadata = {
    note: "not a selected key collection",
    errors: [{ coordinate: "x", error: "denied" }],
  };
  const body = { ...simple(), extra: metadata, contentGroupKeys: { errors: metadata.errors } };
  const response = await (
    await preflight(recipient.publicKey, { composedKinds, composedSections })
  ).prepare(body);
  assert.deepEqual(response.extra, metadata);
  assert.deepEqual(response.contentGroupKeys, body.contentGroupKeys);
  const opener = await open(response.transport, recipient.privateKey);
  assert.equal(
    (await opener.open(at(response, path), ["decrypt"], "contentKey", path)).extractable,
    false,
  );
});

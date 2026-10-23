// @ts-check
//
// The 65 bytes at the front of an ECDH sealed blob, chosen by the reader.
//
// The reader sends those bytes. An ECDH-P256 sealed blob is a fixed layout with
// no length prefixes: an uncompressed public point at offset 0, 65 bytes, then a
// ciphertext and its tag; the twelve-zero nonce is implicit. The blob travels through the
// reader's browser, and an unlock request is whatever the reader posts, so
// those 65 bytes are the reader's to write. `IssuerEngine` walks the request
// and hands them to `keySealing.open`; nothing ahead of that call has looked
// at them.
//
// A point off the curve leaks the private key. The issuer performs an ECDH key
// agreement between that point and its own static private key. A point on
// P-256 gives a shared secret and nothing is learned from it. A point that is
// not on P-256 lies on some other curve, and if the agreement runs anyway - if
// the implementation multiplies the private scalar by whatever coordinates it
// was handed - the result depends on the private key modulo the order of the
// group that other curve's point happens to generate. That order can be small.
// The reader picks the point, so the reader picks the group, reads a few bits
// of the private key out of whether the answer opened anything, and repeats. A
// few thousand requests is the published cost of recovering the whole key.
//
// This file exists because of what the attack takes when it works. The key
// recovered is the issuer's static private key: the one every publisher on
// its books seals to, on every render it has ever served and every render it
// will serve until the key is rotated. Every other attack this suite runs costs
// at most one reader's article. This one costs the issuer's whole business, and
// the reader does it from a browser with no access to anything but the page.
//
// WebCrypto holds the defence. `open` hands the 65 bytes to `subtle.importKey`,
// and WebCrypto refuses a point that is not on P-256 there: `DOMException:
// Invalid keyData`, which the open call's own catch turns into the same
// `unseal_failed` a tag mismatch produces. So there is no check of ours to read,
// and that is the reason to write this down rather than leave it. The property is
// held by a call this code makes, so it lasts only as long as that call: a
// hand-rolled point decoder ahead of the import, an issuer written against a
// library that agrees over raw coordinates, a raw scalar multiply - each of
// those takes it away, and nothing else in the file changes shape.
//
// Dropping the proof manifest opened this path. The wire used to carry an
// `issuerJWT` proof manifest: the publisher signed a hash of every blob it
// emitted and the issuer opened nothing whose hash was not in that signed list,
// so a reader could post a chosen point and it never reached a private-key
// operation. The manifest went out on 2026-08-05 and the engine unseals what it
// is handed, which is what puts the reader's bytes in front of the issuer's
// private key for the first time.
//
// This file counts agreements, because the response says nothing. The answer is
// the same either way. An issuer that refuses the point and an issuer that
// agrees against it both come back 200 with `unseal_failed` at that one
// coordinate, because the agreement against a bad point yields a key that fails
// the GCM tag a moment later. Run with `subtle.importKey` made to hand back a
// valid stand-in key wherever it would have thrown, the body below is byte for
// byte the same one and only the agreement count moves - five, where the honest
// request makes six. So the assertions on status, keys and error codes are
// worth having and cannot catch this, and counting the agreements is the whole
// sensitivity of the file. That is why `agreements` is here rather than an
// assertion on a message.
//
// The honest coordinates in the same request are answered throughout. A bad
// point is one bad blob, indistinguishable from a key rollover the markup
// outlived, so the page around it keeps working - the shape the engine uses for
// every per-item failure.
//
// The wiring is `demo/scenarios/world.js`'s direct-endpoint family: the reader posts
// straight to the endpoint, because a network between them would only add hops
// to count on the way to the one count that matters.

import test from "node:test";
import assert from "node:assert/strict";

import { base64urlDecode, base64urlEncode } from "../../core-shared/codec.js";
import { directWorld } from "../../demo/scenarios/world.js";
import { CONTENT_NAME, ISSUER_NAME, article } from "../../demo/scenarios/fixtures.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { contentKeyMap, errorMap, keyAt, periodKeyMap, setKeyAt } from "../support/namedRecords.js";

const { subtle } = globalThis.crypto;

/**
 * On the hour, where the shared fixture is twenty past. Four of the six
 * agreements counted below are periodKeys, and this render sits exactly on a
 * period turn - the instant where a walk that took one period too many would
 * show in the count. It does not today: the counts are the same at the
 * fixture's clock, so the boundary is held on purpose rather than asserted.
 */
const AT = "2025-10-23T14:00:00Z";

/** The coordinate every attack below is aimed at. */
const ATTACKED = CONTENT_NAME;

/** The other coordinate in the same request, which has to keep working. */
const HONEST = "locked-data";

/** Uncompressed P-256 point: 0x04 and two 32-byte coordinates. */
const POINT_BYTES = 65;

/** The attacked item is the fixture's; the honest one is a second group. */
const ARTICLE = article("A");
const CONTENT = [
  ...ARTICLE.items,
  {
    name: HONEST,
    value: '{"vote":{"for":7,"against":2},"passed":true}',
    contentType: "application/json",
    accessGroups: ["locked-data"],
  },
];

/**
 * One publisher, one issuer, one render, and the endpoint the reader posts to.
 *
 * @returns {Promise<any>}
 */
async function world() {
  const { publisher, endpoint, processor, publisherRegistration } = await directWorld({ at: AT });
  const page = (await publisher.render({ ...ARTICLE, items: CONTENT })).asJson();

  return {
    endpoint,
    processor,
    publisherRegistration,
    /** The request a conformant client emits for this render. */
    request: () =>
      requestFor(
        page,
        ISSUER_NAME,
        CONTENT.map((item) => item.name),
      ),
  };
}

/**
 * How many ECDH agreements one call performed.
 *
 * `subtle.deriveBits` is where a private key meets a point, so counting it is
 * the only way to see whether the issuer's static key was used against what the
 * reader sent. Every other observable is the same whether the point was refused
 * or agreed against.
 *
 * @param {() => Promise<any>} run
 * @returns {Promise<{ result: any, count: number }>}
 */
async function agreements(run) {
  const held = Object.getOwnPropertyDescriptor(subtle, "deriveBits");
  const real = subtle.deriveBits;
  let count = 0;

  subtle.deriveBits = function (/** @type {any[]} */ ...args) {
    count++;
    return real.apply(this, args);
  };

  try {
    return { result: await run(), count };
  } finally {
    if (held) Object.defineProperty(subtle, "deriveBits", held);
    else delete (/** @type {any} */ (subtle).deriveBits);
  }
}

/**
 * The same blob with another point in front of it. Everything from offset 65 on
 * - the nonce, the ciphertext and the tag - is left as the publisher wrote it,
 * so the point is the only thing under attack.
 *
 * @param {string} blob - base64url, as the page carries it
 * @param {Uint8Array} point - 65 bytes
 * @returns {string}
 */
function withPoint(blob, point) {
  assert.equal(point.length, POINT_BYTES, "the field is fixed width, so an attack fills it");

  const bytes = base64urlDecode(blob);
  bytes.set(point, 0);
  return base64urlEncode(bytes);
}

/**
 * @param {string} text
 * @returns {Uint8Array}
 */
function fromHex(text) {
  return Uint8Array.from(
    /** @type {string[]} */ (text.match(/../g)).map((pair) => parseInt(pair, 16)),
  );
}

/**
 * secp256k1's generator, uncompressed. A real point on a real curve, and its
 * coordinates are 32 bytes like P-256's, so it fills this field exactly as it
 * stands. P-384's generator is the other obvious cross-curve point and it
 * cannot be sent here: its coordinates are 48 bytes each, so writing it into 65
 * bytes means cutting it, and a cut point is only another off-curve string,
 * which the first row below already is.
 */
const SECP256K1_GENERATOR = fromHex(
  "04" +
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
);

/**
 * The point fields a reader can put in front of a blob, built from the genuine
 * one so each differs from a working request in the one way it names.
 *
 * @param {string} blob - the blob the publisher emitted at the attacked coordinate
 * @returns {{ label: string, point: Uint8Array }[]}
 */
function badPoints(blob) {
  const genuine = base64urlDecode(blob).subarray(0, POINT_BYTES);

  // A point on the curve with one bit of its y taken out. Well formed, right
  // prefix, right width, and no longer a solution of the curve equation -
  // which is the invalid-curve input itself rather than a malformed blob.
  const offCurve = new Uint8Array(genuine);
  offCurve[POINT_BYTES - 1] ^= 0x01;

  // The identity, written the way this field would have to carry it. It is
  // the small-subgroup end of the same attack: the agreement against it
  // yields the identity whatever the private key is, so an implementation
  // that accepts it answers the same for every key it holds.
  const identity = new Uint8Array(POINT_BYTES);
  identity[0] = 0x04;

  // 65 zero bytes, which is what a client that sent an empty buffer produces.
  // The prefix is 0x00, so this is not an uncompressed point at all.
  const zeroes = new Uint8Array(POINT_BYTES);

  // The x of a genuine point under a compressed-form prefix. The format fixes
  // this field to uncompressed, and the bytes after x here are the genuine y,
  // so an implementation that reads the prefix and then ignores it recovers a
  // point nobody sealed to.
  const compressed = new Uint8Array(genuine);
  compressed[0] = 0x02;

  return [
    { label: "coordinates that are not on P-256", point: offCurve },
    { label: "the point at infinity", point: identity },
    { label: "all-zero bytes", point: zeroes },
    { label: "another curve's generator", point: SECP256K1_GENERATOR },
    { label: "a compressed-form prefix where the format fixes 0x04", point: compressed },
  ];
}

test("the honest request opens both coordinates, and it is six agreements", async () => {
  // The control the rest of the file is read against: what a working request
  // costs the issuer in private-key operations, and what it gets back.
  const { endpoint, processor, publisherRegistration, request } = await world();

  const { result, count } = await agreements(() =>
    unlockThroughAdmission(processor, endpoint, request(), publisherRegistration),
  );
  const body = /** @type {any} */ (result).body;

  assert.equal(result.status, 200);
  assert.deepEqual(
    Object.keys(contentKeyMap(body.keys.contentKeys)).sort(),
    [ATTACKED, HONEST].sort(),
  );
  assert.equal(errorMap(body.errors), undefined);
  assert.equal(count, 6, "two contentKeys and four periodKeys, one agreement each");
});

test("a point the reader chose comes back with no key, and the rest of the request is answered", async () => {
  const { endpoint, processor, publisherRegistration, request } = await world();

  const control = /** @type {any} */ (
    await unlockThroughAdmission(processor, endpoint, request(), publisherRegistration)
  ).body;

  for (const { label, point } of badPoints(
    keyAt(request().sealed.contentKeys, { contentName: ATTACKED }),
  )) {
    const attacked = request();
    setKeyAt(
      attacked.sealed.contentKeys,
      { contentName: ATTACKED },
      withPoint(keyAt(attacked.sealed.contentKeys, { contentName: ATTACKED }), point),
    );

    const { status, body } = await unlockThroughAdmission(
      processor,
      endpoint,
      attacked,
      publisherRegistration,
    );

    assert.equal(status, 200, `${label}: one bad blob is not a bad request`);
    assert.equal(
      contentKeyMap(body.keys.contentKeys)[ATTACKED],
      undefined,
      `${label}: no key at the attacked coordinate`,
    );
    // The code is asserted and the message is not. `unseal`'s one catch
    // covers the import as well as the decrypt, so what comes back here
    // reads "AES-GCM auth tag mismatch" for a blob that never reached
    // AES-GCM - misleading to anyone debugging from the message, and worth
    // knowing before trusting it.
    assert.equal(errorMap(body.errors)[ATTACKED].error, "unseal_failed", label);
    assert.deepEqual(
      Object.keys(errorMap(body.errors)),
      [ATTACKED],
      `${label}: nothing else failed`,
    );

    // The reader attacked one coordinate and asked for the others honestly.
    // A page has to keep working around a blob that will not open.
    assert.equal(
      contentKeyMap(body.keys.contentKeys)[HONEST],
      contentKeyMap(control.keys.contentKeys)[HONEST],
      `${label}: ${HONEST} opens`,
    );
    assert.deepEqual(
      periodKeyMap(body.keys.periodKeys),
      periodKeyMap(control.keys.periodKeys),
      `${label}: the periodKeys are untouched`,
    );
  }
});

test("the issuer performs no agreement against a point the reader chose", async () => {
  // The file exists for this assertion. An unlock path whose import stopped
  // refusing these bytes would agree the issuer's static private key against
  // the reader's coordinates, get a shared secret out of some other curve's
  // group, and fail the GCM tag a moment later - answering exactly the body
  // the test above asserts, having leaked what the reader came for. The count
  // is the only thing that moves, so it is the only thing that can say no.
  const { endpoint, processor, publisherRegistration, request } = await world();

  for (const { label, point } of badPoints(
    keyAt(request().sealed.contentKeys, { contentName: ATTACKED }),
  )) {
    const attacked = request();
    setKeyAt(
      attacked.sealed.contentKeys,
      { contentName: ATTACKED },
      withPoint(keyAt(attacked.sealed.contentKeys, { contentName: ATTACKED }), point),
    );

    const { count } = await agreements(() =>
      unlockThroughAdmission(processor, endpoint, attacked, publisherRegistration),
    );

    assert.equal(count, 5, `${label}: the five honest coordinates agree, and this one never does`);
  }
});

test("a blob cut off inside the point is refused on its width, ahead of everything", async () => {
  // The one shape that fails before the point is looked at. The blob is
  // shorter than a point, a nonce and a tag, so there is nothing to import
  // and no coordinate to name - and it is reported as the same per-item
  // failure, which is what keeps the page around it working.
  const { endpoint, processor, publisherRegistration, request } = await world();
  const attacked = request();

  const bytes = base64urlDecode(
    keyAt(attacked.sealed.contentKeys, { contentName: ATTACKED }),
  ).subarray(0, 40);
  setKeyAt(attacked.sealed.contentKeys, { contentName: ATTACKED }, base64urlEncode(bytes));

  const { result, count } = await agreements(() =>
    unlockThroughAdmission(processor, endpoint, attacked, publisherRegistration),
  );
  const body = /** @type {any} */ (result).body;

  assert.equal(result.status, 200);
  assert.equal(contentKeyMap(body.keys.contentKeys)[ATTACKED], undefined);
  assert.equal(errorMap(body.errors)[ATTACKED].error, "unseal_failed");
  assert.equal(errorMap(body.errors)[ATTACKED].message, "sealed value could not be opened");
  assert.equal(count, 5, "no agreement for a blob there was nothing to agree against");
});

// @ts-check

import test from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { openContent } from "../../../core-client/openContent.js";
import { encrypt } from "../../../core-shared/aead.js";
import { base64urlEncode, utf8Decode, utf8Encode } from "../../../core-shared/codec.js";
import { DcaError } from "../../../core-shared/errors.js";
import { PERIOD_KEY_PROFILE, periodKeyProfile } from "../../../core-shared/periodKeyProfiles.js";
import { omissionContentKeyResolverFactory } from "../core-client/BoundContentKeyResolver.js";
import { contentAadOctets } from "../../../test-reference/support/contentAadOctets.js";
import { contentKeyWrapNonceOctets } from "../../../test-reference/support/contentKeyWrapNonceOctets.js";
import { OMISSION_BIND_IDENTIFIER, omissionBindAad } from "../core-shared/omissionBind.js";

const CONTENT_NAME = "bodytext";
const ACCESS_GROUP = "premium";
const T = "251023T1400";
const RENDER_ID = base64urlEncode(new Uint8Array([...Array(16).keys()]));

function compactJwt(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "ES256", kid: "publisher-1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

/** @param {any} entry */
function page(entry) {
  return new DcaData({
    version: "1",
    resource: {
      origin: "https://publisher.example",
      resourceId: "123456",
      renderId: RENDER_ID,
    },
    resourceJWT: compactJwt({
      origin: "https://publisher.example",
      resourceId: "123456",
      renderId: RENDER_ID,
    }),
    issuerData: [
      {
        issuerName: "issuer_example",
        keyId: "k1",
        unlockUrl: "https://issuer.example/unlock",
        sealed: {},
      },
    ],
    contentData: [
      {
        contentName: CONTENT_NAME,
        contentType: "text/html",
        nonce: base64urlEncode(new Uint8Array(12)),
        // The pre-adoption carried form. The client ignores it.
        aad: "123456|1|bodytext",
        keys: [entry],
      },
    ],
  });
}

const COORDINATE = Object.freeze({
  renderId: RENDER_ID,
  contentName: CONTENT_NAME,
  accessGroup: ACCESS_GROUP,
  t: T,
});

/**
 * One wrap whose GCM AAD is `aad` and whose nonce derives from `nonceAad`, which
 * defaults to the same bytes, as a conforming producer does.
 *
 * @param {Uint8Array} periodKey @param {number} keyBytes @param {Uint8Array|undefined} aad
 * @param {Uint8Array|undefined} [nonceAad]
 */
async function wrappedEntry(periodKey, keyBytes, aad, nonceAad = aad) {
  const contentKey = new Uint8Array(16).fill(7);
  const nonce = contentKeyWrapNonceOctets({ ...COORDINATE, aad: nonceAad });
  return {
    contentKey,
    entry: {
      accessGroup: ACCESS_GROUP,
      period: T,
      key: base64urlEncode(await encrypt(periodKey, nonce, contentKey, aad, keyBytes)),
    },
  };
}

/** @param {Uint8Array} periodKey */
function cache(periodKey) {
  return {
    put() {},
    candidatesAt() {
      return [periodKey];
    },
    attempted() {},
  };
}

test("content opening authenticates the derived content AAD, not the carried string or the wrap's BIND", async () => {
  const contentKey = new Uint8Array(16).fill(3);
  const data = page({ accessGroup: ACCESS_GROUP, period: T, key: "AAAA" });
  const item = /** @type {import('../../../core-client/DcaData.js').ContentItemView} */ (
    data.contentItemFor(CONTENT_NAME)
  );
  const ciphertext = base64urlEncode(
    await encrypt(
      contentKey,
      new Uint8Array(12),
      utf8Encode("article"),
      contentAadOctets(data.toObject(), CONTENT_NAME),
    ),
  );

  assert.equal(
    utf8Decode(await openContent(contentKey, CONTENT_NAME, ciphertext, item.contentAad)),
    "article",
  );
  const binding = {
    renderId: RENDER_ID,
    contentName: CONTENT_NAME,
    accessGroup: ACCESS_GROUP,
    t: T,
  };
  for (const other of [utf8Encode("123456|1|bodytext"), omissionBindAad(binding)]) {
    await assert.rejects(
      () => openContent(contentKey, CONTENT_NAME, ciphertext, other),
      (error) => error instanceof DcaError && error.code === "decrypt_failed",
    );
  }
});

test("the selected omission composition owns its marker and retains base wraps", async () => {
  for (const profileName of [PERIOD_KEY_PROFILE]) {
    const profile = periodKeyProfile(profileName);
    const periodKey = new Uint8Array(profile.periodKeyBytes).fill(3);
    const binding = {
      renderId: RENDER_ID,
      contentName: CONTENT_NAME,
      accessGroup: ACCESS_GROUP,
      t: T,
    };
    const bound = await wrappedEntry(periodKey, profile.periodKeyBytes, omissionBindAad(binding));
    bound.entry.bind = OMISSION_BIND_IDENTIFIER;

    const selected = omissionContentKeyResolverFactory({ cache: cache(periodKey) });
    assert.deepEqual(
      await selected.contentKeyFor(page(bound.entry), CONTENT_NAME),
      bound.contentKey,
      `${profileName}: the selected recognized marker supplies its extension AAD`,
    );

    const ordinary = await wrappedEntry(periodKey, profile.periodKeyBytes, undefined);
    assert.deepEqual(
      await omissionContentKeyResolverFactory({ cache: cache(periodKey) }).contentKeyFor(
        page(ordinary.entry),
        CONTENT_NAME,
      ),
      ordinary.contentKey,
      `${profileName}: an unmarked base entry remains usable in the selected mixed composition`,
    );

    const unknown = { ...ordinary.entry, bind: "unknown-wrap-v1" };
    assert.equal(
      await omissionContentKeyResolverFactory({ cache: cache(periodKey) }).contentKeyFor(
        page(unknown),
        CONTENT_NAME,
      ),
      null,
      `${profileName}: an unknown marker is never retried as the base wrap`,
    );

    assert.equal(
      await new ContentKeyResolver({ cache: cache(periodKey) }).contentKeyFor(
        page(bound.entry),
        CONTENT_NAME,
      ),
      null,
      `${profileName}: a recognized marker is refused when its extension is not selected`,
    );
  }
});

test("a bound wrap opens only under the omission transcript in both its nonce and GCM", async () => {
  const periodKey = new Uint8Array(16).fill(3);
  const aad = omissionBindAad(COORDINATE);
  const resolverFor = () => omissionContentKeyResolverFactory({ cache: cache(periodKey) });

  // GCM under the omission AAD, nonce from the ordinary transcript: a reader
  // that left the selected AAD out of the nonce would open this.
  // Empty selected AAD is the ordinary transcript.
  const halfBound = await wrappedEntry(periodKey, 16, aad, new Uint8Array(0));
  halfBound.entry.bind = OMISSION_BIND_IDENTIFIER;
  assert.equal(await resolverFor().contentKeyFor(page(halfBound.entry), CONTENT_NAME), null);

  // The nonce includes the omission AAD, but GCM does not: a reader that
  // omitted the selected AAD from GCM would open this.
  const noGcmAad = await wrappedEntry(periodKey, 16, undefined, aad);
  noGcmAad.entry.bind = OMISSION_BIND_IDENTIFIER;
  assert.equal(await resolverFor().contentKeyFor(page(noGcmAad.entry), CONTENT_NAME), null);

  // The marker stripped from a bound wrap selects the ordinary transcript, which
  // the wrap was not made under.
  const bound = await wrappedEntry(periodKey, 16, aad);
  const stripped = { ...bound.entry };
  assert.equal(await resolverFor().contentKeyFor(page(stripped), CONTENT_NAME), null);

  // A marker added to an ordinary wrap selects the omission transcript instead.
  const ordinary = await wrappedEntry(periodKey, 16, undefined);
  const marked = { ...ordinary.entry, bind: OMISSION_BIND_IDENTIFIER };
  assert.equal(await resolverFor().contentKeyFor(page(marked), CONTENT_NAME), null);

  // A carried nonce on the bound wrap changes nothing.
  bound.entry.bind = OMISSION_BIND_IDENTIFIER;
  for (const nonce of [base64urlEncode(new Uint8Array(12)), 7, null]) {
    assert.deepEqual(
      await resolverFor().contentKeyFor(page({ ...bound.entry, nonce }), CONTENT_NAME),
      bound.contentKey,
    );
  }
});

test("a tampered bound wrap leaves a valid ordinary sibling to open the item", async () => {
  const periodKey = new Uint8Array(16).fill(3);
  const bound = await wrappedEntry(periodKey, 16, omissionBindAad(COORDINATE));
  const ordinary = await wrappedEntry(periodKey, 16, undefined);
  const data = page(null);
  /** @type {any} */ (
    data
      .toObject()
      .contentData.find((/** @type {any} */ record) => record.contentName === CONTENT_NAME)
  ).keys = [
    { ...bound.entry, bind: OMISSION_BIND_IDENTIFIER, period: "251023T1500" },
    { ...bound.entry, bind: "unknown-wrap-v1" },
    ordinary.entry,
  ];
  assert.deepEqual(
    await omissionContentKeyResolverFactory({ cache: cache(periodKey) }).contentKeyFor(
      data,
      CONTENT_NAME,
    ),
    ordinary.contentKey,
  );
});

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
    issuerData: {
      issuer_example: {
        keyId: "k1",
        unlockUrl: "https://issuer.example/unlock",
        sealed: {},
      },
    },
    contentData: {
      [CONTENT_NAME]: {
        contentType: "text/html",
        nonce: base64urlEncode(new Uint8Array(12)),
        // The pre-adoption carried form. The client ignores it.
        aad: "123456|1|bodytext",
        keys: { [ACCESS_GROUP]: [entry] },
      },
    },
  });
}

/** @param {Uint8Array} periodKey @param {number} keyBytes @param {Uint8Array|undefined} aad */
async function wrappedEntry(periodKey, keyBytes, aad) {
  const contentKey = new Uint8Array(16).fill(7);
  const nonce = new Uint8Array(12).fill(4);
  return {
    contentKey,
    entry: {
      t: T,
      nonce: base64urlEncode(nonce),
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
  const data = page({ t: T, nonce: base64urlEncode(new Uint8Array(12)), key: "AAAA" });
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

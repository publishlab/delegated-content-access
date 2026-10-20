import test from "node:test";
import assert from "node:assert/strict";
import { actorWorld } from "../../demo/scenarios/world.js";
import { PublisherRegistrations } from "../../demo/support/PublisherRegistrations.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { Client } from "../../test-lib/harnesses/client.js";
import {
  DOMAIN,
  ISSUER_NAME,
  UNLOCK_URL,
  CONTENT_NAME,
  ARTICLES,
} from "../../demo/scenarios/fixtures.js";
import { base64urlEncode, utf8Encode, utf8Decode } from "../../core-shared/codec.js";

test("real registration replacement: old-only, overlap, retirement, retained plaintext", async () => {
  const oldKid = "7";
  const newKid = "07";
  const origin = `https://${DOMAIN}`;
  let active;
  const calls = { registration: 0, policy: 0, verify: 0, envelopeOpen: 0 };
  const policy = new AllowAllPolicy();
  const provider = {
    get(kid) {
      calls.registration++;
      const selected = active?.get(kid);
      return selected;
    },
  };
  const stage = await actorWorld({
    signingKids: { [DOMAIN]: [oldKid, newKid] },
    signingKid: oldKid,
    periodKeySupply: null,
    periodKeyInput: false,
    primary: {
      publisherRegistrations: provider,
      accessPolicy: {
        decide(...args) {
          calls.policy++;
          return policy.decide(...args);
        },
      },
    },
  });
  // Use the real provisioner's key entries and the same opening-key scope.
  const oldEntry = stage.publisherRegistrations.get(oldKid);
  const newEntry = stage.publisherRegistrations.get(newKid);
  assert.equal(oldEntry.openingKeys, newEntry.openingKeys);
  assert.notEqual(oldEntry.publicKey, newEntry.publicKey);
  active = new PublisherRegistrations([oldEntry]);
  const oldPage = (await stage.render("A")).asJson();
  stage.publisher.rotateSigningKey(newKid);
  const newPage = (await stage.render("B")).asJson();

  // Observe stock WebCrypto, preserving its inputs/results. Only POST spans are
  // counted: client content decrypts and publisher encryption are excluded.
  const subtle = globalThis.crypto.subtle;
  const verify = subtle.verify;
  const decrypt = subtle.decrypt;
  let observing = false;
  subtle.verify = function (...args) {
    if (observing) calls.verify++;
    return Reflect.apply(verify, this, args);
  };
  subtle.decrypt = function (...args) {
    if (observing) calls.envelopeOpen++;
    return Reflect.apply(decrypt, this, args);
  };
  async function request(label, page, expected, expectedCode, rewrite) {
    const client = new Client({ publisherOrigin: origin, relayPeriodKeys: false });
    const data = client.parse(page);
    const body = client.buildRequest(data, ISSUER_NAME, [CONTENT_NAME]);
    if (rewrite) rewrite(body);
    const before = { ...calls, openingKey: stage.keyStores.primary.reachCount };
    observing = true;
    let answer;
    try {
      answer = await stage.network.post(UNLOCK_URL, body, { origin });
    } finally {
      observing = false;
    }
    const after = { ...calls, openingKey: stage.keyStores.primary.reachCount };
    const delta = Object.fromEntries(Object.keys(after).map((k) => [k, after[k] - before[k]]));
    assert.equal(answer.status, expected === null ? 400 : 200, label);
    if (expected === null) {
      assert.equal(answer.body.error, expectedCode, label);
      assert.equal(answer.body.keys, undefined, label);
      assert.equal(delta.policy, 0, label);
      assert.equal(delta.openingKey, 0, label);
      assert.equal(delta.envelopeOpen, 0, label);
      if (expectedCode !== "bad_signature") assert.equal(delta.verify, 0, label);
      await assert.rejects(() =>
        client.decrypt(data, CONTENT_NAME, client.extract(page, CONTENT_NAME)),
      );
    } else {
      assert.equal(delta.registration, 1, label);
      assert.equal(delta.policy, 1, label);
      assert.equal(delta.openingKey, 1, label);
      assert.equal(delta.envelopeOpen, 1, label);
      assert.equal(delta.verify, 1, `${label}: verified claims are reused by the engine`);
      await client.applyResponse(data, ISSUER_NAME, answer.body);
      assert.equal(
        utf8Decode(await client.decrypt(data, CONTENT_NAME, client.extract(page, CONTENT_NAME))),
        expected,
      );
    }
    return { client, data, page, answer };
  }
  try {
    const retained = await request("old-only: old opens", oldPage, ARTICLES.A);
    await request("old-only: replacement inactive", newPage, null, "unknown_publisher_key");
    active = new PublisherRegistrations([oldEntry, newEntry]);
    await request("overlap: old opens", oldPage, ARTICLES.A);
    await request("overlap: replacement opens", newPage, ARTICLES.B);
    active = new PublisherRegistrations([newEntry]);
    assert.equal(active.get(oldKid), undefined);
    await request("retired: old refused", oldPage, null, "unknown_publisher_key");
    await request("retired: replacement opens", newPage, ARTICLES.B);
    await request("retired: repeat old refused", oldPage, null, "unknown_publisher_key");
    const rewriteKid = (kid) => (body) => {
      const [, payload, signature] = body.resourceJWT.split(".");
      body.resourceJWT = `${base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid })))}.${payload}.${signature}`;
    };
    await request(
      "retired: relabel old as replacement",
      oldPage,
      null,
      "bad_signature",
      rewriteKid(newKid),
    );
    await request("retired: numeric kid never coerces", newPage, null, "bad_jwt", rewriteKid(7));
    await request(
      "retired: whitespace kid never trims",
      newPage,
      null,
      "unknown_publisher_key",
      rewriteKid("07 "),
    );
    const beforeRetained = { ...calls, openingKey: stage.keyStores.primary.reachCount };
    assert.equal(
      utf8Decode(
        await retained.client.decrypt(
          retained.data,
          CONTENT_NAME,
          retained.client.extract(retained.page, CONTENT_NAME),
        ),
      ),
      ARTICLES.A,
    );
    assert.deepEqual({ ...calls, openingKey: stage.keyStores.primary.reachCount }, beforeRetained);
  } finally {
    subtle.verify = verify;
    subtle.decrypt = decrypt;
  }
});

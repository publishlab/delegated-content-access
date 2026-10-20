// @ts-check
//
// Capture before the first await (docs/spec--content-protection.md Section 5.1):
// the client captures renderId, contentType and contentEncodings once,
// builds AAD from renderId and name, and authenticates, picks decoders and hands
// off the type from that one capture. These tests edit the delivery while an
// unlock or a key lookup is suspended and check all three uses at once, through
// the public `createDeliveryClient` and through the demo `PageLoad`, which reads
// a live `DcaData`.
//
// The item under test carries two invented layers. Its decoders record the order
// they ran in, so a reread encoding list shows up as a different decoder trail
// even where the plaintext would come out the same.

import test from "node:test";
import assert from "node:assert/strict";
import { Storage } from "../../demo/actors/Storage.js";
import { Network } from "../../demo/actors/Network.js";
import { Browser } from "../../demo/actors/Browser.js";
import { Clock } from "../../demo/actors/Clock.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import {
  AT,
  BODY,
  DECODERS,
  ENCODED,
  ISSUER,
  LOCKED,
  PUB,
  UNLOCK_URL,
  encodedItem,
  text,
  world,
} from "./derived-content-aad--support.js";

/** @param {string[]} log */
function recordingDecoders(log) {
  return {
    "x-reverse": (/** @type {Uint8Array} */ bytes) => {
      log.push("x-reverse");
      return DECODERS["x-reverse"](bytes);
    },
    "x-identity": (/** @type {Uint8Array} */ bytes) => {
      log.push("x-identity");
      return DECODERS["x-identity"](bytes);
    },
  };
}

/** A storage that suspends the first operation after `arm()` until `release()`. */
function gatedStorage() {
  let armed = false;
  /** @type {() => void} */
  let entered = () => {};
  /** @type {() => void} */
  let release = () => {};
  const hit = new Promise((resolve) => {
    entered = () => resolve("suspended");
  });
  const released = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  return {
    storage: new Storage({
      gate: async () => {
        if (!armed) return;
        armed = false;
        entered();
        await released;
      },
    }),
    arm: () => {
      armed = true;
    },
    hit,
    release,
  };
}

/**
 * Every metadata edit the test makes at the suspension point: the item's type,
 * its encoding list, its nonce, and the delivery's token, each swapped for a
 * well-formed value that would change the AAD or the decoding.
 *
 * @param {any} dcaData
 * @param {string} otherToken - a valid-shaped token of another render
 */
function editItem(dcaData, otherToken) {
  const record = dcaData.contentData[ENCODED.name];
  record.contentType = "text/plain";
  record.contentEncodings = ["x-identity"];
  record.nonce = dcaData.contentData[LOCKED.name].nonce;
  dcaData.resourceJWT = otherToken;
}

async function setup() {
  const w = await world({ route: "period" });
  const delivered = await w.render({ items: [BODY, LOCKED, encodedItem()] });
  const other = await w.render({ items: [BODY] });
  return { w, delivered, otherToken: other.dcaData.resourceJWT };
}

test("the host's page object edited while the unlock awaits changes nothing the client opens with", async () => {
  const { w, delivered, otherToken } = await setup();
  const log = /** @type {string[]} */ ([]);
  let edits = 0;
  const client = w.client(delivered, {
    contentDecoders: recordingDecoders(log),
    hold: () => {
      editItem(delivered.dcaData, otherToken);
      edits += 1;
    },
  });
  const opened = await client.open(ENCODED.name);
  assert.equal(edits, 1, "the edit landed while the unlock was suspended");
  assert.equal(text(opened.bytes), ENCODED.plaintext);
  assert.equal(opened.contentType, ENCODED.contentType, "the handed-off type is the captured one");
  assert.deepEqual(log, ["x-identity", "x-reverse"], "decoders follow the captured list");
});

test("createDeliveryClient: the captured item is decrypted, decoded and handed off as the key resolves", async () => {
  const { w, delivered, otherToken } = await setup();
  const gate = gatedStorage();
  const log = /** @type {string[]} */ ([]);
  const client = w.client(delivered, {
    storage: gate.storage,
    contentDecoders: recordingDecoders(log),
  });
  // A real period grant, filed in the gated storage.
  assert.equal(text((await client.open(BODY.name)).bytes), BODY.value);

  gate.arm();
  const opening = client.openLocal(ENCODED.name);
  assert.equal(
    await Promise.race([gate.hit, opening.then(() => "finished")]),
    "suspended",
    "the key lookup suspended on storage",
  );
  // Both copies a host can reach: the page object it handed the reader, and
  // the client's own delivery copy.
  editItem(delivered.dcaData, otherToken);
  editItem(client.dcaData.toObject(), otherToken);
  gate.release();

  const opened = await opening;
  assert.equal(text(opened.bytes), ENCODED.plaintext);
  assert.equal(opened.contentType, ENCODED.contentType);
  assert.deepEqual(log, ["x-identity", "x-reverse"]);
});

test("createDeliveryClient: open uses the item it captured before the unlock awaited", async () => {
  // `open` captures the item, awaits the unlock, then opens that same capture
  // (content protection Section 5.1): an item edit during the unlock changes
  // nothing. A changed token can still meet the response association, which
  // refuses an answer for another page before any key arrives; that refusal
  // opens nothing. No edit may turn the opening into a decrypt failure.
  /** @type {[string, (dcaData: any, otherToken: string) => void, string[]][]} */
  const edits = [
    [
      "item fields",
      (dcaData) => {
        const record = dcaData.contentData[ENCODED.name];
        record.contentType = "text/plain";
        record.contentEncodings = ["x-identity"];
        record.nonce = dcaData.contentData[LOCKED.name].nonce;
      },
      [],
    ],
    [
      "token",
      (dcaData, otherToken) => {
        dcaData.resourceJWT = otherToken;
      },
      ["bad_config"],
    ],
  ];
  for (const [what, edit, codes] of edits) {
    const { w, delivered, otherToken } = await setup();
    const log = /** @type {string[]} */ ([]);
    /** @type {any} */
    let client;
    client = w.client(delivered, {
      contentDecoders: recordingDecoders(log),
      hold: () => edit(client.dcaData.toObject(), otherToken),
    });
    /** @type {any} */
    let outcome;
    try {
      outcome = await client.open(ENCODED.name);
    } catch (error) {
      outcome = error;
    }
    if (outcome instanceof Error) {
      assert.ok(codes.includes(/** @type {any} */ (outcome).code), `${what}: ${outcome}`);
      assert.deepEqual(log, [], `${what}: no decoder saw unauthenticated bytes`);
    } else {
      assert.equal(text(outcome.bytes), ENCODED.plaintext, what);
      assert.equal(outcome.contentType, ENCODED.contentType, what);
      assert.deepEqual(log, ["x-identity", "x-reverse"], what);
    }
  }
});

test("a failed item releases no plaintext and runs no decoder; its valid siblings still open", async () => {
  const { w, delivered } = await setup();
  // Transit corruption must fail authentication before any decoder sees bytes.
  delivered.sealedContent[ENCODED.name] = "AAAA" + delivered.sealedContent[ENCODED.name].slice(4);
  const log = /** @type {string[]} */ ([]);
  const client = w.client(delivered, { contentDecoders: recordingDecoders(log) });

  const walk = await client.unlockRoutes(
    [ENCODED.name, BODY.name, LOCKED.name],
    [{ issuerName: ISSUER, unlockUrl: UNLOCK_URL }],
  );
  assert.deepEqual(walk.missing, [ENCODED.name], "only the edited item stays locked");
  assert.deepEqual(walk.failed, []);

  /** @type {unknown} */
  let released = null;
  await assert.rejects(
    (async () => {
      released = await client.openLocal(ENCODED.name);
    })(),
    { code: "decrypt_failed" },
  );
  assert.equal(released, null);
  assert.deepEqual(log, [], "no decoder ran on the failed item");

  assert.equal(text((await client.openLocal(BODY.name)).bytes), BODY.value);
  assert.equal(text((await client.openLocal(LOCKED.name)).bytes), LOCKED.value);
});

test("demo PageLoad: a live page edited while the key resolves opens with the captured item", async () => {
  const { w, delivered, otherToken } = await setup();
  const clock = new Clock(AT);
  const network = new Network({ clock });
  network.serve(UNLOCK_URL, (/** @type {any} */ request) =>
    unlockThroughAdmission(w.processor, w.endpoint, request, w.registration),
  );
  const gate = gatedStorage();
  const log = /** @type {string[]} */ ([]);
  const browser = new Browser({
    clock,
    network,
    storage: gate.storage,
    issuers: [{ issuerName: ISSUER, unlockUrl: UNLOCK_URL }],
    relayPeriodKeys: true,
    persistRawPeriodKeys: true,
    contentDecoders: recordingDecoders(log),
  });
  const markup = writeMarkupDelivery(delivered);
  // One load takes the period grant; a second load of the same page opens from
  // the browser's retained cache, which reads the gated storage.
  await browser.load(domOver(markup, { publisherOrigin: PUB })).unlock();
  const load = browser.load(domOver(markup, { publisherOrigin: PUB }));

  gate.arm();
  const opening = load.open(ENCODED.name);
  assert.equal(await Promise.race([gate.hit, opening.then(() => "finished")]), "suspended");
  // The load reads this object live; nothing copied it.
  editItem(load.dcaData, otherToken);
  gate.release();

  const opened = await opening;
  assert.equal(opened.error, null);
  assert.equal(text(/** @type {Uint8Array} */ (opened.bytes)), ENCODED.plaintext);
  assert.deepEqual(log, ["x-identity", "x-reverse"]);

  // A later capture uses the edited processing metadata. Restoring the
  // original token restores its renderId, so authentication succeeds.
  load.dcaData.resourceJWT = delivered.dcaData.resourceJWT;
  const after = await load.open(ENCODED.name);
  assert.equal(after.error, null);
  assert.equal(text(after.bytes), [...ENCODED.plaintext].reverse().join(""));
  assert.deepEqual(
    log,
    ["x-identity", "x-reverse", "x-identity"],
    "the edited encoding list selects processing",
  );
  const sibling = await load.open(LOCKED.name);
  assert.equal(sibling.error, null, "a sibling the edit did not touch still opens");
});

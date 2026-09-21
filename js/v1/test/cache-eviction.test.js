//
// What a full cache costs, and what it cannot cost. Eviction is the one thing
// that takes a periodKey away, and the article it was cut for is still readable
// afterwards: a render carries its own sealed keys, so the client goes back to
// the issuer with what the page has always held and the issuer answers it
// without ever reading a `t`. A full cache costs one unlock, and never a page
// that cannot be opened.
//
// The other half here is what the client asks for when it holds some of what a
// page needs: the request carries the items the trial unwrap could not open and
// nothing else, so the blobs already resolved never leave the browser.
//
// Two loads of one article across the eviction, deliberately. A contentKey is
// good for one render and dies with the load that fetched it, so a second load
// meets the page with the cache alone - which is what makes the miss real
// rather than an artefact of one resolver remembering.
//
// Already elsewhere and not repeated here: `maxEntries + 1`, oldest `t` first,
// no eviction on a failed trial and nothing expiring by age are
// test/storage-concurrency.test.js; dedup by `t` and the overwrite of a
// re-arriving coordinate are that file and test-reference/adapter-client/periodkeys.test.js; a
// contentKey delivery never reaching the cache, and a full hit costing no
// unlock, are test-reference/adapter-client/periodkeys.test.js.
//
// Pinned: one publisher, one issuer, direct transport, grant-all policy, ECDH
// P-256 sealing. Only the publisher's clock moves.

import test from "node:test";
import assert from "node:assert/strict";

import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { Client } from "../test-lib/harnesses/client.js";
import { Storage } from "../demo/actors/Storage.js";
import { decrypt, encrypt } from "../core-shared/aead.js";
import { utf8Decode } from "../core-shared/codec.js";
import { directWorld } from "../demo/scenarios/world.js";
import {
  ACCESS_GROUP as PREMIUM,
  ARTICLES,
  DOMAIN,
  ISSUER_NAME,
} from "../demo/scenarios/fixtures.js";
import { countingEndpoint } from "../test-lib/harnesses/issuer-endpoint.js";
import { held } from "../test-lib/helpers/inspect.js";
import { periodKey } from "../test-reference/support/keys.js";

const HOUR = 60 * 60 * 1000;

/**
 * The publisher these renders name, folded the way the resolver folds it before
 * the cache files a key. A family a full read populates is this publisher and
 * then its accessGroup, so the coordinates a hit reports carry it.
 */
const PUB = `https://${DOMAIN}`;

/**
 * The coordinate one put files under. Every put here is on the exact-period
 * profile a caller naming none is on. The cache partitions by publisher and
 * access group.
 *
 * @param {string} accessGroup
 * @param {string} t
 * @returns {string}
 */
function coordinate(accessGroup, t) {
  return `${PUB}|${accessGroup}/${t}`;
}

/**
 * The second family, and this file's own rather than the shared free one. The
 * tie at the bottom of the file is broken on the family name where the periods
 * are equal, so a second family sorting ahead of `premium` would swap which of
 * the two the eviction takes and leave the surviving pair in one family.
 */
const SUBSCRIBER = "subscriber";

const T14 = "251023T14";
const T15 = "251023T15";
const T16 = "251023T16";
const T17 = "251023T17";
const T18 = "251023T18";
const T19 = "251023T19";

const VOTE = '{"vote":{"for":7,"against":2},"passed":true}';

/**
 * The item beside the bodytext, which is what makes a hit partial: one family
 * in the cache opens one of the two items and says nothing about the other.
 * Its contentType and its family are both spelled out - what `article()` fills
 * in is the suite's `text/html` and the free family, and this item is neither.
 */
const LOCKED_DATA = {
  name: "locked-data",
  value: VOTE,
  contentType: "application/json",
  accessGroups: [SUBSCRIBER],
};

/**
 * One reader over three periods, coming back at the end to the article they
 * started with. Capacity is the only thing that changes between runs, which is
 * what makes it the cause of everything that differs in the result.
 *
 * @param {number} maxEntries
 * @returns {Promise<{ before: string[], covered: string[], missing: string[], reunlock: any, calls: number, held: string[], plaintext: string }>}
 */
async function story(maxEntries) {
  const { clock, publisherRegistration, render } = await directWorld();

  const cache = new PeriodKeyCache({ maxEntries });
  const endpoint = countingEndpoint(publisherRegistration);

  /**
   * One page load: parse, ask for what it cannot open, keep what came back.
   * A load of its own per article, because that is what a reader moving
   * through a site does.
   *
   * @param {any} page
   * @returns {Promise<{ unsealer: Client, dcaData: any, body: any }>}
   */
  async function readThrough(page) {
    const unsealer = new Client({ cache, publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);
    const { missing } = await unsealer.resolve(dcaData, ["bodytext"]);

    let body;
    if (missing.length > 0) {
      ({ body } = await endpoint.unlock(unsealer.buildRequest(dcaData, ISSUER_NAME, missing)));
      await unsealer.applyResponse(dcaData, ISSUER_NAME, body);
    }
    return { unsealer, dcaData, body };
  }

  // The article that will be read again at the end, rendered and unlocked in
  // the period it was made in.
  const recorded = await render("A", { resourceId: "123456" });
  await readThrough(recorded);

  // Two more periods of reading. Each render names its own period and the one
  // after it, so each unlock brings back two keys the cache has never held.
  for (const [label, resourceId] of [
    ["B", "123457"],
    ["C", "123458"],
  ]) {
    clock.advance(2 * HOUR);
    await readThrough(await render(/** @type {'B'|'C'} */ (label), { resourceId }));
  }

  const before = await held(cache);

  // Back to the first article, in a load of its own. The contentKey that
  // opened it the first time died with that load; only the cache crossed.
  const again = new Client({ cache, publisherOrigin: PUB });
  const back = again.parse(recorded);
  const { covered, missing } = await again.resolve(back, ["bodytext"]);

  let reunlock;
  if (missing.length > 0) {
    ({ body: reunlock } = await endpoint.unlock(again.buildRequest(back, ISSUER_NAME, missing)));
    await again.applyResponse(back, ISSUER_NAME, reunlock);
  }

  return {
    before,
    covered,
    missing,
    reunlock,
    calls: endpoint.calls.count,
    held: await held(cache),
    plaintext: utf8Decode(
      await again.decrypt(back, "bodytext", again.extract(recorded, "bodytext")),
    ),
  };
}

test("an article whose periodKeys were evicted still unlocks from the keys it shipped with", async () => {
  // Four entries is two unlocks' worth, so the third one pushes the first
  // article's periods out.
  const run = await story(4);

  assert.deepEqual(
    run.before,
    [T19, T18, T17, T16],
    "the two periods the first article was read under are gone",
  );
  assert.deepEqual(run.covered, []);
  assert.deepEqual(run.missing, ["bodytext"], "nothing held opens it any more");

  // The page never lost anything: the sealed blobs it was rendered with are
  // still on it, and the issuer answers them without reading a `t`.
  assert.deepEqual(
    Object.keys(run.reunlock.keys.periodKeys[PREMIUM]),
    [T14, T15],
    "the periods the page was rendered with, handed back as they are",
  );
  assert.deepEqual(Object.keys(run.reunlock.keys.contentKeys), ["bodytext"]);
  assert.equal(run.reunlock.errors, undefined);

  assert.equal(run.plaintext, ARTICLES.A, "and it opens");
  assert.equal(run.calls, 4, "what a full cache costs is one unlock, not a page");

  // The keys that came back are older than everything held, so a cache with
  // no room takes them straight back out - an old article does not displace
  // the periods the reader is actually in. What opened the page is the
  // contentKey of that same answer.
  assert.deepEqual(run.held, [T19, T18, T17, T16]);
});

test("the same reader with room never lost them, so the re-read costs nothing", async () => {
  // Everything else about the run is identical; only the capacity differs.
  const run = await story(8);

  assert.deepEqual(run.before, [T19, T18, T17, T16, T15, T14]);
  assert.deepEqual(
    run.covered,
    ["bodytext"],
    "the periods the article was rendered in are still held",
  );
  assert.deepEqual(run.missing, []);
  assert.equal(run.reunlock, undefined, "so there was nothing to ask anyone");
  assert.equal(run.calls, 3, "size is the only thing that took the keys away");
  assert.equal(run.plaintext, ARTICLES.A);
  assert.deepEqual(run.held, [T19, T18, T17, T16, T15, T14]);
});

test("a partial hit asks the issuer for the item it could not open, and for nothing else", async () => {
  const { publisherRegistration, render } = await directWorld();

  const cache = new PeriodKeyCache();
  const endpoint = countingEndpoint(publisherRegistration);

  // One article with a body and nothing else. Its unlock fills the premium
  // family and leaves the subscriber family empty.
  const first = new Client({ cache, publisherOrigin: PUB });
  const one = first.parse(await render("A", { resourceId: "123456" }));
  await first.applyResponse(
    one,
    ISSUER_NAME,
    (await endpoint.unlock(first.buildRequest(one, ISSUER_NAME, ["bodytext"]))).body,
  );

  assert.deepEqual(await held(cache, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
  ]);
  assert.equal(endpoint.calls.count, 1);

  // The next article of the same period carries a second item, under a group
  // the reader holds no key for.
  const second = new Client({ cache, publisherOrigin: PUB });
  const twoPage = await render("B", { resourceId: "123457", items: [LOCKED_DATA] });
  const two = second.parse(twoPage);

  const { covered, missing } = await second.resolve(two, ["bodytext", "locked-data"]);
  assert.deepEqual(covered, ["bodytext"], "the cached premium key opens the body");
  assert.deepEqual(missing, ["locked-data"], "and says nothing about the other group");

  // What crosses the wire is the missing item and its group. The bodytext
  // blob and the whole premium family stay in the browser: an issuer that is
  // not asked cannot count the view, and a blob not sent cannot be replayed.
  const request = second.buildRequest(two, ISSUER_NAME, missing);
  assert.deepEqual(Object.keys(request.sealed.contentKeys), ["locked-data"]);
  assert.deepEqual(Object.keys(/** @type {any} */ (request.sealed.periodKeys)), [SUBSCRIBER]);

  const { status, body } = await endpoint.unlock(request);
  assert.equal(status, 200);
  assert.deepEqual(
    Object.keys(body.keys.contentKeys),
    ["locked-data"],
    "a subset is legal, and is answered as one",
  );
  assert.deepEqual(Object.keys(body.keys.periodKeys), [SUBSCRIBER]);

  await second.applyResponse(two, ISSUER_NAME, body);
  assert.equal(endpoint.calls.count, 2, "the covered item cost nothing");

  assert.equal(
    utf8Decode(await second.decrypt(two, "bodytext", second.extract(twoPage, "bodytext"))),
    ARTICLES.B,
  );
  assert.equal(
    utf8Decode(await second.decrypt(two, "locked-data", second.extract(twoPage, "locked-data"))),
    VOTE,
  );

  assert.deepEqual(await held(cache, "coordinate"), [
    coordinate(PREMIUM, T15),
    coordinate(PREMIUM, T14),
    coordinate(SUBSCRIBER, T15),
    coordinate(SUBSCRIBER, T14),
  ]);

  // Both families held now, so a third article of the period is a full hit:
  // zero calls, and the page opens out of the cache alone.
  const third = new Client({ cache, publisherOrigin: PUB });
  const threePage = await render("D", { resourceId: "123458", items: [LOCKED_DATA] });
  const three = third.parse(threePage);

  assert.deepEqual(await third.resolve(three, ["bodytext", "locked-data"]), {
    covered: ["bodytext", "locked-data"],
    missing: [],
  });
  assert.equal(
    utf8Decode(await third.decrypt(three, "bodytext", third.extract(threePage, "bodytext"))),
    ARTICLES.D,
  );
  assert.equal(endpoint.calls.count, 2, "a full hit is an article nobody was asked about");
});

test("at capacity the oldest t goes whatever family holds it, and a tie goes the same way twice", async () => {
  // Two families holding the same period, and one entry too many. Something
  // has to go, and which one cannot depend on the order the two arrived in:
  // two runs of one scenario would report differently, and a family would
  // outlive another by nothing but insertion order. Eviction takes the
  // smallest `(t, accessGroup)` there is - the period first, and the family
  // name only where the periods are equal.
  for (const order of [
    [SUBSCRIBER, PREMIUM],
    [PREMIUM, SUBSCRIBER],
  ]) {
    for (const cache of [
      new PeriodKeyCache({ maxEntries: 2 }),
      new PeriodKeyCache({ maxEntries: 2, storage: new Storage() }),
    ]) {
      await cache.put(/** @type {string} */ (order[0]), T14, periodKey(1), { publisher: PUB });
      await cache.put(/** @type {string} */ (order[1]), T14, periodKey(2), { publisher: PUB });
      assert.deepEqual(await held(cache, "coordinate"), [
        coordinate(PREMIUM, T14),
        coordinate(SUBSCRIBER, T14),
      ]);

      await cache.put(PREMIUM, T15, periodKey(3), { publisher: PUB });
      assert.deepEqual(
        await held(cache, "coordinate"),
        [coordinate(PREMIUM, T15), coordinate(SUBSCRIBER, T14)],
        `the tie at ${T14} goes to the first accessGroup, whichever of them arrived first`,
      );
      assert.deepEqual(
        (await cache.candidatesAt(PREMIUM, T15, { publisher: PUB })).map(
          (/** @type {any} */ key) => key[0],
        ),
        [3],
        "and the arriving key is never the one that goes",
      );
    }
  }
});

test("two publishers reading one logical client never collide on equal accessGroup and t", async () => {
  // One client reads two papers. Both sell a tier they call `premium`, and a
  // render of each falls in the same hour, so the accessGroup and the period
  // label are equal across them. Nothing but the publisher tells the two keys
  // apart, and the family coordinate has to carry it: without a publisher
  // segment both keys land in one family at one `t`, the second overwrites the
  // first, and the paper the client never subscribed to hands over the other
  // paper's key. This is the resolver's own put/candidates path - it files a
  // delivered key under the page's canonical origin and reads candidates back
  // under it.
  const PUB_A = "https://www.news-site.example";
  const PUB_B = "https://www.other-paper.example";

  for (const cache of [new PeriodKeyCache(), new PeriodKeyCache({ storage: new Storage() })]) {
    await cache.put(PREMIUM, T14, periodKey(1), { publisher: PUB_A });
    await cache.put(PREMIUM, T14, periodKey(2), { publisher: PUB_B });

    assert.deepEqual(
      (await cache.candidatesAt(PREMIUM, T14, { publisher: PUB_A })).map(
        (/** @type {any} */ key) => key[0],
      ),
      [1],
      "the first paper keeps its own key across the second paper writing the same coordinate",
    );
    assert.deepEqual(
      (await cache.candidatesAt(PREMIUM, T14, { publisher: PUB_B })).map(
        (/** @type {any} */ key) => key[0],
      ),
      [2],
      "and the second paper never reads the first paper's key back",
    );
  }
});

test("an old and a new render at one coordinate both keep opening, across a periodKey-family rotation", async () => {
  // An exact period-key rotation lands new key bytes on a coordinate the client
  // already holds a key at: the accessGroup and the period label are equal, and
  // only the bytes behind them differ. The render sealed under the old family
  // and the one sealed under the new must both stay openable while the two
  // coexist - so the cache keeps non-interchangeable keys at a coordinate as
  // rival candidates rather than overwriting one with the other. The older key
  // arriving first and the newer one second is exactly the order a rotation
  // delivers them in, and the second put must not take the first render dark.
  const oldKey = periodKey(1);
  const newKey = periodKey(2);

  // Each render's content, sealed under its own period key at the shared
  // coordinate. A wrong key is an AES-GCM tag failure, never silent garbage, so
  // trialling the candidates is what tells the two renders apart.
  const oldNonce = new Uint8Array(12).fill(1);
  const newNonce = new Uint8Array(12).fill(2);
  const oldContent = new Uint8Array([0x0a, 0x0b, 0x0c]);
  const newContent = new Uint8Array([0x1a, 0x1b, 0x1c]);
  const oldSealed = await encrypt(oldKey, oldNonce, oldContent);
  const newSealed = await encrypt(newKey, newNonce, newContent);

  /**
   * The plaintext the first candidate opens a sealed blob to, or null when
   * none of them does - the trial unwrap the resolver runs, in miniature.
   *
   * @param {any[]} candidates
   * @param {Uint8Array} nonce
   * @param {Uint8Array} sealed
   * @returns {Promise<Uint8Array|null>}
   */
  async function openWith(candidates, nonce, sealed) {
    for (const candidate of candidates) {
      try {
        return await decrypt(candidate, nonce, sealed);
      } catch {
        continue;
      }
    }
    return null;
  }

  for (const cache of [new PeriodKeyCache(), new PeriodKeyCache({ storage: new Storage() })]) {
    // The old render's key, then the new one over the same coordinate.
    await cache.put(PREMIUM, T14, oldKey, { publisher: PUB });
    await cache.put(PREMIUM, T14, newKey, { publisher: PUB });

    const candidates = await cache.candidatesAt(PREMIUM, T14, { publisher: PUB });
    assert.deepEqual(
      candidates.map((/** @type {any} */ key) => key[0]).sort(),
      [1, 2],
      "both key families coexist at the one coordinate",
    );

    assert.deepEqual(
      [...((await openWith(candidates, oldNonce, oldSealed)) ?? [])],
      [...oldContent],
      "the render sealed under the old family still opens",
    );
    assert.deepEqual(
      [...((await openWith(candidates, newNonce, newSealed)) ?? [])],
      [...newContent],
      "and the render sealed under the new family opens too",
    );
  }
});

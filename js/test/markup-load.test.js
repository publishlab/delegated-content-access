// @ts-check
//
// The one place the whole markup path runs end to end: the publisher writes a
// render as the delivery markup string, that string is parsed to a queryable
// root, and `Browser.load` reads its render off that root and the client opens
// the article. The placement-contract tests in `markup-placement.test.js` pin
// the writer and reader against each other over values; this test carries the
// string across the seam once, so `writeMarkupDelivery -> markup -> parse ->
// Browser.load -> resolve/unlock/decrypt` is proven as a single flow rather than
// as two halves that each pass alone.
//
// The scenario worlds hand `Browser.load` a root fabricated from a render's
// values, never running the writer. This test closes that loop: it starts from
// the writer's emitted string and parses it with the shared `domOver` fixture,
// the same parse the placement-contract tests read markup through.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { ARTICLES, CONTENT_NAME } from "../demo/scenarios/fixtures.js";
import { utf8Decode } from "../core-shared/codec.js";
import { domOver } from "../test-lib/helpers/domOver.js";
import { sealedContentByName } from "../test-lib/helpers/inspect.js";

describe("The markup path, end to end: writer to string to Browser.load to open", () => {
  test("the client opens the article off a page it parsed from the writer's markup", async () => {
    const { browser, render } = await actorWorld();

    // The publisher render, written as the delivery markup a page would
    // carry, then parsed back to a queryable root: the real string round trip,
    // rather than a root fabricated from the render's values.
    const page = await render("A");
    // The writer takes the ciphertext by name, as the Sealer returns it.
    const { sealedContent: records, ...dcaData } = page.asJson();
    const sealedContent = sealedContentByName({ sealedContent: records });
    const markup = writeMarkupDelivery({ dcaData, sealedContent });
    const root = domOver(markup, { publisherOrigin: page.publisherOrigin });

    const load = browser.load(root);
    const { covered, missing } = await load.resolve([CONTENT_NAME]);
    assert.deepEqual(
      { covered, missing },
      { covered: [], missing: [CONTENT_NAME] },
      "the sealed article is on the page and needs an unlock",
    );

    const unlock = await load.unlock();
    assert.equal(unlock.ok, true, "the issuer answered the request built off the parsed page");

    const { bytes, error } = await load.open(CONTENT_NAME);
    assert.equal(error, null);
    assert.equal(
      utf8Decode(/** @type {Uint8Array} */ (bytes)),
      ARTICLES.A,
      "the plaintext the client opened is the article the publisher sealed",
    );
  });
});

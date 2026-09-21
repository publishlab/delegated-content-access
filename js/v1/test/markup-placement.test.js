// @ts-check
//
// The complete writer-to-reader placement proof. markup-writer.test.js covers
// standalone writer behavior, and markup-delivery-reader.test.js covers the
// reader entry refusals.
//
// These tests stub the DOM. Node has no document, so the emitted string is read
// through the small stub below, which answers the calls `MarkupDeliveryReader`
// makes and nothing else. It cuts each script block at the first `</script>` the
// way the HTML tokenizer does, so a writer that stopped escaping that sequence
// fails here rather than passing on a repaired string.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { writeMarkupDelivery } from "../adapter-publisher/writeMarkupDelivery.js";
import { MarkupDeliveryReader } from "../adapter-client/MarkupDeliveryReader.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { domOver } from "../test-lib/helpers/domOver.js";

/**
 * One render, split the way the writer takes it: dca-data and the sealed content
 * beside it, as `asJson()` hands them over with the ciphertext under a member.
 *
 * @param {any} page
 * @returns {{ dcaData: any, sealedContent: Record<string, string> }}
 */
function renderValues(page) {
  const { sealedContent, ...dcaData } = page.asJson();
  return { dcaData, sealedContent };
}

describe("The markup placement contract, writer to reader", () => {
  test("the reader recovers the writer's dca-data and every ciphertext, down to the miss", async () => {
    const { render } = await actorWorld();
    const { dcaData, sealedContent } = renderValues(await render("A"));
    const markup = writeMarkupDelivery({ dcaData, sealedContent });

    const read = new MarkupDeliveryReader(domOver(markup));

    // The whole of dca-data, member order included: the markup carries no
    // `sealedContent` member, so what comes back is the data the writer was
    // handed and nothing more.
    assert.deepEqual(read.dcaData, dcaData);
    assert.equal(JSON.stringify(read.dcaData), JSON.stringify(dcaData), "down to the member order");
    assert.equal(Object.hasOwn(read.dcaData, "sealedContent"), false, "the blobs are not dca-data");

    // Every blob back by name, byte for byte.
    for (const [contentName, ciphertext] of Object.entries(sealedContent)) {
      assert.equal(read.extract(contentName), ciphertext, `the ciphertext for ${contentName}`);
    }

    // And a name the page never carried gets the same miss.
    assert.equal(read.extract("no-such-item"), null, "a name the page never carried is a miss");
  });

  test("a colon in a contentName survives as the carrier member name", async () => {
    const dcaData = { version: "1", resource: { renderId: "r1" } };
    const sealedContent = { "sponsor:intro": "QUJD", "body:text": "REVG" };
    const markup = writeMarkupDelivery({ dcaData, sealedContent });

    const read = new MarkupDeliveryReader(domOver(markup));
    assert.deepEqual(read.dcaData, dcaData);
    assert.equal(read.extract("sponsor:intro"), "QUJD");
    assert.equal(read.extract("body:text"), "REVG");
  });

  test("the carrier answers by name, so the order the writer emitted is not read back", () => {
    // The same three items in two orders. Each name answers the same, and the
    // two emissions differ only in the carrier's member order, so a client that
    // had come to depend on position would part here.
    const dcaData = { version: "1" };
    const forward = { bodytext: "QUJD", premiumtext: "REVG", sidebar: "R0hJ" };
    const reversed = { sidebar: "R0hJ", premiumtext: "REVG", bodytext: "QUJD" };

    const readForward = new MarkupDeliveryReader(
      domOver(writeMarkupDelivery({ dcaData, sealedContent: forward })),
    );
    const readReversed = new MarkupDeliveryReader(
      domOver(writeMarkupDelivery({ dcaData, sealedContent: reversed })),
    );

    for (const contentName of Object.keys(forward)) {
      assert.equal(readForward.extract(contentName), forward[contentName]);
      assert.equal(
        readReversed.extract(contentName),
        forward[contentName],
        `${contentName}, emitted last first`,
      );
    }
    assert.notEqual(
      writeMarkupDelivery({ dcaData, sealedContent: forward }),
      writeMarkupDelivery({ dcaData, sealedContent: reversed }),
      "the two emissions really do differ, so the reader was asked something",
    );
  });

  test("a page carrying no blobs answers every name as a miss", async () => {
    const markup = writeMarkupDelivery({ dcaData: { version: "1" }, sealedContent: {} });

    const read = new MarkupDeliveryReader(domOver(markup));
    assert.deepEqual(read.dcaData, { version: "1" });
    assert.equal(read.extract("bodytext"), null, "deferred content is a miss, not an error");
  });

  test("a script-closing sequence in dca-data leaves the block intact and round-trips", () => {
    const closing = "</script><img src=x onerror=alert(1)>";
    const commented = "<!--<script>";
    const dcaData = { version: "1", resource: { data: { section: closing, note: commented } } };
    const markup = writeMarkupDelivery({ dcaData, sealedContent: { body: "QUJD" } });

    const block = markup.slice(markup.indexOf(">") + 1, markup.indexOf("</script>"));
    assert.equal(block.includes("</script"), false, "nothing in the JSON ends the block");
    assert.equal(block.includes("<!--"), false, "and nothing in it opens the escaped states");
    assert.equal(
      /** @type {RegExpMatchArray} */ (markup.match(/<\/script/gi)).length,
      2,
      "two closing tags, the writer's own two",
    );

    // The escape is JSON's own for `<`, so the reader hands back the string
    // the caller wrote and no consumer has to know an escape happened.
    const read = new MarkupDeliveryReader(domOver(markup));
    assert.equal(read.dcaData.resource.data.section, closing);
    assert.equal(read.dcaData.resource.data.note, commented);
    assert.equal(read.extract("body"), "QUJD");
  });
});

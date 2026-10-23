import test from "node:test";
import assert from "node:assert/strict";
import { createBrowserMapSession } from "../extensions/html-content-map/integration-client/reconstructBrowserPage.js";
import { createBrowserClient } from "../integration-client/createBrowserClient.js";
import {
  contentDescriptionHandoff,
  selectContentDescriptionHandler,
} from "../extensions/content-description/core-client/contentDescriptionHandoff.js";
import { withContentDescriptions } from "../extensions/content-description/core-publisher/withContentDescriptions.js";
import { admitContentDescription } from "../extensions/content-description/core-shared--client-publisher/contentDescription.js";
import { writeMappedDelivery } from "../extensions/html-content-map/adapter-publisher/writeMappedDelivery.js";
import { parseLockedDocument } from "../extensions/html-content-map/adapter-client/parse5Tree.js";
import { treeDeliveryRoot } from "../extensions/html-content-map/core-client/treeDeliveryRoot.js";
import {
  mapDeliveryOf,
  runContentMap,
} from "../extensions/html-content-map/core-client/contentMapRun.js";
import { ISSUER_NAME, ORIGIN, mapWorld } from "../extensions/html-content-map/test/world.js";

const body = "<p>Publisher's article</p>";
const schema = "urn:example:observations:v1";
const map = { version: "1", rules: [{ item: "bodytext", op: "fill", target: "#article" }] };
const page = (carriers) =>
  `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="article">Teaser</div>${carriers}</body></html>`;

async function delivery() {
  const world = await mapWorld();
  const render = await world.publish({
    items: [
      { name: "bodytext", value: body, contentType: "text/html" },
      { name: "measurements", value: '[{"celsius":12}]', contentType: "application/json" },
    ],
    page,
  });
  const dcaData = withContentDescriptions(render.dcaData, {
    bodytext: { version: "1", description: "The rest of the article." },
    measurements: { version: "1", schema },
  });
  const html = writeMappedDelivery({
    dcaData,
    sealedContent: render.sealedContent,
    contentMap: map,
    page,
    items: { bodytext: body },
  });
  return { world, html };
}

function clientFor(world, tree) {
  return createBrowserClient({
    unlockUrl: "https://issuer.example/unlock",
    root: treeDeliveryRoot(tree, ORIGIN),
    issuerName: ISSUER_NAME,
    transport: world.transport,
  });
}

test("the owner hands opened HTML and data to chosen handlers; map presence causes no placement", async () => {
  const { world, html } = await delivery();
  const tree = parseLockedDocument(html);
  const before = tree.serialize();
  const client = clientFor(world, tree);
  const view = {};
  // These functions stand for owner-selected rendering and data libraries. Updating
  // framework state needs no outside DOM writer and no protocol-selected script.
  const handlers = {
    bodytext(input) {
      view.article = new TextDecoder("utf-8", { fatal: true }).decode(input.bytes);
      assert.equal(input.description.state, "available");
      assert.equal(input.description.description.schema, undefined);
    },
    measurements(input) {
      assert.equal(
        selectContentDescriptionHandler(input, { requiresSchema: true, supportedSchemas: [schema] })
          .state,
        "ready",
      );
      const rows = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input.bytes));
      if (!rows.every((row) => typeof row.celsius === "number"))
        throw new Error("Invalid observations");
      view.temperatures = rows.map((row) => row.celsius);
    },
  };
  for (const name of Object.keys(handlers)) {
    // Capture before the await; the handoff reads neither record again.
    const item = client.dcaData.contentItemFor(name);
    const description = admitContentDescription(client.dcaData.contentDataFor(name));
    const opened = await client.open(name);
    handlers[name](contentDescriptionHandoff(item, description, opened.bytes));
  }
  assert.deepEqual(view, { article: body, temperatures: [12] });
  assert.equal(
    tree.serialize(),
    before,
    "base opening does not execute the map or mutate the owner's DOM",
  );
});

test("an independent map client reconstructs the same article without the owner's handlers", async () => {
  const { world, html } = await delivery();
  const tree = parseLockedDocument(html);
  const client = clientFor(world, tree);
  const result = await runContentMap({
    tree,
    delivery: mapDeliveryOf(client),
    keyClient: () => client,
  });
  assert.deepEqual(result.report, { outcome: "complete", items: { bodytext: "opened" } });
  assert.match(tree.serialize(), /<div id="article"><p>Publisher's article<\/p><\/div>/);
  assert.equal(world.unlocks.length, 1);
  assert.deepEqual(
    world.unlocks[0].request.sealed.contentKeys.map((record) => record.contentName),
    ["bodytext"],
  );
});

test("structural refusal cannot be changed through a returned browser report", async () => {
  const session = createBrowserMapSession({
    document: { characterSet: "UTF-8", querySelectorAll: () => [] },
    isEligible: () => true,
    issuerName: ISSUER_NAME,
    transport: {
      post: async () => {
        throw new Error("must not contact issuer");
      },
    },
  });
  const first = await session.run();
  first.report.outcome = "complete";
  first.reconstructed = true;
  assert.deepEqual(await session.run(), {
    report: { outcome: "failed", failure: "delivery_refused" },
    reconstructed: false,
    targets: [],
  });
  assert.throws(
    () => session.snapshot(),
    (error) => error.code === "delivery_refused",
  );
});

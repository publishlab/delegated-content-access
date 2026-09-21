// @ts-check
//
// The base actor composition carries no codec names. A host injects the gzip
// registry to read this extension; without it, only that item is refused.

import test from "node:test";
import assert from "node:assert/strict";

import { actorWorld } from "../../../demo/scenarios/world.js";
import {
  ACCESS_GROUP,
  DOMAIN,
  RESOURCE_ID,
  SIGNING_KID,
} from "../../../demo/scenarios/fixtures.js";
import { originForHost } from "../../../demo/support/provisioning.js";
import { Page } from "../../../demo/support/Page.js";
import { rootFromPage } from "../../../demo/support/queryableRoot.js";
import { utf8Decode } from "../../../core-shared/codec.js";
import { CompressingSealer } from "../core-publisher/CompressingSealer.js";
import { decoders } from "../core-shared--client-publisher/gzipCodec.js";
import { ARTICLE, SIDEBAR } from "./world.js";

/** A page of one compressed item and one identity item, over the demo deployment. */
async function compressedPage() {
  const stage = await actorWorld();
  const origin = originForHost(DOMAIN);

  const sealer = new CompressingSealer({
    origin,
    clock: stage.clock,
    random: stage.random,
    signingKeys: { [SIGNING_KID]: stage.signingKeys.privateKey },
    signingKid: SIGNING_KID,
    periodKeySupply: stage.periodKeySupply,
    issuers: stage.issuers,
  });
  sealer.resource(RESOURCE_ID, { section: "politics" });
  sealer.content("bodytext", ARTICLE, "text/html", { accessGroups: [ACCESS_GROUP] });
  sealer.content("sidebar", SIDEBAR, "text/html", {
    accessGroups: [ACCESS_GROUP],
    contentEncoding: "identity",
  });

  const { dcaData, sealedContent } = await sealer.seal();
  return { stage, page: new Page({ publisherOrigin: origin, dcaData, sealedContent }) };
}

test("a PageLoad without an injected gzip decoder refuses only the gzip item", async () => {
  const { stage, page } = await compressedPage();

  const load = stage.browser.load(rootFromPage(page));
  const { missing } = await load.resolve(["bodytext", "sidebar"]);
  assert.deepEqual(missing.sort(), ["bodytext", "sidebar"]);
  const unlock = await load.unlock();
  assert.equal(unlock.ok, true);

  const opened = await load.open("bodytext");
  assert.equal(opened.error, "unsupported_encoding");
  assert.equal(opened.bytes, null);
  assert.equal(
    load.stats().keyResolutions.some(({ operation }) => operation === "open"),
    false,
    "an unsupported representation is refused before the opener asks for a key",
  );

  const identity = await load.open("sidebar");
  assert.equal(identity.error, null);
  assert.equal(utf8Decode(/** @type {Uint8Array} */ (identity.bytes)), SIDEBAR);
});

test("the host injects gzip generically and the actor decrypts then decodes", async () => {
  const { stage, page } = await compressedPage();
  const browser = stage.makeBrowser({ contentDecoders: decoders });
  const load = browser.load(rootFromPage(page));
  await load.resolve(["bodytext"]);
  await load.unlock();

  const opened = await load.open("bodytext");
  assert.equal(opened.error, null);
  assert.equal(utf8Decode(/** @type {Uint8Array} */ (opened.bytes)), ARTICLE);
});

//
// The publisher input for an item with no cached path. A sealer holding no
// periodKeySupply has no periodKey to wrap a contentKey under, so its items
// name no accessGroup: the cached path is keyed by the group, and naming one on
// a render that emits none says something the wire cannot carry.
//
// A sealer that does hold a supply keeps the requirement, because there the
// group is the path being asked for and there is no default to fall back on,
// least of all the contentName, which would key every item's family by itself.
//
// The emitted shape is the other half of the same rule: no group on the
// item, no `keys` member on its record, and no periodKey material on either side
// of the wire. The direct grant opens such an item, and the last test takes one
// through the stock issuer.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../adapter-client/PeriodKeyCache.js";
import { requestFor } from "../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../test-lib/harnesses/unlockThroughAdmission.js";
import { refuses } from "../test-lib/helpers/refuses.js";
import { utf8Decode } from "../core-shared/codec.js";
import { ARTICLES, ISSUER_NAME } from "../demo/scenarios/fixtures.js";
import { BODYTEXT, PUB, world } from "../test-lib/fixtures/wire-policy-world.js";

/** The item as a direct-only render receives it: no groups named at all. */
const UNGROUPED = { ...BODYTEXT, accessGroups: undefined };

/** The same item with the empty list written out, which says the same thing. */
const EMPTY_GROUPS = { ...BODYTEXT, accessGroups: [] };

/**
 * What the page says about the cached path, read off the wire rather than off
 * the record alone: a `keys` member is the client's half and `periodKeys` the
 * issuer's, and an item with no group carries neither.
 *
 * @param {any} page
 * @param {string} contentName
 */
function carriesNoCachedPath(page, contentName) {
  const record = page.contentData[contentName];
  assert.deepEqual(
    Object.keys(record),
    ["contentType", "nonce", "aad"],
    "the record the format requires",
  );
  assert.equal(Object.hasOwn(record, "keys"), false, "and no wrapped contentKey beside it");

  const wire = JSON.stringify(page);
  assert.equal(wire.includes('"periodKeys"'), false, "nothing period-keyed anywhere on the page");
  assert.equal(wire.includes('"periodChainKeys"'), false, "nor the chain form of it");
}

describe("A publisher with no periodKeySupply seals a genuine direct-only item", () => {
  test("an item that names no accessGroup is sealed, and its record ships no keys", async () => {
    const w = await world();
    const { page } = await w.render({ periodKeySupply: null, items: [UNGROUPED] });

    carriesNoCachedPath(page, "bodytext");
  });

  test("an empty accessGroups list is the same item", async () => {
    const w = await world();
    const { page } = await w.render({ periodKeySupply: null, items: [EMPTY_GROUPS] });

    carriesNoCachedPath(page, "bodytext");
  });

  test("the direct grant opens the direct-only page, and it is the only key the issuer emits", async () => {
    const w = await world();
    const { page } = await w.render({ periodKeySupply: null, items: [UNGROUPED] });

    const { processor, endpoint, publisherRegistration } = w.endpointWith();
    const { status, body } = await unlockThroughAdmission(
      processor,
      endpoint,
      requestFor(page, ISSUER_NAME, ["bodytext"]),
      publisherRegistration,
    );

    assert.equal(status, 200, "the issuer answered");
    assert.deepEqual(Object.keys(body.keys), ["contentKeys"], "one contentKey and no family");
    assert.equal(
      JSON.stringify(body).includes('"periodKeys"'),
      false,
      "no period-key material was granted",
    );

    // The client holds a cache, so it could have contradicted "nothing was
    // cached" rather than having nowhere to put a key.
    const unsealer = new Client({ cache: new PeriodKeyCache(), publisherOrigin: PUB });
    const dcaData = unsealer.parse(page);
    unsealer.buildRequest(dcaData, ISSUER_NAME, ["bodytext"]);
    await unsealer.applyResponse(dcaData, ISSUER_NAME, body);

    assert.equal(
      utf8Decode(await unsealer.decrypt(dcaData, "bodytext", unsealer.extract(page, "bodytext"))),
      ARTICLES.A,
      "the item opens under the granted contentKey",
    );
  });
});

describe("A publisher holding a periodKeySupply still names its groups", () => {
  test("an item that names no accessGroup is refused, omitted or empty", async () => {
    const w = await world();

    for (const [label, items] of [
      ["omitted", [UNGROUPED]],
      ["empty", [EMPTY_GROUPS]],
    ]) {
      await refuses(
        () => w.render({ items }),
        "bad_config",
        `a cached-path render with ${label} accessGroups names no family to wrap under`,
      );
    }
  });

  test("the group it does name is the one its contentKey is wrapped under", async () => {
    const w = await world();
    const { page } = await w.render();

    assert.deepEqual(Object.keys(page.contentData.bodytext.keys), BODYTEXT.accessGroups);
    assert.ok(page.issuerData[ISSUER_NAME].sealed.periodKeys, "and the issuer holds the family");
  });
});

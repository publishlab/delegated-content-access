//
// The publisher input for an item with no cached path. A sealer holding no
// periodKeySupply has no periodKey to wrap a contentKey under, so its items
// name no accessGroup: the cached path is keyed by the group, and a render that
// names one without a supply is refused rather than shipped without the wraps
// it asked for.
//
// Period access is optional per item (docs/spec-profile--period-keys.md, 6.1). A sealer
// that holds a supply wraps each item under the groups that item names, and an
// item that names none relies on its item content-key route alone. No group is
// assigned by default, least of all one named after the contentName.
//
// The emitted shape is the other half of the same rule: no group on the
// item, no `keys` member on its record, and no periodKey material for it on
// either side of the wire. A content-key grant opens such an item, and the tests
// take one through the stock issuer, alone and beside a grouped sibling.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Client } from "../../test-lib/harnesses/client.js";
import { MarkupDeliveryReader } from "../../adapter-client/MarkupDeliveryReader.js";
import { PeriodKeyCache } from "../../adapter-client/PeriodKeyCache.js";
import { writeMarkupDelivery } from "../../adapter-publisher/writeMarkupDelivery.js";
import { requestFor } from "../../test-lib/harnesses/issuer-endpoint.js";
import { unlockThroughAdmission } from "../../test-lib/harnesses/unlockThroughAdmission.js";
import { refuses } from "../../test-lib/helpers/refuses.js";
import { utf8Decode } from "../../core-shared/codec.js";
import { domOver } from "../../test-lib/helpers/domOver.js";
import { ARTICLES, ISSUER_NAME, KEY_ID } from "../../demo/scenarios/fixtures.js";
import { BODYTEXT, PUB, T_NOW, world } from "../../test-lib/fixtures/wire-policy-world.js";
import {
  contentRecordOf,
  issuerBlockOf,
  wrapGroupsOn,
  wrapsOf,
} from "../../test-lib/helpers/inspect.js";
import { contentKeyMap, errorMap, keyAt, periodKeyMap, setKeyAt } from "../support/namedRecords.js";

/** The item as a content-key-only render receives it: no groups named at all. */
const UNGROUPED = { ...BODYTEXT, accessGroups: undefined };

/** The same item with the empty list written out, which says the same thing. */
const EMPTY_GROUPS = { ...BODYTEXT, accessGroups: [] };
const SECOND_UNGROUPED = {
  ...UNGROUPED,
  name: "premiumtext",
  value: ARTICLES.D,
};

/**
 * The ungrouped item of a mixed render, in both spellings of "no group". It
 * shares the render with `BODYTEXT`, which stays under its group.
 */
const SIDE_ITEMS = [
  ["omitted", { ...SECOND_UNGROUPED, name: "sidetext" }],
  ["empty", { ...SECOND_UNGROUPED, name: "sidetext", accessGroups: [] }],
];

/**
 * What the page says about the cached path, read off the wire rather than off
 * the record alone: a `keys` member is the client's half and `periodKeys` the
 * issuer's, and an item with no group carries neither.
 *
 * @param {any} page
 * @param {string} contentName
 */
function carriesNoCachedPath(page, contentName) {
  const record = contentRecordOf(page, contentName);
  assert.deepEqual(
    Object.keys(record),
    ["contentName", "contentType"],
    "the record the format requires",
  );
  assert.equal(Object.hasOwn(record, "keys"), false, "and no wrapped contentKey beside it");

  const wire = JSON.stringify(page);
  assert.equal(wire.includes('"periodKeys"'), false, "nothing period-keyed anywhere on the page");
  assert.equal(wire.includes('"chainKeys"'), false, "nor the chain form of it");
}

describe("A publisher with no periodKeySupply seals a genuine content-key-only item", () => {
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

  test(
    "the signed, markup-delivered content-key-only item opens through its ECDH issuer envelope",
    {
      tags: [
        "dca-profile-baseline/publisher/content-key-envelope",
        "dca-profile-html-carrier/publisher/markup-emission",
        "dca-profile-html-carrier/client/markup-extraction",
      ],
    },
    async () => {
      const w = await world();
      const { dcaData, sealedContent, page } = await w.render({
        periodKeySupply: null,
        items: [UNGROUPED],
      });

      const { publisherRegistration } = w.endpointWith();
      const [header, payload, signature] = dcaData.resourceJWT.split(".");
      assert.equal(JSON.parse(Buffer.from(header, "base64url").toString()).alg, "ES256");
      assert.equal(
        await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          publisherRegistration.publicKey,
          Buffer.from(signature, "base64url"),
          Buffer.from(`${header}.${payload}`),
        ),
        true,
        "the issuer's registered publisher key verifies this render",
      );
      assert.equal(issuerBlockOf(page, ISSUER_NAME).keyId, KEY_ID);
      assert.ok(contentKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.contentKeys).bodytext);

      const delivery = new MarkupDeliveryReader(
        domOver(writeMarkupDelivery({ dcaData, sealedContent }), { publisherOrigin: PUB }),
      );
      assert.deepEqual(delivery.dcaData, dcaData);
      assert.equal(delivery.extract("bodytext"), sealedContent.bodytext);

      const { processor, endpoint } = w.endpointWith();
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
      const parsed = unsealer.parse(page);
      unsealer.buildRequest(parsed, ISSUER_NAME, ["bodytext"]);
      await unsealer.applyResponse(parsed, ISSUER_NAME, body);

      assert.equal(
        utf8Decode(await unsealer.decrypt(parsed, "bodytext", unsealer.extract(page, "bodytext"))),
        ARTICLES.A,
        "the item opens under the granted contentKey",
      );
    },
  );

  test(
    "each item in one content-key-only render has a usable issuer envelope",
    {
      tags: ["dca-profile-baseline/publisher/content-key-envelope"],
    },
    async () => {
      const w = await world();
      const { page } = await w.render({
        periodKeySupply: null,
        items: [UNGROUPED, SECOND_UNGROUPED],
      });
      const names = ["bodytext", "premiumtext"];
      assert.deepEqual(
        Object.keys(contentKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.contentKeys)),
        names,
      );

      const { processor, endpoint, publisherRegistration } = w.endpointWith();
      const { status, body } = await unlockThroughAdmission(
        processor,
        endpoint,
        requestFor(page, ISSUER_NAME, names),
        publisherRegistration,
      );
      assert.equal(status, 200);
      assert.deepEqual(Object.keys(contentKeyMap(body.keys.contentKeys)), names);

      const client = new Client({ cache: new PeriodKeyCache(), publisherOrigin: PUB });
      const parsed = client.parse(page);
      client.buildRequest(parsed, ISSUER_NAME, names);
      await client.applyResponse(parsed, ISSUER_NAME, body);
      for (const [name, expected] of [
        ["bodytext", ARTICLES.A],
        ["premiumtext", ARTICLES.D],
      ]) {
        assert.equal(
          utf8Decode(await client.decrypt(parsed, name, client.extract(page, name))),
          expected,
        );
      }
    },
  );

  test(
    "a partial direct result preserves the valid item beside failed and denied siblings",
    {
      tags: [
        "dca-profile-baseline/publisher/content-key-envelope",
        "dca-profile-baseline/issuer/direct-result",
        "dca-profile-baseline/client/direct-admission",
        "dca-profile-html-carrier/publisher/markup-emission",
        "dca-profile-html-carrier/client/markup-extraction",
      ],
    },
    async () => {
      const w = await world();
      const failed = { ...UNGROUPED, name: "failed", value: ARTICLES.B };
      const denied = { ...UNGROUPED, name: "denied", value: ARTICLES.C };
      const { dcaData, sealedContent, page } = await w.render({
        periodKeySupply: null,
        items: [UNGROUPED, failed, denied],
      });
      const names = ["bodytext", "failed", "denied"];
      for (const name of names) carriesNoCachedPath(page, name);
      assert.deepEqual(
        Object.keys(contentKeyMap(issuerBlockOf(page, ISSUER_NAME).sealed.contentKeys)),
        names,
      );

      const delivery = new MarkupDeliveryReader(
        domOver(writeMarkupDelivery({ dcaData, sealedContent }), { publisherOrigin: PUB }),
      );
      const cache = new PeriodKeyCache();
      const client = new Client({ cache, publisherOrigin: PUB });
      const parsed = client.parse(delivery.dcaData);
      const request = client.buildRequest(parsed, ISSUER_NAME, names);
      // A genuine publisher envelope carried under another name cannot open
      // at that coordinate, although its granted sibling remains usable.
      setKeyAt(
        request.sealed.contentKeys,
        { contentName: "failed" },
        keyAt(request.sealed.contentKeys, { contentName: "bodytext" }),
      );
      let decisions = 0;
      const { processor, endpoint, publisherRegistration } = w.endpointWith({
        accessPolicy: {
          decide(_claims, presented) {
            decisions += 1;
            assert.deepEqual(presented.contentNames, names);
            return { contentNames: ["bodytext", "failed"], periodGrants: [] };
          },
        },
      });
      const { status, body } = await unlockThroughAdmission(
        processor,
        endpoint,
        request,
        publisherRegistration,
      );
      assert.equal(decisions, 1);
      assert.equal(status, 200);
      assert.equal(body.transport, undefined);
      assert.deepEqual(Object.keys(body.keys), ["contentKeys"]);
      assert.deepEqual(Object.keys(contentKeyMap(body.keys.contentKeys)), ["bodytext"]);
      assert.deepEqual(errorMap(body.errors), {
        failed: { error: "unseal_failed", message: "sealed value could not be opened" },
      });
      assert.equal(Object.hasOwn(errorMap(body.errors), "denied"), false);
      const applied = await client.applyResponse(parsed, ISSUER_NAME, body);
      assert.equal(applied.accepted, 1);
      assert.equal(applied.errors.length, 1);
      assert.deepEqual(applied.issues, []);
      assert.equal(
        utf8Decode(await client.decrypt(parsed, "bodytext", delivery.extract("bodytext"))),
        ARTICLES.A,
      );
      for (const name of ["failed", "denied"]) {
        assert.equal(await client.contentKeyFor(parsed, name), null);
        await assert.rejects(() => client.decrypt(parsed, name, delivery.extract(name)), {
          code: "no_key",
        });
      }
      assert.deepEqual(await cache.entries(), []);
    },
  );

  test("a named accessGroup with no periodKeySupply is refused, not dropped", async () => {
    const w = await world();

    await refuses(
      () => w.render({ periodKeySupply: null, items: [BODYTEXT] }),
      { code: "bad_config", message: /content "bodytext" names accessGroups/ },
      "a render cannot wrap under a group it holds no period key for",
    );
    await refuses(
      () => w.render({ periodKeySupply: null, items: [UNGROUPED, { ...BODYTEXT, name: "x" }] }),
      { code: "bad_config", message: /content "x" names accessGroups/ },
      "an ungrouped sibling does not excuse the grouped item",
    );
  });
});

describe("A publisher holding a periodKeySupply mixes grouped and ungrouped items", () => {
  test("an ungrouped item beside a grouped one ships no keys, omitted or empty", async () => {
    for (const [label, side] of SIDE_ITEMS) {
      const w = await world();
      const { page } = await w.render({ items: [BODYTEXT, side] });

      assert.deepEqual(wrapGroupsOn(page, "bodytext"), BODYTEXT.accessGroups, label);
      const record = contentRecordOf(page, "sidetext");
      assert.deepEqual(Object.keys(record), ["contentName", "contentType"], label);
      assert.equal(Object.hasOwn(record, "keys"), false, `${label}: never an empty keys map`);

      // The whole-render plan selects both item keys and only the group the
      // grouped item names; nothing is supplied for the ungrouped item's sake.
      const sealed = issuerBlockOf(page, ISSUER_NAME).sealed;
      assert.deepEqual(
        Object.keys(contentKeyMap(sealed.contentKeys)),
        ["bodytext", "sidetext"],
        label,
      );
      assert.deepEqual(Object.keys(periodKeyMap(sealed.periodKeys)), BODYTEXT.accessGroups, label);
    }
  });

  test("a supply render whose items all name no group carries no period material", async () => {
    const w = await world();
    const { page } = await w.render({ items: [UNGROUPED, { ...EMPTY_GROUPS, name: "sidetext" }] });

    carriesNoCachedPath(page, "bodytext");
    carriesNoCachedPath(page, "sidetext");
  });

  test("the mixed render, delivered as markup, opens each item through its own route", async () => {
    const w = await world();
    const side = { ...SECOND_UNGROUPED, name: "sidetext" };
    const { dcaData, sealedContent } = await w.render({ items: [BODYTEXT, side] });
    const delivery = new MarkupDeliveryReader(
      domOver(writeMarkupDelivery({ dcaData, sealedContent }), { publisherOrigin: PUB }),
    );

    // A cache holding the grouped item's period key opens it from its wraps
    // and leaves the ungrouped item missing, because that item has none.
    const cache = new PeriodKeyCache();
    const [group] = BODYTEXT.accessGroups;
    await cache.put(group, T_NOW, await w.periodKeySupply.derive(group, T_NOW), {
      publisher: PUB,
    });
    const client = new Client({ cache, publisherOrigin: PUB });
    const parsed = client.parse(delivery.dcaData);
    assert.deepEqual(await client.resolve(parsed, ["bodytext", "sidetext"]), {
      covered: ["bodytext"],
      missing: ["sidetext"],
    });

    // The ungrouped item opens with the item key its issuer route supplies.
    const request = client.buildRequest(parsed, ISSUER_NAME, ["sidetext"]);
    assert.deepEqual(Object.keys(contentKeyMap(request.sealed.contentKeys)), ["sidetext"]);
    const { processor, endpoint, publisherRegistration } = w.endpointWith();
    const { status, body } = await unlockThroughAdmission(
      processor,
      endpoint,
      request,
      publisherRegistration,
    );
    assert.equal(status, 200);
    assert.deepEqual(Object.keys(body.keys), ["contentKeys"]);
    assert.deepEqual(Object.keys(contentKeyMap(body.keys.contentKeys)), ["sidetext"]);
    await client.applyResponse(parsed, ISSUER_NAME, body);

    for (const [name, expected] of [
      ["bodytext", ARTICLES.A],
      ["sidetext", ARTICLES.D],
    ]) {
      assert.equal(
        utf8Decode(await client.decrypt(parsed, name, delivery.extract(name))),
        expected,
        name,
      );
    }
  });

  test("the group it does name is the one its contentKey is wrapped under", async () => {
    const w = await world();
    const { page } = await w.render();

    assert.deepEqual(wrapGroupsOn(page, "bodytext"), BODYTEXT.accessGroups);
    assert.ok(
      issuerBlockOf(page, ISSUER_NAME).sealed.periodKeys,
      "and the issuer holds the family",
    );
  });
});

test("period-only deliveries omit geometry and open with granted and retained period keys", async () => {
  const w = await world();
  const first = await w.render();
  const second = await w.render({ resourceId: "retained-period-story" });
  assert.equal(Object.hasOwn(first.dcaData, "periodGeometry"), false);
  assert.equal(Object.hasOwn(second.dcaData, "periodGeometry"), false);
  assert.deepEqual(
    wrapsOf(first.dcaData, "bodytext", BODYTEXT.accessGroups[0]).map(({ period }) => period),
    [T_NOW, "251023T1500"],
  );
  const { processor, endpoint, publisherRegistration } = w.endpointWith();
  const { status, body } = await unlockThroughAdmission(
    processor,
    endpoint,
    requestFor(first.page, ISSUER_NAME, ["bodytext"]),
    publisherRegistration,
  );
  assert.equal(status, 200);
  const client = new Client({ cache: new PeriodKeyCache(), publisherOrigin: PUB });
  const parsed = client.parse(first.page);
  client.buildRequest(parsed, ISSUER_NAME, ["bodytext"]);
  await client.applyResponse(parsed, ISSUER_NAME, body);
  assert.equal(
    utf8Decode(await client.decrypt(parsed, "bodytext", client.extract(first.page, "bodytext"))),
    ARTICLES.A,
  );
  const retained = client.parse(second.page);
  assert.equal(
    utf8Decode(await client.decrypt(retained, "bodytext", client.extract(second.page, "bodytext"))),
    ARTICLES.A,
  );
});

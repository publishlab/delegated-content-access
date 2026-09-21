// @ts-check
//
// The read-only view over one page's `dca-data`. It has to prove that it
// answers exactly what the nested walks it replaces answered, including
// where those walks are lenient, because tightening one here would change what
// a page opens without anything saying so.
//
// The containers are keyed by names the publisher chose, so every lookup is
// own-property. The malformed shapes below are the ones a page served by
// someone else can carry: missing, null, a scalar where a map belongs, and an
// array whose index names a walk would read as coordinates.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { DcaData } from "../core-client/DcaData.js";
import { Client } from "../test-lib/harnesses/client.js";
import { actorWorld } from "../demo/scenarios/world.js";
import { CONTENT_NAME, ISSUER_NAME, KEY_ID } from "../demo/scenarios/fixtures.js";
import { INHERITED } from "../test-lib/fixtures/inherited-names.js";
import { base64urlEncode, utf8Encode } from "../core-shared/codec.js";

const GROUP = "article";
const PUBLISHER_ORIGIN = "https://news.example";
const HEADER = base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "k1" })));

/** One page shaped like the wire, written out rather than rendered. */
const PAGE = {
  version: "1",
  resource: { resourceId: "123456", renderId: "r-1" },
  resourceJWT: `${HEADER}.${base64urlEncode(
    utf8Encode(
      JSON.stringify({
        resourceId: "123456",
        renderId: "r-1",
      }),
    ),
  )}.signature`,
  issuerData: {
    issuer_example: {
      keyId: "k1",
      unlockUrl: "https://issuer.example/unlock",
      sealed: {
        contentKeys: { bodytext: "content-blob" },
        periodKeys: { [GROUP]: { "251023T15": "period-blob" } },
        periodChainKeys: {
          [GROUP]: {
            "251023T23": "chain-blob",
            "251024T11": "next-chain-blob",
          },
        },
      },
    },
    other_example: {
      keyId: "k9",
      unlockUrl: "https://other.example/unlock",
      sealed: { contentKeys: { bodytext: "other-blob" } },
    },
  },
  contentData: {
    bodytext: {
      contentType: "text/html",
      nonce: "n",
      aad: "123456|1|bodytext",
      keys: { [GROUP]: [{ t: "251023T15", nonce: "wrap-nonce", key: "wrapped" }] },
    },
  },
};

/** What a page raises when its record cannot be used. */
const badPage = (/** @type {any} */ error) => error.code === "bad_page";

test("DcaData refuses a delivery-context option it does not implement", () => {
  assert.throws(
    () => new DcaData(PAGE, /** @type {any} */ ({ origin: PUBLISHER_ORIGIN })),
    (/** @type {any} */ error) => {
      assert.equal(error.code, "unsupported_option");
      assert.match(error.message, /DcaData context has no origin/);
      return true;
    },
  );
});

/**
 * One reader per contentData accessor, so a rule about the inventory is
 * asserted over every one of them rather than the handiest.
 *
 * @param {DcaData} page
 * @returns {(() => unknown)[]}
 */
function inventoryReads(page) {
  return [
    () => page.contentNames(),
    () => page.contentDataFor(CONTENT_NAME),
    () => page.accessGroupsFor(CONTENT_NAME),
    () => page.sealedEntriesFor(CONTENT_NAME, GROUP),
  ];
}

describe("The page data, and what reads it", () => {
  test("the fixed fields and the containers under them", () => {
    const page = new DcaData(PAGE, { publisherOrigin: PUBLISHER_ORIGIN });

    assert.equal(page.version, "1");
    assert.deepEqual(page.resource, PAGE.resource);
    assert.equal(page.renderId, "r-1");
    assert.equal(page.publisherOrigin, PUBLISHER_ORIGIN);
    assert.equal(page.resourceJWT, PAGE.resourceJWT);

    assert.equal(page.hasIssuer("issuer_example"), true);
    assert.equal(page.hasIssuer("nobody.example"), false);
    assert.equal(page.keyIdFor("issuer_example"), "k1");
    assert.equal(page.unlockUrlFor("issuer_example"), "https://issuer.example/unlock");

    assert.equal(page.sealedContentKeyFor("issuer_example", "bodytext"), "content-blob");
    assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", GROUP), {
      "251023T15": "period-blob",
    });
    assert.deepEqual(page.sealedPeriodChainKeysFor("issuer_example", GROUP), {
      "251023T23": "chain-blob",
      "251024T11": "next-chain-blob",
    });
    assert.deepEqual(page.accessGroupsFor("bodytext"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), [
      { t: "251023T15", nonce: "wrap-nonce", key: "wrapped" },
    ]);
    assert.deepEqual(page.contentDataFor("bodytext"), PAGE.contentData.bodytext);

    // Only the issuer that carries the family, and in the page's order.
    assert.deepEqual(page.issuerNamesFor(GROUP), ["issuer_example"]);
    assert.deepEqual(page.issuerNamesFor("no-such-group"), []);
  });

  test("a name off the wire never resolves to an inherited member", () => {
    const page = new DcaData(PAGE);

    for (const name of INHERITED) {
      assert.equal(page.hasIssuer(name), false, `hasIssuer(${name})`);
      assert.equal(page.keyIdFor(name), undefined, `keyIdFor(${name})`);
      assert.equal(page.unlockUrlFor(name), undefined, `unlockUrlFor(${name})`);
      assert.equal(page.sealedContentKeyFor(name, name), undefined);
      assert.equal(page.sealedPeriodKeysFor("issuer_example", name), undefined);
      assert.equal(page.sealedPeriodChainKeysFor("issuer_example", name), undefined);
      assert.deepEqual(page.accessGroupsFor(name), [], `accessGroupsFor(${name})`);
      assert.deepEqual(page.sealedEntriesFor("bodytext", name), []);
      assert.deepEqual(page.issuerNamesFor(name), []);
      assert.equal(page.contentDataFor(name), undefined);
    }

    // And a page that carries none of the fixed fields: it is constructible,
    // and a request read meets the outer admission first. The envelope read
    // the cached walk makes answers where it always did.
    const empty = new DcaData({});
    assert.throws(() => empty.version, badPage);
    assert.throws(() => empty.resourceJWT, badPage);
    assert.equal(empty.resource, undefined);
    assert.throws(
      () => empty.renderId,
      (/** @type {any} */ error) => error.code === "bad_jwt",
    );
  });

  test("renderId comes from the token while publisher origin comes only from delivery context", () => {
    const inheritedResource = Object.create({ renderId: "prototype-render" });
    const page = new DcaData(
      {
        resource: inheritedResource,
        resourceJWT: `${HEADER}.${base64urlEncode(
          utf8Encode(
            JSON.stringify({
              renderId: "token-render",
            }),
          ),
        )}.signature`,
      },
      { publisherOrigin: PUBLISHER_ORIGIN },
    );
    assert.equal(page.renderId, "token-render");
    assert.equal(page.publisherOrigin, PUBLISHER_ORIGIN);

    const absent = new DcaData({
      resourceJWT: `${HEADER}.${base64urlEncode(
        utf8Encode(
          JSON.stringify({
            renderId: "token-render",
          }),
        ),
      )}.signature`,
    });
    assert.equal(absent.renderId, "token-render");
    assert.equal(absent.publisherOrigin, undefined);

    assert.throws(
      () => new DcaData({}, { publisherOrigin: "news.example" }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("a delivery that is not a page fails the reads a request and an item need", () => {
    // The item inventory is the one container the format requires, so a page
    // that carries none is a bad page rather than a page with no items on
    // it, and the outer object is required beside it.
    for (const data of [undefined, null, "a string", 42, []]) {
      const page = new DcaData(data);
      assert.throws(() => page.version, badPage, `version off ${JSON.stringify(data)}`);
      assert.throws(
        () => page.hasIssuer(ISSUER_NAME),
        badPage,
        `hasIssuer off ${JSON.stringify(data)}`,
      );
      for (const read of inventoryReads(page)) {
        assert.throws(read, badPage, `contentData off ${JSON.stringify(data)}`);
      }
    }

    for (const container of [null, "a string", 42]) {
      const page = new DcaData({ issuerData: container, contentData: container });
      assert.throws(() => page.hasIssuer(ISSUER_NAME), badPage, JSON.stringify(container));
      assert.throws(() => page.keyIdFor(ISSUER_NAME), badPage, JSON.stringify(container));
      assert.deepEqual(
        page.issuerNamesFor(GROUP),
        [],
        "the cached walk reads the container as it stands",
      );
      for (const read of inventoryReads(page)) {
        assert.throws(read, badPage, `contentData of ${JSON.stringify(container)}`);
      }
    }
  });

  test("an issuer entry that is present and empty is no issuer, as before", async () => {
    // `DcaRequestBuilder.build` refuses on `if (!issuer)`, so a page carrying
    // the name with nothing under it is `unknown_issuer` there. A view that
    // answered on presence alone would tell the builder to go on and then
    // hand it an entry with no keyId and no blobs.
    const unsealer = new Client({ publisherOrigin: PUBLISHER_ORIGIN });

    for (const entry of [null, false, 0, ""]) {
      const data = { ...PAGE, issuerData: { [ISSUER_NAME]: entry } };

      assert.equal(
        new DcaData(data).hasIssuer(ISSUER_NAME),
        false,
        `an entry of ${JSON.stringify(entry)} is not an issuer this page carries`,
      );
      assert.throws(
        () => unsealer.buildRequest(data, ISSUER_NAME, [CONTENT_NAME]),
        (/** @type {any} */ e) => e.code === "unknown_issuer",
        "and the walk it replaces says the same",
      );
    }

    // The control: a block the format admits is carried.
    assert.equal(
      new DcaData({
        ...PAGE,
        issuerData: {
          [ISSUER_NAME]: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
        },
      }).hasIssuer(ISSUER_NAME),
      true,
    );
  });

  test("a selected issuer block is usable only when its structure admits it", () => {
    // The format: a block is usable only when it and its `sealed` member are
    // non-array objects and `unlockUrl` and `keyId` are strings. A block
    // that is not one carries no route, and the sibling issuer stands.
    const sound = {
      keyId: "k9",
      unlockUrl: "https://other.example/unlock",
      sealed: { contentKeys: { bodytext: "other-blob" } },
    };
    const malformed = [
      [],
      "a string",
      42,
      { keyId: "k1", unlockUrl: "https://issuer.example/unlock" },
      { keyId: 7, unlockUrl: "https://issuer.example/unlock", sealed: {} },
      { keyId: "k1", unlockUrl: 17, sealed: {} },
      { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: [] },
    ];

    for (const block of malformed) {
      const label = JSON.stringify(block);
      const page = new DcaData({
        ...PAGE,
        issuerData: { issuer_example: block, other_example: sound },
      });

      assert.equal(page.hasIssuer("issuer_example"), false, label);
      assert.equal(page.keyIdFor("issuer_example"), undefined, label);
      assert.equal(page.unlockUrlFor("issuer_example"), undefined, label);
      assert.equal(page.sealedContentKeyFor("issuer_example", "bodytext"), undefined, label);
      assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined, label);
      assert.equal(page.sealedPeriodChainKeysFor("issuer_example", GROUP), undefined, label);
      assert.deepEqual(page.issuerNamesFor(GROUP), [], label);

      assert.equal(page.hasIssuer("other_example"), true, `${label}: the sibling issuer stands`);
      assert.equal(page.sealedContentKeyFor("other_example", "bodytext"), "other-blob", label);
    }
  });

  test("a route map that is not a non-array object carries no route of that kind", () => {
    // Every `sealed.periodKeys[accessGroup]` is a non-array object mapping
    // `t` to a sealed value. An array carries positions, so it is no route
    // map, and the valid route map in the same block stays. The chain
    // carrier's own family rules belong to the period-chain extension.
    const page = new DcaData({
      ...PAGE,
      issuerData: {
        issuer_example: {
          keyId: "k1",
          unlockUrl: "https://issuer.example/unlock",
          sealed: {
            contentKeys: { bodytext: "content-blob" },
            periodKeys: { [GROUP]: ["251023T15"], vault: { "251023T15": "vault-blob" } },
          },
        },
      },
    });

    assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
    assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", "vault"), {
      "251023T15": "vault-blob",
    });
    assert.equal(page.sealedContentKeyFor("issuer_example", "bodytext"), "content-blob");

    // A container that is not a non-array object carries no route either.
    for (const sealed of [{ periodKeys: [] }, { periodKeys: "a string" }, { contentKeys: [] }]) {
      const carrier = new DcaData({
        ...PAGE,
        issuerData: {
          issuer_example: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed },
        },
      });
      assert.equal(carrier.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
      assert.equal(carrier.sealedContentKeyFor("issuer_example", "bodytext"), undefined);
    }
  });

  test("a period-chain family that is not a non-array object carries no route", () => {
    const page = new DcaData({
      ...PAGE,
      issuerData: {
        issuer_example: {
          keyId: "k1",
          unlockUrl: "https://issuer.example/unlock",
          sealed: { periodChainKeys: { [GROUP]: ["chain-blob"] } },
        },
      },
    });

    assert.equal(page.sealedPeriodChainKeysFor("issuer_example", GROUP), undefined);
  });

  test("an array where the cached-wrap map belongs supplies no coordinates", () => {
    // An array carries positions and not accessGroups, so the container is
    // malformed and the item offers no cached route. This replaces the walk
    // that read an array's indices as coordinates.
    const page = new DcaData({
      contentData: { bodytext: { keys: ["first", "second"] } },
    });

    assert.deepEqual(page.accessGroupsFor("bodytext"), []);
    assert.deepEqual(page.sealedEntriesFor("bodytext", "0"), []);

    // The record itself is still malformed, so the item never opens: the
    // gate sits in the accessor the open path reads it through.
    assert.throws(() => page.contentDataFor("bodytext"), badPage);
  });

  test("the view answers what the client walks answer, over a rendered page", async () => {
    const { render } = await actorWorld();
    const rendered = await render("A");
    const parsed = new Client({ publisherOrigin: rendered.publisherOrigin }).parse(
      rendered.asJson(),
    );
    const page = new DcaData(parsed, { publisherOrigin: rendered.publisherOrigin });

    assert.equal(page.version, parsed.version);
    assert.deepEqual(page.resource, parsed.resource);
    assert.equal(page.renderId, parsed.resource.renderId);
    assert.equal(page.publisherOrigin, rendered.publisherOrigin);
    assert.equal(page.resourceJWT, parsed.resourceJWT);

    assert.equal(page.hasIssuer(ISSUER_NAME), true);
    assert.equal(page.keyIdFor(ISSUER_NAME), KEY_ID);
    assert.equal(
      page.sealedContentKeyFor(ISSUER_NAME, CONTENT_NAME),
      parsed.issuerData[ISSUER_NAME].sealed.contentKeys[CONTENT_NAME],
    );

    const groups = page.accessGroupsFor(CONTENT_NAME);
    assert.ok(groups.length > 0, "the fixture wraps its bodytext under at least one group");
    for (const group of groups) {
      assert.deepEqual(
        page.sealedPeriodKeysFor(ISSUER_NAME, group),
        parsed.issuerData[ISSUER_NAME].sealed.periodKeys[group],
      );
      assert.deepEqual(
        page.sealedEntriesFor(CONTENT_NAME, group),
        parsed.contentData[CONTENT_NAME].keys[group],
      );
      assert.deepEqual(page.issuerNamesFor(group), [ISSUER_NAME]);
    }

    assert.deepEqual(page.contentDataFor(CONTENT_NAME), parsed.contentData[CONTENT_NAME]);
    assert.equal(page.toObject(), parsed, "the page is handed on unchanged");
  });
});

describe("The outer object, admitted before a request or a key", () => {
  // The format requires `version` "1", a string `resourceJWT`, a
  // `contentData` object and a non-empty `issuerData` map, and makes
  // `resource` an object when it is present. Failure of one of them is a
  // delivery-wide structural failure, so it lands before the delivery is
  // exposed to request construction.

  const SOUND = {
    version: "1",
    resourceJWT: PAGE.resourceJWT,
    contentData: {},
    issuerData: {
      issuer_example: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
    },
  };

  /** What a request is derived from, so the rule is read against every one. */
  const requestReads = (/** @type {DcaData} */ page) => [
    () => page.version,
    () => page.resourceJWT,
    () => page.hasIssuer("issuer_example"),
    () => page.keyIdFor("issuer_example"),
    () => page.unlockUrlFor("issuer_example"),
    () => page.sealedContentKeyFor("issuer_example", "bodytext"),
    () => page.sealedPeriodKeysFor("issuer_example", GROUP),
  ];

  test("a delivery missing an outer requirement answers nothing a request is built from", () => {
    for (const [label, delivery] of [
      ["no version", { ...SOUND, version: undefined }],
      ["another version", { ...SOUND, version: "2" }],
      ["a numeric version", { ...SOUND, version: 1 }],
      ["a non-string resourceJWT", { ...SOUND, resourceJWT: 17 }],
      ["no contentData", { ...SOUND, contentData: undefined }],
      ["an array contentData", { ...SOUND, contentData: [] }],
      ["no issuerData", { ...SOUND, issuerData: undefined }],
      ["an empty issuerData", { ...SOUND, issuerData: {} }],
      ["an array issuerData", { ...SOUND, issuerData: [] }],
      ["an array resource", { ...SOUND, resource: [] }],
    ]) {
      const page = new DcaData(/** @type {any} */ (delivery));
      for (const read of requestReads(page)) {
        assert.throws(read, badPage, `${label}`);
      }
    }
  });

  test("the sound delivery beside them answers, and an absent resource is no failure", () => {
    const page = new DcaData(SOUND);

    assert.equal(page.version, "1");
    assert.equal(page.resourceJWT, PAGE.resourceJWT);
    assert.equal(page.hasIssuer("issuer_example"), true);
    assert.equal(page.keyIdFor("issuer_example"), "k1");
    assert.deepEqual(page.contentNames(), []);
    assert.equal(page.resource, undefined, "the optional member is absent, not malformed");
  });
});

describe("The item inventory, and the rules a reader takes it under", () => {
  // The format's rules for `contentData`: one required inventory, a missing
  // record that declares no item, a malformed record that fails for itself,
  // and members no reader looks at.

  /** One complete record, so a rule is read against a page that is otherwise sound. */
  const RECORD = {
    contentType: "text/html",
    nonce: "live-nonce",
    aad: "123456|1|bodytext",
    keys: { [GROUP]: [{ t: "251023T15", nonce: "live-wrap-nonce", key: "live-wrapped" }] },
  };

  test("a page carrying the retired maps alone declares no items", () => {
    // The prototype's two parallel maps with no `contentData` beside them.
    // A reader that still consulted them would open this page.
    const page = new DcaData({
      contentSealData: { [CONTENT_NAME]: { contentType: "text/html", nonce: "n", aad: "a" } },
      sealedContentKeys: {
        [CONTENT_NAME]: { [GROUP]: [{ t: "251023T15", nonce: "n", key: "w" }] },
      },
    });

    for (const read of inventoryReads(page)) assert.throws(read, badPage);
  });

  test("the retired maps beside an inventory are ignored, not merged and not preferred", () => {
    // Every value under them differs from the one the inventory carries,
    // and one name is theirs alone, so a merge of either map is visible in
    // an answer below rather than only in the shape of the page.
    const page = new DcaData({
      contentData: { [CONTENT_NAME]: RECORD },
      contentSealData: {
        [CONTENT_NAME]: {
          contentType: "application/json",
          nonce: "retired-nonce",
          aad: "retired-aad",
        },
        "retired-only": { contentType: "text/html", nonce: "n", aad: "a" },
      },
      sealedContentKeys: {
        [CONTENT_NAME]: { retired: [{ t: "251023T15", nonce: "n", key: "w" }] },
        "retired-only": { [GROUP]: [{ t: "251023T15", nonce: "n", key: "w" }] },
      },
    });

    assert.deepEqual(page.contentNames(), [CONTENT_NAME]);
    assert.deepEqual(page.contentDataFor(CONTENT_NAME), RECORD);
    assert.deepEqual(
      page.accessGroupsFor(CONTENT_NAME),
      [GROUP],
      "the retired group is not a group here",
    );
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), RECORD.keys[GROUP]);
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, "retired"), []);
    assert.equal(
      page.contentDataFor("retired-only"),
      undefined,
      "a name only the retired maps carry is no item",
    );
    assert.deepEqual(page.accessGroupsFor("retired-only"), []);
  });

  test("unknown top-level and record members are ignored while the known ones answer", () => {
    const page = new DcaData({
      ...PAGE,
      contentData: { [CONTENT_NAME]: { ...RECORD, placement: "below-fold", nonce2: "n2" } },
      renderedBy: "some-cms/9",
    });

    assert.deepEqual(page.contentNames(), [CONTENT_NAME]);
    assert.equal(/** @type {any} */ (page.contentDataFor(CONTENT_NAME)).nonce, "live-nonce");
    assert.deepEqual(page.accessGroupsFor(CONTENT_NAME), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), RECORD.keys[GROUP]);
    assert.equal(page.version, PAGE.version, "and the fixed fields beside them are unmoved");
  });

  test("ordered and repeated contentEncodings are carried, while malformed lists fail their item", () => {
    const layers = ["first", "second", "first"];
    const malformed = [null, "gzip", [], [""], ["gzip", 7], Array(1)];
    const contentData = {
      [CONTENT_NAME]: { ...RECORD, contentEncodings: layers },
      ...Object.fromEntries(
        malformed.map((contentEncodings, index) => [
          `bad-${index}`,
          { ...RECORD, contentEncodings },
        ]),
      ),
    };
    const page = new DcaData({ contentData });

    assert.deepEqual(/** @type {any} */ (page.contentDataFor(CONTENT_NAME)).contentEncodings, [
      "first",
      "second",
      "first",
    ]);
    for (let index = 0; index < malformed.length; index += 1) {
      assert.throws(() => page.contentDataFor(`bad-${index}`), badPage);
    }

    const inherited = Object.create({ contentEncodings: ["inherited"] });
    Object.assign(inherited, RECORD);
    assert.equal(
      Object.hasOwn(
        /** @type {any} */ (
          new DcaData({ contentData: { inherited } }).contentDataFor("inherited")
        ),
        "contentEncodings",
      ),
      false,
      "a prototype value is not a wire layer",
    );
  });

  test("a malformed keys container supplies no cached route and leaves the record usable", () => {
    // The format holds the cached-wrap map to a non-empty object of
    // accessGroup to a non-empty array. A container that is not one
    // supplies no cached route for its item, and the record beside it stays
    // readable so the issuer-mediated route for that item survives.
    const page = new DcaData({
      contentData: {
        [CONTENT_NAME]: RECORD,
        "empty-keys": { ...RECORD, keys: {} },
        "empty-group": { ...RECORD, keys: { [GROUP]: [] } },
        "group-not-array": { ...RECORD, keys: { [GROUP]: { t: "251023T15" } } },
        "array-keys": { ...RECORD, keys: ["first", "second"] },
        "candidate-without-t": { ...RECORD, keys: { [GROUP]: [{ nonce: "n", key: "w" }] } },
        "candidate-beside-valid": {
          ...RECORD,
          keys: {
            [GROUP]: [
              { nonce: "n", key: "w" },
              { t: "251023T15", nonce: "wrap-nonce", key: "wrapped" },
            ],
          },
        },
      },
    });

    for (const contentName of ["empty-keys", "empty-group", "group-not-array", "array-keys"]) {
      assert.deepEqual(
        page.contentDataFor(contentName),
        page.toObject().contentData[contentName],
        `${contentName}: the record still reads`,
      );
      assert.deepEqual(page.accessGroupsFor(contentName), [], `${contentName}: no cached group`);
      assert.deepEqual(
        page.sealedEntriesFor(contentName, GROUP),
        [],
        `${contentName}: no candidate`,
      );
    }

    // Inside an admitted array, one malformed member supplies no candidate
    // and the group it sits under remains the item's cached route.
    assert.deepEqual(page.accessGroupsFor("candidate-without-t"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("candidate-without-t", GROUP), []);

    // And the malformed member drops itself alone: a valid sibling in the
    // same array is still a candidate, which tells a per-member filter
    // apart from an all-or-nothing reject of the array.
    assert.deepEqual(page.accessGroupsFor("candidate-beside-valid"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("candidate-beside-valid", GROUP), [
      { t: "251023T15", nonce: "wrap-nonce", key: "wrapped" },
    ]);

    // And the sound record beside all of them answers as it always did.
    assert.deepEqual(page.contentDataFor(CONTENT_NAME), RECORD);
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), RECORD.keys[GROUP]);
  });

  test("a missing record declares no item, and a malformed one is a bad page for itself", () => {
    const page = new DcaData({
      contentData: {
        [CONTENT_NAME]: RECORD,
        scalar: "not a record",
        array: [],
        "no-nonce": { contentType: "text/html", aad: "a" },
        "numeric-type": { contentType: 7, nonce: "n", aad: "a" },
        "no-aad": { contentType: "text/html", nonce: "n" },
        "numeric-aad": { contentType: "text/html", nonce: "n", aad: 7 },
      },
    });

    assert.equal(page.contentDataFor("no-such-item"), undefined, "a name the page never declared");
    for (const contentName of [
      "scalar",
      "array",
      "no-nonce",
      "numeric-type",
      "no-aad",
      "numeric-aad",
    ]) {
      assert.throws(() => page.contentDataFor(contentName), badPage, contentName);
    }

    // Each of those sits in the inventory beside a sound record, and the
    // sound one answers exactly as it does on a page with nothing wrong.
    assert.deepEqual(page.contentDataFor(CONTENT_NAME), RECORD);
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), RECORD.keys[GROUP]);
  });
});

describe("Identifier-keyed maps, admitted whole", () => {
  // The format's identifier section: a consumer rejects a map keyed by
  // contentName, accessGroup or issuerName when one member name violates the
  // grammar, and it does not ignore the invalid name while accepting its
  // siblings. What the rejection costs follows the map: `contentData` and
  // `issuerData` are the delivery, a cached-wrap map is that item's cached
  // route, and a sealed route map is that route.

  const RECORD = {
    contentType: "text/html",
    nonce: "n",
    aad: "123456|1|bodytext",
    keys: { [GROUP]: [{ t: "251023T15", nonce: "wrap-nonce", key: "wrapped" }] },
  };

  /** One usable block, so a rule about a map is read beside a sound page. */
  const block = (/** @type {any} */ sealed) => ({
    keyId: "k1",
    unlockUrl: "https://issuer.example/unlock",
    sealed,
  });

  test("a contentData name outside the grammar rejects the inventory", () => {
    for (const name of ["2bad", "bad|name", "__proto__", "", "a".repeat(65)]) {
      const page = new DcaData({ ...PAGE, contentData: { [name]: RECORD, bodytext: RECORD } });

      assert.throws(() => page.contentNames(), badPage, name);
      assert.throws(
        () => page.contentDataFor("bodytext"),
        badPage,
        `${name}: and its sound sibling`,
      );
      assert.throws(() => page.accessGroupsFor("bodytext"), badPage, name);
      assert.throws(() => page.sealedEntriesFor("bodytext", GROUP), badPage, name);
    }
  });

  test("an issuerData name outside the grammar rejects the issuer map", () => {
    for (const name of ["2bad", "bad|name", "__proto__"]) {
      const page = new DcaData({
        ...PAGE,
        issuerData: {
          [name]: block({}),
          issuer_example: block({ contentKeys: { bodytext: "blob" } }),
        },
      });

      assert.throws(() => page.hasIssuer("issuer_example"), badPage, name);
      assert.throws(() => page.keyIdFor("issuer_example"), badPage, name);
      assert.throws(() => page.sealedContentKeyFor("issuer_example", "bodytext"), badPage, name);
      assert.throws(() => page.issuerNamesFor(GROUP), badPage, name);
    }
  });

  test("a cached-wrap name outside the grammar supplies no cached route for that item", () => {
    const candidate = [{ t: "251023T15", nonce: "wrap-nonce", key: "wrapped" }];
    const page = new DcaData({
      ...PAGE,
      contentData: {
        bodytext: { ...RECORD, keys: { "2bad": candidate, [GROUP]: candidate } },
        sidebar: RECORD,
      },
    });

    assert.deepEqual(page.accessGroupsFor("bodytext"), [], "the map is rejected, not filtered");
    assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), []);
    assert.deepEqual(
      page.contentDataFor("bodytext"),
      page.toObject().contentData.bodytext,
      "and the record still reads, so the issuer-mediated route stands",
    );

    // The sibling item's own cached route is untouched.
    assert.deepEqual(page.accessGroupsFor("sidebar"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("sidebar", GROUP), RECORD.keys[GROUP]);
  });

  test("a sealed route-map name outside the grammar supplies no route of that kind", () => {
    const page = new DcaData({
      ...PAGE,
      issuerData: {
        issuer_example: block({
          contentKeys: { "2bad": "blob", bodytext: "content-blob" },
          periodKeys: {
            "bad|group": { "251023T15": "blob" },
            [GROUP]: { "251023T15": "period-blob" },
          },
        }),
        other_example: block({ contentKeys: { bodytext: "other-blob" } }),
      },
    });

    assert.equal(page.sealedContentKeyFor("issuer_example", "bodytext"), undefined);
    assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
    assert.equal(page.hasIssuer("issuer_example"), true, "the block itself is still usable");
    assert.equal(
      page.sealedContentKeyFor("other_example", "bodytext"),
      "other-blob",
      "and the sibling issuer carries its own route",
    );
  });

  test("a periodChainKeys name outside the grammar supplies no chain route", () => {
    // The chain carrier is keyed by accessGroup, so the same rule reaches it:
    // a present `sealed.periodChainKeys` rejected under the identifier section
    // supplies no chain route for that issuer block, and it leaves
    // `sealed.contentKeys`, `sealed.periodKeys` and the sibling issuer alone.
    const family = { "251023T23": "chain-blob" };
    const page = new DcaData({
      ...PAGE,
      issuerData: {
        issuer_example: block({
          contentKeys: { bodytext: "content-blob" },
          periodKeys: { [GROUP]: { "251023T15": "period-blob" } },
          periodChainKeys: { "bad|group": family, [GROUP]: family },
        }),
        other_example: block({
          periodChainKeys: { [GROUP]: family },
        }),
      },
    });

    assert.equal(page.sealedPeriodChainKeysFor("issuer_example", GROUP), undefined);
    assert.equal(
      page.sealedContentKeyFor("issuer_example", "bodytext"),
      "content-blob",
      "and the other kinds in the same block stand",
    );
    assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", GROUP), {
      "251023T15": "period-blob",
    });
    assert.deepEqual(
      page.issuerNamesFor(GROUP),
      ["issuer_example"],
      "only the issuer carrying sound periodKeys remains base-eligible",
    );

    // An issuer whose only route is the rejected chain map carries no family.
    const chainOnly = new DcaData({
      ...PAGE,
      issuerData: {
        issuer_example: block({ periodChainKeys: { "bad|group": family, [GROUP]: family } }),
        other_example: block({ periodChainKeys: { [GROUP]: family } }),
      },
    });

    assert.equal(chainOnly.sealedPeriodChainKeysFor("issuer_example", GROUP), undefined);
    assert.deepEqual(
      chainOnly.issuerNamesFor(GROUP),
      [],
      "an optional chain route does not change base exact-key eligibility",
    );
    assert.deepEqual(chainOnly.sealedPeriodChainKeysFor("other_example", GROUP), family);
  });
});

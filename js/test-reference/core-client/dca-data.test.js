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

import { DcaData } from "../../core-client/DcaData.js";
import { Client } from "../../test-lib/harnesses/client.js";
import { actorWorld } from "../../demo/scenarios/world.js";
import { CONTENT_NAME, ISSUER_NAME, KEY_ID } from "../../demo/scenarios/fixtures.js";
import { INHERITED } from "../../test-lib/fixtures/inherited-names.js";
import { base64urlEncode, utf8Encode } from "../../core-shared/codec.js";

const GROUP = "article";
const PUBLISHER_ORIGIN = "https://news.example";
const HEADER = base64urlEncode(utf8Encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "k1" })));

/** One page shaped like the wire, written out rather than rendered. */
const PAGE = {
  version: "1",
  resource: { resourceId: "123456", renderId: "AAAAAAAAAAAAAAAAAAAAAA" },
  resourceJWT: `${HEADER}.${base64urlEncode(
    utf8Encode(
      JSON.stringify({
        resourceId: "123456",
        renderId: "AAAAAAAAAAAAAAAAAAAAAA",
      }),
    ),
  )}.c2lnbmF0dXJl`,
  issuerData: [
    {
      issuerName: "issuer_example",
      keyId: "k1",
      unlockUrl: "https://issuer.example/unlock",
      sealed: {
        contentKeys: [{ contentName: "bodytext", key: "content-blob" }],
        periodKeys: [{ accessGroup: GROUP, period: "251023T1500", key: "period-blob" }],
        chainKeys: [
          { accessGroup: GROUP, cutoff: "251023T2300", key: "chain-blob" },
          { accessGroup: GROUP, cutoff: "251024T1100", key: "next-chain-blob" },
        ],
      },
    },
    {
      issuerName: "other_example",
      keyId: "k9",
      unlockUrl: "https://other.example/unlock",
      sealed: { contentKeys: [{ contentName: "bodytext", key: "other-blob" }] },
    },
  ],
  contentData: [
    {
      contentName: "bodytext",
      contentType: "text/html",
      nonce: "n",
      keys: [{ accessGroup: GROUP, period: "251023T1500", key: "wrapped" }],
    },
  ],
};

/**
 * A `contentData` collection written from a name-keyed map, so a fixture that
 * varies one record reads as that record.
 *
 * @param {Record<string, any>} records
 * @returns {any[]}
 */
const items = (records) =>
  Object.entries(records).map(([contentName, record]) => ({ contentName, ...record }));

/**
 * An `issuerData` collection written the same way.
 *
 * @param {Record<string, any>} blocks
 * @returns {any[]}
 */
const issuers = (blocks) =>
  Object.entries(blocks).map(([issuerName, block]) => ({ issuerName, ...block }));

/**
 * Wire wrap records for one group, from the `{ t, key }` entries the view
 * hands a candidate source.
 *
 * @param {string} accessGroup
 * @param {any[]} entries
 * @returns {any[]}
 */
const wraps = (accessGroup, entries) =>
  entries.map(({ t, ...rest }) => ({ accessGroup, period: t, ...rest }));

/** The one record PAGE carries. */
const BODY = PAGE.contentData[0];

/**
 * The wire record a page carries for one item, found by its name.
 *
 * @param {DcaData} page
 * @param {string} contentName
 * @returns {any}
 */
const recordOf = (page, contentName) =>
  page
    .toObject()
    .contentData.find((/** @type {any} */ record) => record.contentName === contentName);

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
    assert.equal(page.renderId, "AAAAAAAAAAAAAAAAAAAAAA");
    assert.equal(page.publisherOrigin, PUBLISHER_ORIGIN);
    assert.equal(page.resourceJWT, PAGE.resourceJWT);

    assert.equal(page.hasIssuer("issuer_example"), true);
    assert.equal(page.hasIssuer("nobody.example"), false);
    assert.equal(page.keyIdFor("issuer_example"), "k1");

    assert.deepEqual(page.sealedContentKeysFor("issuer_example", "bodytext"), ["content-blob"]);
    assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", GROUP), [
      { accessGroup: GROUP, period: "251023T1500", key: "period-blob" },
    ]);
    assert.deepEqual(page.sealedChainKeysFor("issuer_example", GROUP), [
      { accessGroup: GROUP, cutoff: "251023T2300", key: "chain-blob" },
      { accessGroup: GROUP, cutoff: "251024T1100", key: "next-chain-blob" },
    ]);
    assert.deepEqual(page.accessGroupsFor("bodytext"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), [
      { t: "251023T1500", key: "wrapped" },
    ]);
    assert.deepEqual(page.contentDataFor("bodytext"), BODY);

    // Only the issuer that carries the family, and in the page's order.
    assert.deepEqual(page.issuerNamesFor(GROUP), ["issuer_example"]);
    assert.deepEqual(page.issuerNamesFor("no-such-group"), []);
  });

  test("a name off the wire never resolves to an inherited member", () => {
    const page = new DcaData(PAGE);

    for (const name of INHERITED) {
      assert.equal(page.hasIssuer(name), false, `hasIssuer(${name})`);
      assert.equal(page.keyIdFor(name), undefined, `keyIdFor(${name})`);
      assert.deepEqual(page.sealedContentKeysFor(name, name), []);
      assert.equal(page.sealedPeriodKeysFor("issuer_example", name), undefined);
      assert.equal(page.sealedChainKeysFor("issuer_example", name), undefined);
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
        )}.c2lnbmF0dXJl`,
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
      )}.c2lnbmF0dXJl`,
    });
    assert.equal(absent.renderId, "token-render");
    assert.equal(absent.publisherOrigin, undefined);

    assert.throws(
      () => new DcaData({}, { publisherOrigin: "news.example" }),
      (/** @type {any} */ error) => error.code === "bad_config",
    );
  });

  test("renderId reads a canonical unverified token and refuses noncanonical segment spellings", () => {
    const payload = base64urlEncode(utf8Encode(JSON.stringify({ renderId: "token-render" })));
    const tokenWith = (/** @type {string} */ header, /** @type {string} */ body, signature) =>
      new DcaData({ resourceJWT: `${header}.${body}.${signature}` });

    // Canonical spelling is enough; the client never verifies the signature.
    assert.equal(tokenWith(HEADER, payload, "c2lnbmF0dXJl").renderId, "token-render");
    assert.equal(tokenWith(HEADER, payload, "AAAA").renderId, "token-render");

    for (const [name, header, body, signature] of [
      ["a signature with a dangling character", HEADER, payload, "signature"],
      ["a one-character signature", HEADER, payload, "x"],
      ["a padded signature", HEADER, payload, "c2lnbmF0dXJlAA=="],
      ["a signature with nonzero trailing bits", HEADER, payload, "AB"],
      ["a standard-alphabet signature", HEADER, payload, "c2ln+mF0/XJl"],
      ["a padded payload", HEADER, `${payload}==`, "c2lnbmF0dXJl"],
      ["a padded header", `${HEADER}=`, payload, "c2lnbmF0dXJl"],
    ]) {
      assert.throws(
        () => tokenWith(header, body, signature).renderId,
        (/** @type {any} */ error) => error.code === "bad_jwt",
        name,
      );
    }
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

    for (const entry of [{}, { keyId: "k1" }, { sealed: {} }]) {
      const data = { ...PAGE, issuerData: issuers({ [ISSUER_NAME]: entry }) };

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
        issuerData: issuers({
          [ISSUER_NAME]: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
        }),
      }).hasIssuer(ISSUER_NAME),
      true,
    );
  });

  test("a selected issuer block is usable only when its structure admits it", () => {
    // The format: a block is usable only when its `sealed` member is a
    // non-array object and `keyId` is a nonempty string. A block
    // that is not one carries no route, and the sibling issuer stands.
    const sound = {
      keyId: "k9",
      unlockUrl: "https://other.example/unlock",
      sealed: { contentKeys: [{ contentName: "bodytext", key: "other-blob" }] },
    };
    const malformed = [
      { keyId: "k1", unlockUrl: "https://issuer.example/unlock" },
      { keyId: 7, unlockUrl: "https://issuer.example/unlock", sealed: {} },
      { keyId: "", unlockUrl: "https://issuer.example/unlock", sealed: {} },
      { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: [] },
    ];

    for (const block of malformed) {
      const label = JSON.stringify(block);
      const page = new DcaData({
        ...PAGE,
        issuerData: issuers({ issuer_example: block, other_example: sound }),
      });

      assert.equal(page.hasIssuer("issuer_example"), false, label);
      assert.equal(page.keyIdFor("issuer_example"), undefined, label);
      assert.deepEqual(page.sealedContentKeysFor("issuer_example", "bodytext"), [], label);
      assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined, label);
      assert.equal(page.sealedChainKeysFor("issuer_example", GROUP), undefined, label);
      assert.deepEqual(page.issuerNamesFor(GROUP), [], label);

      assert.equal(page.hasIssuer("other_example"), true, `${label}: the sibling issuer stands`);
      assert.deepEqual(
        page.sealedContentKeysFor("other_example", "bodytext"),
        ["other-blob"],
        label,
      );
    }
  });

  test("a sealed collection that is not an array carries no route of that kind", () => {
    // A record that is not a non-array object, or a period record without a
    // string `period`, supplies no candidate, and its valid siblings in the
    // same collection stay. The chain carrier's own family rules belong to
    // the chain-key extension.
    const vault = { accessGroup: "vault", period: "251023T1500", key: "AQ" };
    const page = new DcaData({
      ...PAGE,
      issuerData: issuers({
        issuer_example: {
          keyId: "k1",
          unlockUrl: "https://issuer.example/unlock",
          sealed: {
            contentKeys: [{ contentName: "bodytext", key: "content-blob" }],
            periodKeys: [
              { accessGroup: GROUP, key: "AQ" },
              { accessGroup: GROUP, period: 7, key: "AQ" },
              ["251023T1500"],
              vault,
            ],
          },
        },
      }),
    });

    assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
    assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", "vault"), [vault]);
    assert.deepEqual(page.sealedContentKeysFor("issuer_example", "bodytext"), ["content-blob"]);

    // A container that is not an array carries no route either.
    for (const sealed of [
      { periodKeys: { [GROUP]: { "251023T1500": "AQ" } } },
      { periodKeys: "a string" },
      { contentKeys: { bodytext: "content-blob" } },
    ]) {
      const carrier = new DcaData({
        ...PAGE,
        issuerData: issuers({
          issuer_example: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed },
        }),
      });
      assert.equal(carrier.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
      assert.deepEqual(carrier.sealedContentKeysFor("issuer_example", "bodytext"), []);
    }
  });

  test("a chain-key collection that is not an array carries no route", () => {
    const page = new DcaData({
      ...PAGE,
      issuerData: issuers({
        issuer_example: {
          keyId: "k1",
          unlockUrl: "https://issuer.example/unlock",
          sealed: { chainKeys: { [GROUP]: { "251023T2300": "chain-blob" } } },
        },
      }),
    });

    assert.equal(page.sealedChainKeysFor("issuer_example", GROUP), undefined);
  });

  test("an object where the cached-wrap collection belongs supplies no coordinates", () => {
    // The old accessGroup-keyed map is no collection, so the container is
    // malformed and the item offers no cached route. Array elements that are
    // not records carry no coordinate either, and positions never become one.
    for (const keys of [{ [GROUP]: [{ t: "251023T1500", key: "w" }] }, ["first", "second"]]) {
      const page = new DcaData({ contentData: items({ bodytext: { keys } }) });

      assert.deepEqual(page.accessGroupsFor("bodytext"), [], JSON.stringify(keys));
      assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), []);
      assert.deepEqual(page.sealedEntriesFor("bodytext", "0"), []);
    }
    const page = new DcaData({ contentData: items({ bodytext: { keys: ["first"] } }) });

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

    const issuerBlock = parsed.issuerData.find(
      (/** @type {any} */ block) => block.issuerName === ISSUER_NAME,
    );
    const itemRecord = parsed.contentData.find(
      (/** @type {any} */ record) => record.contentName === CONTENT_NAME,
    );
    assert.equal(page.hasIssuer(ISSUER_NAME), true);
    assert.equal(page.keyIdFor(ISSUER_NAME), KEY_ID);
    assert.deepEqual(
      page.sealedContentKeysFor(ISSUER_NAME, CONTENT_NAME),
      issuerBlock.sealed.contentKeys
        .filter((/** @type {any} */ record) => record.contentName === CONTENT_NAME)
        .map((/** @type {any} */ record) => record.key),
    );

    const groups = page.accessGroupsFor(CONTENT_NAME);
    assert.ok(groups.length > 0, "the fixture wraps its bodytext under at least one group");
    for (const group of groups) {
      assert.deepEqual(
        page.sealedPeriodKeysFor(ISSUER_NAME, group),
        issuerBlock.sealed.periodKeys.filter(
          (/** @type {any} */ record) => record.accessGroup === group,
        ),
      );
      assert.deepEqual(
        page.sealedEntriesFor(CONTENT_NAME, group),
        itemRecord.keys
          .filter((/** @type {any} */ entry) => entry.accessGroup === group)
          .map(({ period, key }) => ({ t: period, key })),
      );
      assert.deepEqual(page.issuerNamesFor(group), [ISSUER_NAME]);
    }

    assert.equal(page.contentDataFor(CONTENT_NAME), itemRecord);
    assert.equal(page.toObject(), parsed, "the page is handed on unchanged");
  });
});

describe("The outer object, admitted before a request or a key", () => {
  // The format requires `version` "1", a string `resourceJWT`, a
  // `contentData` array and a non-empty `issuerData` array, and makes
  // `resource` an object when it is present. Failure of one of them is a
  // delivery-wide structural failure, so it lands before the delivery is
  // exposed to request construction.

  const SOUND = {
    version: "1",
    resourceJWT: PAGE.resourceJWT,
    contentData: [],
    issuerData: issuers({
      issuer_example: { keyId: "k1", unlockUrl: "https://issuer.example/unlock", sealed: {} },
    }),
  };

  /** What a request is derived from, so the rule is read against every one. */
  const requestReads = (/** @type {DcaData} */ page) => [
    () => page.version,
    () => page.resourceJWT,
    () => page.hasIssuer("issuer_example"),
    () => page.keyIdFor("issuer_example"),
    () => page.sealedContentKeysFor("issuer_example", "bodytext"),
    () => page.sealedPeriodKeysFor("issuer_example", GROUP),
  ];

  test("a delivery missing an outer requirement answers nothing a request is built from", () => {
    for (const [label, delivery] of [
      ["no version", { ...SOUND, version: undefined }],
      ["another version", { ...SOUND, version: "2" }],
      ["a numeric version", { ...SOUND, version: 1 }],
      ["a non-string resourceJWT", { ...SOUND, resourceJWT: 17 }],
      ["no contentData", { ...SOUND, contentData: undefined }],
      ["an object contentData", { ...SOUND, contentData: {} }],
      ["a name-keyed contentData", { ...SOUND, contentData: { bodytext: BODY } }],
      ["no issuerData", { ...SOUND, issuerData: undefined }],
      ["an empty issuerData", { ...SOUND, issuerData: [] }],
      ["an object issuerData", { ...SOUND, issuerData: {} }],
      [
        "a name-keyed issuerData",
        { ...SOUND, issuerData: { issuer_example: SOUND.issuerData[0] } },
      ],
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

  /** The candidates RECORD offers, as the view hands them on. */
  const ENTRIES = [{ t: "251023T1500", key: "live-wrapped" }];

  /** One complete record, so a rule is read against a page that is otherwise sound. */
  const RECORD = {
    contentType: "text/html",
    nonce: "live-nonce",
    aad: "123456|1|bodytext",
    keys: wraps(GROUP, ENTRIES),
  };

  test("a page carrying the retired maps alone declares no items", () => {
    // The prototype's two parallel maps with no `contentData` beside them.
    // A reader that still consulted them would open this page.
    const page = new DcaData({
      contentSealData: { [CONTENT_NAME]: { contentType: "text/html", nonce: "n", aad: "a" } },
      sealedContentKeys: {
        [CONTENT_NAME]: { [GROUP]: [{ t: "251023T1500", nonce: "n", key: "w" }] },
      },
    });

    for (const read of inventoryReads(page)) assert.throws(read, badPage);
  });

  test("the retired maps beside an inventory are ignored, not merged and not preferred", () => {
    // Every value under them differs from the one the inventory carries,
    // and one name is theirs alone, so a merge of either map is visible in
    // an answer below rather than only in the shape of the page.
    const page = new DcaData({
      contentData: items({ [CONTENT_NAME]: RECORD }),
      contentSealData: {
        [CONTENT_NAME]: {
          contentType: "application/json",
          nonce: "retired-nonce",
          aad: "retired-aad",
        },
        "retired-only": { contentType: "text/html", nonce: "n", aad: "a" },
      },
      sealedContentKeys: {
        [CONTENT_NAME]: { retired: [{ t: "251023T1500", nonce: "n", key: "w" }] },
        "retired-only": { [GROUP]: [{ t: "251023T1500", nonce: "n", key: "w" }] },
      },
    });

    assert.deepEqual(page.contentNames(), [CONTENT_NAME]);
    assert.deepEqual(page.contentDataFor(CONTENT_NAME), { contentName: CONTENT_NAME, ...RECORD });
    assert.deepEqual(
      page.accessGroupsFor(CONTENT_NAME),
      [GROUP],
      "the retired group is not a group here",
    );
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), ENTRIES);
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
      contentData: items({ [CONTENT_NAME]: { ...RECORD, placement: "below-fold", nonce2: "n2" } }),
      renderedBy: "some-cms/9",
    });

    assert.deepEqual(page.contentNames(), [CONTENT_NAME]);
    assert.equal(/** @type {any} */ (page.contentDataFor(CONTENT_NAME)).nonce, "live-nonce");
    assert.deepEqual(page.accessGroupsFor(CONTENT_NAME), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), ENTRIES);
    assert.equal(page.version, PAGE.version, "and the fixed fields beside them are unmoved");
  });

  test("ordered and repeated contentEncodings are carried, while malformed lists fail their item", () => {
    const layers = ["first", "second", "first"];
    const malformed = [null, "gzip", [], [""], ["gzip", 7], Array(1)];
    const contentData = items({
      [CONTENT_NAME]: { ...RECORD, contentEncodings: layers },
      ...Object.fromEntries(
        malformed.map((contentEncodings, index) => [
          `bad-${index}`,
          { ...RECORD, contentEncodings },
        ]),
      ),
    });
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
    Object.assign(inherited, { contentName: "inherited", ...RECORD });
    assert.equal(
      Object.hasOwn(
        /** @type {any} */ (new DcaData({ contentData: [inherited] }).contentDataFor("inherited")),
        "contentEncodings",
      ),
      false,
      "a prototype value is not a wire layer",
    );
  });

  test("a malformed keys container supplies no cached route and leaves the record usable", () => {
    // The format holds the cached-wrap collection to a non-empty array of
    // wrap records. A container that is not one supplies no cached route for
    // its item, and the record beside it stays readable so the
    // issuer-mediated route for that item survives.
    const page = new DcaData({
      contentData: items({
        [CONTENT_NAME]: RECORD,
        "empty-keys": { ...RECORD, keys: [] },
        "object-keys": { ...RECORD, keys: { [GROUP]: [{ t: "251023T1500", key: "w" }] } },
        "scalar-keys": { ...RECORD, keys: "a string" },
        "candidate-without-period": { ...RECORD, keys: [{ accessGroup: GROUP, key: "w" }] },
        "candidate-beside-valid": {
          ...RECORD,
          keys: [
            { accessGroup: GROUP, key: "w" },
            { accessGroup: GROUP, period: 7, key: "w" },
            { accessGroup: GROUP, period: "251023T1500" },
            "not a record",
            null,
            [GROUP, "251023T1500", "w"],
            { accessGroup: GROUP, period: "251023T1500", key: "wrapped" },
          ],
        },
      }),
    });

    for (const contentName of ["empty-keys", "object-keys", "scalar-keys"]) {
      assert.equal(
        page.contentDataFor(contentName),
        recordOf(page, contentName),
        `${contentName}: the record still reads`,
      );
      assert.deepEqual(page.accessGroupsFor(contentName), [], `${contentName}: no cached group`);
      assert.deepEqual(
        page.sealedEntriesFor(contentName, GROUP),
        [],
        `${contentName}: no candidate`,
      );
    }

    // Inside an admitted collection, one malformed element supplies no
    // candidate. A record still names its group, so the group stays listed.
    assert.deepEqual(page.accessGroupsFor("candidate-without-period"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("candidate-without-period", GROUP), []);

    // And the malformed element drops itself alone: a valid sibling in the
    // same collection is still a candidate, which tells a per-element filter
    // apart from an all-or-nothing reject of the collection.
    assert.deepEqual(page.accessGroupsFor("candidate-beside-valid"), [GROUP]);
    assert.deepEqual(page.sealedEntriesFor("candidate-beside-valid", GROUP), [
      { t: "251023T1500", key: "wrapped" },
    ]);

    // And the sound record beside all of them answers as it always did.
    assert.deepEqual(page.contentDataFor(CONTENT_NAME), { contentName: CONTENT_NAME, ...RECORD });
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), ENTRIES);
  });

  test("a wrap record's period reaches a candidate source as t, and a carried nonce of any type changes nothing", () => {
    // The wrap nonce is derived, so a record carries only its coordinate and
    // key. An old `nonce` member is unknown: it neither makes nor breaks a
    // candidate. The view hands the label on under the name the candidate
    // sources use, and keeps the other members, such as a `bind` marker.
    const entries = [
      { t: "251023T1400", key: "wrapped" },
      { t: "251023T1400", key: "bound", bind: "marker" },
      ...["n", "", 12, null, [], { bytes: 1 }].map((nonce) => ({
        t: "251023T1500",
        nonce,
        key: "wrapped",
      })),
    ];
    const page = new DcaData({
      ...PAGE,
      contentData: items({
        bodytext: { ...RECORD, keys: wraps(GROUP, entries) },
        "nonce-without-key": {
          ...RECORD,
          keys: [{ accessGroup: GROUP, period: "251023T1500", nonce: "n" }],
        },
      }),
    });
    assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), entries);
    assert.deepEqual(page.sealedEntriesFor("nonce-without-key", GROUP), []);
  });

  test("wrap records group by their accessGroup field, in first-seen order, and position grants nothing", () => {
    const records = [
      { accessGroup: "vault", period: "251023T1500", key: "v1" },
      { accessGroup: GROUP, period: "251023T1500", key: "a1" },
      { accessGroup: "vault", period: "251023T1600", key: "v2" },
    ];
    const forward = new DcaData({
      ...PAGE,
      contentData: items({ bodytext: { ...RECORD, keys: records } }),
    });
    const reversed = new DcaData({
      ...PAGE,
      contentData: items({ bodytext: { ...RECORD, keys: [...records].reverse() } }),
    });

    assert.deepEqual(forward.accessGroupsFor("bodytext"), ["vault", GROUP]);
    assert.deepEqual(reversed.accessGroupsFor("bodytext"), ["vault", GROUP]);
    assert.deepEqual(forward.sealedEntriesFor("bodytext", "vault"), [
      { t: "251023T1500", key: "v1" },
      { t: "251023T1600", key: "v2" },
    ]);
    assert.deepEqual(reversed.sealedEntriesFor("bodytext", "vault"), [
      { t: "251023T1600", key: "v2" },
      { t: "251023T1500", key: "v1" },
    ]);
    assert.deepEqual(forward.sealedEntriesFor("bodytext", GROUP), [
      { t: "251023T1500", key: "a1" },
    ]);
    assert.deepEqual(forward.sealedEntriesFor("bodytext", "0"), []);
  });

  test("several wrap records at one coordinate are all candidates, none overwriting another", () => {
    // Candidate alternatives: the view keeps every distinct record at one
    // (accessGroup, period), in both orders, and a repeated identical record
    // stays a raw record the trial budget counts.
    const wrong = { accessGroup: GROUP, period: "251023T1500", key: "wrong" };
    const right = { accessGroup: GROUP, period: "251023T1500", key: "right" };
    for (const keys of [
      [wrong, right],
      [right, wrong],
      [wrong, wrong, right],
    ]) {
      const page = new DcaData({ ...PAGE, contentData: items({ bodytext: { ...RECORD, keys } }) });
      assert.deepEqual(
        page.sealedEntriesFor("bodytext", GROUP),
        keys.map(({ period, key }) => ({ t: period, key })),
      );
    }
  });

  test("a handed-on entry is a copy, so a later page edit does not move it", () => {
    const data = structuredClone({ ...PAGE, contentData: items({ bodytext: RECORD }) });
    const page = new DcaData(data);
    const [entry] = page.sealedEntriesFor("bodytext", GROUP);
    data.contentData[0].keys[0].period = "251023T1600";
    data.contentData[0].keys[0].key = "moved";
    assert.deepEqual(entry, { t: "251023T1500", key: "live-wrapped" });
  });

  test("a missing record declares no item, and a malformed one is a bad page for itself", () => {
    const page = new DcaData({
      ...PAGE,
      contentData: items({
        [CONTENT_NAME]: RECORD,
        "no-nonce": { contentType: "text/html" },
        "numeric-type": { contentType: 7, nonce: "n" },
        "empty-encodings": { contentType: "text/html", nonce: "n", contentEncodings: [] },
      }),
    });

    assert.equal(page.contentDataFor("no-such-item"), undefined, "a name the page never declared");
    assert.equal(page.contentItemFor("no-such-item"), null, "and captures no item for it");
    for (const contentName of ["numeric-type", "empty-encodings"]) {
      assert.throws(() => page.contentDataFor(contentName), badPage, contentName);
      assert.throws(() => page.contentItemFor(contentName), badPage, contentName);
    }

    // Each of those sits in the inventory beside a sound record, and the
    // sound one answers exactly as it does on a page with nothing wrong.
    assert.deepEqual(page.contentDataFor(CONTENT_NAME), { contentName: CONTENT_NAME, ...RECORD });
    assert.deepEqual(page.sealedEntriesFor(CONTENT_NAME, GROUP), ENTRIES);
  });

  test("the last whole record for one contentName is the item, with nothing merged", () => {
    // Replacement, not merging: the earlier record's keys and encodings do
    // not survive beside the later record, and the order decides which one.
    const first = {
      contentName: CONTENT_NAME,
      contentType: "text/html",
      contentEncodings: ["gzip"],
      keys: wraps(GROUP, ENTRIES),
    };
    const last = { contentName: CONTENT_NAME, contentType: "text/plain" };

    const forward = new DcaData({ ...PAGE, contentData: [first, last] });
    assert.equal(forward.contentDataFor(CONTENT_NAME), last);
    assert.deepEqual(forward.contentNames(), [CONTENT_NAME]);
    assert.deepEqual(forward.accessGroupsFor(CONTENT_NAME), []);
    assert.deepEqual(forward.sealedEntriesFor(CONTENT_NAME, GROUP), []);
    assert.deepEqual(forward.contentItemFor(CONTENT_NAME)?.contentEncodings, []);

    const reversed = new DcaData({ ...PAGE, contentData: [last, first] });
    assert.equal(reversed.contentDataFor(CONTENT_NAME), first);
    assert.deepEqual(reversed.accessGroupsFor(CONTENT_NAME), [GROUP]);
    assert.deepEqual(reversed.sealedEntriesFor(CONTENT_NAME, GROUP), ENTRIES);

    // A malformed last record fails the item even when an earlier one is sound.
    const broken = new DcaData({
      ...PAGE,
      contentData: [first, { contentName: CONTENT_NAME, contentType: 7 }],
    });
    assert.throws(() => broken.contentDataFor(CONTENT_NAME), badPage);
  });

  test("unique items resolve by name whatever their array order", () => {
    const a = { contentName: "a", contentType: "text/html" };
    const b = { contentName: "b", contentType: "text/plain" };
    for (const contentData of [
      [a, b],
      [b, a],
    ]) {
      const page = new DcaData({ ...PAGE, contentData });
      assert.equal(page.contentDataFor("a"), a);
      assert.equal(page.contentDataFor("b"), b);
      assert.deepEqual([...page.contentNames()].sort(), ["a", "b"]);
    }
  });
});

describe("Identifier-carrying collections, admitted whole", () => {
  // The format's identifier section: a consumer rejects a collection whose
  // records carry contentName, accessGroup or issuerName when one record's
  // identifier is missing or violates the grammar, and it does not ignore the
  // invalid record while accepting its siblings. What the rejection costs
  // follows the collection: `contentData` and `issuerData` are the delivery,
  // a cached-wrap collection is that item's cached route, and a sealed route
  // map is that route.

  const ENTRIES = [{ t: "251023T1500", key: "wrapped" }];

  const RECORD = {
    contentType: "text/html",
    nonce: "n",
    aad: "123456|1|bodytext",
    keys: wraps(GROUP, ENTRIES),
  };

  /** One usable block, so a rule about a map is read beside a sound page. */
  const block = (/** @type {any} */ sealed) => ({
    keyId: "k1",
    unlockUrl: "https://issuer.example/unlock",
    sealed,
  });

  test("a contentData name outside the grammar rejects the inventory", () => {
    for (const name of ["2bad", "bad|name", "", "a".repeat(65), 7, null, undefined]) {
      const page = new DcaData({
        ...PAGE,
        contentData: [
          { ...RECORD, contentName: name },
          { ...RECORD, contentName: "bodytext" },
        ],
      });

      assert.throws(() => page.contentNames(), badPage, String(name));
      assert.throws(
        () => page.contentDataFor("bodytext"),
        badPage,
        `${String(name)}: and its sound sibling`,
      );
      assert.throws(() => page.accessGroupsFor("bodytext"), badPage, String(name));
      assert.throws(() => page.sealedEntriesFor("bodytext", GROUP), badPage, String(name));
      assert.throws(() => page.version, badPage, String(name));
    }
  });

  test("a contentData element that is not a record supplies no item, and its sibling opens", () => {
    for (const element of ["not a record", null, 7, [], ["bodytext"]]) {
      const label = JSON.stringify(element);
      const page = new DcaData({
        ...PAGE,
        contentData: [element, { ...RECORD, contentName: "bodytext" }, element],
      });
      assert.deepEqual(page.contentNames(), ["bodytext"], label);
      assert.deepEqual(page.contentDataFor("bodytext"), { ...RECORD, contentName: "bodytext" });
      assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), ENTRIES, label);
      assert.ok(page.contentItemFor("bodytext"), label);
      assert.equal(page.version, "1", label);
    }
  });

  test("an inherited contentName is no identity", () => {
    const inherited = Object.assign(Object.create({ contentName: "bodytext" }), RECORD);
    const page = new DcaData({ ...PAGE, contentData: [inherited] });
    assert.throws(() => page.contentNames(), badPage);
  });

  test("an issuerData name outside the grammar rejects the issuer collection", () => {
    for (const name of ["2bad", "bad|name", "__proto__", 7, undefined]) {
      const page = new DcaData({
        ...PAGE,
        issuerData: [
          { issuerName: name, ...block({}) },
          {
            issuerName: "issuer_example",
            ...block({ contentKeys: [{ contentName: "bodytext", key: "blob" }] }),
          },
        ],
      });

      assert.throws(() => page.hasIssuer("issuer_example"), badPage, String(name));
      assert.throws(() => page.keyIdFor("issuer_example"), badPage, String(name));
      assert.throws(
        () => page.sealedContentKeysFor("issuer_example", "bodytext"),
        badPage,
        String(name),
      );
      assert.throws(() => page.issuerNamesFor(GROUP), badPage, String(name));
    }
  });

  test("an issuerData element that is not a record supplies no issuer, and its sibling stands", () => {
    for (const element of [null, false, 0, "", [], "a string"]) {
      const label = JSON.stringify(element);
      const page = new DcaData({
        ...PAGE,
        issuerData: [element, { issuerName: "issuer_example", ...block({}) }],
      });
      assert.equal(page.hasIssuer("issuer_example"), true, label);
      assert.equal(page.keyIdFor("issuer_example"), "k1", label);
    }
  });

  test("the last whole issuer block is the issuer, and no field crosses from another block", () => {
    // keyId and envelope select how the issuer opens the sealed material
    // beside them, so they must come from the same block.
    const first = {
      issuerName: "issuer_example",
      keyId: "k-first",
      envelope: "first-envelope",
      unlockUrl: "https://issuer.example/unlock",
      sealed: { contentKeys: [{ contentName: "bodytext", key: "first-blob" }] },
    };
    const last = {
      issuerName: "issuer_example",
      keyId: "k-last",
      unlockUrl: "https://issuer.example/unlock",
      sealed: { periodKeys: [{ accessGroup: GROUP, period: "251023T1500", key: "last-period" }] },
    };

    const forward = new DcaData({ ...PAGE, issuerData: [first, last] });
    assert.equal(forward.keyIdFor("issuer_example"), "k-last");
    assert.equal(forward.envelopeFor("issuer_example"), undefined);
    assert.deepEqual(forward.sealedContentKeysFor("issuer_example", "bodytext"), []);
    assert.deepEqual(forward.issuerNamesFor(GROUP), ["issuer_example"]);

    const reversed = new DcaData({ ...PAGE, issuerData: [last, first] });
    assert.equal(reversed.keyIdFor("issuer_example"), "k-first");
    assert.equal(reversed.envelopeFor("issuer_example"), "first-envelope");
    assert.deepEqual(reversed.sealedContentKeysFor("issuer_example", "bodytext"), ["first-blob"]);
    assert.deepEqual(reversed.issuerNamesFor(GROUP), []);

    // An unusable last block leaves no issuer, even after a usable one.
    const unusable = new DcaData({
      ...PAGE,
      issuerData: [first, { issuerName: "issuer_example", keyId: "k-last" }],
    });
    assert.equal(unusable.hasIssuer("issuer_example"), false);
    assert.equal(unusable.keyIdFor("issuer_example"), undefined);
  });

  test("a replacement issuer's empty sealed block inherits no older material", () => {
    const older = {
      issuerName: "issuer_example",
      keyId: "old-key",
      envelope: "old-envelope",
      sealed: {
        contentKeys: [{ contentName: "bodytext", key: "old-content" }],
        periodKeys: [{ accessGroup: GROUP, period: "251023T1500", key: "old-period" }],
        chainKeys: [{ accessGroup: GROUP, cutoff: "251023T2300", key: "old-chain" }],
      },
    };
    const replacement = { issuerName: "issuer_example", keyId: "new-key", sealed: {} };
    const page = new DcaData({ ...PAGE, issuerData: [older, replacement] });
    assert.equal(page.hasIssuer("issuer_example"), true);
    assert.equal(page.keyIdFor("issuer_example"), "new-key");
    assert.equal(page.envelopeFor("issuer_example"), undefined);
    assert.deepEqual(page.sealedContentKeysFor("issuer_example", "bodytext"), []);
    assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
    assert.equal(page.sealedChainKeysFor("issuer_example", GROUP), undefined);

    const reversed = new DcaData({ ...PAGE, issuerData: [replacement, older] });
    assert.deepEqual(reversed.sealedContentKeysFor("issuer_example", "bodytext"), ["old-content"]);
    assert.deepEqual(
      reversed.sealedPeriodKeysFor("issuer_example", GROUP),
      older.sealed.periodKeys,
    );
    assert.deepEqual(reversed.sealedChainKeysFor("issuer_example", GROUP), older.sealed.chainKeys);
  });

  test("issuer blocks resolve by name whatever their array order", () => {
    const a = {
      issuerName: "issuer_a",
      ...block({ contentKeys: [{ contentName: "bodytext", key: "a-blob" }] }),
    };
    const b = {
      issuerName: "issuer_b",
      ...block({ contentKeys: [{ contentName: "bodytext", key: "b-blob" }] }),
    };
    for (const issuerData of [
      [a, b],
      [b, a],
    ]) {
      const page = new DcaData({ ...PAGE, issuerData });
      assert.deepEqual(page.sealedContentKeysFor("issuer_a", "bodytext"), ["a-blob"]);
      assert.deepEqual(page.sealedContentKeysFor("issuer_b", "bodytext"), ["b-blob"]);
    }
  });

  test("a cached-wrap accessGroup outside the grammar supplies no cached route for that item", () => {
    for (const accessGroup of ["2bad", "bad|group", 7, undefined]) {
      const page = new DcaData({
        ...PAGE,
        contentData: items({
          bodytext: {
            ...RECORD,
            keys: [{ accessGroup, period: "251023T1500", key: "wrapped" }, ...RECORD.keys],
          },
          sidebar: RECORD,
        }),
      });

      assert.deepEqual(
        page.accessGroupsFor("bodytext"),
        [],
        "the collection is rejected, not filtered",
      );
      assert.deepEqual(page.sealedEntriesFor("bodytext", GROUP), []);
      assert.equal(
        page.contentDataFor("bodytext"),
        recordOf(page, "bodytext"),
        "and the record still reads, so the issuer-mediated route stands",
      );

      // The sibling item's own cached route is untouched.
      assert.deepEqual(page.accessGroupsFor("sidebar"), [GROUP]);
      assert.deepEqual(page.sealedEntriesFor("sidebar", GROUP), ENTRIES);
    }
  });

  test("a sealed record name outside the grammar supplies no route of that kind", () => {
    const page = new DcaData({
      ...PAGE,
      issuerData: issuers({
        issuer_example: block({
          contentKeys: [
            { contentName: "2bad", key: "blob" },
            { contentName: "bodytext", key: "content-blob" },
          ],
          periodKeys: [
            { accessGroup: "bad|group", period: "251023T1500", key: "blob" },
            { accessGroup: GROUP, period: "251023T1500", key: "period-blob" },
          ],
        }),
        other_example: block({ contentKeys: [{ contentName: "bodytext", key: "other-blob" }] }),
      }),
    });

    assert.deepEqual(page.sealedContentKeysFor("issuer_example", "bodytext"), []);
    assert.equal(page.sealedPeriodKeysFor("issuer_example", GROUP), undefined);
    assert.equal(page.hasIssuer("issuer_example"), true, "the block itself is still usable");
    assert.deepEqual(
      page.sealedContentKeysFor("other_example", "bodytext"),
      ["other-blob"],
      "and the sibling issuer carries its own route",
    );
  });

  test("a malformed sealed period record loses only itself before relay", () => {
    const sound = { accessGroup: "vault", period: "251023T1500", key: "AQ" };
    const client = new Client({ publisherOrigin: PUBLISHER_ORIGIN });

    for (const [label, malformed] of [
      ["no period", { accessGroup: "broken", key: "AQ" }],
      ["wrong type", "not a record"],
    ]) {
      const data = {
        ...PAGE,
        contentData: items({
          bodytext: {
            contentType: BODY.contentType,
            keys: [
              { ...BODY.keys[0], accessGroup: "broken" },
              { ...BODY.keys[0], accessGroup: "vault" },
            ],
          },
        }),
        issuerData: issuers({
          issuer_example: block({ periodKeys: [malformed, sound] }),
        }),
      };
      const page = new DcaData(data);

      assert.deepEqual(page.accessGroupsFor("bodytext"), ["broken", "vault"], label);
      assert.equal(page.sealedPeriodKeysFor("issuer_example", "broken"), undefined, label);
      assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", "vault"), [sound], label);
      assert.deepEqual(page.issuerNamesFor("broken"), [], label);
      assert.deepEqual(page.issuerNamesFor("vault"), ["issuer_example"], label);
      assert.deepEqual(
        client.buildRequest(data, "issuer_example", ["bodytext"]).sealed.periodKeys,
        [sound],
      );
    }
  });

  test("a chainKeys name outside the grammar supplies no chain route", () => {
    // The chain carrier names accessGroups, so the same rule reaches it: a
    // present `sealed.chainKeys` rejected under the identifier section
    // supplies no chain route for that issuer block, and it leaves
    // `sealed.contentKeys`, `sealed.periodKeys` and the sibling issuer alone.
    const record = { accessGroup: GROUP, cutoff: "251023T2300", key: "chain-blob" };
    const bad = { ...record, accessGroup: "bad|group" };
    const period = { accessGroup: GROUP, period: "251023T1500", key: "period-blob" };
    const page = new DcaData({
      ...PAGE,
      issuerData: issuers({
        issuer_example: block({
          contentKeys: [{ contentName: "bodytext", key: "content-blob" }],
          periodKeys: [period],
          chainKeys: [bad, record],
        }),
        other_example: block({
          chainKeys: [record],
        }),
      }),
    });

    assert.equal(page.sealedChainKeysFor("issuer_example", GROUP), undefined);
    assert.deepEqual(
      page.sealedContentKeysFor("issuer_example", "bodytext"),
      ["content-blob"],
      "and the other kinds in the same block stand",
    );
    assert.deepEqual(page.sealedPeriodKeysFor("issuer_example", GROUP), [period]);
    assert.deepEqual(
      page.issuerNamesFor(GROUP),
      ["issuer_example"],
      "only the issuer carrying sound periodKeys remains base-eligible",
    );

    // An issuer whose only route is the rejected chain collection carries no family.
    const chainOnly = new DcaData({
      ...PAGE,
      issuerData: issuers({
        issuer_example: block({ chainKeys: [bad, record] }),
        other_example: block({ chainKeys: [record] }),
      }),
    });

    assert.equal(chainOnly.sealedChainKeysFor("issuer_example", GROUP), undefined);
    assert.deepEqual(
      chainOnly.issuerNamesFor(GROUP),
      [],
      "an optional chain route does not change base period-key eligibility",
    );
    assert.deepEqual(chainOnly.sealedChainKeysFor("other_example", GROUP), [record]);
  });
});

test("item capture refuses an unpaired surrogate in contentType before an unlock can be built", () => {
  const page = structuredClone(PAGE);
  /** @type {any} */ (page.contentData[0]).contentType = "text/\udfff";
  const view = new DcaData(page);
  assert.doesNotThrow(() => view.contentDataFor("bodytext"), "the record shape itself is sound");
  assert.throws(() => view.contentItemFor("bodytext"), { code: "bad_page" });
});

test("item capture refuses a resourceJWT without a compact signing input as the item's bad page", () => {
  for (const token of ["a.b", "a.b.c.d", "a.b.c=", "a..c", "a.b+.c"]) {
    const view = new DcaData({ ...PAGE, resourceJWT: token });
    assert.throws(() => view.contentItemFor("bodytext"), badPage, token);
  }
});

test("carried aad and nonce of any type are ignored and select no transcript", () => {
  const expected = new DcaData(PAGE).contentItemFor("bodytext");
  assert.ok(expected);
  for (const aad of [
    undefined,
    "AAA=",
    "AA",
    "123456|1|bodytext",
    "x\ud800",
    7,
    null,
    {},
    [1],
    { bytes: "AAAA" },
    true,
  ]) {
    const page = structuredClone(PAGE);
    /** @type {any} */ (page.contentData[0]).aad = aad;
    /** @type {any} */ (page.contentData[0]).nonce = aad;
    const view = new DcaData(page);
    assert.equal(view.contentDataFor("bodytext"), page.contentData[0], String(aad));
    const item = view.contentItemFor("bodytext");
    assert.ok(item);
    assert.deepEqual(item.contentAad, expected.contentAad, `aad ${JSON.stringify(aad)}`);
    assert.equal(Object.hasOwn(item, "aad"), false);
  }
});

test("a captured item is a frozen copy that later page edits do not reach", () => {
  const page = structuredClone(PAGE);
  /** @type {any} */ (page.contentData[0]).contentEncodings = ["br"];
  const item = new DcaData(page).contentItemFor("bodytext");
  assert.ok(item);
  assert.deepEqual(Object.keys(item).sort(), [
    "contentAad",
    "contentEncodings",
    "contentName",
    "contentType",
  ]);
  assert.ok(Object.isFrozen(item) && Object.isFrozen(item.contentEncodings));
  const before = Uint8Array.from(item.contentAad);
  /** @type {any} */ (page.contentData[0]).contentEncodings.push("gzip");
  /** @type {any} */ (page.contentData[0]).contentType = "text/plain";
  page.resourceJWT = "eyJh.eyJi.c2ln";
  assert.deepEqual(item.contentEncodings, ["br"]);
  assert.equal(item.contentType, "text/html");
  assert.deepEqual(item.contentAad, before);
});

test("item capture bounds the compact token before decoding its render coordinate", () => {
  const tokenWithData = (size) => {
    const payload = base64urlEncode(
      utf8Encode(JSON.stringify({ renderId: "AAAAAAAAAAAAAAAAAAAAAA", data: "a".repeat(size) })),
    );
    return `${HEADER}.${payload}.c2ln`;
  };
  const below = tokenWithData(700000);
  const above = tokenWithData(800000);
  assert.ok(below.length <= (1 << 20) + 2);
  assert.ok(above.length > (1 << 20) + 2);
  assert.ok(new DcaData({ ...PAGE, resourceJWT: below }).contentItemFor("bodytext"));
  assert.throws(() => new DcaData({ ...PAGE, resourceJWT: above }).contentItemFor("bodytext"), {
    code: "bad_page",
  });
});

test("handling limits and scalar admission remain independent of the content transcript", () => {
  const capture = (record) =>
    new DcaData({ ...PAGE, contentData: items({ bodytext: record }) }).contentItemFor("bodytext");
  const sound = { contentType: "text/plain" };
  for (const record of [
    { contentType: "t".repeat(65536) },
    { contentType: "é".repeat(32768) },
    { ...sound, contentEncodings: Array(8).fill("gzip") },
    { ...sound, contentEncodings: ["g".repeat(128)] },
  ])
    assert.ok(capture(record));
  for (const record of [
    { contentType: "t".repeat(65537) },
    { contentType: "é".repeat(32769) },
    { ...sound, contentEncodings: Array(9).fill("gzip") },
    { ...sound, contentEncodings: ["g".repeat(129)] },
    { ...sound, contentEncodings: ["gz\ud800"] },
    { ...sound, contentEncodings: [""] },
    { ...sound, contentEncodings: [1] },
    { ...sound, contentEncodings: [] },
  ])
    assert.throws(() => capture(record), { code: "bad_page" });
});

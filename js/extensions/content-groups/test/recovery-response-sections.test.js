// @ts-check
//
// The shared resolver's response-section seam, driven by test consumers. A
// selected consumer owns one top-level response member: the resolver hands it
// that member with the one captured association, opens its key values through
// the response's agreed representation, and creates the response lease when
// the consumer accepted something. The lease then reaches the recovery
// sources, and the consumer joins completion and reset. Base sections keep
// their behavior beside a consumer.

import test from "node:test";
import assert from "node:assert/strict";

import { ContentKeyResolver } from "../../../core-client/ContentKeyResolver.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { ResponseAssociation } from "../../../core-client/ResponseAssociation.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";

const ISSUER = "issuer";
const KEY = new Uint8Array(16).fill(5);

/** @param {object} payload */
function compactJwt(payload) {
  const encode = (/** @type {object} */ value) =>
    base64urlEncode(utf8Encode(JSON.stringify(value)));
  return `${encode({ alg: "ES256", typ: "JWT", kid: "k1" })}.${encode(payload)}.c2lnbmF0dXJl`;
}

function page() {
  return new DcaData(
    {
      version: "1",
      resourceJWT: compactJwt({ origin: "https://news.example", renderId: "r-1" }),
      issuerData: [{ issuerName: ISSUER, keyId: "k1", sealed: {} }],
      contentData: [
        {
          contentName: "bodytext",
          contentType: "text/html",
          nonce: base64urlEncode(new Uint8Array(12)),
        },
      ],
    },
    { publisherOrigin: "https://news.example" },
  );
}

/** @param {DcaData} dcaData @param {{ acceptDirectResponse?: boolean }} [endpoint] */
function association(dcaData, endpoint) {
  return new ResponseAssociation(
    dcaData,
    ISSUER,
    {
      version: "1",
      issuerName: ISSUER,
      resourceJWT: dcaData.resourceJWT,
      keyId: "k1",
      sealed: { contentKeys: [{ contentName: "bodytext", key: "AA" }] },
      requestedThings: { bodytext: ["politics"] },
    },
    endpoint,
  );
}

/**
 * A consumer of `things.keys.<name>` that opens each value as a raw 16-byte
 * derivation key and records what it saw.
 * @param {{ accept?: boolean }} [options]
 */
function thingsConsumer({ accept = true } = {}) {
  const seen = {
    admits: /** @type {any[]} */ ([]),
    opened: /** @type {any[]} */ ([]),
    promoted: /** @type {object[]} */ ([]),
    attempted: /** @type {object[]} */ ([]),
    cleared: 0,
  };
  return {
    seen,
    consumer: {
      name: "things",
      /** @param {any} section */
      keyValues(section) {
        return Object.values(section?.keys ?? {});
      },
      /** @param {any} section @param {any} context */
      async admit(section, context) {
        seen.admits.push({ section, context });
        let accepted = 0;
        /** @type {any[]} */
        const issues = [];
        for (const value of Object.values(section.keys ?? {})) {
          const opened = await context.openKey(value, { keyKind: "thingKey", raw: true });
          context.check();
          if (opened.issue) issues.push({ code: opened.issue });
          else {
            seen.opened.push(opened.key);
            if (accept) accepted++;
          }
        }
        return { accepted, issues };
      },
      /** @param {{ lease: object }} context */
      async promote({ lease }) {
        seen.promoted.push(lease);
      },
      /** @param {{ lease: object }} context */
      async attempted({ lease }) {
        seen.attempted.push(lease);
      },
      async clearReaderContext() {
        seen.cleared++;
      },
    },
  };
}

/** A recovery source that records the lease each call carries. */
function leaseSource() {
  const leases = /** @type {any[]} */ ([]);
  return {
    leases,
    source: {
      maxTrialsPerItem: 4,
      /** @param {any} context */
      // eslint-disable-next-line require-yield
      async *candidates(context) {
        leases.push(context.lease);
      },
      async clearReaderContext() {},
    },
  };
}

test("a consumer admits its section against the association and its acceptance makes a lease", async () => {
  const { seen, consumer } = thingsConsumer();
  const { leases, source } = leaseSource();
  const resolver = new ContentKeyResolver({
    responseSections: [consumer],
    recoverySources: [source],
  });
  const dcaData = page();
  const exchange = association(dcaData);
  const response = { things: { keys: { politics: base64urlEncode(KEY) } } };

  const application = await resolver.applyResponse(dcaData, ISSUER, response, exchange);
  assert.equal(application.accepted, 1);
  assert.deepEqual(application.issues, []);
  assert.deepEqual(seen.opened, [KEY]);
  const { section, context } = seen.admits[0];
  assert.deepEqual(section, response.things);
  assert.equal(context.association, exchange);
  assert.equal(context.issuerName, ISSUER);
  assert.equal(context.publisher, "https://news.example");
  assert.equal(context.dcaData, dcaData);
  assert.equal(context.response, response);
  assert.equal(typeof context.lease, "object");

  await resolver.resolveAuthenticated(dcaData, ["bodytext"], async () => false, application);
  assert.equal(leases[0], context.lease, "the recovery source reads under the response lease");
  assert.deepEqual(seen.promoted, [context.lease], "completion promotes the consumer once");
  assert.deepEqual(seen.attempted, [context.lease], "completion releases the consumer once");

  await resolver.resolveAuthenticated(dcaData, ["bodytext"], async () => false, application);
  assert.equal(leases[1], undefined, "a completed response lends no lease again");
});

test("a consumer that accepts nothing makes no lease; an absent section is not offered", async () => {
  const { seen, consumer } = thingsConsumer({ accept: false });
  const { leases, source } = leaseSource();
  const resolver = new ContentKeyResolver({
    responseSections: [consumer],
    recoverySources: [source],
  });
  const dcaData = page();
  const application = await resolver.applyResponse(
    dcaData,
    ISSUER,
    { things: { keys: { politics: base64urlEncode(KEY) } } },
    association(dcaData),
  );
  assert.equal(application.accepted, 0);
  await resolver.resolveAuthenticated(dcaData, ["bodytext"], async () => false, application);
  assert.equal(leases[0], undefined);

  await resolver.applyResponse(dcaData, ISSUER, { keys: {} }, association(dcaData));
  assert.equal(seen.admits.length, 1, "a response without the member never reaches the consumer");
});

test("base sections behave the same beside a consumer", async () => {
  const dcaData = page();
  const response = {
    keys: {
      contentKeys: [
        { contentName: "bodytext", key: base64urlEncode(KEY) },
        { contentName: "stray", key: base64urlEncode(KEY) },
      ],
    },
  };
  const plain = await new ContentKeyResolver().applyResponse(
    dcaData,
    ISSUER,
    structuredClone(response),
    association(dcaData),
  );
  const resolver = new ContentKeyResolver({ responseSections: [thingsConsumer().consumer] });
  const composed = await resolver.applyResponse(
    dcaData,
    ISSUER,
    structuredClone(response),
    association(dcaData),
  );
  assert.deepEqual(composed, plain);
  assert.deepEqual(await resolver.contentKeyFor(dcaData, "bodytext"), KEY);
});

test("a consumer section counts toward the response representation and the strict endpoint", async () => {
  const dcaData = page();
  const { seen, consumer } = thingsConsumer();
  const resolver = new ContentKeyResolver({ responseSections: [consumer] });

  const strict = await resolver.applyResponse(
    dcaData,
    ISSUER,
    { things: { keys: { politics: base64urlEncode(KEY) } } },
    association(dcaData, { acceptDirectResponse: false }),
  );
  assert.deepEqual(strict.issues, [{ section: "response", code: "invalid_transport" }]);

  const mixed = await resolver.applyResponse(
    dcaData,
    ISSUER,
    {
      keys: { contentKeys: [{ contentName: "bodytext", key: base64urlEncode(KEY) }] },
      things: { keys: { politics: { key: "AA" } } },
    },
    association(dcaData),
  );
  assert.deepEqual(mixed.issues, [{ section: "response", code: "invalid_transport" }]);
  assert.equal(seen.admits.length, 0, "a refused response never reaches the consumer");
});

test("openKey refuses a value of the wrong width as one malformed key", async () => {
  const dcaData = page();
  const { seen, consumer } = thingsConsumer();
  const resolver = new ContentKeyResolver({ responseSections: [consumer] });
  const application = await resolver.applyResponse(
    dcaData,
    ISSUER,
    { things: { keys: { politics: base64urlEncode(new Uint8Array(15)) } } },
    association(dcaData),
  );
  assert.equal(application.accepted, 0);
  assert.deepEqual(application.issues, [{ section: "things", code: "malformed_key" }]);
  assert.deepEqual(seen.opened, []);
});

test("consumers are checked at construction and join the reset duties", async () => {
  const valid = thingsConsumer().consumer;
  for (const bad of [
    { ...valid, name: "keys" },
    { ...valid, name: "errors" },
    { ...valid, name: "" },
    { ...valid, admit: undefined },
    { ...valid, keyValues: undefined },
  ])
    assert.throws(
      () => new ContentKeyResolver({ responseSections: [/** @type {any} */ (bad)] }),
      (error) => /** @type {any} */ (error)?.code === "bad_config",
    );
  assert.throws(
    () => new ContentKeyResolver({ responseSections: [valid, { ...valid }] }),
    (error) => /** @type {any} */ (error)?.code === "bad_config",
  );

  const { seen, consumer } = thingsConsumer();
  const resolver = new ContentKeyResolver({ responseSections: [consumer] });
  resolver.assertReaderContextReset();
  await resolver.clearReaderContext();
  assert.equal(seen.cleared, 1);

  const { clearReaderContext, ...retaining } = thingsConsumer().consumer;
  void clearReaderContext;
  const incomplete = new ContentKeyResolver({ responseSections: [retaining] });
  assert.throws(
    () => incomplete.assertReaderContextReset(),
    (error) => /** @type {any} */ (error)?.code === "bad_config",
  );
});

test("reset while a consumer awaits retires the application before any lease", async () => {
  /** @type {(() => void)|null} */
  let release = null;
  const consumer = {
    ...thingsConsumer().consumer,
    /** @param {any} section @param {any} context */
    async admit(section, context) {
      await new Promise((resolve) => {
        release = () => resolve(undefined);
      });
      context.check();
      return { accepted: 1, issues: [] };
    },
  };
  const resolver = new ContentKeyResolver({ responseSections: [consumer] });
  const dcaData = page();
  const applying = resolver.applyResponse(
    dcaData,
    ISSUER,
    { things: { keys: {} } },
    association(dcaData),
  );
  while (release === null) await new Promise((resolve) => setImmediate(resolve));
  const clearing = resolver.clearReaderContext();
  /** @type {() => void} */ (release)();
  await assert.rejects(applying, (error) => /** @type {any} */ (error)?.code === "context_retired");
  await clearing;
});

test("a consumer holds an item key it admitted, and a retired application holds nothing", async () => {
  /** @type {(() => void)|null} */
  let release = null;
  let delayed = false;
  const consumer = {
    ...thingsConsumer().consumer,
    /** @param {any} section @param {any} context */
    async admit(section, context) {
      const opened = await context.openKey(section.items.bodytext, {
        keyKind: "contentKey",
        usages: ["decrypt"],
      });
      if (delayed) {
        await new Promise((resolve) => {
          release = () => resolve(undefined);
        });
        // No check() first: the hold itself must refuse a retired application.
        context.holdContentKey("bodytext", opened.key);
        return { accepted: 1, issues: [] };
      }
      for (const bad of [
        ["stray", opened.key],
        ["bodytext", new Uint8Array(15)],
        ["bodytext", "AA"],
      ])
        assert.throws(
          () => context.holdContentKey(...bad),
          (error) => /** @type {any} */ (error)?.code === "bad_config",
          String(bad[0]),
        );
      context.holdContentKey("bodytext", opened.key);
      return { accepted: 1, issues: [] };
    },
  };
  const resolver = new ContentKeyResolver({ responseSections: [consumer] });
  const dcaData = page();
  const response = { things: { items: { bodytext: base64urlEncode(KEY) } } };
  const application = await resolver.applyResponse(
    dcaData,
    ISSUER,
    structuredClone(response),
    association(dcaData),
  );
  assert.equal(application.accepted, 1);
  const held = await resolver.contentKeyWithOriginFor(dcaData, "bodytext");
  assert.equal(held.origin.kind, "held-content-key");
  assert.ok(held.key, "the plain key path finds the held key");

  await resolver.clearReaderContext();
  assert.equal(await resolver.contentKeyFor(dcaData, "bodytext"), null, "reset drops it");

  delayed = true;
  const applying = resolver.applyResponse(dcaData, ISSUER, response, association(dcaData));
  while (release === null) await new Promise((resolve) => setImmediate(resolve));
  const clearing = resolver.clearReaderContext();
  /** @type {() => void} */ (release)();
  await assert.rejects(applying, (error) => /** @type {any} */ (error)?.code === "context_retired");
  await clearing;
  assert.equal(
    await resolver.contentKeyFor(dcaData, "bodytext"),
    null,
    "a hold after reset must not reach the new reader",
  );
});

/** A consumer that accepts nothing and reports the given error records. */
function reportingConsumer(/** @type {unknown} */ errors) {
  return {
    name: "things",
    keyValues: () => [],
    admit: async () => ({ accepted: 0, issues: [], errors }),
  };
}

test("a consumer's key_retired records join the application errors beside the core entries", async () => {
  const record = { section: "periodKeys", contentName: "bodytext", t: "261014T1500" };
  const resolver = new ContentKeyResolver({
    responseSections: [reportingConsumer([{ ...record, error: "key_retired" }])],
  });
  const dcaData = page();
  const application = await resolver.applyResponse(
    dcaData,
    ISSUER,
    {
      keys: { contentKeys: [] },
      errors: [{ coordinate: "bodytext", error: "key_retired", message: "retired" }],
      things: {},
    },
    association(dcaData),
  );
  assert.deepEqual(application.issues, []);
  assert.deepEqual(application.errors, [
    { coordinate: "bodytext", error: "key_retired", message: "retired" },
    { ...record, error: "key_retired", consumer: "things" },
  ]);
  assert.ok(application.errors.every((entry) => Object.isFrozen(entry)));
});

test("a consumer error record that is not a plain key_retired record is a composition fault", async () => {
  for (const errors of [
    { error: "key_retired" },
    [{ contentName: "bodytext", error: "unseal_failed" }],
    [{ contentName: "bodytext" }],
    [{ contentName: "bodytext", error: "key_retired", key: new Uint8Array(16) }],
    [{ contentName: { nested: "x" }, error: "key_retired" }],
    [{ coordinate: "bodytext", error: "key_retired" }],
    [{ consumer: "other", error: "key_retired" }],
    ["key_retired"],
  ]) {
    const resolver = new ContentKeyResolver({ responseSections: [reportingConsumer(errors)] });
    const dcaData = page();
    await assert.rejects(
      resolver.applyResponse(dcaData, ISSUER, { things: {} }, association(dcaData)),
      { code: "bad_config" },
      JSON.stringify(errors),
    );
  }
});

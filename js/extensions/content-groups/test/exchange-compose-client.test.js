// @ts-check
//
// Composition wiring for a selected extension without base naming it: the
// request builder factory receives the base options and may wrap the base
// builder, and `recoverySources` and `responseSections` reach the resolver
// factory as lists of extension owners. A browser client asserts reset on
// every owner registered this way, even when a custom resolver wrapper offers
// no reset assertion of its own.

import test from "node:test";
import assert from "node:assert/strict";

import { composeClient } from "../../../integration-client/composeClient.js";
import { createBrowserClient } from "../../../integration-client/createBrowserClient.js";
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";
import { domOver } from "../../../test-lib/helpers/domOver.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { ContentGroupRequestBuilder } from "../core-client/ContentGroupRequestBuilder.js";

const PUB = "https://news.example";
/** @param {any} value */
const json = (value) => base64urlEncode(utf8Encode(JSON.stringify(value)));

test("recoverySources and responseSections reach the resolver factory beside the base members", () => {
  /** @type {any} */
  let seen;
  const responseSections = [{ name: "contentGroups" }];
  const recoverySources = [{ candidates() {} }];
  const { builder } = composeClient({
    responseSections,
    recoverySources,
    resolverFactory: (options) => (seen = options),
    requestBuilderFactory: (options) => new ContentGroupRequestBuilder(options),
    relayPeriodKeys: true,
  });
  assert.equal(seen.responseSections, responseSections);
  assert.equal(seen.recoverySources, recoverySources);
  assert.ok(seen.cache);
  assert.ok(builder instanceof ContentGroupRequestBuilder);
});

test("extension owners come as lists, and only the two resolver ports take them", () => {
  /** @type {any} */
  let seen;
  composeClient({ resolverFactory: (options) => (seen = options) });
  assert.equal(Object.hasOwn(seen, "recoverySources"), false);
  assert.equal(Object.hasOwn(seen, "responseSections"), false);
  for (const extension of [
    { responseSections: {} },
    { recoverySources: "contentGroups" },
    { responseSections: null },
  ])
    assert.throws(
      () => composeClient({ ...extension, resolverFactory: () => ({}) }),
      { code: "bad_config" },
      JSON.stringify(extension),
    );
  assert.throws(
    () =>
      composeClient(
        /** @type {any} */ ({
          resolverExtensions: { responseSections: [] },
          resolverFactory: () => ({}),
        }),
      ),
    { code: "unsupported_option" },
  );
});

function root() {
  const jwt = `${json({ alg: "ES256", kid: "k" })}.${json({ origin: PUB, renderId: "r" })}.c2ln`;
  const markup = writeMarkupDelivery({
    dcaData: {
      version: "1",
      resourceJWT: jwt,
      contentData: {
        bodytext: { contentType: "text/plain", nonce: base64urlEncode(new Uint8Array(12)) },
      },
      issuerData: { issuer: { keyId: "kid", sealed: { contentKeys: {} } } },
    },
    sealedContent: { bodytext: base64urlEncode(new Uint8Array(32)) },
  });
  return domOver(markup, { publisherOrigin: PUB });
}

/** A resolver wrapper with every walk method and no reset assertion of its own. */
const wrapper = () => ({
  applyResponse: async () => ({}),
  resolveDetailed: async () => ({}),
  resolve: async () => [],
  contentKeyFor: async () => null,
  contentKeyWithOriginFor: async () => null,
  clearReaderContext: async () => {},
});

test("a browser client refuses a registered extension owner it could not reset", () => {
  const base = {
    root: root(),
    issuerName: "issuer",
    transport: { post: async () => ({ status: 500, contentType: null }) },
    resolverFactory: wrapper,
  };
  assert.throws(
    () =>
      createBrowserClient({
        ...base,
        responseSections: [{ name: "contentGroups" }],
      }),
    { code: "bad_config", message: /clearReaderContext/ },
  );
  assert.ok(
    createBrowserClient({
      ...base,
      responseSections: [{ name: "contentGroups", clearReaderContext: async () => {} }],
    }),
  );
});

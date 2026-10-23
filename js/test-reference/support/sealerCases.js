// @ts-check
//
// The portable Sealer renders and refusals, as plain data: the factory setup
// and the calls that render one page, or that one page refuses, and the content
// representations a render seals alike. The bridged
// cases in core-publisher/sealer-origin.test.js, sealer-options.test.js,
// sealer-factory.test.js, sealer-composition.test.js and
// adapter-client/periodkeys.test.js run them,
// and tools/sealerFactoryRecords.js records the renders and refusals under
// verification/fixtures/v1/reference/protocol-regressions/. All of them read them from here, so the
// bridged cases and the records cannot drift apart. The records hold no content
// representation and no runtime setup.
//
// A setup holds only what a port's factory builds its own Sealer from: a
// fixed instant, one random stream, fixed period keys where the render seals
// periods, and the known test keys. The runtime setup leaves the instant and
// the stream out. It holds the issuer's public key only. Each setup names every
// issuer's scope for its render as data under `issuerSupplyPlans`, so a port's
// factory receives an explicit selection and nothing defaults to every name.
// The private half stays in keys.js for the test that opens the envelopes.
// Each call returns new objects, so no render shares bytes with another.

import {
  ACCESS_GROUP,
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME,
  CONTENT_TYPE,
  DOMAIN,
  FALLBACK_ISSUER_NAME,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  RESOURCE_ID,
  SIGNING_KID,
} from "../../demo/scenarios/fixtures.js";
import {
  labelStream,
  periodKey,
  TEST_ISSUER_PUBLIC_KEY_SPKI,
  TEST_RSA_ISSUER_PUBLIC_KEY_SPKI,
  TEST_SIGNING_KEY_PKCS8,
} from "./keys.js";

/** The RSA-OAEP issuer's key id in the mixed-issuer setup. */
export const RSA_KEY_ID = "2025-10-rsa";

/**
 * @param {string} instant
 * @param {Uint8Array} stream
 */
function setupWith(instant, stream) {
  return {
    origin: ORIGIN,
    signingKid: SIGNING_KID,
    issuers: [{ issuerName: ISSUER_NAME, keyId: KEY_ID, algorithm: ALGORITHM }],
    fixedInstant: new Date(instant),
    randomStream: stream,
    testKeyDocuments: {
      signingKeys: { [SIGNING_KID]: TEST_SIGNING_KEY_PKCS8 },
      issuerPublicKeys: { [KEY_ID]: TEST_ISSUER_PUBLIC_KEY_SPKI },
    },
  };
}

/**
 * @param {Record<string, string>} data
 * @param {string[]} accessGroups
 */
function oneItemRender(data, accessGroups) {
  return {
    resource: { resourceId: RESOURCE_ID, data },
    content: [
      {
        name: CONTENT_NAME,
        value: ARTICLES.A,
        contentType: CONTENT_TYPE,
        accessGroups,
      },
    ],
  };
}

/**
 * The origin case's setup: a content-key-only render, with no period-key supply,
 * on the 32-byte stream `label` names (keys.js, `labelStream`).
 *
 * @param {string} instant
 * @param {string} label
 */
export function sealerOriginSetup(instant, label) {
  return {
    ...setupWith(instant, labelStream(label, 32)),
    // Content-key-only: the render wraps nothing, so no group can be supplied.
    issuerSupplyPlans: {
      [ISSUER_NAME]: { contentKeyNames: [CONTENT_NAME], suppliedAccessGroups: [] },
    },
  };
}

/**
 * The calls of the origin case's render. Its one item names no group: the
 * setup holds no period-key supply, so the item's only route is its item key.
 */
export function sealerOriginRender() {
  return oneItemRender({}, []);
}

/**
 * The period-key case's setup: the 32-byte stream "sealer-period-keys" and a
 * fixed key for each of the two periods the render seals, 0xa1 and 0xa2
 * repeated. The stream holds the render id and one content key. Ordinary
 * envelopes use implicit zero nonces; the two wraps derive theirs and draw nothing.
 */
export function sealerPeriodKeysSetup() {
  return {
    ...setupWith(AT, labelStream("sealer-period-keys", 32)),
    issuerSupplyPlans: {
      [ISSUER_NAME]: { contentKeyNames: [CONTENT_NAME], suppliedAccessGroups: [ACCESS_GROUP] },
    },
    fixedPeriodKeys: {
      [ACCESS_GROUP]: { "251023T1400": periodKey(0xa1), "251023T1500": periodKey(0xa2) },
    },
  };
}

/** The calls of the period-key case's render. */
export function sealerPeriodKeysRender() {
  return oneItemRender({ section: "politics" }, [ACCESS_GROUP]);
}

/**
 * The mixed-issuer case's setup: the ECDH issuer, then an RSA-OAEP issuer
 * when `withRsaIssuer` is true, over the 48-byte stream "sealer-issuers" and a fixed key for
 * each of the two periods. The RSA issuer draws nothing from the stream, so
 * both variants read the same bytes.
 *
 * @param {boolean} withRsaIssuer
 */
export function sealerIssuersSetup(withRsaIssuer) {
  const setup = setupWith(AT, labelStream("sealer-issuers", 48));
  return {
    ...setup,
    issuers: [
      ...setup.issuers,
      ...(withRsaIssuer
        ? [
            {
              issuerName: FALLBACK_ISSUER_NAME,
              keyId: RSA_KEY_ID,
              algorithm: "rsa-oaep",
            },
          ]
        : []),
    ],
    issuerSupplyPlans: {
      [ISSUER_NAME]: wholeIssuersRender(),
      ...(withRsaIssuer ? { [FALLBACK_ISSUER_NAME]: wholeIssuersRender() } : {}),
    },
    fixedPeriodKeys: {
      [ACCESS_GROUP]: { "251023T1400": periodKey(0xa1), "251023T1500": periodKey(0xa2) },
    },
    testKeyDocuments: {
      ...setup.testKeyDocuments,
      issuerPublicKeys: {
        ...setup.testKeyDocuments.issuerPublicKeys,
        ...(withRsaIssuer ? { [RSA_KEY_ID]: TEST_RSA_ISSUER_PUBLIC_KEY_SPKI } : {}),
      },
    },
  };
}

/** Every name and the one group of the mixed-issuer render, for one issuer. */
function wholeIssuersRender() {
  return { contentKeyNames: [CONTENT_NAME, "sidebar"], suppliedAccessGroups: [ACCESS_GROUP] };
}

/** The calls of the mixed-issuer render: two items under one access group. */
export function sealerIssuersRender() {
  const render = oneItemRender({ section: "politics" }, [ACCESS_GROUP]);
  return {
    ...render,
    content: [
      ...render.content,
      {
        name: "sidebar",
        value: ARTICLES.B,
        contentType: CONTENT_TYPE,
        accessGroups: [ACCESS_GROUP],
      },
    ],
  };
}

/**
 * A render's calls as data, each `[member, args]` on the Sealer: `resource`,
 * then `content` for each item in order, then `seal`, whose result is the
 * render.
 *
 * @param {{ resource: { resourceId: string, data: object }, content: any[] }} render
 * @returns {[string, unknown[]][]}
 */
export function sealerRenderCalls(render) {
  return [
    ["resource", [render.resource.resourceId, render.resource.data]],
    ...render.content.map(
      (item) =>
        /** @type {[string, unknown[]]} */ ([
          "content",
          [item.name, item.value, item.contentType, { accessGroups: item.accessGroups }],
        ]),
    ),
    ["seal", []],
  ];
}

/**
 * The origin case's setup with the fixed instant and the random stream left
 * out, so the factory builds the runtime's own clock and secure random source.
 * The test key documents stay, so the render still seals and signs with keys
 * a test knows.
 */
export function sealerRuntimeSetup() {
  const { fixedInstant, randomStream, ...setup } = sealerOriginSetup(AT, "sealer-origin");
  return setup;
}

/**
 * One item's text as the content values a Sealer seals to the same bytes: the
 * string itself, its UTF-8 bytes, and two descriptors of those bytes. A
 * descriptor's `contentEncodings` lists the layers its bytes already carry, so
 * the Sealer seals the bytes unchanged and puts the list on the wire as given.
 * `layered` lists three layers in an order with a repeat. `unlayered` lists
 * none, and its render carries no `contentEncodings` member, as the string's
 * render does not. Each call returns new objects, so a test may change them
 * after `content()`.
 *
 * @param {string} text
 */
export function sealerContentRepresentations(text) {
  const bytes = () => new TextEncoder().encode(text);
  return {
    string: text,
    bytes: bytes(),
    layered: {
      bytes: bytes(),
      contentType: CONTENT_TYPE,
      contentEncodings: ["first", "second", "first"],
    },
    unlayered: { bytes: bytes(), contentType: CONTENT_TYPE, contentEncodings: [] },
  };
}

/**
 * The delivery origins a Sealer signs as given besides `ORIGIN`, as the
 * origin case's setup with `origin` replaced: canonical IPv6 literals, and
 * http origins on a localhost host, which only the development profile
 * (`developmentHttpOrigin: true`) admits.
 */
export function sealerAdmittedOrigins() {
  return {
    ipv6: ["https://[2001:db8::1]", "https://[2001:db8::1]:8443", "https://[::ffff:7f00:1]"],
    developmentHttp: [
      "http://localhost:8080",
      "http://www-default.localhost",
      "http://127.0.0.1:8000",
    ],
  };
}

/**
 * One refusal: the origin case's setup with `set` laid over it and `unset`
 * members removed, then `calls` on the Sealer the factory returns. The last
 * call refuses, or the factory itself when there are no calls, with `code`.
 * `message`, where given, is what a bridged case also matches; a record
 * carries only the code.
 *
 * `dynamic` marks a case whose input a typed port cannot receive: a value
 * whose JSON kind contradicts the type the reference declares for it, such
 * as a list where bytes or a record are declared, or a record where a
 * function or a hook object is declared, or a member the declared record
 * does not have. Those cases run under `portable-sealer-refusals-dynamic`,
 * and the rest under `portable-sealer-refusals`. A record does not carry
 * the mark.
 *
 * @typedef {object} SealerRefusal
 * @property {string} name
 * @property {Record<string, unknown>} [set]
 * @property {string[]} [unset]
 * @property {[string, unknown[]][]} [calls]
 * @property {string} code
 * @property {RegExp} [message]
 * @property {true} [dynamic]
 */

/** The setup every refusal changes: the origin case's, at `AT`, from fill 1. */
export function sealerRefusalSetup() {
  return sealerOriginSetup(AT, "sealer-origin");
}

/**
 * The refusals that cross a test bridge with the plain factory setup, by the
 * bridged case that runs them. Inputs that are JavaScript functions or sparse
 * arrays have no place here. A clock or random source crosses only as a setup
 * member the factory refuses, because the factory builds both itself.
 * Each call returns new objects.
 */
export function sealerRefusalCases() {
  const base = sealerRefusalSetup();
  const [issuer] = base.issuers;
  const documents = base.testKeyDocuments;
  /** The origin case's render, whose `seal` is the call that refuses. */
  const render = sealerRenderCalls(sealerOriginRender());
  /**
   * The period-key case's render, for the cases whose fixed period keys must
   * be read: the origin render's item names no group, so it reads none.
   */
  const groupedRender = sealerRenderCalls(sealerPeriodKeysRender());
  /** @param {unknown} signingKey @returns {Record<string, unknown>} */
  const signingDocument = (signingKey) => ({
    testKeyDocuments: { ...documents, signingKeys: { [SIGNING_KID]: signingKey } },
  });
  const descriptor = {
    bytes: new Uint8Array([1, 2, 3]),
    contentType: "text/html",
    contentEncodings: ["example"],
  };
  /**
   * @param {string} name @param {unknown[]} args @param {string} code
   * @param {boolean} [dynamic] @returns {SealerRefusal}
   */
  const content = (name, args, code, dynamic = false) => ({
    name,
    calls: [["content", args]],
    code,
    ...(dynamic && { dynamic: /** @type {true} */ (true) }),
  });
  return {
    /** @type {SealerRefusal[]} */
    origin: [
      { name: "origin missing", unset: ["origin"], code: "bad_config" },
      ...[
        "www.news-site.example",
        "HTTPS://www.news-site.example",
        "https://www.news-site.example/",
        "https://www.news-site.example:443",
        "https://www.news-site.example/news",
        "https://www.news-site.example|x",
        "https://[2001:DB8::1]",
        "https://[fe80::1%25eth0]",
        "https://[2001:db8::1",
      ].map((origin) => ({ name: `origin ${origin}`, set: { origin }, code: "bad_config" })),
    ],
    /** @type {SealerRefusal[]} */
    http: [
      ...["http://publisher.example", "http://localhost:8080", "http://www-default.localhost"].map(
        (origin) => ({
          name: `origin ${origin} without the profile`,
          set: { origin },
          code: "bad_config",
        }),
      ),
      ...["http://publisher.example", "http://[::1]:8080"].map((origin) => ({
        name: `origin ${origin} with the profile`,
        set: { origin, developmentHttpOrigin: true },
        code: "bad_config",
      })),
    ],
    // The reference's direct cases pass `undefined` for the misspelled
    // periodKeySupplies and a function for ephemeralKeyPairs. No bridge or
    // record carries either. The Sealer refuses the name whatever its value,
    // so here both are `true`.
    /** @type {SealerRefusal[]} */
    names: [
      { name: "domain", set: { domain: DOMAIN }, code: "unsupported_option", dynamic: true },
      {
        name: "periodKeySupplies",
        set: { periodKeySupplies: true },
        code: "unsupported_option",
        dynamic: true,
      },
      {
        name: "ephemeralKeyPairs",
        set: { ephemeralKeyPairs: true },
        code: "unsupported_option",
        dynamic: true,
      },
      { name: "periodSecret", set: { periodSecret: null }, code: "bad_config", dynamic: true },
    ],
    // The sparse `contentEncodings: Array(1)` descriptor stays in the direct
    // test: a bridge carries no array holes.
    /** @type {SealerRefusal[]} */
    content: [
      content("content value 42", ["bodytext", 42, "text/html", {}], "bad_config", true),
      content(
        "content value [1, 2, 3]",
        ["bodytext", [1, 2, 3], { accessGroups: [ACCESS_GROUP] }],
        "unsupported_option",
        true,
      ),
      content(
        "accessGroups a string",
        ["bodytext", "article", "text/html", { accessGroups: ACCESS_GROUP }],
        "bad_config",
        true,
      ),
      // The direct case passes an `undefined` content type before the
      // options. Here the content type and the options are left out, which
      // the Sealer refuses at the same content type check.
      content("content type left out", ["bodytext", "<p>x</p>"], "bad_config"),
      content(
        "content type 7",
        ["bodytext", "<p>x</p>", 7, { accessGroups: [ACCESS_GROUP] }],
        "bad_config",
        true,
      ),
      ...[
        ["descriptor {}", {}, "bad_config"],
        ["descriptor bytes a list", { ...descriptor, bytes: [1, 2, 3] }, "bad_config", true],
        [
          "descriptor without contentEncodings",
          { bytes: descriptor.bytes, contentType: "text/html" },
          "bad_config",
        ],
        [
          "descriptor without contentType",
          { bytes: descriptor.bytes, contentEncodings: descriptor.contentEncodings },
          "bad_config",
        ],
        [
          "descriptor contentEncodings a string",
          { ...descriptor, contentEncodings: "example" },
          "bad_config",
          true,
        ],
        [
          'descriptor contentEncodings [""]',
          { ...descriptor, contentEncodings: [""] },
          "bad_config",
        ],
        [
          "descriptor contentEncodings with a number",
          { ...descriptor, contentEncodings: ["example", 7] },
          "bad_config",
          true,
        ],
        [
          "descriptor with an extra member",
          { ...descriptor, extra: true },
          "unsupported_option",
          true,
        ],
      ].map(([name, value, code, dynamic]) =>
        content(
          /** @type {string} */ (name),
          ["bodytext", value, {}],
          /** @type {string} */ (code),
          /** @type {boolean | undefined} */ (dynamic),
        ),
      ),
      content(
        "descriptor with legacy contentType and options",
        ["bodytext", descriptor, "text/html", {}],
        "bad_config",
      ),
      content(
        "descriptor with legacy contentType",
        ["bodytext", descriptor, "text/html"],
        "bad_config",
      ),
    ],
    // The factory's own refusals, and the Sealer's refusal of a fixed period
    // key of the wrong width. The key-document messages differ between
    // ports, so those cases pin the code alone. The direct cases give a
    // supply with a derive function beside fixed period keys, and native keys
    // beside key documents. The factory refuses on the member being there and
    // reads none of it, so here the supply is an empty record and each key is
    // its PEM document. That record where a hook object is declared, and
    // that PEM text where a native key is declared, make those cases dynamic.
    /** @type {SealerRefusal[]} */
    factory: [
      {
        name: "a list instead of a fixed period-key record",
        set: { fixedPeriodKeys: [] },
        code: "bad_config",
        dynamic: true,
        message: /^fixed period keys are records of bytes by access group and period$/,
      },
      {
        name: "a list instead of an access group's period-key record",
        set: { fixedPeriodKeys: { [ACCESS_GROUP]: [] } },
        code: "bad_config",
        dynamic: true,
        message: /^fixed period keys are records of bytes by access group and period$/,
      },
      {
        name: "a read past the end of the random stream",
        set: { randomStream: labelStream("sealer-short-stream", 31) },
        calls: render,
        code: "bad_config",
        // How a port splits its reads decides both numbers, so the portable
        // case leaves them open; the direct test in sealer-factory.test.js
        // pins this reference's own.
        message: /^the random stream has \d+ bytes left, asked for \d+$/,
      },
      {
        name: "a random stream that is a list of numbers",
        set: { randomStream: [1, 2, 3] },
        code: "bad_config",
        dynamic: true,
        message: /^a random stream is bytes$/,
      },
      {
        name: "a period the fixed keys do not list",
        set: {
          randomStream: labelStream("sealer-period-keys", 32),
          fixedPeriodKeys: { [ACCESS_GROUP]: { "251023T1400": periodKey(0xa1) } },
        },
        calls: groupedRender,
        code: "bad_config",
        message: new RegExp(`^no fixed period key for ${ACCESS_GROUP} at 251023T1500$`),
      },
      ...["clock", "random"].map((name) => ({
        name: `a ${name} in the setup`,
        set: { [name]: {} },
        code: "bad_config",
        dynamic: /** @type {true} */ (true),
        message: new RegExp(`^the Sealer factory builds the ${name}; the setup holds none$`),
      })),
      { name: "an empty signing-key document", set: signingDocument(""), code: "bad_config" },
      {
        name: "a public-key document as the signing key",
        set: signingDocument(TEST_ISSUER_PUBLIC_KEY_SPKI),
        code: "bad_config",
      },
      {
        name: "a framed private-key document that does not import",
        set: signingDocument("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
        code: "bad_config",
      },
      {
        name: "a period-key supply beside fixed period keys",
        set: {
          periodKeySupply: {},
          fixedPeriodKeys: { [ACCESS_GROUP]: { "251023T1400": periodKey(0xa1) } },
        },
        code: "bad_config",
        dynamic: true,
        message: /^period keys come from a supply or from fixed test keys, not both$/,
      },
      {
        name: "a signing key beside the signing-key documents",
        set: { signingKeys: { [SIGNING_KID]: TEST_SIGNING_KEY_PKCS8 } },
        code: "bad_config",
        dynamic: true,
        message: /^signing keys come from native keys or test documents, not both$/,
      },
      {
        name: "an issuer public key beside its key document",
        set: { issuers: [{ ...issuer, publicKey: TEST_ISSUER_PUBLIC_KEY_SPKI }] },
        code: "bad_config",
        dynamic: true,
        message: new RegExp(
          `^issuer key ${KEY_ID} comes from a native key or a test document, not both$`,
        ),
      },
      {
        name: "a fixed period key of 15 bytes",
        set: {
          randomStream: labelStream("sealer-period-keys", 32),
          fixedPeriodKeys: {
            [ACCESS_GROUP]: {
              "251023T1400": new Uint8Array(15).fill(0xa1),
              "251023T1500": periodKey(0xa2),
            },
          },
        },
        calls: groupedRender,
        code: "bad_key",
        message: new RegExp(
          `periodKey for accessGroup "${ACCESS_GROUP}" at "251023T1400" is 16 bytes`,
        ),
      },
    ],
    /** @type {SealerRefusal[]} */
    config: [
      {
        name: "no issuers",
        set: { issuers: [] },
        code: "bad_config",
        message: /at least one issuer/,
      },
      {
        name: "one issuer name twice",
        set: { issuers: [issuer, { ...issuer }] },
        code: "bad_config",
        message: /issuerName .* is configured more than once/,
      },
      {
        name: "a supply without derive",
        set: { periodKeySupply: {} },
        code: "bad_config",
        dynamic: true,
        message: /periodKeySupply is an object with a derive/,
      },
      {
        name: "a sealing hook without seal",
        set: { keySealing: {} },
        code: "bad_config",
        dynamic: true,
        message: /keySealing is an object with a seal/,
      },
      {
        name: "an empty signing-key map",
        set: { testKeyDocuments: { ...documents, signingKeys: {} } },
        code: "bad_config",
        message: /needs a signingKeys map/,
      },
      {
        name: "a selected signing key absent from the map",
        set: { signingKid: "not-present" },
        code: "bad_config",
        message: /holds no signing key/,
      },
      {
        name: "two signing keys and no selection",
        set: {
          testKeyDocuments: {
            ...documents,
            signingKeys: { [SIGNING_KID]: TEST_SIGNING_KEY_PKCS8, next: TEST_SIGNING_KEY_PKCS8 },
          },
        },
        unset: ["signingKid"],
        code: "bad_config",
        message: /more than one signing key and needs a signingKid/,
      },
      {
        name: "an issuer naming a derivation",
        set: { issuers: [{ ...issuer, kdf: "hkdf" }] },
        code: "unsupported_option",
        dynamic: true,
        message: new RegExp(
          `issuer "${ISSUER_NAME}" states kdf, and a sealed blob carries no derivation`,
        ),
      },
      {
        name: "an issuer name with a delimiter",
        set: { issuers: [{ ...issuer, issuerName: "bad|name" }] },
        code: "bad_name",
        message: /issuerName "bad\|name" is not/,
      },
      // The direct case in sealer-composition.test.js keeps its two
      // function-valued strategies and its valid control.
      ...[
        ["null", null],
        ["a list", []],
        ["a string", "ordinary"],
        ["an empty record", {}],
      ].map(([label, contentKeyWrapStrategy]) => ({
        name: `a wrap strategy that is ${label}`,
        set: { contentKeyWrapStrategy },
        code: "bad_config",
        dynamic: /** @type {true} */ (true),
        message: /contentKeyWrapStrategy is an object with aad\(coordinate\) and entry\(wrap\)/,
      })),
      {
        name: "a supply planner that is a record",
        set: { issuerSupplyPlanFor: {} },
        unset: ["issuerSupplyPlans"],
        code: "bad_config",
        dynamic: true,
        message: /issuerSupplyPlanFor is a function/,
      },
      {
        name: "no issuer scope",
        unset: ["issuerSupplyPlans"],
        code: "bad_config",
        message: /issuerSupplyPlanFor/,
      },
      {
        name: "an issuer scope naming content the render does not carry",
        set: {
          issuerSupplyPlans: {
            [ISSUER_NAME]: { contentKeyNames: ["footnote"], suppliedAccessGroups: [] },
          },
        },
        calls: render,
        code: "bad_config",
        message: /selects content-key name "footnote", which this render does not carry/,
      },
      {
        name: "an issuer scope with no content-key selection",
        set: { issuerSupplyPlans: { [ISSUER_NAME]: { suppliedAccessGroups: [] } } },
        calls: render,
        code: "bad_config",
        message: /has no content-key selection/,
      },
    ],
    /** @type {SealerRefusal[]} */
    seal: [
      {
        name: "seal before a resource",
        calls: [["seal", []]],
        code: "bad_config",
        message: /needs a resource/,
      },
      {
        name: "seal before a content item",
        calls: [
          ["resource", ["123456", { section: "politics" }]],
          ["seal", []],
        ],
        code: "bad_config",
        message: /needs a content item/,
      },
    ],
  };
}

/**
 * The cases of one group of `sealerRefusalCases()` that a typed port can
 * receive, which `portable-sealer-refusals` runs.
 *
 * @param {SealerRefusal[]} group
 */
export function typedRefusals(group) {
  return group.filter((refused) => refused.dynamic !== true);
}

/**
 * The cases of one group of `sealerRefusalCases()` marked `dynamic`, which
 * `portable-sealer-refusals-dynamic` runs.
 *
 * @param {SealerRefusal[]} group
 */
export function dynamicRefusals(group) {
  return group.filter((refused) => refused.dynamic === true);
}

/**
 * The setup of one refusal: `base` with the case's members laid over it and
 * its removed members left out.
 *
 * @param {Record<string, unknown>} base
 * @param {SealerRefusal} refusal
 */
export function refusalSetup(base, refusal) {
  const setup = { ...base, ...(refusal.set ?? {}) };
  for (const name of refusal.unset ?? []) delete setup[name];
  return setup;
}

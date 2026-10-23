//
// `dca-bind-key-envelope`, the first field of every bound value, and the deployment it
// exists for. bind.test.js attacks the binding at the carrier; this file covers the one
// thing that file leaves untouched: the tag itself.
//
// The tag can separate a future grammar from v1, even when a reader changes
// the unsigned request selector. It forecloses a mistake such a version could
// make: shipping a vX grammar
// whose byte strings can equal v1's while meaning something else. The demo's own fixtures
// already carry the collision - a content item named `premium` beside an access
// tier named `premium`:
//
//     v1:  c | renderId | contentName    ->   c|R|premium   the item called premium
//     vX:  c | renderId | accessGroup    ->   c|R|premium   anything in the premium tier
//
// Same arity, same bytes, different meaning. Untagged, an issuer running vX code
// that meets a v1-sealed blob rebuilds what it believes is the tier binding, the
// string matches, the blob opens, and it hands back a key the publisher scoped
// to one item under a grant that was checked against the tier. Both arms run
// here, because the control carries the argument: the tagged pair refuses, and the
// same pair with the tag stripped hands the key over.
//
// This file defines the vX grammar, and no proposal anywhere else carries it. The
// grammar is v1's nearest neighbour: same field count, same delimiter, the third field
// read as the tier instead of the item, which is the direction the scope-only
// alternative stands in experiments/ for. It is built on
// `js/core-shared--publisher-issuer/bind.js`, so the anchor width, the banned
// delimiter and the field order stay core's. This file varies only the tag and
// what the third field means.
//
// The issuer sees a POST body, not the page. The shipped request builder copies
// `version` from the page and the shipped client admits only version "1".
// This test deliberately mutates that built request to name X; it does not run
// a vX-capable client or specify a vX wire migration. A reader can make that
// mutation because no version appears in the signed resourceJWT payload. The
// blob's sealed BIND, rather than the unsigned selector, must prevent a
// cross-grammar opening.
//
// A hypothetical two-grammar deployment is the comparison in this file.
// The tests isolate issuer grammar support,
// publisher sealing and retained-key reuse. They do not prove that a real
// vX client can parse a new wire version or select the right request grammar.
//
// One issuer speaks two grammars, and this says where that code lives.
// `core-issuer/IssuerEngine` builds the value one way and has no dispatch seam,
// which is right for an issuer that speaks one version. `issuerSpeaking` below
// is what a vX-capable deployment adds and nothing more: core's `checkVersion`
// against the grammars it holds, core's `checkEnvelopes` for the anchor, then
// the value built by the grammar the request named. The private key is reached
// for in one place, and it counts, so "no key was touched" is an assertion
// rather than a reading.
//
// Page-level runs use ECDH. `core-publisher/Sealer` supplies an ephemeral pair
// on every seal and RSA-OAEP refuses it, so no render goes out under the RSA
// carrier today. The grammar arms run both carriers at the keySealing level,
// where the tag rides as GCM `additionalData` on one and inside the OAEP
// plaintext on the other, and the RSA path compares the recovered value whole.
//
// This file takes its names from the suite, out of `demo/scenarios/fixtures.js`: one
// publisher, one issuer, and a signing kid minted the month the page is rendered in. The
// set this file once carried of its own named `sign-2026-08` over a page rendered
// 2025-10-23, a key ten months younger than the render it signed, the writing date having
// got into a story constant. Nothing here reads those strings, so the alignment moves no
// assertion.
//
// This file keeps one thing of its own, the collision cast: an item and a tier spelled
// the same seven bytes. That pair carries the argument of this file, and it holds whatever
// the fixtures happen to call their tier.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import {
  BIND_DELIMITER,
  BIND_IDENTIFIER,
  bindFields,
  bindValue,
} from "../../../core-shared--publisher-issuer/bind.js";
import { sealingWith } from "../../../tools/vector-fixtures/keySealingWith.js";
import { contentAad } from "../../../core-shared--client-publisher/contentAad.js";
import { checkVersion, checkEnvelopes } from "../../../core-issuer/IssuerEngine.js";
import { DcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { sign, verify } from "../../../core-shared--publisher-issuer/jwt.js";
import { decrypt } from "../../../core-shared/aead.js";
import { randomPeriodKeySupply } from "../../../demo/support/randomPeriodKeySupply.js";
import { writeJsonDelivery } from "../../../adapter-publisher/writeJsonDelivery.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { wholeRenderIssuerSupplyPlan } from "../../../core-publisher/issuerSupplyPlan.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { base64urlDecode, base64urlEncode, utf8Decode } from "../../../core-shared/codec.js";
import { DcaError, dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { Clock } from "../../../demo/actors/Clock.js";
import { IssuerKeyStore } from "../../../demo/support/IssuerKeyStore.js";
import {
  ALGORITHM,
  ARTICLES,
  AT,
  CONTENT_NAME as ITEM_BODYTEXT,
  ISSUER_NAME,
  KEY_ID,
  ORIGIN,
  SIGNING_KID,
} from "../../../demo/scenarios/fixtures.js";
import {
  asWire,
  issuerKeypair,
  seededRandom,
  signingKeypair,
} from "../../../test-reference/support/keys.js";
import { countingEndpoint, requestFor } from "../../../test-lib/harnesses/issuer-endpoint.js";
import { makeRenderId } from "../../../test-lib/fixtures/renderId.js";
import { refuses } from "../../../test-lib/helpers/refuses.js";

/**
 * The tag a later grammar would carry, if this project ever shipped one. The
 * letter rather than a number: nothing here proposes a next version, and a
 * digit would read as one.
 */
const BIND_VX = "dca-bind-vX";

/** A renderId to bind on; the value is incidental. */
const RENDER_A = makeRenderId(0x7e);

/**
 * A content item, and an access tier, spelled the same seven bytes. Written out
 * here rather than taken from the fixtures: the collision is what every claim in
 * this file rests on, and a tier renamed in `demo/scenarios/fixtures.js` would take it
 * away without anything saying so.
 */
const ITEM_PREMIUM = "premium";
const TIER_PREMIUM = "premium";

const TIER_VAULT = "vault";

/**
 * Which tier each item sits in - the table a vX issuer would need and a v1 one
 * does not, because v1 rebuilds from the request member name alone. `bodytext`
 * is in the tier called `premium`; the item called `premium` is sold on its own
 * and sits in `vault`, so no grant on the first ever covers the second.
 */
const TIER_OF = { [ITEM_BODYTEXT]: TIER_PREMIUM, [ITEM_PREMIUM]: TIER_VAULT };

const T = "251023T13";

/** The publisher's own key bytes, so a recovered key can be named. */
const ITEM_KEYS = {
  [ITEM_BODYTEXT]: new Uint8Array(16).fill(0x44),
  [ITEM_PREMIUM]: new Uint8Array(16).fill(0x55),
};

const TIER_KEYS = {
  [TIER_PREMIUM]: { [T]: new Uint8Array(16).fill(0x66) },
  [TIER_VAULT]: { [T]: new Uint8Array(16).fill(0x77) },
};

/**
 * The two carriers of one value, and what each says when the value it rebuilt is
 * not the one that was sealed. GCM learns it while decrypting; RSA recovers a
 * plaintext and compares it whole, which is a different line of code and worth
 * naming separately.
 */
const CARRIERS = [
  {
    label: "ECDH P-256",
    algorithm: "ecdh-p256",
    refusal: "AES-GCM auth tag mismatch",
  },
  { label: "rsa-oaep", algorithm: "rsa-oaep", refusal: "not bound to this coordinate" },
];

/**
 * One carrier's unseal options. Both carriers take the binding and nothing else,
 * so this stands where a per-carrier option list used to.
 *
 * @param {object} extra
 * @returns {any}
 */
function carrierOptions(extra) {
  return { ...extra };
}

/**
 * The vX field list: v1's own, with the tag replaced and the item's tier where
 * the item name stood. Built on `bindFields` so the renderId width, the ban
 * on the delimiter and the kind char are core's. This file varies the tag and
 * the meaning of one field, and nothing else.
 *
 * A periodKey coordinate is already the tier and its bucket, so vX changes
 * nothing there but the tag. That is the sharper half of the collision: the two
 * period grammars are one string once the tag is gone.
 *
 * @param {any} binding
 * @param {Record<string, string>} tierOf
 * @returns {string[]}
 */
function vXFields(binding, tierOf) {
  const fields = bindFields(binding);
  if (binding.contentName === undefined) return [BIND_VX, ...fields.slice(1)];

  const tier = own(tierOf, binding.contentName);
  if (typeof tier !== "string") {
    throw dcaError(
      "binding_failed",
      `a vX issuer binds the tier, and it holds none for "${binding.contentName}"`,
    );
  }
  return [BIND_VX, ...fields.slice(1, 3), tier];
}

/**
 * The two grammars as a value builder each, keyed by the version string a
 * request carries. `tagged: false` is the same pair with the version field
 * dropped from the front, which is the weakening probe every claim here is
 * measured against.
 *
 * @param {Record<string, string>} tierOf - the vX issuer's tier table
 * @param {{ tagged?: boolean }} [options]
 * @returns {Record<string, (binding: any) => string>}
 */
function grammars(tierOf, { tagged = true } = {}) {
  const join = (/** @type {string[]} */ fields) =>
    (tagged ? fields : fields.slice(1)).join(BIND_DELIMITER);

  return {
    1: (binding) => join(bindFields(binding)),
    X: (binding) => join(vXFields(binding, tierOf)),
  };
}

/**
 * The issuer a migration needs, and the whole of what it adds to
 * `core-issuer/IssuerEngine`: one instance holding several grammars, picking by the
 * request's own `version` because that is the only thing on the wire saying
 * which one a page was rendered under.
 *
 * The order is the engine's - version, then the envelope and the anchor under
 * it, then the private key - and `touched` counts every unseal, so an assertion
 * can say a refusal happened ahead of the key rather than assume it.
 *
 * @param {string[]} versions - the grammars this deployment speaks
 * @param {object} config
 * @param {CryptoKey} config.privateKey
 * @param {string} config.algorithm
 * @param {CryptoKey} config.publisherKey - ECDSA public half, for the envelope
 * @param {Record<string, string>} [config.tierOf]
 */
function issuerSpeaking(versions, { privateKey, algorithm, publisherKey, tierOf = TIER_OF }) {
  const build = grammars(tierOf);

  /** @type {Record<string, (binding: any) => string>} */
  const speaks = {};
  for (const version of versions) speaks[version] = build[version];

  const touched = { count: 0 };

  /**
   * @param {string} blob
   * @param {any} binding
   * @param {{ unseal: (blob: string, privateKey: CryptoKey, algorithm: string, options: any) => Promise<Uint8Array> }} sealing
   * @param {string} coordinate - for the message only
   * @returns {Promise<string>}
   */
  const open = async (blob, binding, sealing, coordinate) => {
    touched.count++;
    try {
      return base64urlEncode(
        await sealing.unseal(blob, privateKey, algorithm, carrierOptions({ binding })),
      );
    } catch (cause) {
      throw dcaError(
        "binding_failed",
        `sealed.${coordinate} did not open bound to the coordinate it was presented at: ` +
          (cause instanceof Error ? cause.message : "unseal failed"),
      );
    }
  };

  /**
   * @param {any} posted - the POST body, as the client assembled it
   * @param {{ contentNames?: string[], accessGroups?: string[] }} [granted]
   */
  const unlock = async (posted, granted) => {
    // This issuer is written against the same request the reference one
    // takes, so the document is constructed here rather than read raw.
    const request = posted instanceof DcaRequest ? posted : new DcaRequest(posted);

    checkVersion(request, Object.keys(speaks));
    const claims = await checkEnvelopes(request, publisherKey);

    const sealing = sealingWith(own(speaks, request.version));
    const renderId = claims.resource.renderId;

    // This historical grammar control retains every distinct successful rival.
    // A failed opening cannot hide a success at the same coordinate. Preserve
    // its original binding_failed assertion when a coordinate has no success.
    const openRivals = async (records, fields, permitted, bindingFor) => {
      const successes = [];
      const failures = new Map();
      const openedCoordinates = new Set();
      for (const record of records) {
        if (!permitted(record)) continue;
        const identity = Object.fromEntries(fields.map((field) => [field, record[field]]));
        const coordinate = JSON.stringify(fields.map((field) => record[field]));
        try {
          const key = await open(record.key, bindingFor(record), sealing, coordinate);
          openedCoordinates.add(coordinate);
          if (
            !successes.some(
              (entry) =>
                fields.every((field) => entry[field] === record[field]) && entry.key === key,
            )
          )
            successes.push({ ...identity, key });
        } catch (error) {
          failures.set(coordinate, error);
        }
      }
      for (const [coordinate, error] of failures)
        if (!openedCoordinates.has(coordinate)) throw error;
      return successes;
    };
    const contentKeys = await openRivals(
      request.sealedContentKeys ?? [],
      ["contentName"],
      ({ contentName }) => !granted?.contentNames || granted.contentNames.includes(contentName),
      ({ contentName }) => ({ renderId, contentName }),
    );
    const periodKeys = await openRivals(
      request.sealedPeriodKeys ?? [],
      ["accessGroup", "period"],
      ({ accessGroup }) => !granted?.accessGroups || granted.accessGroups.includes(accessGroup),
      ({ accessGroup, period: t }) => ({ renderId, accessGroup, t }),
    );

    return { contentKeys, periodKeys };
  };

  return { unlock, touched, speaks };
}

/**
 * The refusal itself, for the cases that claim which check said no.
 * `test-lib/helpers/refuses.js` asserts the code and hands nothing back; here the message
 * is read too, so the error itself has to come out.
 *
 * @param {() => Promise<unknown>} run
 * @param {string} why
 * @returns {Promise<DcaError>}
 */
async function refusal(run, why) {
  const error = await run().then(
    () => null,
    (thrown) => thrown,
  );
  assert.ok(error instanceof DcaError, `${why}: expected a DcaError, got ${error}`);
  return error;
}

describe("The collision, as strings", () => {
  // No key material in this section - a bound value is a string, and whether
  // two grammars can produce the same one is arithmetic.

  test("the v1 arm is core's own builder, and the vX arm differs in the tag and one field", () => {
    const build = grammars(TIER_OF);

    for (const binding of [
      { renderId: RENDER_A, contentName: ITEM_BODYTEXT },
      { renderId: RENDER_A, accessGroup: TIER_PREMIUM, t: T },
    ]) {
      assert.equal(build["1"](binding), bindValue(binding), "nothing here re-implements v1");
    }

    assert.equal(
      build["X"]({ renderId: RENDER_A, contentName: ITEM_BODYTEXT }),
      `${BIND_VX}|c|${RENDER_A}|${TIER_PREMIUM}`,
      "vX binds the tier the item sits in",
    );
    assert.equal(
      build["X"]({ renderId: RENDER_A, accessGroup: TIER_PREMIUM, t: T }),
      `${BIND_VX}|p|${RENDER_A}|${TIER_PREMIUM}|${T}`,
      "and a period coordinate is already the tier, so only the tag moves",
    );

    // Same field count on both sides, which is what makes the collision a
    // collision rather than a length mismatch.
    for (const version of ["1", "X"]) {
      assert.equal(
        build[version]({ renderId: RENDER_A, contentName: ITEM_BODYTEXT }).split(BIND_DELIMITER)
          .length,
        4,
      );
      assert.equal(
        build[version]({ renderId: RENDER_A, accessGroup: TIER_PREMIUM, t: T }).split(
          BIND_DELIMITER,
        ).length,
        5,
      );
    }
  });

  test("with the tag on, the item and the tier of one name are two values; with it off, one", () => {
    const tagged = grammars(TIER_OF);
    const stripped = grammars(TIER_OF, { tagged: false });

    // The concrete pair: a blob sealed for the item called `premium`, and
    // the value a vX issuer rebuilds while opening `bodytext`, whose tier is
    // called `premium`. Two different keys, one string.
    const sealedAt = { renderId: RENDER_A, contentName: ITEM_PREMIUM };
    const rebuiltAt = { renderId: RENDER_A, contentName: ITEM_BODYTEXT };

    assert.equal(
      stripped["1"](sealedAt),
      stripped["X"](rebuiltAt),
      "untagged, the two grammars meet",
    );
    assert.equal(stripped["1"](sealedAt), `c|${RENDER_A}|premium`);

    assert.notEqual(tagged["1"](sealedAt), tagged["X"](rebuiltAt));
    assert.equal(
      tagged["1"](sealedAt).split(BIND_DELIMITER).slice(1).join(BIND_DELIMITER),
      tagged["X"](rebuiltAt).split(BIND_DELIMITER).slice(1).join(BIND_DELIMITER),
      "and the tag is the only field that differs, which is the whole claim",
    );

    // The period coordinate is worse untagged: the two grammars are
    // identical there, so every periodKey blob of every render crosses.
    const period = { renderId: RENDER_A, accessGroup: TIER_PREMIUM, t: T };
    assert.equal(stripped["1"](period), stripped["X"](period));
    assert.notEqual(tagged["1"](period), tagged["X"](period));

    assert.equal(BIND_IDENTIFIER, "dca-bind-key-envelope", "what a v1 blob carries");
    assert.equal(BIND_VX, "dca-bind-vX", "and what a vX one would");
  });
});

/**
 * One render's blobs, sealed under whichever grammar a test names, and the
 * issuer that meets them. Everything below moves one of two things: which
 * grammar sealed, and which one opens.
 *
 * @param {typeof CARRIERS[number]} carrier
 * @param {{ tagged?: boolean }} [options]
 */
async function grammarWorld(carrier, { tagged = true } = {}) {
  const { publicKey, privateKey } = await issuerKeypair(carrier.algorithm);
  const random = seededRandom(20260805);
  const build = grammars(TIER_OF, { tagged });

  /** @param {string} version */
  const sealUnder = async (version) => {
    const sealing = sealingWith(build[version]);

    /** @type {Record<string, string>} */
    const contentKeys = {};
    for (const [contentName, keyBytes] of Object.entries(ITEM_KEYS)) {
      contentKeys[contentName] = await sealing.seal(
        keyBytes,
        publicKey,
        carrier.algorithm,
        carrierOptions({ random, binding: { renderId: RENDER_A, contentName } }),
      );
    }

    /** @type {Record<string, Record<string, string>>} */
    const periodKeys = {};
    for (const [accessGroup, byPeriod] of Object.entries(TIER_KEYS)) {
      /** @type {Record<string, string>} */
      const periods = {};
      for (const [t, keyBytes] of Object.entries(byPeriod)) {
        periods[t] = await sealing.seal(
          keyBytes,
          publicKey,
          carrier.algorithm,
          carrierOptions({ random, binding: { renderId: RENDER_A, accessGroup, t } }),
        );
      }
      periodKeys[accessGroup] = periods;
    }

    return { contentKeys, periodKeys };
  };

  /**
   * The issuer walk, with the grammar named rather than dispatched - the
   * dispatch is its own test further down.
   *
   * @param {string} version
   * @param {any} presented
   * @param {{ contentNames?: string[], accessGroups?: string[] }} [granted]
   */
  const openUnder = async (version, presented, granted) => {
    const sealing = sealingWith(build[version]);

    /** @type {Record<string, string>} */
    const contentKeys = {};
    for (const contentName of granted?.contentNames ??
      Object.keys(own(presented, "contentKeys") ?? {})) {
      const blob = own(own(presented, "contentKeys"), contentName);
      if (typeof blob !== "string") continue;
      try {
        contentKeys[contentName] = base64urlEncode(
          await sealing.unseal(
            blob,
            privateKey,
            carrier.algorithm,
            carrierOptions({
              binding: { renderId: RENDER_A, contentName },
            }),
          ),
        );
      } catch (cause) {
        throw dcaError(
          "binding_failed",
          `sealed.contentKeys.${contentName} did not open: ` +
            (cause instanceof Error ? cause.message : "unseal failed"),
        );
      }
    }

    /** @type {Record<string, Record<string, string>>} */
    const periodKeys = {};
    for (const accessGroup of granted?.accessGroups ??
      Object.keys(own(presented, "periodKeys") ?? {})) {
      const byPeriod = own(own(presented, "periodKeys"), accessGroup);
      if (byPeriod === null || typeof byPeriod !== "object") continue;

      /** @type {Record<string, string>} */
      const opened = {};
      for (const t of Object.keys(byPeriod)) {
        try {
          opened[t] = base64urlEncode(
            await sealing.unseal(
              byPeriod[t],
              privateKey,
              carrier.algorithm,
              carrierOptions({
                binding: { renderId: RENDER_A, accessGroup, t },
              }),
            ),
          );
        } catch (cause) {
          throw dcaError(
            "binding_failed",
            `sealed.periodKeys.${accessGroup}.${t} did not open: ` +
              (cause instanceof Error ? cause.message : "unseal failed"),
          );
        }
      }
      periodKeys[accessGroup] = opened;
    }

    return { contentKeys, periodKeys };
  };

  return { publicKey, privateKey, build, sealUnder, openUnder };
}

/**
 * What a vX issuer grants: the tier decides, so every item in the tier the
 * caller holds is granted at once. That decision is what the collision needs:
 * checked against a tier, spent on an item.
 *
 * @param {string} tier
 * @returns {{ contentNames: string[] }}
 */
function grantedByTier(tier) {
  return { contentNames: Object.keys(TIER_OF).filter((item) => TIER_OF[item] === tier) };
}

describe("The two carriers", () => {
  // One value, and the tag rides differently on each: GCM `additionalData` on
  // ECDH, the front of the OAEP plaintext on RSA, where the recovered value is
  // compared whole.

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("a v1 blob does not open under the vX grammar it collides with", async () => {
        const world = await grammarWorld(carrier);
        const v1 = await world.sealUnder("1");

        // The caller holds the tier called `premium`, which under vX
        // grants `bodytext` and nothing else. The attack is the
        // `premium` item's blob - the publisher's, off the same page,
        // nothing malformed about it - moved into the `bodytext` slot,
        // where the value the issuer rebuilds is `premium` again for the
        // other reason.
        const granted = grantedByTier(TIER_PREMIUM);
        assert.deepEqual(granted, { contentNames: [ITEM_BODYTEXT] });

        const relabeled = { contentKeys: { [ITEM_BODYTEXT]: v1.contentKeys[ITEM_PREMIUM] } };

        const error = await refusal(
          () => world.openUnder("X", relabeled, granted),
          "the v1 blob under vX code",
        );
        assert.equal(error.code, "binding_failed");
        assert.ok(
          error.message.includes(carrier.refusal),
          `the refusal is the bound value's, not something incidental: ${error.message}`,
        );

        // Two controls, because a walk that refused everything would
        // prove nothing. The v1 issuer opens the same blob at the
        // coordinate it was sealed at, and the vX issuer opens a
        // vX-sealed blob at the coordinate it decided on - so both ends
        // work, and only the crossing does not.
        const honest = await world.openUnder("1", {
          contentKeys: { [ITEM_PREMIUM]: v1.contentKeys[ITEM_PREMIUM] },
        });
        assert.equal(honest.contentKeys[ITEM_PREMIUM], asWire(ITEM_KEYS[ITEM_PREMIUM]));

        const vX = await world.sealUnder("X");
        const native = await world.openUnder("X", {
          contentKeys: { [ITEM_BODYTEXT]: vX.contentKeys[ITEM_BODYTEXT] },
        });
        assert.equal(native.contentKeys[ITEM_BODYTEXT], asWire(ITEM_KEYS[ITEM_BODYTEXT]));

        // The period coordinate, where the two grammars differ in the
        // tag alone, and the tag alone is what refuses it.
        await refuses(
          () =>
            world.openUnder("X", {
              periodKeys: { [TIER_PREMIUM]: { [T]: v1.periodKeys[TIER_PREMIUM][T] } },
            }),
          "binding_failed",
          "a v1 periodKey blob is not a vX one",
        );

        // The tag costs the wire nothing on either carrier: it is inside
        // the AEAD, and a blob is the width the format budgets whatever
        // it commits to.
        for (const [contentName, blob] of Object.entries(v1.contentKeys)) {
          assert.equal(blob.length, vX.contentKeys[contentName].length);
        }
      });

      test("with the tag stripped the same move opens, and hands back the item's key", async () => {
        const world = await grammarWorld(carrier, { tagged: false });
        const v1 = await world.sealUnder("1");

        // The one difference from the test above: no `dca-bind-key-envelope` in
        // front of either value. The strings the two grammars produce
        // now meet.
        assert.equal(
          world.build["1"]({ renderId: RENDER_A, contentName: ITEM_PREMIUM }),
          world.build["X"]({ renderId: RENDER_A, contentName: ITEM_BODYTEXT }),
        );

        const granted = grantedByTier(TIER_PREMIUM);
        const opened = await world.openUnder(
          "X",
          { contentKeys: { [ITEM_BODYTEXT]: v1.contentKeys[ITEM_PREMIUM] } },
          granted,
        );

        // The consequence, which is the point of running this arm at
        // all. What came back under the `bodytext` label is the
        // publisher's genuine key for the item called `premium` - an
        // item in the `vault` tier, which this caller was never granted
        // and this walk never considered.
        assert.equal(
          opened.contentKeys[ITEM_BODYTEXT],
          asWire(ITEM_KEYS[ITEM_PREMIUM]),
          "the vault item's key",
        );
        assert.notEqual(opened.contentKeys[ITEM_BODYTEXT], asWire(ITEM_KEYS[ITEM_BODYTEXT]));
        assert.equal(
          TIER_OF[ITEM_PREMIUM],
          TIER_VAULT,
          "and the tier it belongs to is not the granted one",
        );

        // The period blobs cross whole untagged, the two grammars being
        // one string there: a v1 render's tier key opens under a vX
        // issuer entire.
        const periods = await world.openUnder("X", {
          periodKeys: { [TIER_PREMIUM]: { [T]: v1.periodKeys[TIER_PREMIUM][T] } },
        });
        assert.equal(periods.periodKeys[TIER_PREMIUM][T], asWire(TIER_KEYS[TIER_PREMIUM][T]));

        // The probe, in place: the identical move with the tag back on,
        // so what opened above is the missing tag and not the harness.
        // The two worlds differ in that one flag and in nothing else.
        const tagged = await grammarWorld(carrier);
        const taggedV1 = await tagged.sealUnder("1");
        await refuses(
          () =>
            tagged.openUnder(
              "X",
              { contentKeys: { [ITEM_BODYTEXT]: taggedV1.contentKeys[ITEM_PREMIUM] } },
              granted,
            ),
          "binding_failed",
          "the tag is the whole of the difference between the two arms",
        );
      });
    });
  }
});

describe("The dispatch key is the client's", () => {
  // `version` rides in the POST body, nothing signed carries it, and the
  // grammar a blob obeys was decided at seal time.

  for (const carrier of CARRIERS) {
    describe(carrier.label, () => {
      test("the request's version cannot move a blob between grammars", async () => {
        const world = await grammarWorld(carrier);
        const v1 = await world.sealUnder("1");
        const signing = await signingKeypair();

        // The envelope a publisher signs, with the anchor these blobs
        // were sealed under. The payload is the Sealer's five fields,
        // and `version` is not one of them.
        const resource = {
          renderId: RENDER_A,
          origin: ORIGIN,
          issuedAt: AT,
          resourceId: "123456",
          data: { section: "politics" },
        };
        const resourceJWT = await sign(resource, signing.privateKey, { kid: SIGNING_KID });

        const issuer = issuerSpeaking(["1", "X"], {
          privateKey: world.privateKey,
          algorithm: carrier.algorithm,
          publisherKey: signing.publicKey,
        });

        const honest = {
          version: "1",
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          resource,
          resourceJWT,
          sealed: {
            contentKeys: [{ contentName: ITEM_BODYTEXT, key: v1.contentKeys[ITEM_BODYTEXT] }],
          },
        };

        const opened = await issuer.unlock(honest, { contentNames: [ITEM_BODYTEXT] });
        assert.equal(
          opened.contentKeys.find((record) => record.contentName === ITEM_BODYTEXT).key,
          asWire(ITEM_KEYS[ITEM_BODYTEXT]),
        );

        // Distinct key material at one coordinate survives in both carrier
        // arms; failed and duplicate candidates cannot erase either success.
        const sealing = sealingWith(world.build["1"]);
        const alternate = new Uint8Array(16).fill(0x99);
        const contentRival = await sealing.seal(
          alternate,
          world.publicKey,
          carrier.algorithm,
          carrierOptions({
            random: seededRandom(901),
            binding: { renderId: RENDER_A, contentName: ITEM_BODYTEXT },
          }),
        );
        const periodRival = await sealing.seal(
          alternate,
          world.publicKey,
          carrier.algorithm,
          carrierOptions({
            random: seededRandom(902),
            binding: { renderId: RENDER_A, accessGroup: TIER_PREMIUM, t: T },
          }),
        );
        const candidates = {
          contentKeys: [
            { contentName: ITEM_BODYTEXT, key: v1.contentKeys[ITEM_PREMIUM] },
            honest.sealed.contentKeys[0],
            { contentName: ITEM_BODYTEXT, key: contentRival },
            honest.sealed.contentKeys[0],
            { contentName: ITEM_BODYTEXT, key: v1.contentKeys[ITEM_PREMIUM] },
          ],
          periodKeys: [
            { accessGroup: TIER_PREMIUM, period: T, key: v1.periodKeys[TIER_VAULT][T] },
            { accessGroup: TIER_PREMIUM, period: T, key: v1.periodKeys[TIER_PREMIUM][T] },
            { accessGroup: TIER_PREMIUM, period: T, key: periodRival },
            { accessGroup: TIER_PREMIUM, period: T, key: v1.periodKeys[TIER_PREMIUM][T] },
            { accessGroup: TIER_PREMIUM, period: T, key: v1.periodKeys[TIER_VAULT][T] },
          ],
        };
        for (const reverse of [false, true]) {
          const sealed = Object.fromEntries(
            Object.entries(candidates).map(([name, records]) => [
              name,
              reverse ? [...records].reverse() : records,
            ]),
          );
          const before = issuer.touched.count;
          const rivals = await issuer.unlock({ ...honest, sealed });
          assert.equal(issuer.touched.count - before, 10, "every candidate is attempted");
          assert.deepEqual(
            rivals.contentKeys.map((record) => record.key).sort(),
            [asWire(ITEM_KEYS[ITEM_BODYTEXT]), asWire(alternate)].sort(),
          );
          assert.deepEqual(
            rivals.periodKeys.map((record) => record.key).sort(),
            [asWire(TIER_KEYS[TIER_PREMIUM][T]), asWire(alternate)].sort(),
          );
        }

        // One field changed, in the one place the reader is free to
        // change it. The outcome is a refusal and never "opened under
        // the other grammar": the blob says which grammar it belongs to
        // and the request cannot argue.
        await refuses(
          () => issuer.unlock({ ...honest, version: "X" }, { contentNames: [ITEM_BODYTEXT] }),
          "binding_failed",
          "the flip does not re-read the blob, it fails it",
        );

        // And the pairing the collision would need - flipped version,
        // relabeled blob - which is the same refusal.
        await refuses(
          () =>
            issuer.unlock(
              {
                ...honest,
                version: "X",
                sealed: {
                  contentKeys: [{ contentName: ITEM_BODYTEXT, key: v1.contentKeys[ITEM_PREMIUM] }],
                },
              },
              grantedByTier(TIER_PREMIUM),
            ),
          "binding_failed",
          "the tagged grammars do not meet, whichever one the request names",
        );

        // Nothing signed contradicts the lie, which is why the tag has
        // to be inside the blob: the payload the publisher signed
        // carries no version.
        const payload = await verify(resourceJWT, signing.publicKey);
        assert.deepEqual(
          Object.keys(payload).sort(),
          ["data", "issuedAt", "origin", "renderId", "resourceId"],
          "the signed envelope is the resource, and a version is not part of it",
        );

        // The simple gate, and where it sits: a version this issuer does
        // not speak is refused before the private key is reached for at
        // all.
        const before = issuer.touched.count;
        await refuses(
          () => issuer.unlock({ ...honest, version: "3" }, { contentNames: [ITEM_BODYTEXT] }),
          "bad_version",
          "an unsupported version is refused rather than guessed at",
        );
        assert.equal(
          issuer.touched.count,
          before,
          "the version gate is ahead of every private-key operation",
        );
      });
    });
  }
});

/** The period the fixture clock falls in, and the one every page below ships. */
const PERIOD_T = "251023T1400";

/** A second item, so a render carries one of each tier. */
const VAULT_ITEM = "<p>Two councillors hold shares in the developer.</p>";

/**
 * One publisher, one issuer keypair, and renders sealed under either grammar.
 * Both renders still carry wire version 1. Both sides of the example share
 * the period-key supply, the domain, the signing key and the clock, so a
 * v1 page and a vX page of the same hour differ in the grammar and the renderId
 * and in nothing else.
 */
async function fleet() {
  const issuerKeys = await issuerKeypair(ALGORITHM);
  const signing = await signingKeypair();
  const build = grammars(TIER_OF);

  // One period-key supply across both deploys, so a v1 page and a vX page of
  // the same hour carry the same periodKey bytes, which is what the
  // cached-key test asks.
  const periodKeySupply = randomPeriodKeySupply({ random: seededRandom(700) });

  let seed = 700;

  /**
   * @param {string} version - the grammar this deploy renders under
   * @param {string} resourceId
   * @param {string} [article]
   */
  const render = async (version, resourceId, article = ARTICLES.A) => {
    const sealer = new Sealer({
      origin: ORIGIN,
      clock: new Clock(AT),
      random: seededRandom(seed++),
      signingKeys: { [SIGNING_KID]: signing.privateKey },
      periodKeySupply,
      issuerSupplyPlanFor: wholeRenderIssuerSupplyPlan,
      // A publisher deploy as a keySealing module: core's bound bodies over
      // the grammar this fleet renders under, dropped into the seam
      // `core-publisher/Sealer` already takes, which is what makes a vX publisher a
      // swap rather than a fork.
      keySealing: sealingWith(build[version]),
      issuers: [
        {
          issuerName: ISSUER_NAME,
          keyId: KEY_ID,
          algorithm: ALGORITHM,
          publicKey: issuerKeys.publicKey,
        },
      ],
    });

    sealer.resource(resourceId, { section: "politics" });
    sealer.content(ITEM_BODYTEXT, article, "text/html", { accessGroups: [TIER_PREMIUM] });
    sealer.content(ITEM_PREMIUM, VAULT_ITEM, "text/html", { accessGroups: [TIER_VAULT] });

    const rendered = await sealer.seal();

    // `core-publisher/Sealer` still writes version 1 and the shipped client
    // admits only that version. `requestUnder` manually selects the hypothetical
    // grammar at the issuer; this does not establish a deployable vX exchange.
    return JSON.parse(utf8Decode(writeJsonDelivery(rendered)));
  };

  // The store counts its own reaches, which is what "no private key was
  // touched" is asserted with. The publisher's verification key has no such
  // store, so the registration below counts every read of it.
  const asked = { publisherKeys: 0 };

  const keyStore = new IssuerKeyStore([
    {
      issuerName: ISSUER_NAME,
      keyId: KEY_ID,
      algorithm: ALGORITHM,
      privateKey: issuerKeys.privateKey,
      publicKey: issuerKeys.publicKey,
    },
  ]);

  // The one publisher this issuer onboarded, selected by the exact resourceJWT
  // header kid before the engine is called. Reading its verification key is
  // what the version gate has to stay ahead of, so the property counts its own
  // reaches the way the key store does.
  const publisherRegistration = {
    kid: SIGNING_KID,
    get publicKey() {
      asked.publisherKeys++;
      return signing.publicKey;
    },
    openingKeys: keyStore,
  };

  /**
   * The deployment that speaks whichever grammars it is given.
   *
   * @param {string[]} versions
   */
  const issuer = (versions) =>
    issuerSpeaking(versions, {
      privateKey: issuerKeys.privateKey,
      algorithm: ALGORITHM,
      publisherKey: signing.publicKey,
    });

  return {
    render,
    issuer,
    issuerKeys,
    signing,
    periodKeySupply,
    keyStore,
    publisherRegistration,
    asked,
  };
}

/**
 * A request built through the real v1 client, then manually given a hypothetical
 * grammar selector. The shipped builder itself copies version 1 from every page
 * in this fixture. The mutation probes an untrusted POST body, not supported
 * client behavior for X.
 *
 * @param {string} version - the grammar the request names
 * @param {any} page
 * @param {string[]} [names]
 * @returns {any} the wire-shaped request
 */
function requestUnder(version, page, names = [ITEM_BODYTEXT]) {
  return { ...requestFor(page, ISSUER_NAME, names), version };
}

/**
 * What the key that came back actually opens, which is what "unlocks correctly"
 * has to mean: the article, through the fixed zero nonce and the content AAD
 * computed from the resourceJWT renderId and the item name.
 *
 * @param {any} page
 * @param {string} contentName
 * @param {string} keyBase64url
 * @returns {Promise<string>}
 */
async function readWith(page, contentName, keyBase64url) {
  const renderId = JSON.parse(utf8Decode(base64urlDecode(page.resourceJWT.split(".")[1]))).renderId;
  const aad = contentAad({
    renderId,
    contentName,
  });
  assert.ok(aad !== null, `the page's "${contentName}" record forms a content AAD`);
  return utf8Decode(
    await decrypt(
      base64urlDecode(keyBase64url),
      new Uint8Array(12),
      base64urlDecode(
        page.sealedContent.find((record) => record.contentName === contentName).content,
      ),
      aad,
    ),
  );
}

describe("Hypothetical two-grammar deployment", () => {
  // These orderings probe grammar separation, not a shipped vX client or wire
  // rollout. ECDH throughout: `core-publisher/Sealer` supplies an ephemeral pair on
  // every seal and RSA-OAEP refuses it, so no page goes out under that carrier.
  //
  // The v1-only issuer is `test-lib/harnesses/issuer-endpoint.js`'s counting endpoint over the
  // shipped `IssuerEngine`: one grammar, no dispatch, and it says how often it
  // was posted to.

  test("one issuer can open blobs sealed under either grammar when the request names it", async () => {
    // Dual issuer grammar support handles these two manually selected inputs.
    // A deployable migration would additionally need a distinguishable wire
    // version and a client that admits and forwards it.
    const { render, issuer } = await fleet();
    const dual = issuer(["1", "X"]);

    const v1Page = await render("1", "123456");
    const vXPage = await render("X", "123457");

    assert.equal(v1Page.version, "1");
    assert.equal(
      vXPage.version,
      "1",
      "a page sealed under either grammar ships as the delivery a client admits",
    );
    assert.deepEqual(
      Object.keys(v1Page),
      Object.keys(vXPage),
      "the wire shape does not move between grammars",
    );

    for (const [version, page] of [
      ["1", v1Page],
      ["X", vXPage],
    ]) {
      const request = requestUnder(version, page);
      assert.equal(request.version, version, "the dispatch key is the request's");

      const opened = await dual.unlock(request, { contentNames: [ITEM_BODYTEXT] });

      assert.equal(
        await readWith(
          page,
          ITEM_BODYTEXT,
          opened.contentKeys.find((record) => record.contentName === ITEM_BODYTEXT).key,
        ),
        ARTICLES.A,
        `the key came back for version ${version} and opens the article`,
      );
    }

    // Both grammars, one private key, one instance: nothing about the two
    // runs differs except which value the issuer rebuilt.
    assert.deepEqual(Object.keys(dual.speaks), ["1", "X"]);
  });

  test("a v1-only issuer refuses a manually X-labeled request before key lookup", async () => {
    const { render, keyStore, publisherRegistration, asked } = await fleet();
    const endpoint = countingEndpoint(publisherRegistration);

    const v1Page = await render("1", "123456");
    const vXPage = await render("X", "123457");

    // The control first, so the refusal below is the version and not the
    // world: the shipped issuer opens the shipped grammar.
    const ok = await endpoint.unlock(requestUnder("1", v1Page));
    assert.equal(ok.status, 200);
    assert.ok(ok.body.keys.contentKeys.find((record) => record.contentName === ITEM_BODYTEXT)?.key);

    const before = { keyStore: keyStore.reachCount, publisherKeys: asked.publisherKeys };

    const refused = await endpoint.unlock(requestUnder("X", vXPage));
    assert.equal(refused.status, 400);
    assert.equal(
      refused.body.error,
      "bad_version",
      "a clean refusal, not a blob that would not open",
    );

    // Nothing was reached for. A version this issuer cannot read stops ahead
    // of the publisher key lookup and ahead of the private key entirely, so
    // this ordering costs a reader an article and costs the issuer nothing -
    // This supports an issuer-first grammar rollout if a future wire/client
    // design actually selects X; it is not that rollout's complete evidence.
    assert.equal(asked.publisherKeys, before.publisherKeys);
    assert.equal(keyStore.reachCount, before.keyStore);
  });

  test("an X-only issuer refuses a v1 request before key lookup", async () => {
    const { render, issuer } = await fleet();
    const vXOnly = issuer(["X"]);

    const v1Page = await render("1", "123456");
    const vXPage = await render("X", "123457");

    // The control: this issuer does open the grammar it speaks.
    const opened = await vXOnly.unlock(requestUnder("X", vXPage), {
      contentNames: [ITEM_BODYTEXT],
    });
    assert.equal(
      await readWith(
        vXPage,
        ITEM_BODYTEXT,
        opened.contentKeys.find((record) => record.contentName === ITEM_BODYTEXT).key,
      ),
      ARTICLES.A,
    );

    const before = vXOnly.touched.count;
    await refuses(
      () => vXOnly.unlock(requestUnder("1", v1Page), { contentNames: [ITEM_BODYTEXT] }),
      "bad_version",
      "markup an edge cached before the deploy is a version this issuer dropped",
    );
    assert.equal(vXOnly.touched.count, before, "again ahead of the private key");

    // Dropping v1 makes fresh unlocks for retained v1 ciphertext unavailable.
    // A deployment may choose when that availability cost is acceptable;
    // edge-cache expiry alone does not erase independently saved renders.
  });

  test("a mixed publisher fleet: two renders of one resource, one per grammar, both unlock and neither crosses", async () => {
    const { render, issuer } = await fleet();
    const dual = issuer(["1", "X"]);

    // The same article rendered twice during the rollout, by two hosts on
    // different sides of it, both live in caches at once.
    const resourceId = "123456";
    const v1Page = await render("1", resourceId);
    const vXPage = await render("X", resourceId);

    assert.equal(v1Page.resource.resourceId, vXPage.resource.resourceId);
    assert.notEqual(
      v1Page.resource.renderId,
      vXPage.resource.renderId,
      "a render is a render, whatever the grammar",
    );

    for (const [version, page] of [
      ["1", v1Page],
      ["X", vXPage],
    ]) {
      const opened = await dual.unlock(requestUnder(version, page), {
        contentNames: [ITEM_BODYTEXT],
      });
      assert.equal(
        await readWith(
          page,
          ITEM_BODYTEXT,
          opened.contentKeys.find((record) => record.contentName === ITEM_BODYTEXT).key,
        ),
        ARTICLES.A,
      );
    }

    // Crossing them: each request keeps its own envelope - so the issuer
    // anchors on that render - and carries the other render's blob. The
    // renderId component should already refuse this, and the grammar
    // dispatch changes nothing about it either way. Confirmed rather than
    // assumed.
    const v1Request = requestUnder("1", v1Page);
    const vXRequest = requestUnder("X", vXPage);

    await refuses(
      () =>
        dual.unlock(
          {
            ...vXRequest,
            sealed: {
              contentKeys: v1Request.sealed.contentKeys,
            },
          },
          { contentNames: [ITEM_BODYTEXT] },
        ),
      "binding_failed",
      "a v1 render's blob inside a vX render's request",
    );
    await refuses(
      () =>
        dual.unlock(
          {
            ...v1Request,
            sealed: {
              contentKeys: vXRequest.sealed.contentKeys,
            },
          },
          { contentNames: [ITEM_BODYTEXT] },
        ),
      "binding_failed",
      "and the other direction",
    );

    // Why it holds under either grammar: the anchor is a field of both, so
    // two renders never share a value even where the rest of the coordinate
    // matches.
    const build = grammars(TIER_OF);
    for (const version of ["1", "X"]) {
      assert.notEqual(
        build[version]({ renderId: v1Page.resource.renderId, contentName: ITEM_BODYTEXT }),
        build[version]({ renderId: vXPage.resource.renderId, contentName: ITEM_BODYTEXT }),
      );
    }
  });

  test("the shipped v1 client copies version 1; manual mutation probes X", async () => {
    // `DcaData` admits only version 1 and `buildRequest` copies it. This
    // cannot establish how a stale bundle would handle a real vX page.
    const { render, issuer, publisherRegistration } = await fleet();

    const v1Page = await render("1", "123456");
    const vXPage = await render("X", "123457");

    const v1Built = requestFor(v1Page);
    const vXBuilt = requestFor(vXPage);

    assert.equal(v1Built.version, "1", "copied out of the page, not chosen by the client");
    assert.equal(
      vXBuilt.version,
      "1",
      "and the same field off a page whose blobs another grammar sealed",
    );
    assert.deepEqual(
      Object.keys(v1Built),
      Object.keys(vXBuilt),
      "and the request it builds is the same shape",
    );

    // A page whose blobs a grammar this client has never heard of sealed
    // still produces a well-formed request: every member is there, and the
    // blobs are the page's.
    assert.deepEqual(
      vXBuilt.sealed.contentKeys.map((record) => record.contentName),
      [ITEM_BODYTEXT],
      "the item asked for, and no mangling around it",
    );
    assert.deepEqual(
      vXBuilt.sealed.periodKeys.map(({ accessGroup, period }) => ({ accessGroup, period })),
      vXPage.issuerData
        .find((record) => record.issuerName === ISSUER_NAME)
        .sealed.periodKeys.filter((record) => record.accessGroup === TIER_PREMIUM)
        .map(({ accessGroup, period }) => ({ accessGroup, period })),
      "every period coordinate for the requested item's tier is relayed unchanged",
    );
    assert.equal(vXBuilt.resourceJWT, vXPage.resourceJWT);

    // The test, acting as a reader that edits the POST body, moves one field
    // from the client-built '1' to 'X'. No shipped client emitted this request.
    const vXRequest = requestUnder("X", vXPage);
    assert.deepEqual(
      Object.keys(vXRequest),
      Object.keys(vXBuilt),
      "one field carries another value, and nothing else moved",
    );

    const dual = issuer(["1", "X"]);
    const opened = await dual.unlock(vXRequest, { contentNames: [ITEM_BODYTEXT] });
    assert.equal(
      await readWith(
        vXPage,
        ITEM_BODYTEXT,
        opened.contentKeys.find((record) => record.contentName === ITEM_BODYTEXT).key,
      ),
      ARTICLES.A,
    );

    const endpoint = countingEndpoint(publisherRegistration);
    const refused = await endpoint.unlock(vXRequest);
    assert.equal(refused.status, 400);
    assert.equal(refused.body.error, "bad_version");
  });

  test("a retained period key opens another render despite a different sealing grammar", async () => {
    // The question that decides whether a migration costs every reader an
    // unlock. The binding rides on the sealed blob rather than on the key
    // inside it, so the bytes a client cached before the deploy should be the
    // bytes the next render's content is wrapped under. Run rather than reasoned.
    const { render, periodKeySupply, publisherRegistration } = await fleet();
    const cache = new PeriodKeyCache();
    const unsealer = new Client({ cache, publisherOrigin: ORIGIN });
    const endpoint = countingEndpoint(publisherRegistration);

    const v1Page = await render("1", "123456");
    const v1Data = unsealer.parse(v1Page);

    const { body } = await endpoint.unlock(
      unsealer.buildRequest(v1Data, ISSUER_NAME, [ITEM_BODYTEXT]),
    );
    await unsealer.applyResponse(v1Data, ISSUER_NAME, body);
    assert.equal(endpoint.calls.count, 1);

    // What landed in the cache is a period key and nothing about a grammar.
    assert.deepEqual(
      base64urlDecode(
        body.keys.periodKeys.find(
          (record) => record.accessGroup === TIER_PREMIUM && record.period === PERIOD_T,
        ).key,
      ),
      await periodKeySupply.derive(TIER_PREMIUM, PERIOD_T),
    );

    // The deploy happens here: the next article the reader opens was
    // rendered by a host on the far side of it.
    const vXPage = await render("X", "123457", VAULT_ITEM);
    const vXData = unsealer.parse(vXPage);

    const { covered, missing } = await unsealer.resolve(vXData, [ITEM_BODYTEXT]);
    assert.deepEqual(
      covered,
      [ITEM_BODYTEXT],
      "the cached key opens the page rendered under the other grammar",
    );
    assert.deepEqual(missing, []);

    const plaintext = await unsealer.decrypt(
      vXData,
      ITEM_BODYTEXT,
      unsealer.extract(vXPage, ITEM_BODYTEXT),
    );
    assert.equal(utf8Decode(plaintext), VAULT_ITEM);
    assert.equal(endpoint.calls.count, 1, "the grammar change costs the reader no unlock");

    // The same retained key also opens a later v1-sealed render. This checks
    // key-byte reuse across renders, not a vX-client cache migration.
    const laterV1 = unsealer.parse(await render("1", "123458"));
    const back = await unsealer.resolve(laterV1, [ITEM_BODYTEXT]);
    assert.deepEqual(back.covered, [ITEM_BODYTEXT]);
    assert.equal(endpoint.calls.count, 1);
  });
});

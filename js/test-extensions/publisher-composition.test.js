// @ts-check
//
// Chain keys and omission composed for one publisher: the chain contribution
// owns the period-key supply, omission owns the render's wrap and wraps the
// planner, and omission's need for a supply is met by chain keys rather than by
// base. The render compares against a record written once from
// `OmittingSealer` with the chain supply nested by hand, before composition
// existed (`fixtures/`).

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Sealer } from "../core-publisher/Sealer.js";
import { composePublisherConfig } from "../core-publisher/publisherComposition.js";
import { createPublisher } from "../integration-publisher/createPublisher.js";
import { periodFamilyGeneration } from "../extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js";
import {
  periodFamilyContribution,
  periodFamilySupply,
} from "../extensions/chain-keys/core-publisher/periodFamilySupply.js";
import { OmittingSealer } from "../extensions/content-key-seal-omission/core-publisher/OmittingSealer.js";
import { omissionContribution } from "../extensions/content-key-seal-omission/core-publisher/omissionSealing.js";
import {
  assertRendersRecord,
  recordedPublisherWorld,
} from "../test-lib/fixtures/publisher-composition-world.js";
import { writeJsonDelivery } from "../adapter-publisher/writeJsonDelivery.js";
import { JsonDeliveryReader } from "../adapter-client/JsonDeliveryReader.js";
import { utf8Encode } from "../core-shared/codec.js";
import { contentGroupsProfile } from "../extensions/content-groups/referenceProfile.js";
import {
  CHAIN,
  GEOMETRY,
  NEXT,
  PUBLISHER,
  SECRET,
  T12,
  T18,
  instant,
  item,
  names,
  world as contentGroupsWorld,
} from "../extensions/content-groups/test/_lib/world.js";

const CHAIN_OMISSION = JSON.parse(
  readFileSync(
    new URL("./fixtures/publisher-composition--chain-omission.json", import.meta.url),
    "utf8",
  ),
);

/** @param {{ derive: Function }} periodKeySupply */
function familyConfig(periodKeySupply) {
  const { chain } = CHAIN_OMISSION.input;
  return {
    periodKeySupply: /** @type {any} */ (periodKeySupply),
    families: Object.fromEntries(
      chain.groups.map((/** @type {string} */ group) => [
        group,
        periodFamilyGeneration({
          keyDerivationSecret: Buffer.from(chain.keyDerivationSecret, "base64url"),
          geometry: chain.geometry,
        }),
      ]),
    ),
    chainWindows: chain.chainWindows,
    // Preserve the recorded two-alternative composition, independent of the default.
    chainItemSlots: 2,
  };
}

describe("Chain keys plus omission through the composed path", () => {
  test("createPublisher renders the record in either list order", async () => {
    const world = await recordedPublisherWorld(CHAIN_OMISSION.input);

    for (const order of ["omission first", "chain first"]) {
      const base = world.config();
      const omission = omissionContribution(base);
      const chain = periodFamilyContribution(familyConfig(world.periodKeySupply));
      const contributions = order === "omission first" ? [omission, chain] : [chain, omission];
      await assertRendersRecord(
        await createPublisher(base, ...contributions).publish(world.article()),
        CHAIN_OMISSION,
      );
    }
  });

  test("the composed Sealer renders the record, with chain keys meeting omission's need", async () => {
    const world = await recordedPublisherWorld(CHAIN_OMISSION.input);
    const base = world.config();
    assert.equal(Object.hasOwn(base, "periodKeySupply"), false);

    const composed = composePublisherConfig(
      base,
      omissionContribution(base),
      periodFamilyContribution(familyConfig(world.periodKeySupply)),
    );
    assert.deepEqual(composed.owners, {
      contentKeyWrapStrategy: "content-key-seal-omission",
      keySealing: "base",
      periodKeySupply: "chain-keys",
    });
    assert.deepEqual(composed.plannerOrder, ["content-key-seal-omission"]);
    await assertRendersRecord(await world.sealed(new Sealer(composed.config)), CHAIN_OMISSION);
  });

  test("OmittingSealer over a hand-nested supply still renders the record", async () => {
    const world = await recordedPublisherWorld(CHAIN_OMISSION.input);
    const config = {
      ...world.config(),
      periodKeySupply: periodFamilySupply(familyConfig(world.periodKeySupply)),
    };

    await assertRendersRecord(await world.sealed(new OmittingSealer(config)), CHAIN_OMISSION);
  });
});

// Content groups sized against the default content-group bounds. The groups an
// item offers are choices; the publisher counts the one key per item a route
// promises, so a policy that grants a bounded selection serves every item.
describe("Content-group publication sizing at the default bounds", () => {
  const items = Array.from({ length: 64 }, (_, i) => `item${String(i).padStart(2, "0")}`);

  test("64 items with 33 groups each publish, and one granted group per item opens all 64", async () => {
    const w = await contentGroupsWorld();
    const published = await w.publish({ items: items.map((name) => item(name, names(33))) });
    const issuer = w.issuer({
      policy: (/** @type {any} */ input) => ({
        grants: Object.entries(input.contentGroups).map(([contentName, { groups }]) => ({
          kind: "chain",
          contentName,
          group: groups[0],
          windowStart: T12,
          cutoffT: T18,
        })),
        authorizePeriod: () => true,
      }),
    });
    const client = w.reader().client(published, issuer);
    const walk = await client.unlock(items);
    assert.deepEqual(walk.missing, []);
    for (const name of items) assert.equal(await client.open(name), `content:${name}`);
  });

  test("a policy granting all 2,112 offered chains is refused whole as bad_policy", async () => {
    const w = await contentGroupsWorld();
    const published = await w.publish({ items: items.map((name) => item(name, names(33))) });
    const issuer = w.issuer();
    const client = w.reader().client(published, issuer);
    const walk = await client.unlock(items);
    assert.equal(issuer.calls.answers.at(-1)?.status, 500);
    assert.equal(issuer.calls.answers.at(-1)?.code, "bad_policy");
    assert.equal(walk.missing.length, 64);
  });
});

// The publisher sizes the request a content-groups client actually sends:
// base members, seed envelopes, requestedContentGroups, renderPeriod and
// periodGeometry. Every render of one shape has the same byte length, so the
// bytes one client sends set the exact limit the next render must meet.
describe("Content-group request bytes against the issuer body limit", () => {
  const random = { bytes: (/** @type {number} */ n) => crypto.getRandomValues(new Uint8Array(n)) };
  /** @param {number} itemCount @param {number} groupCount */
  const page = (itemCount, groupCount) =>
    Array.from({ length: itemCount }, (_, i) =>
      item(`item${String(i).padStart(2, "0")}`, names(groupCount)),
    );

  /**
   * One render through `createPublisher` for the world's issuer, with
   * optional trusted request limits for that issuer.
   * @param {any} w @param {any[]} items @param {Record<string, number>} [limits]
   */
  async function publish(w, items, limits) {
    const composed = createPublisher(
      /** @type {any} */ ({
        origin: PUBLISHER,
        clock: { now: () => instant(T12) },
        random,
        signingKeys: { p1: w.signing.privateKey },
        issuers: [
          {
            issuerName: "issuer",
            keyId: "issuer-k1",
            algorithm: "ecdh-p256",
            publicKey: w.opening.issuer.publicKey,
            ...(limits === undefined ? {} : { limits }),
          },
        ],
        issuerSupplyPlanFor: () => ({ contentKeyNames: [], suppliedAccessGroups: [] }),
      }),
      contentGroupsProfile.publisherContribution({
        retainedSecret: SECRET,
        periodGeometry: GEOMETRY,
        issuerSeedWindows: {
          issuer: Object.fromEntries(items.map((entry) => [entry.name, [T12, NEXT]])),
        },
        chain: CHAIN,
      }),
    );
    const render = await composed.publish({ resourceId: "story1", data: {}, items });
    const reader = new JsonDeliveryReader(writeJsonDelivery(render), {
      publisherOrigin: PUBLISHER,
    });
    const sealedContent = Object.fromEntries(
      Object.keys(reader.dcaData.contentData).map((name) => [name, reader.extract(name)]),
    );
    return { page: structuredClone(reader.dcaData), sealedContent, origin: PUBLISHER };
  }

  /** The UTF-8 bytes of the first request a default client sends for every item. */
  async function sentBytes(/** @type {any} */ w, /** @type {any} */ published) {
    /** @type {any[]} */
    const sent = [];
    const client = w.reader().client(published, w.issuer(), { sent });
    await client.unlock(Object.keys(published.page.contentData));
    return utf8Encode(JSON.stringify(sent[0])).length;
  }

  test("64 items with two groups: a 16,384-byte issuer refuses the page the client could not send", async () => {
    const w = await contentGroupsWorld();
    const bytes = await sentBytes(w, await publish(w, page(64, 2)));
    assert.ok(bytes > 16384);
    await assert.rejects(publish(w, page(64, 2), { maxBodyBytes: 16384 }), {
      code: "bad_config",
      message: /maxBodyBytes/,
    });
    await publish(w, page(64, 2), { maxBodyBytes: bytes });
    await assert.rejects(publish(w, page(64, 2), { maxBodyBytes: bytes - 1 }), {
      code: "bad_config",
      message: /maxBodyBytes/,
    });
  });

  test("at the default body limit, 64 x 33 publishes at its sent bytes and 64 x 64 does not publish", async () => {
    const w = await contentGroupsWorld();
    const bytes = await sentBytes(w, await publish(w, page(64, 33)));
    assert.ok(bytes <= 65536);
    await publish(w, page(64, 33), { maxBodyBytes: bytes });
    await assert.rejects(publish(w, page(64, 33), { maxBodyBytes: bytes - 1 }), {
      code: "bad_config",
      message: /maxBodyBytes/,
    });
    await assert.rejects(publish(w, page(64, 64)), {
      code: "bad_config",
      message: /maxBodyBytes/,
    });
  });
});

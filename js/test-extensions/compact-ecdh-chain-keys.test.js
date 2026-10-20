// @ts-check
//
// Chain keys in a compact-ECDH issuer block. The compact profile covers
// `sealed.chainKeys` when the chain-key profile is selected
// (docs/spec-profile--compact-ecdh.md Section 3.1), so every chain key the
// Sealer seals for a compact-selected issuer is a 65-octet compact envelope
// under the chain-key BIND octets, and none is an ordinary envelope. Two
// extensions take part, so this test lives with the compositions.

import test from "node:test";
import assert from "node:assert/strict";

import { Sealer } from "../core-publisher/Sealer.js";
import { composePublisherConfig } from "../core-publisher/publisherComposition.js";
import { bindValue } from "../core-shared--publisher-issuer/bind.js";
import { open as ordinaryOpen } from "../core-shared--publisher-issuer/keySealing.js";
import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { utf8Encode } from "../core-shared/codec.js";
import { Clock } from "../demo/actors/Clock.js";
import { Random } from "../demo/actors/Random.js";
import { issuerKeypair, signingKeypair } from "../test-reference/support/keys.js";
import { ACCESS_GROUP } from "../demo/scenarios/fixtures.js";
import {
  GEOMETRY,
  chainGeneration,
  chainSupply,
  deliveryPlan,
} from "../extensions/chain-keys/test/world.js";
import { compactEcdhPublisherContribution } from "../extensions/compact-ecdh/core-publisher/keySealing.js";
import { openCompactEcdh } from "../extensions/compact-ecdh/core-issuer/procedure.js";
import { COMPACT_ECDH } from "../extensions/compact-ecdh/core-shared--publisher-issuer/selector.js";

test("a compact-selected issuer's chain keys are compact envelopes under the chain-key BIND", async () => {
  const signing = await signingKeypair();
  const pair = await issuerKeypair("ecdh-p256");
  const base = {
    origin: "https://publisher.example",
    clock: new Clock("2025-10-23T14:20:00Z"),
    random: new Random({ seed: 12 }),
    signingKeys: { signing: signing.privateKey },
    periodKeySupply: chainSupply(chainGeneration(7)),
    issuerSupplyPlanFor: deliveryPlan(() => ["chain-keys"]),
    issuers: [
      {
        issuerName: "compact",
        keyId: "k",
        algorithm: "ecdh-p256",
        publicKey: pair.publicKey,
        envelope: COMPACT_ECDH,
      },
    ],
  };
  const sealer = new Sealer(
    composePublisherConfig(base, compactEcdhPublisherContribution()).config,
  );
  sealer.resource("123456", {});
  sealer.content("body", "<p>text</p>", "text/html", { accessGroups: [ACCESS_GROUP] });
  const { dcaData } = await sealer.seal();
  const block = dcaData.issuerData.compact;
  assert.equal(block.envelope, COMPACT_ECDH);
  const chains = block.sealed.chainKeys?.[ACCESS_GROUP] ?? {};
  assert.ok(Object.keys(chains).length > 0, "the plan delivers chain keys");
  const renderId = dcaData.resource.renderId;
  for (const [t, blob] of Object.entries(chains)) {
    const bytes = binaryStringBytes(blob);
    assert.equal(bytes?.length, 65, t);
    const binding = {
      renderId,
      accessGroup: ACCESS_GROUP,
      suppliedT: t,
      chainKey: true,
      ...GEOMETRY,
    };
    const key = await openCompactEcdh(
      /** @type {string} */ (blob),
      { privateKey: pair.privateKey, publicKey: pair.publicKey },
      utf8Encode(bindValue(/** @type {any} */ (binding))),
    );
    assert.equal(key.length, 16, t);
    // The blob is not an ordinary envelope: the ordinary opener refuses it.
    await assert.rejects(() => ordinaryOpen(blob, pair.privateKey, "ecdh-p256", { binding }), {
      code: "unseal_failed",
    });
  }
});

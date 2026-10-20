// @ts-check
//
// Page and unlock-request bytes, inactive against active, over the matrix this
// measurement covers: one and three content items, one and two issuers.
//
// Run it from `js/`:
//
//     node extensions/content-key-seal-omission/test-lib/measure.js
//
// Raw is `JSON.stringify` UTF-8 bytes; base64url is what that JSON costs
// carried as one base64url string; gzip is `node:zlib` at level 9, a common
// setting for wire payloads.
//
// Renders are seeded and take injected ephemeral keypairs, so raw and base64url
// are exact and a rerun reports them again. The gzip column varies: WebCrypto
// draws the ECDSA signature nonce itself, the injected `random` does not reach
// it, and how well a fresh 64-byte signature compresses moves the total by a
// few bytes either way. So each row is rendered `RUNS` times and the gzip
// column is the median, which is stable to about a byte.

import { gzipSync } from "node:zlib";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { ISSUER_A, ISSUER_B, PUB, ephemeralPool, render, world } from "./world.js";

/**
 * @param {object} value
 * @returns {{ raw: number, base64url: number, gzip: number }}
 */
function bytesOf(value) {
  const json = Buffer.from(JSON.stringify(value), "utf8");
  return {
    raw: json.length,
    base64url: json.toString("base64url").length,
    gzip: gzipSync(json, { level: 9 }).length,
  };
}

const RUNS = 5;

const ITEM_SETS = [["bodytext"], ["bodytext", "sidebar", "note"]];
const ISSUER_SETS = [[ISSUER_A], [ISSUER_A, ISSUER_B]];

const { issuerConfig, sealerConfig } = await world();
const providers = await ephemeralPool(256);

/** @type {string[]} */
const rows = [];

/**
 * The middle of an odd number of readings.
 *
 * @param {number[]} values
 * @returns {number}
 */
function median(values) {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}

for (const items of ITEM_SETS) {
  for (const issuerNames of ISSUER_SETS) {
    for (const active of [false, true]) {
      /** @type {{ raw: number, base64url: number, gzip: number }[]} */
      const pages = [];
      /** @type {{ raw: number, base64url: number, gzip: number }[]} */
      const asks = [];

      for (let run = 0; run < RUNS; run += 1) {
        const issuers = issuerNames.map((issuerName) =>
          issuerConfig(issuerName, active ? { extensions: [EXTENSION_NAME] } : {}),
        );
        const config = sealerConfig({ issuers, ephemeralKeyPairs: providers() });
        const sealer = active ? new OmittingSealer(config) : new Sealer(config);
        const page = await render(sealer, { items });

        const { sealedContent, ...dcaData } = page;
        void sealedContent;
        const view = new DcaData(page, { publisherOrigin: PUB });
        const request = active
          ? new OmissionRequestBuilder().build(view, ISSUER_A, items)
          : new DcaRequestBuilder().build(view, ISSUER_A, items);

        pages.push(bytesOf(dcaData));
        asks.push(bytesOf(request.toObject()));
      }

      rows.push(
        [
          items.length,
          issuerNames.length,
          active ? "active" : "inactive",
          pages[0].raw,
          pages[0].base64url,
          median(pages.map((one) => one.gzip)),
          asks[0].raw,
          asks[0].base64url,
          median(asks.map((one) => one.gzip)),
        ].join(" | "),
      );
    }
  }
}

process.stdout.write(
  [
    "| items | issuers | state | page raw | page b64url | page gzip | request raw | request b64url | request gzip |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...rows.map((row) => `| ${row} |`),
    "",
  ].join("\n"),
);

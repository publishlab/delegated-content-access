// @ts-check
//
// What one unlock costs the issuer, on the inactive base route and on the
// active bound route, and what the page saved to buy it.
//
// Run it from `js/`:
//
//     node extensions/content-key-seal-omission/test-lib/load.js
//
// The two halves of the trade do not meet anywhere else. Page bytes are
// cacheable: one render is served to every reader of it, and an edge cache
// answers most of those without the publisher. Request bytes are not: every
// unlock carries its own, and every unlock reaches the issuer. So they are
// reported apart, and the ratio between page views and unlocks decides whether
// the trade pays.
//
// The crypto counter wraps `globalThis.crypto.subtle` here in the harness. No
// base or extension source knows about it. It counts at the primitive layer
// rather than at the module entry points, which makes the two routes
// comparable: `deriveBits` is one sealed-blob open under the outer BIND, and a
// `decrypt` beyond that count is one AES-GCM unwrap of a content-key wrap.

import { performance } from "node:perf_hooks";

import { Sealer } from "../../../core-publisher/Sealer.js";
import { IssuerEngine } from "../../../core-issuer/IssuerEngine.js";
import { DcaData } from "../../../core-client/DcaData.js";
import { DcaRequestBuilder } from "../../../core-client/DcaRequestBuilder.js";
import { OmittingSealer } from "../core-publisher/OmittingSealer.js";
import { omissionIssuerEngine } from "../core-issuer/omissionIssuerEngine.js";
import { OmissionRequestBuilder } from "../core-client/OmissionRequestBuilder.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";
import { ISSUER_A, PUB, contentOnlyPolicy, ephemeralPool, render, world } from "./world.js";

const ITEMS = ["bodytext", "sidebar", "note"];
const CONCURRENCIES = [1, 8, 32];
const UNLOCKS = 200;
const BURST = 200;

/** @param {object} value */
function rawBytes(value) {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

/**
 * The subtle operations one call performs, counted while it runs. Instance
 * properties shadow the prototype methods and are put back afterwards.
 *
 * @template T
 * @param {() => Promise<T>} run
 * @returns {Promise<Record<string, number>>}
 */
async function subtleOps(run) {
  const subtle = globalThis.crypto.subtle;
  const names = [
    "decrypt",
    "encrypt",
    "deriveBits",
    "deriveKey",
    "importKey",
    "verify",
    "sign",
    "digest",
  ];
  /** @type {Record<string, number>} */
  const counts = {};

  for (const name of names) {
    const original = /** @type {any} */ (subtle)[name].bind(subtle);
    counts[name] = 0;
    Object.defineProperty(subtle, name, {
      configurable: true,
      writable: true,
      value: (/** @type {any[]} */ ...args) => {
        counts[name] += 1;
        return original(...args);
      },
    });
  }

  try {
    await run();
  } finally {
    for (const name of names) delete (/** @type {any} */ (subtle)[name]);
  }

  return counts;
}

/**
 * N unlocks with `inFlight` of them outstanding at any moment, timed one by one.
 *
 * @param {() => Promise<any>} unlock
 * @param {number} total
 * @param {number} inFlight
 * @returns {Promise<{ throughput: number, p50: number, p95: number, p99: number }>}
 */
async function drive(unlock, total, inFlight) {
  /** @type {number[]} */
  const latencies = [];
  let started = 0;

  const worker = async () => {
    while (started < total) {
      started += 1;
      const at = performance.now();
      await unlock();
      latencies.push(performance.now() - at);
    }
  };

  const wall = performance.now();
  await Promise.all(Array.from({ length: Math.min(inFlight, total) }, worker));
  const elapsed = (performance.now() - wall) / 1000;

  latencies.sort((a, b) => a - b);
  /** @param {number} q */
  const at = (q) => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))];
  return { throughput: latencies.length / elapsed, p50: at(0.5), p95: at(0.95), p99: at(0.99) };
}

const { issuerConfig, sealerConfig, registration } = await world();
const providers = await ephemeralPool(256);

/**
 * One route ready to be driven: the render it was produced from, the request
 * one client sends, and the engine that answers it.
 *
 * @param {boolean} active
 */
async function route(active) {
  const issuers = [issuerConfig(ISSUER_A, active ? { extensions: [EXTENSION_NAME] } : {})];
  const config = sealerConfig({ issuers, ephemeralKeyPairs: providers() });
  const page = await render(active ? new OmittingSealer(config) : new Sealer(config), {
    items: ITEMS,
  });

  const { sealedContent, ...dcaData } = page;
  void sealedContent;
  const view = new DcaData(page, { publisherOrigin: PUB });
  const request = active
    ? new OmissionRequestBuilder({ relayPeriodKeys: true }).build(view, ISSUER_A, ITEMS)
    : new DcaRequestBuilder().build(view, ISSUER_A, ITEMS);

  const accessPolicy = contentOnlyPolicy(ITEMS);
  const engine = active
    ? omissionIssuerEngine({ operatingIssuerNames: [ISSUER_A], accessPolicy })
    : new IssuerEngine({ operatingIssuerNames: [ISSUER_A], accessPolicy });

  const unlock = async () => {
    const result = await engine.unlock(request, registration);
    if (
      JSON.stringify(result.contentKeys.map((record) => record.contentName).sort()) !==
      JSON.stringify([...ITEMS].sort())
    ) {
      throw new Error(
        `the ${active ? "active" : "inactive"} route answered ${result.contentKeys.map((record) => record.contentName)}`,
      );
    }
    return result;
  };

  return { page: rawBytes(dcaData), request: rawBytes(request.toObject()), unlock };
}

const routes = { inactive: await route(false), active: await route(true) };

/** @type {string[]} */
const out = [];

out.push("| route | page raw (cacheable) | request raw (uncacheable) |");
out.push("| --- | --- | --- |");
for (const [name, one] of Object.entries(routes))
  out.push(`| ${name} | ${one.page} | ${one.request} |`);
out.push("");

out.push(
  "| route | subtle.decrypt | subtle.deriveBits | subtle.importKey | subtle.verify | sealed opens | wrap opens |",
);
out.push("| --- | --- | --- | --- | --- | --- | --- |");
for (const [name, one] of Object.entries(routes)) {
  await one.unlock();
  const counts = await subtleOps(one.unlock);
  out.push(
    [
      name,
      counts.decrypt,
      counts.deriveBits,
      counts.importKey,
      counts.verify,
      counts.deriveBits,
      counts.decrypt - counts.deriveBits,
    ]
      .map(String)
      .join(" | ")
      .replace(/^/, "| ") + " |",
  );
}
out.push("");

out.push("| route | in flight | unlocks | throughput /s | p50 ms | p95 ms | p99 ms |");
out.push("| --- | --- | --- | --- | --- | --- | --- |");
for (const [name, one] of Object.entries(routes)) {
  if (process.argv.includes("--smoke")) continue;
  await drive(one.unlock, 50, 8);
  for (const inFlight of [...CONCURRENCIES, BURST]) {
    const total = inFlight === BURST ? BURST : UNLOCKS;
    const run = await drive(one.unlock, total, inFlight);
    out.push(
      `| ${name} | ${inFlight}${inFlight === BURST ? " (burst)" : ""} | ${total} | ${run.throughput.toFixed(
        0,
      )} | ${run.p50.toFixed(2)} | ${run.p95.toFixed(2)} | ${run.p99.toFixed(2)} |`,
    );
  }
}
out.push("");

process.stdout.write(`${out.join("\n")}\n`);

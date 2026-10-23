// @ts-check
//
// Array position on the named-record wire carries no meaning. One page is read
// twice through the production roles: once as published, once with every
// record collection reversed after a JSON round trip. That covers items,
// connectors, issuer blocks, seeds, and every request and answer section. Both
// readers send the same request records, get the same answer records and open
// the same plaintext.

import test from "node:test";
import assert from "node:assert/strict";

import { copy, item, world } from "./_lib/world.js";

/** Reverse every array in a JSON value, at every depth. @param {any} value @returns {any} */
function reversed(value) {
  if (Array.isArray(value)) return value.map(reversed).reverse();
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([name, v]) => [name, reversed(v)]));
  return value;
}

/**
 * A JSON value with every array sorted by its members' canonical text, so two
 * permutations of the same records compare equal.
 * @param {any} value @returns {any}
 */
function canonical(value) {
  if (Array.isArray(value))
    return value.map(canonical).sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([name, v]) => [name, canonical(v)]),
    );
  return value;
}

test("reversed record order across JSON resolves to the same coordinates and keys", async () => {
  const w = await world();
  const items = [
    item("bodytext", ["politics", "sports"]),
    item("headline", ["politics"]),
    item("shoppingAd", ["shopping"]),
  ];
  const published = await w.publish({ items });
  const names = items.map((entry) => entry.name);

  // The reversal reaches the page's item records, each item's connectors, the
  // issuer blocks and their seed records.
  const permuted = { ...published, page: reversed(JSON.parse(JSON.stringify(published.page))) };
  assert.notDeepEqual(permuted.page.contentData, published.page.contentData);

  /** @type {any[]} */
  const raw = [];
  /** @type {any[]} */
  const opened = [];
  /** @type {any[]} */
  const answers = [];
  for (const [label, page, answered] of /** @type {const} */ ([
    ["as published", published, undefined],
    ["reversed", permuted, (/** @type {any} */ body) => reversed(body)],
  ])) {
    const issuer = w.issuer();
    const client = w.reader().client(page, issuer, {
      narrowing: { requestedContentKeys: { shoppingAd: "shopping" } },
      ...(answered === undefined ? {} : { answered }),
    });
    await client.unlock(names);
    const texts = await Promise.all(names.map((name) => client.open(name)));
    assert.deepEqual(texts, ["content:bodytext", "content:headline", "content:shoppingAd"], label);
    assert.equal(client.sent.length, 1, label);
    raw.push(copy(client.sent[0]));
    opened.push(canonical(copy(client.sent[0])));
    answers.push(canonical(issuer.calls.answers[0].body));
  }

  // The reversed page did reorder the request, and the request and answer
  // still hold the same records.
  assert.notDeepEqual(raw[1], raw[0]);
  assert.deepEqual(opened[1], opened[0]);
  assert.deepEqual(answers[1], answers[0]);
});

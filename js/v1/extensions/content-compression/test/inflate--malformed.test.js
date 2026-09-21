// @ts-check
//
// A few hundred damaged streams, each of which has to come back as a typed
// refusal rather than as wrong bytes, a hang or an untyped throw. Each stream is
// damaged by a flipped byte or a cut, drawn from a seeded generator so a rerun
// reproduces any failure.
//
// The wall clock is part of the assertion. A decoder that loops on some input
// would show up here as a run that does not finish, and a bound turns that into
// a failure rather than a stuck lane.

import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";

import { DcaError } from "../../../core-shared/errors.js";
import { utf8Encode } from "../../../core-shared/codec.js";
import { syntheticArticle } from "../../../tools/synthetic-html.js";
import { inflateGzip } from "../core-client/inflate/inflate.js";

/** The whole loop has this long, decoding included. */
const BUDGET_MS = 30_000;
const CASES = 600;

/** @param {number} seed @returns {() => number} a small deterministic generator */
function random(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1103515245 + 12345) >>> 0;
    return state / 0x100000000;
  };
}

const SOURCES = [
  utf8Encode(syntheticArticle({ bytes: 3000, seed: 1 })),
  utf8Encode(syntheticArticle({ bytes: 30_000, form: "json", seed: 2 })),
  utf8Encode(syntheticArticle({ bytes: 60_000, form: "txt", seed: 3 })),
  utf8Encode("a"),
  new Uint8Array(0),
];

/** Each valid member kept beside the bytes it carries. */
const VALID = SOURCES.flatMap((body) =>
  [0, 1, 6, 9].map((level) => ({ body, member: new Uint8Array(gzipSync(body, { level })) })),
);

test("every damaged stream is a typed refusal or the bytes that went in", async () => {
  const draw = random(20260910);
  const started = performance.now();
  let refusals = 0;
  let survived = 0;

  for (let at = 0; at < CASES; at += 1) {
    const { body, member } = VALID[Math.floor(draw() * VALID.length)];
    let damaged = Uint8Array.from(member);

    if (draw() < 0.5) {
      // Flip: one to three bytes take a new value.
      const flips = 1 + Math.floor(draw() * 3);
      for (let flip = 0; flip < flips; flip += 1) {
        damaged[Math.floor(draw() * damaged.length)] ^= 1 + Math.floor(draw() * 255);
      }
    } else {
      // Cut: the stream stops somewhere inside itself.
      damaged = damaged.subarray(0, Math.floor(draw() * damaged.length));
    }

    try {
      // A flip in a header field this decoder skips leaves a stream that
      // still decodes. No damage may produce bytes other than what went in.
      assert.deepEqual(
        await inflateGzip.decode(damaged),
        body,
        `case ${at}: decoded something else`,
      );
      survived += 1;
    } catch (cause) {
      assert.ok(cause instanceof DcaError, `case ${at}: untyped throw ${cause}`);
      assert.equal(/** @type {any} */ (cause).code, "bad_encoding");
      refusals += 1;
    }
  }

  const elapsed = performance.now() - started;
  assert.ok(elapsed < BUDGET_MS, `${CASES} damaged streams took ${elapsed.toFixed(0)} ms`);
  assert.equal(refusals + survived, CASES);
  assert.ok(refusals > CASES / 2, `only ${refusals} of ${CASES} damaged streams were refused`);
  process.stdout.write(
    `# ${CASES} damaged streams in ${elapsed.toFixed(0)} ms, ${refusals} refused\n`,
  );
});

test("a stream damaged in its deflate body never decodes to different bytes", async () => {
  const body = utf8Encode(syntheticArticle({ bytes: 8000, seed: 11 }));
  const valid = new Uint8Array(gzipSync(body, { level: 9 }));
  const draw = random(7);

  for (let at = 0; at < 120; at += 1) {
    const damaged = Uint8Array.from(valid);
    // Past the header, before the trailer: the deflate data itself.
    const target = 10 + Math.floor(draw() * (damaged.length - 18));
    damaged[target] ^= 1 << Math.floor(draw() * 8);

    try {
      const back = await inflateGzip.decode(damaged);
      assert.deepEqual(back, body, `case ${at}: decoded bytes that are not the input`);
    } catch (cause) {
      assert.equal(/** @type {any} */ (cause).code, "bad_encoding");
    }
  }
});

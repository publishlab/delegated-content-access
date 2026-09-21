// @ts-check
//
// One refusal, asserted on the code rather than the message. The code is what
// the port maps a status from, so a test matching only the wording would pass
// while the status went wrong; and a rejection that is not a `DcaError` at all
// is a bug in the code under test wearing the shape of an expected refusal.
//
// This helper accepts a throw and a rejection alike. Whether a call refuses
// before its first await or after it is the code's business and not the claim's.
// A test that had to know would be pinned to that, and would go red when a
// constructor check moved behind an async boundary or in front of one.
//
// The message is matchable and stays optional. Where two refusals share a code
// (one `bad_config` for a coordinate and another for what is filed at it), the
// code alone would let either one pass for the other.

import assert from "node:assert/strict";

import { DcaError } from "../../core-shared/errors.js";

/**
 * @param {() => unknown} run - called here, and either throwing or rejecting is
 *   the refusal
 * @param {string|{ code: string, message?: RegExp }} expected - the code, or the
 *   code beside what the message has to say
 * @param {string} why - what this refusal is being asked to show, repeated into
 *   every failure message so a red line names the claim and not just the code
 * @returns {Promise<void>}
 */
export async function refuses(run, expected, why) {
  const { code, message } =
    typeof expected === "string" ? { code: expected, message: undefined } : expected;

  await assert.rejects(
    async () => run(),
    (error) => {
      assert.ok(error instanceof DcaError, `${why}: expected a DcaError, got ${error}`);
      assert.equal(/** @type {DcaError} */ (error).code, code, why);
      if (message !== undefined) {
        assert.match(/** @type {DcaError} */ (error).message, message, why);
      }
      return true;
    },
  );
}

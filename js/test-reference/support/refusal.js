// @ts-check
//
// A check for `assert.throws` and `assert.rejects` that accepts only a DCA
// refusal: a `DcaError` whose `code` is the one the case names, and whose
// message matches where the case names one. Through a test bridge, the
// implementation's own refusal arrives as its mapped DCA error with that code,
// while an adapter refusal or a bridge failure carries another code, so a
// crossing failure fails the case instead of passing for a refusal. A refusal
// the adapter sends without an error type arrives as a plain `Error` that
// carries the adapter's code, so the check requires the error type too: an
// adapter cannot pass a case by naming the code itself.

import assert from "node:assert/strict";

import { DcaError } from "../../core-shared/errors.js";
import { refusalSetup, sealerRefusalSetup } from "./sealerCases.js";

/**
 * @param {string} code - such as `bad_config` or `unsupported_option`
 * @param {RegExp} [message]
 * @returns {(error: any) => true}
 */
export function refusal(code, message) {
  return (error) => {
    assert.ok(
      error instanceof DcaError,
      `expected a ${code} refusal as a DcaError, got: ${error?.name} ${error?.code} ${error?.message}`,
    );
    assert.equal(
      error?.code,
      code,
      `expected a ${code} refusal, got: ${error?.code} ${error?.message}`,
    );
    if (message !== undefined) assert.match(error.message, message);
    return true;
  };
}

/**
 * Runs one refusal from `sealerCases.js` through `sealerForRender`: builds
 * the case's setup, makes its calls, and asserts that the last call, or the
 * factory when the case makes none, refuses with the case's code and message.
 * A port may refuse at once or through the promise; both are its refusal.
 *
 * @param {(setup: any) => Promise<any>} sealerForRender
 * @param {import("./sealerCases.js").SealerRefusal} refused
 */
export async function assertRefusalCase(sealerForRender, refused) {
  const setup = refusalSetup(sealerRefusalSetup(), refused);
  const check = refusal(refused.code, refused.message);
  const calls = refused.calls ?? [];
  if (calls.length === 0) {
    await assert.rejects(async () => sealerForRender(setup), check, refused.name);
    return;
  }
  const sealer = await sealerForRender(setup);
  for (const [member, args] of calls.slice(0, -1)) await sealer[member](...args);
  const [member, args] = calls[calls.length - 1];
  await assert.rejects(async () => sealer[member](...args), check, refused.name);
}

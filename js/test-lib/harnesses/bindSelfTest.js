// @ts-check
//
// A modeled fixture diagnostic for construction tests. It is not installed
// in the production issuer and does not define its per-coordinate error handling.
//
// This harness tells a wiring mistake from an attack. Any post-unseal binding
// failure is classified by this model as suspected tampering. Its whole-request
// observation differs from production per-coordinate results. Wrong binding
// wiring fails every blob; the diagnostic models how a deployment could
// distinguish that from suspected tampering. The wiring errors are real and
// cheap to make: a BIND joined without the delimiter, an unseal path that
// supplies no additionalData, a renderId compared as bytes where the grammar
// binds the string. All of them fail closed, none of them says what it was.
//
// A fixture the issuer holds itself separates the two: a blob a publisher
// sealed, the coordinate it was sealed at, and the key bytes it has to open to.
// Nothing in it came off the wire, so its outcome is a statement about this
// issuer's configuration and nothing else. It is one unseal of one known blob,
// and this file runs it from the tests that record the separation. Where a
// deployment would run it, and whether it runs it at all, is that deployment's
// question and no part of this harness.
//
// This harness reads the failure class off the fixture. "Every blob failed" and
// "the wiring is wrong" are different claims: a render every one of whose blobs
// was moved is still per-blob tampering, and a keyId wired to the wrong join
// fails a fixture that never left the building. So `bindFailureClass` reads the
// class off the self-test, and uses the per-blob outcomes only to name what
// failed.

import { base64urlEncode } from "../../core-shared/codec.js";
import * as boundSealing from "../../core-shared--publisher-issuer/keySealing.js";

/**
 * Core's module as this harness's KeySealing: core exports the opening side as
 * `open`, and this self-test reads it under the name `unseal`.
 */
const coreSealing = { seal: boundSealing.seal, unseal: boundSealing.open };

/**
 * A blob whose provenance the issuer knows, and what it has to open to. The
 * binding fields ride at the top level, in the shape `bind.js` takes them:
 * `renderId` with a `contentName`, `renderId` with an `accessGroup` and its
 * `t`, or a chain position as an `accessGroup` with a `suppliedT` and the
 * complete geometry. A recorded vector is one of these.
 *
 * @typedef {object} BindFixture
 * @property {string} blob - as a wire would carry it, base64url
 * @property {string} keyBase64url - the key bytes the blob is known to hold
 * @property {string} renderId
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t]
 * @property {string} [suppliedT]
 * @property {boolean} [chainKey]
 * @property {number} [chainsPerDay]
 * @property {number} [periodMinutes]
 */

/**
 * @typedef {object} SelfTestResult
 * @property {boolean} ok
 * @property {string} reason - one of a fixed few sentences, for a line a reader
 *   of the result writes. It states the wiring and never which field of the
 *   coordinate disagreed: the fixture answers whether this keyId is wired the
 *   way the publisher's is, and a per-field cause reads like the per-blob
 *   relabel report this exists to be told apart from
 */

/**
 * One unseal of a known blob, run through the same modules and the same options
 * a request would take, so a misconfiguration is reproduced rather than
 * described. Returns rather than throws: a failed self-test is a fact about the
 * configuration, and a caller reads it as one.
 *
 * @param {object} config
 * @param {BindFixture} config.fixture
 * @param {CryptoKey} config.privateKey - the keyId's, the one being checked
 * @param {string} config.algorithm
 * @param {{ unseal?: (blob: string, privateKey: CryptoKey, algorithm: string, options: any) => Promise<Uint8Array> }} [config.keySealing]
 * @returns {Promise<SelfTestResult>}
 */
export async function bindSelfTest({ fixture, privateKey, algorithm, keySealing = coreSealing }) {
  const unseal = keySealing.unseal;
  if (typeof unseal !== "function") {
    return {
      ok: false,
      reason: "the configured keySealing has no unseal to run the fixture through",
    };
  }

  const { blob, keyBase64url, ...binding } = fixture;
  const options = { binding };

  let opened;
  try {
    opened = await unseal(blob, privateKey, algorithm, options);
  } catch {
    return {
      ok: false,
      reason: "the fixture did not open under this keyId's binding configuration",
    };
  }

  // A blob that opens to other bytes is not a thing either carrier can
  // produce - both authenticate what they return. It is checked anyway,
  // because the fixture is the issuer's statement about its own wiring and a
  // statement that only ever checks half of itself is worth less.
  if (base64urlEncode(opened) !== keyBase64url) {
    return { ok: false, reason: "the fixture opened to bytes other than the ones it records" };
  }

  return { ok: true, reason: "the fixture opened to the key it records" };
}

/**
 * What one blob's unseal did, as a count of this request's blobs.
 *
 * @typedef {object} BlobOutcome
 * @property {string} coordinate - `contentKeys.<name>`, `periodKeys.<group>.<t>`
 * @property {boolean} ok
 */

/**
 * @typedef {object} BindFailureClass
 * @property {'ok'|'all-blobs-fail'|'single-blob-fail'} class
 * @property {string[]} coordinates - what failed; empty on `ok`, and on
 *   `all-blobs-fail` it is whatever this request happened to carry
 * @property {string} reason
 */

/**
 * Distinguish a misconfigured opener from a failing request blob using the
 * self-test fixture rather than the number of failed request entries.
 *
 * @param {SelfTestResult} selfTest
 * @param {BlobOutcome[]} outcomes - this request's blobs
 * @returns {BindFailureClass}
 */
export function bindFailureClass(selfTest, outcomes) {
  const failed = outcomes.filter((outcome) => !outcome.ok).map((outcome) => outcome.coordinate);

  if (!selfTest.ok) {
    // The keyId's own fixture did not open, so nothing this keyId is asked
    // to unseal will open either. Whatever failed in the request is a
    // consequence, and calling it tampering would bury the wiring error
    // under alarms, which is the whole of the hazard.
    return {
      class: "all-blobs-fail",
      coordinates: failed,
      reason: `this keyId's binding configuration is wrong: ${selfTest.reason}`,
    };
  }
  if (failed.length === 0) {
    return {
      class: "ok",
      coordinates: [],
      reason: "the fixture opened and so did every blob presented",
    };
  }

  return {
    class: "single-blob-fail",
    coordinates: failed,
    reason: `the fixture opened, so the binding is wired right and these blobs did not open: ${failed.join(", ")}`,
  };
}

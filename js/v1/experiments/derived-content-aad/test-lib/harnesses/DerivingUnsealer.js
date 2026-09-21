// @ts-check
//
// The client half of the variant: a client composition that builds the content
// aad instead of reading it.
//
// One thing changes. Key delivery, the cache, the trial unwrap, the request and
// the response belong to the dissolved units and stay theirs - the aad is an
// argument to the last call of the open path, so this variant overrides only
// where the aad comes from. Resolving a cached page and an unlocked page open
// the same way here as on the base composition, because that logic is inherited
// rather than reimplemented. `openContent` is reused for the same reason on the other
// end: the aad is what this variant chooses, and the guards around a mangled
// nonce, an undecodable ciphertext and a failing tag are not variant business
// and must not be a copy that falls behind.
//
// The contentData record is still required. `nonce` and `contentType` are
// there and only `aad` is derived, so a name the page has no record for is the
// same miss it always was and reports the same code.
//
// A publisher that sealed under an aad outside the grammar ships a page this
// composition cannot open. There is no fallback to the shipped field: reading
// the wire when the derivation disagrees would hand the binding back to whoever
// wrote the page, which is the property the variant exists to remove.
//
// It extends the reference client composition in `test-lib`, which is where
// the network-free wiring of the dissolved `Unsealer`'s successors lives; this
// variant and that composition are both reference-suite material.

import { Client } from "../../../../test-lib/harnesses/client.js";
import { contentAadFor } from "../../implementation/contentAad.js";

export class DerivingUnsealer extends Client {
  /**
   * The one departure from the base composition: the aad comes from the slot
   * being filled, not from the item record beside the ciphertext.
   *
   * @param {object} dcaData
   * @param {string} contentName
   * @returns {string}
   */
  aadFor(dcaData, contentName) {
    return contentAadFor(dcaData, contentName);
  }
}

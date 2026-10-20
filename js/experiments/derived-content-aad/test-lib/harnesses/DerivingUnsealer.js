// @ts-check
//
// The historical mirror-rebuild client: an old-format client that builds the
// content aad from the page's `resource.resourceId` mirror and `version`
// instead of reading the carried member.
//
// One thing changes. Key delivery, the cache, the trial unwrap, the request and
// the response stay the reference composition's, and the open step is the
// old-format control's in `CarriedAadClient`. This variant overrides only where
// the aad comes from, so the guards around a missing record, a mangled nonce,
// an undecodable ciphertext and a failing tag stay shared with that control.
//
// The contentData record is still required. `nonce` and `contentType` are
// there and only `aad` is derived, so a name the page has no record for is the
// same miss it always was and reports the same code.
//
// It compares against the pre-adoption carried format only. The adopted
// `dca-bind-content` transcript is neither of these strings, so this client
// opens nothing a current publisher seals. Its substantive defect is relying
// on the optional diagnostic mirror.

import { CarriedAadClient } from "./CarriedAadClient.js";
import { contentAadFor } from "../../implementation/contentAad.js";

export class DerivingUnsealer extends CarriedAadClient {
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

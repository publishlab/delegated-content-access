// @ts-check
//
// Historical candidate: rebuild the pre-adoption content AAD from the optional
// resource mirror. It is neither the adopted `dca-bind-content` transcript nor
// the old carried rule; it is an old-format comparator only.
//
// Until 2026-10-15, `js/core-publisher/Sealer.js` built every content aad as
// `[resourceId, version, contentName].join(AAD_DELIMITER)` and shipped it in
// `contentData[contentName].aad`. The version and selected content name are
// required, but `resource` is only an optional diagnostic mirror. Unlock
// relays `resourceJWT` unchanged; it does not read this mirror. This
// construction therefore loses valid mirror-absent deliveries.
//
// The issuer independently rebuilds envelope BIND from its authorized
// coordinate. That is a different trust boundary: the client need not verify
// the signed JWT, and this mirror carries no authenticated publisher claim.
//
// The old content-protection rule fixed `resourceId|1|contentName` even though
// the client read the carried string. Arbitrary publisher AAD was not
// conformant. The historical candidate differed on source, not publisher
// freedom to invent another transcript.
//
// `disagreeingShippedAad` makes an old-format page whose carried AAD no longer
// equals the transcript the publisher sealed under. The test shows which field
// the two old-format clients use, not two conformant readings. A current client
// ignores the member altogether.

import { AAD_DELIMITER } from "../../../core-shared--client-publisher/names.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";

/**
 * The aad one content item was sealed under, from the page's own fields.
 *
 * The two page fields are checked rather than coerced: a missing `version`
 * joined as `undefined` would produce a plausible string that opens nothing,
 * and a tag failure is a worse report than the field that was not there.
 * When this candidate was written, `validateResourceId` refused the delimiter
 * at the publisher and `version` was the format version, so no pair of them
 * joined to another pair's aad.
 *
 * @param {object} dcaData
 * @param {string} contentName
 * @returns {string}
 */
export function contentAadFor(dcaData, contentName) {
  const version = own(dcaData, "version");
  if (typeof version !== "string") {
    throw dcaError("bad_page", "dca-data carries no version, and the content aad is built from it");
  }

  const resourceId = own(own(dcaData, "resource"), "resourceId");
  if (typeof resourceId !== "string") {
    throw dcaError(
      "bad_page",
      "dca-data carries no resourceId, and the content aad is built from it",
    );
  }

  return [resourceId, version, contentName].join(AAD_DELIMITER);
}

/**
 * The value written over every shipped aad. A well-formed string the grammar
 * cannot produce: the derivation joins three fields on the delimiter, and this
 * carries none of it.
 */
export const DISAGREEING_AAD = "shipped-aad-this-variant-ignores";

/**
 * The same page with every `contentData[*].aad` replaced by a value that is
 * wrong for the item it sits on. A clone, because the comparison runs against
 * the caller's page, and a page that quietly lost its own aads leaves nothing
 * to compare against.
 *
 * The field stays present and a string, so structural admission succeeds, but
 * the page violates the old producer rule. It no longer carries a usable
 * value, so an old-format client reading the field off it opens nothing and an
 * old-format client deriving it opens every item.
 *
 * Takes a whole page or the dca-data alone: the field sits at the same place in
 * both, and `sealedContent` beside it is carried through untouched.
 *
 * @param {object} pageOrDcaData
 * @returns {any} the same shape, with every aad disagreeing
 */
export function disagreeingShippedAad(pageOrDcaData) {
  const disagreeing = structuredClone(pageOrDcaData);

  const contentData = own(disagreeing, "contentData");
  if (contentData === null || typeof contentData !== "object") return disagreeing;

  for (const contentName of Object.keys(contentData)) {
    const record = own(contentData, contentName);
    if (record !== null && typeof record === "object") record.aad = DISAGREEING_AAD;
  }

  return disagreeing;
}

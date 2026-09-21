// @ts-check
//
// The content aad, rebuilt from the page rather than read off it.
//
// `js/v1/core-publisher/Sealer.js` builds every content aad the same way,
// `[resourceId, version, contentName].join(AAD_DELIMITER)`, and then ships the
// result in `contentData[contentName].aad`. All three inputs are already on
// the page in fields the client has to read anyway: `version` and
// `resource.resourceId` are what the unlock request is built from, and the
// contentName is the slot being filled. So the shipped string is a copy of
// something the client can produce, and this module produces it.
//
// The issuer already works this way. It rebuilds the value a sealed key blob
// was bound under from the coordinate the request presented that blob at, and
// never from a field the blob carries beside itself: a label the attacker
// moves along with the blob labels nothing. `DerivingUnsealer` beside this puts
// the content aad on the same footing, one layer down and on the client.
//
// The derivation costs a degree of freedom: the grammar becomes normative. A
// publisher that seals under an aad of its own choosing (a compartment id, a
// licence term, anything opaque) produces a page a deriving client cannot
// open, and the page is still conformant to the shipped-aad reading. That is
// the degree of freedom the wire field buys, and the one this variant spends.
//
// `disagreeingShippedAad` puts the shipped field and the derivation in open
// conflict. The page stays the format's page, since `aad` is a required member
// and keeps a string in it, so an end-to-end run over such a page shows that
// the value is never read: the deriving client opens every item, and the
// stock client, holding the same keys, opens none.

import { AAD_DELIMITER } from "../../../core-shared--client-publisher/names.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";

/**
 * The aad one content item was sealed under, from the page's own fields.
 *
 * The two page fields are checked rather than coerced: a missing `version`
 * joined as `undefined` would produce a plausible string that opens nothing,
 * and a tag failure is a worse report than the field that was not there.
 * Neither field can carry the delimiter, since `validateResourceId` refuses it
 * at the publisher and `version` is the format version, so no pair of them
 * joins to another pair's aad.
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
 * The field stays present and a string: the format requires it and this variant
 * ships the format's page. What the page no longer carries is a usable value,
 * so a client reading the field off it opens nothing and a client deriving it
 * opens every item.
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

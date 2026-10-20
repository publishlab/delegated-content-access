// @ts-check
import { validateContentName } from "../../../core-shared/names.js";
import { isDescriptionRecord } from "../core-shared--client-publisher/contentDescription.js";
/** @typedef {import('../core-shared--client-publisher/contentDescription.js').DescriptionAdmission} DescriptionAdmission */
/** @typedef {{contentName: string, contentType: string, bytes: Uint8Array, description: DescriptionAdmission}} DescriptionHandoff */
const ADMISSION_STATES = ["absent", "available", "unsupported", "invalid"];
/** Package one opened item for its handler. Both inputs come from the capture the
 * client made before its first await: the item view `DcaData#contentItemFor`
 * returned, and the description admitted from the record at that same moment.
 * A page that edits the record while the client awaits a key changes neither,
 * so the handler gets the captured contentType. Content AAD does not bind that
 * type. This function reads no delivery record, opens nothing and applies no
 * inverse transform.
 * @param {Readonly<{contentName: string, contentType: string}>} item - the captured
 *   view, as `DcaData#contentItemFor` returns it
 * @param {DescriptionAdmission} description - `admitContentDescription(record)`,
 *   taken together with `item`
 * @param {Uint8Array} openedBytes - after opening and inverse transforms
 * @returns {DescriptionHandoff}
 */
export function contentDescriptionHandoff(item, description, openedBytes) {
  if (!isDescriptionRecord(item)) throw new TypeError("Expected the captured item view");
  validateContentName(item.contentName);
  if (typeof item.contentType !== "string" || !item.contentType.length)
    throw new TypeError("An authoritative contentType is required");
  if (
    !isDescriptionRecord(description) ||
    !ADMISSION_STATES.includes(description.state) ||
    (description.state === "available"
      ? !isDescriptionRecord(description.description)
      : description.description !== null)
  )
    throw new TypeError("Expected a description admission");
  if (!(openedBytes instanceof Uint8Array)) throw new TypeError("Expected opened bytes");
  return {
    contentName: item.contentName,
    contentType: item.contentType,
    bytes: openedBytes,
    description,
  };
}
/** Check a trusted handler's declared schema policy. Ready means permitted handoff,
 * never successful payload validation. The application owns decoding, validation,
 * source provenance and handler invocation. Identifiers match exactly.
 * @param {DescriptionHandoff} handoff
 * @param {{requiresSchema: boolean, supportedSchemas: string[]}} policy
 * @returns {{state: 'ready'|'refused', schema: string|null}}
 */
export function selectContentDescriptionHandler(handoff, policy) {
  if (
    typeof policy.requiresSchema !== "boolean" ||
    !Array.isArray(policy.supportedSchemas) ||
    policy.supportedSchemas.some((schema) => typeof schema !== "string")
  )
    throw new TypeError("Expected a trusted handler policy");
  const schema =
    handoff.description.state === "available"
      ? (handoff.description.description?.schema ?? null)
      : null;
  const supported = schema !== null && policy.supportedSchemas.includes(schema);
  return {
    state: policy.requiresSchema && !supported ? "refused" : "ready",
    schema: supported ? schema : null,
  };
}

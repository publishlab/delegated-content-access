// @ts-check
import { isContentName, validateContentName } from "../../../core-shared/names.js";
import { recordsByName } from "../../../core-shared--client-publisher/deliveryRecords.js";
import {
  admitContentDescription,
  isDescriptionRecord,
} from "../core-shared--client-publisher/contentDescription.js";
/** Compose descriptions into an already published delivery; inputs are not mutated.
 * Every supplied and retained description must be admissible before a result returns.
 * Records are copied shallowly; unrelated metadata and ciphertext remain unchanged.
 * `contentData` is the wire collection `[{contentName, ...}]`. A repeated name
 * keeps its last whole record, as a reader would resolve it, so the result
 * carries one record per name.
 * @param {Record<string, any>} dcaData
 * @param {Record<string, unknown>} descriptionsByName
 * @param {import('../core-shared--client-publisher/contentDescription.js').DescriptionOptions} [options]
 * @returns {Record<string, any>}
 */
export function withContentDescriptions(dcaData, descriptionsByName, options = {}) {
  if (
    !isDescriptionRecord(dcaData) ||
    !Object.hasOwn(dcaData, "contentData") ||
    !Array.isArray(dcaData.contentData) ||
    !isDescriptionRecord(descriptionsByName)
  )
    throw new TypeError("Expected delivery and description records");
  // A publisher step refuses what a reader would skip: a non-record element
  // means the delivery it was handed is already broken.
  if (!dcaData.contentData.every(isDescriptionRecord))
    throw new TypeError("Expected content records");
  const records = recordsByName(dcaData.contentData, "contentName", isContentName);
  if (records === null) throw new TypeError("Expected a contentName on every content record");
  for (const name of Object.keys(descriptionsByName)) {
    validateContentName(name);
    if (!records.has(name)) throw new TypeError(`Unknown content name: ${name}`);
    const admitted = admitContentDescription(
      { contentDescription: descriptionsByName[name] },
      options,
    );
    if (admitted.state !== "available")
      throw new TypeError(`Invalid supplied content description: ${name}`);
  }
  const contentData = [];
  for (const [name, source] of records) {
    if (
      !Object.hasOwn(source, "contentType") ||
      typeof source.contentType !== "string" ||
      !source.contentType.length
    )
      throw new TypeError(`Missing contentType: ${name}`);
    const item = { ...source };
    if (Object.hasOwn(descriptionsByName, name)) item.contentDescription = descriptionsByName[name];
    const admitted = admitContentDescription(item, options);
    if (admitted.state === "invalid" || admitted.state === "unsupported")
      throw new TypeError(`Invalid content description: ${name}`);
    if (admitted.state === "available") item.contentDescription = admitted.description;
    contentData.push(item);
  }
  return { ...dcaData, contentData };
}

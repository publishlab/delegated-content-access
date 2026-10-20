// @ts-check
import { validateContentName } from "../../../core-shared/names.js";
import {
  admitContentDescription,
  isDescriptionRecord,
} from "../core-shared--client-publisher/contentDescription.js";
/** Compose descriptions into an already published delivery; inputs are not mutated.
 * Every supplied and retained description must be admissible before a result returns.
 * Records are copied shallowly; unrelated metadata and ciphertext remain unchanged.
 * @param {Record<string, any>} dcaData
 * @param {Record<string, unknown>} descriptionsByName
 * @param {import('../core-shared--client-publisher/contentDescription.js').DescriptionOptions} [options]
 * @returns {Record<string, any>}
 */
export function withContentDescriptions(dcaData, descriptionsByName, options = {}) {
  if (
    !isDescriptionRecord(dcaData) ||
    !Object.hasOwn(dcaData, "contentData") ||
    !isDescriptionRecord(dcaData.contentData) ||
    !isDescriptionRecord(descriptionsByName)
  )
    throw new TypeError("Expected delivery and description records");
  for (const name of Object.keys(descriptionsByName)) {
    validateContentName(name);
    if (!Object.hasOwn(dcaData.contentData, name))
      throw new TypeError(`Unknown content name: ${name}`);
    const admitted = admitContentDescription(
      { contentDescription: descriptionsByName[name] },
      options,
    );
    if (admitted.state !== "available")
      throw new TypeError(`Invalid supplied content description: ${name}`);
  }
  const contentData = Object.create(null);
  for (const name of Object.keys(dcaData.contentData)) {
    validateContentName(name);
    const source = dcaData.contentData[name];
    if (
      !isDescriptionRecord(source) ||
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
    contentData[name] = item;
  }
  return { ...dcaData, contentData };
}

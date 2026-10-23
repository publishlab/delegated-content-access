// @ts-check
// Trusted endpoint limits are publisher configuration, never wire claims.
import { utf8Encode } from "../core-shared/codec.js";
import { dcaError } from "../core-shared/errors.js";
import { requestEntryCounts } from "../core-shared/requestLimits.js";
import { recordsByName } from "../core-shared--client-publisher/deliveryRecords.js";

/**
 * What a selected request composition adds to the base request it wraps:
 * members of `sealed` and members of the request root.
 * @typedef {{ sealed?: Record<string, unknown>, members?: Record<string, unknown> }} RequestRelay
 */

/**
 * The widest request a client composed for this delivery sends to one issuer,
 * or undefined when the delivery carries no block for it. Base members are
 * conservative: every sealed content key, and the period and chain members of
 * every group an item is wrapped under. `relays` are the selected
 * extensions' own projections of the delivery, so the extension members are
 * the ones a client relays, not a copy of their rules. Client-added public
 * keys, hints and local narrowing are not in it; `clientRequestExtraBytes`
 * bounds their bytes.
 * @param {any} delivery
 * @param {any} issuer
 * @param {readonly ((delivery: any, issuerName: string) => RequestRelay | undefined)[]} [relays]
 */
export function issuerRequestDocument(delivery, issuer, relays = []) {
  const block = recordsByName(delivery.issuerData, "issuerName", () => true)?.get(
    issuer.issuerName,
  );
  if (block === undefined) return undefined;
  const groupsNeeded = new Set(
    delivery.contentData.flatMap((/** @type {any} */ item) =>
      (item.keys ?? []).map((/** @type {any} */ entry) => entry.accessGroup),
    ),
  );
  /** @type {Record<string, any>} */
  const sealed = { contentKeys: block.sealed.contentKeys ?? [] };
  for (const field of ["periodKeys", "chainKeys"]) {
    const records = (block.sealed[field] ?? []).filter((/** @type {any} */ record) =>
      groupsNeeded.has(record.accessGroup),
    );
    if (records.length > 0) sealed[field] = records;
  }
  /** @type {Record<string, unknown>} */
  const members = {};
  for (const relay of relays) {
    const added = relay(delivery, issuer.issuerName);
    Object.assign(sealed, added?.sealed ?? {});
    Object.assign(members, added?.members ?? {});
  }
  return {
    version: delivery.version,
    issuerName: issuer.issuerName,
    resourceJWT: delivery.resourceJWT,
    keyId: block.keyId,
    // The client relays the block's procedure selector beside keyId.
    ...(block.envelope === undefined ? {} : { envelope: block.envelope }),
    sealed,
    ...(sealed.chainKeys && delivery.periodGeometry
      ? { periodGeometry: delivery.periodGeometry }
      : {}),
    ...members,
  };
}

/**
 * Refuse a delivery whose widest request to one issuer exceeds that issuer's
 * trusted entry or byte limits. An explicit additional-byte bound covers
 * client-added members; absent that bound, only the publisher-authored lower
 * bound is checked.
 * @param {any} delivery
 * @param {any} issuer
 * @param {readonly ((delivery: any, issuerName: string) => RequestRelay | undefined)[]} [relays]
 */
export function assertIssuerRequestBudget(delivery, issuer, relays = []) {
  const document = issuerRequestDocument(delivery, issuer, relays);
  if (document === undefined) return;
  const counts = requestEntryCounts(document.sealed);
  const limits = issuer.limits;
  const failure =
    counts.entries > limits.maxEntries
      ? "maxEntries"
      : [...counts.groups.values()].some((count) => count > limits.maxEntriesPerGroup)
        ? "maxEntriesPerGroup"
        : undefined;
  if (failure)
    throw dcaError("bad_config", `issuer ${issuer.issuerName} publication exceeds ${failure}`);
  const bytes = utf8Encode(JSON.stringify(document)).length + (issuer.clientRequestExtraBytes ?? 0);
  if (bytes > limits.maxBodyBytes)
    throw dcaError("bad_config", `issuer ${issuer.issuerName} publication exceeds maxBodyBytes`);
}

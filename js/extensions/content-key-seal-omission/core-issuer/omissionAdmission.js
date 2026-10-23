// @ts-check
import { dcaError } from "../../../core-shared/errors.js";
import { isAccessGroup, isContentName } from "../../../core-shared/names.js";
import { isPeriodKeyLabel } from "../../../core-shared/periodLabels.js";
import { DEFAULT_REQUEST_LIMITS } from "../../../core-shared/requestLimits.js";
import { own } from "../../../core-shared/wire.js";
import { EXTENSION_NAME } from "../core-shared/omissionBind.js";

/** Validate identities before policy, signature or private-key work.
 * @param {any} request
 */
export function admitOmissionCandidates(request) {
  const value = own(request.toObject(), "boundCandidates");
  if (value === undefined) return;
  if (!Array.isArray(value)) throw dcaError("binding_failed", "boundCandidates must be an array");
  if (value.length > DEFAULT_REQUEST_LIMITS.maxEntries)
    throw dcaError("too_many_entries", "too many bound candidates");
  for (const record of value) {
    if (record === null || typeof record !== "object" || Array.isArray(record)) continue;
    if (
      !isContentName(own(record, "contentName")) ||
      !isAccessGroup(own(record, "accessGroup")) ||
      !isPeriodKeyLabel(own(record, "period"))
    )
      throw dcaError("binding_failed", "invalid bound candidate identity");
  }
}

/** Atomic processor selection: structural admission and coordinate presence.
 * @returns {{ selectedExtensions: string[], requestBounds: ((request: any) => void)[], extensionCoordinates: Record<string, (request: any) => boolean> }}
 */
export function omissionProcessorOptions() {
  return {
    selectedExtensions: [EXTENSION_NAME],
    requestBounds: [admitOmissionCandidates],
    extensionCoordinates: {
      [EXTENSION_NAME]: (request) => {
        admitOmissionCandidates(request);
        return (own(request.toObject(), "boundCandidates") ?? []).some(
          (/** @type {any} */ record) =>
            record !== null && typeof record === "object" && !Array.isArray(record),
        );
      },
    },
  };
}

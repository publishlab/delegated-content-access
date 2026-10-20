// @ts-check
//
// The omission composition's one reading of a content-key entry. Unmarked
// entries stay ordinary for mixed renders; this extension owns its own wrap
// marker and its wrap AAD, and declines every other marker without an unbound
// retry. The item's content AAD is not this module's: the core capture derives
// it from the delivery token and the item record.

import { DcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { isBoundEntry, omissionBindAad } from "../core-shared/omissionBind.js";

/**
 * @param {{ entry: any, renderId: string, contentName: string, accessGroup: string }} context
 * @returns {{ aad?: Uint8Array }|null}
 */
export function omissionEntryInterpretation({ entry, renderId, contentName, accessGroup }) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return null;
  if (!Object.hasOwn(entry, "bind")) return { aad: undefined };
  if (!isBoundEntry(entry)) return null;

  const t = own(entry, "t");
  if (typeof t !== "string") return null;
  try {
    return { aad: omissionBindAad({ renderId, contentName, accessGroup, t }) };
  } catch (cause) {
    if (cause instanceof DcaError && cause.code === "binding_failed") return null;
    throw cause;
  }
}

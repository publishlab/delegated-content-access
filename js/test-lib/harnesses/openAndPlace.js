// @ts-check
//
// A reference-test harness for the proposed plaintext hand-off. It combines the
// opening, miss collection, metadata reading, and the `place(...)` call into one
// loop so `test/leak-checks.test.js` can exercise that seam end to end. It stands
// outside client core, outside shipped production behavior, and outside the target
// placement adapter: the design's client placement adapter is deliberately held
// out, and it receives already-opened content, so it never receives an unsealer,
// keys, dcaData, or a resolver - all of which this harness holds only to drive the
// read.
//
// `place(contentName, decryptedData, contentType)` and nothing else. The
// publisher knows its own markup and the issuer's decrypt chain knows the keys;
// three values is the whole of what crosses between them, so a placement script
// is never handed a key, a dcaData or a resolver to reach one through. It is
// called once per opened item, after the decrypt and never before it - a
// callback that fired on a miss would be a page rendering an empty article as
// though it had been unlocked.
//
// This loop runs the same under both transports. Direct hands the client key
// bytes and client-bound hands it handles; by the time anything reaches here the
// key is spent and what is left is plaintext, so a publisher's placement script
// has no transport to know about.
//
// The caller picks the delivery form. `page` is anything answering `dcaData` and
// `extract(contentName)` - `adapter-client/MarkupDeliveryReader.js` over a DOM, or
// `demo/support/ObjectDeliveryReader.js` over the JSON form. The two forms
// differ in where a blob is looked up and in nothing that reaches this loop.
//
// A typed refusal is a locked item and not a failure: a name with no key, a page
// with no record for it, a tag mismatch. Anything untyped is a bug in the
// client rather than a state to show, and goes up loud - the rule
// `demo/actors/PageLoad.js` already reads by.

import { DcaError, dcaError } from "../../core-shared/errors.js";
import { own } from "../../core-shared/wire.js";
import { contentRecordOf } from "../helpers/inspect.js";

/**
 * @typedef {object} SealedPage
 * @property {any} dcaData
 * @property {(contentName: string) => string|null} extract
 */

/**
 * @param {object} config
 * @param {SealedPage} config.page - the render, in whichever delivery form
 * @param {any} config.unsealer - holding whatever the unlock returned
 * @param {string[]} config.contentNames - what to open, in the caller's order
 * @param {(contentName: string, decryptedData: Uint8Array, contentType: any) => void} config.place
 * @returns {Promise<{ placed: string[], locked: { contentName: string, error: string }[] }>}
 */
export async function openAndPlace(config) {
  for (const name of Object.keys(config ?? {})) {
    if (!["page", "unsealer", "contentNames", "place"].includes(name)) {
      throw dcaError(
        "unsupported_option",
        `openAndPlace has no ${name} yet, and will not pretend to`,
      );
    }
  }
  const { page, unsealer, contentNames, place } = config ?? {};
  if (typeof place !== "function") {
    throw dcaError("bad_config", "placement is the caller's: openAndPlace needs a place callback");
  }
  if (typeof page?.extract !== "function") {
    throw dcaError(
      "bad_config",
      "a page here answers dcaData and extract - the markup form or the JSON one",
    );
  }
  if (!Array.isArray(contentNames)) {
    throw dcaError("bad_config", "openAndPlace opens the names it is given, as an array");
  }

  /** @type {string[]} */
  const placed = [];
  /** @type {{ contentName: string, error: string }[]} */
  const locked = [];

  for (const contentName of contentNames) {
    /** @type {Uint8Array} */
    let decryptedData;
    try {
      decryptedData = await unsealer.decrypt(page.dcaData, contentName, page.extract(contentName));
    } catch (cause) {
      if (!(cause instanceof DcaError)) throw cause;
      locked.push({ contentName, error: cause.code });
      continue;
    }

    // contentType is the page's own metadata beside the blob, read after the
    // decrypt rather than carried through it: it tells the placement script
    // text from binary and decides nothing about the crypto.
    const record = contentRecordOf(page.dcaData, contentName);
    place(contentName, decryptedData, own(record, "contentType"));
    placed.push(contentName);
  }

  return { placed, locked };
}

// @ts-check
//
// Key acquisition and opening for the map items, and the three item states of
// docs/spec-proposal--html-content-map.md Section 6.2. The map is a profile layer after
// DCA key opening: this module drives the base client pieces a host already
// composes (`integration-client/createBrowserClient.js` returns them) and adds
// no key path of its own. The resolver tries held and cached capability first,
// one unlock asks the issuer for what is still missing, and the base opener
// authenticates, decrypts and reverses any content encodings.
//
// An item that still resolves no key after a completed unlock is `locked`:
// an omitted coordinate, a `notDelivered` family, a per-coordinate error or
// a completed refusal status. An exhausted observable 5xx is acquisition
// failure when an item remains unresolved. Section 6.2
// forbids turning any of these into an item-level policy or availability
// claim, because core may omit a denied item content key without a reason.
//
// An item whose key resolved and whose opening or decoding fails is `failed`:
// the delivery is defective. Section 4.3 decodes the octets as UTF-8 without a
// byte order mark or fail, so `EF BB BF` at the start is a failure too, because
// engines disagree on whether to strip it.
//
// Each item is opened from the view `DcaData#contentItemFor` captured before
// the key is awaited. The content AAD, the decoders and the contentType an
// opened item reports all come from that one read, so the type a caller
// places the text as is the type the AEAD authenticated.

import { DcaError, dcaError } from "../../../core-shared/errors.js";

/** @typedef {'opened'|'locked'|'failed'} ItemState */
/** The acquisition result this mapper observes; response bodies stay with the client.
 * @typedef {{ status: number }|{ skipped: string }} MapUnlockResult
 */

/**
 * The base client pieces this module drives. `createBrowserClient` returns all
 * five; another composition supplies the same calls.
 *
 * @typedef {object} MapKeyClient
 * @property {any} dcaData - the `core-client/DcaData.js` view of the delivery
 * @property {{ extract: (contentName: string) => string|null }} reader
 * @property {any} resolver - `core-client/ContentKeyResolver.js` or a
 *   composition answering `resolveDetailed` and `contentKeyWithOriginFor`
 * @property {any} opener - `core-client/ContentRepresentationOpener.js`
 * @property {(contentNames: string[]) => Promise<MapUnlockResult>} unlock
 */

/**
 * One map item after opening: its state, and its decoded text and captured
 * contentType when it opened.
 *
 * @typedef {{ state: 'opened', text: string, contentType: string }
 *   | { state: 'locked'|'failed', text: null }} MapItemResult
 */

const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decode opened octets under Section 4.3, or return null for an item failure.
 *
 * @param {Uint8Array} bytes
 * @returns {string|null}
 */
export function decodeMapItemText(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return null;
  }
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Obtain keys for the map items, open each and decode it. Every name ends in
 * exactly one state.
 *
 * @param {MapKeyClient} client
 * @param {string[]} contentNames - the map items, in map order
 * @returns {Promise<Record<string, MapItemResult>>}
 */
export async function openMapItems(client, contentNames) {
  const { dcaData, reader, resolver, opener, unlock } = client;
  if (typeof resolver?.resolveAuthenticated !== "function")
    throw dcaError("bad_config", "map opening needs authenticated item-key selection");
  /** @type {Set<string>} */
  const locked = new Set();

  const first = await resolver.resolveDetailed(dcaData, contentNames);
  /** @type {string[]} */
  const missing = first.missing;
  let acquisitionFailed = false;
  if (missing.length > 0) {
    try {
      const answer = await unlock(missing);
      acquisitionFailed =
        "status" in answer && typeof answer.status === "number" && answer.status >= 500;
    } catch (cause) {
      if (cause instanceof DcaError && cause.code === "bad_config") throw cause;
      acquisitionFailed = true;
    }
    const after = await resolver.resolveDetailed(dcaData, missing);
    for (const contentName of after.missing) locked.add(contentName);
  }

  /** @type {Record<string, MapItemResult>} */
  const results = {};
  for (const contentName of contentNames) {
    if (locked.has(contentName)) {
      results[contentName] = { state: "locked", text: null };
      continue;
    }
    let bytes;
    let item;
    try {
      item = dcaData.contentItemFor(contentName);
      if (item === null) {
        throw dcaError("bad_page", `the delivery declares no item "${contentName}"`);
      }
      bytes = await opener.open({
        item,
        ciphertext: reader.extract(contentName),
        // Rival candidates for one item are held newest first, and the newest
        // may be a wrong one: the opener's predicate selects the one that
        // opens, and the key comes out of the predicate rather than a second
        // read of the live delivery.
        resolveKey: async (/** @type {any} */ authenticate) => {
          /** @type {any} */
          let opened = null;
          await resolver.resolveAuthenticated(
            dcaData,
            [contentName],
            async (
              /** @type {string} */ _name,
              /** @type {any} */ candidate,
              /** @type {any} */ origin,
            ) => {
              const opens = await authenticate(candidate, origin);
              if (opens) opened = candidate;
              return opens;
            },
          );
          return opened;
        },
      });
    } catch (cause) {
      // A typed refusal is a defective item: record, AEAD or representation.
      // Anything untyped is a bug in this client and goes up.
      if (!(cause instanceof DcaError)) throw cause;
      results[contentName] = { state: "failed", text: null };
      continue;
    }
    const text = decodeMapItemText(bytes);
    results[contentName] =
      text === null
        ? { state: "failed", text: null }
        : { state: "opened", text, contentType: item.contentType };
  }
  if (acquisitionFailed && locked.size > 0) {
    const error =
      /** @type {import('../../../core-shared/errors.js').DcaError & { knownItems?: Record<string, MapItemResult> }} */ (
        dcaError("key_acquisition_failed", "key acquisition left an item unresolved")
      );
    error.knownItems = Object.fromEntries(
      Object.entries(results).filter(([name]) => !locked.has(name)),
    );
    throw error;
  }
  return results;
}

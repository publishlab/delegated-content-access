// @ts-check
//
// This module reads the baseline delivery form: the serialized UTF-8 JSON
// document of spec--data-format.md Section 6, object delivery, as
// `adapter-publisher/writeJsonDelivery.js` emits it. It answers the same
// surface as `MarkupDeliveryReader.js`, which reads the `dca-profile-html-carrier`
// markup form: `dcaData`, `publisherOrigin` and `extract(contentName)`. A
// client therefore drives the identical walk over either form.
//
// The reader takes bytes, because the octets are what crossed from the
// publisher. It decodes them as UTF-8 and stops at the first malformed
// sequence: the format makes malformed UTF-8 a failure of the whole document,
// so the reader salvages nothing. Section 6 requires ignoring exactly one
// UTF-8 byte order mark at byte offset zero. The decoder preserves any further
// mark, so `JSON.parse` refuses a repeated or misplaced mark.
//
// The host that obtained the document supplies the publisher origin. A JSON
// document carries no location, and the reader infers no provenance from it.
//
// `JSON.parse` keeps the last occurrence of a duplicated member name. The
// format lets a consumer accept such an object if it uses only the last
// occurrence, so the reader relies on that and adds no scanner of its own.
//
// The reader checks the structure Section 6 owns and nothing more. The
// `version` member and the rest of `dca-data` are admitted by
// `core-client/DcaData.js`, as they are for the markup form.
//
// The constructor decodes and parses once and keeps the result. What a client
// builds a request from and what it decrypts both come from that one reading,
// and a later change to the caller's bytes changes neither answer.

import { dcaError } from "../core-shared/errors.js";
import { isContentName } from "../core-shared/names.js";
import { normalizePublisherOrigin } from "../core-shared/publisherOrigin.js";
import { own } from "../core-shared/wire.js";

/** The members of the reader's context; any other member is refused. */
const CONTEXT_MEMBERS = ["publisherOrigin"];

/** The document member that carries the sealed-content map. */
const SEALED_MEMBER = "sealedContent";

/**
 * A decoder that throws on malformed UTF-8 and keeps a byte order mark in its
 * output. A non-streaming `decode` holds no state between calls, so one serves
 * every reader.
 */
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Whether `value` is a non-array object.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class JsonDeliveryReader {
  /** @type {any} */
  #dcaData;

  /**
   * The parsed sealed-content map, or null when the document carries none.
   *
   * @type {any}
   */
  #sealedContent;

  /** @type {string} */
  #publisherOrigin;

  /**
   * Refusals:
   * - `bad_config` for `bytes` that is not a `Uint8Array` (a string included),
   *   a `context` that is not an object, and a missing or non-canonical
   *   `publisherOrigin`
   * - `unsupported_option` for a context member other than `publisherOrigin`
   * - `bad_page` for malformed UTF-8, empty input or anything else `JSON.parse`
   *   refuses, a repeated or misplaced byte order mark, a non-array-object failure, a
   *   present `sealedContent` that is not a non-array object, and a
   *   `sealedContent` member name outside the contentName grammar
   *
   * @param {Uint8Array} bytes - the serialized document as it arrived
   * @param {{ publisherOrigin: string }} context - supplied by the host that
   *   obtained the document; the origin is a canonical HTTP(S) origin
   */
  constructor(bytes, context) {
    if (!(bytes instanceof Uint8Array)) {
      throw dcaError("bad_config", "a JsonDeliveryReader reads the document's bytes");
    }
    if (context === null || typeof context !== "object" || Array.isArray(context)) {
      throw dcaError("bad_config", "a JsonDeliveryReader needs its delivery context");
    }
    for (const name of Object.keys(context)) {
      if (!CONTEXT_MEMBERS.includes(name)) {
        throw dcaError("unsupported_option", `a JsonDeliveryReader context has no ${name}`);
      }
    }
    const publisherOrigin = normalizePublisherOrigin(own(context, "publisherOrigin"));
    if (publisherOrigin === null) {
      throw dcaError("bad_config", "a JsonDeliveryReader needs a canonical publisherOrigin");
    }

    let parsed;
    try {
      const document =
        bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? bytes.subarray(3) : bytes;
      parsed = JSON.parse(UTF8.decode(document));
    } catch {
      throw dcaError("bad_page", "the delivery is not one UTF-8 JSON document");
    }
    if (!isRecord(parsed)) {
      throw dcaError("bad_page", "the delivery document is not an object");
    }

    // An own-member read, like every name off the wire. `JSON.parse` makes
    // every member own, so this matters for the copy below, not for the parse.
    const sealedContent = own(parsed, SEALED_MEMBER);
    if (sealedContent !== undefined && !isRecord(sealedContent)) {
      throw dcaError("bad_page", "the sealedContent member is not an object");
    }
    // The map is keyed by contentName. The format rejects such a map on one
    // member name outside the grammar instead of passing over that member, so
    // the reader refuses the whole document.
    for (const name of Object.keys(sealedContent ?? {})) {
      if (!isContentName(name)) {
        throw dcaError("bad_page", "the sealedContent member carries a name outside the grammar");
      }
    }

    // The spread defines each member as an own data property, so a member
    // named `__proto__` stays a member and does not become a prototype.
    const dcaData = { ...parsed };
    delete dcaData[SEALED_MEMBER];
    this.#dcaData = dcaData;
    this.#sealedContent = sealedContent ?? null;
    this.#publisherOrigin = publisherOrigin;
  }

  /**
   * The parsed document without its `sealedContent` member: the same members a
   * markup reader returns from the `dca-data` block. Parsing does not
   * authenticate it.
   *
   * @returns {any}
   */
  get dcaData() {
    return this.#dcaData;
  }

  /**
   * The origin the host supplied, in canonical form.
   *
   * @returns {string}
   */
  get publisherOrigin() {
    return this.#publisherOrigin;
  }

  /**
   * The sealed ciphertext for one item, or null when this document does not
   * carry it. The read is an own-member lookup, so a name every object inherits
   * finds nothing. An absent item, a deferred item, a member that is not a
   * string and a name outside the grammar all return null; the decrypt decides
   * whether a string is usable ciphertext.
   *
   * @param {string} contentName
   * @returns {string|null} base64url ciphertext
   */
  extract(contentName) {
    if (!isContentName(contentName)) return null;

    const value = own(this.#sealedContent, contentName);
    return typeof value === "string" ? value : null;
  }
}

// @ts-check

// A buffering adapter over base Sealer. `content()` snapshots the caller's
// representation while the API is still synchronous; `seal()` compresses each
// selected item independently, adds the gzip layer to its ordered descriptor,
// and delegates the complete render to base.

import { Sealer } from "../../../core-publisher/Sealer.js";
import {
  isContentRepresentation,
  normalizeContentRepresentation,
} from "../../../core-publisher/contentRepresentation.js";
import { validateAccessGroup, validateContentName } from "../../../core-shared/names.js";
import { DcaError, dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { ENCODING, IDENTITY, webStreamsGzip } from "../core-shared--client-publisher/gzipCodec.js";
import { gunzip } from "../core-shared--client-publisher/inflate/inflate.js";

/**
 * @typedef {object} BufferedItem
 * @property {string} name
 * @property {Readonly<{ bytes: Uint8Array, contentType: string, contentEncodings: readonly string[] }>} representation
 * @property {string[]} accessGroups
 * @property {Record<string, unknown>} options - copies of the declared
 *   contributed item options this item named
 * @property {boolean} gzip
 */

/**
 * A plain JSON copy of one declared item option, under the rule base applies
 * in `Sealer.content()`. Base copies the option only at seal() when this
 * adapter flushes, so the adapter copies it at content(): a non-JSON value
 * fails at the call that named it, and a later change to the caller's object
 * reaches no render.
 *
 * Copied from ../../../core-publisher/Sealer.js: `snapshotContributedJson` and
 * the walk it calls, `snapshotJsonValue`, `snapshotJsonObject` and
 * `snapshotJsonArray`, folded into one walk. They are module-private there, and
 * base runs them inside its own `content()`, which this adapter calls only when
 * it flushes at seal(); base offers no seam that copies an option at entry
 * time. `../test/entry-validation-parity.test.js` refuses the same non-JSON
 * option through both sealers, so a change to base's rule shows up there.
 *
 * @param {unknown} value
 * @param {string} what
 * @returns {unknown}
 */
function plainJsonCopy(value, what) {
  /** @type {Set<object>} */
  const ancestors = new Set();
  /** @returns {never} */
  const refuse = () => {
    throw dcaError("bad_config", `${what} is a plain JSON value`);
  };
  /** @param {unknown} node @returns {unknown} */
  const copy = (node) => {
    if (node === null || typeof node === "string" || typeof node === "boolean") return node;
    if (typeof node === "number") return Number.isFinite(node) ? node : refuse();
    if (typeof node !== "object" || ancestors.has(node)) return refuse();
    const array = Array.isArray(node);
    const prototype = Object.getPrototypeOf(node);
    if (!array && prototype !== Object.prototype && prototype !== null) refuse();
    const keys = Reflect.ownKeys(node).filter((key) => !(array && key === "length"));
    if (array && keys.length !== /** @type {unknown[]} */ (node).length) refuse();
    ancestors.add(node);
    /** @type {any} */
    const out = array ? new Array(keys.length) : {};
    for (const key of keys) {
      if (typeof key !== "string") refuse();
      if (array && String(Number(key)) !== key) refuse();
      const descriptor = Object.getOwnPropertyDescriptor(node, key);
      if (!descriptor || !Object.hasOwn(descriptor, "value")) return refuse();
      if (!array && !descriptor.enumerable) refuse();
      // defineProperty keeps an own "__proto__" JSON member as data.
      Object.defineProperty(out, key, {
        value: copy(descriptor.value),
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
    ancestors.delete(node);
    return out;
  };
  return copy(value);
}

export class CompressingSealer {
  /** @type {Sealer} */
  #base;
  /** @type {import('../core-shared--client-publisher/gzipCodec.js').Gzip} */
  #gzip;
  /** @type {BufferedItem[]} */
  #items = [];
  #hasPeriodKeySupply;
  /** @type {readonly string[]} */
  #itemOptionMembers;
  /** @type {readonly (readonly string[])[]} */
  #supportedEncodingSequences;
  #flushed = false;
  /** @type {Promise<void>|null} */
  #flushPromise = null;

  /**
   * @param {any} config - base Sealer configuration
   * @param {{ gzip?: import('../core-shared--client-publisher/gzipCodec.js').Gzip, supportedEncodingSequences?: readonly (readonly string[])[] }} [options]
   */
  constructor(
    config,
    { gzip = webStreamsGzip, supportedEncodingSequences = [[], [ENCODING]] } = {},
  ) {
    this.#base = new Sealer(config);
    // Base has validated the config; a supply it holds is a usable object.
    this.#hasPeriodKeySupply = config.periodKeySupply != null;
    // Composition writes the item options its contributions read; base has
    // checked the list, and the adapter carries each one to base.
    this.#itemOptionMembers = Object.freeze([...(config.itemOptionMembers ?? [])]);
    if (typeof gzip?.encode !== "function") {
      throw dcaError("bad_config", "a gzip implementation compresses bytes with encode(bytes)");
    }
    this.#gzip = gzip;
    if (!Array.isArray(supportedEncodingSequences) || supportedEncodingSequences.length === 0) {
      throw dcaError(
        "bad_config",
        "supportedEncodingSequences is a nonempty list of encoding sequences",
      );
    }
    const sequences = [];
    for (const sequence of supportedEncodingSequences) {
      if (!Array.isArray(sequence)) {
        throw dcaError("bad_config", "each supported encoding sequence is a list");
      }
      const copy = [];
      for (const encoding of sequence) {
        if (typeof encoding !== "string" || encoding.length === 0) {
          throw dcaError("bad_config", "a supported encoding sequence contains nonempty names");
        }
        copy.push(encoding);
      }
      sequences.push(Object.freeze(copy));
    }
    this.#supportedEncodingSequences = Object.freeze(sequences);
  }

  /**
   * @param {string} resourceId
   * @param {object} data
   * @returns {this}
   */
  resource(resourceId, data) {
    this.#base.resource(resourceId, data);
    return this;
  }

  /**
   * Bare strings/bytes retain the extension's legacy call: this adapter
   * compresses them at seal() and appends `gzip` to the descriptor it builds.
   * An explicit base representation is already represented bytes, so this
   * adapter delegates it to base unchanged, appends no layer, and keeps its
   * contentType and ordered layers. Beside a descriptor this adapter takes
   * `accessGroups` and the declared contributed item options only, and
   * refuses both a fourth argument, as base refuses it, and a
   * `contentEncoding` option.
   *
   * Options also carry the per-item options a selected contribution declared
   * (`config.itemOptionMembers`); each one reaches base on every path. The
   * adapter refuses any other option with `unsupported_option`: base would
   * pass over it, and an item sealed without the route a misspelled option
   * named would fail no call.
   *
   * @param {string} name
   * @param {string|Uint8Array|{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} value
   * @param {string|{ accessGroups?: string[] } & Record<string, unknown>} [contentTypeOrOptions]
   * @param {{ accessGroups?: string[], contentEncoding?: string } & Record<string, unknown>} [legacyOptions]
   * @returns {this}
   */
  content(name, value, contentTypeOrOptions, legacyOptions) {
    if (this.#flushed || this.#flushPromise !== null) {
      throw dcaError("bad_config", "CompressingSealer accepts no content after sealing has begun");
    }
    validateContentName(name);
    if (this.#items.some((item) => item.name === name)) {
      throw dcaError("bad_config", `content "${name}" is already in this render`);
    }

    const descriptor = isContentRepresentation(value);
    if (descriptor && legacyOptions !== undefined) {
      throw dcaError(
        "bad_config",
        `content "${name}" uses descriptor options as its third argument`,
      );
    }
    const options = descriptor ? (contentTypeOrOptions ?? {}) : (legacyOptions ?? {});
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      throw dcaError("bad_config", `content "${name}" options are an object`);
    }

    // A descriptor's bytes and ordered list already state their layers, so
    // the caller names no encoding beside it and this adapter selects none.
    if (descriptor && Object.hasOwn(options, "contentEncoding")) {
      throw dcaError(
        "unsupported_option",
        `content "${name}" is a descriptor, and a descriptor states its own layers`,
      );
    }

    const contentEncoding = own(options, "contentEncoding") ?? ENCODING;
    if (contentEncoding !== IDENTITY && contentEncoding !== ENCODING) {
      throw dcaError(
        "unsupported_option",
        `this sealer writes ${JSON.stringify(ENCODING)} or ${JSON.stringify(IDENTITY)}` +
          `, not ${JSON.stringify(contentEncoding)}`,
      );
    }

    // Keep base's validation order: representation faults precede faults
    // in the access-group option beside that representation.
    const representation = normalizeContentRepresentation(
      value,
      descriptor ? undefined : contentTypeOrOptions,
    );

    // Groups are optional per item, as in base: an ungrouped item rides its
    // item-key route, which base checks at seal(). Without a supply, base
    // refuses a named group, because it could only drop the wraps; refuse it
    // here at content(), in base's order, before any codec work.
    const accessGroups = own(options, "accessGroups") ?? [];
    if (!Array.isArray(accessGroups)) {
      throw dcaError("bad_config", `content "${name}" accessGroups are a list`);
    }
    for (const accessGroup of accessGroups) validateAccessGroup(accessGroup);
    if (!this.#hasPeriodKeySupply && accessGroups.length) {
      throw dcaError(
        "bad_config",
        `content "${name}" names accessGroups, and this publisher holds no periodKeySupply to wrap under`,
      );
    }

    /** @type {Record<string, unknown>} */
    const declaredOptions = {};
    for (const member of this.#itemOptionMembers) {
      const value = own(options, member);
      if (value !== undefined) {
        declaredOptions[member] = plainJsonCopy(value, `content "${name}" option ${member}`);
      }
    }
    const known = ["accessGroups", "contentEncoding", ...this.#itemOptionMembers];
    for (const member of Reflect.ownKeys(options)) {
      if (typeof member !== "string" || !known.includes(member)) {
        throw dcaError(
          "unsupported_option",
          `content "${name}" has no option ${String(member)} that a selected contribution declared`,
        );
      }
    }

    const gzip = !descriptor && contentEncoding === ENCODING;
    const outputEncodings = gzip
      ? [...representation.contentEncodings, ENCODING]
      : representation.contentEncodings;
    if (
      !this.#supportedEncodingSequences.some(
        (sequence) =>
          sequence.length === outputEncodings.length &&
          sequence.every((encoding, index) => encoding === outputEncodings[index]),
      )
    ) {
      throw dcaError(
        "unsupported_encoding",
        `content "${name}" encoding sequence ${JSON.stringify(outputEncodings)} is not supported by this publisher`,
      );
    }

    this.#items.push({
      name,
      representation,
      accessGroups: [...accessGroups],
      options: declaredOptions,
      gzip,
    });
    return this;
  }

  /**
   * @returns {Promise<any>} base Sealer's render
   */
  async seal() {
    if (!this.#items.length || this.#flushed) return this.#base.seal();

    if (this.#flushPromise === null) this.#flushPromise = this.#flush();
    const flush = this.#flushPromise;
    try {
      await flush;
    } catch (cause) {
      // A codec failure changes neither the held base sealer nor this
      // adapter's item list, so a later call may retry it.
      if (this.#flushPromise === flush) this.#flushPromise = null;
      throw cause;
    }
    return this.#base.seal();
  }

  /** @returns {Promise<void>} */
  async #flush() {
    // Finish every asynchronous transform before changing the held base
    // sealer. A failed codec therefore leaves no partly queued render.
    const prepared = await Promise.all(
      this.#items.map(async (item) => {
        if (!item.gzip) return item.representation;
        let bytes;
        try {
          bytes = await this.#gzip.encode(item.representation.bytes.slice());
        } catch (cause) {
          if (cause instanceof DcaError) throw cause;
          throw dcaError("bad_encoding", `gzip encode failed for "${item.name}"`);
        }
        if (!(bytes instanceof Uint8Array)) {
          throw dcaError("bad_encoding", `gzip encode returned no bytes for "${item.name}"`);
        }
        // A supplied encoder may produce a valid gzip file with multiple
        // members. Check the exact single-member representation before sealing.
        const opened = gunzip(bytes);
        if (
          opened.length !== item.representation.bytes.length ||
          opened.some((value, index) => value !== item.representation.bytes[index])
        ) {
          throw dcaError("bad_encoding", `gzip encode changed the content of "${item.name}"`);
        }
        return {
          bytes,
          contentType: item.representation.contentType,
          contentEncodings: [...item.representation.contentEncodings, ENCODING],
        };
      }),
    );

    for (const [index, item] of this.#items.entries()) {
      this.#base.content(
        item.name,
        {
          ...prepared[index],
          contentEncodings: [...prepared[index].contentEncodings],
        },
        {
          ...item.options,
          accessGroups: item.accessGroups,
        },
      );
    }
    this.#flushed = true;
  }
}

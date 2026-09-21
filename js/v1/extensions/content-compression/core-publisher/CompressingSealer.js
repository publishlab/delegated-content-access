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

/**
 * @typedef {object} BufferedItem
 * @property {string} name
 * @property {Readonly<{ bytes: Uint8Array, contentType: string, contentEncodings: readonly string[] }>} representation
 * @property {string[]} accessGroups
 * @property {boolean} gzip
 */

export class CompressingSealer {
  /** @type {Sealer} */
  #base;
  /** @type {import('../core-shared--client-publisher/gzipCodec.js').Gzip} */
  #gzip;
  /** @type {BufferedItem[]} */
  #items = [];
  #needsAccessGroup;
  #flushed = false;
  /** @type {Promise<void>|null} */
  #flushPromise = null;

  /**
   * @param {any} config - base Sealer configuration
   * @param {{ gzip?: import('../core-shared--client-publisher/gzipCodec.js').Gzip }} [options]
   */
  constructor(config, { gzip = webStreamsGzip } = {}) {
    this.#base = new Sealer(config);
    this.#needsAccessGroup = config.periodKeySupply !== undefined;
    if (typeof gzip?.encode !== "function") {
      throw dcaError("bad_config", "a gzip implementation compresses bytes with encode(bytes)");
    }
    this.#gzip = gzip;
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
   * `accessGroups` only, and refuses both a fourth argument, as base refuses
   * it, and a `contentEncoding` option.
   *
   * @param {string} name
   * @param {string|Uint8Array|{ bytes: Uint8Array, contentType: string, contentEncodings: string[] }} value
   * @param {string|{ accessGroups?: string[] }} [contentTypeOrOptions]
   * @param {{ accessGroups?: string[], contentEncoding?: string }} [legacyOptions]
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

    const accessGroups = own(options, "accessGroups") ?? [];
    if (!Array.isArray(accessGroups)) {
      throw dcaError("bad_config", `content "${name}" accessGroups are a list`);
    }
    if (this.#needsAccessGroup && accessGroups.length === 0) {
      throw dcaError("bad_config", `content "${name}" needs at least one accessGroup`);
    }
    for (const accessGroup of accessGroups) validateAccessGroup(accessGroup);

    this.#items.push({
      name,
      representation,
      accessGroups: [...accessGroups],
      gzip: !descriptor && contentEncoding === ENCODING,
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
          bytes = await this.#gzip.encode(item.representation.bytes);
        } catch (cause) {
          if (cause instanceof DcaError) throw cause;
          throw dcaError("bad_encoding", `gzip encode failed for "${item.name}"`);
        }
        if (!(bytes instanceof Uint8Array)) {
          throw dcaError("bad_encoding", `gzip encode returned no bytes for "${item.name}"`);
        }
        return {
          bytes,
          contentType: item.representation.contentType,
          contentEncodings: [...item.representation.contentEncodings, ENCODING],
        };
      }),
    );

    for (const [index, item] of this.#items.entries()) {
      this.#base.content(item.name, prepared[index], { accessGroups: item.accessGroups });
    }
    this.#flushed = true;
  }
}

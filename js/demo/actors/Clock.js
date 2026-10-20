// @ts-check
//
// A render stamps `resource.issuedAt`, so something has to report the moment.
// Calling `new Date()` inside a sealer would put period rollover and expiry
// out of a test's reach, so the time comes in as an injected Clock instead.
//
// It reports the moment and nothing else. Period labels are computed from an
// injected `now` in `periodKeys`, which keeps that format in one place.

import { dcaError } from "../../core-shared/errors.js";

export class Clock {
  /** @type {number} milliseconds since the epoch */
  #at;

  /**
   * @param {string} isoString
   */
  constructor(isoString) {
    this.#at = Date.parse(isoString);
    if (Number.isNaN(this.#at)) {
      throw dcaError("bad_config", `Clock cannot read the instant "${isoString}"`);
    }
  }

  /**
   * A fresh Date each read, so a caller holding one cannot move the clock.
   *
   * @returns {Date}
   */
  now() {
    return new Date(this.#at);
  }

  /**
   * @param {number} milliseconds
   */
  advance(milliseconds) {
    if (!Number.isFinite(milliseconds)) {
      throw dcaError("bad_config", `Clock cannot advance by ${milliseconds}`);
    }
    this.#at += milliseconds;
  }

  /**
   * @param {string} isoString
   */
  set(isoString) {
    const at = Date.parse(isoString);
    if (Number.isNaN(at)) {
      throw dcaError("bad_config", `Clock cannot read the instant "${isoString}"`);
    }
    this.#at = at;
  }
}

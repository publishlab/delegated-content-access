// @ts-check
import { dcaError } from "../core-shared/errors.js";

/** A local reader generation. This fences effects; it does not revoke copied keys. */
export class ReaderContext {
  #revision = 0;
  /** @type {Promise<void>|null} */
  #clearing = null;
  /** @type {unknown} */
  #failure = null;
  #blocked = false;
  #failed = false;

  /** @returns {number} */
  capture() {
    this.check(this.#revision);
    return this.#revision;
  }

  /** @param {number} revision @returns {void} */
  check(revision) {
    if (revision !== this.#revision || this.#blocked)
      throw dcaError(
        "context_retired",
        "reader context retired, clearing or detached after cleanup failure",
      );
  }

  /** Check in the awaiting caller's continuation, immediately before effects.
   * @template T @param {T} result @param {number} revision @returns {T}
   */
  accept(result, revision) {
    this.check(revision);
    return result;
  }

  /** Cleanup is invoked synchronously, after retiring the old generation.
   * Failure is terminal for this owner; retries cannot claim durable success.
   * @param {() => Promise<void>|void} cleanup @returns {Promise<void>}
   */
  clear(cleanup) {
    if (this.#clearing) return this.#clearing;
    if (this.#failed) return Promise.reject(this.#failure);
    this.#revision++;
    this.#blocked = true;
    let pending;
    try {
      pending = cleanup();
    } catch (error) {
      pending = Promise.reject(error);
    }
    this.#clearing = Promise.resolve(pending).then(
      () => {
        this.#blocked = false;
        this.#clearing = null;
      },
      (error) => {
        this.#failure = error;
        this.#failed = true;
        this.#clearing = null;
        throw error;
      },
    );
    return this.#clearing;
  }
}

// @ts-check

// A fallback serves a request only after its own probe finds the primary down.
// The probe travels through the same Network as browser traffic and uses the
// owning server as its caller, preserving per-caller reachability.
//
// Health is cached because a fallback under load should not probe a struggling
// primary for every request. Its age starts when the probe answer arrives
// rather than when the probe was sent. On a known transport failure the gate
// records the primary as down; it rethrows any other exception, which signals
// a fault in this deployment.

import { isTransportFailureCode } from "../../../core-shared/errors.js";

const DEFAULT_HEALTH_TTL = 30_000;
const DEFAULT_PROBE_TIMEOUT = 2_000;

export class FailoverGate {
  #clock;
  #network;
  #healthCheckUrl;
  #healthTtl;
  #probeTimeout;
  #caller;

  /** @type {{ at: number, up: boolean }|null} */
  #health = null;

  #probes = 0;
  #healthReads = 0;

  /**
   * @param {object} config
   * @param {{ now: () => Date }} config.clock
   * @param {{ probe: Function }} config.network
   * @param {string} config.healthCheckUrl
   * @param {number} [config.healthTtl]
   * @param {number} [config.probeTimeout]
   * @param {any} config.caller - the owning server, for per-caller reachability
   */
  constructor({ clock, network, healthCheckUrl, healthTtl, probeTimeout, caller }) {
    this.#clock = clock;
    this.#network = network;
    this.#healthCheckUrl = healthCheckUrl;
    this.#healthTtl = healthTtl ?? DEFAULT_HEALTH_TTL;
    this.#probeTimeout = probeTimeout ?? DEFAULT_PROBE_TIMEOUT;
    this.#caller = caller;
  }

  /**
   * Whether this fallback may serve now.
   *
   * @returns {Promise<boolean>}
   */
  async allows() {
    const asked = this.#clock.now().getTime();
    if (this.#health && asked - this.#health.at < this.#healthTtl) {
      this.#healthReads++;
      return !this.#health.up;
    }

    let up;
    try {
      this.#probes++;
      const answer = await this.#network.probe(this.#healthCheckUrl, {
        from: this.#caller,
        timeout: this.#probeTimeout,
      });
      up = answer.status === 200 && answer.body?.healthy === true;
    } catch (cause) {
      if (!isTransportFailureCode(/** @type {any} */ (cause)?.code)) throw cause;
      up = false;
    }

    this.#health = { at: this.#clock.now().getTime(), up };
    return !up;
  }

  /** @returns {{ probes: number, healthReads: number }} */
  stats() {
    return { probes: this.#probes, healthReads: this.#healthReads };
  }
}

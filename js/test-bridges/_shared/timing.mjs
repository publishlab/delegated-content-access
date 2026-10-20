import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// A test may replace performance.now; timing keeps the clock it loaded with.
const now = performance.now.bind(performance);

export class TimingWriter {
  /** @param {string | undefined} path @param {boolean} [enabled] */
  constructor(path, enabled = path !== undefined) {
    this.path = path;
    this.enabled = enabled;
    this.started = enabled ? now() : 0;
    this.calls = 0;
    this.maximumCallMs = 0;
  }

  /** The start of a call to time, or 0 when timing is off. */
  now() {
    return this.enabled ? now() : 0;
  }

  /** @param {number} elapsed */
  call(elapsed) {
    if (!this.enabled) return;
    this.calls += 1;
    this.maximumCallMs = Math.max(this.maximumCallMs, elapsed);
  }

  finish(detail = {}) {
    if (!this.enabled) return;
    const record = {
      calls: this.calls,
      maximumCallMs: this.maximumCallMs,
      totalMs: now() - this.started,
      ...detail,
    };
    if (this.path) {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(this.path, `${JSON.stringify(record)}\n`);
    } else {
      process.stderr.write(`dca bridge timing: ${JSON.stringify(record)}\n`);
    }
  }
}

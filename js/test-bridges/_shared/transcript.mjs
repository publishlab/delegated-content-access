import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// A test may replace the global Date, for example with a trap that fails on
// any use of ambient time. The transcript keeps the clock it loaded with.
const IntrinsicDate = Date;

export class TranscriptWriter {
  /** @param {string | undefined} path */
  constructor(path) {
    this.path = path;
    if (path) mkdirSync(dirname(path), { recursive: true });
  }

  /** @param {string} event @param {Record<string, unknown>} detail */
  write(event, detail) {
    if (!this.path) return;
    appendFileSync(
      this.path,
      `${JSON.stringify({ event, at: new IntrinsicDate().toISOString(), ...detail })}\n`,
    );
  }
}

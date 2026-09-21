// @ts-check

// The one house rule of `pnpm test`, written as a `node --test` reporter. Node runs a reporter
// in the process it was launched as, so node exits with the code this module sets.
// Node reports a failing TODO as a successful run. A developer reading exit 0 would take a run
// that carried a TODO, or a run that matched no file at all, for full proof, so both exit 2.
// A failure keeps node's own exit 1: exit 2 says the run proved less than intended, not that
// something disagreed.
//
// Node sends one `test:summary` per file and one for the run, and the per-file ones only under
// `--experimental-test-isolation=process`. Under `none` the slowest-file list stays empty and
// this module reads the run summary alone.

/** @typedef {{ tests: number, passed: number, failed: number, cancelled: number, skipped: number, todo: number }} Counts */

const SLOWEST_LISTED = 10;

/**
 * @param {AsyncIterable<{ type: string, data: any }>} source
 */
export default async function* testVerdictReporter(source) {
  /** @type {{ file: string, milliseconds: number }[]} */
  const files = [];

  for await (const event of source) {
    if (event.type !== "test:summary") continue;
    if (event.data.file) {
      files.push({ file: event.data.file, milliseconds: event.data.duration_ms });
      continue;
    }

    const counts = /** @type {Counts} */ (event.data.counts);
    yield `${counts.tests} tests, ${counts.passed} passed, ${counts.failed} failed, ` +
      `${counts.skipped} skipped, ${counts.todo} todo\n`;

    if (files.length > 0) {
      yield "SLOWEST FILES\n";
      const slowest = [...files]
        .sort((one, other) => other.milliseconds - one.milliseconds)
        .slice(0, SLOWEST_LISTED);
      for (const one of slowest) {
        yield `  ${Math.round(one.milliseconds)} ms  ${one.file}\n`;
      }
    }

    const nothingDisagreed = counts.failed === 0 && counts.cancelled === 0;
    if (nothingDisagreed && (counts.todo > 0 || counts.tests === 0)) process.exitCode = 2;
  }
}

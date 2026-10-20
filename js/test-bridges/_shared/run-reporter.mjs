// @ts-check

// The case counts of a named selection, written as a `node --test` reporter.
// Node runs a reporter in the parent process, so under process isolation it
// receives every file's test events. `run.mjs` names a file as this reporter's
// destination and reads the report after Node exits.
//
// Each file's cases are counted from their `test:pass` and `test:fail`
// events, by the rule Node's own summary uses: a suite is not a case, a
// skipped case counts as skipped and a TODO case as TODO whether it passed or
// failed, and a case cancelled by its parent or by a timeout counts as
// cancelled. A test file whose process ends early reports itself as one failed
// case. Node's run summary goes into the report beside the counts, so the
// runner can refuse counts that disagree with it.
//
// The report is written only once Node's run summary has arrived. A run that
// ends before it leaves the destination empty, and the runner refuses it.

import { relative } from "node:path";

/** @typedef {{ tests: number, passed: number, failed: number, cancelled: number, skipped: number, todo: number }} CaseCounts */

/** The count names, in the order the report and the runner list them. */
export const CASE_COUNT_NAMES = Object.freeze(
  /** @type {const} */ (["tests", "passed", "failed", "cancelled", "skipped", "todo"]),
);

const CANCELLED = new Set(["cancelledByParent", "testTimeoutFailure"]);

/** @returns {CaseCounts} */
function zero() {
  return { tests: 0, passed: 0, failed: 0, cancelled: 0, skipped: 0, todo: 0 };
}

/** @param {{ type: string, data: any }} event @returns {keyof CaseCounts} */
function outcome({ type, data }) {
  if (data.skip) return "skipped";
  if (data.todo) return "todo";
  if (type === "test:fail")
    return CANCELLED.has(data.details?.error?.failureType) ? "cancelled" : "failed";
  return "passed";
}

/** @param {AsyncIterable<{ type: string, data: any }>} source */
export default async function* runReporter(source) {
  /** @type {Map<string, CaseCounts>} */
  const files = new Map();
  /** @type {CaseCounts | undefined} */
  let node;
  for await (const event of source) {
    if (event.type === "test:summary") {
      if (event.data.file === undefined)
        node = /** @type {CaseCounts} */ (
          Object.fromEntries(CASE_COUNT_NAMES.map((name) => [name, event.data.counts[name]]))
        );
      continue;
    }
    if (event.type !== "test:pass" && event.type !== "test:fail") continue;
    if (event.data.details?.type === "suite") continue;
    const file =
      typeof event.data.file === "string" ? relative(process.cwd(), event.data.file) : "";
    const counts = files.get(file) ?? zero();
    files.set(file, counts);
    counts.tests += 1;
    counts[outcome(event)] += 1;
  }
  if (node === undefined) return;
  const sorted = [...files].sort(([one], [other]) => (one < other ? -1 : one > other ? 1 : 0));
  yield `${JSON.stringify({ version: 1, files: Object.fromEntries(sorted), node })}\n`;
}

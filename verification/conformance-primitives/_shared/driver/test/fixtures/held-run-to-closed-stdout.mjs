// This script makes one held run through the runner's own default output writers.
//
// The test that starts this closes the read end of its stdout first, which is what
// `run.sh php | head -1` does the moment head has its line. Nothing is passed for
// `out` and `err`, so the writers under test are the ones an operator gets.
//
// It takes the corpus path and the fake bridge's settings as arguments, and exits
// with the runner's exit code.

import { runConformance } from '../../run.mjs';
import { OPERATIONS } from '../../validate-results.mjs';

const [corpusPath, fakeBridge, settings] = process.argv.slice(2);

process.exitCode = await runConformance({
    argv: ['php'],
    corpusPath,
    timeoutMs: 5000,
    bridges: {
        php: { script: fakeBridge, command: process.execPath, operations: OPERATIONS, args: [fakeBridge, settings] },
    },
});

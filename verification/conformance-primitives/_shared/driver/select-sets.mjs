#!/usr/bin/env node
// Which corpus sets one lane can be asked, printed for the shell that walks them.
//
//     node conformance-primitives/_shared/driver/select-sets.mjs <lane>
//
// One line per set, in corpus order: the set name, then `supported` or
// `unsupported`. A lane declares the operations its bridge answers in its own
// `bridge.json`, and a set asking for an operation the lane has not declared is
// unsupported for that lane. `_shared/driver-steps.sh` reads these lines, runs the
// supported sets through `run.mjs --set` and writes an explicit row for each
// unsupported one, so a lane answering some of the seven operations reports what it
// answered and what it was never asked, and neither reads as the other.
//
// The applicability rule lives here rather than in the shell because
// the driver already reads both the corpus and the manifest. The shell starts processes and
// folds their exit codes.
//
// Exit 0 with the lines on stdout, or exit 2 with a reason on stderr: an unknown
// lane, an unreadable manifest and an unreadable corpus all leave a caller with
// nothing to walk.

import { CorpusError, loadCases, corpusSets } from './cases.mjs';
import { CONFORMANCE_DIR, loadBridges } from './run.mjs';

const lane = process.argv[2];
if (lane === undefined || lane === '') {
    process.stderr.write('usage: node conformance-primitives/_shared/driver/select-sets.mjs <lane>\n');
    process.exit(2);
}

let bridges;
try {
    bridges = loadBridges(CONFORMANCE_DIR);
} catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(2);
}

const entry = bridges[lane];
if (!entry) {
    process.stderr.write(`no bridge is named ${JSON.stringify(lane)}. This driver knows ${Object.keys(bridges).join(', ')}.\n`);
    process.exit(2);
}

let sets;
try {
    sets = corpusSets(loadCases());
} catch (error) {
    if (error instanceof CorpusError) {
        for (const problem of error.problems) process.stderr.write(`${problem}\n`);
        process.exit(2);
    }
    throw error;
}

for (const { set, operations } of sets) {
    const supported = operations.every((operation) => entry.operations.includes(operation));
    process.stdout.write(`${set} ${supported ? 'supported' : 'unsupported'}\n`);
}

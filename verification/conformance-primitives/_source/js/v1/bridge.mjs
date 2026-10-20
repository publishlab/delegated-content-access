#!/usr/bin/env node
// The stdin entry of the shared JavaScript bridge: one batch in on fd 0, one
// answer out on stdout, an exit code. Node, Deno and Bun run this file.
//
// It reads the whole of stdin as text, hands it to `answerLine` in
// `answer.mjs`, writes the line that returns on stdout with a newline and
// exits 0. Everything about the operations, the refusals, the closed shapes and
// the bytes of both output lines lives in `answer.mjs`; this file only moves
// bytes and sets the exit code. Diagnostics go to stderr; nothing reads a result
// out of stderr, so a bridge may say whatever it likes there.
//
// A batch `answerLine` cannot serve throws, and this entry then writes the line
// `faultLine` builds on stderr, nothing on stdout, and exits 1. The runner reads
// that as a run nobody could complete.
//
// The answering code sits in its own module because a runtime without a process
// cannot run this one: inside a workerd isolate fd 0 reads empty and
// `process.exitCode` ends nothing, so workerd runs `answer.mjs` from an entry of
// its own.
//
// Each JavaScript lane's `bridge` wrapper starts this file under that lane's pinned
// runtime. By hand, from `verification/`, it is the same:
//   printf '%s\n' '<batch json>' | node conformance-primitives/_source/js/v1/bridge.mjs

import { readFileSync } from 'node:fs';

import { answerLine, faultLine } from './answer.mjs';

process.exitCode = await main();

async function main() {
    let raw;
    try {
        raw = readFileSync(0, 'utf8');
    } catch (error) {
        process.stderr.write(`bridge: stdin could not be read: ${error.message}\n`);
        return 1;
    }

    let line;
    try {
        line = await answerLine(raw);
    } catch (error) {
        process.stderr.write(`${faultLine(error)}\n`);
        return 1;
    }

    process.stdout.write(`${line}\n`);
    return 0;
}

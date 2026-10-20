// The workerd entry of the shared JavaScript bridge: one batch in as a text
// module, one answer out through `console.log`, and a thrown error for a batch
// this bridge cannot serve.
//
// A workerd isolate has no host stdin and no exit code of its own: fd 0 reads
// empty inside it, and `process.exitCode` ends nothing. So `bridge` beside this
// file writes stdin to `batch.txt`, `config.capnp` embeds that file as the text
// module imported below, and `workerd test` runs the `test()` handler once and
// exits 0 when it returns and nonzero when it throws.
//
// `console.log` is the one writer whose output reaches workerd's stdout
// unprefixed in test mode; `process.stdout.write` gets a `stdout: ` prefix
// there. `console.error` goes to stderr. The answer is one `console.log` call,
// which adds the newline, so it arrives as one line, the same bytes
// `../../_source/js/v1/bridge.mjs` writes on Node.
//
// Everything about the operations and the bytes of both output lines lives in
// `answer.mjs`, the shared answer source, which `bridge` stages beside this file.

import batch from 'batch.txt';

import { answerLine, faultLine } from './answer.mjs';

export default {
    async test() {
        let line;
        try {
            line = await answerLine(batch);
        } catch (error) {
            // The rethrow makes `workerd test` exit nonzero, and nothing has
            // reached stdout.
            console.error(faultLine(error));
            throw error;
        }
        console.log(line);
    },
};

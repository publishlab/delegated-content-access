// The transport a bridge answers over, and nothing about what it answers.
//
// One batch of questions in, one JSON value out. `askBatch` writes a single
// `dca-operation-bridge-v1` line carrying `{id, op, input}` per request, closes
// stdin, and reads exactly one JSON value carrying `results` off stdout. Stderr is
// diagnostic: a bridge may write anything there, and a run may print it, but
// nothing here reads a result out of it.
//
// The driver builds first and asks later. `prepareBridge` runs whatever a language
// needs done before it can be asked anything, under its own generous allowance, and
// `askBatch` times one already-runnable program answering one batch. A bridge compiled
// inside the request would be measured on its compiler.
//
// This file never reads inside an observation. It carries no `held` verdict and no
// expected-value field. It checks that the envelope is the one that was asked for and
// hands the results on unread, and `validate-results.mjs` reads them.
//
// This file reports every transport failure as `incomplete`. A bridge that exits
// nonzero, dies on a signal, runs past its time, prints nothing, prints something
// that is not JSON, or prints two values has not disagreed about anything: it never
// reached an answer. Calling any of those a disagreement would report a conformance
// finding the run never made.

import { spawn } from 'node:child_process';

export const INCOMPLETE = 'incomplete';
export const RESPONSE = 'response';
export const READY = 'ready';
export const RESPONSE_LIMIT_BYTES = 256 * 1024;

// The batch envelope both sides write on the wire. One string, named once, so a
// bridge answering an older or a mistyped protocol is told what it answered.
export const BATCH_PROTOCOL = 'dca-operation-bridge-v1';

// One JSON value out of a bridge's stdout, or the reason it is not one.
//
// This file keeps malformed bytes and two well-formed values apart: the first is a
// bridge that cannot write the protocol, the second is a bridge that answered a
// question it was not asked, and an operator reading the failure needs to know
// which.
export function parseSingleJson(text, who = 'bridge') {
    const trimmed = text.trim();
    if (trimmed === '') {
        return { ok: false, reason: 'no-stdout', detail: `the ${who} wrote nothing to stdout.` };
    }

    let parsed;
    try {
        parsed = parseNoDuplicateJson(trimmed);
    } catch (error) {
        if (error instanceof DuplicateMemberError) {
            return { ok: false, reason: 'duplicate-member', detail: `stdout ${error.message}` };
        }
        return { ok: false, reason: 'malformed-json', detail: 'stdout does not parse as JSON.' };
    }

    const rest = trimmed.slice(parsed.end).trim();
    if (rest !== '') {
        try {
            parseNoDuplicateJson(rest);
            return {
                ok: false,
                reason: 'multiple-responses',
                detail: 'stdout carries more than one JSON value, and one question is answered once.',
            };
        } catch (error) {
            if (error instanceof DuplicateMemberError) {
                return { ok: false, reason: 'duplicate-member', detail: `stdout ${error.message}` };
            }
            return {
                ok: false,
                reason: 'malformed-json',
                detail: 'stdout carries a JSON value followed by bytes that are not one.',
            };
        }
    }

    return { ok: true, value: parsed.value };
}

// The request one bridge is handed for a whole batch. One JSON line again, and only
// `{id, op, input}` per request: `expected`, `class` and any verdict field stay on
// this side of the process boundary, because a bridge that can read the answer is not
// being tested.
export function batchRequestFor(requests) {
    const carried = requests.map(({ id, op, input }) => ({ id, op, input }));
    return `${JSON.stringify({ protocol: BATCH_PROTOCOL, requests: carried })}\n`;
}

// One batch of questions to one bridge process.
//
// Returns `{outcome, ...}` and never rejects for anything the bridge did: this harness
// reports a bridge failure as data rather than raising an exception. `outcome` is
// `response` with `results` straight off the wire, or `incomplete` with a reason
// out of the list above and a sentence saying what happened. The results themselves
// are handed on unread: this file checks the envelope, and `validate-results.mjs`
// reads the answers.
export async function askBatch({ command, args = [], requests, timeoutMs = 10000, cwd }) {
    const answered = await converse({
        command,
        args,
        cwd,
        timeoutMs,
        requestLine: batchRequestFor(requests),
        who: 'bridge',
    });
    if (answered.outcome === INCOMPLETE) return answered;

    const { value, stderr, stdout } = answered;
    const incomplete = (reason, detail) => ({ outcome: INCOMPLETE, reason, detail, stderr, stdout });

    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return incomplete('malformed-json', 'the response is not a JSON object carrying results.');
    }
    if (value.protocol !== BATCH_PROTOCOL) {
        return incomplete(
            'protocol-mismatch',
            `the response names protocol ${JSON.stringify(value.protocol ?? null)}, and the request was ${JSON.stringify(BATCH_PROTOCOL)}.`,
        );
    }
    if (!Array.isArray(value.results)) {
        return incomplete('response-shape', 'the response carries no results array.');
    }

    // The envelope is closed as well as the results inside it. A member nobody
    // named is a bridge writing a protocol outside the contract.
    const unknown = Object.keys(value).filter((name) => name !== 'protocol' && name !== 'results');
    if (unknown.length > 0) {
        return incomplete('response-shape', `the response carries ${unknown.join(', ')}, and the envelope carries protocol and results only.`);
    }

    return { outcome: RESPONSE, results: value.results, stderr, stdout };
}

// `prepareBridge` runs whatever a language has to do before its bridge can be asked
// anything, to completion and outside the request's time.
//
// A compiled or JIT runtime builds, restores packages or warms up before it answers,
// and a batch launched through a build command spends the request budget on that
// build. So the build is a separate command with a separate and generous allowance,
// and what the batch measures is one already-runnable program answering questions.
//
// Returns `{outcome}`: `ready` when the command exited 0, `incomplete` with a reason,
// a sentence and the command's own stderr when it did anything else. A build that
// fails is a run that could not be completed, never a disagreement, because nothing
// was asked yet.
export async function prepareBridge({ command, args = [], cwd, timeoutMs = 300000 }) {
    const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });

    let timedOut = false;
    const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
    }, timeoutMs);

    const ended = await new Promise((resolve) => {
        child.on('error', (error) => resolve({ spawnError: error }));
        child.on('close', (code, signal) => resolve({ code, signal }));
    });
    clearTimeout(timer);

    const incomplete = (reason, detail) => ({ outcome: INCOMPLETE, reason, detail, stderr: `${stdout}${stderr}` });

    if (ended.spawnError) return incomplete('prepare-failed', `the preparation step could not be started: ${ended.spawnError.message}`);
    if (timedOut) return incomplete('prepare-timeout', `the preparation step did not finish within ${timeoutMs}ms.`);
    if (ended.signal) return incomplete('prepare-failed', `the preparation step died on ${ended.signal}.`);
    if (ended.code !== 0) return incomplete('prepare-failed', `the preparation step exited ${ended.code}.`);

    return { outcome: READY, stderr: `${stdout}${stderr}` };
}

// The one place a question is put to a child process, written, waited on and read.
//
// It answers `incomplete` for everything the child did, or the one JSON value it
// wrote.
async function converse({ command, args = [], cwd, timeoutMs, requestLine, who }) {
    const child = spawn(command, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'] });

    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    let oversized = false;
    child.stdout.on('data', (chunk) => {
        stdout += chunk;
        if (Buffer.byteLength(stdout, 'utf8') > RESPONSE_LIMIT_BYTES) {
            oversized = true;
            child.kill('SIGKILL');
        }
    });
    child.stderr.on('data', (chunk) => { stderr += chunk; });

    // A bridge that has stopped reading its stdin is a fault this harness reports
    // rather than one that crashes it, so the broken pipe is swallowed and the
    // outcome is read off what the process did.
    child.stdin.on('error', () => {});
    child.stdin.end(requestLine);

    let timedOut = false;
    const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
    }, timeoutMs);

    const ended = await new Promise((resolve) => {
        child.on('error', (error) => resolve({ spawnError: error }));
        child.on('close', (code, signal) => resolve({ code, signal }));
    });
    clearTimeout(timer);

    const incomplete = (reason, detail) => ({ outcome: INCOMPLETE, reason, detail, stderr, stdout });

    if (ended.spawnError) {
        return incomplete('spawn-failed', `the ${who} could not be started: ${ended.spawnError.message}`);
    }
    if (timedOut) {
        return incomplete('timeout', `the ${who} did not answer within ${timeoutMs}ms.`);
    }
    if (oversized) {
        return incomplete('response-too-large', `the ${who} wrote more than the ${RESPONSE_LIMIT_BYTES}-byte response limit.`);
    }
    if (ended.signal) {
        return incomplete('signal', `the ${who} died on ${ended.signal} before it answered.`);
    }
    if (ended.code !== 0) {
        return incomplete('exit-status', `the ${who} exited ${ended.code} before it answered.`);
    }

    const parsed = parseSingleJson(stdout, who);
    if (!parsed.ok) {
        return incomplete(parsed.reason, parsed.detail);
    }

    return { outcome: RESPONSE, value: parsed.value, stderr, stdout };
}

export class DuplicateMemberError extends Error {}

// A small JSON reader exists here only because JSON.parse drops duplicate object
// members by specification. A duplicate has to be caught while the text is still
// text, before an object is built; all actual values still come from JSON.parse over
// each complete token.
//
// It reads two documents, and only two: a bridge's answer, where the sender is the
// subject under test, and the case corpus in `cases.mjs`, where a repeated member
// would silently leave half the file out of a run. A bridge is never asked to make
// this reading of the batch it receives, because Node writes those bytes and never
// repeats a member, and asking for it would mean one hand-written parser per
// language.
export function parseNoDuplicateJson(text) {
    let index = 0;
    const space = () => { while (/\s/.test(text[index] ?? '')) index += 1; };
    const string = () => {
        const start = index;
        if (text[index] !== '"') throw new Error('string');
        index += 1;
        while (index < text.length) {
            if (text[index] === '\\') { index += 2; continue; }
            if (text[index] === '"') { index += 1; return JSON.parse(text.slice(start, index)); }
            index += 1;
        }
        throw new Error('unterminated string');
    };
    const value = () => {
        space();
        if (text[index] === '{') {
            index += 1; space();
            const object = {};
            const keys = new Set();
            if (text[index] === '}') { index += 1; return object; }
            while (true) {
                space(); const key = string(); space();
                if (keys.has(key)) throw new DuplicateMemberError(`repeats JSON member ${JSON.stringify(key)}.`);
                keys.add(key);
                if (text[index] !== ':') throw new Error('colon');
                index += 1;
                Object.defineProperty(object, key, {
                    value: value(), enumerable: true, writable: true, configurable: true,
                });
                space();
                if (text[index] === '}') { index += 1; return object; }
                if (text[index] !== ',') throw new Error('comma');
                index += 1;
            }
        }
        if (text[index] === '[') {
            index += 1; space(); const array = [];
            if (text[index] === ']') { index += 1; return array; }
            while (true) {
                array.push(value()); space();
                if (text[index] === ']') { index += 1; return array; }
                if (text[index] !== ',') throw new Error('comma');
                index += 1;
            }
        }
        if (text[index] === '"') return string();
        const start = index;
        while (index < text.length && !/[\s,\]\}]/.test(text[index])) index += 1;
        return JSON.parse(text.slice(start, index));
    };
    const result = value();
    return { value: result, end: index };
}

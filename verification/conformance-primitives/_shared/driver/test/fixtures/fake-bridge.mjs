// A fake bridge that answers from the map the test hands it, and fails as the test tells it to.
//
// The harness has to be provable before any real toolchain is installed, and a real
// bridge fails only now and then. This one is handed a JSON configuration as its
// single argument and fails on demand: the wrong answer, a missing one, a duplicate,
// an unasked-for one, the wrong operation, a member nobody named, a broken envelope,
// bytes that are not JSON, more bytes than the cap, a nonzero exit, a signal, and
// silence for as long as the test waits.
//
// This file knows nothing about what any case expects. The test writes the `answers`
// map out of the fixture corpus, so nothing on this side of the process boundary can
// look up an expected value, exactly as a real bridge cannot. It records the request
// it was handed, so a test can prove that `expected`, the label and every verdict
// field stayed on the harness side.
//
// Configuration, all optional:
//   launchLog        a file one line is appended to per launch, so launches are counted
//   requestLog       a file the raw request line is written to
//   stderr           text written to stderr before anything else
//   stderrLines      that many further stderr lines, for a bridge that floods a terminal
//   answers          {id: observation} the correct-looking answer per case id
//   guess            true to answer from the identifier and the operation name alone
//   replaceObservation {id: observation} answer this id with that instead
//   retagOp          {id: op} answer this id under another operation
//   addField         {id: {name: value}} add members the contract does not name
//   drop             [id] leave these unanswered
//   duplicate        [id] answer these twice
//   extra            [{id, op, observation}] answer questions nobody asked
//   reverse          true to write the results back to front
//   protocol         an envelope protocol string other than the agreed one
//   envelopeExtra    {name: value} extra top-level members
//   output           'malformed' | 'oversized' | 'silent' | 'two', written instead of results
//   exitCode         exit with this status after writing
//   signal           true to die on SIGKILL without answering
//   hang             true to never answer at all

import { appendFileSync, writeFileSync, writeSync } from 'node:fs';

const config = JSON.parse(process.argv[2] ?? '{}');

if (config.launchLog) appendFileSync(config.launchLog, `launch ${process.pid}\n`);
// Written straight to the descriptor, because a bridge that dies on a signal a
// moment later has still written this, and a buffered write would be lost with it.
if (config.stderr) writeSync(2, `${config.stderr}\n`);
for (let line = 0; line < (config.stderrLines ?? 0); line += 1) {
    writeSync(2, `flood line ${line}: ${'x'.repeat(200)}\n`);
}
if (config.signal) process.kill(process.pid, 'SIGKILL');
if (config.hang) setInterval(() => {}, 1000);

if (!config.signal && !config.hang) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const line = Buffer.concat(chunks).toString('utf8');
    if (config.requestLog) writeFileSync(config.requestLog, line);

    process.stdout.write(answer(line));
    // The status is set rather than exited on, so stdout is flushed on the way out
    // and a nonzero exit after a good answer stays a nonzero exit after a good
    // answer.
    if (config.exitCode !== undefined) process.exitCode = config.exitCode;
}

function answer(line) {
    if (config.output === 'silent') return '';
    if (config.output === 'malformed') return 'OK: the bridge held\n';
    if (config.output === 'oversized') return 'x'.repeat(256 * 1024 + 1);

    const request = JSON.parse(line);
    if (config.guess) return guessed(request);

    const answers = config.answers ?? {};
    const replace = config.replaceObservation ?? {};
    const retag = config.retagOp ?? {};
    const added = config.addField ?? {};
    const drop = config.drop ?? [];
    const duplicate = config.duplicate ?? [];

    let results = request.requests
        .filter((one) => !drop.includes(one.id))
        .map((one) => {
            const observation = Object.hasOwn(replace, one.id) ? replace[one.id] : answers[one.id];
            const result = { id: one.id, op: Object.hasOwn(retag, one.id) ? retag[one.id] : one.op, observation };
            return Object.hasOwn(added, one.id) ? { ...result, ...added[one.id] } : result;
        });

    for (const id of duplicate) {
        const found = results.find((one) => one.id === id);
        if (found) results.push({ ...found });
    }
    for (const one of config.extra ?? []) results.push(one);
    if (config.reverse) results = results.slice().reverse();

    const envelope = {
        protocol: config.protocol ?? 'dca-operation-bridge-v1',
        results,
        ...(config.envelopeExtra ?? {}),
    };
    const text = JSON.stringify(envelope);
    return config.output === 'two' ? `${text}\n${text}\n` : text;
}

// `guessed` never looks at `input`, and answers each request out of its identifier and
// the operation name. The contract is public, so the two well-formed shapes per
// operation are written out below; the identifier is all it has to pick between them.
//
// This probe holds against a corpus whose identifiers encode how their cases come out.
// Against opaque identifiers it can only guess, and a guess inside the contract is a
// disagreement at every case it guessed on.
function guessed(request) {
    const REFUSAL = {
        'decode-base64url': 'invalid_base64url',
        'open-aes-gcm': 'authentication_failed',
        'open-rsa-oaep': 'unseal_failed',
    };
    const SUCCESS = {
        'decode-base64url': { bytesHex: '00' },
        'hkdf-sha256': { okmBase64url: 'Z3Vlc3M' },
        'open-aes-gcm': { plaintextBase64url: 'Z3Vlc3M' },
        'seal-aes-gcm': { ciphertextBase64url: 'Z3Vlc3M' },
        'ecdh-p256': { sharedSecretBase64url: 'Z3Vlc3M' },
        'p256-point': { pointBase64url: 'Z3Vlc3M' },
        'open-rsa-oaep': { plaintextBase64url: 'Z3Vlc3M' },
    };

    const results = request.requests.map(({ id, op }) => {
        const readable = id.toLowerCase();
        const soundsRefused = /refus|invalid|malform|reject|fail|wrong|bad|empty|duplicate|noncanonical|padding|delimiter/.test(readable);
        const refusal = REFUSAL[op];
        return { id, op, observation: soundsRefused && refusal ? { refused: refusal } : SUCCESS[op] };
    });

    return JSON.stringify({ protocol: 'dca-operation-bridge-v1', results });
}

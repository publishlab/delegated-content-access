// The operation-bridge harness, driven end to end with a bridge that fails on
// demand.
//
// Every run below goes through `runConformance`, so these tests exercise the runner an
// operator invokes rather than a rehearsal of its parts. The bridge is
// `fixtures/fake-bridge.mjs`, configured per run, and the corpus is a fixture corpus
// under `fixtures/`: the real corpus is a separate piece of work, and a harness
// proven against the file it is meant to check would have to be proven again the
// day that file changes.
//
// These tests still read the real corpus, for three claims about it: which cases it
// holds, that no identifier reaching a bridge says how its case comes out, and that a
// bridge answering from the identifier and the operation name disagrees. Each is a
// claim about every case in the shipped file, so each is asserted over the whole file
// rather than over a fixture standing in for it.
//
// Every test asserts two things, whether or not they are its subject: how many bridge
// processes a run started, because exactly one per run is the whole debuggability
// claim, and what the request carried, because an expectation that reaches a bridge is
// an oracle a bridge can read back.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
    accessSync, chmodSync, constants, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    CorpusError, DEFAULT_CORPUS_PATH, SelectionError, corpusSets, loadCases, parseSelectors, selectCases,
} from '../cases.mjs';
import { loadBridges, runConformance } from '../run.mjs';
import { OPERATIONS } from '../validate-results.mjs';

const FAKE_BRIDGE = fileURLToPath(new URL('./fixtures/fake-bridge.mjs', import.meta.url));
const CLOSED_STDOUT_RUN = fileURLToPath(new URL('./fixtures/held-run-to-closed-stdout.mjs', import.meta.url));
const TWO_SETS = fileURLToPath(new URL('./fixtures/corpus-two-sets.json', import.meta.url));
const ONE_OP = fileURLToPath(new URL('./fixtures/corpus-one-op.json', import.meta.url));
const NON_ASCII = fileURLToPath(new URL('./fixtures/corpus-non-ascii.json', import.meta.url));
const PHP_BRIDGE = fileURLToPath(new URL('../../../php/v1/bridge.php', import.meta.url));

const scratch = mkdtempSync(join(tmpdir(), 'dca-operation-bridge-'));
after(() => rmSync(scratch, { recursive: true, force: true }));

const corpus = loadCases(TWO_SETS);
const ALL_IDS = corpus.map((one) => one.id);

// What a bridge that computes everything correctly would answer. The test builds it
// out of the corpus and hands it over as configuration, so the fake bridge still
// knows nothing it was not told.
const CORRECT = Object.fromEntries(corpus.map((one) => [one.id, one.expected]));

const STDERR_MARK = 'the bridge said this on stderr';

let runCount = 0;

// A second language whose script is a file nobody wrote, so a run can name a
// language whose bridge is absent. Every language in the shipped table has a bridge
// now, so the absent one is built here rather than borrowed from there.
const ABSENT_BRIDGE = fileURLToPath(new URL('./fixtures/no-such-bridge.go', import.meta.url));

// One full invocation, with the fake bridge standing in for php and the absent
// bridge standing in for go.
async function run({
    argv,
    config = {},
    corpusPath = TWO_SETS,
    timeoutMs = 5000,
    answers = null,
    prepare = undefined,
    script = FAKE_BRIDGE,
}) {
    runCount += 1;
    const launchLog = join(scratch, `launches-${runCount}.log`);
    const requestLog = join(scratch, `request-${runCount}.json`);
    const settings = { launchLog, requestLog, stderr: STDERR_MARK, answers: answers ?? CORRECT, ...config };

    const out = [];
    const err = [];
    const exit = await runConformance({
        argv,
        corpusPath,
        timeoutMs,
        bridges: {
            php: {
                script,
                command: process.execPath,
                operations: OPERATIONS,
                args: [script, JSON.stringify(settings)],
                ...(prepare ? { prepare } : {}),
            },
            // Path-shaped, like a real manifest's `command` would be. This entry never
            // actually launches anything: `script` names a file nobody wrote, so the
            // run reports `UNAVAILABLE` before `command` is ever read.
            go: {
                script: ABSENT_BRIDGE,
                command: 'go/v1/bridge/bridge',
                operations: OPERATIONS,
            },
        },
        out: (line) => out.push(line),
        err: (line) => err.push(line),
    });

    return {
        exit,
        out: out.join('\n'),
        err: err.join('\n'),
        launches: existsSync(launchLog) ? readFileSync(launchLog, 'utf8').trim().split('\n').filter(Boolean).length : 0,
        request: existsSync(requestLog) ? JSON.parse(readFileSync(requestLog, 'utf8')) : null,
    };
}

// The ids a run reported as selected, read back off what it printed, so selection is
// asserted through the operator's own evidence.
function printedIds(text) {
    return [...text.matchAll(/^ {4}(\S+) \(/gm)].map((match) => match[1]);
}

describe('selection', () => {
    it('selects every shipped case when a lane declares every operation', async () => {
        const shipped = loadCases(DEFAULT_CORPUS_PATH);
        const answers = Object.fromEntries(shipped.map((one) => [one.id, one.expected]));
        const result = await run({ argv: ['php'], corpusPath: DEFAULT_CORPUS_PATH, answers });
        assert.equal(result.exit, 0, result.err);
        assert.deepEqual(printedIds(result.out), shipped.map(({ id }) => id));
        assert.equal(result.launches, 1);
    });

    it('runs the whole corpus when no selector is given', async () => {
        const result = await run({ argv: ['php'] });
        assert.equal(result.exit, 0, result.err);
        assert.deepEqual(printedIds(result.out), ALL_IDS);
        assert.equal(result.launches, 1);
    });

    it('runs one set', async () => {
        const result = await run({ argv: ['php', '--set', 'encoding'] });
        assert.equal(result.exit, 0, result.err);
        assert.deepEqual(printedIds(result.out), ALL_IDS.filter((id) => id.startsWith('encoding/')));
        assert.equal(result.launches, 1);
    });

    it('runs one operation', async () => {
        const result = await run({ argv: ['php', '--op', 'open-aes-gcm'] });
        assert.equal(result.exit, 0, result.err);
        assert.deepEqual(printedIds(result.out), ['crypto/01', 'crypto/02']);
        assert.equal(result.launches, 1);
    });

    it('runs one exact case', async () => {
        const result = await run({ argv: ['php', '--case', 'encoding/03'] });
        assert.equal(result.exit, 0, result.err);
        assert.deepEqual(printedIds(result.out), ['encoding/03']);
        assert.equal(result.launches, 1);
    });

    it('runs a repeated-case group in corpus order, in one batch', async () => {
        const result = await run({
            argv: ['php', '--case', 'crypto/01', '--case', 'encoding/03'],
        });
        assert.equal(result.exit, 0, result.err);
        assert.deepEqual(printedIds(result.out), ['encoding/03', 'crypto/01']);
        assert.equal(result.launches, 1);
        assert.equal(result.request.requests.length, 2);
    });

    it('takes --set=value as well as --set value', () => {
        assert.deepEqual(parseSelectors(['--set=encoding']), { sets: ['encoding'], ops: [], caseIds: [] });
    });

    it('prints each selected case beside the label the bridge never receives', async () => {
        const result = await run({ argv: ['php', '--case', 'encoding/03'] });
        assert.equal(result.exit, 0, result.err);
        assert.match(result.out, /^ {4}encoding\/03 \(open-rsa-oaep\) recorded ciphertext$/m);
        assert.ok(!JSON.stringify(result.request).includes('recorded ciphertext'), 'the label stays on the harness side');
    });
});

describe('refusals before any bridge starts', () => {
    const refusals = [
        ['an unknown language', ['rust'], /no bridge is named "rust"/],
        ['an unknown set', ['php', '--set', 'no-such-set'], /no set is named "no-such-set"/],
        ['an unknown operation', ['php', '--op', 'decode-base32'], /no operation is named "decode-base32"/],
        ['an unknown case id', ['php', '--case', 'encoding/99'], /no case is named "encoding\/99"/],
        ['--set with --op', ['php', '--set', 'encoding', '--op', 'open-rsa-oaep'], /one run narrows one way/],
        ['--set with --case', ['php', '--set', 'encoding', '--case', 'encoding/03'], /one run narrows one way/],
        ['--op with --case', ['php', '--op', 'open-rsa-oaep', '--case', 'encoding/03'], /one run narrows one way/],
        ['a repeated --set', ['php', '--set', 'encoding', '--set', 'crypto'], /--set was given 2 times/],
        ['a repeated --op', ['php', '--op', 'open-rsa-oaep', '--op', 'open-aes-gcm'], /--op was given 2 times/],
        [
            'the same --case id twice',
            ['php', '--case', 'encoding/03', '--case', 'encoding/03'],
            /more than once/,
        ],
        ['a selector that is not one', ['php', '--only', 'encoding'], /is not a selector/],
        ['a selector naming nothing', ['php', '--set'], /--set names nothing/],
    ];

    for (const [what, argv, message] of refusals) {
        it(`refuses ${what} without starting a bridge`, async () => {
            const result = await run({ argv });
            assert.equal(result.exit, 2, result.err);
            assert.match(result.err, message);
            assert.equal(result.launches, 0, 'no bridge process was started');
            assert.equal(result.request, null);
        });
    }

    it('refuses a known operation that selects no case', async () => {
        const result = await run({ argv: ['php', '--op', 'seal-aes-gcm'], corpusPath: ONE_OP });
        assert.equal(result.exit, 2);
        assert.match(result.err, /selects no case/);
        assert.equal(result.launches, 0);
    });

    it('refuses a corpus it cannot read, and calls it a corpus fault', async () => {
        const result = await run({ argv: ['php'], corpusPath: join(scratch, 'no-such-corpus.json') });
        assert.equal(result.exit, 2);
        assert.match(result.err, /case corpus could not be read/);
        assert.equal(result.launches, 0);
    });

    it('refuses an empty corpus selection at the selector layer itself', () => {
        assert.throws(() => selectCases([], { sets: [], ops: [], caseIds: [] }), SelectionError);
    });
});

describe('the corpus file itself', () => {
    // A corpus written by hand is read once, strictly, and a fault in it is never
    // reported as something a bridge did.
    function corpusFile(name, text) {
        const path = join(scratch, name);
        writeFileSync(path, text);
        return path;
    }

    it('refuses a duplicated cases member rather than running the surviving half', async () => {
        const one = readFileSync(ONE_OP, 'utf8').trim().replace(/^\{/, '').replace(/\}$/, '');
        const path = corpusFile('duplicate-cases.json', `{${one}, "cases": []}`);

        assert.throws(() => loadCases(path), (error) => {
            assert.ok(error instanceof CorpusError);
            assert.match(error.message, /repeats JSON member "cases"/);
            return true;
        });

        const result = await run({ argv: ['php'], corpusPath: path });
        assert.equal(result.exit, 2, result.err);
        assert.match(result.err, /repeats JSON member "cases"/);
        assert.equal(result.launches, 0);
    });

    it('refuses a case row carrying a member the corpus shape does not name', async () => {
        const path = corpusFile('unknown-case-member.json', JSON.stringify({
            cases: [{
                id: 'encoding/01',
                set: 'encoding',
                label: 'canonical value',
                op: 'decode-base64url',
                input: { value: 'AQID' },
                expected: { bytesHex: '010203' },
                verdict: 'held',
            }],
        }));

        assert.throws(() => loadCases(path), (error) => {
            assert.ok(error instanceof CorpusError);
            assert.match(error.message, /carries \{.*verdict.*\}/);
            return true;
        });

        const result = await run({ argv: ['php'], corpusPath: path });
        assert.equal(result.exit, 2, result.err);
        assert.equal(result.launches, 0);
    });

    it('refuses a case row carrying no label', async () => {
        const path = corpusFile('no-label.json', JSON.stringify({
            cases: [{
                id: 'encoding/01',
                set: 'encoding',
                op: 'decode-base64url',
                input: { value: 'AQID' },
                expected: { bytesHex: '010203' },
            }],
        }));
        assert.throws(() => loadCases(path), CorpusError);
    });
});

describe('what crosses to the bridge', () => {
    it('sends the batch envelope and nothing that could be read as an oracle', async () => {
        const result = await run({ argv: ['php'] });
        assert.equal(result.exit, 0, result.err);
        assert.equal(result.request.protocol, 'dca-operation-bridge-v1');
        assert.deepEqual(Object.keys(result.request).sort(), ['protocol', 'requests']);
        assert.equal(result.request.requests.length, ALL_IDS.length);

        for (const request of result.request.requests) {
            assert.deepEqual(Object.keys(request).sort(), ['id', 'input', 'op']);
        }

        const text = JSON.stringify(result.request);
        assert.ok(!text.includes('expected'), 'no expectation crosses the boundary');
        assert.ok(!text.includes('"label"'), 'no label crosses the boundary');
        for (const verdict of ['held', 'disagreed', 'incomplete', 'verdict', 'exit']) {
            assert.ok(!text.includes(`"${verdict}"`), `no ${verdict} field crosses the boundary`);
        }
    });
});

// Everything written about this corpus calls it frozen and nothing held it to that. A run
// prints the number of cases it selected and compares that number against nothing, no
// checksum or manifest covers `_shared/cases/v1/cases.json`, and a run over a corpus somebody
// trimmed prints the same `HELD` line an outside implementer reads as agreement on the
// protocol. The membership is written out by hand below, so a case that is removed,
// renamed, re-oped or added turns this suite red, which a corpus change should not
// pass silently. The list is the whole corpus, so a case added at the end
// fails it exactly as a missing case does.
describe('the frozen corpus', () => {
    // `<set>/<nn> (<op>)`, sorted, one line per case.
    const FROZEN = [
        'aes-gcm-128/01 (open-aes-gcm)',
        'aes-gcm-128/02 (open-aes-gcm)',
        'aes-gcm-256/01 (seal-aes-gcm)',
        'aes-gcm-256/02 (seal-aes-gcm)',
        'aes-gcm-256/03 (open-aes-gcm)',
        'aes-gcm-256/04 (open-aes-gcm)',
        'aes-gcm-256/05 (open-aes-gcm)',
        'ecdh/01 (ecdh-p256)',
        'ecdh/02 (ecdh-p256)',
        'ecdh/03 (p256-point)',
        'encoding/01 (decode-base64url)',
        'encoding/02 (decode-base64url)',
        'encoding/03 (decode-base64url)',
        'encoding/04 (decode-base64url)',
        'hkdf/01 (hkdf-sha256)',
        'hkdf/02 (hkdf-sha256)',
        'hkdf/03 (hkdf-sha256)',
        'hkdf/04 (hkdf-sha256)',
        'hkdf/05 (hkdf-sha256)',
        'hkdf/06 (hkdf-sha256)',
        'hkdf/07 (hkdf-sha256)',
        'hkdf/08 (hkdf-sha256)',
        'hkdf/09 (hkdf-sha256)',
        'hkdf/10 (hkdf-sha256)',
        'hkdf/11 (hkdf-sha256)',
        'hkdf/12 (hkdf-sha256)',
        'rsa-oaep/01 (open-rsa-oaep)',
        'rsa-oaep/02 (open-rsa-oaep)',
    ];

    it('ships these cases under these operations and no others', () => {
        const shipped = loadCases(DEFAULT_CORPUS_PATH).map((one) => `${one.id} (${one.op})`).sort();
        assert.deepEqual(shipped, FROZEN, 'the shipped corpus is unchanged');
    });

    it('states on every row the wrong implementation it distinguishes', () => {
        for (const one of loadCases(DEFAULT_CORPUS_PATH)) {
            assert.ok(one.rationale.length > 40, `${one.id} carries a rationale`);
        }
    });

    // A set is what a lane is asked or not asked, so the operations a set needs are
    // what decides it. A set spanning two operations makes both a condition of being
    // asked at all, which is why the grouping is asserted here rather than left to
    // whoever adds the next case.
    it('groups the corpus into sets by the operations each one asks for', () => {
        assert.deepEqual(corpusSets(loadCases(DEFAULT_CORPUS_PATH)), [
            { set: 'encoding', operations: ['decode-base64url'] },
            { set: 'aes-gcm-128', operations: ['open-aes-gcm'] },
            { set: 'hkdf', operations: ['hkdf-sha256'] },
            { set: 'aes-gcm-256', operations: ['seal-aes-gcm', 'open-aes-gcm'] },
            { set: 'ecdh', operations: ['ecdh-p256', 'p256-point'] },
            { set: 'rsa-oaep', operations: ['open-rsa-oaep'] },
        ]);
    });
});

// The identifier travels inside the request, so an identifier that says how its case
// comes out is the expectation crossing the boundary in the one field that has to
// cross it. Both claims below are made over the shipped corpus, every case of it.
describe('an identifier that gives nothing away', () => {
    const shipped = loadCases(DEFAULT_CORPUS_PATH);

    // Words a first cut of this corpus used in its suffixes, plus the ones a next
    // author would reach for. A suffix carrying any of them states its own answer.
    const OUTCOME_WORDS = [
        'refus', 'reject', 'invalid', 'malformed', 'fail', 'wrong', 'bad', 'error',
        'empty', 'duplicate', 'noncanonical', 'canonical', 'padding', 'padded',
        'delimiter', 'held', 'pass', 'ok', 'good', 'valid', 'success',
    ];

    it('carries no word stating an outcome, in any identifier in the corpus', () => {
        assert.ok(shipped.length > 0, 'the corpus is not empty');
        for (const one of shipped) {
            assert.match(one.id, /^[a-z0-9-]+\/\d{2}$/, `${one.id} is <set>/<nn>`);
            for (const word of OUTCOME_WORDS) {
                assert.ok(!one.id.toLowerCase().includes(word), `${one.id} carries the outcome word ${word}`);
            }
        }
    });

    it('leaves a bridge that answers from the identifier and the op name disagreeing on every case', async () => {
        const result = await run({
            argv: ['php'],
            corpusPath: DEFAULT_CORPUS_PATH,
            config: { guess: true },
        });
        assert.equal(result.exit, 1, result.err);
        assert.match(result.err, /^DISAGREED:/m);
        assert.match(result.err, new RegExp(`${shipped.length} answer\\(s\\) differ`));
        for (const one of shipped) {
            assert.match(result.err, new RegExp(`${one.id.replace('/', '\\/')} \\(${one.op}\\)`));
        }
    });
});

describe('accounting over one batch', () => {
    it('reads the results as a set and not as a sequence', async () => {
        const result = await run({ argv: ['php'], config: { reverse: true } });
        assert.equal(result.exit, 0, result.err);
        assert.match(result.out, /^HELD:/m);
    });

    it('holds a correct value answer and every defined refusal', async () => {
        for (const one of corpus) {
            const result = await run({ argv: ['php', '--case', one.id] });
            assert.equal(result.exit, 0, `${one.id}: ${result.err}`);
        }
    });

    const incompletes = [
        ['a missing result', { drop: ['encoding/03'] }, /encoding\/03 \(open-rsa-oaep\) was selected and no result answers it/],
        ['a duplicate result', { duplicate: ['encoding/03'] }, /was answered 2 times/],
        [
            'a result nobody asked for',
            { extra: [{ id: 'encoding/77', op: 'open-rsa-oaep', observation: { plaintextBase64url: 'eA' } }] },
            /encoding\/77 was answered and was not selected/,
        ],
        [
            'the wrong operation on a known id',
            { retagOp: { 'encoding/03': 'decode-base64url' } },
            /was asked as open-rsa-oaep and answered as "decode-base64url"/,
        ],
        [
            'a member the contract does not name',
            { addField: { 'encoding/03': { note: 'extra' } } },
            /carries \{id, op, observation, note\}/,
        ],
        [
            'an observation with an unknown member',
            { replaceObservation: { 'encoding/03': { value: 'aGVsbG8' } } },
            /answers \{plaintextBase64url\} or \{refused\}/,
        ],
        [
            'an empty observation',
            { replaceObservation: { 'encoding/03': {} } },
            /answers \{plaintextBase64url\} or \{refused\}/,
        ],
        [
            'an observation carrying both a value and a refusal',
            { replaceObservation: { 'encoding/03': { plaintextBase64url: 'eA', refused: 'unseal_failed' } } },
            /a refusal carries the code and nothing beside it/,
        ],
        [
            'an observation whose member is the wrong type',
            { replaceObservation: { 'encoding/03': { plaintextBase64url: 5 } } },
            /answers plaintextBase64url as a string/,
        ],
    ];

    for (const [what, config, message] of incompletes) {
        it(`calls ${what} incomplete`, async () => {
            const result = await run({ argv: ['php'], config });
            assert.equal(result.exit, 2, result.err);
            assert.match(result.err, /^INCOMPLETE:/m);
            assert.match(result.err, message);
        });
    }
});

describe('the 1 and 2 line', () => {
    it('calls one wrong value a disagreement, at its case id, with no second bridge', async () => {
        const result = await run({
            argv: ['php'],
            config: { replaceObservation: { 'encoding/01': { bytesHex: 'ffffffff' } } },
        });
        assert.equal(result.exit, 1, result.err);
        assert.match(result.err, /^DISAGREED:/m);
        assert.match(result.err, /encoding\/01 \(decode-base64url\)/);
        assert.match(result.err, /expected: \{"bytesHex":"010203"\}/);
        assert.match(result.err, /answered: \{"bytesHex":"ffffffff"\}/);
        assert.equal(result.launches, 1, 'a disagreement is reported once and never retried');
    });

    it('calls a refusal code nothing defines a disagreement, because it is well formed', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/01'],
            config: { replaceObservation: { 'encoding/01': { refused: 'nope' } } },
        });
        assert.equal(result.exit, 1, result.err);
        assert.match(result.err, /answered: \{"refused":"nope"\}/);
    });

    it('calls the wrong defined refusal on a refusal case a disagreement', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/02'],
            config: { replaceObservation: { 'encoding/02': { refused: 'unseal_failed' } } },
        });
        assert.equal(result.exit, 1, result.err);
        assert.match(result.err, /expected: \{"refused":"invalid_base64url"\}/);
    });

    it('calls a refusal where a value was expected a disagreement', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/03'],
            config: { replaceObservation: { 'encoding/03': { refused: 'unseal_failed' } } },
        });
        assert.equal(result.exit, 1, result.err);
    });

    it('lets one incomplete outrank a disagreement in the same batch', async () => {
        const result = await run({
            argv: ['php'],
            config: {
                replaceObservation: { 'encoding/01': { bytesHex: 'ffffffff' } },
                drop: ['encoding/03'],
            },
        });
        assert.equal(result.exit, 2, result.err);
        // The disagreement is still named. It is counted and it is not the answer.
        assert.match(result.err, /encoding\/01 also disagreed/);
    });
});

// Two spellings of one text are two answers, and the comparison reports them as two.
// The printed lines have to show the difference: a terminal draws the composed and
// the decomposed spelling the same way, so `expected:` and `answered:` can be two
// lines an operator reads as one line printed twice.
describe('a disagreement the two printed lines cannot show', () => {
    const accented = loadCases(NON_ASCII)[0];
    const COMPOSED = accented.expected.plaintextBase64url;
    const DECOMPOSED = COMPOSED.normalize('NFD');
    const WITH_AN_INVISIBLE = `${COMPOSED}${String.fromCodePoint(0x200b)}`;

    it('has a fixture whose two spellings are the same text and different bytes', () => {
        assert.notEqual(COMPOSED, DECOMPOSED);
        assert.equal(COMPOSED.normalize('NFC'), DECOMPOSED.normalize('NFC'));
    });

    it('names the normalization and spells out both sides in code points', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/01'],
            corpusPath: NON_ASCII,
            config: { replaceObservation: { 'encoding/01': { plaintextBase64url: DECOMPOSED } } },
        });
        assert.equal(result.exit, 1, result.err);

        const printed = result.err.match(/^ {4}expected: (.*)$/m)[1];
        const answered = result.err.match(/^ {4}answered: (.*)$/m)[1];
        assert.notEqual(printed, answered, 'the two lines are different bytes');
        assert.equal(printed.normalize('NFC'), answered.normalize('NFC'), 'and a reader cannot tell them apart');

        assert.match(result.err, /plaintextBase64url differs from code point 23, the same text under Unicode normalization and not the same bytes:/);
        assert.match(result.err, /^ {8}expected .*U\+00E9/m);
        assert.match(result.err, /^ {8}answered .*U\+0065 U\+0301/m);
    });

    it('spells out a difference that is invisible for another reason, and claims no normalization', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/01'],
            corpusPath: NON_ASCII,
            config: { replaceObservation: { 'encoding/01': { plaintextBase64url: WITH_AN_INVISIBLE } } },
        });
        assert.equal(result.exit, 1, result.err);
        assert.match(result.err, /plaintextBase64url differs from code point 28:/);
        assert.ok(!result.err.includes('Unicode normalization'), 'these two are not one text spelled twice');
        assert.match(result.err, /U\+200B/);
    });

    it('says the same about a disagreement an incomplete run only mentions in passing', async () => {
        const result = await run({
            argv: ['php'],
            corpusPath: NON_ASCII,
            config: {
                replaceObservation: { 'encoding/01': { plaintextBase64url: DECOMPOSED } },
                drop: ['encoding/02'],
            },
        });
        assert.equal(result.exit, 2, result.err);
        assert.match(result.err, /encoding\/01 also disagreed/);
        assert.match(result.err, /plaintextBase64url differs from code point 23, the same text under Unicode normalization/);
    });

    it('adds nothing to a disagreement both sides of which are printable ASCII', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/03'],
            config: { replaceObservation: { 'encoding/03': { plaintextBase64url: 'a-fixture-value-of-other' } } },
        });
        assert.equal(result.exit, 1, result.err);
        assert.ok(!result.err.includes('differs'), 'the two printed lines already show it');
        assert.ok(!result.err.includes('U+'), 'no code point is spelled out');
    });
});

describe('a bridge that never answers in the contract', () => {
    const transport = [
        ['bytes that are not JSON', { output: 'malformed' }, 5000, /malformed-json/],
        ['more bytes than the cap', { output: 'oversized' }, 5000, /response-too-large/],
        ['two JSON values', { output: 'two' }, 5000, /multiple-responses/],
        ['no output at all', { output: 'silent' }, 5000, /no-stdout/],
        ['a nonzero exit', { exitCode: 3 }, 5000, /exit-status/],
        ['a signal', { signal: true }, 5000, /signal/],
        ['no answer within the time given', { hang: true }, 400, /timeout/],
        ['an envelope naming another protocol', { protocol: 'dca-operation-bridge-v0' }, 5000, /protocol-mismatch/],
        ['an envelope carrying a member nobody named', { envelopeExtra: { verdict: 'held' } }, 5000, /response-shape/],
    ];

    for (const [what, config, timeoutMs, reason] of transport) {
        it(`calls ${what} incomplete`, async () => {
            const result = await run({ argv: ['php'], config, timeoutMs });
            assert.equal(result.exit, 2, result.err);
            assert.match(result.err, reason);
        });
    }

    it('calls a language whose bridge is not there unavailable', async () => {
        const result = await run({ argv: ['go'] });
        assert.equal(result.exit, 2, result.err);
        assert.match(result.err, /^UNAVAILABLE: the go bridge is not there/m);
        assert.match(result.err, /no-such-bridge\.go/);
        assert.ok(!existsSync(ABSENT_BRIDGE), 'the script named for go is a file nobody wrote');
        assert.equal(result.launches, 0);
    });

    // The other two ways a bridge source answers nothing. A language whose entry names
    // a directory or a file this process may not open is as unavailable as one nobody
    // wrote, and the run names which of the three it met.
    it('calls a bridge whose script is not a file unavailable', async () => {
        const result = await run({ argv: ['php'], script: scratch });
        assert.equal(result.exit, 2, result.err);
        assert.match(result.err, /^UNAVAILABLE: the php bridge is not a file/m);
        assert.equal(result.launches, 0);
    });

    it('calls a bridge whose script cannot be read unavailable', async (t) => {
        const unreadable = join(scratch, 'unreadable-bridge.mjs');
        writeFileSync(unreadable, '// a bridge behind a mode nobody can open\n');
        chmodSync(unreadable, 0o000);

        // A process allowed to read every file, root among them, cannot be shown one it
        // may not read, and a mode that means nothing proves nothing.
        try {
            accessSync(unreadable, constants.R_OK);
            t.skip('this process can read a mode-000 file');
            return;
        } catch {
            // The mode means what it says here, so the run below has something to find.
        }

        const result = await run({ argv: ['php'], script: unreadable });
        assert.equal(result.exit, 2, result.err);
        assert.match(result.err, /^UNAVAILABLE: the php bridge cannot be read/m);
        assert.equal(result.launches, 0);
    });
});

// A compiled or JIT runtime builds before it can answer, and a build inside the
// request would be measured against the request's budget.
describe('getting a bridge runnable, outside the request', () => {
    it('does not spend the request budget on the preparation step', async () => {
        const result = await run({
            argv: ['php', '--case', 'encoding/03'],
            timeoutMs: 500,
            prepare: { command: process.execPath, args: ['-e', 'setTimeout(() => {}, 1500)'] },
        });
        assert.equal(result.exit, 0, result.err);
        assert.equal(result.launches, 1);
    });

    it('calls a preparation step that fails incomplete, and never asks the bridge', async () => {
        const result = await run({
            argv: ['php'],
            prepare: { command: process.execPath, args: ['-e', 'console.error("no compiler here"); process.exit(2)'] },
        });
        assert.equal(result.exit, 2, result.err);
        assert.match(result.err, /could not be made runnable: prepare-failed/);
        assert.match(result.err, /no compiler here/);
        assert.equal(result.launches, 0);
    });
});

describe('what an incomplete run leaves the operator', () => {
    const narrowable = [
        ['a transport failure', { output: 'malformed' }, 5000],
        ['a timeout', { hang: true }, 400],
        ['a signal', { signal: true }, 5000],
        ['a missing result', { drop: ['encoding/03'] }, 5000],
        ['a duplicate result', { duplicate: ['encoding/03'] }, 5000],
    ];

    for (const [what, config, timeoutMs] of narrowable) {
        it(`names the selected ids, the reason and the bridge stderr after ${what}`, async () => {
            const result = await run({ argv: ['php', '--set', 'encoding'], config, timeoutMs });
            assert.equal(result.exit, 2);
            assert.match(result.err, /^INCOMPLETE:/m);
            assert.match(result.err, /selected 4 case\(s\):/);
            for (const id of ALL_IDS.filter((one) => one.startsWith('encoding/'))) {
                assert.ok(result.err.includes(id), `${id} is printed for the operator to narrow with`);
            }
            assert.match(result.err, new RegExp(STDERR_MARK));
        });
    }

    it('says so plainly when the bridge wrote no stderr at all', async () => {
        const result = await run({ argv: ['php'], config: { stderr: '', output: 'malformed' } });
        assert.equal(result.exit, 2);
        assert.match(result.err, /wrote nothing to stderr/);
    });

    it('states the size of a flood of stderr and prints a capped part of it', async () => {
        const result = await run({ argv: ['php'], config: { output: 'malformed', stderrLines: 5000 } });
        assert.equal(result.exit, 2);
        assert.match(result.err, /wrote \d{6,} byte\(s\) on \d{4,} line\(s\) to stderr, and the first \d+ line\(s\) follow:/);
        assert.match(result.err, /further line\(s\) not printed\./);
        assert.ok(result.err.length < 20000, `the reprint is capped, and it printed ${result.err.length} characters`);
        assert.match(result.err, new RegExp(STDERR_MARK));
    });
});

// `run.sh php | head -1` closes the pipe once head has its line, and the runner exits
// on its verdict rather than on a reader that stopped reading.
describe('a reader that stops reading', () => {
    it('still exits 0 on a held run whose stdout is closed early', async () => {
        const settings = JSON.stringify({ answers: CORRECT });
        const child = spawn(process.execPath, [CLOSED_STDOUT_RUN, TWO_SETS, FAKE_BRIDGE, settings], {
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        child.stdout.destroy();
        child.stderr.resume();

        const ended = await new Promise((resolve) => child.on('close', (code, signal) => resolve({ code, signal })));
        assert.equal(ended.signal, null, 'the run was not killed by a signal');
        assert.equal(ended.code, 0);
    });
});

// The php bridge's own reading of the request, checked here because the contract
// calls these shapes closed and a closed shape nobody checks is a sentence in a
// document. Each of these is a batch no harness would send, so each is a nonzero exit
// with a stderr line and no partial results.
describe('the php bridge on a request outside the contract', () => {
    const php = spawnSync('php', ['-v'], { encoding: 'utf8' });
    const available = !php.error && php.status === 0;

    function ask(batch) {
        return spawnSync('php', [PHP_BRIDGE], { input: `${JSON.stringify(batch)}\n`, encoding: 'utf8' });
    }

    const good = {
        protocol: 'dca-operation-bridge-v1',
        requests: [{ id: 'encoding/01', op: 'decode-base64url', input: { value: '3q2-7w' } }],
    };

    it('answers a batch inside the contract', { skip: available ? false : 'php is not installed' }, () => {
        const answered = ask(good);
        assert.equal(answered.status, 0, answered.stderr);
        assert.deepEqual(JSON.parse(answered.stdout).results, [
            { id: 'encoding/01', op: 'decode-base64url', observation: { bytesHex: 'deadbeef' } },
        ]);
    });

    const outside = [
        ['an unknown member in the envelope', { ...good, verdict: 'held' }, /the batch carries \{.*verdict.*\}/],
        [
            'an unknown member in a request row',
            { ...good, requests: [{ ...good.requests[0], expected: { bytesHex: 'deadbeef' } }] },
            /a request entry carries \{.*expected.*\}/,
        ],
        [
            'an unknown member in an input',
            { ...good, requests: [{ ...good.requests[0], input: { value: '3q2-7w', mode: 'lax' } }] },
            /the input of request .* carries \{.*mode.*\}/,
        ],
        [
            'a missing input member',
            { ...good, requests: [{ ...good.requests[0], input: {} }] },
            /the input of request .* carries \{\}/,
        ],
        [
            'a missing request member',
            { ...good, requests: [{ id: 'encoding/01', op: 'decode-base64url' }] },
            /a request entry carries \{id, op\}/,
        ],
        [
            'an input member of the wrong type',
            { ...good, requests: [{ ...good.requests[0], input: { value: 7 } }] },
            /carries no string value/,
        ],
        [
            'a protocol it does not speak',
            { ...good, protocol: 'dca-operation-bridge-v0' },
            /names a protocol this bridge does not speak/,
        ],
        [
            'an operation it does not implement',
            { ...good, requests: [{ ...good.requests[0], op: 'decode-base32' }] },
            /which this bridge does not implement/,
        ],
    ];

    for (const [what, batch, message] of outside) {
        it(`refuses ${what}`, { skip: available ? false : 'php is not installed' }, () => {
            const answered = ask(batch);
            assert.notEqual(answered.status, 0, `stdout was ${answered.stdout}`);
            assert.equal(answered.stdout, '', 'no partial results are written');
            assert.match(answered.stderr, message);
        });
    }
});

// The driver holds no table of languages. A lane is an immediate child directory of
// the conformance dir carrying a `bridge.json`, discovered rather than named here, the
// same way `check` discovers a lane by its executable `check`.
describe('discovering bridges from a manifest beside each lane', () => {
    const GOOD_TREE = fileURLToPath(new URL('./fixtures/bridge-manifests/', import.meta.url));
    // Malformed JSON has to live apart from a tree otherwise good, because
    // `loadBridges` throws on the first bad manifest and never reaches the rest.
    const MALFORMED_TREE = fileURLToPath(new URL('./fixtures/bridge-manifests-malformed/', import.meta.url));
    // Every one of these fixture roots holds exactly one lane, for the same reason:
    // a walk that throws on its first bad manifest never proves anything about a
    // second one sitting beside it in the same tree.
    const INVALID_ROOT = fileURLToPath(new URL('./fixtures/bridge-manifests-invalid/', import.meta.url));
    // _shared/driver/test/ to conformance-primitives/, the same distance run.mjs's own
    // CONFORMANCE_DIR resolves from _shared/driver/, one level further out.
    const REAL_CONFORMANCE_DIR = fileURLToPath(new URL('../../../', import.meta.url));

    it('discovers a lane by its bridge.json, in sorted order, and skips a dir without one', () => {
        const bridges = loadBridges(GOOD_TREE);
        assert.deepEqual(Object.keys(bridges), ['alpha', 'beta'], 'gamma carries no manifest and sorted order holds');
    });

    it('builds an entry of the same shape the runner asks for, prepare included', () => {
        const bridges = loadBridges(GOOD_TREE);
        assert.deepEqual(bridges.alpha, {
            script: 'alpha/bridge.mjs',
            command: 'alpha/run.sh',
            operations: ['decode-base64url'],
            prepare: { command: 'alpha/prepare.sh', args: ['--go'] },
        });
    });

    it('carries no prepare key when a manifest omits it', () => {
        const bridges = loadBridges(GOOD_TREE);
        assert.deepEqual(bridges.beta, {
            script: 'beta/bridge.mjs', command: 'beta/run.sh', operations: ['open-aes-gcm'],
        });
        assert.ok(!('prepare' in bridges.beta), 'beta names no prepare step');
    });

    it('refuses a malformed manifest by name through runConformance, and starts no bridge', async () => {
        const out = [];
        const err = [];
        const exit = await runConformance({
            argv: ['broken'],
            corpusPath: TWO_SETS,
            conformanceDir: MALFORMED_TREE,
            out: (line) => out.push(line),
            err: (line) => err.push(line),
        });
        assert.equal(exit, 2);
        assert.match(err.join('\n'), /^REFUSED: lane broken: bridge\.json does not parse as JSON:/m);
        assert.equal(out.length, 0, 'a manifest fault starts no bridge and prints nothing on stdout');
    });

    it('uses a caller-supplied bridges table as given, even over a tree with a bad manifest', async () => {
        // `conformanceDir` names a tree whose one lane's manifest is malformed JSON.
        // A run that supplies its own `bridges` holds anyway: `loadBridges` runs only
        // when `bridges` is not given, so this run never reads that manifest at all.
        const settings = { answers: CORRECT };
        const out = [];
        const err = [];
        const exit = await runConformance({
            argv: ['php'],
            corpusPath: TWO_SETS,
            conformanceDir: MALFORMED_TREE,
            bridges: {
                php: {
                    script: FAKE_BRIDGE, command: process.execPath, operations: OPERATIONS,
                    args: [FAKE_BRIDGE, JSON.stringify(settings)],
                },
            },
            out: (line) => out.push(line),
            err: (line) => err.push(line),
        });
        assert.equal(exit, 0, err.join('\n'));
    });

    // One tree, one lane, one fault. `run.mjs`'s closed-shape rule mirrors the batch
    // envelope it validates elsewhere in this file: a member nobody named is refused
    // by name rather than dropped, and every shape check gets its own case here so a
    // message that drifts into naming the wrong member cannot hide behind a passing
    // suite.
    const invalid = [
        ['missing-script', /^lane lane: bridge\.json is missing a string "script"\.$/],
        ['missing-command', /^lane lane: bridge\.json is missing a string "command"\.$/],
        ['missing-operations', /^lane lane: bridge\.json is missing an "operations" array\.$/],
        ['not-an-object', /^lane lane: bridge\.json is not a JSON object\.$/],
        ['unknown-member', /^lane lane: bridge\.json carries a member this format does not name: "cwd"\.$/],
        ['prepare-not-object', /^lane lane: bridge\.json's "prepare" is not a JSON object\.$/],
        ['prepare-missing-command', /^lane lane: bridge\.json's "prepare" is missing a string "command"\.$/],
        [
            'prepare-unknown-member',
            /^lane lane: bridge\.json's "prepare" carries a member this format does not name: "cwd"\.$/,
        ],
        ['prepare-args-not-array', /^lane lane: bridge\.json's "prepare\.args" is not an array\.$/],
    ];

    // `assert.throws`'s RegExp form matches the error's own string form, `Error:
    // <message>`, not `.message` alone, so a pattern anchored on the message's own
    // first character never matches through it. A validator function reaches
    // `.message` directly, which is what these patterns are written against.
    function throwsMessage(message) {
        return (error) => {
            assert.match(error.message, message);
            return true;
        };
    }

    for (const [fixture, message] of invalid) {
        it(`refuses ${fixture.replace(/-/g, ' ')}, naming the lane and the problem`, () => {
            const root = fileURLToPath(new URL(`./fixtures/bridge-manifests-invalid/${fixture}/`, import.meta.url));
            assert.throws(() => loadBridges(root), throwsMessage(message));
        });
    }

    it('calls a bridge.json that cannot be read a read failure, naming the lane', (t) => {
        const root = join(scratch, 'unreadable-manifest-root');
        const laneDir = join(root, 'lane');
        mkdirSync(laneDir, { recursive: true });
        const manifestPath = join(laneDir, 'bridge.json');
        writeFileSync(manifestPath, '{ "script": "lane/bridge.mjs", "command": "lane/run.sh" }\n');
        chmodSync(manifestPath, 0o000);

        // A process allowed to read every file, root among them, cannot be shown one
        // it may not read, and a mode that means nothing proves nothing.
        try {
            accessSync(manifestPath, constants.R_OK);
            t.skip('this process can read a mode-000 file');
            return;
        } catch {
            // The mode means what it says here, so the assertion below has something
            // to find.
        }

        assert.throws(() => loadBridges(root), throwsMessage(/^lane lane: bridge\.json could not be read: /));
    });

    it('loads all six shipped lanes, each naming a script this checkout actually has', () => {
        const bridges = loadBridges(REAL_CONFORMANCE_DIR);
        assert.deepEqual(Object.keys(bridges), ['dotnet', 'go', 'jvm', 'node', 'php', 'python']);
        for (const [lane, entry] of Object.entries(bridges)) {
            const scriptPath = isAbsolute(entry.script) ? entry.script : join(REAL_CONFORMANCE_DIR, entry.script);
            assert.ok(existsSync(scriptPath), `${lane}'s script ${entry.script} is not on disk`);
            // Every lane but go and node names a checked-in wrapper as its command.
            // go's command is a build artifact `prepare` produces and .gitignore
            // excludes, and node's is the bridge's own source, run directly. Asserting
            // a wrapper here would fail a checkout that has not built go's yet.
            const commandPath = isAbsolute(entry.command) ? entry.command : join(REAL_CONFORMANCE_DIR, entry.command);
            assert.ok(
                existsSync(commandPath) || Boolean(entry.prepare),
                `${lane}'s command ${entry.command} is neither on disk nor produced by a prepare step`,
            );
            if (existsSync(commandPath)) {
                assert.doesNotThrow(
                    () => accessSync(commandPath, constants.X_OK),
                    `${lane}'s command ${entry.command} is on disk but not executable`,
                );
            }
        }
    });
});

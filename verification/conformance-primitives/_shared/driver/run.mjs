// The runner: one language, one selection, one bridge process, one exit code.
//
// `node conformance-primitives/_shared/driver/run.mjs <language> [--set <set> | --op <operation> |
// --case <id> ...]` reaches here. The order is fixed and short. Read the corpus,
// narrow it, find the named language's bridge, ask it once, judge the answers,
// print, exit 0, 1 or 2.
//
// The command line carries selectors and no behavior toggles. A full run, a set, an
// operation, one case and a repeated-`--case` group all use identical validation,
// refusal semantics, diagnostics and process handling. There is no strict or
// compatibility mode, no debug mode, no retry and no isolation mode, because a
// harness whose strictness is a flag reports whichever answer the operator asked
// for. Narrowing a failure is what the selectors are for: the printed selected ids
// are copyable straight into repeated `--case` arguments, and each such command
// starts a fresh bridge.
//
// Validation, comparison and framing live in other modules, and how each of them
// works is not written here. This file knows where a bridge lives, in what order the
// four steps happen, and what an operator needs printed when a step fails. Reading
// two values that already disagree to say where they disagree is part of that
// printing, and the verdict it describes was reached before this file was handed it.
//
// The runner catches these faults before the bridge starts: it exits 2 and starts no
// process. An unknown language, an unknown set, operation or case, mixed or repeated
// selector kinds, a selection that covers nothing and an unreadable corpus are all
// faults in the command or the corpus. Starting a bridge to report them would suggest
// a bridge had been measured.
//
// A language that needs building is built before the request clock starts. A bridge
// entry may name a `prepare` command, and the batch is asked of a program that is
// already runnable. The request budget then measures answering rather than compiling.

import { accessSync, constants, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    CorpusError, DEFAULT_CORPUS_PATH, SelectionError, loadCases, parseSelectors, selectCases,
} from './cases.mjs';
import { INCOMPLETE, askBatch, prepareBridge } from './protocol.mjs';
import { OPERATION_SHAPES, validateResults } from './validate-results.mjs';

export const CONFORMANCE_DIR = fileURLToPath(new URL('../..', import.meta.url));

// Where each lane's bridge lives, discovered rather than written down here. An
// immediate child or runtime/binding directory carrying a `bridge.json` is a
// lane; directories without one are skipped. This mirrors how `check`
// discovers a lane by its executable `check`,
// so a bridge and a lane's own gate are found the same way and neither list has
// to be kept in step with the tree. A lane may carry a `bridge.json` before its
// `script` lands, and that is what separates an `UNAVAILABLE` bridge from an
// unknown language: the first is a lane this driver has registered but not
// written yet, the second is a name this driver does not know.
//
// A manifest is a JSON object naming exactly:
//   script    the bridge's source, the file whose absence makes a language
//             unavailable
//   command   what is started to answer a batch: a path inside the conformance
//             directory, or absolute
//   members   the parts of this binding that answer operations, as
//             { name: one line saying what it is }, for example
//             { "openssl": "ext/openssl", "lane": "code written in this lane" };
//             a name is lowercase letters and digits
//   operations  every operation the bridge implements, as { operation: member
//               name }; every value names a key of `members`, and every member
//               answers at least one operation. An empty `members` beside an
//               empty `operations` is valid only for an intentionally
//               unavailable operation surface
//   prepare   optional: { command, args? }, a command that runs once, outside
//             the batch's time, to turn `script` into something `command` can
//             run
//
// `members` and the member each operation names are harness metadata: the
// record carries them, and no bridge is ever asked who answered. The entry
// keeps `operations` as a list of names in manifest order, because selection
// only asks whether an operation is declared; `answeredBy` maps each
// operation to its member name and `members` carries the descriptions.
//
// A member this shape does not name, at either level, is refused rather than
// silently carried or dropped, the same closed-shape rule the rest of this
// tree holds a batch envelope to. Loading throws, naming the lane and the
// problem, on a `bridge.json` that cannot be read, JSON that does not parse, a
// value that is not a JSON object, a missing string `script` or `command`, or
// an unnamed member. `runConformance` turns that throw into a refusal rather
// than letting a broken manifest crash the process.
const MANIFEST_MEMBERS = ['script', 'command', 'members', 'operations', 'prepare'];
// A member name travels into a lane record as `member=<name>`, which the shell
// aggregator splits on spaces and `=`, so it stays one plain token.
const MEMBER_NAME = /^[a-z0-9]+$/;
const PREPARE_MEMBERS = ['command', 'args'];

export function loadBridges(conformanceDir) {
    const bridges = {};
    const runtimeDirs = readdirSync(conformanceDir, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort();
    const lanes = runtimeDirs.flatMap((runtime) => [
        runtime,
        ...readdirSync(join(conformanceDir, runtime), { withFileTypes: true })
            .filter((entry) => entry.isDirectory())
            .map((entry) => `${runtime}/${entry.name}`),
    ]).sort();

    for (const lane of lanes) {
        const manifestPath = join(conformanceDir, lane, 'bridge.json');
        if (!existsSync(manifestPath)) continue;

        let text;
        try {
            text = readFileSync(manifestPath, 'utf8');
        } catch (error) {
            throw new Error(`lane ${lane}: bridge.json could not be read: ${error.message}`);
        }

        let manifest;
        try {
            manifest = JSON.parse(text);
        } catch (error) {
            throw new Error(`lane ${lane}: bridge.json does not parse as JSON: ${error.message}`);
        }

        if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
            throw new Error(`lane ${lane}: bridge.json is not a JSON object.`);
        }
        const unnamed = Object.keys(manifest).find((name) => !MANIFEST_MEMBERS.includes(name));
        if (unnamed !== undefined) {
            throw new Error(`lane ${lane}: bridge.json carries a member this format does not name: "${unnamed}".`);
        }
        if (typeof manifest.script !== 'string' || manifest.script === '') {
            throw new Error(`lane ${lane}: bridge.json is missing a string "script".`);
        }
        if (typeof manifest.command !== 'string' || manifest.command === '') {
            throw new Error(`lane ${lane}: bridge.json is missing a string "command".`);
        }
        const members = readMembers(lane, manifest.members);
        const answeredBy = readOperations(lane, manifest.operations, members);
        const operations = Object.keys(answeredBy);

        let prepare;
        if (manifest.prepare !== undefined) {
            const given = manifest.prepare;
            if (typeof given !== 'object' || given === null || Array.isArray(given)) {
                throw new Error(`lane ${lane}: bridge.json's "prepare" is not a JSON object.`);
            }
            const unnamedPrepare = Object.keys(given).find((name) => !PREPARE_MEMBERS.includes(name));
            if (unnamedPrepare !== undefined) {
                throw new Error(
                    `lane ${lane}: bridge.json's "prepare" carries a member `
                    + `this format does not name: "${unnamedPrepare}".`,
                );
            }
            if (typeof given.command !== 'string' || given.command === '') {
                throw new Error(`lane ${lane}: bridge.json's "prepare" is missing a string "command".`);
            }
            if (given.args !== undefined && !Array.isArray(given.args)) {
                throw new Error(`lane ${lane}: bridge.json's "prepare.args" is not an array.`);
            }
            prepare = { command: given.command, args: given.args ?? [] };
        }

        bridges[lane] = {
            script: manifest.script,
            command: manifest.command,
            operations,
            members,
            answeredBy,
            ...(prepare ? { prepare } : {}),
        };
    }

    return bridges;
}

function isPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// `members`: which parts of the binding answer, each described in one line.
// The description is for a reader of bridge.json; only the name reaches a
// record.
function readMembers(lane, given) {
    if (!isPlainObject(given)) {
        throw new Error(`lane ${lane}: bridge.json is missing a "members" object.`);
    }
    const names = Object.keys(given);
    const members = {};
    for (const name of names) {
        if (!MEMBER_NAME.test(name)) {
            throw new Error(
                `lane ${lane}: bridge.json's member ${JSON.stringify(name)} is not a name of lowercase letters and digits.`,
            );
        }
        const description = given[name];
        if (typeof description !== 'string' || description.trim() === '' || /[\r\n]/.test(description)) {
            throw new Error(`lane ${lane}: bridge.json's member ${name} is not described: its value is one non-empty line.`);
        }
        members[name] = description;
    }
    return members;
}

// `operations`: which member answers each declared operation. The earlier
// shape was an array of names, and one still written that way is told so
// rather than read as an empty map.
function readOperations(lane, given, members) {
    if (Array.isArray(given)) {
        throw new Error(
            `lane ${lane}: bridge.json's "operations" is an array; `
            + 'it is now an object naming the member that answers each operation.',
        );
    }
    if (!isPlainObject(given)) {
        throw new Error(`lane ${lane}: bridge.json is missing an "operations" object.`);
    }
    const operations = Object.keys(given);
    const answeredBy = {};
    for (const operation of operations) {
        if (!Object.hasOwn(OPERATION_SHAPES, operation)) {
            throw new Error(`lane ${lane}: bridge.json carries an unknown operation: ${JSON.stringify(operation)}.`);
        }
        const member = given[operation];
        if (typeof member !== 'string' || !Object.hasOwn(members, member)) {
            throw new Error(
                `lane ${lane}: bridge.json's operation ${operation} names member ${JSON.stringify(member)}, `
                + 'which "members" does not declare.',
            );
        }
        answeredBy[operation] = member;
    }
    // A member that answers nothing would print as part of the binding in its
    // README and never appear in a record.
    const idle = Object.keys(members).find((name) => !Object.values(answeredBy).includes(name));
    if (idle !== undefined) {
        throw new Error(`lane ${lane}: bridge.json's member ${idle} answers no operation.`);
    }
    return answeredBy;
}

export const RUN_EXIT = { held: 0, disagreed: 1, incomplete: 2 };

// How much of a bridge's stderr is reprinted, in lines and in bytes. A bridge may
// write any amount there, and an operator reading a failure in a terminal
// is not helped by a megabyte of it scrolling past the reason it happened. The full
// size is always stated, so nothing is quietly dropped.
export const STDERR_LINE_LIMIT = 40;
export const STDERR_BYTE_LIMIT = 8000;

// One run, from an argument list to an exit code.
//
// Everything a test needs to steer is a parameter: the corpus path, the bridge
// table and where the two output streams go. The defaults are the real ones, so the
// shell wrapper passes nothing but the operator's arguments.
export async function runConformance({
    argv = [],
    corpusPath = DEFAULT_CORPUS_PATH,
    bridges,
    conformanceDir = CONFORMANCE_DIR,
    timeoutMs = 10000,
    out = lineWriter(process.stdout),
    err = lineWriter(process.stderr),
} = {}) {
    const language = argv[0];
    if (language === undefined || language.startsWith('-')) {
        err('usage: node conformance-primitives/_shared/driver/run.mjs <language> [--set <set> | --op <operation> | --case <id> ...]');
        return RUN_EXIT.incomplete;
    }

    // Evaluated here rather than as a default parameter value, so a manifest that
    // fails to load becomes this function's own `REFUSED` and exit 2 instead of an
    // uncaught throw out of a default expression. A caller that hands its own
    // `bridges` (every test but the ones proving this discovery) uses it as given.
    let bridgeTable = bridges;
    if (!bridgeTable) {
        try {
            bridgeTable = loadBridges(conformanceDir);
        } catch (error) {
            err(`REFUSED: ${error.message}`);
            return RUN_EXIT.incomplete;
        }
    }

    const entry = bridgeTable[language];
    if (!entry) {
        const known = Object.keys(bridgeTable).join(', ');
        err(`REFUSED: no bridge is named ${JSON.stringify(language)}. This driver knows ${known}.`);
        return RUN_EXIT.incomplete;
    }

    let selected;
    try {
        selected = selectCases(loadCases(corpusPath), parseSelectors(argv.slice(1)));
    } catch (error) {
        if (error instanceof SelectionError) {
            err(`REFUSED: ${error.message}`);
            return RUN_EXIT.incomplete;
        }
        if (error instanceof CorpusError) {
            err('REFUSED: the case corpus could not be read, so no run was started.');
            for (const problem of error.problems) err(`  ${problem}`);
            return RUN_EXIT.incomplete;
        }
        throw error;
    }

    return askAndJudge({
        language,
        entry,
        selected,
        conformanceDir,
        timeoutMs,
        out,
        err,
        words: {
            accountedFor: 'the batch',
            answeredEvery: 'every selected case',
            held: `${selected.length} selected case(s) as this corpus expects`,
        },
    });
}

// The four steps that are the same whatever the questions were: make the bridge
// runnable, ask it once, judge what came back, print and exit.
//
// Both entry points end here, so there is one place a bridge is started, one
// judge, one output discipline and one mapping from an outcome to an exit code. A
// sixth failure branch is added once. What differs between a corpus run and a
// vector run is the questions and three sentences, so the sentences are the
// parameter: a verdict says what was measured, and what was measured is a frozen
// corpus in one case and a set of recorded vectors in the other.
//
// `words` names those three: `accountedFor` follows "the answers do not account
// for", `answeredEvery` follows "answered", and `held` is the whole tail of the
// `HELD` line after the language.
export async function askAndJudge({ language, entry, selected, conformanceDir, timeoutMs, out, err, words }) {
    const unavailableOperations = [...new Set(selected.map(({ op }) => op))]
        .filter((operation) => !entry.operations.includes(operation));
    if (unavailableOperations.length > 0) {
        err(`INCOMPLETE: the ${language} bridge does not declare operation(s) ${unavailableOperations.join(', ')}.`);
        printSelected(err, selected);
        return RUN_EXIT.incomplete;
    }
    const unavailable = bridgeUnavailable(scriptPath(entry, conformanceDir));
    if (unavailable !== null) {
        err(`UNAVAILABLE: the ${language} bridge ${unavailable}`);
        printSelected(err, selected);
        return RUN_EXIT.incomplete;
    }

    if (entry.prepare) {
        const prepared = await prepareBridge({
            command: entry.prepare.command,
            args: entry.prepare.args ?? [],
            cwd: conformanceDir,
        });
        if (prepared.outcome === INCOMPLETE) {
            err(`INCOMPLETE: the ${language} bridge could not be made runnable: ${prepared.reason}.`);
            err(`  ${prepared.detail}`);
            printSelected(err, selected);
            printStderr(err, `${language} preparation step`, prepared.stderr);
            return RUN_EXIT.incomplete;
        }
    }

    // The batch is asked of a program that is already runnable, so `timeoutMs` covers
    // answering and nothing before it.
    const answered = await askBatch({
        command: commandFor(entry, conformanceDir),
        args: entry.args ?? [],
        requests: selected.map(({ id, op, input }) => ({ id, op, input })),
        timeoutMs,
        cwd: conformanceDir,
    });

    if (answered.outcome === INCOMPLETE) {
        err(`INCOMPLETE: the ${language} bridge did not answer this batch: ${answered.reason}.`);
        err(`  ${answered.detail}`);
        printSelected(err, selected);
        printStderr(err, `${language} bridge`, answered.stderr);
        return RUN_EXIT.incomplete;
    }

    const judged = validateResults({ selected, results: answered.results });

    if (judged.status === 'incomplete') {
        err(`INCOMPLETE: the ${language} bridge answered, and the answers do not account for ${words.accountedFor}.`);
        for (const problem of judged.problems) err(`  ${problem}`);
        for (const one of judged.disagreements) {
            err(`  ${one.id} also disagreed: expected ${JSON.stringify(one.expected)}, answered ${JSON.stringify(one.observed)}`);
            for (const line of invisibleDifference(one.expected, one.observed)) err(`  ${line}`);
        }
        printSelected(err, selected);
        printStderr(err, `${language} bridge`, answered.stderr);
        return RUN_EXIT.incomplete;
    }

    if (judged.status === 'disagreed') {
        err(`DISAGREED: the ${language} bridge answered ${words.answeredEvery}, and ${judged.disagreements.length} answer(s) differ.`);
        for (const one of judged.disagreements) {
            err(`  ${one.id} (${one.op})`);
            err(`    expected: ${JSON.stringify(one.expected)}`);
            err(`    answered: ${JSON.stringify(one.observed)}`);
            for (const line of invisibleDifference(one.expected, one.observed)) err(`    ${line}`);
        }
        printSelected(err, selected);
        return RUN_EXIT.disagreed;
    }

    out(`HELD: ${language} answered ${words.held}.`);
    printSelected(out, selected);
    return RUN_EXIT.held;
}

// Why a named language's bridge cannot be asked, or `null` when it can.
//
// This reads the source file, because the fault it reports is a language whose bridge
// this driver has not written: the file is there, it is a file, and it can be read.
//
// This function leaves the launched command unchecked, because it cannot reach it yet.
// A bridge's `command` is launched through a file the preparation step produces, which
// does not exist yet when this runs, or a file already checked in. An earlier revision asked for
// `X_OK` on the source whenever `command` and `script` were the same string, and at the
// time the check answered nothing and fired for nobody. A command that cannot be
// executed is reported by the launch itself, as an incomplete run carrying
// `spawn-failed` and the system's own reason.
export function bridgeUnavailable(script) {
    let stat;
    try {
        stat = statSync(script);
    } catch {
        return `is not there: ${script}`;
    }
    if (!stat.isFile()) {
        return `is not a file: ${script}`;
    }
    try {
        accessSync(script, constants.R_OK);
    } catch {
        return `cannot be read: ${script}`;
    }
    return null;
}

// What is actually started for one language: a path inside the conformance
// directory, or the absolute path already written in a manifest.
export function commandFor(entry, conformanceDir) {
    return isAbsolute(entry.command) ? entry.command : resolve(conformanceDir, entry.command);
}

// Where one language's bridge source sits, read the same way: a path inside the
// conformance directory, or the absolute path already written in a manifest.
export function scriptPath(entry, conformanceDir) {
    return isAbsolute(entry.script) ? entry.script : resolve(conformanceDir, entry.script);
}

// The ids this run covered, always printed, always one per line, each beside the
// label its case carries. On a failure the ids are the operator's next command: copy
// half of them back as repeated `--case` arguments and the same contract runs the
// smaller batch. The label is on the same row because an opaque id says nothing on
// its own, and the label is the reason it stays on this side of the process boundary.
export function printSelected(write, selected) {
    write(`  selected ${selected.length} case(s):`);
    for (const one of selected) write(`    ${one.id} (${one.op}) ${one.label}`);
}

// How many code points of one value are spelled out before the count stands in for the
// rest. A conformance value is short, and a bridge answering a megabyte of text is not
// made clearer by a megabyte of `U+`.
export const CODE_POINT_LIMIT = 40;

// What a disagreement differs in, when reading the two printed lines cannot show it.
//
// The comparison itself is on bytes and is right to be: two spellings of the same text
// are two different answers, and a bridge that returns one where the corpus records the
// other has disagreed. A terminal composes both spellings the same way, so `expected:`
// and `answered:` above can be two lines that look like one line printed twice. This
// says what the eye cannot see. It says nothing at all while both values are printable
// ASCII, which is every value in the corpus today.
export function invisibleDifference(expected, observed) {
    const lines = [];
    if (!isObject(expected) || !isObject(observed)) return lines;

    for (const name of Object.keys(expected)) {
        const wanted = expected[name];
        const answered = observed[name];
        if (typeof wanted !== 'string' || typeof answered !== 'string') continue;
        if (wanted === answered) continue;
        if (printableAscii(wanted) && printableAscii(answered)) continue;

        const composition = wanted.normalize('NFC') === answered.normalize('NFC')
            ? ', the same text under Unicode normalization and not the same bytes'
            : '';
        lines.push(`  ${name} differs from code point ${firstDifference(wanted, answered)}${composition}:`);
        lines.push(`    expected ${codePoints(wanted)}`);
        lines.push(`    answered ${codePoints(answered)}`);
    }

    return lines;
}

// Where to start reading, counted in code points from one. Two values that share a
// long prefix are two long lines of `U+`, and the position says which column to look
// at rather than leaving the eye to compare them.
function firstDifference(wanted, answered) {
    const left = [...wanted];
    const right = [...answered];
    let at = 0;
    while (at < left.length && at < right.length && left[at] === right[at]) at += 1;
    return at + 1;
}

function codePoints(text) {
    const points = [...text];
    const spelled = points
        .slice(0, CODE_POINT_LIMIT)
        .map((one) => `U+${one.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    if (points.length > spelled.length) spelled.push(`... ${points.length - spelled.length} further code point(s)`);
    return spelled.join(' ');
}

function printableAscii(text) {
    return [...text].every((one) => one >= ' ' && one <= '~');
}

function isObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// Whatever a bridge wrote on stderr, reprinted with its size stated and its length
// capped. A bridge in a loop can write megabytes, and the line saying what went
// wrong is lost among them in a terminal.
export function printStderr(write, who, text) {
    const trimmed = (text ?? '').trim();
    if (trimmed === '') {
        write(`  the ${who} wrote nothing to stderr.`);
        return;
    }

    const bytes = Buffer.byteLength(trimmed, 'utf8');
    const lines = trimmed.split('\n');
    const kept = [];
    let keptBytes = 0;
    for (const line of lines) {
        if (kept.length >= STDERR_LINE_LIMIT) break;
        const size = Buffer.byteLength(line, 'utf8') + 1;
        if (keptBytes + size > STDERR_BYTE_LIMIT) break;
        kept.push(line);
        keptBytes += size;
    }

    const whole = kept.length === lines.length;
    write(`  the ${who} wrote ${bytes} byte(s) on ${lines.length} line(s) to stderr${whole ? ':' : `, and the first ${kept.length} line(s) follow:`}`);
    for (const line of kept) write(`    ${line}`);
    if (!whole) write(`    ... ${lines.length - kept.length} further line(s) not printed.`);
}

// A line writer that keeps working after a reader closes the pipe.
//
// `node conformance-primitives/_shared/driver/run.mjs php | head -1` closes the pipe
// as soon as it has its line, and an unhandled EPIPE would end the process on a
// failure the run did not have: exit 1 is the code for a bridge that answered
// wrongly, so a broken pipe could turn exit 0 into exit 1. This process exits on
// the verdict, and a reader that stopped reading does not change it.
const guardedStreams = new WeakSet();

export function lineWriter(stream, onError = (error) => { throw error; }) {
    function handleError(error) {
        if (error && (error.code === 'EPIPE' || error.code === 'ERR_STREAM_DESTROYED')) return;
        onError(error);
    }
    if (!guardedStreams.has(stream)) {
        guardedStreams.add(stream);
        stream.on('error', handleError);
    }
    return (line) => {
        try {
            stream.write(`${line}\n`);
        } catch (error) {
            handleError(error);
        }
    };
}

// When this file is started as a program rather than imported, the whole entry point
// is here: the arguments come in, the exit code goes out.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    let infrastructureFailed = false;
    function incomplete(error) {
        if (infrastructureFailed) return;
        infrastructureFailed = true;
        process.exitCode = RUN_EXIT.incomplete;
        // The diagnostic stream may itself be the failed infrastructure. Report
        // once, without recursively writing again if that stream cannot write.
        try {
            process.stderr.write(`INCOMPLETE: the driver failed unexpectedly: ${error?.message ?? String(error)}\n`);
        } catch {
            // The exit code still states that verification was incomplete.
        }
    }
    try {
        const exit = await runConformance({
            argv: process.argv.slice(2),
            out: lineWriter(process.stdout, incomplete),
            err: lineWriter(process.stderr, incomplete),
        });
        process.exitCode = infrastructureFailed ? RUN_EXIT.incomplete : exit;
    } catch (error) {
        incomplete(error);
    }
}

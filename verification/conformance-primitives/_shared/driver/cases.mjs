// The case corpus, and the selectors that narrow it.
//
// A case is `{id, set, label, op, input, expected, rationale}`, where `id` is
// `<set>/<suffix>`. The corpus lives at `conformance-primitives/_shared/cases/v1/cases.json` and
// is small, literal and conformance-owned: nothing here computes an expected value,
// and nothing here reads a vector.
//
// The bridge reads an opaque identifier, and the label stays on this side. The
// identifier travels to the bridge inside the request, so an identifier that says how
// its case comes out hands a bridge the answer: a probe that read its own identifier
// and ignored `input` held every case whose name ended in `-refused`. The readable
// text lives in `label`, which no bridge ever receives, and the runner prints
// identifier and label together so an operator narrowing with `--case` still reads a
// sentence.
//
// This file reads a closed case row. A row carrying a member this file does not name
// is a corpus written against a contract nobody agreed to, and reading it while
// ignoring the member would run a case whose author expected something else.
//
// This file reads the corpus with the duplicate-refusing reader. `JSON.parse` keeps
// the last spelling of a repeated member and reports nothing, so a run over a corpus
// carrying two `cases` members would cover one of them and report held over half the
// file. This is the one place that reader is used on an incoming document, because
// this document is a repository file we write rather than a bridge's answer.
//
// This file knows nothing about running a bridge. It does not know how a bridge is
// started, what a bridge answers, or how an answer is judged. It hands the runner a
// list of cases with their withheld expectations attached, and the runner decides
// which fields ever reach a bridge process.
//
// Each row states the wrong implementation it distinguishes in `rationale`, which
// the README's admission rule asks for. That text stays on this side with the
// label, and the loader requires it so no row enters the corpus without it.
//
// The loader rejects a bad corpus and reports no run verdict. Duplicate ids, an id
// whose prefix disagrees with its set and an operation nothing implements are all
// faults in the corpus itself. Reporting them as `disagreed` would name a bridge
// wrong for a file it never saw, and reporting them as a held run would gate on cases
// nobody could read.
//
// One invocation narrows on one axis. The valid lines are: no selector, exactly one
// `--set`, exactly one `--op`, or one or more `--case` with distinct ids. Repeated
// `--case` selects that exact group, because manual binary-tree isolation is the whole
// reason the group form exists. Everything else refuses, each for its own reason:
// `--set a --op b` reads as either an intersection or a union depending on who is
// looking; a union of sets is already a `--case` list; and the same id twice would
// have to be silently deduped in the one workflow built on group membership. This
// file refuses before any bridge process starts.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { DuplicateMemberError, parseNoDuplicateJson } from './protocol.mjs';
import { definedRefusals, observationProblem, OPERATIONS } from './validate-results.mjs';

export const DEFAULT_CORPUS_PATH = fileURLToPath(new URL('../cases/v1/cases.json', import.meta.url));

// Everything a case row carries, and nothing else.
const CASE_MEMBERS = ['id', 'set', 'label', 'op', 'input', 'expected', 'rationale'];

export class CorpusError extends Error {
    constructor(problems) {
        super(Array.isArray(problems) ? problems.join('\n') : String(problems));
        this.name = 'CorpusError';
        this.problems = Array.isArray(problems) ? problems : [String(problems)];
    }
}

export class SelectionError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SelectionError';
    }
}

// The corpus on disk, checked once, in file order.
//
// The path is a parameter so a test can point this at a fixture corpus. The default
// is the real one, so a runner never has to name it and two callers cannot end up
// reading two different files by accident.
export function loadCases(corpusPath = DEFAULT_CORPUS_PATH) {
    let text;
    try {
        text = readFileSync(corpusPath, 'utf8');
    } catch (error) {
        throw new CorpusError([`${corpusPath}: the case corpus could not be read: ${error.message}`]);
    }

    let parsed;
    try {
        parsed = parseNoDuplicateJson(text).value;
    } catch (error) {
        if (error instanceof DuplicateMemberError) {
            throw new CorpusError([`${corpusPath}: the case corpus repeats a JSON member, so which cases a run covers depends on which copy a parser kept: ${error.message}`]);
        }
        throw new CorpusError([`${corpusPath}: the case corpus is not readable JSON: ${error.message}`]);
    }

    // The corpus is written by hand, so both a bare array and an object carrying a
    // `cases` array are read the same way. Anything else says nothing about which
    // cases a run covers.
    let rows;
    if (Array.isArray(parsed)) {
        rows = parsed;
    } else if (parsed && typeof parsed === 'object' && Array.isArray(parsed.cases)) {
        rows = parsed.cases;
    } else {
        throw new CorpusError([`${corpusPath}: the case corpus holds neither an array of cases nor a "cases" array.`]);
    }

    if (rows.length === 0) {
        throw new CorpusError([`${corpusPath}: the case corpus holds no cases, so a run would cover nothing.`]);
    }

    const problems = [];
    const seen = new Set();
    const cases = [];

    rows.forEach((row, index) => {
        const at = `${corpusPath}: case ${index}`;
        if (!row || typeof row !== 'object' || Array.isArray(row)) {
            problems.push(`${at} is not a JSON object.`);
            return;
        }
        const { id, set, label, op, input, expected, rationale } = row;
        const named = typeof id === 'string' && id !== '' ? `${corpusPath}: ${id}` : at;

        const members = Object.keys(row);
        const unknown = members.filter((name) => !CASE_MEMBERS.includes(name));
        const absent = CASE_MEMBERS.filter((name) => !members.includes(name));
        if (unknown.length > 0 || absent.length > 0) {
            problems.push(`${named} carries {${members.join(', ')}}, and a case carries {${CASE_MEMBERS.join(', ')}} exactly.`);
            return;
        }

        if (typeof id !== 'string' || id === '') {
            problems.push(`${at} carries no id, and a case is selected and reported by its id.`);
            return;
        }
        if (seen.has(id)) {
            problems.push(`${named} appears more than once, and one case is observed once.`);
            return;
        }
        seen.add(id);

        if (typeof set !== 'string' || set === '') {
            problems.push(`${named} names no set.`);
            return;
        }
        if (!id.startsWith(`${set}/`) || id.slice(set.length + 1) === '') {
            problems.push(`${named} is not "${set}/<suffix>", and an id states the set it belongs to.`);
        }
        if (typeof label !== 'string' || label === '') {
            problems.push(`${named} carries no label, and the readable text is what an operator reads beside an opaque id.`);
        }
        if (typeof rationale !== 'string' || rationale === '') {
            problems.push(`${named} carries no rationale, and a row states the wrong implementation it distinguishes.`);
        }
        if (!OPERATIONS.includes(op)) {
            problems.push(`${named} names operation ${JSON.stringify(op ?? null)}, and this corpus carries ${OPERATIONS.join(', ')}.`);
            return;
        }
        if (!input || typeof input !== 'object' || Array.isArray(input)) {
            problems.push(`${named} carries no input object, and a bridge is asked with an input.`);
        }

        // The expected observation is held back from every bridge, and it is still
        // checked here. An expectation outside the operation's well-formed shape
        // could never be met, and a run held to it would report a bridge failure
        // for a corpus fault. The refusal code is checked against the defined list
        // on this side only: a bridge answering an undefined code has answered and
        // is told it answered wrongly, while a corpus expecting one is broken.
        const badExpectation = observationProblem(op, expected);
        if (badExpectation !== null) {
            problems.push(`${named} expects ${badExpectation}`);
        } else if (typeof expected.refused === 'string' && !definedRefusals(op).includes(expected.refused)) {
            problems.push(`${named} expects refusal ${JSON.stringify(expected.refused)}, and ${op} defines ${definedRefusals(op).join(', ')}.`);
        }

        cases.push({ id, set, label, op, input, expected, rationale });
    });

    if (problems.length > 0) throw new CorpusError(problems);
    return cases;
}

// The sets this corpus holds, in corpus order, each with the operations its cases
// ask for.
//
// A lane declares the operations its bridge answers. A set asking for one the lane
// has not declared is unsupported for that lane, which the contract states as its
// own outcome: the lane is never asked the set, and the run never reports a hold
// over cases nobody ran. Grouping cases into sets by the operations they need is
// what makes that outcome per set rather than per case, so a lane answering four of
// the seven operations still holds the four sets it can answer.
export function corpusSets(cases) {
    const sets = [];
    const byName = new Map();
    for (const one of cases) {
        if (!byName.has(one.set)) {
            const entry = { set: one.set, operations: [] };
            byName.set(one.set, entry);
            sets.push(entry);
        }
        const entry = byName.get(one.set);
        if (!entry.operations.includes(one.op)) entry.operations.push(one.op);
    }
    return sets;
}

// The selectors on a command line, read into one shape, or a refusal saying which
// rule the line broke.
//
// `args` is everything after the language name. The language itself is the runner's
// business, because the runner knows which bridges exist.
export function parseSelectors(args) {
    const sets = [];
    const ops = [];
    const caseIds = [];

    for (let index = 0; index < args.length; index += 1) {
        const argument = args[index];
        let flag = argument;
        let value = null;

        const equals = argument.indexOf('=');
        if (argument.startsWith('--') && equals !== -1) {
            flag = argument.slice(0, equals);
            value = argument.slice(equals + 1);
        }

        if (flag !== '--set' && flag !== '--op' && flag !== '--case') {
            throw new SelectionError(`${argument} is not a selector, and this runner takes --set, --op and --case only.`);
        }
        if (value === null) {
            index += 1;
            if (index >= args.length) {
                throw new SelectionError(`${flag} names nothing.`);
            }
            value = args[index];
        }
        if (value === '') {
            throw new SelectionError(`${flag} names nothing.`);
        }

        if (flag === '--set') sets.push(value);
        if (flag === '--op') ops.push(value);
        if (flag === '--case') caseIds.push(value);
    }

    const kinds = [];
    if (sets.length > 0) kinds.push('--set');
    if (ops.length > 0) kinds.push('--op');
    if (caseIds.length > 0) kinds.push('--case');
    if (kinds.length > 1) {
        throw new SelectionError(
            `${kinds.join(' and ')} were given together, and one run narrows one way. Use one selector kind, or repeat --case.`,
        );
    }
    if (sets.length > 1) {
        throw new SelectionError(`--set was given ${sets.length} times, and one run walks one set. Repeat --case to select an exact group.`);
    }
    if (ops.length > 1) {
        throw new SelectionError(`--op was given ${ops.length} times, and one run walks one operation. Repeat --case to select an exact group.`);
    }

    return { sets, ops, caseIds };
}

// The cases one selection covers, in corpus order, or a refusal naming what was
// wrong. This refuses a selector that matches nothing: an empty run that exits 0
// reports a hold over cases it never asked about.
export function selectCases(cases, selection) {
    const { sets = [], ops = [], caseIds = [] } = selection;

    if (sets.length === 1) {
        const set = sets[0];
        const known = [...new Set(cases.map((one) => one.set))];
        if (!known.includes(set)) {
            throw new SelectionError(`no set is named ${JSON.stringify(set)}. The corpus carries ${known.join(', ')}.`);
        }
        return refuseEmpty(cases.filter((one) => one.set === set), `--set ${set}`);
    }

    if (ops.length === 1) {
        const op = ops[0];
        const known = [...new Set(cases.map((one) => one.op))];
        if (!OPERATIONS.includes(op)) {
            throw new SelectionError(`no operation is named ${JSON.stringify(op)}. This corpus carries ${OPERATIONS.join(', ')}.`);
        }
        return refuseEmpty(cases.filter((one) => one.op === op), `--op ${op}. The corpus exercises ${known.join(', ')}`);
    }

    if (caseIds.length > 0) {
        const byId = new Map(cases.map((one) => [one.id, one]));
        const missing = caseIds.filter((id) => !byId.has(id));
        if (missing.length > 0) {
            throw new SelectionError(`no case is named ${missing.map((id) => JSON.stringify(id)).join(', ')}.`);
        }
        const repeated = caseIds.filter((id, index) => caseIds.indexOf(id) !== index);
        if (repeated.length > 0) {
            throw new SelectionError(`--case names ${[...new Set(repeated)].join(', ')} more than once, and one case is asked once.`);
        }
        // Corpus order, so a group selection and a full run report their cases the
        // same way round.
        return refuseEmpty(cases.filter((one) => caseIds.includes(one.id)), '--case');
    }

    return refuseEmpty(cases, 'the whole corpus');
}

function refuseEmpty(selected, what) {
    if (selected.length === 0) {
        throw new SelectionError(`${what} selects no case, and a run that covers nothing cannot hold.`);
    }
    return selected;
}

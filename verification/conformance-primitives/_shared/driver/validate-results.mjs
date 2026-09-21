// The withheld expectations, held up against what a bridge answered.
//
// This is the only file that ever sees an expected value beside an observed one.
// The bridge is asked with `{id, op, input}` and answers with `{id, op,
// observation}`, so everything read here about correctness is read on this side of
// the process boundary.
//
// This file takes the selected cases and a list of results, and answers with one
// status per selected case folded into 0, 1 or 2, plus sentences a runner can print.
// It spawns nothing, reads no corpus off disk and prints nothing.
//
// Each case matches or it does not, and the fold says only that. Every
// case in this corpus is checked the same way, so there is no per-case class here, no
// vocabulary that reads differently depending on one, and no set-level walk. The fold
// below is the whole of it: incomplete first, disagreed second, otherwise held.
//
// This file counts the results before it compares them. Every selected `(id, op)` must
// appear exactly once. A missing result, a duplicate, a result about an id nobody
// asked for, a result carrying the wrong operation for a known id, and any member the
// contract does not name are all `incomplete`. None of them is a disagreement: a run
// that cannot say which answer belongs to which question has not measured anything to
// disagree about. Result order carries no meaning, because a batch is a set of
// questions rather than a sequence.
//
// This file draws the 1/2 line on well-formedness and not on the value list. An
// observation is well formed when it is an object carrying exactly one of its
// operation's defined member sets, each member of the defined type, or `{refused}`
// as a string. A bridge that answers `{bytes: "..."}` where the contract says
// `{bytesHex}`, answers `{}`, answers both a value and a `refused`, or answers a
// member of the wrong type has failed to answer in the contract at all, and that
// is incomplete: calling it a disagreement would report a finding about bytes
// nobody compared.
//
// A well-formed answer that is wrong counts as a disagreement, whatever it says. That
// includes a refusal where success was expected, a refusal code this operation does
// not define, and the wrong defined code on a refusal case. The bridge reached an
// answer in the contract's vocabulary and the answer differs from the expectation,
// which is exactly what exit 1 means. The defined codes are still written down
// here, and `cases.mjs` holds the corpus to them, because an expectation naming a
// code nothing defines is a fault in the corpus rather than a finding about a
// bridge.

// The operations this driver carries, and the closed observation each answers
// with. `success` names the exact member set of a successful observation. `refusals`
// names the codes the operation defines: `cases.mjs` checks the corpus against that
// list, and no run's exit turns on it, because a bridge answering an undefined code
// has answered, and answered wrongly.
//
// Each is one primitive a runtime's own crypto library reaches, and each refusal is
// a fact about bytes: a spelling that does not decode, a tag that does not verify,
// and a ciphertext that does not open. An operation whose answer a runtime's own
// library cannot reach is not in this list, because reaching it would mean every
// bridge reimplementing the harness once per language.
//
// This table is the contract's own table, `contract/v1/bridge.md` under
// Observations, and the seven names and their member sets are read from there.
//
// A seal, a derivation and a point encoding define no refusal. A seal that cannot be
// computed is a request the bridge could not serve, which is a nonzero exit and not
// an answer about bytes.
export const OPERATION_SHAPES = {
    'decode-base64url': { success: { bytesHex: 'string' }, refusals: ['invalid_base64url'] },
    'hkdf-sha256': { success: { okmBase64url: 'string' }, refusals: [] },
    'open-aes-gcm': { success: { plaintextBase64url: 'string' }, refusals: ['authentication_failed'] },
    'seal-aes-gcm': { success: { ciphertextBase64url: 'string' }, refusals: [] },
    'ecdh-p256': { success: { sharedSecretBase64url: 'string' }, refusals: [] },
    'p256-point': { success: { pointBase64url: 'string' }, refusals: [] },
    'open-rsa-oaep': { success: { plaintextBase64url: 'string' }, refusals: ['unseal_failed'] },
};

export const OPERATIONS = Object.keys(OPERATION_SHAPES);

// The members a result carries, and no others.
const RESULT_MEMBERS = ['id', 'op', 'observation'];

// The codes one operation defines. The corpus is held to these; a bridge is not,
// because an undefined code is a wrong answer rather than a broken one.
export function definedRefusals(op) {
    return OPERATION_SHAPES[op] ? OPERATION_SHAPES[op].refusals : [];
}

// Why one observation is not well formed under one operation, or `null` when it is.
// Read on the answered side to draw the 1/2 line, and on the expected side so a
// corpus cannot state an expectation outside the operation's vocabulary.
export function observationProblem(op, observation) {
    const shape = OPERATION_SHAPES[op];
    if (!shape) return `an observation for unknown operation ${JSON.stringify(op ?? null)}.`;
    if (!observation || typeof observation !== 'object' || Array.isArray(observation)) {
        return `${describe(observation)}, and an observation is a JSON object.`;
    }

    const members = Object.keys(observation);
    if (members.includes('refused')) {
        if (members.length > 1) {
            return `${describe(observation)}, and a refusal carries the code and nothing beside it.`;
        }
        if (typeof observation.refused !== 'string') {
            return `refused as ${describe(observation.refused)}, and a refusal code is a string.`;
        }
        return null;
    }

    const wanted = Object.keys(shape.success);
    const missing = wanted.filter((name) => !members.includes(name));
    const extra = members.filter((name) => !wanted.includes(name));
    if (missing.length > 0 || extra.length > 0) {
        return `${describe(observation)}, and ${op} answers {${wanted.join(', ')}} or {refused}.`;
    }

    for (const name of wanted) {
        const type = shape.success[name];
        const value = observation[name];
        if (type === 'string' && typeof value !== 'string') {
            return `${name} as ${describe(value)}, and ${op} answers ${name} as a string.`;
        }
        if (type === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) {
            return `${name} as ${describe(value)}, and ${op} answers ${name} as a finite number.`;
        }
    }

    return null;
}

// One batch of results, read against the cases that were selected.
//
// Returns `status`, one of `held`, `disagreed` and `incomplete`, plus two things a
// runner prints: `problems`, one sentence per accounting or shape fault in the
// order they were found, and `disagreements`, one `{id, op, expected, observed}`
// per case that answered inside the contract and answered wrongly. The runner turns
// that status into an exit code, because the runner is the process that exits.
export function validateResults({ selected, results }) {
    const problems = [];
    const disagreements = [];
    const outcomes = [];

    if (!Array.isArray(results)) {
        throw new TypeError('validateResults is handed the results array the transport already read.');
    }

    // Results grouped by the id they claim. A result that claims no readable id is
    // reported against its position, because there is no case to report it against.
    const claimed = new Map();
    results.forEach((result, index) => {
        const at = `result ${index}`;
        if (!result || typeof result !== 'object' || Array.isArray(result)) {
            problems.push(`${at} is ${describe(result)}, and a result is a JSON object.`);
            outcomes.push('incomplete');
            return;
        }

        const members = Object.keys(result);
        const unknown = members.filter((name) => !RESULT_MEMBERS.includes(name));
        const absent = RESULT_MEMBERS.filter((name) => !members.includes(name));
        const label = typeof result.id === 'string' && result.id !== '' ? result.id : at;
        if (unknown.length > 0 || absent.length > 0) {
            problems.push(`${label} carries {${members.join(', ')}}, and a result carries {${RESULT_MEMBERS.join(', ')}} exactly.`);
            outcomes.push('incomplete');
            return;
        }
        if (typeof result.id !== 'string' || result.id === '') {
            problems.push(`${at} names no case id, so nothing can be said about which question it answers.`);
            outcomes.push('incomplete');
            return;
        }
        if (typeof result.op !== 'string' || result.op === '') {
            problems.push(`${result.id} names no operation, and a result answers one asked (id, op) pair.`);
            outcomes.push('incomplete');
            return;
        }

        const list = claimed.get(result.id) ?? [];
        list.push(result);
        claimed.set(result.id, list);
    });

    const wanted = new Set(selected.map((one) => one.id));

    for (const id of claimed.keys()) {
        if (wanted.has(id)) continue;
        problems.push(`${id} was answered and was not selected, so this batch answered a question it was not asked.`);
        outcomes.push('incomplete');
    }

    for (const one of selected) {
        const list = claimed.get(one.id) ?? [];
        if (list.length === 0) {
            problems.push(`${one.id} (${one.op}) was selected and no result answers it.`);
            outcomes.push('incomplete');
            continue;
        }
        if (list.length > 1) {
            problems.push(`${one.id} was answered ${list.length} times, and one question is answered once.`);
            outcomes.push('incomplete');
            continue;
        }

        const result = list[0];
        if (result.op !== one.op) {
            // Results are keyed by the (id, op) pair, so a result with another op
            // answers a question nobody asked and leaves the asked one unanswered.
            problems.push(`${one.id} was asked as ${one.op} and answered as ${JSON.stringify(result.op)}, so ${one.id} (${one.op}) has no answer.`);
            outcomes.push('incomplete');
            continue;
        }

        const bad = observationProblem(one.op, result.observation);
        if (bad !== null) {
            problems.push(`${one.id} answered ${bad}`);
            outcomes.push('incomplete');
            continue;
        }

        if (!sameObservation(one.expected, result.observation)) {
            disagreements.push({ id: one.id, op: one.op, expected: one.expected, observed: result.observation });
            outcomes.push('disagreed');
            continue;
        }

        outcomes.push('held');
    }

    return { status: foldOutcomes(outcomes), problems, disagreements };
}

// The per-case outcomes, folded into the one word a run leaves with.
//
// Incomplete outranks disagreed, the same order the exit codes are in: a run
// that could not account for every case it selected has not shown that
// the rest were wrong, and answering `disagreed` there would claim the batch was
// measured end to end. A fold over nothing is incomplete for the same reason: a batch
// where no case was judged never comes back `held`.
export function foldOutcomes(outcomes) {
    if (outcomes.length === 0) return 'incomplete';
    if (outcomes.includes('incomplete')) return 'incomplete';
    if (outcomes.includes('disagreed')) return 'disagreed';
    return 'held';
}

// Two observations agree when they carry the same members with the same values.
// Member order inside an object carries no meaning, and every value under comparison here
// is a string compared byte for byte after JSON decoding.
export function sameObservation(a, b) {
    return canonical(a) === canonical(b);
}

function canonical(value) {
    if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
    if (value && typeof value === 'object') {
        const names = Object.keys(value).sort();
        return `{${names.map((name) => `${JSON.stringify(name)}:${canonical(value[name])}`).join(',')}}`;
    }
    return JSON.stringify(value ?? null);
}

function describe(value) {
    if (value === null || value === undefined) return 'nothing';
    if (Array.isArray(value)) return 'an array';
    if (typeof value === 'object') return JSON.stringify(value);
    return JSON.stringify(value);
}

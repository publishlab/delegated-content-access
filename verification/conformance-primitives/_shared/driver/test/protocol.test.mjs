// `protocol.mjs` reads one JSON value out of a bridge's stdout. These tests drive
// that reader one failing spelling at a time.
//
// The transport's process handling, its timeout, its byte cap and its envelope
// checks are driven end to end in `operation-bridge.test.mjs`, against a bridge
// that fails on demand. The reader those runs go through is tested here on strings,
// because a string literal holds a nearly-JSON spelling exactly as written.
//
// The duplicate-refusing reader reads two documents, a bridge's answer and the case
// corpus, and both callers need it to refuse a repeated member at any nesting level
// and to keep every value JSON.parse would have produced.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { DuplicateMemberError, parseNoDuplicateJson, parseSingleJson } from '../protocol.mjs';

describe('reading one value out of a bridge\'s stdout', () => {
    it('tells an empty stdout, a malformed one and two values apart', () => {
        assert.equal(parseSingleJson('   \n').reason, 'no-stdout');
        assert.equal(parseSingleJson('not json').reason, 'malformed-json');
        assert.equal(parseSingleJson('{"a": ').reason, 'malformed-json');
        assert.equal(parseSingleJson('{} {}').reason, 'multiple-responses');
        assert.equal(parseSingleJson('{}{}').reason, 'multiple-responses');
        assert.equal(parseSingleJson('{} tail').reason, 'malformed-json');
        assert.deepEqual(parseSingleJson('{"a":1}').value, { a: 1 });
    });

    it('accepts a value written with leading and trailing whitespace', () => {
        const parsed = parseSingleJson('\n  {"a":1}  \n\n');
        assert.equal(parsed.ok, true);
        assert.deepEqual(parsed.value, { a: 1 });
    });

    it('names whoever wrote the empty stdout, so a failure says which process', () => {
        assert.match(parseSingleJson('', 'php bridge').detail, /the php bridge wrote nothing/);
    });

    it('refuses a repeated member rather than keeping one spelling of it', () => {
        assert.equal(parseSingleJson('{"a":1,"a":2}').reason, 'duplicate-member');
    });
});

describe('the duplicate-refusing reader', () => {
    it('refuses a repeated member at every nesting level', () => {
        assert.throws(() => parseNoDuplicateJson('{"a":{"b":1,"b":2}}'), DuplicateMemberError);
        assert.throws(() => parseNoDuplicateJson('{"a":[{"b":1,"b":2}]}'), DuplicateMemberError);
        assert.throws(() => parseNoDuplicateJson('{"cases":[],"cases":[]}'), /repeats JSON member "cases"/);
    });

    it('reads the values JSON.parse reads, and says where the document ended', () => {
        const parsed = parseNoDuplicateJson('{"a":[1,-2.5,true,null,"x\\"y"],"b":{}}  ');
        assert.deepEqual(parsed.value, { a: [1, -2.5, true, null, 'x"y'], b: {} });
        assert.equal(parsed.end, '{"a":[1,-2.5,true,null,"x\\"y"],"b":{}}'.length);
    });

    it('preserves __proto__ as an own JSON member', () => {
        const parsed = parseSingleJson('{"__proto__":{"safe":true}}');
        assert.equal(parsed.ok, true);
        assert.equal(Object.hasOwn(parsed.value, '__proto__'), true);
        assert.deepEqual({ ...parsed.value.__proto__ }, { safe: true });
    });
});

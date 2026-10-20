import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { ProcessBinding } from "../register.mjs";
import {
  bridgeValueTypes,
  decodeValueAsync,
  encodeValueAsync,
  runtimeValueTypes,
} from "../serializer.mjs";

/**
 * Proves that a target adapter receives, uses and returns every value type it
 * advertises in `valueTypes`. Each adapter's `self-test/bridge-values.test.js`
 * calls `testBridgeValues` with its bridge definition and a native fixture
 * module. The fixture exports three functions, and the expected values stay in
 * `corpus.json` on this side:
 *
 * - `identity(value)` returns `value`.
 * - `inspect(value, ...operands)` returns a plain JSON reading of `value`:
 *   `null`, a boolean or a number as itself; a string as its UTF-8 octets and
 *   bytes as their octets, both `{ octets: "<lowercase hex>" }`; `undefined`
 *   as `{ undefined: true }`; an instant as `{ epochMilliseconds: n }`; a list
 *   or record as the list or record of its entries' readings. For a key,
 *   `operands` are a message and a 64-octet `r || s` signature, and the reading
 *   is `{ verifies: boolean }` from an ECDSA P-256 SHA-256 verification with
 *   that key.
 * - `transform(value)` builds a new value: `null` and `undefined` stay; a
 *   boolean is negated; a number is negated; a string gains a trailing `é`;
 *   bytes gain a trailing `0xff` octet; an instant moves one millisecond later;
 *   a list is reversed after each entry is transformed; a record keeps its
 *   member names and transforms each member; a key is exported and imported
 *   again.
 *
 * A case runs only when the adapter advertises every value type it uses. The
 * call takes the route the bridge proxy takes: a `sync` member through the
 * synchronous binding call, an `async` member through the asynchronous one.
 */

/** @typedef {import("../serializer.mjs").BridgeValue} BridgeValue */
/** @typedef {import("../register.mjs").BridgeDefinition} BridgeDefinition */
/** @typedef {{ type: string, name: string, value: BridgeValue, operands?: BridgeValue[], inspect: BridgeValue, transform: BridgeValue }} BridgeValueCase */

export const CORPUS_VERSION = 1;

/** @type {{ version: number, cases: BridgeValueCase[] }} */
export const corpus = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));

/** @param {BridgeValueCase} entry */
export function caseValueTypes(entry) {
  /** @type {Set<string>} */
  const types = new Set();
  for (const value of [entry.value, ...(entry.operands ?? []), entry.inspect, entry.transform])
    bridgeValueTypes(value, types);
  return types;
}

/**
 * @param {ProcessBinding} binding
 * @param {import("../register.mjs").ModuleMember} member
 * @param {unknown[]} input
 */
async function invoke(binding, member, input) {
  return member.callShape === "async"
    ? binding.callAsync(member.id, input)
    : binding.call(member.id, input);
}

/**
 * Registers the corpus check and one test that starts `definition`, then runs
 * each case the adapter's `valueTypes` admit through `identity`, `inspect` and
 * `transform` as subtests.
 *
 * @param {BridgeDefinition} definition
 * @param {{ sourceModule: string, skip?: string }} options
 *   `sourceModule` names the fixture module. `skip` reports every test as
 *   skipped with that reason.
 */
export function testBridgeValues(definition, options) {
  const skip = options.skip === undefined ? {} : { skip: options.skip };

  test("the bridge-values corpus proves every value type the serializer may advertise", () => {
    assert.equal(corpus.version, CORPUS_VERSION);
    const proven = new Set(corpus.cases.map((entry) => entry.type));
    assert.deepEqual(
      [...runtimeValueTypes].filter((type) => !proven.has(type)),
      [],
    );
    assert.deepEqual(
      [...proven].filter((type) => !runtimeValueTypes.includes(type)),
      [],
    );
    for (const entry of corpus.cases)
      assert.ok(caseValueTypes(entry).has(entry.type), `${entry.type}: ${entry.name}`);
  });

  test(`the ${definition.id} adapter proves each value type it advertises`, skip, async (t) => {
    const binding = await new ProcessBinding(definition).start();
    try {
      const advertised = binding.capabilities?.valueTypes ?? [];
      assert.deepEqual(
        advertised.filter((type) => !corpus.cases.some((entry) => entry.type === type)),
        [],
        "every advertised value type has a corpus case",
      );
      const unadvertised = runtimeValueTypes.filter((type) => !advertised.includes(type));
      if (unadvertised.length) t.diagnostic(`not advertised: ${unadvertised.join(", ")}`);
      const members = binding.describeModule(options.sourceModule);
      /** @param {string} name */
      const member = (name) => {
        const found = members.find((candidate) => candidate.sourceExport === name);
        assert.ok(found, `${options.sourceModule} exports ${name}`);
        return found;
      };
      for (const entry of corpus.cases) {
        if (![...caseValueTypes(entry)].every((type) => advertised.includes(type))) continue;
        const title = `${entry.type}: ${entry.name}`;
        await t.test(`${title}: identity`, async () => {
          const result = await invoke(binding, member("identity"), [
            await decodeValueAsync(entry.value),
          ]);
          assert.deepEqual(await encodeValueAsync(result), entry.value);
        });
        await t.test(`${title}: inspect`, async () => {
          const input = [];
          for (const value of [entry.value, ...(entry.operands ?? [])])
            input.push(await decodeValueAsync(value));
          const result = await invoke(binding, member("inspect"), input);
          assert.deepEqual(await encodeValueAsync(result), entry.inspect);
        });
        await t.test(`${title}: transform`, async () => {
          const result = await invoke(binding, member("transform"), [
            await decodeValueAsync(entry.value),
          ]);
          assert.deepEqual(await encodeValueAsync(result), entry.transform);
        });
      }
    } finally {
      await binding.dispose();
    }
  });
}

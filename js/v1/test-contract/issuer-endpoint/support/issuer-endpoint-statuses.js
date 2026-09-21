// @ts-check

// The status expectation, owned by the contract and by nothing else.
//
// Its values say what an endpoint answers, and they are written here from the
// endpoint contract rather than copied from an implementation: a request the
// issuer refuses whole carries the status its refusal class deserves, while a
// request the issuer answered is 200 whether or not every coordinate in it
// opened. Reading either implementation's own status table to produce these
// numbers would make the two agree by construction and prove nothing, so the
// runner may not do it and `assertContractOwnsItsStatuses` below fails if a
// later edit tries.

import { readFileSync } from "node:fs";

const STATUS_TABLE_FILE = new URL("./issuer-endpoint-statuses.json", import.meta.url);

/** The raw text, kept so a test can prove one key carries one mapping. */
export const endpointStatusesSource = readFileSync(STATUS_TABLE_FILE, "utf8");

/** @type {{ success: number, partial: number, wholeRequest: Record<string, number> }} */
export const endpointStatuses = JSON.parse(endpointStatusesSource);

/**
 * The projection itself. A non-null top-level `code` is a whole-request
 * refusal and selects `wholeRequest`; anything else was answered, and only the
 * presence of per-coordinate errors separates a partial answer from a
 * complete one. A coordinate code such as `unseal_failed` never reaches
 * `wholeRequest`, because it never appears at the top level of an `expected`.
 *
 * The table is a parameter so a test can drive the selection with a probe
 * table and see that the three members are read independently.
 *
 * @param {{ success: number, partial: number, wholeRequest: Record<string, number> }} table
 * @param {{ code?: string | null, errors?: Record<string, string> }} expected
 * @returns {number}
 */
export function resolveStatus(table, expected) {
  const code = expected.code ?? null;
  if (code !== null) {
    if (!Object.hasOwn(table.wholeRequest, code)) {
      throw new Error(
        `the contract status table has no whole-request mapping for ${JSON.stringify(code)}`,
      );
    }
    return table.wholeRequest[code];
  }
  return Object.keys(expected.errors ?? {}).length > 0 ? table.partial : table.success;
}

/**
 * @param {{ code?: string | null, errors?: Record<string, string> }} expected
 * @returns {number}
 */
export function statusForVector(expected) {
  return resolveStatus(endpointStatuses, expected);
}

/**
 * The named cases that carry the status entries no reject vector reaches. Each
 * one perturbs a working request or its provisioning until the endpoint refuses
 * it with that code, then the contract compares the public `{ status, body }`
 * against the table entry. `errorDetail` is `code` here on purpose: a uniform
 * body would hide which refusal actually happened, and then a case that drifted
 * onto another code would still pass.
 *
 * @type {{ code: string, name: string, perturb: (setup: { base: any, rawRequest: string }) => { base: any, rawRequest: string } }[]}
 */
export const NON_VECTOR_STATUS_CASES = [
  {
    code: "invalid_json",
    name: "a body that never parses is refused before anything is read out of it",
    perturb({ base }) {
      return { base, rawRequest: '{"version":"1"' };
    },
  },
  {
    code: "body_too_large",
    name: "a body over the host limit is refused without being parsed",
    perturb({ base, rawRequest }) {
      return { base: { ...base, limits: { ...base.limits, maxBodyBytes: 8 } }, rawRequest };
    },
  },
  {
    code: "too_many_entries",
    name: "a request asking beyond the host entry limit is refused whole",
    perturb({ base, rawRequest }) {
      return {
        base: { ...base, limits: { ...base.limits, maxEntries: 1, maxEntriesPerGroup: 1 } },
        rawRequest,
      };
    },
  },
  {
    code: "bad_version",
    name: "a request naming a version this issuer does not speak is refused whole",
    perturb({ base, rawRequest }) {
      const document = JSON.parse(rawRequest);
      document.version = "9999";
      return { base, rawRequest: JSON.stringify(document) };
    },
  },
  {
    code: "unknown_key",
    name: "a keyId the issuer holds nothing for is refused whole",
    perturb({ base, rawRequest }) {
      return {
        base: {
          ...base,
          issuerKeys: {
            async get() {
              return undefined;
            },
          },
        },
        rawRequest,
      };
    },
  },
  {
    code: "unknown_publisher_key",
    name: "a publisher key the issuer cannot produce is refused whole",
    perturb({ base, rawRequest }) {
      return {
        base: { ...base, publisherRegistration: null },
        rawRequest,
      };
    },
  },
  {
    code: "bad_jwt",
    name: "a request carrying no resourceJWT is refused whole",
    perturb({ base, rawRequest }) {
      const document = JSON.parse(rawRequest);
      delete document.resourceJWT;
      return { base, rawRequest: JSON.stringify(document) };
    },
  },
  {
    code: "denied",
    name: "a reader granted nothing at all is refused, and refused differently",
    perturb({ base, rawRequest }) {
      return {
        base: {
          ...base,
          accessPolicy: {
            async decide() {
              return { contentNames: [], periodGrants: [], policyData: [] };
            },
          },
        },
        rawRequest,
      };
    },
  },
];

/**
 * The boundary guard. The contract runner and its support may read shared
 * vectors and their own files; they may not reach an implementation, and in
 * particular not an implementation's status table, because the table above was
 * written independently. Bindings are the one place that knows an
 * implementation by name, so they are not scanned.
 *
 * The forbidden name is assembled from parts so that this guard does not match
 * its own source text.
 *
 * @param {URL[]} sources
 */
export function assertContractOwnsItsStatuses(sources) {
  const contractRoot = new URL("../../", import.meta.url).href;
  const referenceStatusSource = ["Unlock", "Endpoint.js"].join("");
  const productStatusSource = ["Dca", "Unlock", "Endpoint"].join("");
  /** @type {string[]} */
  const failures = [];
  for (const source of sources) {
    const text = readFileSync(source, "utf8");
    const file = source.pathname.split("/").pop();
    for (const [, , specifier] of text.matchAll(/\bfrom\s+(['"])([^'"]+)\1/g)) {
      if (specifier.startsWith("node:")) continue;
      if (!new URL(specifier, source).href.startsWith(contractRoot)) {
        failures.push(`${file} imports ${specifier}, which is outside test-contract/`);
      }
    }
    if (text.includes(referenceStatusSource))
      failures.push(`${file} names ${referenceStatusSource}`);
    if (text.includes(productStatusSource)) failures.push(`${file} names ${productStatusSource}`);
  }
  return failures;
}

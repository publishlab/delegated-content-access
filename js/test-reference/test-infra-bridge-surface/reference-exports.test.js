// @ts-check
//
// The adopter entry points, loaded. `reference.mjs` is the one file a bridge in
// another repository imports, and `experiments/reference.mjs` is the same promise
// for the optional experiments rack. Both re-export rather than define, and a
// re-export naming a symbol its target no longer exports is a link error: the
// module throws when something loads it, and nothing else in this tree does.
// `import-boundary.test.js` resolves the paths those statements name and stops
// at `existsSync`, so a moved file is caught there and a renamed symbol behind
// an intact path is not.
//
// This file loads them. The baselines below spell that promise out: a dropped
// name breaks every consumer, and an added one is a name this tree is now on the
// hook for, so both move only with the surface.

import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The public testing surface, `reference.mjs`, in full. */
const REFERENCE_EXPORTS = [
  "AAD_DELIMITER",
  "CONTENT_KIND",
  "Client",
  "ContentKeyResolver",
  "ContentRepresentationOpener",
  "DcaData",
  "DcaRequest",
  "DcaRequestBuilder",
  "JsonDeliveryReader",
  "MarkupDeliveryReader",
  "NONCE_BYTES",
  "PERIOD_KEY_PROFILE",
  "PERIOD_KIND",
  "PeriodKeyCache",
  "RENDER_ID_BYTES",
  "ResponseAssociation",
  "TAG_BYTES",
  "base64urlDecode",
  "base64urlEncode",
  "bindFields",
  "bindValue",
  "checkEnvelopes",
  "contentAad",
  "contentKeyWrapNonce",
  "dcaTestBinding",
  "decrypt",
  "encrypt",
  "formatT",
  "isAccessGroup",
  "isContentName",
  "issuerEndpointContract",
  "issuerEndpointRejectVectorContract",
  "open",
  "openContent",
  "periodKeyProfile",
  "proofHash",
  "seal",
  "utf8Decode",
  "utf8Encode",
  "verify",
  "writeJsonDelivery",
];

/** The optional experiments rack surface, `experiments/reference.mjs`, in full. */
const EXPERIMENTS_EXPORTS = ["bindOnAccessGroup", "openOnAccessGroup", "sealOnAccessGroup"];

// The rack is optional: a consumer that needs only the standard reference can
// omit the whole directory, and this file says nothing about a tree without it.
const EXPERIMENTS_PRESENT = existsSync(
  fileURLToPath(new URL("../../experiments/reference.mjs", import.meta.url)),
);

/**
 * @param {Record<string, unknown>} namespace
 * @param {string[]} expected
 * @param {string} what
 */
function assertSurface(namespace, expected, what) {
  assert.deepEqual(Object.keys(namespace).sort(), expected, `${what}: the promised export names`);
  for (const name of expected) {
    assert.notEqual(namespace[name], undefined, `${what}: ${name} is bound to nothing`);
  }
}

describe("The entry points a consumer outside this tree imports", () => {
  test("reference.mjs loads and carries exactly its promised names", async () => {
    assertSurface(await import("../../reference.mjs"), REFERENCE_EXPORTS, "reference.mjs");
  });

  test(
    "experiments/reference.mjs loads and carries exactly its promised names",
    { skip: !EXPERIMENTS_PRESENT },
    async () => {
      assertSurface(
        await import("../../experiments/reference.mjs"),
        EXPERIMENTS_EXPORTS,
        "experiments/reference.mjs",
      );
    },
  );
});

// @ts-check
//
// Which failure keeps which identity in the chain path.
//
// A coordinate whose sealed material does not open reports the uniform
// per-coordinate `unseal_failed`, and so does material that opens to something
// other than one 32-byte chain state: both are facts about the blob that
// arrived. An off-grid label, a cutoff outside the supplied window or any
// other construction refusal is a defect in this issuer, and it keeps its
// typed code. The carrier reader keeps the same separation: every error it
// absorbs is a typed refusal, and it records a duplicate window as state.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { Clock } from "../../../demo/actors/Clock.js";
import { Random } from "../../../demo/actors/Random.js";
import { Sealer } from "../../../core-publisher/Sealer.js";
import { PeriodKeyCache } from "../../../adapter-client/PeriodKeyCache.js";
import { DcaRequest, parseDcaRequest } from "../../../core-shared--client-issuer/DcaRequest.js";
import { base64urlEncode, utf8Encode } from "../../../core-shared/codec.js";
import { DcaError } from "../../../core-shared/errors.js";
import {
  openingKeysOver,
  PublisherRegistrations,
} from "../../../demo/support/PublisherRegistrations.js";
import { Client } from "../../../test-lib/harnesses/client.js";
import { PeriodChainRequestBuilder } from "../core-client/PeriodChainRequestBuilder.js";
import { periodChainResponseInput } from "../core-client/periodChainResponseInput.js";
import { periodChainCapabilitySource } from "../core-issuer/periodChainCapabilitySource.js";
import { periodChainIssuerEngine } from "../core-issuer/periodChainIssuerEngine.js";
import { periodChainRequestInput } from "../core-issuer/periodChainRequestInput.js";
import { periodFamilyGeneration } from "../core-publisher/periodFamilyGeneration.js";
import { periodFamilySupply } from "../core-publisher/periodFamilySupply.js";
import {
  periodChainCoordinate,
  periodChainLeafFromState,
  settlePeriodChainGeometry,
} from "../core-shared/periodChainConstruction.js";

const GROUP = "premium";
const OTHER = "archive";
const GEOMETRY = Object.freeze({ chainsPerDay: 2, periodMinutes: 15 });
const SETTLED = settlePeriodChainGeometry(GEOMETRY);
const AT = "2025-10-23T14:20:00Z";
const CAPTURED_AT_MS = Date.parse(AT);
const HONEST_T = "251023T2345";
const NEXT_WINDOW_T = "251024T2345";
const OFF_GRID_T = "251023T2342";
const STATE = base64urlEncode(new Uint8Array(16).fill(3));

/**
 * Run the issuer capability path over one real supplied carrier: select what
 * a two-period grant reaches, optionally inject an internal selection fault,
 * then produce it under the given opener.
 *
 * @param {object} run
 * @param {(sealed: unknown, coordinate: unknown) => Promise<any>} run.open
 * @param {'exact'|'chain'} [run.representation]
 * @param {(selected: any[]) => any[]} [run.amendSelected]
 */
async function capabilityRun({
  open,
  representation = "exact",
  amendSelected = (selected) => selected,
}) {
  const source = periodChainCapabilitySource({ representation });
  const request = new DcaRequest({
    periodChain: GEOMETRY,
    sealed: { periodChainKeys: { [GROUP]: { [HONEST_T]: STATE } } },
  });
  const answer = source.selection(request, { capturedAtMs: CAPTURED_AT_MS })(GROUP, 2);
  assert.ok(
    "selected" in answer,
    "the carrier is valid, so selection selects before the injected fault",
  );
  return source.capabilities({ request, open })(
    GROUP,
    amendSelected(/** @type {any} */ (answer).selected),
  );
}

/** An opener that answers the bytes it was built with, as base does for a good blob. */
function openerAnswering(bytes) {
  return async () => ({ bytes });
}

describe("a derivation fault keeps its own identity", () => {
  test("an off-grid supplied label propagates as the construction fault it is", async () => {
    await assert.rejects(
      capabilityRun({
        open: openerAnswering(new Uint8Array(16).fill(9)),
        amendSelected: ([selection]) => [{ ...selection, targetTs: [OFF_GRID_T] }],
      }),
      (/** @type {any} */ error) => error instanceof DcaError && error.code === "bad_config",
      "a label off the family grid is a defect in this issuer, not a blob that would not open",
    );
  });

  test("a cutoff outside the supplied window propagates through the chain representation", async () => {
    await assert.rejects(
      capabilityRun({
        open: openerAnswering(new Uint8Array(16).fill(9)),
        representation: "chain",
        amendSelected: ([selection]) => [{ ...selection, targetTs: [NEXT_WINDOW_T] }],
      }),
      (/** @type {any} */ error) => error instanceof DcaError && error.code === "bad_config",
      "a walk asked to reach across windows is a defect in this issuer",
    );
  });

  test("a derivation the environment refuses reports bad_key and carries what WebCrypto threw", async () => {
    const { subtle } = globalThis.crypto;
    const real = subtle.deriveBits;
    const refusal = new Error("WebCrypto refused to derive");
    subtle.deriveBits = async () => {
      throw refusal;
    };
    try {
      await assert.rejects(
        periodChainLeafFromState({
          state: new Uint8Array(16).fill(5),
          accessGroup: GROUP,
          t: HONEST_T,
          geometry: SETTLED,
        }),
        (/** @type {any} */ error) =>
          error instanceof DcaError && error.code === "bad_key" && error.cause === refusal,
        "an environment fault keeps the bad_key code and the reason WebCrypto gave",
      );
    } finally {
      subtle.deriveBits = real;
    }
  });
});

describe("sealed material that does not open is the uniform per-coordinate error", () => {
  for (const representation of /** @type {const} */ (["exact", "chain"])) {
    test(`${representation}: material opening to the wrong width is one uniform coordinate error`, async () => {
      const capability = await capabilityRun({
        open: openerAnswering(new Uint8Array(31)),
        representation,
      });

      assert.equal(capability.periods.length, 1);
      assert.equal(capability.periods[0].t, HONEST_T);
      assert.equal(
        capability.periods[0].error.error,
        "unseal_failed",
        "a value that is not one chain state is malformed sealed material",
      );
    });

    test(`${representation}: an opener refusal is carried through unchanged`, async () => {
      const refusal = Object.freeze({ error: "unseal_failed", message: "the opener said so" });
      const capability = await capabilityRun({
        open: async () => ({ error: refusal }),
        representation,
      });

      assert.deepEqual(capability.periods, [{ t: HONEST_T, error: refusal }]);
    });
  }
});

const PUB = "https://www.news-site.example";
const ISSUER = "paywall_subscription_service";
const KEY_ID = "2025-10";
const SIGNING_KID = "sign-2025-10";
const NAME = "bodytext";

/** @param {object} payload */
function token(payload) {
  return `e30.${base64urlEncode(utf8Encode(JSON.stringify(payload)))}.x`;
}

/** @param {number} periodCount */
function policy(periodCount) {
  return {
    decide(/** @type {any} */ _claims, /** @type {any} */ requested) {
      return {
        contentNames: [],
        periodGrants: requested.accessGroups.map((/** @type {string} */ accessGroup) => ({
          accessGroup,
          periodCount,
        })),
      };
    },
  };
}

/** One sealed page, its registration and a relay client, as the issuer lane builds them. */
async function world() {
  const { subtle } = globalThis.crypto;
  const signingKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  const issuerKeys = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
  );
  const generation = periodFamilyGeneration({
    keyDerivationSecret: new Uint8Array(32).fill(7),
    geometry: GEOMETRY,
  });
  const sealer = new Sealer({
    origin: PUB,
    clock: new Clock(AT),
    random: new Random({ seed: 3 }),
    signingKeys: { [SIGNING_KID]: signingKeys.privateKey },
    periodKeySupply: periodFamilySupply({ families: { [GROUP]: generation }, chainWindows: 2 }),
    issuerSupplyPlanFor: () => ({ periodKeyDelivery: { [GROUP]: ["chain"] } }),
    issuers: [
      {
        issuerName: ISSUER,
        keyId: KEY_ID,
        algorithm: "ECDH-P256",
        publicKey: issuerKeys.publicKey,
        unlockUrl: "https://api.example.com/unlock",
      },
    ],
  });
  sealer.resource("123456", { section: "politics" });
  sealer.content(NAME, "<p>The council voted 7-2 to rezone the harbour.</p>", "text/html", {
    accessGroups: [GROUP],
  });
  const rendered = await sealer.seal();
  const page = JSON.parse(
    JSON.stringify({ ...rendered.dcaData, sealedContent: rendered.sealedContent }),
  );
  const registration = new PublisherRegistrations([
    {
      kid: SIGNING_KID,
      publicKey: signingKeys.publicKey,
      origin: PUB,
      openingKeys: openingKeysOver(
        {
          get: (/** @type {string} */ issuerName, /** @type {string} */ keyId) =>
            issuerName === ISSUER && keyId === KEY_ID
              ? { algorithm: "ECDH-P256", privateKey: issuerKeys.privateKey }
              : undefined,
        },
        [{ issuerName: ISSUER, keyId: KEY_ID }],
      ),
    },
  ]).get(SIGNING_KID);
  const client = new Client({
    publisherOrigin: PUB,
    cache: new PeriodKeyCache(),
    requestBuilderFactory: (/** @type {any} */ options) => new PeriodChainRequestBuilder(options),
  });

  /** @param {(document: any) => void} [amend] */
  function requestFor(amend) {
    const document = client.buildRequest(client.parse(page), ISSUER, [NAME]);
    if (amend) amend(document);
    return parseDcaRequest(JSON.stringify(document));
  }

  return { page, registration, requestFor };
}

test("a chain blob moved to another window is the uniform coordinate error, and its sibling answers", async () => {
  const { page, registration, requestFor } = await world();
  const terminals = Object.keys(page.issuerData[ISSUER].sealed.periodChainKeys[GROUP]).sort();
  assert.equal(
    terminals.length,
    2,
    "the render ships two stationary windows to move a blob between",
  );
  const request = requestFor((document) => {
    document.sealed.periodChainKeys[GROUP][terminals[0]] =
      document.sealed.periodChainKeys[GROUP][terminals[1]];
  });

  const result = await periodChainIssuerEngine({
    accessPolicy: policy(96),
    clock: new Clock(AT),
  }).unlock(request, registration);

  assert.deepEqual(
    Object.keys(result.errors),
    [`${GROUP}|${terminals[0]}`],
    "the moved blob is the one coordinate that fails",
  );
  assert.equal(
    result.errors[`${GROUP}|${terminals[0]}`].error,
    "unseal_failed",
    "a real BIND failure stays the uniform per-coordinate error",
  );
  assert.ok(
    Object.keys(result.periodKeys[GROUP] ?? {}).length > 0,
    "and the honest sibling window still answers",
  );
});

/**
 * Read a carrier while counting every `new Error(...)` the reading builds. A
 * generic `Error` would be the one error object in this path that is not a
 * `DcaError`, so a count of zero proves the sentinel is gone. It counts plain
 * `new Error(...)` built while the reading runs; the reader resolves every
 * family eagerly, so the whole reading happens inside the swap.
 *
 * @param {() => any} read
 */
function countingGenericErrors(read) {
  const RealError = globalThis.Error;
  let generic = 0;
  class CountedError extends RealError {
    constructor(/** @type {any[]} */ ...rest) {
      super(...rest);
      generic++;
    }
  }
  globalThis.Error = /** @type {any} */ (CountedError);
  try {
    const view = read();
    return { view, generic };
  } finally {
    globalThis.Error = RealError;
  }
}

/** Each carrier's own vocabulary over the one reading. */
const CARRIERS = [
  {
    carrier: "request",
    read: (/** @type {unknown} */ collection) =>
      periodChainRequestInput(
        new DcaRequest({
          version: "dca/1",
          issuerName: "issuer.example",
          sealed: { contentKeys: {}, periodChainKeys: collection },
          periodChain: GEOMETRY,
        }),
      ),
  },
  {
    carrier: "response",
    read: (/** @type {unknown} */ collection) =>
      periodChainResponseInput({
        keys: { periodChainKeys: collection },
        periodChain: GEOMETRY,
      }),
  },
];

describe("the carrier reader holds its refusals as state, not as a thrown sentinel", () => {
  for (const { carrier, read } of CARRIERS) {
    test(`${carrier}: two members in one window invalidate that family alone, untyped-error-free`, () => {
      const { view, generic } = countingGenericErrors(() =>
        read({
          [GROUP]: { [HONEST_T]: STATE, "251023T2330": STATE },
          [OTHER]: { [HONEST_T]: STATE },
        }),
      );

      assert.equal(
        view.family(GROUP).kind,
        "invalid",
        "two positions from one window invalidate the family collection",
      );
      assert.equal(view.family(OTHER).kind, "valid", "and the neighbour is untouched");
      assert.equal(
        generic,
        0,
        "a duplicate window is state the reading holds, never a thrown Error",
      );
    });

    test(`${carrier}: a label refusal invalidates its family, and the refusal is typed`, () => {
      const { view, generic } = countingGenericErrors(() =>
        read({
          [GROUP]: { [OFF_GRID_T]: STATE },
          [OTHER]: { [HONEST_T]: STATE },
        }),
      );

      assert.equal(
        view.family(GROUP).kind,
        "invalid",
        "an off-grid label carries no detail onward",
      );
      assert.equal(view.family(OTHER).kind, "valid");
      assert.equal(generic, 0, "the only errors this reading absorbs are typed refusals");
    });
  }

  test("the coordinate refusal the reader absorbs is a DcaError", () => {
    assert.throws(
      () => periodChainCoordinate(OFF_GRID_T, SETTLED),
      (/** @type {any} */ error) => error instanceof DcaError && error.code === "bad_config",
    );
  });
});

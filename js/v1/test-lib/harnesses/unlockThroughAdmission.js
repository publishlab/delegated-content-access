// @ts-check
//
// Composes the two public issuer calls a host makes to unlock a request: explicit
// admission through the processor, then `handleRequest` on the request admission
// returned. It reproduces exactly what the removed `UnlockEndpoint.post` bundled,
// including refusing a malformed body at admission, and returns the same wire
// `{ status, body }` response those tests read.
//
// It composes public calls only. It signs nothing, holds no keys, and runs no
// engine or protocol logic. A string body is admitted through the endpoint's own
// `handleDocument`, so the byte cap and invalid-JSON refusal stay where the
// processor owns them; an object or `DcaRequest` is admitted through the
// processor and, on admission, handed to `handleRequest`.
//
// This directory is the assert side of the suite. The run glob is
// `js/v1/test/*.test.js` and does not descend, so nothing here is collected as a
// test file.

import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js";

/**
 * @param {import('../../core-issuer/IssuerProcessor.js').IssuerProcessor} processor
 *   - the same processor the endpoint was constructed around
 * @param {import('../../ports/UnlockEndpoint.js').UnlockEndpoint} endpoint
 * @param {DcaRequest|object|string} request
 * @param {import('../../core-issuer/IssuerEngine.js').PublisherRegistration} registration
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function unlockThroughAdmission(processor, endpoint, request, registration) {
  if (typeof request === "string") {
    return (await endpoint.handleDocument(request, registration)).response;
  }

  const admission = processor.admit(
    request instanceof DcaRequest ? request : new DcaRequest(request),
  );
  if (admission.kind !== "admitted") return endpoint.refusal(admission).response;
  return (await endpoint.handleRequest({ request: admission.request, registration })).response;
}

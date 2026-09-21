// @ts-check
//
// The issuer side of a test that is not about the issuer: an endpoint that says
// how often it was called, and the request a client would have posted.
//
// This directory holds the assert side of the suite and may reach for node:test and
// node:assert. It is not `demo/scenarios/`, which has to keep loading in a page. The
// run glob is `js/v1/test/*.test.js` and does not descend, so nothing here is
// collected as a test file.

import { Client } from "./client.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { UnlockEndpoint } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { CONTENT_NAME, ISSUER_NAME } from "../../demo/scenarios/fixtures.js";
import { AllowAllPolicy } from "../../demo/support/AllowAllPolicy.js";
import { unlockThroughAdmission } from "./unlockThroughAdmission.js";

/**
 * An endpoint that counts what crossed it, so "zero calls" is an assertion.
 * A fresh engine each time: the count is per endpoint, and a test that made two
 * of them meant two.
 *
 * @param {import('../../core-issuer/IssuerEngine.js').PublisherRegistration} publisherRegistration
 * @returns {{ calls: { count: number }, unlock: (body: any) => Promise<any> }}
 */
export function countingEndpoint(publisherRegistration) {
  const processor = new IssuerProcessor(
    new IssuerEngine({
      accessPolicy: new AllowAllPolicy(),
    }),
    // This historical helper backs exact-period client/cache stories.
    { exactPeriodInput: true },
  );
  const endpoint = new UnlockEndpoint(processor);
  const calls = { count: 0 };
  return {
    calls,
    /** @param {any} body */
    async unlock(body) {
      calls.count++;
      return unlockThroughAdmission(processor, endpoint, body, publisherRegistration);
    },
  };
}

/**
 * The origin the delivery arrived from. A `Page` carries it beside its data, the
 * way a browser reads it off the document it loaded; a delivery handed over as
 * the wire object alone names it in the resource the publisher signed. This
 * harness has no origin of its own to fall back on.
 *
 * @param {any} page
 * @param {any} wire
 * @returns {any}
 */
function deliveryOriginOf(page, wire) {
  return typeof page?.publisherOrigin === "string" ? page.publisherOrigin : wire?.resource?.origin;
}

/**
 * The wire-shaped request a client would post for these names. Built through the
 * real client composition rather than written out, so a test cannot pass against
 * a shape the client has drifted away from.
 *
 * Takes a `Page` or the delivery form directly - the two families deliver a
 * render differently and both of them ask this the same question.
 *
 * @param {any} page
 * @param {string} [issuerName] - whose blobs the request carries. One issuer is
 *   the pinned case; a page carrying two is what makes this an argument.
 * @param {string[]} [names]
 * @returns {any}
 */
export function requestFor(page, issuerName = ISSUER_NAME, names = [CONTENT_NAME]) {
  const wire = typeof page?.asJson === "function" ? page.asJson() : page;
  const client = new Client({ publisherOrigin: deliveryOriginOf(page, wire) });
  return client.buildRequest(client.parse(wire), issuerName, names);
}

// @ts-check

// Direct-response browser composition over one issuer core. The host supplies
// trusted Origin observation, registration lookup, caller admission and the
// request clock. This entry performs the DCA admission order and lets the HTTP
// adapter own CORS and cache-control. Hosts with response transforms or
// transactional business commits use `admitBrowserRequest` in their own final
// response flow, as the reference demo does.

import { BrowserUnlockHttp } from "../adapter-issuer/BrowserUnlockHttp.js";
import { dcaError } from "../core-shared/errors.js";
import { signableOrigin } from "../core-shared/publisherOrigin.js";
import { admitBrowserRequest } from "./admitBrowserRequest.js";

/**
 * @param {object} config
 * @param {{ processor: import('../core-issuer/IssuerProcessor.js').IssuerProcessor,
 *   endpoint: import('../ports/UnlockEndpoint.js').UnlockEndpoint }} config.core
 * @param {(kid: string) => import('../core-issuer/IssuerEngine.js').PublisherRegistration|null|undefined|
 *   Promise<import('../core-issuer/IssuerEngine.js').PublisherRegistration|null|undefined>} config.registrationForKid
 * @param {(origin: string) => boolean|Promise<boolean>} config.preflight
 * @param {(hostContext: any, registration: import('../core-issuer/IssuerEngine.js').PublisherRegistration, authorization?: string) =>
 *   { kind: 'admitted', principal?: any, context?: any }|
 *   { kind: 'refused', status: number, code: string }|
 *   Promise<{ kind: 'admitted', principal?: any, context?: any }|
 *   { kind: 'refused', status: number, code: string }>} config.admitCaller
 * @param {{ now: () => Date }} config.clock
 * @param {boolean} [config.developmentHttpOrigin]
 * @param {boolean} [config.credentials]
 * @param {boolean} [config.authorization]
 * @returns {BrowserUnlockHttp}
 */
export function createBrowserIssuer({
  core,
  registrationForKid,
  preflight,
  admitCaller,
  clock,
  developmentHttpOrigin = false,
  credentials = false,
  authorization = false,
}) {
  if (
    typeof core?.processor?.admit !== "function" ||
    typeof core?.endpoint?.handleRequest !== "function" ||
    typeof core?.endpoint?.admissionRefusalBody !== "function" ||
    typeof registrationForKid !== "function" ||
    typeof preflight !== "function" ||
    typeof admitCaller !== "function" ||
    typeof clock?.now !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "createBrowserIssuer needs a core, registration lookup, preflight, caller admission and clock",
    );
  }
  if (typeof developmentHttpOrigin !== "boolean") {
    throw dcaError("bad_config", "developmentHttpOrigin is on or off");
  }

  return new BrowserUnlockHttp({
    credentials,
    authorization,
    errorBody: (code) => core.endpoint.admissionRefusalBody(code),
    originAdmission: {
      preflight: (origin) =>
        signableOrigin(origin, developmentHttpOrigin) === origin && preflight(origin),
      async admit(origin, body, hostContext, bearer) {
        const admitted = await admitBrowserRequest({
          processor: core.processor,
          endpoint: core.endpoint,
          document: body,
          origin,
          registrationForKid,
          developmentHttpOrigin,
          async beforeVerify(registration) {
            const caller = await admitCaller(hostContext, registration, bearer);
            if (caller?.kind === "refused") return caller;
            if (caller?.kind !== "admitted") {
              return { kind: "refused", status: 500, code: "internal_error" };
            }
            const now = clock.now();
            if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
              return { kind: "refused", status: 500, code: "internal_error" };
            }
            return {
              kind: "admitted",
              state: {
                capturedAtMs: now.getTime(),
                policyInput: {
                  principal: caller.principal ?? null,
                  ...(caller.context === undefined ? {} : { context: caller.context }),
                },
              },
            };
          },
        });
        if (admitted.kind === "refused") {
          const source = admitted.response;
          return {
            kind: "refused",
            response: {
              ...source,
              status: source?.status ?? admitted.status,
              body: core.endpoint.admissionRefusalBody(admitted.code),
            },
          };
        }
        return { kind: "admitted", context: admitted };
      },
    },
    async unlock(_body, context) {
      const admitted = context.admission;
      if (admitted.state === null) {
        throw dcaError("bad_config", "browser issuer caller admission supplied no request state");
      }
      const result = await core.endpoint.handleRequest({
        request: admitted.request,
        registration: admitted.registration,
        verification: admitted.claims,
        policyInput: admitted.state.policyInput,
        capturedAtMs: admitted.state.capturedAtMs,
      });
      return result.response;
    },
  });
}

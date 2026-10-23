// @ts-check
//
// The demo issuer actor registered with the simulated `Network`. It wraps the
// reusable issuer processor and `IssuerEngine` with issuer business data,
// failover admission, response transport, key lifecycle, refusal
// wording, and whole-request stats. Components under `demo/actors/issuer/` implement
// the mechanisms; this class runs them in order.
//
// That order is load bearing and remains visible across `#admitBrowser` and
// `#unlock`. Browser admission structurally admits the request, selects its
// exact publisher registration, authenticates, verifies the resourceJWT under
// that registration's key, requires the observed browser origin to equal the
// origin the publisher signed into it, applies whatever origin limit the
// registration carries, and only then selects and preflights response
// transport. The unlock then checks fallback admission, calls the reusable
// endpoint, trims a fallback response, applies transport, commits host policy
// data after delivery, and counts the outcome. Structural admission and the
// signed-origin comparison both run ahead of transport, access policy and
// private-key work. The auth gate runs ahead of the signature, so an
// unidentified caller is turned away without any asymmetric operation. The
// transport agreement waits for both origin checks: a client-bound preflight
// generates an ephemeral private key, and a request from an origin the
// publisher did not sign reaches no private key. A fallback's health gate
// sits behind the comparison: only an admitted request pays for a probe or
// receives `primary_healthy`. Admission refusals use the endpoint's refusal
// wording.
//
// Every refusal browser admission makes leaves without CORS permission: the
// page that reads an answer must be the one the publisher signed for, and
// until the comparison holds that is not known. The transport refusals after
// the comparison leave the same way, because admission returns them. Everything
// the unlock answers comes after the comparison, so the HTTP adapter gives it
// exact-origin permission, a denial included.
//
// Browser admission verifies once to compare the signed origin. The engine
// consumes that original verified result when its private provenance matches,
// otherwise verifying independently before policy and opening.
//
import { UnlockEndpoint, refusalBody } from "../../ports/UnlockEndpoint.js";
import { IssuerProcessor } from "../../core-issuer/IssuerProcessor.js";
import { IssuerEngine } from "../../core-issuer/IssuerEngine.js";
import { FailoverGate } from "./issuer/FailoverGate.js";
import { trimToCurrentPeriod } from "./issuer/trimToCurrentPeriod.js";
import { IssuerBusinessData } from "./issuer/IssuerBusinessData.js";
import { KeyDelivery } from "../../adapter-issuer/KeyDelivery.js";
import { BrowserUnlockHttp } from "../../adapter-issuer/BrowserUnlockHttp.js";
import { admitBrowserRequest } from "../../integration-issuer/admitBrowserRequest.js";
import { deliveredCoordinates } from "../../core-shared--client-issuer/responseKeys.js";
import { dcaError } from "../../core-shared/errors.js";

/** @import { DcaRequest } from "../../core-shared--client-issuer/DcaRequest.js" */

const TRANSPORT_MODES = ["direct", "client-bound"];

/**
 * `bad_config` is useful inside the application and not a request-facing
 * diagnosis. Match the processor boundary while leaving other fault-code
 * vocabulary unchanged until that separate decision is made.
 *
 * @param {unknown} cause
 * @returns {string}
 */
function requestFaultCode(cause) {
  const code = /** @type {any} */ (cause)?.code;
  return code === "bad_config" || !code ? "internal_error" : code;
}

const OPTIONS = [
  "clock",
  "network",
  "random",
  "issuerName",
  "operatingIssuerNames",
  "unlockUrl",
  "keyStore",
  "publisherRegistrations",
  "accessPolicy",
  "transportMode",
  "transportPolicy",
  "clientBoundProfile",
  "responseSections",
  "composedKinds",
  "role",
  "healthCheckUrl",
  "healthTtl",
  "probeTimeout",
  "emergencyUntil",
  "requireAuthentication",
  "errorDetail",
  "limits",
  "log",
  "businessData",
  "supportedVersions",
  "periodGrantKind",
  "periodKeyInput",
  "chainKeyProfile",
  "developmentHttpOrigin",
];

export class IssuerServer {
  #clock;
  #issuerName;
  #unlockUrl;
  /** @type {'primary'|'fallback'} */
  #role;

  /** @type {FailoverGate|null} */
  #failoverGate = null;

  /** A fallback-only, server-owned emergency window. */
  /** @type {number|null} */
  #emergencyUntil = null;

  /** @type {KeyDelivery} */
  #keyDelivery;

  /** @type {'direct'|'client-bound'|null} null when a policy decides per request */
  #mode;

  /** @type {boolean} the development profile the signed origin is read under */
  #developmentHttpOrigin = false;

  /** @type {{ modeFor: Function }|null} */
  #transportPolicy;

  /** Whether a request that names nobody this server knows gets past the door. */
  #requireAuthentication = false;

  /** @type {'code'|'uniform'} */
  #errorDetail = "code";

  /** What the issuer processor refuses before expensive work. */
  #limits = {};

  /** @type {{ refused: (record: any) => void }|null} */
  #log = null;

  /** @type {{ get: Function, rotate?: Function, retire?: Function }} */
  #keyStore;

  /** @type {{ get: Function, prepareOpeningKeyRotation?: Function }} */
  #publisherRegistrations;

  /** @type {IssuerProcessor} */
  #processor;

  /** @type {UnlockEndpoint} */
  #endpoint;

  /**
   * Identities, entitlements, and metered views held by this demo issuer.
   * A shared instance may be injected; otherwise this server keeps its own.
   */
  #businessData;

  #requests = 0;
  #grants = 0;
  #denials = 0;
  #refusals = 0;
  #faults = 0;
  #unsealFailures = 0;

  /**
   * @param {object} config
   * @param {{ now: () => Date }} config.clock
   * @param {{ serve: Function, serveDocument: Function, probe: Function }} config.network
   * @param {string} config.issuerName
   * @param {string[]} [config.operatingIssuerNames] - trusted issuer names
   *   this shared engine may serve. By default, this endpoint is scoped to its
   *   configured `issuerName`.
   * @param {string} config.unlockUrl
   * @param {{ get: Function, rotate?: Function, retire?: Function }} config.keyStore - `get(issuerName, keyId)`, duck-typed;
   *   `rotate` and `retire` are needed only when the matching server method is used
   * @param {{ get: Function, prepareOpeningKeyRotation?: Function }} config.publisherRegistrations - exact `get(kid)`,
   *   duck-typed. `prepareOpeningKeyRotation()` is
   *   needed only when this server's rotation method is used.
   * @param {import('../../core-issuer/IssuerEngine.js').AccessPolicy} config.accessPolicy - who may read what
   * @param {'primary'|'fallback'} [config.role]
   * @param {string} [config.healthCheckUrl] - where the primary's health lives:
   *   a primary serves it, a fallback reads it. One string, wired on both.
   * @param {number} [config.healthTtl] - how long a health answer is believed
   * @param {number} [config.probeTimeout] - what a probe waits before it calls it down
   * @param {number} [config.emergencyUntil] - fallback-only server time in
   *   milliseconds after which this demo's emergency authorization is closed
   * @param {{ bytes: (n: number) => Uint8Array }} [config.random] - the
   *   transport nonces, one per wrapped key. Required as soon as this server
   *   could answer client-bound.
   * @param {'direct'|'client-bound'} [config.transportMode] - pinned, so a
   *   test of one mode tests only that mode
   * @param {{ modeFor: Function }} [config.transportPolicy] - decides the mode
   *   per request, in place of a pinned one. For when the switch is the point.
   *   Called `modeFor(request, decision)` with the request-scoped decision view
   *   `{ principal, context }`, the same one snapshot the miss reads.
   * @param {{ METHOD: string, RANDOM_REQUIRED: boolean, seal: (clientPublicKey: any, options: any) => Promise<any> }} [config.clientBoundProfile] -
   *   the selected extension's issuer-side transport profile
   * @param {readonly Readonly<import('../../core-shared--client-issuer/responseKeys.js').ComposedSection>[]} [config.responseSections] -
   *   the response sections selected extensions declare, such as
   *   `createIssuerCore(...).responseSections`. Client-bound transport wraps
   *   their keys and refuses a body member none of them roots. None when left out.
   * @param {Readonly<Record<string, { width: number }>>} [config.composedKinds] -
   *   the transport-settled kind set for those sections' non-base kinds
   * @param {boolean} [config.requireAuthentication] - refuse a request that
   *   names nobody this server knows, before anything is verified or opened
   * @param {'code'|'uniform'} [config.errorDetail] - what a refusal says on
   *   the wire, this server's own admission refusals included
   * @param {{ maxBodyBytes?: number, maxEntries?: number, maxEntriesPerGroup?: number }} [config.limits] -
   *   what the port refuses before it reads. A member left out keeps the
   *   processor's finite reference default, so this server is bounded even
   *   when a deployment names no cap at all.
   * @param {{ refused: (record: any) => void }} [config.log] - this
   *   application's refusal observer: every refusal this server makes, at its
   *   admission gates and behind the endpoint alike, is reported here with its
   *   true code, whatever the wire was told to carry
   * @param {{ snapshot: Function, authenticate: Function, grant: Function, expire: Function, apply: Function, views: Function }} [config.businessData] - a shared business-state instance
   *   holding identities, entitlements and metered views. Two servers may be
   *   handed the same one to share those; health, stats and availability stay
   *   endpoint-local either way. Left out, this server keeps a store of its own.
   * @param {string[]} [config.supportedVersions] - the request versions this
   *   issuer's engine reads. Left out, the engine's own default set is used.
   * @param {'period-keys'|'chain-keys'} [config.periodGrantKind] - which reusable grant
   *   kind this issuer returns
   * @param {boolean} [config.periodKeyInput] - whether trusted route
   *   configuration selects period-key request processing
   * @param {{ issuerEngineFor: Function }} [config.chainKeyProfile] - the
   *   explicitly selected frozen chain-response composition
   * @param {boolean} [config.developmentHttpOrigin] - run this issuer under
   *   the development profile, which admits a render whose signed origin is
   *   http on a loopback host. Off unless a deployment says otherwise, and it
   *   never widens to a public host. The publisher's `Sealer` takes the same
   *   option under the same name, so a development world turns it on at both
   *   ends or at neither.
   */
  constructor(config) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `IssuerServer has no ${name} yet, and will not pretend to`,
        );
      }
    }

    const { clock, network, issuerName, unlockUrl, keyStore, publisherRegistrations } =
      config ?? {};
    for (const [name, value] of Object.entries({
      clock,
      network,
      issuerName,
      unlockUrl,
      keyStore,
      publisherRegistrations,
    })) {
      if (!value) throw dcaError("bad_config", `IssuerServer needs a ${name}`);
    }
    if (typeof publisherRegistrations.get !== "function") {
      throw dcaError("bad_config", "publisherRegistrations answers get(kid)");
    }

    const role = config.role ?? "primary";
    if (role !== "primary" && role !== "fallback") {
      throw dcaError("bad_config", `an issuer is primary or fallback, not ${JSON.stringify(role)}`);
    }
    // A fallback that cannot check the primary grants on hearsay, and this role
    // exists to avoid exactly that.
    if (role === "fallback" && !config.healthCheckUrl) {
      throw dcaError("bad_config", "a fallback needs the healthCheckUrl it decides from");
    }
    if (config.emergencyUntil !== undefined && !Number.isFinite(config.emergencyUntil)) {
      throw dcaError("bad_config", "an emergencyUntil is a finite server timestamp");
    }
    if (role !== "fallback" && config.emergencyUntil !== undefined) {
      throw dcaError("bad_config", "only a fallback has an emergency authorization window");
    }
    if (role === "fallback" && config.periodGrantKind === "chain-keys") {
      throw dcaError("bad_config", "a fallback cannot trim a chain-key grant yet");
    }

    // This application pins a transport mode or injects a policy that
    // selects one per request. `KeyDelivery` applies the selected mode.
    if (config.transportMode !== undefined && config.transportPolicy !== undefined) {
      throw dcaError(
        "bad_config",
        "a server has a transport mode or a policy that decides one, never both",
      );
    }
    if (
      config.transportPolicy !== undefined &&
      typeof config.transportPolicy?.modeFor !== "function"
    ) {
      throw dcaError(
        "bad_config",
        "a transportPolicy is an object with a modeFor(request, decision)",
      );
    }
    const pinned = config.transportPolicy === undefined ? (config.transportMode ?? "direct") : null;
    if (pinned !== null && !TRANSPORT_MODES.includes(pinned)) {
      throw dcaError("unsupported_option", `${pinned} transport is not a mode this issuer has`);
    }
    if (config.random !== undefined && typeof config.random?.bytes !== "function") {
      throw dcaError("bad_config", "a random is an object with a bytes(n)");
    }
    const profile = config.clientBoundProfile ?? null;
    if (
      profile !== null &&
      (typeof profile.METHOD !== "string" ||
        typeof profile.RANDOM_REQUIRED !== "boolean" ||
        typeof profile.seal !== "function")
    ) {
      throw dcaError(
        "bad_config",
        "a clientBoundProfile has a string METHOD, boolean RANDOM_REQUIRED, and a seal(clientPublicKey, options) function",
      );
    }
    const couldWrap = pinned === "client-bound" || config.transportPolicy !== undefined;
    if (couldWrap && profile === null) {
      throw dcaError("bad_config", "client-bound transport needs an injected clientBoundProfile");
    }
    if (couldWrap && profile?.RANDOM_REQUIRED && config.random === undefined) {
      throw dcaError(
        "bad_config",
        `${profile.METHOD} client-bound transport needs an injected Random`,
      );
    }
    if (config.periodKeyInput !== undefined && typeof config.periodKeyInput !== "boolean") {
      throw dcaError("bad_config", "periodKeyInput is boolean");
    }
    this.#mode = /** @type {'direct'|'client-bound'|null} */ (pinned);
    this.#transportPolicy = config.transportPolicy ?? null;
    this.#keyDelivery = new KeyDelivery({
      ...(config.random === undefined ? {} : { random: config.random }),
      ...(profile === null ? {} : { profile }),
      ...(config.responseSections === undefined
        ? {}
        : { composedSections: [...config.responseSections] }),
      ...(config.composedKinds === undefined ? {} : { composedKinds: config.composedKinds }),
    });

    this.#clock = clock;
    this.#issuerName = issuerName;
    this.#unlockUrl = unlockUrl;
    this.#role = role;
    this.#failoverGate =
      role === "fallback"
        ? new FailoverGate({
            clock,
            network,
            healthCheckUrl: /** @type {string} */ (config.healthCheckUrl),
            healthTtl: config.healthTtl,
            probeTimeout: config.probeTimeout,
            caller: this,
          })
        : null;
    this.#emergencyUntil = role === "fallback" ? (config.emergencyUntil ?? null) : null;
    this.#keyStore = /** @type {any} */ (keyStore);
    this.#publisherRegistrations = /** @type {any} */ (publisherRegistrations);

    if (
      config.requireAuthentication !== undefined &&
      typeof config.requireAuthentication !== "boolean"
    ) {
      throw dcaError("bad_config", "requireAuthentication is on or off, nothing in between");
    }
    this.#requireAuthentication = config.requireAuthentication ?? false;

    // The deployment injects a shared business-state instance: two
    // servers handed the same one hold one set of identities, entitlements
    // and metered views between them. This server keeps its own stats, its
    // own health and its own availability either way. When nothing
    // is injected this server keeps a store of its own.
    if (config.businessData !== undefined) {
      const holds = ["snapshot", "authenticate", "grant", "expire", "apply", "views"];
      if (
        holds.some(
          (name) =>
            typeof (/** @type {Record<string, unknown>|null} */ (config.businessData)?.[name]) !==
            "function",
        )
      ) {
        throw dcaError(
          "bad_config",
          "a businessData holds snapshot, authenticate, grant, expire, apply and views",
        );
      }
    }
    this.#businessData = config.businessData ?? new IssuerBusinessData();

    // The endpoint defines and validates `errorDetail` and `limits`, so one
    // place decides what a cap and refusal wording mean. This application
    // observes every refusal itself, and nothing else does, so it checks the
    // log's shape here, where it reads it.
    this.#errorDetail = /** @type {'code'|'uniform'} */ (config.errorDetail ?? "code");
    this.#limits = config.limits ?? {};
    if (config.log !== undefined && typeof config.log?.refused !== "function") {
      throw dcaError("bad_config", "a log is an object with a refused(record)");
    }
    this.#log = config.log ?? null;

    if (typeof config.accessPolicy?.decide !== "function") {
      throw dcaError(
        "bad_config",
        "an accessPolicy is an object with a decide(claims, requested, input)",
      );
    }

    if (
      config.developmentHttpOrigin !== undefined &&
      typeof config.developmentHttpOrigin !== "boolean"
    ) {
      throw dcaError("bad_config", "developmentHttpOrigin is a profile that is on or off");
    }
    this.#developmentHttpOrigin = config.developmentHttpOrigin ?? false;

    // This application composes which engine answers; the ordinary engine
    // knows no such mode. The ordinary engine answers the presented
    // coordinates, and a separate engine the chain-key profile supplies answers
    // with chain keys. This server never names the derivation.
    const engineOptions = {
      operatingIssuerNames: config.operatingIssuerNames ?? [issuerName],
      accessPolicy: config.accessPolicy,
      supportedVersions: config.supportedVersions,
      developmentHttpOrigin: this.#developmentHttpOrigin,
    };
    let engine;
    if (config.periodGrantKind === "chain-keys") {
      if (typeof config.chainKeyProfile?.issuerEngineFor !== "function") {
        throw dcaError("bad_config", "chain grants need an injected chainKeyProfile");
      }
      engine = config.chainKeyProfile.issuerEngineFor({ ...engineOptions, clock });
    } else {
      engine = new IssuerEngine(engineOptions);
    }

    // This application runs structural admission: it constructs the
    // processor with the caps it configures and runs admission before policy
    // and key work. The port is handed
    // that same processor and admits nothing of its own in the application
    // path. Its caps and wording are the deployment's answer to what may be
    // sent and what a refusal says; reaching the compatibility call directly
    // is not a way around either.
    this.#processor = new IssuerProcessor(engine, {
      limits: this.#limits,
      capabilityEncoders: /** @type {any} */ (engine).capabilityEncoders ?? {},
      selectedExtensions: /** @type {any} */ (engine).selectedExtensions ?? [],
      periodKeyInput: config.periodKeyInput ?? false,
    });
    this.#endpoint = new UnlockEndpoint(this.#processor, this.#portOptions());

    // The server registers its own url with the network, because it already
    // holds that url in its configuration. A network told the same string
    // separately would be a second place for it to be wrong.
    const browserHttp = new BrowserUnlockHttp({
      originAdmission: {
        // This simulated POST-only route enables no preflight origins.
        // Canonical syntax alone does not satisfy an origin policy. A real
        // HTTP host must supply its selected preflight policy separately.
        preflight: () => false,
        admit: (
          /** @type {string} */ origin,
          /** @type {any} */ payload,
          /** @type {any} */ hostContext,
        ) => this.#admitBrowser(origin, payload, hostContext),
      },
      unlock: (/** @type {any} */ payload, /** @type {any} */ context) =>
        this.#unlock(payload, context),
      credentials: true,
    });
    /** @type {any} */ (network).serveDocument(
      unlockUrl,
      (/** @type {string} */ document, /** @type {any} */ context) =>
        browserHttp.handle({
          method: context.method ?? "POST",
          origin: context.origin,
          contentType: context.contentType,
          body: document,
          hostContext: context,
        }),
    );
    if (role === "primary" && config.healthCheckUrl) {
      network.serve(config.healthCheckUrl, () => ({
        status: 200,
        body: { healthy: true, issuerName: this.#issuerName },
      }));
    }
  }

  /**
   * What both compatibility and network calls are configured with.
   *
   * @returns {object}
   */
  #portOptions() {
    return { errorDetail: this.#errorDetail };
  }

  /**
   * An admission refusal: made from deployment state before the reusable
   * endpoint is reached, and worded exactly as that endpoint words its own.
   *
   * @param {number} status
   * @param {string} code
   * @returns {{ status: number, body: any }}
   */
  #refuse(status, code) {
    this.#log?.refused({ status, code });
    return { status, body: refusalBody(code, this.#errorDetail, { issuerName: this.#issuerName }) };
  }

  /** @returns {string} */
  get issuerName() {
    return this.#issuerName;
  }

  /** @returns {string} */
  get unlockUrl() {
    return this.#unlockUrl;
  }

  /** @returns {'primary'|'fallback'} */
  get role() {
    return this.#role;
  }

  /** Compatibility endpoint: a library caller skips the network. */
  get endpoint() {
    return this.#endpoint;
  }

  /**
   * The processor behind that endpoint. A library caller that skips the network
   * admits its request through this first and hands the endpoint the miss, so it
   * composes the two public calls the network path runs rather than a shortcut.
   *
   * This handle exists for migration and tests. A
   * reusable integration composes `IssuerProcessor` and `UnlockEndpoint`
   * directly; this actor keeps owning its own request path. Do not read
   * `IssuerServer.processor` as the integration seam.
   */
  get processor() {
    return this.#processor;
  }

  /**
   * @param {string} user
   * @param {Record<string, any>} [entitlement]
   * @returns {void}
   */
  grant(user, entitlement = {}) {
    this.#businessData.grant(user, entitlement);
  }

  /**
   * @param {string} user
   * @returns {void}
   */
  expire(user) {
    this.#businessData.expire(user);
  }

  /**
   * @param {string|{ user?: string }} [credential]
   * @returns {object|null}
   */
  authenticate(credential) {
    return this.#businessData.authenticate(credential);
  }

  /**
   * @param {string} user
   * @returns {string[]}
   */
  views(user) {
    return this.#businessData.views(user);
  }

  /**
   * @param {string} keyId
   * @param {{ algorithm: string, privateKey: CryptoKey }} entry
   * @param {string} [oldKeyId] - restrict a multi-keyset rotation to views
   *   that already address this issuer coordinate
   * @returns {void}
   */
  rotateKey(keyId, entry, oldKeyId = undefined) {
    if (typeof keyId !== "string" || !entry?.privateKey) {
      throw dcaError("bad_config", "a rotation is a keyId and the key that answers to it");
    }
    if (typeof (/** @type {any} */ (this.#keyStore).rotate) !== "function") {
      throw dcaError(
        "bad_config",
        "rotateKey needs a keyStore with rotate(issuerName, keyId, entry)",
      );
    }
    if (typeof this.#publisherRegistrations.prepareOpeningKeyRotation !== "function") {
      throw dcaError(
        "bad_config",
        "rotateKey needs publisher registrations that can prepareOpeningKeyRotation",
      );
    }
    // This does every registration-state check before the key store changes.
    // The returned commit only touches the selected, already-validated views.
    const extendRegistrations = this.#publisherRegistrations.prepareOpeningKeyRotation(
      this.#issuerName,
      keyId,
      oldKeyId,
    );
    if (typeof extendRegistrations !== "function") {
      throw dcaError(
        "bad_config",
        "publisher registrations did not prepare an issuer-key rotation",
      );
    }
    /** @type {any} */ (this.#keyStore).rotate(this.#issuerName, keyId, entry);
    extendRegistrations();
  }

  /**
   * @param {string} keyId
   * @returns {void}
   */
  retireKey(keyId) {
    if (typeof keyId !== "string" || keyId.length === 0) {
      throw dcaError("bad_config", "a retirement names a keyId");
    }
    if (typeof (/** @type {any} */ (this.#keyStore).retire) !== "function") {
      throw dcaError("bad_config", "retireKey needs a keyStore with retire(issuerName, keyId)");
    }
    /** @type {any} */ (this.#keyStore).retire(this.#issuerName, keyId);
  }

  /**
   * Select one transport mode before anything is opened. A pinned mode answers
   * directly; a policy is asked per request.
   *
   * @param {DcaRequest} request
   * @param {{ principal: any, context: any }} state - the request-scoped
   *   decision view, the one business-state read this request decides from.
   *   Forwarded to the policy as-is; this method reads none of its fields.
   * @returns {'direct'|'client-bound'}
   */
  #modeFor(request, state) {
    const asked = this.#transportPolicy
      ? this.#transportPolicy.modeFor(request, state)
      : this.#mode;
    if (typeof asked !== "string" || !TRANSPORT_MODES.includes(asked)) {
      throw dcaError(
        "bad_transport_policy",
        `the transport policy answered ${JSON.stringify(asked)}, which is not a mode`,
      );
    }
    return /** @type {'direct'|'client-bound'} */ (asked);
  }

  /**
   * Admit one browser-profile request before the reusable HTTP adapter calls
   * the issuer operation. It admits only a request whose resourceJWT verifies
   * under the selected registration's key and whose signed origin equals the
   * observed one. Later transport refusals retain that verified admission and
   * carry exact-origin CORS permission. The
   * returned context is the one request-scoped view: admitted request,
   * publisher registration, verified claims, origin, principal, time and
   * business snapshot. The composition does not repeat the registration
   * lookup or snapshot; the engine consumes the original verified result when
   * its request, token, key and origin mode still match, otherwise verifying again.
   *
   * @param {string} origin
   * @param {string} document
   * @param {{ credential?: any }} [hostContext]
   * @returns {Promise<{ kind: 'admitted', context: any }|{ kind: 'refused', response: any, cors?: boolean }>}
   */
  async #admitBrowser(origin, document, hostContext = {}) {
    this.#requests++;

    // The reusable boundary measures and freezes the raw request, selects this
    // issuer-held registration, verifies the signed resource and compares the
    // observed Origin before transport, policy, failover or opening work.
    const admission = await admitBrowserRequest({
      processor: this.#processor,
      endpoint: this.#endpoint,
      document,
      origin,
      registrationForKid: (kid) => this.#publisherRegistrations.get(kid),
      developmentHttpOrigin: this.#developmentHttpOrigin,
      beforeVerify: () => {
        const principal = this.authenticate(hostContext.credential);
        if (this.#requireAuthentication && principal === null) {
          return { kind: "refused", status: 401, code: "unauthenticated" };
        }
        const requestAt = this.#clock.now();
        const decision = Object.freeze({
          principal,
          context: this.#businessData.snapshot(requestAt),
        });
        return { kind: "admitted", state: { requestAt, decision } };
      },
    });
    if (admission.kind !== "admitted") {
      const response = admission.response ?? this.#refuse(admission.status, admission.code);
      if (admission.response) {
        this.#log?.refused({ status: response.status, code: admission.code });
      }
      if (response.status >= 500) this.#faults++;
      else this.#refusals++;
      return { kind: "refused", response };
    }
    const admitted = admission.request;
    const registration = admission.registration;
    const claims = admission.claims;
    const { requestAt, decision } = /** @type {NonNullable<typeof admission.state>} */ (
      admission.state
    );

    /** @type {'direct'|'client-bound'} */
    let mode;
    try {
      mode = this.#modeFor(admitted, decision);
    } catch (cause) {
      // A server that cannot work out how to answer has not been told
      // something it needed. That is its operator's mistake rather than the
      // caller's, so it counts as a fault. Nobody was
      // turned away here; the server fell over, and counting that as a
      // refusal would report a misconfiguration as traffic this
      // deployment declined to serve.
      this.#faults++;
      return { kind: "refused", response: this.#refuse(500, requestFaultCode(cause)), cors: true };
    }

    // The transport is agreed after both origin checks, because a
    // client-bound preflight generates an ephemeral ECDH private key and
    // agrees a transport key with it. A request from an origin the publisher
    // did not sign reaches none of that. The agreement still comes before
    // policy and anything opened, so a client key this server cannot read
    // costs it no unseal. The view carries the mode from here to body
    // preparation in the unlock.
    let view;
    try {
      view = await this.#keyDelivery.preflight(mode, admitted);
    } catch (cause) {
      const code = /** @type {any} */ (cause)?.code;
      // A client key this server cannot read is the caller's mistake, so it
      // takes a 400 refusal. Anything else the preflight threw means this
      // server is broken, so it counts as a fault, the same split the mode
      // selection above makes.
      if (code === "client_key_required" || code === "bad_client_key") {
        this.#refusals++;
        return { kind: "refused", response: this.#refuse(400, code), cors: true };
      }
      this.#faults++;
      return { kind: "refused", response: this.#refuse(500, requestFaultCode(cause)), cors: true };
    }

    return {
      kind: "admitted",
      context: Object.freeze({
        admitted,
        registration,
        claims,
        origin,
        requestAt,
        decision,
        view,
      }),
    };
  }

  /**
   * The issuer operation after browser admission. It receives the one view
   * built above, whose resourceJWT is already verified, whose signed origin
   * already matched and whose transport is already agreed. It checks
   * fallback admission, processes the request and prepares the final
   * response.
   *
   * @param {any} payload
   * @param {{ admission?: any }} [context]
   * @returns {Promise<{ status: number, body: any }>}
   */
  async #unlock(payload, context = {}) {
    const state = context.admission;
    if (state === null || typeof state !== "object") {
      throw dcaError("bad_config", "IssuerServer unlock needs its browser admission context");
    }
    const { admitted, registration, claims, requestAt, decision, view } = state;

    // Whether this fallback may stand in at all, and behind the admission
    // comparison on purpose: a probe, the health it caches and a
    // `primary_healthy` answer are work an admitted request pays for. A
    // request from another origin, or one whose signature this
    // registration's key refuses, buys none of it.
    if (this.#failoverGate && !(await this.#failoverGate.allows())) {
      this.#refusals++;
      return this.#refuse(403, "primary_healthy");
    }

    // The primary being down only permits this server to consider standing in.
    // This non-normative reference implementation's separate emergency
    // authorization is issuer construction state, not a page, request or
    // client field, and it expires on this server's clock before policy or
    // private-key work begins.
    if (
      this.#failoverGate &&
      (this.#emergencyUntil === null || this.#clock.now().getTime() >= this.#emergencyUntil)
    ) {
      this.#refusals++;
      return this.#refuse(403, "emergency_inactive");
    }

    const answered = await this.#endpoint.handleRequest({
      request: admitted,
      registration,
      verification: claims,
      policyInput: {
        principal: decision.principal,
        context: decision.context,
      },
      capturedAtMs: requestAt.getTime(),
    });
    const answer = answered.response;

    if (answer.status === 401) this.#denials++;
    if (answer.status === 200) {
      const responseBody = /** @type {{ errors?: unknown[] }} */ (answer.body);
      if (Array.isArray(responseBody.errors)) this.#unsealFailures += responseBody.errors.length;

      const trimmed = this.#failoverGate
        ? trimToCurrentPeriod(answer.body, requestAt)
        : answer.body;
      let finalBody;
      try {
        finalBody = await this.#keyDelivery.prepare(trimmed, view);
      } catch {
        // The endpoint already made its access decision. A failure in
        // the final transport adapter is this application's fault, not
        // a per-coordinate withholding or a request refusal; do not
        // debit or return its partially prepared body.
        this.#faults++;
        return this.#refuse(500, "internal_error");
      }
      const delivered = [...deliveredCoordinates(finalBody?.keys)];

      // One gate for both: this server counts a grant and debits a reader on
      // the same event, the delivery. A grant covers one view per render
      // while the coordinates are per item, so a partial answer records the
      // view it granted whole. What was opened varies; that a key went over
      // does not.
      if (delivered.length > 0) {
        try {
          this.#businessData.apply(answered.policyData);
          this.#grants++;
        } catch (cause) {
          this.#faults++;
          return this.#refuse(500, requestFaultCode(cause));
        }
      }

      return { status: 200, body: finalBody };
    }

    // Everything the endpoint turned away leaves by this line: caps,
    // unreadable bodies, and integrity failures. It is counted here
    // rather than case by case, so a status this server has never heard of
    // is still a request it did not serve. `denials` above stays what it
    // was: the one refusal that was an access decision, named as well as
    // counted.
    //
    // A 5xx is the other counter, and the split is the same one transport
    // selection makes above: the endpoint returns 500 for an engine error it
    // has no status for, say a policy that answered with something that is
    // not a decision, and that means this server broke rather than said no.
    // If the stats counted a broken issuer as one refusing everybody, it
    // would read exactly like one enforcing a policy.
    this.#log?.refused({ status: answer.status, code: answered.code });
    if (answer.status >= 500) this.#faults++;
    else this.#refusals++;

    return answer;
  }

  /**
   * `transportMode` is null when a policy decides per request. There is no
   * mode this server is in then, and naming one would be a summary of the
   * last request rather than a fact about the deployment.
   *
   * `refusals` counts every request turned away, at this server's admission
   * gates and at the endpoint alike. A caller that got nothing does not care
   * which of the two said so. `denials` counts the part of that total that
   * was an access decision. A 5xx lands in neither: nobody was refused, this
   * server broke, and `faults` counts it.
   *
   * @returns {{ requests: number, grants: number, denials: number, refusals: number, faults: number, unsealFailures: number, probes: number, healthReads: number, transportMode: string|null, role: string }}
   */
  stats() {
    const failover = this.#failoverGate?.stats() ?? { probes: 0, healthReads: 0 };
    return {
      requests: this.#requests,
      grants: this.#grants,
      denials: this.#denials,
      refusals: this.#refusals,
      faults: this.#faults,
      unsealFailures: this.#unsealFailures,
      probes: failover.probes,
      healthReads: failover.healthReads,
      transportMode: this.#mode,
      role: this.#role,
    };
  }
}

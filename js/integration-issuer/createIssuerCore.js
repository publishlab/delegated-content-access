// @ts-check
//
// The issuer's DCA core as one call. This entry builds an `IssuerEngine`, an
// `IssuerProcessor` over it and an `UnlockEndpoint` over that, and returns all
// three. Each configuration member goes to the one component that owns it and
// is checked there:
//
//   engine     accessPolicy, developmentHttpOrigin, notDeliveredReport,
//              supportedVersions, contentKeySource, contentKeyScope,
//              periodCapabilitySource, operatingIssuerNames
//   processor  periodKeyInput, limits, selectedExtensions, capabilityEncoders
//   endpoint   errorDetail
//
// An injected `engine` replaces the first row. When it declares
// `selectedExtensions` or `capabilityEncoders`, the processor takes those for
// each one the host leaves out. A host that leaves out `selectedExtensions`
// gets the engine's declared names followed by the contributions' names.
//
// A selected extension that answers through the base engine passes a
// contribution after the configuration: its name, which joins
// `selectedExtensions`; an `extensionCoordinate(request)` reading, which lets
// a request carrying only that extension's members pass admission and
// defaults to the source's `presented` reading;
// `requestBounds`, which the processor runs before signature verification;
// a `responseSectionSource`, which the base engine answers after its own
// coordinates; and `responseSections`, the key-bearing sections that source
// writes. Base reads none of the extension's members itself. A section may
// declare an `errorPath`, the trusted place its source reports a retired
// opening key per coordinate; it passes through unchanged. The entry refuses
// a source member other than `periodGeometry` that no declared section or
// error path roots, and returns the union as `responseSections` for the host's
// `KeyDelivery`: client-bound transport wraps only declared sections and
// admits only declared error maps, so an undeclared one would leave raw.
//
// `accessPolicy` is required, because an issuer that grants what a request
// presents has decided nothing. `periodKeyInput` is the processor's choice
// to read relayed period keys; the policy decides what is granted and
// the endpoint's body is the direct response representation, so none of the
// three selects another.
//
// The entry holds no request-time fact. Core 6.2 orders the body limit, the
// one parse and the version check before the registration the JWT header key
// id selects, so a host that selects by `kid` admits first:
//
// - `processor.admit(document)` measures, parses and admits the raw request
//   once; `endpoint.refusal(admission)` maps a refused admission. Only then
//   does the host read the admitted request's header `kid`
//   (`admitHeader(request.resourceJWT)`) as an untrusted lookup hint, select
//   the registration and its opening-key view, authenticate the reader,
//   capture the instant, and under the browser-origin profile compare the
//   observed Origin with the signed one before any cache lookup, policy or
//   private-key work. A cache hit must be authorized by the current call's
//   registration, context and policy decision. On a miss
//   `endpoint.handleRequest({ request, registration, policyInput, capturedAtMs })`
//   processes that same admitted request, and verifies the signature under
//   the registration.
// - `endpoint.handleDocument(document, registration, policyInput, capturedAtMs)`
//   admits and processes in one call. It suits a host that already holds its
//   one registration; a host that would have to parse the body to choose a
//   registration uses the path above instead.
//
// The returned `engine` is a lower seam, not a third path. `engine.unlock`
// skips the processor, so it applies neither admission `limits` nor
// `periodKeyInput`: it reads relayed period keys even when the
// host turned that input off.
//
// `createBrowserIssuer` composes this entry with the browser-origin adapter.
// Response caching and client-bound transport remain selected host composition.

import { IssuerEngine } from "../core-issuer/IssuerEngine.js";
import { IssuerProcessor } from "../core-issuer/IssuerProcessor.js";
import { UnlockEndpoint } from "../ports/UnlockEndpoint.js";
import { dcaError } from "../core-shared/errors.js";
import { settleComposedSections } from "../core-shared--client-issuer/responseKeys.js";

// Keep the browser compositions in this entry's static closure so the source
// copy and checked JavaScript configuration include their complete API.
export { admitBrowserRequest } from "./admitBrowserRequest.js";
export { createBrowserIssuer } from "./createBrowserIssuer.js";

/** @typedef {ConstructorParameters<typeof IssuerProcessor>[0]} IssuerEngineLike */

const ENGINE_OPTIONS = [
  "responseSectionSources",
  "envelopeProcedures",
  "accessPolicy",
  "developmentHttpOrigin",
  "notDeliveredReport",
  "supportedVersions",
  "operatingIssuerNames",
  "contentKeySource",
  "contentKeyScope",
  "periodCapabilitySource",
];
const PROCESSOR_OPTIONS = [
  "periodKeyInput",
  "limits",
  "selectedExtensions",
  "capabilityEncoders",
  "requestBounds",
  "extensionCoordinates",
];
const CONTRIBUTION_MEMBERS = [
  "name",
  "extensionCoordinate",
  "requestBounds",
  "responseSectionSource",
  "responseSections",
  "envelopeProcedures",
];
const ENDPOINT_OPTIONS = ["errorDetail"];
const OPTIONS = [...ENGINE_OPTIONS, ...PROCESSOR_OPTIONS, ...ENDPOINT_OPTIONS, "engine"];

/**
 * @typedef {object} IssuerEntryConfig
 * @property {string[]} [operatingIssuerNames] - distinct issuer names this
 *   endpoint serves under its policy and each publisher registration's
 *   scoped opening-key view. Required when createIssuerCore constructs the
 *   base engine; an injected engine owns and checks its own operating-name scope.
 * @property {import('../core-issuer/IssuerEngine.js').AccessPolicy} [accessPolicy] -
 *   who may read what. Required when `engine` is absent.
 * @property {boolean} [developmentHttpOrigin] - the development profile, off
 *   when left out. On, the engine also answers a render signed for `http` on a
 *   loopback host.
 * @property {'none'|'partial'|'complete'} [notDeliveredReport] - which
 *   not-delivered family reports the engine discloses; "none" when left out.
 * @property {boolean} [periodKeyInput] - whether the processor reads relayed
 *   period keys; off when left out.
 * @property {{ maxBodyBytes?: number, maxEntries?: number, maxEntriesPerGroup?: number }} [limits] -
 *   the admission caps this deployment replaces; each one left out keeps the
 *   processor's finite default.
 * @property {'code'|'uniform'} [errorDetail] - how much a refusal body names;
 *   "code" when left out.
 * @property {string[]} [supportedVersions] - a selected version set for the
 *   base engine. Admission uses that engine's pure version guard before
 *   version-dependent member checks.
 * @property {import('../core-issuer/IssuerEngine.js').ContentKeySource} [contentKeySource]
 * @property {(registration: import('../core-issuer/IssuerEngine.js').PublisherRegistration) => any|Promise<any>} [contentKeyScope]
 * @property {import('../core-issuer/IssuerEngine.js').PeriodCapabilitySource} [periodCapabilitySource]
 * @property {Record<string, (record: any) => any>} [capabilityEncoders]
 * @property {string[]} [selectedExtensions]
 * @property {import('../core-issuer/IssuerEngine.js').ResponseSectionSource[]} [responseSectionSources] -
 *   selected extensions' response sections; contributions append theirs
 * @property {Record<string, import('../core-issuer/IssuerEngine.js').EnvelopeProcedure
 *   | import('../core-issuer/IssuerEngine.js').DeclaredEnvelopeProcedure>} [envelopeProcedures] -
 *   extension envelope procedures by name; contributions add theirs, one owner per name
 * @property {((request: any) => void)[]} [requestBounds] - checks run during
 *   admission, before signature verification; contributions append theirs
 * @property {Record<string, (request: any) => boolean>} [extensionCoordinates] -
 *   by selected extension name, whether a request presents its coordinate
 * @property {IssuerEngineLike} [engine] - a selected extension's complete
 *   issuer engine, when it owns construction. Mutually exclusive with the
 *   base engine's options above. Its optional synchronous pure `checkVersion(request)`
 *   returns void and owns the selected version set; unlock-only engines use
 *   baseline version admission. Its optional `selectedExtensions` and
 *   `capabilityEncoders` declare the processor selections its route needs.
 */

/**
 * The members of `config` one component owns, only where the host named them,
 * so the component applies its own treatment of an absent one.
 *
 * @param {Record<string, unknown>} config
 * @param {string[]} names
 * @returns {Record<string, any>}
 */
function pick(config, names) {
  /** @type {Record<string, unknown>} */
  const picked = {};
  for (const name of names) {
    if (Object.hasOwn(config, name)) picked[name] = config[name];
  }
  return picked;
}

/**
 * An injected engine may declare the processor selections its own route needs:
 * `selectedExtensions`, whose request sections then count as coordinates, and
 * `capabilityEncoders`, which encode the capability records it returns. Without
 * them the processor would refuse the engine's own requests or fail on its
 * results. A selection the host leaves out takes the engine's declaration; one
 * the host names stays, but must still cover every declared extension and
 * encoder kind. Only the engine's construction-time declaration counts, never a
 * request field.
 *
 * Contributions append their names to `selectedExtensions` before this runs,
 * so `hostSelected` says whether the host wrote that list itself. Without a
 * host list, the engine's names come first and a contribution may not repeat
 * one of them.
 *
 * @param {Record<string, any>} engine
 * @param {Record<string, any>} options - the host's processor members, completed in place
 * @param {boolean} hostSelected - whether the host configuration gives `selectedExtensions`
 *   a value; an explicit `undefined` counts as omitted
 */
function composeDeclaredSelections(engine, options, hostSelected) {
  const declaredExtensions = engine.selectedExtensions;
  if (declaredExtensions !== undefined) {
    if (!Array.isArray(declaredExtensions)) {
      throw dcaError("bad_config", "an injected engine declares selectedExtensions as a list");
    }
    if (!hostSelected) {
      const contributed = options.selectedExtensions ?? [];
      const repeated = contributed.find((/** @type {string} */ name) =>
        declaredExtensions.includes(name),
      );
      if (repeated !== undefined) {
        throw dcaError("bad_config", `the issuer extension ${repeated} is selected twice`);
      }
      options.selectedExtensions = [...declaredExtensions, ...contributed];
    } else if (
      Array.isArray(options.selectedExtensions) &&
      declaredExtensions.some((name) => !options.selectedExtensions.includes(name))
    ) {
      throw dcaError(
        "bad_config",
        "selectedExtensions leaves out an extension the injected engine routes",
      );
    }
  }
  const declaredEncoders = engine.capabilityEncoders;
  if (declaredEncoders !== undefined) {
    if (
      declaredEncoders === null ||
      typeof declaredEncoders !== "object" ||
      Array.isArray(declaredEncoders)
    ) {
      throw dcaError("bad_config", "an injected engine declares capabilityEncoders as an object");
    }
    if (!Object.hasOwn(options, "capabilityEncoders")) {
      options.capabilityEncoders = { ...declaredEncoders };
    } else {
      const named = options.capabilityEncoders;
      if (
        named !== null &&
        typeof named === "object" &&
        Object.keys(declaredEncoders).some((kind) => !Object.hasOwn(named, kind))
      ) {
        throw dcaError(
          "bad_config",
          "capabilityEncoders leaves out a capability kind the injected engine returns",
        );
      }
    }
  }
}

/**
 * What one selected extension adds to an issuer that answers through the base
 * engine. Every member but `name` is optional.
 *
 * @typedef {object} IssuerContribution
 * @property {string} name - the extension name; it joins `selectedExtensions`
 * @property {(request: any) => boolean} [extensionCoordinate] - whether a
 *   request presents this extension's coordinate; defaults to the
 *   `responseSectionSource.presented` reading
 * @property {((request: any) => void)[]} [requestBounds] - admission checks
 *   over its own request members, before signature verification
 * @property {import('../core-issuer/IssuerEngine.js').ResponseSectionSource} [responseSectionSource]
 * @property {readonly Readonly<import('../core-shared--client-issuer/responseKeys.js').ComposedSection>[]} [responseSections] -
 *   the key-bearing sections its source writes, each rooted at one of the
 *   source's members; client-bound transport wraps their entries and admits
 *   each section's optional `errorPath` map of fixed `key_retired` leaves
 * @property {Record<string, import('../core-issuer/IssuerEngine.js').EnvelopeProcedure
 *   | import('../core-issuer/IssuerEngine.js').DeclaredEnvelopeProcedure>} [envelopeProcedures] -
 *   envelope procedures by name for the base engine; a request selects one
 *   only where its key entry permits it
 */

/**
 * Fold the contributions into the host's members, refusing a member the host
 * also named for the same extension.
 *
 * @param {Record<string, any>} members - a copy of the host configuration, completed in place
 * @param {unknown[]} contributions
 * @returns {unknown[]} the contributions' declared response sections, unsettled
 */
function composeContributions(members, contributions) {
  /** @type {unknown[]} */
  const declared = [];
  for (const contribution of contributions) {
    if (contribution === null || typeof contribution !== "object" || Array.isArray(contribution)) {
      throw dcaError("bad_config", "an issuer contribution is an object");
    }
    const entry = /** @type {Record<string, any>} */ (contribution);
    for (const name of Object.keys(entry)) {
      if (!CONTRIBUTION_MEMBERS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `an issuer contribution has no ${name}, and will not pretend to`,
        );
      }
    }
    const { name } = entry;
    if (typeof name !== "string" || name === "") {
      throw dcaError("bad_config", "an issuer contribution has a nonempty name");
    }
    const selected = members.selectedExtensions ?? [];
    if (!Array.isArray(selected) || selected.includes(name)) {
      throw dcaError("bad_config", `the issuer extension ${name} is selected twice`);
    }
    members.selectedExtensions = [...selected, name];
    // A source's own presence reading is the contribution's admission
    // coordinate, so one predicate decides both; `extensionCoordinate`
    // replaces it only where admission reads the request differently.
    const source = entry.responseSectionSource;
    let coordinate = entry.extensionCoordinate;
    if (!Object.hasOwn(entry, "extensionCoordinate")) {
      const presented = source?.presented;
      coordinate =
        typeof presented === "function"
          ? (/** @type {any} */ request) => Reflect.apply(presented, source, [request])
          : undefined;
    }
    if (coordinate !== undefined) {
      members.extensionCoordinates = {
        ...(members.extensionCoordinates ?? {}),
        [name]: coordinate,
      };
    }
    if (Object.hasOwn(entry, "requestBounds")) {
      if (!Array.isArray(entry.requestBounds)) {
        throw dcaError("bad_config", `${name} lists its request bounds`);
      }
      members.requestBounds = [...(members.requestBounds ?? []), ...entry.requestBounds];
    }
    if (Object.hasOwn(entry, "envelopeProcedures")) {
      if (members.engine !== undefined) {
        throw dcaError(
          "bad_config",
          `${name} opens through the base engine, and an injected engine replaces it`,
        );
      }
      const procedures = entry.envelopeProcedures;
      if (procedures === null || typeof procedures !== "object" || Array.isArray(procedures)) {
        throw dcaError("bad_config", `${name} maps its envelope procedures by name`);
      }
      const held = members.envelopeProcedures ?? {};
      for (const procedure of Object.keys(procedures)) {
        // One name, one opener: a second owner would decide which bytes a
        // selector opens by contribution order.
        if (Object.hasOwn(held, procedure)) {
          throw dcaError("bad_config", `the envelope procedure ${procedure} is declared twice`);
        }
      }
      members.envelopeProcedures = { ...held, ...procedures };
    }
    if (Object.hasOwn(entry, "responseSections")) {
      if (!Array.isArray(entry.responseSections)) {
        throw dcaError("bad_config", `${name} lists its response sections`);
      }
      declared.push(...entry.responseSections);
    }
    if (Object.hasOwn(entry, "responseSectionSource")) {
      if (members.engine !== undefined) {
        throw dcaError(
          "bad_config",
          `${name} answers through the base engine, and an injected engine replaces it`,
        );
      }
      members.responseSectionSources = [
        ...(members.responseSectionSources ?? []),
        entry.responseSectionSource,
      ];
    }
  }
  return declared;
}

/**
 * Each member a source may write, other than the base `periodGeometry`, is
 * the root of a declared section or error path. Runs after the engine
 * admitted the sources' shape, so its refusals keep their own wording.
 *
 * @param {unknown} sources
 * @param {readonly Readonly<import('../core-shared--client-issuer/responseKeys.js').ComposedSection>[]} sections
 */
function requireDeclaredSources(sources, sections) {
  const roots = new Set(
    sections.flatMap((section) => [section.path[0], ...(section.errorPath ?? []).slice(0, 1)]),
  );
  for (const source of Array.isArray(sources) ? sources : []) {
    for (const member of source.members) {
      if (member !== "periodGeometry" && !roots.has(member)) {
        throw dcaError(
          "bad_config",
          `the response section source ${source.name} writes ${member}, which no contribution declares as a response section`,
        );
      }
    }
  }
}

/**
 * @param {IssuerEntryConfig} config
 * @param {...IssuerContribution} contributions - selected extensions that
 *   answer through the base engine
 * @returns {Readonly<{ engine: IssuerEngineLike, processor: IssuerProcessor, endpoint: UnlockEndpoint,
 *   responseSections: readonly Readonly<import('../core-shared--client-issuer/responseKeys.js').ComposedSection>[] }>}
 */
export function createIssuerCore(config = /** @type {IssuerEntryConfig} */ ({}), ...contributions) {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw dcaError("bad_config", "createIssuerCore takes one configuration object");
  }
  for (const name of Object.keys(config)) {
    if (!OPTIONS.includes(name)) {
      throw dcaError(
        "unsupported_option",
        `createIssuerCore has no ${name}, and will not pretend to`,
      );
    }
  }
  const members = /** @type {Record<string, any>} */ ({ ...config });
  const declared = composeContributions(members, contributions);

  if (members.engine !== undefined && ENGINE_OPTIONS.some((name) => Object.hasOwn(members, name))) {
    throw dcaError("bad_config", "an injected engine owns its policy and engine options");
  }
  if (
    members.engine !== undefined &&
    typeof (/** @type {any} */ (members.engine)?.unlock) !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "an injected engine has an unlock(request, registration, policyInput, invocation)",
    );
  }
  if (
    members.engine !== undefined &&
    typeof (/** @type {any} */ (members.engine)?.checkOperatingIssuerName) !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "an injected engine checks operating issuer names during admission and unlock",
    );
  }
  const engine =
    members.engine === undefined
      ? new IssuerEngine(/** @type {any} */ (pick(members, ENGINE_OPTIONS)))
      : /** @type {any} */ (members.engine);
  const responseSections = settleComposedSections(declared);
  requireDeclaredSources(members.responseSectionSources, responseSections);
  const processorOptions = pick(members, PROCESSOR_OPTIONS);
  if (members.engine !== undefined) {
    composeDeclaredSelections(engine, processorOptions, config.selectedExtensions !== undefined);
  }
  const processor = new IssuerProcessor(engine, processorOptions);
  const endpoint = new UnlockEndpoint(processor, pick(members, ENDPOINT_OPTIONS));
  return Object.freeze({ engine, processor, endpoint, responseSections });
}

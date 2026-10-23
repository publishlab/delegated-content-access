// @ts-check

import { dcaError } from "../core-shared/errors.js";

const BASE_MEMBERS = Object.freeze([
  "version",
  "issuerName",
  "resourceJWT",
  "keyId",
  "envelope",
  "sealed",
  "clientPublicKey",
  "periodGeometry",
  "requestedPeriodKeys",
]);
const BASE_SEALED_MEMBERS = Object.freeze(["contentKeys", "periodKeys", "chainKeys"]);
// Request context an extension may also carry for its own routes. Every other
// base member is identity or a base route map and stays base-owned.
const SHARED_CONTEXT_MEMBERS = Object.freeze(["periodGeometry"]);

/** @typedef {import("../core-client/requestBuilderContracts.js").ExtensionKeyFamilies} ExtensionKeyFamilies */

/**
 * The records of one base request collection, or an empty list when it is
 * absent or not an array.
 * @param {unknown} collection
 * @returns {any[]}
 */
function records(collection) {
  return Array.isArray(collection) ? collection : [];
}

/**
 * Whether a built request offers any coordinate to this issuer: a record in a
 * base route collection, or a coordinate the selected builder's `keyFamilies`
 * reports.
 * @param {any} request
 * @param {((request: any) => ExtensionKeyFamilies)|null} [keyFamilies]
 */
export function hasEligibleCoordinates(request, keyFamilies = null) {
  const sealed = request?.sealed ?? {};
  if (BASE_SEALED_MEMBERS.some((name) => records(sealed[name]).length > 0)) return true;
  if (keyFamilies === null) return false;
  const families = keyFamilies(request);
  return families?.contentKeys === true || families?.familyKeys === true;
}

/**
 * `routes` holds the opaque route identities a selected extension's
 * projection reports; the walk compares them only for equality.
 * @typedef {{ contentNames: string[], accessGroups: string[], routes?: string[] }} RouteIdentities
 */

/** @typedef {import("../core-client/requestBuilderContracts.js").RouteProjection} RouteProjection */

/**
 * Admit a builder's projection seam once, at composition. It may claim no
 * base identity or base route member; `periodGeometry` is shared request
 * context an extension may carry for its own routes.
 * @param {unknown} value
 * @returns {Readonly<RouteProjection>}
 */
export function settleRouteProjection(value) {
  const projection = /** @type {any} */ (value);
  const names = (/** @type {unknown} */ list) =>
    Array.isArray(list) && list.every((name) => typeof name === "string" && name.length > 0);
  if (
    projection === null ||
    typeof projection !== "object" ||
    !names(projection.members) ||
    !names(projection.sealedMembers) ||
    typeof projection.identities !== "function" ||
    typeof projection.project !== "function" ||
    typeof projection.useful !== "function"
  )
    throw dcaError(
      "bad_config",
      "a routeProjection declares members and sealedMembers and answers identities, project and useful",
    );
  const claimsBase =
    projection.members.some(
      (/** @type {string} */ name) =>
        BASE_MEMBERS.includes(name) && !SHARED_CONTEXT_MEMBERS.includes(name),
    ) ||
    projection.sealedMembers.some((/** @type {string} */ name) =>
      BASE_SEALED_MEMBERS.includes(name),
    );
  if (claimsBase)
    throw dcaError("bad_config", "a routeProjection may not claim a base request member");
  return Object.freeze({
    members: Object.freeze([...projection.members]),
    sealedMembers: Object.freeze([...projection.sealedMembers]),
    identities: projection.identities.bind(projection),
    project: projection.project.bind(projection),
    useful: projection.useful.bind(projection),
  });
}

/**
 * The route identities actually presented to one issuer.
 * @param {any} request
 * @param {Readonly<RouteProjection>|null} [projection]
 * @returns {RouteIdentities}
 */
export function routeIdentities(request, projection = null) {
  const sealed = request?.sealed ?? {};
  return {
    contentNames: [...new Set(records(sealed.contentKeys).map((record) => record?.contentName))],
    accessGroups: [
      ...new Set(
        [...records(sealed.periodKeys), ...records(sealed.chainKeys)].map(
          (record) => record?.accessGroup,
        ),
      ),
    ],
    routes: projection === null ? [] : [...new Set(projection.identities(request))],
  };
}

/**
 * Restrict a conditional attempt to the route identities that qualified.
 * An item content-key coordinate has its own identity and is never inherited
 * from a family's `unavailable` report. An extension member is carried only
 * as the selected projection rebuilds it for the qualified routes; an
 * undeclared member cannot be projected safely, so this returns null rather
 * than forwarding it.
 * @param {any} request
 * @param {RouteIdentities} identities
 * @param {Readonly<RouteProjection>|null} [projection]
 * @returns {any|null}
 */
export function projectEligibleIdentities(request, identities, projection = null) {
  const extensionMembers = new Set(projection?.members ?? []);
  const extensionSealed = new Set(projection?.sealedMembers ?? []);
  if (
    Object.keys(request).some(
      (name) => !BASE_MEMBERS.includes(name) && !extensionMembers.has(name),
    ) ||
    Object.keys(request.sealed ?? {}).some(
      (name) => !BASE_SEALED_MEMBERS.includes(name) && !extensionSealed.has(name),
    )
  )
    return null;
  const selected = projectBase(request, identities);
  if (projection === null) return selected;
  for (const name of extensionMembers)
    if (!SHARED_CONTEXT_MEMBERS.includes(name)) delete selected[name];
  const extension = projection.project(request, [...(identities.routes ?? [])]);
  if (extension === null || typeof extension !== "object" || Array.isArray(extension))
    throw dcaError("bad_config", "a routeProjection project answers an object");
  for (const [part, declared, target] of /** @type {const} */ ([
    ["members", extensionMembers, selected],
    ["sealed", extensionSealed, selected.sealed],
  ])) {
    const members = /** @type {any} */ (extension)[part] ?? {};
    for (const [name, value] of Object.entries(members)) {
      if (!declared.has(name))
        throw dcaError(
          "bad_config",
          `a routeProjection returned undeclared ${part} member ${name}`,
        );
      target[name] = value;
    }
  }
  return selected;
}

/**
 * The base part of a projection: item and family route records narrowed to
 * the qualified identities, with their context only while a family remains.
 * Every record of a qualified identity stays, rival candidates included.
 * @param {any} request
 * @param {RouteIdentities} identities
 * @returns {any}
 */
function projectBase(request, identities) {
  const groups = new Set(identities.accessGroups);
  const items = new Set(identities.contentNames);
  /** @param {unknown} collection @param {string} field @param {Set<string>} admitted */
  const select = (collection, field, admitted) =>
    records(collection).filter((record) => admitted.has(record?.[field]));
  /** @type {any} */
  const selected = {
    ...request,
    sealed: { contentKeys: select(request.sealed?.contentKeys, "contentName", items) },
  };
  for (const kind of ["periodKeys", "chainKeys"]) {
    const families = select(request.sealed?.[kind], "accessGroup", groups);
    if (families.length > 0) selected.sealed[kind] = families;
  }
  if (Object.hasOwn(request, "requestedPeriodKeys")) {
    const hints = select(request.requestedPeriodKeys, "accessGroup", groups);
    if (hints.length > 0) selected.requestedPeriodKeys = hints;
    else delete selected.requestedPeriodKeys;
  }
  if (records(selected.sealed.chainKeys).length === 0) {
    delete selected.requestedPeriodKeys;
  }
  if (
    records(selected.sealed.chainKeys).length === 0 &&
    records(selected.sealed.periodKeys).length === 0
  ) {
    delete selected.periodGeometry;
  }
  return selected;
}

/**
 * Restrict a conditional `unavailable` retry to its admitted period families.
 * @param {any} request
 * @param {string[]} accessGroups
 * @returns {any|null}
 */
export function projectUnavailableFamilies(request, accessGroups) {
  return projectEligibleIdentities(request, { contentNames: [], accessGroups });
}

/**
 * Only admitted, still-useful `unavailable` families qualify for recovery.
 * A rejected key entry beside the report leaves it admitted (period keys
 * Section 5.6); a whole-response refusal admits no report, so it never
 * reaches this list.
 * @param {{ application: any, missing: string[], dcaData: { accessGroupsFor: (name: string) => string[] }, retryUnavailable: boolean }} input
 * @returns {string[]}
 */
export function retryableUnavailableFamilies({ application, missing, dcaData, retryUnavailable }) {
  if (!retryUnavailable) return [];
  const useful = new Set(missing.flatMap((name) => dcaData.accessGroupsFor(name)));
  return [
    ...new Set(
      (application.notDelivered ?? [])
        .filter(
          (/** @type {any} */ entry) =>
            entry?.reason === "unavailable" && useful.has(entry.accessGroup),
        )
        .map((/** @type {any} */ entry) => entry.accessGroup),
    ),
  ];
}

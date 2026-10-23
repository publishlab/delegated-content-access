// @ts-check
// Portable contracts supplied by request builders to client compositions.

/**
 * What a selected extension's request builder may tell the delivery client
 * about the coordinates it added: whether they can return item content keys,
 * and whether they can return period or chain keys (derivation keys), which a
 * direct answer hands over as raw bytes.
 * @typedef {{ contentKeys: boolean, familyKeys: boolean }} ExtensionKeyFamilies
 */

/**
 * The retry-projection seam a selected extension's request builder offers as
 * `routeProjection`. The extension declares the request members it adds,
 * names its route identities as opaque strings, rebuilds its members for a
 * subset of them, and says whether an identity still serves a missing item.
 * The walk does set operations only; it never reads an extension member.
 * @typedef {object} RouteProjection
 * @property {readonly string[]} members - root request members the extension adds
 * @property {readonly string[]} sealedMembers - `sealed` members the extension adds
 * @property {(request: any) => string[]} identities
 * @property {(request: any, routes: string[]) => { members?: Record<string, unknown>, sealed?: Record<string, unknown> } | null} project
 *   - the extension's members narrowed to those routes; `{}` when none remain,
 *   `null` when independently owned members prevent safe projection
 * @property {(route: string, missing: string[]) => boolean} useful
 */

export {};

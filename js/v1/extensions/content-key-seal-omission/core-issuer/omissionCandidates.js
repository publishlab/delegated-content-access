// @ts-check
//
// The issuer half of content-key seal omission: which forwarded candidates an
// unlock may try for one granted item, and how each of them is unwrapped.
//
// It answers an item the publisher never sealed a contentKey to this issuer
// for, by unwrapping the candidate the client forwarded under period material
// the issuer was already entrusted with. Nothing here opens anything: it names
// coordinates and hands back closures, and `omissionContentKeySource.js` runs
// them under base's key authority and base's verified render anchor.
//
// The contentName is the policy's, out of what the request presented, and so
// is the `(accessGroup, t)` it may be opened through: the policy answers
// `sourceGrants`, clamped to the labels the request carried the way a period
// prefix is clamped. A candidate at a coordinate outside that set is not tried
// at all. Within it, the accessGroup and t on a candidate are
// labels that select which sealed period blob is opened under the outer BIND,
// and nothing more. The inner binding is rebuilt from the render anchor the
// caller hands `unwrap`, the policy's contentName and that same pair, so a
// candidate carried to another render, name, group or period fails
// authentication and yields no key. There is one label per blob and no second
// one beside it.
//
// The outer BIND is not a substitute for the decision. It proves a blob sits at
// the coordinate the publisher sealed it at, not that this caller may be
// answered through that coordinate, and an issuer-held leaf proves neither.
//
// The leaf view arrives already selected for the authenticated publisher
// registration and takes `(accessGroup, t)` alone. Selection is
// `omissionContentKeySource.js`'s and the reason is there: `(accessGroup, t)`
// is a coordinate inside one publisher's render rather than a global one.
//
// Every candidate is a trial: a coordinate that will not open lets the next
// candidate try, and the item reports one failure only when every eligible
// candidate is spent.
//
// This module reads a decision member of its own with the same grammar the base
// engine reads `periodGrants` under, and holds its own copy of that reader. The
// period-chain route is no concern of this extension: it takes an already
// selected exact leaf view instead, so it never reaches the sibling
// period-chain extension.

import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { decrypt } from "../../../core-shared/aead.js";
import { BIND_DELIMITER } from "../../../core-shared--publisher-issuer/bind.js";
import { dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { isBoundEntry, omissionBindAad } from "../core-shared/omissionBind.js";

/**
 * One thing to try for one granted item, in the order it is tried.
 *
 * `leaf` is material the issuer holds for this coordinate and answers `null`
 * where it holds none; `sealed` is the value the request presented at that
 * coordinate, which the caller opens under its own key authority. `unwrap`
 * turns whichever arrived into the content key, against the verified render
 * anchor the caller supplies.
 *
 * @typedef {object} OmissionCandidate
 * @property {{ accessGroup: string, t: string }} coordinate
 * @property {() => Promise<Uint8Array|null>} [leaf]
 * @property {unknown} [sealed]
 * @property {(material: Uint8Array, renderId: string) => Promise<Uint8Array>} unwrap
 */

/**
 * The coordinates this request presents that the ordinary reading does not see.
 * Presenting grants nothing. It lets a policy decide on a content name that a
 * request carrying no sealed contentKeys would otherwise not present at all.
 *
 * @param {any} request
 * @returns {{ contentNames: string[], accessGroups: string[] }}
 */
export function presentedCoordinates(request) {
  const candidates = boundCandidatesOf(request);
  return {
    contentNames: Object.keys(candidates),
    accessGroups: [...candidateLabelsOf(candidates).keys()],
  };
}

/**
 * What may be tried for each item the request forwarded candidates for, keyed by
 * content name. A name with an entry and an empty list forwarded candidates this
 * decision reaches none of, which is one failure rather than silence.
 *
 * @param {object} unlock
 * @param {any} unlock.request
 * @param {any} unlock.decision - the whole policy answer; this module reads its own member
 * @param {((accessGroup: string, t: string) => Promise<Uint8Array|null>)|null} unlock.leafFor -
 *   the exact leaf view already selected for the authenticated registration
 * @returns {Map<string, OmissionCandidate[]>}
 */
export function candidatesFor({ request, decision, leafFor }) {
  const candidates = boundCandidatesOf(request);
  const sealedPeriods = request.sealedPeriodKeys ?? {};

  // Which `(accessGroup, t)` this caller's granted items may be opened
  // through. It is the policy's decision and never the candidate's label. A
  // policy that names no `sourceGrants` falls back to its `periodGrants`, so
  // an existing policy keeps one answer for both questions. Naming
  // them separately lets an issuer open a source it does not hand back.
  const sourceGrants = sourceCoordinates(
    periodGrants(decision?.sourceGrants ?? decision?.periodGrants),
    sealedPeriods,
    candidateLabelsOf(candidates),
  );

  /** @type {Map<string, OmissionCandidate[]>} */
  const byContentName = new Map();
  for (const contentName of Object.keys(candidates)) {
    const forwarded = own(candidates, contentName);
    if (!Array.isArray(forwarded) || forwarded.length === 0) continue;

    /** @type {OmissionCandidate[]} */
    const tries = [];
    for (const candidate of forwarded) {
      // A candidate with no marker is refused rather than tried unbound:
      // the two representations are told apart by the marker and never by
      // shape.
      if (!isBoundEntry(candidate)) continue;

      const accessGroup = own(candidate, "accessGroup");
      const t = own(candidate, "t");
      const nonce = own(candidate, "nonce");
      const wrapped = own(candidate, "key");
      if (
        typeof accessGroup !== "string" ||
        typeof t !== "string" ||
        typeof nonce !== "string" ||
        typeof wrapped !== "string"
      )
        continue;
      if (!sourceGrants.has(`${accessGroup}${BIND_DELIMITER}${t}`)) continue;

      /**
       * @param {Uint8Array} periodKey
       * @param {string} renderId
       */
      const unwrap = (periodKey, renderId) => {
        // Both leaves arrived on the wire, so they are read in the one
        // spelling section 2.2 admits. A leaf the generic decoder could
        // not read at all used to throw here, and the caller reads a
        // throw as this candidate spent with the next one still allowed
        // to answer; a spelling that decodes to the same bytes as the
        // canonical one now ends the same way.
        const nonceBytes = binaryStringBytes(nonce);
        const wrappedBytes = binaryStringBytes(wrapped);
        if (nonceBytes === null || wrappedBytes === null) {
          throw dcaError("unseal_failed", "a forwarded candidate is canonical unpadded base64url");
        }
        return decrypt(
          periodKey,
          nonceBytes,
          wrappedBytes,
          omissionBindAad({ renderId, contentName, accessGroup, t }),
        );
      };

      // The issuer's own leaf first, then the period blob the request
      // forwarded. The caller opens the second one; this module opens
      // neither.
      const coordinate = { accessGroup, t };
      if (leafFor !== null) {
        tries.push({ coordinate, leaf: () => leafFor(accessGroup, t), unwrap });
      }
      tries.push({ coordinate, sealed: own(own(sealedPeriods, accessGroup), t), unwrap });
    }

    byContentName.set(contentName, tries);
  }
  return byContentName;
}

/**
 * The forwarded candidates of one request, container-checked. A request built by
 * another client, or by a base client, carries none.
 *
 * @param {any} request
 * @returns {Record<string, unknown>}
 */
function boundCandidatesOf(request) {
  const value = own(request.toObject(), "boundCandidates");
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

/**
 * The period labels the forwarded candidates present, per accessGroup. They are
 * the client's words for where its blobs sit, so they are the set a policy
 * decision is clamped against and never the decision itself.
 *
 * @param {Record<string, unknown>} candidates
 * @returns {Map<string, Set<string>>}
 */
function candidateLabelsOf(candidates) {
  /** @type {Map<string, Set<string>>} */
  const labels = new Map();
  for (const contentName of Object.keys(candidates)) {
    const forwarded = own(candidates, contentName);
    if (!Array.isArray(forwarded)) continue;
    for (const candidate of forwarded) {
      const accessGroup = own(candidate, "accessGroup");
      const t = own(candidate, "t");
      if (typeof accessGroup !== "string" || typeof t !== "string") continue;
      let periods = labels.get(accessGroup);
      if (!periods) {
        periods = new Set();
        labels.set(accessGroup, periods);
      }
      periods.add(t);
    }
  }
  return labels;
}

/**
 * The coordinates a granted item may be opened through, as `accessGroup|t`.
 *
 * The clamp is the ordinary one: the group's presented labels sorted ascending,
 * cut to the count the policy answered. The presented set here is the union of
 * the sealed period labels and the candidate labels, because an issuer answering
 * from an injected leaf source is presented no sealed period map at all. A group
 * the policy did not name contributes nothing, so a generous label cannot widen
 * a decision in either axis.
 *
 * @param {{ accessGroup: string, periodCount: number }[]} grants
 * @param {Record<string, unknown>} sealedPeriods
 * @param {Map<string, Set<string>>} candidateLabels
 * @returns {Set<string>}
 */
function sourceCoordinates(grants, sealedPeriods, candidateLabels) {
  /** @type {Map<string, number>} */
  const countByGroup = new Map();
  for (const grant of grants) {
    const prior = countByGroup.get(grant.accessGroup) ?? 0;
    if (grant.periodCount > prior) countByGroup.set(grant.accessGroup, grant.periodCount);
  }

  /** @type {Set<string>} */
  const coordinates = new Set();
  for (const [accessGroup, count] of countByGroup) {
    const sealed = own(sealedPeriods, accessGroup);
    const presented = new Set([
      ...(sealed !== null && typeof sealed === "object" ? Object.keys(sealed) : []),
      ...(candidateLabels.get(accessGroup) ?? []),
    ]);
    for (const t of [...presented].sort().slice(0, Math.min(count, presented.size))) {
      coordinates.add(`${accessGroup}${BIND_DELIMITER}${t}`);
    }
  }
  return coordinates;
}

/**
 * Copied from `core-issuer/IssuerEngine.js`, where it is module-private and
 * reads the ordinary `periodGrants`. This extension reads a decision member of
 * its own under the same grammar.
 *
 * @param {any} value
 * @returns {{ accessGroup: string, periodCount: number }[]}
 */
function periodGrants(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw dcaError("bad_policy", "the access policy answered with periodGrants that is not a list");
  }
  return value.map((grant) => {
    if (grant === null || typeof grant !== "object") {
      throw dcaError(
        "bad_policy",
        "a periodGrant is an object of an accessGroup and a periodCount",
      );
    }
    const accessGroup = own(grant, "accessGroup");
    const periodCount = own(grant, "periodCount");
    if (typeof accessGroup !== "string") {
      throw dcaError("bad_policy", "a periodGrant names the accessGroup it opens");
    }
    if (!Number.isInteger(periodCount) || periodCount < 0) {
      throw dcaError("bad_policy", "a periodGrant opens a whole, non-negative number of periods");
    }
    return { accessGroup, periodCount };
  });
}

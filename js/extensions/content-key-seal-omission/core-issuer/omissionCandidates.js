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
// `sourceGrants`, clamped to the canonical labels the request carried. A
// candidate at a coordinate outside that set is not tried
// at all. Within it, the accessGroup and t on a candidate are
// labels that select which sealed period blob is opened under the outer BIND,
// and nothing more. The inner binding is rebuilt from the render anchor the
// caller hands `unwrap`, the policy's contentName and that same pair, so a
// candidate carried to another render, name, group or period fails
// authentication and yields no key. There is one label per blob and no second
// one beside it. The `sourceGrants` clamp is this mechanism's input
// authorization and the inner AEAD check its proof of the result. Base enforces
// neither (core Section 6.3 leaves both to a trusted source), so both stay here.
//
// The outer BIND is not a substitute for the decision. It proves a blob sits at
// the coordinate the publisher sealed it at, not that this caller may be
// answered through that coordinate, and an issuer-held period key proves neither.
//
// The period-key view arrives already selected for the authenticated publisher
// registration and takes `(accessGroup, t)` alone. Selection is
// `omissionContentKeySource.js`'s and the reason is there: `(accessGroup, t)`
// is a coordinate inside one publisher's render rather than a global one.
//
// Every candidate is a trial: a candidate that will not open lets the next
// one try, and the item reports one failure only when every eligible candidate
// is spent. A trial costs a key import and an AEAD open, and the processor
// counts no candidate at admission, so this module spends them only on
// candidates that could be a wrap of the item: a content name the format
// admits, and a nonce and wrapped key in their one admitted spelling at the v1
// widths. Distinct material at one `(accessGroup, t)` stays an alternative,
// because only the AEAD check tells a valid wrap from a corrupted one, and the
// first one to arrive may be either. Material identical to one already listed
// for the item at that coordinate is the same trial, so it is listed once.
// Request byte bounds, not this listing, limit how many distinct trials one
// request can ask for.
//
// This module reads a decision member of its own with the same grammar the base
// engine reads `periodGrants` under, and holds its own copy of that reader. The
// chain-key route is no concern of this extension: it takes an already
// selected period-key view instead, so it never reaches the sibling
// chain-key extension.

import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { decrypt, NONCE_BYTES, TAG_BYTES } from "../../../core-shared/aead.js";
import { BIND_DELIMITER } from "../../../core-shared--publisher-issuer/bind.js";
import { dcaError } from "../../../core-shared/errors.js";
import { isAccessGroup, isContentName } from "../../../core-shared/names.js";
import { isPeriodKeyLabel } from "../../../core-shared/periodLabels.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import { isBoundEntry, omissionBindAad } from "../core-shared/omissionBind.js";

/** A wrapped v1 content key: its 16 bytes and the AES-GCM tag. */
const WRAPPED_KEY_BYTES = 16 + TAG_BYTES;

/**
 * One thing to try for one granted item, in the order it is tried.
 *
 * `periodKey` is material the issuer holds for this coordinate and answers `null`
 * where it holds none; `sealed` is the value the request presented at that
 * coordinate, which the caller opens under its own key authority. `unwrap`
 * turns whichever arrived into the content key, against the verified render
 * anchor the caller supplies.
 *
 * @typedef {object} OmissionCandidate
 * @property {{ accessGroup: string, t: string }} coordinate
 * @property {() => Promise<Uint8Array|null>} [periodKey]
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
 * @param {((accessGroup: string, t: string) => Promise<Uint8Array|null>)|null} unlock.periodKeyFor -
 *   the period-key view already selected for the authenticated registration
 * @returns {Map<string, OmissionCandidate[]>}
 */
export function candidatesFor({ request, decision, periodKeyFor }) {
  const candidates = boundCandidatesOf(request);
  const sealedPeriods = request.sealedPeriodKeys ?? {};

  // Which `(accessGroup, t)` this caller's granted items may be opened
  // through. It is the policy's decision and never the candidate's label. A
  // missing `sourceGrants` member falls back only to ordinary explicit labels
  // in `periodGrants`; a present malformed member does not fall back.
  const grants =
    decision !== null && typeof decision === "object" && Object.hasOwn(decision, "sourceGrants")
      ? sourceGrants(own(decision, "sourceGrants"))
      : periodGrants(own(decision, "periodGrants")).filter((grant) => grant.periods !== undefined);
  const allowedCoordinates = sourceCoordinates(
    grants,
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
    /** @type {Set<string>} */
    const listed = new Set();
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
      const at = `${accessGroup}${BIND_DELIMITER}${t}`;
      if (!allowedCoordinates.has(at)) continue;

      // Both strings arrived on the wire, so they are read in the one
      // spelling section 2.2 admits, at the widths a v1 wrap has. Anything
      // else could not be this item's wrap and costs no trial.
      const nonceBytes = binaryStringBytes(nonce);
      const wrappedBytes = binaryStringBytes(wrapped);
      if (nonceBytes?.length !== NONCE_BYTES || wrappedBytes?.length !== WRAPPED_KEY_BYTES)
        continue;
      // Each string is the one admitted spelling of its bytes, so equal
      // strings are equal material. Neither contains a ".", so the last two
      // fields of this key are always the nonce and the wrapped key.
      const material = `${at}.${nonce}.${wrapped}`;
      if (listed.has(material)) continue;
      listed.add(material);

      /**
       * @param {Uint8Array} periodKey
       * @param {string} renderId
       */
      const unwrap = (periodKey, renderId) =>
        decrypt(
          periodKey,
          nonceBytes,
          wrappedBytes,
          omissionBindAad({ renderId, contentName, accessGroup, t }),
        );

      // The issuer's own period key first, then the period blob the request
      // forwarded. The caller opens the second one; this module opens
      // neither.
      const coordinate = { accessGroup, t };
      if (periodKeyFor !== null) {
        tries.push({ coordinate, periodKey: () => periodKeyFor(accessGroup, t), unwrap });
      }
      tries.push({ coordinate, sealed: own(own(sealedPeriods, accessGroup), t), unwrap });
    }

    byContentName.set(contentName, tries);
  }
  return byContentName;
}

/**
 * The forwarded candidates of one request, container-checked. A request built by
 * another client, or by a base client, carries none. A content name the format
 * refuses names no item this issuer could grant, so its candidates stay inert
 * rather than reaching the policy as a presented name.
 *
 * @param {any} request
 * @returns {Record<string, unknown>}
 */
function boundCandidatesOf(request) {
  const value = own(request.toObject(), "boundCandidates");
  /** @type {Record<string, unknown>} */
  const candidates = {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) return candidates;
  for (const contentName of Object.keys(value)) {
    if (isContentName(contentName)) setOwn(candidates, contentName, own(value, contentName));
  }
  return candidates;
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
      if (!isBoundEntry(candidate) || !isAccessGroup(accessGroup) || !isPeriodKeyLabel(t)) continue;
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
 * The policy names exact labels. This source intersects them with the union of
 * canonical sealed labels and canonical forwarded-candidate labels; neither
 * group visibility nor a label outside that presented set widens the grant.
 *
 * @param {{ accessGroup: string, periods: string[] }[]} grants
 * @param {Record<string, unknown>} sealedPeriods
 * @param {Map<string, Set<string>>} candidateLabels
 * @returns {Set<string>}
 */
function sourceCoordinates(grants, sealedPeriods, candidateLabels) {
  /** @type {Map<string, Set<string>>} */
  const labelsByGroup = new Map();
  for (const grant of grants) {
    let labels = labelsByGroup.get(grant.accessGroup);
    if (!labels) {
      labels = new Set();
      labelsByGroup.set(grant.accessGroup, labels);
    }
    for (const t of grant.periods) labels.add(t);
  }

  /** @type {Set<string>} */
  const coordinates = new Set();
  for (const [accessGroup, authorized] of labelsByGroup) {
    const sealed = own(sealedPeriods, accessGroup);
    const presented = new Set([
      ...(sealed !== null && typeof sealed === "object" && !Array.isArray(sealed)
        ? Object.keys(sealed).filter(isPeriodKeyLabel)
        : []),
      ...(candidateLabels.get(accessGroup) ?? []),
    ]);
    for (const t of authorized) {
      if (presented.has(t)) coordinates.add(`${accessGroup}${BIND_DELIMITER}${t}`);
    }
  }
  return coordinates;
}

/**
 * Reads the ordinary core grant grammar, including its separate independent
 * chain form. Only ordinary labels can authorize this extension's auxiliary
 * item opening.
 *
 * @param {any} value
 * @returns {({ accessGroup: string, periods: string[] }|{ accessGroup: string, futurePeriodCount: number, authorizePeriod: (t: string) => boolean })[]}
 */
function periodGrants(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw dcaError("bad_policy", "the access policy answered with periodGrants that is not a list");
  }
  return value.map((grant) => {
    if (grant === null || typeof grant !== "object" || Array.isArray(grant)) {
      throw dcaError(
        "bad_policy",
        "a periodGrant is an object with an accessGroup and explicit labels, or an independent capability grant",
      );
    }
    const accessGroup = own(grant, "accessGroup");
    if (!isAccessGroup(accessGroup)) {
      throw dcaError("bad_policy", "a periodGrant names the accessGroup it opens");
    }
    const independent =
      Object.hasOwn(grant, "futurePeriodCount") || Object.hasOwn(grant, "authorizePeriod");
    if (independent) {
      const futurePeriodCount = own(grant, "futurePeriodCount");
      const authorizePeriod = own(grant, "authorizePeriod");
      if (
        Object.hasOwn(grant, "periods") ||
        Object.hasOwn(grant, "periodCount") ||
        !Number.isSafeInteger(futurePeriodCount) ||
        futurePeriodCount < 0 ||
        typeof authorizePeriod !== "function"
      ) {
        throw dcaError(
          "bad_policy",
          "an independent period grant has a horizon and trusted authorization callback only",
        );
      }
      return { accessGroup, futurePeriodCount, authorizePeriod };
    }
    const periods = own(grant, "periods");
    if (
      Object.hasOwn(grant, "periodCount") ||
      !Array.isArray(periods) ||
      periods.some((t) => !isPeriodKeyLabel(t))
    ) {
      throw dcaError("bad_policy", "an ordinary periodGrant names explicit period labels");
    }
    return { accessGroup, periods: [...new Set(periods)] };
  });
}

/** @param {any} value @returns {{ accessGroup: string, periods: string[] }[]} */
function sourceGrants(value) {
  if (!Array.isArray(value)) {
    throw dcaError("bad_policy", "sourceGrants is a list of explicit auxiliary opening labels");
  }
  const byGroup = new Map();
  for (const grant of value) {
    if (
      grant === null ||
      typeof grant !== "object" ||
      Array.isArray(grant) ||
      !isAccessGroup(own(grant, "accessGroup")) ||
      Object.hasOwn(grant, "periodCount") ||
      Object.hasOwn(grant, "futurePeriodCount") ||
      Object.hasOwn(grant, "authorizePeriod")
    ) {
      throw dcaError("bad_policy", "sourceGrants names an accessGroup and explicit periods only");
    }
    const accessGroup = own(grant, "accessGroup");
    const periods = own(grant, "periods");
    if (!Array.isArray(periods) || periods.some((t) => !isPeriodKeyLabel(t))) {
      throw dcaError("bad_policy", "sourceGrants periods are canonical period labels");
    }
    let selected = byGroup.get(accessGroup);
    if (!selected) {
      selected = new Set();
      byGroup.set(accessGroup, selected);
    }
    for (const t of periods) selected.add(t);
  }
  return [...byGroup].map(([accessGroup, periods]) => ({ accessGroup, periods: [...periods] }));
}

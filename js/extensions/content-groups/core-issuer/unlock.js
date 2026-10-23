import { seedHandle, STOCK_CHAIN } from "../core-shared--publisher-issuer/seedHandle.js";
import { base64urlEncode } from "../../../core-shared/codec.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import {
  CONTRACT,
  bytes,
  checkedScope,
  checkedWindow,
  contentNameSeedAad,
  itemPad,
  labelAt,
  settleLimits,
  validateClaim,
  xor16,
} from "../core-shared/construction.js";
import { ENVELOPE_BYTES, openSeed } from "../core-shared/seed-envelope.js";
import {
  RESPONSE_SECTIONS,
  readContentGroupRequest,
} from "../core-shared--client-issuer/request.js";
import { dcaError, DcaError } from "../../../core-shared/errors.js";

/** @param {unknown} value */
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The extension name an issuer selects and a request coordinate counts under. */
const EXTENSION = "content-groups";
const RESPONSE_MEMBER = CONTRACT.wire.response;

/**
 * A request refusal: the request, not this issuer, is at fault.
 * @param {string} message
 */
function refusal(message) {
  return dcaError("binding_failed", message);
}

/**
 * A policy answer this issuer cannot serve as given.
 * @param {string} message
 */
function policyFault(message) {
  return dcaError("bad_policy", message);
}

/**
 * Run request-admission code, turning a plain construction error into a
 * request refusal. Stock chain validators use configuration error codes for
 * geometry and labels; at this request-only boundary those are malformed
 * request coordinates. Other DcaErrors keep their code.
 *
 * @template T
 * @param {() => T} admit
 * @returns {T}
 */
function admitting(admit) {
  try {
    return admit();
  } catch (cause) {
    if (
      cause instanceof DcaError &&
      cause.code !== "bad_config" &&
      cause.code !== "unsupported_option"
    )
      throw cause;
    throw refusal(/** @type {any} */ (cause)?.message ?? "invalid content-groups request");
  }
}

/**
 * The content-group members of one request, bounded and shape-checked by the
 * shared request reader the client builds with, plus the one issuer rule it
 * leaves out: every seed envelope is exactly 113 bytes. It verifies nothing:
 * it runs during admission, before the resource signature, and again inside
 * the unlock. Null when the request carries no content-group member.
 *
 * @param {any} document - the request as it arrived
 * @param {import('../core-shared/construction.js').ContentGroupLimits} limits
 */
function boundedMembers(document, limits) {
  const view = readContentGroupRequest(document, limits);
  if (view === null) return null;
  admitting(() => {
    for (const windows of Object.values(view.seeds))
      for (const envelopes of Object.values(windows))
        for (const envelope of envelopes) bytes(envelope, ENVELOPE_BYTES, "seed envelope");
  });
  return {
    seeds: view.seeds,
    groups: Object.fromEntries(
      Object.entries(view.contentGroups).map(([name, { groups }]) => [name, groups]),
    ),
    items: view.contentKeys,
    cutoffs: view.cutoffs,
  };
}

/**
 * Whether a request presents a content-group coordinate: a requested group or
 * a requested content key. Seeds alone ask nothing.
 *
 * @param {any} request - a DcaRequest
 */
function presents(request) {
  const document = request.toObject();
  if (!record(document)) return false;
  const groups = document[CONTRACT.wire.requestedContentGroups];
  const items = document[CONTRACT.wire.requestedContentKeys];
  return (Array.isArray(groups) && groups.length > 0) || (Array.isArray(items) && items.length > 0);
}

/**
 * The content-groups policy port. `decide` is asked once per exchange, before
 * any seed opens, with the verified claims, the host's principal and context,
 * the verified publisher, this issuer's name, the requested
 * `contentGroups: {contentName: {groups, windows}}`, requested `items`, and
 * `request: {periodGeometry, renderPeriod}`, the request's frozen geometry pair
 * and render-period label. Those two are unsigned and grant nothing: policy
 * reads requested windows under that geometry and takes reach from the verified
 * claims and trusted configuration; the render time it needs is the verified
 * `issuedAt`. A policy that does not serve a geometry denies it.
 * It answers grants of three kinds and a whole-reach authorizer:
 * `{kind: "chain", contentName, group, windowStart, cutoffT}`,
 * `{kind: "period", contentName, group, t}` and `{kind: "item", contentName}`.
 * `authorizePeriod(contentName, group, t, windowStart)` must answer `true` for
 * every period a chain grant reaches, from the window start through the
 * cutoff.
 *
 * @typedef {object} ContentGroupsPolicy
 * @property {(input: any) => any} decide
 */

/**
 * The portable contribution produced here. Integration checks it against its
 * complete issuer contribution contract when composing the selected source.
 * @typedef {Readonly<{
 *   name: string,
 *   requestBounds: ((request: any) => void)[],
 *   responseSectionSource: import('../../../core-issuer/IssuerEngine.js').ResponseSectionSource,
 *   responseSections: readonly Readonly<import('../../../core-shared--client-issuer/responseKeys.js').ComposedSection>[]
 * }>} ContentGroupsIssuerContribution
 */

/**
 * The content-groups contribution to `createIssuerCore`. It answers through
 * the base processor and engine: its request bound runs during admission,
 * before signature verification; its section source answers
 * `contentGroupKeys.{chainKeys,periodKeys,contentKeys}` under the request's
 * captured `periodGeometry` after the base coordinates. A malformed request, a seed
 * envelope that does not open refuses the whole exchange, base keys included.
 * An authorized item grant returns the candidate recovered from the connector;
 * the client authenticates its content with that key.
 * A seed opening under a retired opening key refuses nothing: each granted
 * coordinate that needed that seed gets `{error: "key_retired"}` under
 * `contentGroupKeys.errors`, and its siblings keep their keys. Keys go back in
 * the direct representation.
 *
 * @param {{ chain?: any, policy: ContentGroupsPolicy, limits?: Record<string, number> }} options
 * @returns {ContentGroupsIssuerContribution}
 */
export function contentGroupsIssuerContribution({
  chain = STOCK_CHAIN,
  policy,
  limits: inputLimits,
}) {
  if (
    !chain ||
    ["settleGeometry", "coordinate", "labelAt", "familyGeneration"].some(
      (name) => typeof chain[name] !== "function",
    )
  )
    throw new Error("content groups need the host's trusted chain port");
  if (!policy || typeof policy.decide !== "function")
    throw new Error("content groups need a policy with decide(input)");
  const limits = settleLimits(inputLimits);

  /** @param {import('../../../core-issuer/IssuerEngine.js').ResponseSectionUnlock} unlock */
  async function respond(unlock) {
    const { request, claims, policyInput } = unlock;
    const document = request.toObject();
    const members = boundedMembers(document, limits);
    if (members === null) throw refusal("the request presents no content-group coordinate");
    const { seeds, groups, items, cutoffs } = members;
    const issuerName = /** @type {string} */ (request.issuerName);
    const publisher = claims.origin;
    const renderId = claims.renderId;

    // Coordinates and labels, before policy and before any seed opens.
    const { geometry, period, scopes, itemNames, ceilings } = admitting(() => {
      validateClaim(claims, publisher);
      const checked = checkedScope(document, chain);
      // Every requested cutoff label is admitted before the lowest one of its
      // window becomes that window's ceiling: record order never raises one.
      /** @type {Record<string, string>|undefined} */
      let lowest;
      if (cutoffs !== undefined) {
        lowest = {};
        for (const [window, labels] of Object.entries(cutoffs)) {
          checkedWindow(window, checked.geometry, chain);
          let ceiling;
          for (const t of labels) {
            const at = chain.coordinate(t, checked.geometry);
            if (at.startT !== window) throw new Error("a requested cutoff lies outside its window");
            if (ceiling === undefined || at.position < ceiling.position) ceiling = at;
          }
          setOwn(lowest, window, ceiling.t);
        }
      }
      for (const windows of Object.values(seeds))
        for (const label of Object.keys(windows)) checkedWindow(label, checked.geometry, chain);
      /** @type {Record<string, { groups: string[], windows: string[] }>} */
      const coordinates = {};
      for (const [contentName, list] of Object.entries(groups)) {
        const supplied = Object.keys(own(seeds, contentName) ?? {});
        const windows =
          lowest === undefined ? supplied : supplied.filter((w) => Object.hasOwn(lowest, w));
        setOwn(coordinates, contentName, { groups: [...list], windows });
      }
      for (const contentName of Object.keys(items))
        if (!Object.hasOwn(own(seeds, contentName) ?? {}, checked.period.startT))
          throw new Error("a requested content key has no render-window seed");
      const names = Object.keys(items);
      if (Object.keys(coordinates).length === 0 && names.length === 0)
        throw new Error("the request presents no content-group coordinate");
      return { ...checked, scopes: coordinates, itemNames: names, ceilings: lowest };
    });

    const decisionInput = {
      claims,
      principal: policyInput.principal,
      context: policyInput.context,
      publisher: policyInput.publisher,
      issuerName,
      contentGroups: structuredClone(scopes),
      items: [...itemNames],
      // Unsigned: admitted for shape only. Policy interprets windows under this
      // geometry; seed opening later checks it through the envelope AAD.
      request: Object.freeze({
        periodGeometry: Object.freeze({
          chainsPerDay: geometry.chainsPerDay,
          periodMinutes: geometry.periodMinutes,
        }),
        renderPeriod: period.t,
      }),
    };
    let decision;
    try {
      decision = await policy.decide(decisionInput);
    } catch (cause) {
      if (/** @type {any} */ (cause)?.code === "policy_unavailable") throw cause;
      throw dcaError("internal_error", "the content-groups policy failed unexpectedly");
    }
    if (
      !record(decision) ||
      !Array.isArray(decision.grants) ||
      typeof decision.authorizePeriod !== "function"
    )
      throw policyFault("the policy answers grants and a whole-reach authorizer");
    if (decision.grants.length > limits.maxResponseMembers)
      throw policyFault("the policy answers more grants than maxResponseMembers");

    const accepted = await acceptedGrants(decision, {
      scopes,
      itemNames,
      items,
      cutoffs: ceilings,
      geometry,
    });
    if (accepted.length === 0) return {};

    /** @type {Map<string, any[]>} */
    const handles = new Map();
    // Seeds whose opening found the selected opening key retired. Retirement
    // is the key's, not the envelope's, so it reports the coordinate and
    // leaves the exchange standing; every other opening failure refuses it.
    /** @type {Set<string>} */
    const retired = new Set();
    /**
     * The seed handles of one content name and window, one per distinct seed
     * envelope the request carried there, or null when the selected opening
     * key is retired. Every envelope opens: a rival that opens yields its own
     * candidate keys, and one that does not open refuses the exchange.
     * @param {string} contentName @param {string} windowStart
     * @returns {Promise<any[]|null>}
     */
    const handlesFor = async (contentName, windowStart) => {
      const id = JSON.stringify([contentName, windowStart]);
      if (retired.has(id)) return null;
      if (!handles.has(id)) {
        /** @type {any[]} */
        const opened = [];
        handles.set(id, opened);
        const aad = await contentNameSeedAad(
          {
            publisher,
            renderId,
            issuerName,
            contentName,
            windowStartLabel: windowStart,
            periodGeometry: geometry,
          },
          chain,
        );
        for (const envelope of own(own(seeds, contentName), windowStart)) {
          // The engine selects the procedure from the trusted key entry.
          const result = await unlock.openAuxiliary(envelope, { aad });
          if (!("bytes" in result)) {
            if (result.error?.error !== "key_retired")
              throw refusal("a seed envelope does not open at its coordinate");
            retired.add(id);
            return null;
          }
          try {
            opened.push(seedHandle(result.bytes, geometry, windowStart, chain));
          } finally {
            result.bytes.fill(0);
          }
        }
      }
      return handles.get(id) ?? null;
    };
    /** @type {import("../core-shared--client-issuer/request.js").ContentGroupChainKeys<string>} */
    const chainKeys = [];
    /** @type {import("../core-shared--client-issuer/request.js").ContentGroupPeriodKeys<string>} */
    const periodKeys = [];
    /** @type {import("../core-shared--client-issuer/request.js").ContentGroupContentKeys<string>} */
    const contentKeys = [];
    /** @type {Required<import("../core-shared--client-issuer/request.js").ContentGroupResponseErrors>} */
    const errors = { chainKeys: [], periodKeys: [], contentKeys: [] };
    // An error record carries its coordinate and the fixed error, never a
    // message or a key.
    const RETIRED = /** @type {const} */ ("key_retired");
    /** @param {Iterable<string>} keys */
    const distinct = (keys) => [...new Set(keys)];
    // Every handle keeps its own copy of an opened seed; zero each copy
    // when the grants are done, answered or refused.
    try {
      for (const grant of accepted) {
        if (grant.kind === "chain") {
          const coordinate = {
            contentName: grant.contentName,
            group: grant.group,
            cutoff: grant.cutoffT,
          };
          const sources = await handlesFor(grant.contentName, grant.windowStart);
          if (sources === null) {
            errors.chainKeys.push({ ...coordinate, error: RETIRED });
            continue;
          }
          /** @type {string[]} */
          const keys = [];
          for (const handle of sources) {
            const capability = await handle.chainKey(grant.group, grant.cutoffT);
            keys.push(base64urlEncode(capability.key));
          }
          for (const key of distinct(keys)) chainKeys.push({ ...coordinate, key });
        } else if (grant.kind === "period") {
          const coordinate = {
            contentName: grant.contentName,
            group: grant.group,
            period: grant.t,
          };
          const sources = await handlesFor(grant.contentName, grant.windowStart);
          if (sources === null) {
            errors.periodKeys.push({ ...coordinate, error: RETIRED });
            continue;
          }
          /** @type {string[]} */
          const keys = [];
          for (const handle of sources)
            keys.push(base64urlEncode(await handle.periodKey(grant.group, grant.t)));
          for (const key of distinct(keys)) periodKeys.push({ ...coordinate, key });
        } else {
          const sources = await handlesFor(grant.contentName, period.startT);
          if (sources === null) {
            errors.contentKeys.push({ contentName: grant.contentName, error: RETIRED });
            continue;
          }
          /** @type {string[]} */
          const keys = [];
          // Every requested route keeps its own group and connector; each
          // seed source and route gives one candidate for this one item.
          for (const route of grant.routes)
            for (const handle of sources) {
              // The pad binds the verified render id, the content name and the
              // period key of this name's seed at the request's render period.
              const key = await handle.periodKey(route.group, period.t);
              const pad = await itemPad(key, { renderId, contentName: grant.contentName });
              const recovered = xor16(bytes(route.connector, 16, "relayed connector"), pad);
              // The connector is relayed request data. Only the client's body
              // authentication determines whether this candidate opens the item.
              keys.push(base64urlEncode(recovered));
            }
          for (const key of distinct(keys))
            contentKeys.push({ contentName: grant.contentName, key });
        }
      }
    } finally {
      for (const opened of handles.values()) for (const handle of opened) handle.dispose();
    }
    withinOutputBounds({ chainKeys, periodKeys, contentKeys, errors });
    /** @param {unknown[]} list */
    const present = (list) => list.length > 0;
    const reported = {
      ...(present(errors.chainKeys) ? { [CONTRACT.wire.chainKeys]: errors.chainKeys } : {}),
      ...(present(errors.periodKeys) ? { [CONTRACT.wire.periodKeys]: errors.periodKeys } : {}),
      ...(present(errors.contentKeys) ? { [CONTRACT.wire.contentKeys]: errors.contentKeys } : {}),
    };
    /** @type {{contentGroupKeys: import("../core-shared--client-issuer/request.js").ContentGroupResponse<string>}} */
    const answer = {
      [RESPONSE_MEMBER]: {
        ...(present(chainKeys) ? { [CONTRACT.wire.chainKeys]: chainKeys } : {}),
        ...(present(periodKeys) ? { [CONTRACT.wire.periodKeys]: periodKeys } : {}),
        ...(present(contentKeys) ? { [CONTRACT.wire.contentKeys]: contentKeys } : {}),
        ...(Object.keys(reported).length > 0 ? { [CONTRACT.wire.errors]: reported } : {}),
      },
    };
    return answer;
  }

  /**
   * The client counts every raw record of the member, candidates and errors
   * included, against its response bounds and refuses the whole member over
   * one. Rival seeds and item-route alternatives multiply admitted grants
   * into records, so the issuer counts the same way before it answers. An
   * answer over a bound is never trimmed: the request asked for more
   * candidates than one exchange carries, and it is refused.
   *
   * @param {{ chainKeys: { contentName: string, group: string, cutoff: string }[],
   *   periodKeys: { contentName: string, group: string }[],
   *   contentKeys: unknown[], errors: Required<import("../core-shared--client-issuer/request.js").ContentGroupResponseErrors> }} answer
   */
  function withinOutputBounds({ chainKeys, periodKeys, contentKeys, errors }) {
    const over = (/** @type {string} */ why) =>
      dcaError("too_many_entries", `content-group answer: ${why}`);
    const total =
      chainKeys.length +
      periodKeys.length +
      contentKeys.length +
      errors.chainKeys.length +
      errors.periodKeys.length +
      errors.contentKeys.length;
    if (total > limits.maxResponseMembers) throw over("records over maxResponseMembers");
    /** @type {Map<string, number>} */
    const periods = new Map();
    for (const { contentName, group } of [...periodKeys, ...errors.periodKeys]) {
      const id = JSON.stringify([contentName, group]);
      const count = (periods.get(id) ?? 0) + 1;
      if (count > limits.maxPeriodKeysPerContentGroup)
        throw over("period records over maxPeriodKeysPerContentGroup");
      periods.set(id, count);
    }
    // A window bound: candidates share their window's one selected cutoff, so
    // distinct cutoffs per content name and group are distinct windows.
    /** @type {Map<string, Set<string>>} */
    const windows = new Map();
    for (const { contentName, group, cutoff } of [...chainKeys, ...errors.chainKeys]) {
      const id = JSON.stringify([contentName, group]);
      const held = windows.get(id) ?? new Set();
      held.add(cutoff);
      windows.set(id, held);
      if (held.size > limits.maxWindowsPerGroup)
        throw over("chain windows over maxWindowsPerGroup");
    }
  }

  /**
   * Admit the policy's grants against the requested coordinates, in order;
   * every period a chain grant reaches must be authorized.
   *
   * @param {any} decision
   * @param {{ scopes: Record<string, { groups: string[], windows: string[] }>, itemNames: string[],
   *   items: Readonly<Record<string, readonly { group: string, connector: string }[]>>,
   *   cutoffs: Record<string, string>|undefined, geometry: any }} requested
   */
  async function acceptedGrants(decision, { scopes, itemNames, items, cutoffs, geometry }) {
    /** @type {any[]} */
    const accepted = [];
    const seen = new Set();
    /** @type {Map<string, number>} */
    const windowsPer = new Map();
    /** @type {Map<string, number>} */
    const periodsPer = new Map();
    /** @param {Map<string, number>} counter @param {string} id @param {number} max @param {string} label */
    const count = (counter, id, max, label) => {
      const used = (counter.get(id) ?? 0) + 1;
      if (used > max) throw policyFault(`${label} budget exceeded`);
      counter.set(id, used);
    };
    /** @param {string} id */
    const once = (id) => {
      if (seen.has(id)) throw policyFault("duplicate policy grant");
      seen.add(id);
    };
    /** @param {any} grant */
    const inside = (grant) => {
      const scope = own(scopes, grant.contentName);
      if (!scope || !scope.groups.includes(grant.group))
        throw policyFault("a policy grant lies outside the requested names and groups");
      return scope;
    };
    /** @param {string} t */
    const coordinate = (t) => {
      try {
        return chain.coordinate(t, geometry);
      } catch {
        throw policyFault("a policy grant names an invalid period label");
      }
    };
    for (const grant of decision.grants) {
      if (!record(grant)) throw policyFault("a policy grant is a record");
      if (grant.kind === "chain") {
        const scope = inside(grant);
        if (!scope.windows.includes(grant.windowStart))
          throw policyFault("a policy grant lies outside the supplied windows");
        once(JSON.stringify(["chain", grant.contentName, grant.group, grant.windowStart]));
        count(
          windowsPer,
          JSON.stringify([grant.contentName, grant.group]),
          limits.maxWindowsPerGroup,
          "window",
        );
        const policyAt = coordinate(grant.cutoffT);
        if (policyAt.startT !== grant.windowStart)
          throw policyFault("a policy cutoff lies outside its window");
        const ceiling = own(cutoffs, grant.windowStart);
        const asked = ceiling === undefined ? policyAt : coordinate(ceiling);
        const cutoff = asked.position < policyAt.position ? asked : policyAt;
        // A chain key derives every earlier period of its window.
        for (let position = 0; position <= cutoff.position; position++) {
          const t = labelAt(cutoff.windowStart + position * geometry.periodMinutes, chain);
          if (
            (await decision.authorizePeriod(
              grant.contentName,
              grant.group,
              t,
              grant.windowStart,
            )) !== true
          )
            throw policyFault("the policy does not authorize the whole backward chain reach");
        }
        accepted.push({
          kind: "chain",
          contentName: grant.contentName,
          group: grant.group,
          windowStart: grant.windowStart,
          cutoffT: cutoff.t,
        });
      } else if (grant.kind === "period") {
        const scope = inside(grant);
        const at = coordinate(grant.t);
        if (!scope.windows.includes(at.startT))
          throw policyFault("a policy grant lies outside the supplied windows");
        const ceiling = own(cutoffs, at.startT);
        if (ceiling !== undefined && at.position > coordinate(ceiling).position)
          throw policyFault("a period grant lies beyond the requested cutoff");
        once(JSON.stringify(["period", grant.contentName, grant.group, at.t]));
        count(
          periodsPer,
          JSON.stringify([grant.contentName, grant.group]),
          limits.maxPeriodKeysPerContentGroup,
          "period key",
        );
        if (
          (await decision.authorizePeriod(grant.contentName, grant.group, at.t, at.startT)) !== true
        )
          throw policyFault("the policy does not authorize the period");
        accepted.push({
          kind: "period",
          contentName: grant.contentName,
          group: grant.group,
          t: at.t,
          windowStart: at.startT,
        });
      } else if (grant.kind === "item") {
        if (!itemNames.includes(grant.contentName))
          throw policyFault("a policy grant lies outside the requested items");
        once(JSON.stringify(["item", grant.contentName]));
        accepted.push({
          kind: "item",
          contentName: grant.contentName,
          routes: own(items, grant.contentName),
        });
      } else throw policyFault("unknown policy grant kind");
    }
    return accepted;
  }

  const responseSectionSource = Object.freeze({
    name: EXTENSION,
    members: [RESPONSE_MEMBER],
    // The seed envelope exists only under the base ecdh-p256 procedure: 32
    // seed bytes under the seed AAD. Under any other procedure the engine
    // selects, a seed does not open.
    envelopeOpeners: Object.freeze({ "ecdh-p256": openSeed }),
    presented: presents,
    respond,
  });
  return Object.freeze({
    name: EXTENSION,
    requestBounds: [
      (/** @type {any} */ request) => {
        boundedMembers(request.toObject(), limits);
      },
    ],
    responseSectionSource,
    // Client-bound transport wraps each key of these sections; createIssuerCore
    // refuses the source's contentGroupKeys member without them.
    responseSections: RESPONSE_SECTIONS,
  });
}

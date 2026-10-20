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
 * leaves out: every seed envelope is exactly 125 bytes. It verifies nothing:
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
      for (const envelope of Object.values(windows))
        bytes(envelope, ENVELOPE_BYTES, "seed envelope");
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
  return (
    (record(groups) && Object.keys(groups).length > 0) ||
    (record(items) && Object.keys(items).length > 0)
  );
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
 * The content-groups contribution to `createIssuerCore`. It answers through
 * the base processor and engine: its request bound runs during admission,
 * before signature verification; its section source answers
 * `contentGroups.{chainKeys,periodKeys,contentKeys}` under the request's
 * captured `periodGeometry` after the base coordinates. A malformed request, a seed
 * envelope that does not open refuses the whole exchange, base keys included.
 * An authorized item grant returns the candidate recovered from the connector;
 * the client authenticates its content with that key.
 * A seed opening under a retired opening key refuses nothing: each granted
 * coordinate that needed that seed gets `{error: "key_retired"}` under
 * `contentGroups.errors`, and its siblings keep their keys. Keys go back in
 * the direct representation.
 *
 * @param {{ chain?: any, policy: ContentGroupsPolicy, limits?: Record<string, number> }} options
 * @returns {import('../../../integration-issuer/createIssuerCore.js').IssuerContribution}
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
    const { geometry, period, scopes, itemNames } = admitting(() => {
      validateClaim(claims, publisher);
      const checked = checkedScope(document, chain);
      for (const [window, t] of Object.entries(cutoffs ?? {})) {
        checkedWindow(window, checked.geometry, chain);
        if (chain.coordinate(t, checked.geometry).startT !== window)
          throw new Error("a requested cutoff lies outside its window");
      }
      for (const windows of Object.values(seeds))
        for (const label of Object.keys(windows)) checkedWindow(label, checked.geometry, chain);
      /** @type {Record<string, { groups: string[], windows: string[] }>} */
      const coordinates = {};
      for (const [contentName, list] of Object.entries(groups)) {
        const supplied = Object.keys(own(seeds, contentName) ?? {});
        const windows =
          cutoffs === undefined ? supplied : supplied.filter((w) => Object.hasOwn(cutoffs, w));
        setOwn(coordinates, contentName, { groups: [...list], windows });
      }
      for (const contentName of Object.keys(items))
        if (!Object.hasOwn(own(seeds, contentName) ?? {}, checked.period.startT))
          throw new Error("a requested content key has no render-window seed");
      const names = Object.keys(items);
      if (Object.keys(coordinates).length === 0 && names.length === 0)
        throw new Error("the request presents no content-group coordinate");
      return { ...checked, scopes: coordinates, itemNames: names };
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
      cutoffs,
      geometry,
    });
    if (accepted.length === 0) return {};

    /** @type {Map<string, any>} */
    const handles = new Map();
    // Seeds whose opening found the selected opening key retired. Retirement
    // is the key's, not the envelope's, so it reports the coordinate and
    // leaves the exchange standing; every other opening failure refuses it.
    /** @type {Set<string>} */
    const retired = new Set();
    /**
     * The seed handle of one content name and window, or null when the
     * selected opening key is retired.
     * @param {string} contentName @param {string} windowStart
     */
    const handleFor = async (contentName, windowStart) => {
      const id = JSON.stringify([contentName, windowStart]);
      if (retired.has(id)) return null;
      if (!handles.has(id)) {
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
        // The engine selects the procedure from the trusted key entry.
        const opened = await unlock.openAuxiliary(own(own(seeds, contentName), windowStart), {
          aad,
        });
        if (!("bytes" in opened)) {
          if (opened.error?.error !== "key_retired")
            throw refusal("a seed envelope does not open at its coordinate");
          retired.add(id);
          return null;
        }
        try {
          handles.set(id, seedHandle(opened.bytes, geometry, windowStart, chain));
        } finally {
          opened.bytes.fill(0);
        }
      }
      return handles.get(id);
    };
    // Content and group names are request data: `constructor` or `__proto__`
    // must file as own members, never reach an inherited one.
    /** @param {any} root @param {string[]} path @param {any} value */
    const put = (root, path, value) => {
      let node = root;
      for (const part of path.slice(0, -1)) {
        if (!Object.hasOwn(node, part)) setOwn(node, part, {});
        node = own(node, part);
      }
      setOwn(node, path[path.length - 1], value);
    };
    /** @type {Record<string, any>} */
    const chainKeys = {};
    /** @type {Record<string, any>} */
    const periodKeys = {};
    /** @type {Record<string, string>} */
    const contentKeys = {};
    /** @type {Record<string, any>} */
    const errors = {};
    // A fixed record, never a message: an error leaf carries nothing else.
    const retirement = () => ({ error: "key_retired" });
    // Every handle keeps its own copy of an opened seed; zero each copy
    // when the grants are done, answered or refused.
    try {
      for (const grant of accepted) {
        if (grant.kind === "chain") {
          const coordinate = [grant.contentName, grant.group, grant.cutoffT];
          const handle = await handleFor(grant.contentName, grant.windowStart);
          if (handle === null) {
            put(errors, [CONTRACT.wire.chainKeys, ...coordinate], retirement());
            continue;
          }
          const capability = await handle.chainKey(grant.group, grant.cutoffT);
          put(chainKeys, coordinate, base64urlEncode(capability.key));
        } else if (grant.kind === "period") {
          const coordinate = [grant.contentName, grant.group, grant.t];
          const handle = await handleFor(grant.contentName, grant.windowStart);
          if (handle === null) {
            put(errors, [CONTRACT.wire.periodKeys, ...coordinate], retirement());
            continue;
          }
          const key = await handle.periodKey(grant.group, grant.t);
          put(periodKeys, coordinate, base64urlEncode(key));
        } else {
          const handle = await handleFor(grant.contentName, period.startT);
          if (handle === null) {
            put(errors, [CONTRACT.wire.contentKeys, grant.contentName], retirement());
            continue;
          }
          // The pad binds the verified render id, the content name and the
          // period key of this name's seed at the request's render period.
          const key = await handle.periodKey(grant.group, period.t);
          const pad = await itemPad(key, { renderId, contentName: grant.contentName });
          const recovered = xor16(bytes(grant.connector, 16, "relayed connector"), pad);
          // The connector is relayed request data. Only the client's body
          // authentication determines whether this candidate opens the item.
          setOwn(contentKeys, grant.contentName, base64urlEncode(recovered));
        }
      }
    } finally {
      for (const handle of handles.values()) handle.dispose();
    }
    /** @param {object} map */
    const present = (map) => Object.keys(map).length > 0;
    const answer = {
      [RESPONSE_MEMBER]: {
        ...(present(chainKeys) ? { [CONTRACT.wire.chainKeys]: chainKeys } : {}),
        ...(present(periodKeys) ? { [CONTRACT.wire.periodKeys]: periodKeys } : {}),
        ...(present(contentKeys) ? { [CONTRACT.wire.contentKeys]: contentKeys } : {}),
        ...(present(errors) ? { [CONTRACT.wire.errors]: errors } : {}),
      },
    };
    return answer;
  }

  /**
   * Admit the policy's grants against the requested coordinates, in order;
   * every period a chain grant reaches must be authorized.
   *
   * @param {any} decision
   * @param {{ scopes: Record<string, { groups: string[], windows: string[] }>, itemNames: string[],
   *   items: Record<string, { group: string, connector: string }>, cutoffs: Record<string, string>|undefined,
   *   geometry: any }} requested
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
          ...own(items, grant.contentName),
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
    // refuses the source's contentGroups member without them.
    responseSections: RESPONSE_SECTIONS,
  });
}

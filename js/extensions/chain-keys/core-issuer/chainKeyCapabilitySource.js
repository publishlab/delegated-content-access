// @ts-check
//
// The issuer input of one named construction profile. The request supplies
// explicit geometry and positioned chain keys sealed under that same geometry.
// This source opens each selected member once and projects only
// policy-authorized period keys into the ordinary base response. The profile
// the route was composed on states the chain-key width, so every width here
// comes from the composition rather than from a payload length.

import { dcaError } from "../../../core-shared/errors.js";
import { chainMemberLimit } from "../../../core-shared/chainMemberLimit.js";
import {
  MAX_PERIOD_KEYS_PER_FAMILY,
  MAX_PERIOD_KEYS_PER_RESPONSE,
} from "../../../core-shared/geometryBounds.js";
import {
  CHAIN_KEY_CONSTRUCTION,
  chainKeyConstructionProfile,
  chainKeyCoordinate,
  chainKeyDerivations,
  chainKeyLabelAt,
} from "../core-shared/chainKeyConstruction.js";
import { chainKeyRequestInput } from "./chainKeyRequestInput.js";

const MS_PER_MINUTE = 60_000;
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;
const UNSEAL_FAILED = Object.freeze({
  error: "unseal_failed",
  message: "sealed value could not be opened",
});
const MISS = Object.freeze({ miss: /** @type {true} */ (true) });
const UNAVAILABLE = Object.freeze({ unavailable: /** @type {true} */ (true) });
const AUTHORIZED_UNAVAILABLE = Object.freeze({
  unavailable: /** @type {const} */ ("unavailable"),
});
const DENIED = Object.freeze({ unavailable: /** @type {const} */ ("denied") });

/** @param {unknown} value */
function capturedMinutes(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || Math.abs(value) > MAX_DATE_EPOCH_MS) {
    throw dcaError(
      "bad_config",
      "a chain capability source needs finite host-captured epoch milliseconds within Date range",
    );
  }
  return Math.floor(value / MS_PER_MINUTE);
}

/**
 * The supplied member that serves one already authorized target. A valid
 * member serves first. A member whose sealed value the reader refused still
 * serves a target no valid member reaches, so that authorized coordinate is
 * answered with `unseal_failed` at its supplied label (core Section 7.1)
 * rather than read as missing supply.
 *
 * @param {any} family @param {string} t
 */
function sourceFor(family, t) {
  const target = chainKeyCoordinate(t, family.geometry);
  const serves = (/** @type {any} */ member) =>
    member.coordinate.windowStart === target.windowStart &&
    member.coordinate.position >= target.position;
  return family.members.find(serves) ?? family.malformedMembers.find(serves);
}

/** @param {any} grant */
function validGrant(grant) {
  if (
    grant === null ||
    typeof grant !== "object" ||
    typeof grant.accessGroup !== "string" ||
    !Number.isInteger(grant.futurePeriodCount) ||
    grant.futurePeriodCount < 0 ||
    typeof grant.authorizePeriod !== "function"
  ) {
    throw dcaError("bad_policy", "a chain grant needs a future count and period authorizer");
  }
  return grant;
}

/**
 * Evaluate one trusted decision at most once per coordinate. A policy callback
 * is never fed back into request admission or inferred from unsigned hints.
 *
 * @param {any} grant
 */
function authorizerFor(grant) {
  /** @type {Map<string, boolean>} */
  const checked = new Map();
  return (/** @type {string} */ t) => {
    if (checked.has(t)) return checked.get(t);
    let answer;
    try {
      answer = grant.authorizePeriod(t);
    } catch {
      throw dcaError("bad_policy", "the period authorizer failed");
    }
    if (typeof answer !== "boolean") {
      throw dcaError("bad_policy", "the period authorizer must return a boolean");
    }
    checked.set(t, answer);
    return answer;
  };
}

/**
 * @param {{ representation?: 'period-keys'|'chain-keys', construction?: string, maxChainMembersPerMessage?: number }} [config] -
 *   `construction` names the canonical construction this route is on. Omitting
 *   it selects `dca-construction-chain-keys`, whose chain keys are 16 bytes. An
 *   unknown name is refused here, before any request reaches it.
 * @returns {import('../../../core-issuer/IssuerEngine.js').PeriodCapabilitySource}
 */
export function chainKeyCapabilitySource({
  representation = "period-keys",
  construction = CHAIN_KEY_CONSTRUCTION,
  maxChainMembersPerMessage,
} = {}) {
  if (representation !== "period-keys" && representation !== "chain-keys") {
    throw dcaError(
      "bad_config",
      `unknown chain-key response representation ${JSON.stringify(representation)}`,
    );
  }
  const maximum = chainMemberLimit(maxChainMembersPerMessage);
  const profile = chainKeyConstructionProfile(construction);
  const {
    chainKeyFromChainKey: derivedChainKeyFromChainKey,
    periodKeysFromChainKey: derivedPeriodKeysFromChainKey,
  } = chainKeyDerivations(profile.name);
  // Base asks this source three times for one unlock: what it presents,
  // what it selects, and what it represents. All three read the same
  // untrusted carrier, so this source reads the carrier at the first call
  // and hands the other two the resolved view.
  /** @type {WeakMap<object, any>} */
  const resolved = new WeakMap();
  /** @param {any} request */
  const carrierOf = (request) => {
    if (request === null || typeof request !== "object")
      return chainKeyRequestInput(request, { maxChainMembersPerMessage: maximum });
    const held = resolved.get(request);
    if (held !== undefined) return held;
    const view = chainKeyRequestInput(request, { maxChainMembersPerMessage: maximum });
    resolved.set(request, view);
    return view;
  };

  return {
    presented(request) {
      return { accessGroups: carrierOf(request).presented };
    },

    selection(request, invocation, trustedGrants) {
      const input = carrierOf(request);
      const nowMinutes = capturedMinutes(invocation?.capturedAtMs);
      if (!Array.isArray(trustedGrants)) {
        throw dcaError("bad_policy", "chain selection needs the complete trusted grant set");
      }

      /** @type {Map<string, any>} */
      const states = new Map();
      for (const rawGrant of trustedGrants) {
        // Ordinary explicit-label grants belong to the base period-key route.
        // This source is selected only by the independent chain-horizon form.
        if (rawGrant?.authorizePeriod === undefined) continue;
        const grant = validGrant(rawGrant);
        if (states.has(grant.accessGroup)) {
          throw dcaError("bad_policy", "a chain family has one normalized trusted grant");
        }
        const family = input.family(grant.accessGroup);
        states.set(grant.accessGroup, {
          grant,
          family,
          permits: authorizerFor(grant),
          targets: new Map(),
          articleTargets: new Set(),
          denied: false,
          authorized: false,
          authorizedUnsupplied: false,
        });
      }

      let responsePeriodKeys = 0;
      /** @param {any} state @param {string} t */
      const consider = (state, t) => {
        if (!state.permits(t)) {
          state.denied = true;
          return false;
        }
        state.authorized = true;
        const member = sourceFor(state.family, t);
        if (!member) {
          state.authorizedUnsupplied = true;
          return false;
        }
        if (state.targets.has(t)) return true;
        if (
          representation === "period-keys" &&
          (state.targets.size >= MAX_PERIOD_KEYS_PER_FAMILY ||
            responsePeriodKeys >= MAX_PERIOD_KEYS_PER_RESPONSE)
        )
          return false;
        state.targets.set(t, member);
        if (representation === "period-keys") responsePeriodKeys++;
        return true;
      };

      const ordered = [...states.keys()].sort();
      // Reserve every sourceable article target across all families before any
      // current/future grant can occupy a response slot. The request reader has
      // already admitted, sorted and deduplicated the untrusted hint arrays.
      for (const accessGroup of ordered) {
        const state = states.get(accessGroup);
        if (state.family.kind !== "valid") continue;
        const desired = Object.hasOwn(input.requestedPeriodKeys ?? {}, accessGroup)
          ? input.requestedPeriodKeys[accessGroup]
          : [];
        for (const t of desired) {
          if (consider(state, t)) state.articleTargets.add(t);
        }
      }

      for (const accessGroup of ordered) {
        const state = states.get(accessGroup);
        if (state.family.kind !== "valid") continue;
        const { geometry, members, malformedMembers } = state.family;
        if (members.length === 0 && malformedMembers.length === 0) continue;
        const aligned =
          nowMinutes -
          (((nowMinutes % geometry.periodMinutes) + geometry.periodMinutes) %
            geometry.periodMinutes);
        const lastSuppliedMinute = Math.max(
          ...[...members, ...malformedMembers].map(
            (/** @type {any} */ member) =>
              member.coordinate.windowStart + member.coordinate.position * geometry.periodMinutes,
          ),
        );
        const count = Math.min(state.grant.futurePeriodCount, MAX_PERIOD_KEYS_PER_FAMILY);
        for (let index = 0; index < count; index++) {
          const targetMinute = aligned + index * geometry.periodMinutes;
          if (targetMinute > lastSuppliedMinute) {
            if (index === 0) {
              const currentT = chainKeyLabelAt(targetMinute);
              if (state.permits(currentT)) {
                state.authorized = true;
                state.authorizedUnsupplied = true;
              } else {
                state.denied = true;
              }
            }
            break;
          }
          const t = chainKeyLabelAt(targetMinute);
          if (!consider(state, t)) break;
        }
      }

      /** @type {Map<string, any>} */
      const answers = new Map();
      /** @type {Map<string, any[]>} */
      const candidates = new Map();
      for (const accessGroup of ordered) {
        const state = states.get(accessGroup);
        if (state.family.kind === "absent") {
          answers.set(accessGroup, MISS);
          continue;
        }
        if (
          state.family.kind === "valid" &&
          state.family.members.length === 0 &&
          state.family.malformedMembers.length === 0
        ) {
          answers.set(accessGroup, UNAVAILABLE);
          continue;
        }
        if (state.family.kind === "invalid") {
          answers.set(accessGroup, UNAVAILABLE);
          continue;
        }
        /** @type {Map<string, any>} */
        const byMember = new Map();
        for (const [t, member] of state.targets) {
          let selected = byMember.get(member.t);
          if (!selected) {
            selected = {
              t: member.t,
              chainKey: true,
              chainsPerDay: state.family.geometry.chainsPerDay,
              periodMinutes: state.family.geometry.periodMinutes,
              targetTs: [],
            };
            byMember.set(member.t, selected);
          }
          selected.targetTs.push(t);
        }
        /** @type {any[]} */
        const selected = [];
        for (const entry of byMember.values()) {
          entry.targetTs.sort();
          if (representation === "chain-keys") {
            const latest = chainKeyCoordinate(entry.targetTs.at(-1), state.family.geometry);
            let allowedThrough = -1;
            for (let position = 0; position <= latest.position; position++) {
              const t = chainKeyLabelAt(
                latest.windowStart + position * state.family.geometry.periodMinutes,
              );
              if (!state.permits(t)) break;
              allowedThrough = position;
            }
            entry.targetTs = entry.targetTs.filter(
              (/** @type {string} */ t) =>
                chainKeyCoordinate(t, state.family.geometry).position <= allowedThrough,
            );
            if (entry.targetTs.length === 0) continue;
          }
          selected.push({
            selection: Object.freeze({ ...entry, targetTs: Object.freeze(entry.targetTs) }),
            article: entry.targetTs.some((/** @type {string} */ t) => state.articleTargets.has(t)),
          });
        }
        if (selected.length > 0) {
          candidates.set(accessGroup, selected);
        } else if (state.authorizedUnsupplied && state.targets.size === 0) {
          answers.set(accessGroup, AUTHORIZED_UNAVAILABLE);
        } else if (state.denied && !state.authorized) {
          answers.set(accessGroup, DENIED);
        } else {
          answers.set(accessGroup, UNAVAILABLE);
        }
      }

      // A chain response is bounded by source members, not projected keys.
      // Reserve its scarce slots for all article-bearing members before any
      // optional future-only member, across the entire request.
      let responseMembers = 0;
      for (const article of [true, false]) {
        for (const accessGroup of ordered) {
          for (const candidate of candidates.get(accessGroup) ?? []) {
            if (candidate.article !== article) continue;
            if (representation === "chain-keys" && responseMembers >= maximum) continue;
            const answer = answers.get(accessGroup) ?? { selected: [] };
            answer.selected.push(candidate.selection);
            answers.set(accessGroup, answer);
            responseMembers++;
          }
        }
      }
      for (const answer of answers.values()) {
        if (answer.selected)
          answer.selected.sort((/** @type {any} */ a, /** @type {any} */ b) =>
            a.t.localeCompare(b.t),
          );
      }

      return (accessGroup) => {
        return answers.get(accessGroup) ?? MISS;
      };
    },

    capabilities({ request, open }) {
      const input = carrierOf(request);
      return async (accessGroup, selected) => {
        const family = input.family(accessGroup);
        if (family.kind !== "valid") {
          throw dcaError(
            "bad_config",
            "selected chain input remains valid through capability production",
          );
        }
        const periods = [];
        for (const selection of /** @type {any[]} */ (selected)) {
          const member = family.members.find(
            (/** @type {any} */ candidate) => candidate.t === selection.t,
          );
          // The selection authorized this member before its value was
          // looked at. A value the reader refused is answered here without
          // reaching the opener, so its bytes are never decoded or opened.
          if (
            !member &&
            family.malformedMembers.some(
              (/** @type {any} */ candidate) => candidate.t === selection.t,
            )
          ) {
            periods.push({ t: selection.t, error: UNSEAL_FAILED });
            continue;
          }
          if (!member) {
            throw dcaError(
              "bad_config",
              "selected chain member remains present through capability production",
            );
          }
          // The coordinate is the binding this chain key was sealed at,
          // and the chain grammar names its position `suppliedT`.
          const opened = await open(member.sealed, {
            accessGroup,
            suppliedT: selection.t,
            chainKey: true,
            chainsPerDay: selection.chainsPerDay,
            periodMinutes: selection.periodMinutes,
          });
          if ("error" in opened) {
            periods.push({ t: selection.t, error: opened.error });
            continue;
          }
          // Material that opens to anything but one chain key is
          // malformed sealed material, like a tag that will not
          // verify, so it reads as the same per-coordinate
          // unseal_failed. A value that is not bytes at all comes
          // from a broken opener, and it falls through to the
          // construction's typed refusal. The source catches nothing
          // below this line: a refusal there is a fault in this
          // issuer, and it propagates with the error code the
          // construction threw.
          if (opened.bytes?.length !== profile.chainKeyBytes) {
            periods.push({ t: selection.t, error: UNSEAL_FAILED });
            continue;
          }
          const cutoffT = selection.targetTs[selection.targetTs.length - 1];
          if (representation === "chain-keys") {
            const chainKey = await derivedChainKeyFromChainKey({
              chainKey: opened.bytes,
              accessGroup,
              suppliedT: selection.t,
              targetT: cutoffT,
              geometry: family.geometry,
            });
            periods.push({ t: cutoffT, bytes: chainKey });
            continue;
          }
          const expansion = await derivedPeriodKeysFromChainKey({
            chainKey: opened.bytes,
            accessGroup,
            suppliedT: selection.t,
            cutoffT,
            geometry: family.geometry,
          });
          const wanted = new Set(selection.targetTs);
          for (const periodKey of expansion) {
            if (wanted.has(periodKey.t)) periods.push({ t: periodKey.t, bytes: periodKey.key });
          }
        }
        if (representation === "chain-keys") {
          return {
            kind: "chain-keys",
            interpretation: {
              geometry: {
                chainsPerDay: family.geometry.chainsPerDay,
                periodMinutes: family.geometry.periodMinutes,
              },
              selections: /** @type {any[]} */ (selected).map((selection) => ({
                suppliedT: selection.t,
                cutoffT: selection.targetTs[selection.targetTs.length - 1],
              })),
            },
            periods,
          };
        }
        return {
          kind: "period-keys",
          interpretation: { selections: selected },
          periods,
        };
      };
    },
  };
}

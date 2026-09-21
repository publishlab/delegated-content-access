// @ts-check
//
// The issuer input of one named construction profile. The request supplies
// explicit geometry and positioned state sealed under that same geometry. This
// source opens each selected member once and projects only policy-authorized
// exact leaves into the ordinary base response. The profile the route was
// composed on states the state width, so every width here comes from the
// composition rather than from a payload length.

import { dcaError } from "../../../core-shared/errors.js";
import {
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_EXACT_LEAVES_PER_FAMILY,
  MAX_EXACT_LEAVES_PER_RESPONSE,
} from "../../../core-shared/geometryBounds.js";
import {
  PERIOD_CHAIN_CONSTRUCTION,
  periodChainConstructionProfile,
  periodChainCoordinate,
  periodChainDerivations,
  periodChainLabelAt,
} from "../core-shared/periodChainConstruction.js";
import { periodChainRequestInput } from "./periodChainRequestInput.js";

const MS_PER_MINUTE = 60_000;
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;
const UNSEAL_FAILED = Object.freeze({
  error: "unseal_failed",
  message: "sealed value could not be opened",
});
const MISS = Object.freeze({ miss: /** @type {true} */ (true) });
const UNAVAILABLE = Object.freeze({ unavailable: /** @type {true} */ (true) });

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
 * Select the source member for each consecutive authorized coordinate. A gap
 * stops the reach: a later supplied window cannot turn an absent current
 * coordinate into a grant beginning in the future.
 *
 * @param {any} family
 * @param {number} nowMinutes
 * @param {number} periodCount
 * @param {number} responseRoom
 */
function selectionsFor(family, nowMinutes, periodCount, responseRoom) {
  const { geometry, members } = family;
  const aligned =
    nowMinutes -
    (((nowMinutes % geometry.periodMinutes) + geometry.periodMinutes) % geometry.periodMinutes);
  const lastSuppliedMinute = Math.max(
    ...members.map(
      (member) =>
        member.coordinate.windowStart + member.coordinate.position * geometry.periodMinutes,
    ),
  );
  const count = Math.min(periodCount, MAX_EXACT_LEAVES_PER_FAMILY, responseRoom);
  /** @type {Map<string, any>} */
  const byMember = new Map();

  for (let index = 0; index < count; index++) {
    const targetMinute = aligned + index * geometry.periodMinutes;
    if (targetMinute > lastSuppliedMinute) break;
    const targetT = periodChainLabelAt(targetMinute);
    const target = periodChainCoordinate(targetT, geometry);
    const member = members.find(
      (candidate) =>
        candidate.coordinate.windowStart === target.windowStart &&
        candidate.coordinate.position >= target.position,
    );
    if (!member) break;
    let selection = byMember.get(member.t);
    if (!selection) {
      selection = {
        t: member.t,
        periodChain: true,
        chainsPerDay: geometry.chainsPerDay,
        periodMinutes: geometry.periodMinutes,
        targetTs: [],
      };
      byMember.set(member.t, selection);
    }
    selection.targetTs.push(targetT);
  }
  return [...byMember.values()].map((selection) =>
    Object.freeze({
      ...selection,
      targetTs: Object.freeze(selection.targetTs),
    }),
  );
}

/**
 * @param {{ representation?: 'exact'|'chain', construction?: string }} [config] -
 *   `construction` names the canonical construction this route is on. Omitting
 *   it selects `dca-period-chain-v1`, whose states are 16 bytes. An
 *   unknown name is refused here, before any request reaches it.
 * @returns {import('../../../core-issuer/IssuerEngine.js').PeriodCapabilitySource}
 */
export function periodChainCapabilitySource({
  representation = "exact",
  construction = PERIOD_CHAIN_CONSTRUCTION,
} = {}) {
  if (representation !== "exact" && representation !== "chain") {
    throw dcaError(
      "bad_config",
      `unknown period-chain response representation ${JSON.stringify(representation)}`,
    );
  }
  const profile = periodChainConstructionProfile(construction);
  const { stateFromState: derivedStateFromState, expansionFromState: derivedExpansionFromState } =
    periodChainDerivations(profile.constructionId);
  // Base asks this source three times for one unlock: what it presents,
  // what it selects, and what it represents. All three read the same
  // untrusted carrier, so this source reads the carrier at the first call
  // and hands the other two the resolved view.
  /** @type {WeakMap<object, any>} */
  const resolved = new WeakMap();
  /** @param {any} request */
  const carrierOf = (request) => {
    if (request === null || typeof request !== "object") return periodChainRequestInput(request);
    const held = resolved.get(request);
    if (held !== undefined) return held;
    const view = periodChainRequestInput(request);
    resolved.set(request, view);
    return view;
  };

  return {
    presented(request) {
      return { accessGroups: carrierOf(request).presented };
    },

    selection(request, invocation) {
      const input = carrierOf(request);
      const nowMinutes = capturedMinutes(invocation?.capturedAtMs);
      let responseLeaves = 0;
      let responseMembers = 0;

      return (accessGroup, periodCount) => {
        const family = input.family(accessGroup);
        if (family.kind === "absent") return MISS;
        if (family.kind === "invalid") return UNAVAILABLE;
        let selected = selectionsFor(
          family,
          nowMinutes,
          periodCount,
          representation === "exact"
            ? MAX_EXACT_LEAVES_PER_RESPONSE - responseLeaves
            : MAX_EXACT_LEAVES_PER_FAMILY,
        );
        if (representation === "chain") {
          selected = selected.slice(0, MAX_CHAIN_MEMBERS_PER_MESSAGE - responseMembers);
        }
        if (selected.length === 0) return UNAVAILABLE;
        if (representation === "exact") {
          responseLeaves += selected.reduce((total, entry) => total + entry.targetTs.length, 0);
        } else {
          responseMembers += selected.length;
        }
        return { selected };
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
        for (const selection of selected) {
          const member = family.members.find((candidate) => candidate.t === selection.t);
          if (!member) {
            throw dcaError(
              "bad_config",
              "selected chain member remains present through capability production",
            );
          }
          // The coordinate is the binding this state was sealed at,
          // and the chain grammar names its position `suppliedT`.
          const opened = await open(member.sealed, {
            accessGroup,
            suppliedT: selection.t,
            periodChain: true,
            chainsPerDay: selection.chainsPerDay,
            periodMinutes: selection.periodMinutes,
          });
          if ("error" in opened) {
            periods.push({ t: selection.t, error: opened.error });
            continue;
          }
          // Material that opens to anything but one chain state is
          // malformed sealed material, like a tag that will not
          // verify, so it reads as the same per-coordinate
          // unseal_failed. A value that is not bytes at all comes
          // from a broken opener, and it falls through to the
          // construction's typed refusal. The source catches nothing
          // below this line: a refusal there is a fault in this
          // issuer, and it propagates with the error code the
          // construction threw.
          if (opened.bytes?.length !== profile.stateBytes) {
            periods.push({ t: selection.t, error: UNSEAL_FAILED });
            continue;
          }
          const cutoffT = selection.targetTs[selection.targetTs.length - 1];
          if (representation === "chain") {
            const state = await derivedStateFromState({
              state: opened.bytes,
              accessGroup,
              suppliedT: selection.t,
              targetT: cutoffT,
              geometry: family.geometry,
            });
            periods.push({ t: cutoffT, bytes: state });
            continue;
          }
          const expansion = await derivedExpansionFromState({
            state: opened.bytes,
            accessGroup,
            suppliedT: selection.t,
            cutoffT,
            geometry: family.geometry,
          });
          const wanted = new Set(selection.targetTs);
          for (const leaf of expansion) {
            if (wanted.has(leaf.t)) periods.push({ t: leaf.t, bytes: leaf.key });
          }
        }
        if (representation === "chain") {
          return {
            kind: "period-chain",
            interpretation: {
              geometry: {
                chainsPerDay: family.geometry.chainsPerDay,
                periodMinutes: family.geometry.periodMinutes,
              },
              selections: selected.map((selection) => ({
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

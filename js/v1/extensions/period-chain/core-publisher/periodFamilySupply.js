// @ts-check
//
// Extension-side publisher supply planning.  Base sees only derive(group, t);
// this module keeps the family generation and its positioned capabilities on
// the selected extension side until the publisher composition asks for a
// family plan.

import { dcaError } from "../../../core-shared/errors.js";
import {
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  PERIOD_GEOMETRY_MINUTES_PER_DAY,
} from "../../../core-shared/geometryBounds.js";
import { validateAccessGroup } from "../../../core-shared/names.js";
import { periodsFor } from "../../../core-shared--publisher-issuer/periodKeys.js";
import { periodChainConstructionProfile } from "../core-shared/periodChainConstruction.js";

const MS_PER_MINUTE = 60_000;

/** @param {unknown} accessGroup */
function checkedGroup(accessGroup) {
  validateAccessGroup(/** @type {any} */ (accessGroup));
  return /** @type {string} */ (accessGroup);
}

/** @param {number} value */
function two(value) {
  return String(value).padStart(2, "0");
}

/** @param {number} minutes */
function fixedT(minutes) {
  const date = new Date(minutes * MS_PER_MINUTE);
  if (date.getUTCFullYear() < 2000 || date.getUTCFullYear() > 2099) {
    throw dcaError(
      "bad_config",
      "a period-family chain plan is inside the profile years 2000 through 2099",
    );
  }
  return (
    `${two(date.getUTCFullYear() % 100)}${two(date.getUTCMonth() + 1)}${two(date.getUTCDate())}` +
    `T${two(date.getUTCHours())}${two(date.getUTCMinutes())}`
  );
}

/**
 * One acquired exact leaf, at the width the family's own profile states. The
 * width comes from the selected profile and never from the value.
 *
 * @param {unknown} value
 * @param {string} where
 * @param {number} width
 */
function keyBytes(value, where, width) {
  if (!(value instanceof Uint8Array) || value.length !== width) {
    throw dcaError("bad_config", `${where} returns ${width} exact-key bytes`);
  }
  return Uint8Array.from(value);
}

/** @param {unknown} value */
function frozenGeneration(value) {
  if (
    !Object.isFrozen(value) ||
    typeof (/** @type {any} */ (value)?.periodKey) !== "function" ||
    typeof (/** @type {any} */ (value)?.chainCapability) !== "function" ||
    typeof (/** @type {any} */ (value)?.coordinateFor) !== "function" ||
    typeof (/** @type {any} */ (value)?.constructionProfile?.constructionId) !== "string" ||
    !Number.isInteger(/** @type {any} */ (value)?.constructionProfile?.stateBytes) ||
    !Object.isFrozen(/** @type {any} */ (value).geometry)
  ) {
    throw dcaError(
      "bad_config",
      "a period-family supply family is a frozen periodFamilyGeneration handle",
    );
  }
  const geometry = /** @type {any} */ (value).geometry;
  if (
    !Number.isInteger(geometry.chainsPerDay) ||
    !Number.isInteger(geometry.periodMinutes) ||
    geometry.chainsPerDay <= 0 ||
    geometry.periodMinutes <= 0
  ) {
    throw dcaError("bad_config", "a period-family generation carries complete positive geometry");
  }
  const generation =
    /** @type {{
     *   geometry: { chainsPerDay: number, periodMinutes: number },
     *   constructionProfile: { constructionId: string, stateBytes: number },
     *   coordinateFor: (t: string) => { t: string, windowStart: number },
     *   periodKey: (accessGroup: string, t: string) => Promise<Uint8Array>,
     *   chainCapability: (accessGroup: string, t: string) => Promise<any>,
     * }} */ (value);
  const constructionProfile = periodChainConstructionProfile(
    generation.constructionProfile.constructionId,
  );
  if (generation.constructionProfile.stateBytes !== constructionProfile.stateBytes) {
    throw dcaError(
      "bad_config",
      `a period-family generation carries the registered paired widths for ` +
        `${JSON.stringify(constructionProfile.constructionId)}`,
    );
  }
  return generation;
}

/** @param {unknown} now */
function minutesAt(now) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw dcaError("bad_config", "a period-family plan needs one finite render Date");
  }
  return Math.floor(now.getTime() / MS_PER_MINUTE);
}

/** @param {unknown} period */
function slotsOf(period) {
  const periodPlan = /** @type {any} */ (period);
  const slots = period === undefined ? 2 : (periodPlan?.slots ?? 2);
  if (!Number.isInteger(slots) || slots <= 0) {
    throw dcaError(
      "bad_config",
      `a period-family plan needs positive defaultPeriod.slots, got ${String(slots)}`,
    );
  }
  return slots;
}

/** @param {{ coordinateFor: (t: string) => any }} generation @param {string} t */
function coordinateAt(generation, t) {
  const at = generation.coordinateFor(t);
  if (at === null || typeof at !== "object" || at.t !== t || !Number.isInteger(at.windowStart)) {
    throw dcaError(
      "bad_config",
      `a period-family generation returned no usable coordinate for period ${t}`,
    );
  }
  return /** @type {{ t: string, windowStart: number }} */ (at);
}

/** @param {string[]} allowed @param {string} t @param {string} operation */
function planned(allowed, t, operation) {
  if (typeof t !== "string" || !allowed.includes(t)) {
    throw dcaError(
      "bad_config",
      `${operation} is called only for this family's planned coordinate`,
    );
  }
}

/**
 * A base-compatible exact supply plus optional extension family generations.
 * Own `families` members select construction; inherited names are not family
 * configuration.  A family handle remains private to this closure, so the
 * base-facing supply cannot discover positioned-chain operations.
 *
 * @param {{ exactSupply?: { derive: (accessGroup: string, t: string) => Promise<Uint8Array> }, families: Record<string, unknown>, chainWindows: number }} config
 */
export function periodFamilySupply(config = /** @type {any} */ ({})) {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw dcaError(
      "bad_config",
      "a period-family supply is { exactSupply?, families, chainWindows }",
    );
  }
  for (const name of Object.keys(config)) {
    if (name !== "exactSupply" && name !== "families" && name !== "chainWindows") {
      throw dcaError(
        "unsupported_option",
        `a period-family supply has no ${name} yet, and will not pretend to`,
      );
    }
  }
  if (!Object.hasOwn(config, "families") || !Object.hasOwn(config, "chainWindows")) {
    throw dcaError("bad_config", "a period-family supply names own families and chainWindows");
  }
  const exactSupply = Object.hasOwn(config, "exactSupply")
    ? /** @type {any} */ (config).exactSupply
    : undefined;
  const families = /** @type {any} */ (config).families;
  const chainWindows = /** @type {any} */ (config).chainWindows;
  if (exactSupply !== undefined && typeof exactSupply?.derive !== "function") {
    throw dcaError("bad_config", "a period-family exactSupply has derive(accessGroup, t)");
  }
  if (exactSupply && Object.hasOwn(exactSupply, "exactProfile")) {
    throw dcaError(
      "unsupported_option",
      "a period-family exactSupply has no width profile selector",
    );
  }
  if (families === null || typeof families !== "object" || Array.isArray(families)) {
    throw dcaError("bad_config", "a period-family supply families is an own-keyed object");
  }
  if (
    !Number.isInteger(chainWindows) ||
    chainWindows <= 0 ||
    chainWindows > MAX_CHAIN_MEMBERS_PER_FAMILY
  ) {
    throw dcaError(
      "bad_config",
      `a period-family supply chainWindows is from 1 through ${MAX_CHAIN_MEMBERS_PER_FAMILY}, got ${String(chainWindows)}`,
    );
  }

  /** @type {Map<string, ReturnType<typeof frozenGeneration>>} */
  const selected = new Map();
  for (const accessGroup of Object.keys(families)) {
    const group = checkedGroup(accessGroup);
    const family = Object.hasOwn(families, group) ? families[group] : undefined;
    selected.set(group, frozenGeneration(family));
  }

  async function exactFor(accessGroup, t) {
    const generation = selected.get(accessGroup);
    if (selected.has(accessGroup)) {
      return keyBytes(await generation.periodKey(accessGroup, t), "a period-family generation", 16);
    }
    if (exactSupply) {
      return keyBytes(await exactSupply.derive(accessGroup, t), "a period-family exactSupply", 16);
    }
    throw dcaError(
      "bad_config",
      `period-family supply has no exact source for ${JSON.stringify(accessGroup)}`,
    );
  }

  return Object.freeze({
    /** Base-compatible opaque exact-key seam. */
    derive(accessGroup, t) {
      return exactFor(checkedGroup(accessGroup), t);
    },

    /**
     * Snapshot one family at the render's already-captured instant.
     * Exact-only families keep the base labels; selected chain families use
     * their explicit geometry and the fixed chain label grammar instead.
     */
    familyPlan(accessGroup, now, defaultPeriod) {
      const group = checkedGroup(accessGroup);
      const at = minutesAt(now);
      const generation = selected.get(group);

      if (!selected.has(group)) {
        if (!exactSupply) {
          throw dcaError(
            "bad_config",
            `period-family supply has no exact source for ${JSON.stringify(group)}`,
          );
        }
        const periods = Object.freeze([...periodsFor(/** @type {Date} */ (now), defaultPeriod)]);
        return Object.freeze({
          periods,
          exactAt: async (t) => {
            planned(periods, t, "exactAt");
            return exactFor(group, t);
          },
        });
      }

      const { chainsPerDay, periodMinutes } = generation.geometry;
      const windowMinutes = PERIOD_GEOMETRY_MINUTES_PER_DAY / chainsPerDay;
      if (!Number.isInteger(windowMinutes) || windowMinutes % periodMinutes !== 0) {
        throw dcaError(
          "bad_config",
          "a period-family generation geometry divides its stationary window",
        );
      }
      const slots = slotsOf(defaultPeriod);
      const current = at - (at % periodMinutes);
      const periods = Object.freeze(
        Array.from({ length: slots }, (_, index) => fixedT(current + index * periodMinutes)),
      );
      // The frozen handle alone decides label range and geometry alignment;
      // this module only plans from its snapshot.
      const plannedAt = periods.map((t) => coordinateAt(generation, t));

      const windowStart = current - (current % windowMinutes);
      const terminal = windowStart + windowMinutes - periodMinutes;
      const suppliedTs = Object.freeze([
        ...new Set(
          Array.from({ length: chainWindows }, (_, index) =>
            fixedT(terminal + index * windowMinutes),
          ),
        ),
      ]);
      const suppliedWindows = new Set(
        suppliedTs.map((t) => coordinateAt(generation, t).windowStart),
      );
      // Every planned exact leaf sits in a stationary window some supplied
      // positioned capability reaches, so an issuer given only this
      // family's chain supply derives every leaf this render wraps under.
      // A positioned capability reaches back to its own window start and
      // never into another window, so equal window starts settle reach and
      // no key is derived to answer it.  `chainWindows` caps the supplied
      // windows: the loop below refuses an under-reaching plan rather than
      // quietly widening it.
      for (const at of plannedAt) {
        if (!suppliedWindows.has(at.windowStart)) {
          throw dcaError(
            "bad_config",
            `a period-family plan wraps period ${at.t} in a stationary window ` +
              `no supplied period-chain capability reaches, with chainWindows ${chainWindows}`,
          );
        }
      }
      const geometry = Object.freeze({ chainsPerDay, periodMinutes });

      return Object.freeze({
        periods,
        exactAt: async (t) => {
          planned(periods, t, "exactAt");
          return exactFor(group, t);
        },
        chain: Object.freeze({
          geometry,
          suppliedTs,
          capabilityAt: async (t) => {
            planned(suppliedTs, t, "capabilityAt");
            const capability = await generation.chainCapability(group, t);
            if (
              capability === null ||
              typeof capability !== "object" ||
              capability.t !== t ||
              !(capability.key instanceof Uint8Array) ||
              capability.key.length !== 16
            ) {
              throw dcaError(
                "bad_config",
                "a period-family generation returns its planned 16-byte capability",
              );
            }
            return Uint8Array.from(capability.key);
          },
        }),
      });
    },
  });
}

// @ts-check
//
// Admission of the `contentGroups` response member against the one captured
// exchange. There is no second pending token: the request comes from the
// resolver's `ResponseAssociation`, read once per captured request with the
// same reader the issuer uses. Admission is atomic for the member. Raw entries
// are counted first; then every member must sit inside the pending content
// names, groups and windows and at or below the requested ceiling. Chain
// positions come from the captured geometry and label; content keys come back only
// for requested items. A `key_retired` error sits under the same rules, at a
// coordinate no key holds, and counts toward the same bounds. Only then does
// any key open, each under the kind its section fixes, and only when every key
// opened does the answer reach `retain`. An error opens and files nothing.

import {
  composedSectionEntries,
  composedSectionErrors,
} from "../../../core-client/responseSectionEntries.js";
import { isRetirementLeaf } from "../../../core-shared--client-issuer/responseKeys.js";
import { DcaError, dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";
import { CONTRACT, checkedGeometry, record, settleLimits } from "../core-shared/construction.js";
import {
  RESPONSE_SECTIONS,
  readContentGroupRequest,
} from "../core-shared--client-issuer/request.js";

const WIRE = CONTRACT.wire;
/** @type {readonly string[]} */
const SECTIONS = Object.freeze([WIRE.chainKeys, WIRE.periodKeys, WIRE.contentKeys]);
/** @type {readonly string[]} */
const MEMBERS = Object.freeze([...SECTIONS, WIRE.errors]);
/** Codes a refusal of this member carries; any other throw is a fault. */
const REFUSALS = Object.freeze(["bad_response", "binding_failed", "too_many_entries"]);

/** @param {string} why @returns {never} */
function refuse(why) {
  throw dcaError("bad_response", `content-group response: ${why}`);
}

/**
 * @typedef {object} StagedChain
 * @property {string} contentName
 * @property {string} group
 * @property {string} windowStart
 * @property {string} cutoffT
 * @property {number} position
 * @property {string} keyKind
 * @property {unknown} value - the key entry as the response carried it
 */
/**
 * @typedef {object} StagedPeriod
 * @property {string} contentName
 * @property {string} group
 * @property {string} windowStart
 * @property {string} t
 * @property {number} position
 * @property {string} keyKind
 * @property {unknown} value
 */
/**
 * @typedef {object} StagedContentKey
 * @property {string} contentName
 * @property {string} group - the route the request named for it
 * @property {string} keyKind
 * @property {unknown} value
 */
/**
 * A coordinate the issuer authorized and found its opening key retired at.
 * A chain or period error carries its window and label; an item error the
 * route group the request named.
 *
 * @typedef {{ section: 'chainKeys'|'periodKeys', contentName: string, group: string, windowStart: string,
 *   t: string, error: 'key_retired' }
 *   | { section: 'contentKeys', contentName: string, group: string, error: 'key_retired' }} StagedError
 */
/**
 * @typedef {{ chains: StagedChain[], periods: StagedPeriod[], contentKeys: StagedContentKey[],
 *   errors: StagedError[], periodGeometry: Readonly<{ chainsPerDay: number, periodMinutes: number }> }} StagedResponse
 */

/**
 * Raw own entries of the member, counted before anything is admitted.
 * @param {Record<string, unknown>} section
 */
function rawEntries(section) {
  let count = 0;
  for (const name of [WIRE.chainKeys, WIRE.periodKeys]) {
    const names = own(section, name);
    if (!record(names)) continue;
    for (const groups of Object.values(names)) {
      if (!record(groups)) continue;
      for (const entries of Object.values(groups))
        if (record(entries)) count += Object.keys(entries).length;
    }
  }
  const items = own(section, WIRE.contentKeys);
  if (record(items)) count += Object.keys(items).length;
  const response = { [WIRE.response]: section };
  for (const descriptor of RESPONSE_SECTIONS)
    count += composedSectionErrors(response, descriptor).entries.length;
  return count;
}

/**
 * Admit one `contentGroups` member against its exchange's request, without
 * opening anything. Throws a `bad_response` DcaError naming the first fault;
 * the caller refuses the whole member on it.
 * @param {unknown} section - the response's `contentGroups` member
 * @param {unknown} request - the request the association captured
 * @param {{ chain: any, limits?: Record<string, number>,
 *   read?: (request: unknown) => ReturnType<typeof readContentGroupRequest> }} options
 * @returns {StagedResponse}
 */
export function admitContentGroupResponse(section, request, options) {
  const { chain } = options;
  const limits = settleLimits(options.limits);
  const view = (options.read ?? ((r) => readContentGroupRequest(r, limits)))(request);
  if (view === null) refuse("no pending content-group exchange asked for this member");
  if (!record(section)) refuse("the member is a map");
  if (rawEntries(section) > limits.maxResponseMembers)
    refuse("raw response bound exceeded before admission");
  for (const name of Object.keys(section))
    if (!MEMBERS.includes(name)) refuse(`unknown content-group response member ${name}`);

  let geometry;
  try {
    geometry = checkedGeometry(view.periodGeometry, chain);
  } catch {
    refuse("the captured request has no complete valid periodGeometry");
  }
  /** @param {string} t */
  const coordinate = (t) => {
    let at;
    try {
      at = chain.coordinate(t, geometry);
    } catch {
      refuse(`${JSON.stringify(t)} is no canonical period label`);
    }
    if (at.t !== t) refuse(`${JSON.stringify(t)} is no canonical period label`);
    return at;
  };
  /** @param {string} contentName @param {string} group */
  const pending = (contentName, group) => {
    const held = own(view.contentGroups, contentName);
    if (held === undefined || !held.groups.includes(group))
      refuse(`${contentName}/${group} is outside the pending content names and groups`);
    return held;
  };
  /** @param {{ windows: readonly string[] }} held @param {string} t */
  const reach = (held, t) => {
    const at = coordinate(t);
    const cutoff = view.cutoffs === undefined ? undefined : own(view.cutoffs, at.startT);
    if (!held.windows.includes(at.startT) || (view.cutoffs !== undefined && cutoff === undefined))
      refuse(`${t} is outside the pending windows`);
    if (cutoff !== undefined && at.position > coordinate(cutoff).position)
      refuse(`${t} exceeds the requested cutoff ${cutoff}`);
    return at;
  };
  /**
   * @param {string} member
   * @param {(contentName: string, group: string, t: string, value: unknown) => void} visit
   * @param {unknown} [from] - the map holding `member`: the section, or its error map
   */
  const eachFamilyEntry = (member, visit, from = section) => {
    const names = own(from, member) ?? {};
    if (!record(names)) refuse(`${member} is a map`);
    for (const [contentName, groups] of Object.entries(names)) {
      if (!record(groups)) refuse(`${member}.${contentName} is a map`);
      for (const [group, entries] of Object.entries(groups)) {
        if (!record(entries)) refuse(`${member}.${contentName}.${group} is a map`);
        pending(contentName, group);
        for (const [t, value] of Object.entries(entries)) visit(contentName, group, t, value);
      }
    }
  };

  /** @type {StagedChain[]} */
  const chains = [];
  /** @type {Map<string, Set<string>>} */
  const chainWindows = new Map();
  eachFamilyEntry(WIRE.chainKeys, (contentName, group, t, leaf) => {
    const at = reach(pending(contentName, group), t);
    const family = JSON.stringify([contentName, group]);
    const windows = chainWindows.get(family) ?? new Set();
    chainWindows.set(family, windows);
    if (windows.has(at.startT)) refuse("a response carries one chain key per window");
    windows.add(at.startT);
    if (windows.size > limits.maxWindowsPerGroup) refuse("chain windows over maxWindowsPerGroup");
    chains.push({
      contentName,
      group,
      windowStart: at.startT,
      cutoffT: t,
      position: at.position,
      keyKind: CONTRACT.keyKinds.chainKey,
      value: leaf,
    });
  });

  /** @type {StagedPeriod[]} */
  const periods = [];
  /** @type {Map<string, number>} */
  const periodCounts = new Map();
  eachFamilyEntry(WIRE.periodKeys, (contentName, group, t, value) => {
    const at = reach(pending(contentName, group), t);
    const family = JSON.stringify([contentName, group]);
    const count = (periodCounts.get(family) ?? 0) + 1;
    periodCounts.set(family, count);
    if (count > limits.maxPeriodKeysPerContentGroup)
      refuse("period keys over maxPeriodKeysPerContentGroup");
    periods.push({
      contentName,
      group,
      windowStart: at.startT,
      t,
      position: at.position,
      keyKind: CONTRACT.keyKinds.periodKey,
      value,
    });
  });

  /** @type {StagedContentKey[]} */
  const contentKeys = [];
  const items = own(section, WIRE.contentKeys) ?? {};
  if (!record(items)) refuse(`${WIRE.contentKeys} is a map`);
  for (const [contentName, value] of Object.entries(items)) {
    const asked = own(view.contentKeys, contentName);
    if (asked === undefined) refuse(`content key ${contentName} is outside the requested items`);
    contentKeys.push({ contentName, group: asked.group, keyKind: "contentKey", value });
  }

  /** @type {StagedError[]} */
  const errors = [];
  const reported = own(section, WIRE.errors) ?? {};
  if (!record(reported)) refuse(`${WIRE.errors} is a map`);
  for (const name of Object.keys(reported))
    if (!SECTIONS.includes(name)) refuse(`unknown content-group error map ${name}`);
  /** @param {unknown} leaf */
  const retirement = (leaf) => {
    if (!isRetirementLeaf(leaf)) refuse('an error is exactly {error: "key_retired"}');
  };
  // A chain error takes its window's one place, as a chain key does.
  eachFamilyEntry(
    WIRE.chainKeys,
    (contentName, group, t, leaf) => {
      const at = reach(pending(contentName, group), t);
      retirement(leaf);
      const family = JSON.stringify([contentName, group]);
      const windows = chainWindows.get(family) ?? new Set();
      chainWindows.set(family, windows);
      if (windows.has(at.startT)) refuse("a window carries one chain key or chain error");
      windows.add(at.startT);
      if (windows.size > limits.maxWindowsPerGroup) refuse("chain windows over maxWindowsPerGroup");
      errors.push({
        section: "chainKeys",
        contentName,
        group,
        windowStart: at.startT,
        t,
        error: "key_retired",
      });
    },
    reported,
  );
  eachFamilyEntry(
    WIRE.periodKeys,
    (contentName, group, t, leaf) => {
      const at = reach(pending(contentName, group), t);
      retirement(leaf);
      if (periods.some((p) => p.contentName === contentName && p.group === group && p.t === t))
        refuse(`period ${t} carries both a key and an error`);
      const family = JSON.stringify([contentName, group]);
      const count = (periodCounts.get(family) ?? 0) + 1;
      periodCounts.set(family, count);
      if (count > limits.maxPeriodKeysPerContentGroup)
        refuse("period keys over maxPeriodKeysPerContentGroup");
      errors.push({
        section: "periodKeys",
        contentName,
        group,
        windowStart: at.startT,
        t,
        error: "key_retired",
      });
    },
    reported,
  );
  const itemErrors = own(reported, WIRE.contentKeys) ?? {};
  if (!record(itemErrors)) refuse(`${WIRE.errors}.${WIRE.contentKeys} is a map`);
  for (const [contentName, leaf] of Object.entries(itemErrors)) {
    const asked = own(view.contentKeys, contentName);
    if (asked === undefined) refuse(`item error ${contentName} is outside the requested items`);
    retirement(leaf);
    if (Object.hasOwn(items, contentName))
      refuse(`item ${contentName} carries both a key and an error`);
    errors.push({ section: "contentKeys", contentName, group: asked.group, error: "key_retired" });
  }
  return { chains, periods, contentKeys, errors, periodGeometry: geometry };
}

/**
 * @typedef {object} AdmittedContentGroupResponse
 * @property {string|undefined} publisher - the trusted page origin
 * @property {string} issuerName
 * @property {Readonly<{ chainsPerDay: number, periodMinutes: number }>} periodGeometry
 * @property {(StagedChain & { key: Uint8Array })[]} chains
 * @property {(StagedPeriod & { key: Uint8Array })[]} periods
 * @property {(StagedContentKey & { key: Uint8Array|CryptoKey })[]} contentKeys
 * @property {object} lease - the response's private lease
 * @property {any} dcaData
 */

/**
 * The resolver's response-section consumer for `contentGroups`. `retain`
 * files one wholly admitted and opened answer; it runs only after every key
 * opened, and never under a retired reader. Recovered item keys are then held
 * through the resolver's `holdContentKey`. `promote`, `attempted` and
 * `clearReaderContext` join the resolver's completion and reset when given.
 *
 * @param {{ chain: any, limits?: Record<string, number>,
 *   retain: (admitted: AdmittedContentGroupResponse) => Promise<void>,
 *   promote?: (context: { lease: object }) => Promise<void>,
 *   attempted?: (context: { lease: object }) => Promise<void>,
 *   clearReaderContext?: () => Promise<void> }} config
 * @returns {import("../../../core-client/ContentKeyResolver.js").ResponseSectionConsumer}
 */
export function contentGroupResponseInput(config) {
  const { chain, retain, promote, attempted, clearReaderContext } = config ?? {};
  if (
    typeof chain?.coordinate !== "function" ||
    typeof chain?.settleGeometry !== "function" ||
    typeof retain !== "function"
  )
    throw dcaError("bad_config", "a content-group response input needs a chain port and retain");
  let limits;
  try {
    limits = settleLimits(config.limits);
  } catch (cause) {
    throw Object.assign(dcaError("bad_config", /** @type {Error} */ (cause).message), { cause });
  }
  const settled = limits;
  /** @type {WeakMap<object, ReturnType<typeof readContentGroupRequest>>} */
  const views = new WeakMap();
  /** @param {unknown} request */
  const read = (request) => {
    if (request === null || typeof request !== "object")
      return readContentGroupRequest(request, settled);
    if (views.has(request)) return views.get(request) ?? null;
    const view = readContentGroupRequest(request, settled);
    views.set(request, view);
    return view;
  };

  return {
    name: WIRE.response,
    keyValues(section) {
      const response = { [WIRE.response]: section };
      return RESPONSE_SECTIONS.flatMap((descriptor) =>
        composedSectionEntries(response, descriptor).entries.map(({ value }) => value),
      );
    },
    async admit(section, context) {
      let staged;
      try {
        staged = admitContentGroupResponse(section, context.association.request, {
          chain,
          limits: settled,
          read,
        });
      } catch (cause) {
        if (cause instanceof DcaError && REFUSALS.includes(cause.code))
          return { accepted: 0, issues: [{ code: "malformed_response" }] };
        throw cause;
      }
      /** @param {StagedChain|StagedPeriod|StagedContentKey} entry */
      const open = async (entry) => {
        const use =
          entry.keyKind === "contentKey"
            ? {
                keyKind: entry.keyKind,
                usages: /** @type {KeyUsage[]} */ (["decrypt"]),
                raw: false,
              }
            : { keyKind: entry.keyKind, raw: true };
        const opened = await context.openKey(entry.value, use);
        context.check();
        return opened;
      };
      /** @type {any[]} */
      const chains = [];
      /** @type {any[]} */
      const periods = [];
      /** @type {any[]} */
      const contentKeys = [];
      for (const [list, out] of /** @type {const} */ ([
        [staged.chains, chains],
        [staged.periods, periods],
        [staged.contentKeys, contentKeys],
      ]))
        for (const entry of list) {
          const { key, issue } = await open(entry);
          if (key === null) return { accepted: 0, issues: [{ code: issue }] };
          /** @type {any[]} */ (out).push({ ...entry, key });
        }
      context.check();
      // Retirements reach the application through the resolver; they file nothing.
      const reported = staged.errors.length > 0 ? { errors: staged.errors } : {};
      const accepted = chains.length + periods.length + contentKeys.length;
      if (accepted === 0) return { accepted: 0, issues: [], ...reported };
      await retain({
        publisher: context.publisher,
        issuerName: context.issuerName,
        periodGeometry: staged.periodGeometry,
        chains: /** @type {any} */ (chains),
        periods: /** @type {any} */ (periods),
        contentKeys: /** @type {any} */ (contentKeys),
        lease: context.lease,
        dcaData: context.dcaData,
      });
      context.check();
      // A recovered item key needs no cache: it is held like a base content
      // key, so the plain key path opens the item without another exchange.
      for (const { contentName, key } of contentKeys) context.holdContentKey(contentName, key);
      return { accepted, issues: [], ...reported };
    },
    ...(promote === undefined ? {} : { promote }),
    ...(attempted === undefined ? {} : { attempted }),
    ...(clearReaderContext === undefined ? {} : { clearReaderContext }),
  };
}

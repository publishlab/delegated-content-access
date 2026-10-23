// @ts-check
//
// Admission of the `contentGroupKeys` response member against the one captured
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

import { composedSectionEntries } from "../../../core-client/responseSectionEntries.js";
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
 * Raw records of the member, key and error records alike, counted before
 * anything is admitted. A section that is not an array counts nothing here and
 * refuses the member when it is read.
 * @param {Record<string, unknown>} section
 */
function rawEntries(section) {
  let count = 0;
  const reported = own(section, WIRE.errors);
  for (const name of SECTIONS) {
    for (const list of [own(section, name), own(reported, name)])
      if (Array.isArray(list)) count += list.length;
  }
  return count;
}

/**
 * The records of one section, each exactly its coordinate fields, every one a
 * string, and `last`: `key` for a key record, `error` for an error record.
 * Any other shape refuses the member.
 * @param {unknown} list @param {readonly string[]} fields @param {string} last @param {string} label
 * @returns {Record<string, any>[]}
 */
function records(list, fields, last, label) {
  if (list === undefined) return [];
  if (!Array.isArray(list)) refuse(`${label} is an array of records`);
  for (const entry of list)
    if (
      !record(entry) ||
      Object.keys(entry).length !== fields.length + 1 ||
      !Object.hasOwn(entry, last) ||
      !fields.every((field) => typeof own(entry, field) === "string")
    )
      refuse(`${label} holds records of ${[...fields, last].join(", ")}`);
  return /** @type {Record<string, any>[]} */ (list);
}

/** @type {Readonly<Record<string, readonly string[]>>} */
const FIELDS = Object.freeze(
  Object.fromEntries(
    RESPONSE_SECTIONS.map((descriptor) => [descriptor.path.at(-1), descriptor.fields]),
  ),
);

/**
 * Admit one `contentGroupKeys` member against its exchange's request, without
 * opening anything. Throws a `bad_response` DcaError naming the first fault;
 * the caller refuses the whole member on it.
 *
 * Several key records at one coordinate are candidates, and every one is
 * staged. A chain window has one selected cutoff: chain keys at another
 * cutoff of that window, or a chain error beside its keys, refuse the member.
 * An error record repeated at one coordinate is the same report, so the last
 * whole record stands. Raw records count toward every bound.
 * @param {unknown} section - the response's `contentGroupKeys` member
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
  if (!record(section)) refuse("the member is an object of record sections");
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
  // Each window's ceiling is the lowest requested cutoff label of it; the
  // labels were admitted when the request was built and the issuer admits
  // them again, so an unreadable one here refuses the member.
  /** @type {Map<string, number>} */
  const ceilings = new Map();
  for (const [window, labels] of Object.entries(view.cutoffs ?? {}))
    ceilings.set(window, Math.min(...labels.map((label) => coordinate(label).position)));
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
    const ceiling = ceilings.get(at.startT);
    if (!held.windows.includes(at.startT) || (view.cutoffs !== undefined && ceiling === undefined))
      refuse(`${t} is outside the pending windows`);
    if (ceiling !== undefined && at.position > ceiling)
      refuse(`${t} exceeds the requested cutoff of its window`);
    return at;
  };
  /** @param {string} contentName */
  const askedItem = (contentName) => {
    const routes = own(view.contentKeys, contentName);
    if (routes === undefined) return undefined;
    // An item's alternatives may name several groups; report the lowest.
    return [.../** @type {readonly { group: string }[]} */ (routes)].map((r) => r.group).sort()[0];
  };

  const errorsIn = own(section, WIRE.errors);
  const reported = errorsIn === undefined ? {} : errorsIn;
  if (!record(reported)) refuse(`${WIRE.errors} is an object of record sections`);
  for (const name of Object.keys(reported))
    if (!SECTIONS.includes(name)) refuse(`unknown content-group error section ${name}`);
  const keyed = (/** @type {string} */ name) =>
    records(own(section, name), FIELDS[name], "key", name);
  const failed = (/** @type {string} */ name) => {
    const list = own(reported, name);
    const label = `${WIRE.errors}.${name}`;
    if (list === undefined) return [];
    if (!Array.isArray(list)) refuse(`${label} is an array of records`);
    const fields = FIELDS[name];
    /** @type {Map<string, Record<string, any>>} */
    const last = new Map();
    for (const entry of list) {
      // Admit every raw identity and count it before replacement. Only the
      // last whole record at that identity supplies the error payload.
      if (!record(entry) || !fields.every((field) => typeof own(entry, field) === "string"))
        refuse(`${label} holds records with its coordinate fields`);
      if (name === WIRE.periodKeys)
        countPeriod(/** @type {string} */ (entry.contentName), /** @type {string} */ (entry.group));
      last.set(JSON.stringify(fields.map((field) => own(entry, field))), entry);
    }
    return records([...last.values()], fields, "error", label);
  };
  /** @param {unknown} leaf */
  const retirement = (leaf) => {
    if (leaf !== "key_retired") refuse('an error record carries error "key_retired"');
  };

  // One selected cutoff per content name, group and window, whether it
  // carries chain keys or a chain error; distinct windows count toward
  // maxWindowsPerGroup.
  /** @type {Map<string, { cutoff: string, error: boolean }>} */
  const selected = new Map();
  /** @type {Map<string, Set<string>>} */
  const chainWindows = new Map();
  /** @param {string} contentName @param {string} group @param {string} cutoff @param {boolean} error */
  const selectCutoff = (contentName, group, cutoff, error) => {
    const at = reach(pending(contentName, group), cutoff);
    const window = JSON.stringify([contentName, group, at.startT]);
    const held = selected.get(window);
    if (held !== undefined && held.cutoff !== cutoff)
      refuse("records at different cutoffs of one window conflict");
    if (held !== undefined && held.error !== error)
      refuse("a window carries chain keys or a chain error, never both");
    selected.set(window, { cutoff, error });
    const family = JSON.stringify([contentName, group]);
    const windows = chainWindows.get(family) ?? new Set();
    chainWindows.set(family, windows);
    windows.add(at.startT);
    if (windows.size > limits.maxWindowsPerGroup) refuse("chain windows over maxWindowsPerGroup");
    return at;
  };

  /** @type {StagedChain[]} */
  const chains = [];
  for (const { contentName, group, cutoff, key } of keyed(WIRE.chainKeys)) {
    const at = selectCutoff(contentName, group, cutoff, false);
    chains.push({
      contentName,
      group,
      windowStart: at.startT,
      cutoffT: cutoff,
      position: at.position,
      keyKind: CONTRACT.keyKinds.chainKey,
      value: key,
    });
  }

  // Raw period records, key and error, count toward
  // maxPeriodKeysPerContentGroup with the others of their content name and group.
  /** @type {Map<string, number>} */
  const periodCounts = new Map();
  /** @param {string} contentName @param {string} group */
  const countPeriod = (contentName, group) => {
    const family = JSON.stringify([contentName, group]);
    const count = (periodCounts.get(family) ?? 0) + 1;
    periodCounts.set(family, count);
    if (count > limits.maxPeriodKeysPerContentGroup)
      refuse("period keys over maxPeriodKeysPerContentGroup");
  };
  /** @type {StagedPeriod[]} */
  const periods = [];
  for (const { contentName, group, period, key } of keyed(WIRE.periodKeys)) {
    const at = reach(pending(contentName, group), period);
    countPeriod(contentName, group);
    periods.push({
      contentName,
      group,
      windowStart: at.startT,
      t: period,
      position: at.position,
      keyKind: CONTRACT.keyKinds.periodKey,
      value: key,
    });
  }

  /** @type {StagedContentKey[]} */
  const contentKeys = [];
  for (const { contentName, key } of keyed(WIRE.contentKeys)) {
    const group = askedItem(contentName);
    if (group === undefined) refuse(`content key ${contentName} is outside the requested items`);
    contentKeys.push({ contentName, group, keyKind: "contentKey", value: key });
  }

  // Errors: the last whole record per full coordinate stands.
  /** @type {Map<string, StagedError>} */
  const errors = new Map();
  for (const { contentName, group, cutoff, error } of failed(WIRE.chainKeys)) {
    const at = selectCutoff(contentName, group, cutoff, true);
    retirement(error);
    errors.set(JSON.stringify(["chainKeys", contentName, group, cutoff]), {
      section: "chainKeys",
      contentName,
      group,
      windowStart: at.startT,
      t: cutoff,
      error: "key_retired",
    });
  }
  for (const { contentName, group, period, error } of failed(WIRE.periodKeys)) {
    const at = reach(pending(contentName, group), period);
    retirement(error);
    if (periods.some((p) => p.contentName === contentName && p.group === group && p.t === period))
      refuse(`period ${period} carries both a key and an error`);
    errors.set(JSON.stringify(["periodKeys", contentName, group, period]), {
      section: "periodKeys",
      contentName,
      group,
      windowStart: at.startT,
      t: period,
      error: "key_retired",
    });
  }
  for (const { contentName, error } of failed(WIRE.contentKeys)) {
    const group = askedItem(contentName);
    if (group === undefined) refuse(`item error ${contentName} is outside the requested items`);
    retirement(error);
    if (contentKeys.some((entry) => entry.contentName === contentName))
      refuse(`item ${contentName} carries both a key and an error`);
    errors.set(JSON.stringify(["contentKeys", contentName]), {
      section: "contentKeys",
      contentName,
      group,
      error: "key_retired",
    });
  }
  return { chains, periods, contentKeys, errors: [...errors.values()], periodGeometry: geometry };
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
 * The resolver's response-section consumer for `contentGroupKeys`. `retain`
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

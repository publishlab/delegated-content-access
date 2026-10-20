// @ts-check
//
// This run measures what chain-key supply costs on the wire, on deliveries
// and unlock exchanges the reference produces. It compares three
// publisher-to-issuer supply forms at two crossings that different parties pay
// for:
//
//   period-key-only        sealed period keys only
//   period-key-plus-chain  sealed period keys and sealed chain keys
//   chain-only             sealed chain keys only
//
//   delivery   the publisher's markup delivery, which a CDN serves with every
//              article response
//   exchange   one client request to one issuer and that issuer's response
//
// Run it from the repository root, with no network:
//
//     node js/evidence-benchmarks/chain-keys-wire-cost/run.js
//     node js/evidence-benchmarks/chain-keys-wire-cost/run.js --bytes
//
// The first prints every section. `--bytes` prints the deterministic byte and
// operation-count sections alone, so two runs on an unchanged tree can be
// compared with `diff`. `./README.md` states the method and reads the result.
//
// Every render and exchange goes through `./world.js`, which composes the
// reference publisher, markup adapter, client and issuer. Nothing here builds
// dca-data, a request or a response by hand.
//
// The run checks its own measurements. Each render must carry exactly the
// supply form its row names, each request the members its client selects, and
// each 200 response the representation its issuer is configured for, with the
// client admitting it and opening the article through it. A route the
// reference refuses is printed as refused with its code, and only where the
// row expects that refusal; any other outcome stops the run with exit status 1.

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { counted, grouped, normalizer, sizes } from "./measure.js";
import { ARTICLE, GEOMETRY, NAME, exchange, render } from "./world.js";

const BYTES_ONLY = process.argv.includes("--bytes");

/** Genuine renders per case in the compression-spread section. */
const SPREAD_RENDERS = 7;

const MS_PER_MINUTE = 60_000;
const WINDOW_MINUTES = 1440 / GEOMETRY.chainsPerDay;

/** Render instants: inside a window, in a window's last period, at a window's start. */
const MID = "2025-10-23T05:05:00Z";
const EDGE = "2025-10-23T11:50:00Z";
const START = "2025-10-23T00:00:00Z";

/** The three supply forms under comparison, in print order. */
const SUPPLY = /** @type {const} */ (["period-key-only", "period-key-plus-chain", "chain-only"]);

const ENVELOPES = /** @type {const} */ (["ecdh-p256", "rsa-oaep"]);

/** @type {string[]} */
const out = [];
/** @param {string} line */
const say = (line) => out.push(line);

/** @param {boolean} condition @param {string} message */
function check(condition, message) {
  if (!condition) throw new Error(`self-check failed: ${message}`);
}

/** @typedef {{ raw: number, gzip: number, br: number }} Size */

/** @param {Size} size */
const triple = (size) => `${grouped(size.raw)} / ${grouped(size.gzip)} / ${grouped(size.br)}`;

/** @param {Size} a @param {Size} b @returns {Size} */
const minus = (a, b) => ({ raw: a.raw - b.raw, gzip: a.gzip - b.gzip, br: a.br - b.br });

/** @param {number} value */
const signed = (value) =>
  value > 0 ? `+${grouped(value)}` : value < 0 ? `-${grouped(-value)}` : "0";

/** @param {Size} size */
const signedTriple = (size) => `${signed(size.raw)} / ${signed(size.gzip)} / ${signed(size.br)}`;

/** Plural spellings of the nouns a line counts. */
const PLURAL = {
  "period key": "period keys",
  "chain key": "chain keys",
  carrier: "carriers",
  window: "windows",
  issuer: "issuers",
  "access group": "access groups",
};

/** @param {number} count @param {keyof typeof PLURAL} noun */
const many = (count, noun) => `${count} ${count === 1 ? noun : PLURAL[noun]}`;

/** @param {string} form */
const hasPeriodKeys = (form) => form === "period-key-only" || form === "period-key-plus-chain";
/** @param {string} form */
const hasChain = (form) => form === "chain-only" || form === "period-key-plus-chain";

// ---------------------------------------------------------------------------
// Supply and response geometry the checks compare against

/** @param {string} at */
const minutesOf = (at) => Math.floor(Date.parse(at) / MS_PER_MINUTE);

/**
 * The coordinates a chain-input issuer selects for `horizon`, from its current
 * coordinate to the end of the last supplied window, together with the
 * explicitly requested item-wrap coordinates, as the minute each starts.
 *
 * @param {{ at: string, chainWindows: number, slots: number }} spec
 * @param {number} horizon
 */
function chainSelection(spec, horizon) {
  const now = minutesOf(spec.at);
  const current = now - (now % GEOMETRY.periodMinutes);
  const windowStart = current - (current % WINDOW_MINUTES);
  const lastSupplied = windowStart + spec.chainWindows * WINDOW_MINUTES - GEOMETRY.periodMinutes;
  const reach = (lastSupplied - current) / GEOMETRY.periodMinutes + 1;
  return Array.from(
    { length: Math.min(Math.max(horizon, spec.slots), reach) },
    (unused, index) => current + index * GEOMETRY.periodMinutes,
  );
}

/**
 * How many values each returned family carries: period keys for a period-key
 * response, one chain key per window the selection touches for a chain
 * response.
 *
 * @param {any} spec
 * @param {{ issuer: string, horizon: number }} route
 */
function expectedPerFamily(spec, route) {
  if (route.issuer === "period-key") return Math.min(route.horizon, spec.slots);
  const selected = chainSelection(spec, route.horizon);
  if (route.issuer === "chain>period-key") return selected.length;
  return new Set(selected.map((minute) => minute - (minute % WINDOW_MINUTES))).size;
}

// ---------------------------------------------------------------------------
// Form checks

/**
 * The render carries exactly the supply form its spec names, for every issuer
 * and access group, and wraps the item under every planned period.
 *
 * @param {any} rendered
 */
function checkDeliveryForm(rendered) {
  const { spec, dcaData } = rendered;
  const groups = Object.keys(dcaData.contentData[NAME].keys ?? {});
  const floor = spec.form === "content-key-only";
  check(groups.length === (floor ? 0 : spec.groups), `${spec.form}: wrapped groups`);
  for (const group of groups) {
    check(dcaData.contentData[NAME].keys[group].length === spec.slots, `${spec.form}: wraps`);
  }
  check(Object.keys(dcaData.issuerData).length === spec.issuers, `${spec.form}: issuer blocks`);
  for (const [issuerName, block] of Object.entries(dcaData.issuerData)) {
    const sealed = /** @type {any} */ (block).sealed;
    const where = `${spec.form} ${issuerName}`;
    check(Object.keys(sealed.contentKeys).length === 1, `${where}: content-key route`);
    if (hasPeriodKeys(spec.form)) {
      check(Object.keys(sealed.periodKeys).length === spec.groups, `${where}: period-key families`);
      for (const members of Object.values(sealed.periodKeys)) {
        check(Object.keys(members).length === spec.slots, `${where}: period-key members`);
      }
    } else {
      check(sealed.periodKeys === undefined, `${where}: carries no period-key members`);
    }
    if (hasChain(spec.form)) {
      check(Object.keys(sealed.chainKeys).length === spec.groups, `${where}: chain families`);
      for (const members of Object.values(sealed.chainKeys)) {
        check(Object.keys(members).length === spec.chainWindows, `${where}: chain members`);
      }
    } else {
      check(sealed.chainKeys === undefined, `${where}: carries no chain members`);
    }
  }
  const geometry = dcaData.periodGeometry;
  if (!hasChain(spec.form)) {
    check(geometry === undefined, `${spec.form}: no period geometry`);
  } else {
    check(
      geometry !== null && typeof geometry === "object" && !Array.isArray(geometry),
      `${spec.form}: period geometry object`,
    );
    check(geometry.periodMinutes === GEOMETRY.periodMinutes, `${spec.form}: shared period length`);
    check(
      Object.keys(geometry).sort().join(",") === "chainsPerDay,periodMinutes",
      `${spec.form}: exact geometry members`,
    );
    if (hasChain(spec.form)) {
      check(geometry.chainsPerDay === GEOMETRY.chainsPerDay, `${spec.form}: shared chain windows`);
    }
  }
}

/**
 * The request carries what its client selects from this delivery: period-key
 * members whenever the delivery has them, since both clients select
 * `relayPeriodKeys`, and chain members and geometry only on the relay client.
 *
 * @param {any} spec
 * @param {{ client: string }} route
 * @param {string} requestDocument
 */
function checkRequestForm(spec, route, requestDocument) {
  const request = JSON.parse(requestDocument);
  const where = `${spec.form} ${route.client} request`;
  const chain = route.client === "relay" && hasChain(spec.form);
  check(
    (request.sealed.periodKeys !== undefined) === hasPeriodKeys(spec.form),
    `${where}: period-key members`,
  );
  check((request.sealed.chainKeys !== undefined) === chain, `${where}: chain members`);
  check((request.periodGeometry !== undefined) === chain, `${where}: chain geometry`);
  if (chain) {
    check(
      request.periodGeometry.chainsPerDay === GEOMETRY.chainsPerDay &&
        request.periodGeometry.periodMinutes === GEOMETRY.periodMinutes,
      `${where}: relayed shared pair`,
    );
  }
}

/**
 * A 200 response carries the representation its issuer is configured for, in
 * the expected count per family, and the client admitted it and opened the
 * article through it.
 *
 * @param {any} spec
 * @param {{ client: string, issuer: string, horizon: number }} route
 * @param {import('./world.js').Exchange} result
 */
function checkResponseForm(spec, route, result) {
  const where = `${spec.form} ${route.client}>${route.issuer} response`;
  const keys = result.body.keys;
  const want = expectedPerFamily(spec, route);
  const chainOutput = route.issuer === "chain>chain";
  const section = chainOutput ? keys.chainKeys : keys.periodKeys;
  const other = chainOutput ? keys.periodKeys : keys.chainKeys;
  check(section !== undefined && Object.keys(section).length === spec.groups, `${where}: families`);
  for (const members of Object.values(section)) {
    check(Object.keys(members).length === want, `${where}: ${want} per family`);
  }
  check(other === undefined, `${where}: carries no other period representation`);
  check(result.body.periodGeometry === undefined, `${where}: response omits geometry echo`);
  check(result.application.issues.length === 0, `${where}: client admitted it without issues`);
  check(
    result.origin?.kind === (chainOutput ? "cached-chain-key" : "cached-period-key"),
    `${where}: the item opened through the returned representation`,
  );
  check(result.opened === ARTICLE, `${where}: the article decrypted`);
}

// ---------------------------------------------------------------------------
// Measurement

/**
 * One render and its delivery sizes. The raw size is measured on the markup
 * as written; compressed sizes on its normalized twin, whose raw size must be
 * the same.
 *
 * @param {import('./world.js').CaseSpec} spec
 */
async function delivery(spec) {
  const { value: rendered, work } = await counted(async (phase) => {
    phase("publisher");
    return render(spec);
  });
  checkDeliveryForm(rendered);
  const normalize = normalizer(rendered.dcaData);
  const size = sizes(normalize(rendered.markup));
  check(size.raw === sizes(rendered.markup).raw, "normalization kept the markup length");
  return {
    rendered,
    normalize,
    size,
    work: work.publisher ?? { hkdf: 0, ecdh: 0, rsa: 0 },
    parts: parts(rendered.dcaData),
  };
}

/**
 * The raw bytes three members of the dca-data take: the item's wraps, the
 * period-key supply members, and the chain supply members with the
 * root `periodGeometry` increment. Each is what removing it takes off the serialized
 * dca-data.
 *
 * @param {any} dcaData
 */
function parts(dcaData) {
  const whole = JSON.stringify(dcaData).length;
  /** @param {(copy: any) => void} edit */
  const without = (edit) => {
    const copy = structuredClone(dcaData);
    edit(copy);
    return whole - JSON.stringify(copy).length;
  };
  return {
    wraps: without((copy) => delete copy.contentData[NAME].keys),
    periodKeys: without((copy) => {
      for (const block of Object.values(copy.issuerData)) delete block.sealed.periodKeys;
    }),
    chain: without((copy) => {
      if (copy.periodGeometry !== undefined) {
        if (Object.values(copy.issuerData).some((block) => block.sealed.periodKeys !== undefined)) {
          delete copy.periodGeometry.chainsPerDay;
        } else {
          delete copy.periodGeometry;
        }
      }
      for (const block of Object.values(copy.issuerData)) delete block.sealed.chainKeys;
    }),
  };
}

/**
 * @typedef {object} Route
 * @property {import('./world.js').ClientKind} client
 * @property {import('./world.js').IssuerKind} issuer
 * @property {number} horizon
 * @property {Record<string, number>} [limits]
 * @property {string} [refused] - the refusal code this row expects
 */

/**
 * One exchange for the first issuer of a measured render. A route may name the
 * refusal it expects; a refusal it does not expect, or a success where it
 * expected one, stops the run.
 *
 * @param {Awaited<ReturnType<typeof delivery>>} measured
 * @param {Route} route
 */
async function measuredExchange(measured, route) {
  const { spec } = measured.rendered;
  const { value: result, work } = await counted((phase) =>
    exchange(measured.rendered, route, phase),
  );
  checkRequestForm(spec, route, result.requestDocument);
  const request = sizes(measured.normalize(result.requestDocument));
  const where = `${spec.form} ${route.client}>${route.issuer}`;
  if (route.refused !== undefined) {
    check(result.status !== 200 && result.code === route.refused, `${where}: refused as expected`);
    return { refused: `${result.status} ${result.code}`, request, work };
  }
  check(result.status === 200, `${where}: answered 200, got ${result.status} ${result.code}`);
  checkResponseForm(spec, route, result);
  checkIssuerInput(spec, route, work);
  return {
    refused: null,
    request,
    response: sizes(result.responseDocument),
    count: expectedPerFamily(spec, route),
    work,
  };
}

/** @param {Record<string, { hkdf: number, ecdh: number, rsa: number }>} work @param {string} phase */
const opened = (work, phase) => (work[phase]?.ecdh ?? 0) + (work[phase]?.rsa ?? 0);
/** @param {Record<string, { hkdf: number, ecdh: number, rsa: number }>} work @param {string} phase */
const hkdf = (work, phase) => work[phase]?.hkdf ?? 0;

/**
 * The issuer answered from the input its kind selects. The period-key issuer
 * opens one carrier per granted period key and derives nothing. A chain-input
 * issuer opens one chain carrier per touched window, and one that projects
 * period keys derives them. The response form alone cannot tell these apart:
 * a relay request for `period-key-plus-chain` carries both member kinds, and
 * an issuer that answered from the relayed period keys would return the same
 * period keys while opening two carriers and running no HKDF.
 *
 * @param {any} spec
 * @param {{ issuer: string, horizon: number }} route
 * @param {Record<string, { hkdf: number, ecdh: number, rsa: number }>} work
 */
function checkIssuerInput(spec, route, work) {
  const where = `${spec.form} ${route.issuer} issuer input`;
  const perFamily =
    route.issuer === "period-key"
      ? Math.min(route.horizon, spec.slots)
      : new Set(
          chainSelection(spec, route.horizon).map((minute) => minute - (minute % WINDOW_MINUTES)),
        ).size;
  check(opened(work, "issuer") === spec.groups * perFamily, `${where}: carriers opened`);
  if (route.issuer === "period-key") check(hkdf(work, "issuer") === 0, `${where}: no derivation`);
  if (route.issuer === "chain>period-key") {
    check(hkdf(work, "issuer") > 0, `${where}: period keys derived from chain keys`);
  }
}

/**
 * The lines one exchange prints.
 *
 * @param {string} label
 * @param {Awaited<ReturnType<typeof measuredExchange>>} x
 * @param {'period key'|'chain key'} unit
 */
function exchangeLines(label, x, unit) {
  if (x.refused !== null) {
    return [
      `     ${label}`,
      `       request ${triple(x.request)}; refused as the row expects: ${x.refused}`,
    ];
  }
  return [
    `     ${label}`,
    `       request ${triple(x.request)}, response ${triple(x.response)}, ` +
      `${many(x.count, unit)} per family`,
    `       issuer opened ${many(opened(x.work, "issuer"), "carrier")} and ran ` +
      `${hkdf(x.work, "issuer")} HKDF; client ran ${hkdf(x.work, "client")} HKDF`,
  ];
}

/**
 * The routes each supply form is exchanged over, at a horizon of `h` periods.
 *
 * @param {string} form
 * @param {number} h
 * @returns {{ label: string, unit: 'period key'|'chain key', route: Route }[]}
 */
function routesFor(form, h) {
  const periodKey = {
    label: "period-key client > period-key issuer",
    unit: /** @type {const} */ ("period key"),
    route: /** @type {Route} */ ({ client: "period-key", issuer: "period-key", horizon: h }),
  };
  const projected = {
    label: "relay client > chain-input issuer, period-key output",
    unit: /** @type {const} */ ("period key"),
    route: /** @type {Route} */ ({ client: "relay", issuer: "chain>period-key", horizon: h }),
  };
  const chain = {
    label: "relay client > chain-input issuer, chain output",
    unit: /** @type {const} */ ("chain key"),
    route: /** @type {Route} */ ({ client: "relay", issuer: "chain>chain", horizon: h }),
  };
  if (form === "period-key-only") return [periodKey];
  if (form === "period-key-plus-chain") return [periodKey, projected];
  return [
    projected,
    chain,
    {
      ...periodKey,
      label: "period-key client > period-key issuer (no period-key member to relay)",
      route: { ...periodKey.route, refused: "denied" },
    },
  ];
}

// ---------------------------------------------------------------------------
// Header

/** The revision this run measured, and any tracked change under js beside it. */
function revision() {
  const cwd = fileURLToPath(new URL(".", import.meta.url));
  try {
    const head = execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd })
      .toString()
      .trim();
    const changed = execFileSync(
      "git",
      ["status", "--porcelain", "--untracked-files=no", "--", "../.."],
      { cwd },
    )
      .toString()
      .split("\n")
      .filter(Boolean)
      .map((line) => line.slice(3));
    return { head, changed };
  } catch {
    return { head: "unknown (no git)", changed: [] };
  }
}

const rev = revision();
say(`Reference revision ${rev.head}, Node ${process.version}.`);
if (rev.changed.length === 0) {
  say("Tracked files under js match that revision.");
} else {
  say("Tracked files under js that differ from that revision:");
  for (const path of rev.changed) say(`  ${path}`);
}
say(
  `Geometry ${GEOMETRY.chainsPerDay}/${GEOMETRY.periodMinutes}: ` +
    `${WINDOW_MINUTES / GEOMETRY.periodMinutes} periods per ${WINDOW_MINUTES / 60}-hour window.`,
);
say("Sizes are raw / gzip -9 / Brotli q11 bytes; compressed sizes are of the normalized twin.");
say("");

// ---------------------------------------------------------------------------
// A. The focused case

const FOCUS = {
  algorithm: /** @type {'ecdh-p256'|'rsa-oaep'} */ ("ecdh-p256"),
  issuers: 1,
  groups: 1,
  slots: 2,
  chainWindows: 1,
  at: MID,
};

{
  say("A. Focused case: ECDH-P256, 1 issuer, 1 access group, 2 periods, 1 window, 05:05Z");
  const floor = await delivery({ ...FOCUS, form: "content-key-only" });
  say(`   content-key-only floor    ${triple(floor.size)}`);
  /** @type {Record<string, Awaited<ReturnType<typeof delivery>>>} */
  const measured = {};
  for (const form of SUPPLY) {
    measured[form] = await delivery({ ...FOCUS, form });
    say(
      `   ${form.padEnd(22)}    ${triple(measured[form].size)}   ` +
        `(${signedTriple(minus(measured[form].size, floor.size))} over the floor)`,
    );
    say(
      `     raw parts: wraps ${measured[form].parts.wraps}, ` +
        `period-key supply ${measured[form].parts.periodKeys}, ` +
        `chain supply ${measured[form].parts.chain}; publisher ran ${measured[form].work.hkdf} HKDF`,
    );
  }
  say("   Exchanges at horizon 2, the two periods the render wraps under:");
  for (const form of SUPPLY) {
    say(`   ${form}`);
    for (const { label, unit, route } of routesFor(form, 2)) {
      const x = await measuredExchange(measured[form], route);
      for (const line of exchangeLines(label, x, unit)) say(line);
    }
  }
  say("");
}

// ---------------------------------------------------------------------------
// B. Envelopes and period cases

/** The three period cases every envelope runs. */
const PERIOD_CASES = [
  {
    name: "current period only: 1 period, 1 window, 05:05Z",
    slots: 1,
    chainWindows: 1,
    at: MID,
  },
  {
    name: "current and next inside one window: 2 periods, 1 window, 05:05Z",
    slots: 2,
    chainWindows: 1,
    at: MID,
  },
  {
    name: "current and next across a window edge: 2 periods, 2 windows, 11:50Z",
    slots: 2,
    chainWindows: 2,
    at: EDGE,
  },
];

/** @type {Record<string, Record<string, Record<string, Size>>>} */
const byEnvelope = {};
{
  say("B. Envelopes by period case: 1 issuer, 1 access group, horizon = wrapped periods");
  for (const algorithm of ENVELOPES) {
    byEnvelope[algorithm] = {};
    for (const periodCase of PERIOD_CASES) {
      byEnvelope[algorithm][periodCase.name] = {};
      say(`   ${algorithm}, ${periodCase.name}`);
      const spec = { algorithm, issuers: 1, groups: 1, ...periodCase };
      const floor = await delivery({ ...spec, form: "content-key-only" });
      say(`     content-key-only floor      ${triple(floor.size)}`);
      for (const form of SUPPLY) {
        const measured = await delivery({ ...spec, form });
        byEnvelope[algorithm][periodCase.name][form] = measured.size;
        say(`     ${form.padEnd(22)}      ${triple(measured.size)}`);
        for (const { label, unit, route } of routesFor(form, spec.slots)) {
          const x = await measuredExchange(measured, route);
          for (const line of exchangeLines(label, x, unit)) say(`  ${line}`);
        }
      }
    }
  }
  // The second-window wrap is cached-only in this case. The independent item
  // content-key route completes the item, so the publisher may author it.
  const cachedOnly = await render({
    ...FOCUS,
    form: "chain-only",
    slots: 2,
    chainWindows: 1,
    at: EDGE,
  });
  checkDeliveryForm(cachedOnly);
  say("   Accepted: one chain window across the edge with a cached-only second wrap");
  say("");
}

// ---------------------------------------------------------------------------
// C. Issuers and access groups

{
  say("C. Issuers and access groups: 2 periods, 1 window, 05:05Z, horizon 2");
  for (const algorithm of ENVELOPES) {
    for (const [issuers, groups] of [
      [1, 1],
      [2, 1],
      [1, 3],
      [2, 3],
    ]) {
      say(`   ${algorithm}, ${many(issuers, "issuer")}, ${many(groups, "access group")}`);
      const spec = { algorithm, issuers, groups, slots: 2, chainWindows: 1, at: MID };
      const floor = await delivery({ ...spec, form: "content-key-only" });
      say(`     content-key-only floor      ${triple(floor.size)}`);
      for (const form of SUPPLY) {
        const measured = await delivery({ ...spec, form });
        say(
          `     ${form.padEnd(22)}      ${triple(measured.size)}   ` +
            `(${signedTriple(minus(measured.size, floor.size))} over the floor)`,
        );
        // Section B already exchanges one access group; each issuer's
        // exchange carries only its own block, so a second issuer changes
        // nothing a client sends or receives.
        if (groups === 1 || issuers > 1) continue;
        for (const { label, unit, route } of routesFor(form, 2)) {
          const x = await measuredExchange(measured, route);
          for (const line of exchangeLines(label, x, unit)) say(`  ${line}`);
        }
      }
    }
  }
  say("");
}

// ---------------------------------------------------------------------------
// D. Period series: fixed and marginal bytes, break-even

/**
 * Two series. With one supplied window the render sits at the window start,
 * so every P up to the window's 48 periods fits it. With two it sits in the
 * window's last period, so every P from 2 on crosses into the second window.
 */
const SERIES = [
  { windows: 1, at: START, slots: [1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48] },
  { windows: 2, at: EDGE, slots: [1, 2, 3, 4, 8, 16, 48] },
];

{
  say("D. Wrapped periods P, 1 issuer, 1 access group");
  say("   K is period-key-only, C chain-only, K+C period-key-plus-chain. Every form wraps the");
  say("   item under the same P periods, so K - C is the supply difference alone.");
  for (const series of SERIES) {
    for (const algorithm of ENVELOPES) {
      say(`   ${algorithm}, ${many(series.windows, "window")} supplied, render at ${series.at}`);
      /** @type {Record<number, Record<string, Size>>} */
      const rows = {};
      for (const slots of series.slots) {
        const spec = {
          algorithm,
          issuers: 1,
          groups: 1,
          slots,
          chainWindows: series.windows,
          at: series.at,
        };
        rows[slots] = {};
        for (const form of SUPPLY) rows[slots][form] = (await delivery({ ...spec, form })).size;
        const k = rows[slots]["period-key-only"];
        const c = rows[slots]["chain-only"];
        const kc = rows[slots]["period-key-plus-chain"];
        say(
          `     P ${String(slots).padStart(2)}  K ${triple(k)}  C ${triple(c)}  K+C ${triple(kc)}`,
        );
        say(
          `           K - C ${signedTriple(minus(k, c))}   K+C - K ${signedTriple(minus(kc, k))}`,
        );
      }
      for (const measure of /** @type {const} */ (["raw", "gzip", "br"])) {
        /** @param {number} p @param {string} form */
        const at = (p, form) => rows[p][form][measure];
        const crossing = series.slots.find((p) => at(p, "period-key-only") > at(p, "chain-only"));
        /** @param {(p: number) => number} value */
        const slopes = (value) =>
          series.slots.slice(1).map((p, index) => {
            const before = series.slots[index];
            return (value(p) - value(before)) / (p - before);
          });
        const member = slopes((p) => at(p, "period-key-only") - at(p, "chain-only"));
        const wrap = slopes((p) => at(p, "chain-only"));
        const range = (/** @type {number[]} */ values) =>
          `${Math.min(...values).toFixed(1)} to ${Math.max(...values).toFixed(1)}`;
        say(`     ${measure.padEnd(4)} K is larger than C from P = ${crossing ?? "none"}`);
        say(`          per period-key member ${range(member)}; per wrapped period ${range(wrap)}`);
      }
    }
  }
  say("");
}

// ---------------------------------------------------------------------------
// E. Authorized horizon with period length fixed

const HORIZONS = [1, 2, 3, 4, 8, 16, 28, 29, 48];

/** Issuer limits for the period-key exchanges the reference defaults refuse. */
const RAISED = { maxEntries: 64, maxEntriesPerGroup: 64 };

{
  say("E. Horizon h with 15-minute periods: ECDH-P256, 1 issuer, 1 access group, 05:05Z");
  say("   chain-only delivery is fixed: 2 wrapped periods, 2 windows supplied.");
  say("   Each period-key-only delivery supplies P = h period keys and shows its excess over it.");
  const chainSpec = { ...FOCUS, chainWindows: 2 };
  const chain = await delivery({ ...chainSpec, form: "chain-only" });
  say(`     chain-only delivery      ${triple(chain.size)}`);
  for (const horizon of HORIZONS) {
    say(`   h ${horizon}`);
    const keyed = await delivery({ ...chainSpec, form: "period-key-only", slots: horizon });
    say(
      `     period-key-only delivery, P = ${horizon}: ${triple(keyed.size)}, ` +
        `${signedTriple(minus(keyed.size, chain.size))}`,
    );
    /** @type {Route} */
    const route = { client: "period-key", issuer: "period-key", horizon };
    const label = "period-key client > period-key issuer";
    // The reference issuer admits at most 4 relayed period keys per family by
    // default (`maxEntriesPerGroup`), so the row expects the refusal above 4.
    const defaults = await measuredExchange(
      keyed,
      horizon > 4 ? { ...route, refused: "too_many_entries" } : route,
    );
    if (defaults.refused === null) {
      for (const line of exchangeLines(label, defaults, "period key")) say(`  ${line}`);
    } else {
      say(`       default issuer limits: request ${triple(defaults.request)}`);
      say(`         refused: ${defaults.refused}`);
      const raised = await measuredExchange(keyed, { ...route, limits: RAISED });
      for (const line of exchangeLines(`${label}, limits raised to 64`, raised, "period key")) {
        say(`  ${line}`);
      }
    }
    for (const { label: chainLabel, unit, route: chainRoute } of routesFor(
      "chain-only",
      horizon,
    ).slice(0, 2)) {
      const x = await measuredExchange(chain, chainRoute);
      for (const line of exchangeLines(`chain-only, ${chainLabel}`, x, unit)) say(`  ${line}`);
    }
  }
  say("");
}

// ---------------------------------------------------------------------------
// F. Projection

{
  say("F. Projection: Brotli delivery bytes per render x CDN responses");
  say("   shown at 100 000 000 article responses; 1 GB = 10^9 bytes");
  const atVolume = (/** @type {number} */ bytes) => `${((bytes * 1e8) / 1e9).toFixed(1)} GB`;
  for (const algorithm of ENVELOPES) {
    for (const periodCase of PERIOD_CASES) {
      const forms = byEnvelope[algorithm][periodCase.name];
      const saved = minus(forms["period-key-only"], forms["chain-only"]).br;
      const transition = minus(forms["period-key-plus-chain"], forms["period-key-only"]).br;
      say(`   ${algorithm}, ${periodCase.name}`);
      say(
        saved >= 0
          ? `     chain-only is ${grouped(saved)} B smaller per render: ${atVolume(saved)} less`
          : `     chain-only is ${grouped(-saved)} B larger per render: ${atVolume(-saved)} more`,
      );
      say(
        `     period-key-plus-chain is ${grouped(transition)} B larger than period-key-only: ` +
          `${atVolume(transition)} more`,
      );
    }
  }
  say("");
}

// ---------------------------------------------------------------------------
// G. Random-dependent: compressed spread over genuine renders

const bytesSection = [...out];
if (!BYTES_ONLY) {
  say("G. Compressed spread over genuine renders (random carriers; not part of --bytes)");
  say(`   focused case, ${SPREAD_RENDERS} renders each, markup as written: min..max`);
  for (const algorithm of ENVELOPES) {
    for (const form of SUPPLY) {
      /** @type {{ gzip: number[], br: number[] }} */
      const seen = { gzip: [], br: [] };
      /** @type {Size|null} */
      let normalized = null;
      for (let index = 0; index < SPREAD_RENDERS; index++) {
        const measured = await delivery({ ...FOCUS, algorithm, form });
        const genuine = sizes(measured.rendered.markup);
        seen.gzip.push(genuine.gzip);
        seen.br.push(genuine.br);
        normalized = measured.size;
      }
      const span = (/** @type {number[]} */ values) =>
        `${Math.min(...values)}..${Math.max(...values)}`;
      say(`   ${algorithm} ${form}`);
      say(
        `     gzip ${span(seen.gzip)} (normalized ${normalized?.gzip}), ` +
          `br ${span(seen.br)} (normalized ${normalized?.br})`,
      );
    }
  }
  say("");
}

process.stdout.write(`${(BYTES_ONLY ? bytesSection : out).join("\n")}\n`);

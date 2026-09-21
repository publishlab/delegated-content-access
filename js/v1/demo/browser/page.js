// @ts-check
//
// This file reads the controls, runs the scenario, and puts the trace on the
// page. Nothing here decides anything about the protocol. It reads the steps
// the scenario already took and gives each one a shape to look at.
//
// Only this file touches the DOM, so the identical scenario runs under
// `node --test` with no DOM at all.
//
// The form holds one control per argument `run()` takes, and holds no others.
// A control that named something the scenario has no knob for is refused rather
// than ignored, and the refusal lands in the panel below like any other
// failure. That keeps this file from growing a setting the scenario does not
// have. A field left empty sends no argument at all, so the scenario's
// own default applies, and the controls are written back from the world that
// ran, so they show the run that produced the page.
//
// A later run supersedes an earlier one instead of cancelling it. Every change
// starts a run; a run that finishes after a later one started is dropped on
// arrival rather than rendered over the newer one. Nothing here can abort a
// run, because the scenario awaits in sequence with no timers in it, so only
// the ticket check keeps a stale run from rendering.
//
// Everything is written with textContent. A decrypted article is HTML, and
// this page shows what came out of the AEAD rather than the browser's
// rendering of it. The page exists to show those bytes, and inserting them as
// markup would teach a bad habit.

import { run } from "./scenario.js";
import * as clientBoundEcdh from "../../extensions/client-bound-transport/ecdhP256.js";
import { clientBoundKeyCapability } from "../../extensions/client-bound-transport/core-client/clientBoundKeyCapability.js";

const CLIENT_BOUND = { profile: clientBoundEcdh, capability: clientBoundKeyCapability };

const MINUTE = 60_000;

const KINDS = {
  render: { title: "Publisher renders", tone: "sealed" },
  resolve: { title: "Client looks at what it holds", tone: "plain" },
  decrypt: { title: "Client decrypts", tone: "plain" },
  unlock: { title: "Client asks the issuer", tone: "wire" },
  advance: { title: "Time passes", tone: "time" },
};

/**
 * @param {string} tag
 * @param {{ className?: string, text?: string }} [attrs]
 * @param {(Node|null)[]} [children]
 * @returns {HTMLElement}
 */
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  if (attrs.className) node.className = attrs.className;
  if (attrs.text !== undefined) node.textContent = attrs.text;
  for (const child of children) {
    if (child) node.appendChild(child);
  }
  return node;
}

/**
 * @param {string} label
 * @param {string} value
 * @returns {HTMLElement}
 */
function field(label, value) {
  return el("div", { className: "field" }, [
    el("span", { className: "label", text: label }),
    el("span", { className: "value", text: value }),
  ]);
}

/**
 * @param {string[]} values
 * @param {string} [className]
 * @returns {HTMLElement}
 */
function chips(values, className = "") {
  return el(
    "div",
    { className: "chips" },
    values.map((value) => el("span", { className: `chip ${className}`.trim(), text: value })),
  );
}

/**
 * @param {string} label
 * @param {string[]} values
 * @returns {HTMLElement}
 */
function chipField(label, values) {
  return el("div", { className: "field" }, [
    el("span", { className: "label", text: label }),
    chips(values),
  ]);
}

/**
 * @param {string} caption
 * @param {string} text
 * @param {string} [className]
 * @returns {HTMLElement}
 */
function block(caption, text, className = "") {
  return el("div", { className: "block" }, [
    el("div", { className: "caption", text: caption }),
    el("pre", { className: `mono ${className}`.trim(), text }),
  ]);
}

/**
 * @param {string} caption
 * @param {any} value
 * @returns {HTMLElement}
 */
function json(caption, value) {
  const details = el("details", { className: "json" });
  details.appendChild(el("summary", { text: caption }));
  details.appendChild(el("pre", { className: "mono", text: JSON.stringify(value, null, 2) }));
  return details;
}

/**
 * @param {string} text
 * @returns {HTMLElement}
 */
function aside(text) {
  return el("p", { className: "aside", text });
}

/**
 * What the network counted, added up across the urls one step has reached. The
 * bytes count the serialised payloads measured at the seam, a refused call
 * included: a client pays for what it tried to send.
 *
 * Probes are added up apart from unlocks, and the failures span both. A
 * fallback checking a primary that is down fails twice over one article, and
 * folding those into the requests would report calls no client made.
 *
 * @param {Record<string, any>} wire
 * @returns {{ attempts: number, probes: number, failures: number, requestBytes: number, responseBytes: number }}
 */
function totals(wire) {
  const summed = { attempts: 0, probes: 0, failures: 0, requestBytes: 0, responseBytes: 0 };
  for (const url of Object.values(wire ?? {})) {
    summed.attempts += url.attempts;
    summed.probes += url.probes;
    summed.failures += url.failures;
    summed.requestBytes += url.requestBytes;
    summed.responseBytes += url.responseBytes;
  }
  return summed;
}

/**
 * @param {Record<string, any>} wire
 * @returns {string}
 */
function wireText(wire) {
  const { attempts, probes, failures, requestBytes, responseBytes } = totals(wire);
  if (attempts === 0 && probes === 0) return "nothing on the wire";

  const calls = `${attempts} ${attempts === 1 ? "request" : "requests"}`;
  const probed = probes === 0 ? "" : `, ${probes} health ${probes === 1 ? "probe" : "probes"}`;
  const failed = failures === 0 ? "" : `, ${failures} unanswered`;
  return `${calls}${probed}${failed}, ${requestBytes} B out, ${responseBytes} B in`;
}

/**
 * @param {any} step
 * @returns {HTMLElement}
 */
function body(step) {
  const parts = el("div", { className: "body" });

  if (step.kind === "render") {
    parts.appendChild(field("rendered in period", step.t));
    parts.appendChild(field("renderId", step.renderId));
    parts.appendChild(chipField("periods shipped", step.periods));
    parts.appendChild(
      block(
        `sealedContent.${step.contentName}: base64url AES-256-GCM`,
        step.ciphertext,
        "gibberish",
      ),
    );
    parts.appendChild(field("nonce / aad", `${step.nonce} / ${step.aad}`));
  }

  if (step.kind === "resolve") {
    parts.appendChild(
      field("opened from cache", step.covered.length ? step.covered.join(", ") : "nothing"),
    );
    parts.appendChild(
      field("still needs an unlock", step.missing.length ? step.missing.join(", ") : "nothing"),
    );
    parts.appendChild(field("trial unwraps so far", String(step.load.trials)));
  }

  if (step.kind === "decrypt") {
    if (step.text === null) {
      parts.appendChild(el("p", { className: "refused", text: `locked: ${step.error}` }));
      parts.appendChild(aside("A name with no key is a typed miss, not a wrong plaintext."));
    } else {
      parts.appendChild(block("plaintext", step.text, "plaintext"));
    }
  }

  if (step.kind === "unlock") {
    parts.appendChild(field("asked for", step.needed.length ? step.needed.join(", ") : "nothing"));
    parts.appendChild(
      chipField(
        "issuers tried, in order",
        step.attempts.map((/** @type {any} */ attempt) =>
          [attempt.issuerName, attempt.outcome, attempt.status === null ? "" : attempt.status]
            .filter(Boolean)
            .join(" "),
        ),
      ),
    );
    if (step.unlockUrl) parts.appendChild(field("POST", step.unlockUrl));
    parts.appendChild(field("answered by", step.issuerName ?? "nobody"));
    parts.appendChild(field("status", step.status === null ? "no answer" : String(step.status)));
    if (step.transportMode) parts.appendChild(field("transport", step.transportMode));

    if (step.request) parts.appendChild(json("request body, as it crossed", step.request));
    if (step.response) parts.appendChild(json("response body, as it crossed", step.response));
    if (step.transportMode === "client-bound") {
      parts.appendChild(
        aside(
          "Every key arrived wrapped to the public half this client offered, so what it holds " +
            "are handles it cannot export - and the cache below reports them as handles rather " +
            "than printing bytes it was never given.",
        ),
      );
    }
    if (!step.request) {
      parts.appendChild(
        aside("Nothing was answered, so there is no body to show - the attempts above say why."),
      );
    }
    parts.appendChild(json("what has crossed, per url", step.wire));
  }

  if (step.kind === "advance") {
    parts.appendChild(field("clock", `${step.from}  →  ${step.to}`));
    parts.appendChild(field("period label", `${step.fromT}  →  ${step.toT}`));
    parts.appendChild(aside("Only the publisher owns a clock. The client never reads one."));
  }

  return parts;
}

/**
 * The numbers under every step: what the client has spent on the issuer, what
 * it holds, and what that cost the wire.
 *
 * @param {any} step
 * @returns {HTMLElement}
 */
function footer(step) {
  return el("div", { className: "footer" }, [
    el("span", {
      className: `count ${step.unlockCalls === 0 ? "zero" : ""}`.trim(),
      text: `${step.unlockCalls} unlock ${step.unlockCalls === 1 ? "call" : "calls"}`,
    }),
    el("span", { className: "chip", text: wireText(step.wire) }),
    step.cache.length
      ? chips(
          step.cache.map((/** @type {any} */ entry) => `${entry.accessGroup} ${entry.t}`),
          "held",
        )
      : el("span", { className: "chip empty", text: "cache empty" }),
  ]);
}

/**
 * @param {any} step
 * @param {number} index
 * @returns {HTMLElement}
 */
function card(step, index) {
  const kind = Object.hasOwn(KINDS, step.kind)
    ? KINDS[/** @type {keyof typeof KINDS} */ (step.kind)]
    : null;
  const tone = step.kind === "unlock" && step.ok === false ? "failed" : (kind?.tone ?? "");

  return el("section", { className: `step ${tone}`.trim() }, [
    el("header", {}, [
      el("span", { className: "ordinal", text: String(index + 1) }),
      el("h2", { text: kind?.title ?? step.kind }),
      step.label ? el("span", { className: "article", text: `article ${step.label}` }) : null,
    ]),
    body(step),
    footer(step),
  ]);
}

/**
 * @param {any} world
 * @returns {HTMLElement}
 */
function preamble(world) {
  return el("section", { className: "world" }, [
    field(
      "publisher",
      `${world.origin}, ${world.period.length}-minute periods, ${world.period.slots} slots`,
    ),
    field(
      "signs as",
      `${world.signingKid}, the issuer verifies both envelopes before it opens a blob`,
    ),
    field("issuer", `${world.issuerName}, keyId ${world.keyId}, ${world.algorithm}`),
    chipField(
      "client walks",
      world.issuers.map((/** @type {any} */ issuer) => issuer.issuerName),
    ),
    field("content", `${world.contentName} in accessGroup ${world.accessGroup}`),
    field("transport", `${world.transportMode}, as the primary answers`),
    world.fallback
      ? field(
          "fallback authorization",
          "simulation: issuer-owned emergency window; primary failure alone grants nothing",
        )
      : null,
    world.primaryOffline
      ? field("the primary", "down: its unlock url and its health check both refuse the connection")
      : null,
    field("clock starts", world.at),
    field("entropy", `seeded (${world.seed}): this run replays byte for byte`),
  ]);
}

/**
 * @param {any} trace
 * @returns {string}
 */
function outcome(trace) {
  if (trace.summary.articlesOpened === 0) {
    return "Nothing opened. The steps above say where it stopped, and what the issuer said when it did.";
  }
  const secondUnlocked = trace.steps.some(
    (/** @type {any} */ step) => step.kind === "unlock" && step.label === "B",
  );
  if (secondUnlocked) {
    // Why the second article went back on the wire: a fallback that answered
    // the first unlock grants the current period only, so its grant does not
    // reach the next one. A healthy primary grants across periods, and the
    // second article costs a call only when the clock jumped past the reach
    // of the forward key that first unlock handed over.
    const firstUnlock = trace.steps.find(
      (/** @type {any} */ step) => step.kind === "unlock" && step.label === "A",
    );
    const trimmedByFallback =
      trace.world.fallback &&
      firstUnlock?.issuerName != null &&
      firstUnlock.issuerName !== trace.world.issuerName;
    if (trimmedByFallback) {
      return (
        "The second article crossed a period boundary the first grant did not reach, so it cost a call " +
        "of its own. That is what a grant trimmed to the current period costs the article after it."
      );
    }
    return (
      "The second article landed past the reach of the forward key the first unlock handed over, so it " +
      "cost a call of its own. The primary was healthy and the grant was whole; the clock jumped further " +
      "than one unlock keys ahead."
    );
  }
  return (
    "The second article crossed a period boundary and never reached the issuer. " +
    "The forward-overlap key from the first unlock covered it."
  );
}

/**
 * @param {any} trace
 * @returns {HTMLElement}
 */
function conclusion(trace) {
  const { summary } = trace;
  const calls = summary.unlockCalls;

  return el("section", { className: "conclusion" }, [
    el("h2", {
      text: `${summary.articlesOpened} articles opened, ${calls} unlock ${calls === 1 ? "call" : "calls"}`,
    }),
    el("p", { text: outcome(trace) }),
    field("across the wire", wireText(summary.wire)),
    chips(
      Object.entries(summary.servers).map(([role, stats]) => {
        const counted = /** @type {any} */ (stats);
        return `${role}: requests ${counted.requests}, grants ${counted.grants}, refused ${counted.refusals}`;
      }),
    ),
    chips(
      summary.cache.map((/** @type {any} */ entry) => `${entry.accessGroup} ${entry.t}`),
      "held",
    ),
  ]);
}

/**
 * @param {unknown} cause
 * @returns {HTMLElement}
 */
function failure(cause) {
  const message = cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
  return el("section", { className: "step failed" }, [
    el("header", {}, [el("h2", { text: "The scenario did not finish" })]),
    el("div", { className: "body" }, [
      block("error", message),
      aside(
        globalThis.isSecureContext
          ? "crypto.subtle is available, so this is a real failure."
          : "crypto.subtle is unavailable in this browser context.",
      ),
    ]),
  ]);
}

const main = /** @type {HTMLElement} */ (document.querySelector("main"));
const controls = /** @type {HTMLFormElement} */ (document.querySelector("#controls"));

/**
 * @param {string} name
 * @returns {any}
 */
function control(name) {
  return controls.elements.namedItem(name);
}

/**
 * A number a control holds, or null when it holds nothing. An empty field
 * reads as null rather than zero: it was cleared, and a cleared field sends no
 * argument so the scenario's own default stands.
 *
 * @param {FormDataEntryValue|null} value
 * @returns {number|null}
 */
function number(value) {
  const text = String(value ?? "").trim();
  if (text === "") return null;
  const parsed = Number(text);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * The controls, as `run()` takes them.
 *
 * @returns {object}
 */
function optionsFrom() {
  const held = new FormData(controls);

  /** @type {any} */
  const config = {
    fallback: held.get("fallback") !== null,
    primaryOffline: held.get("primaryOffline") !== null,
    transportMode: String(held.get("transportMode")),
  };

  const at = String(held.get("at") ?? "").trim();
  if (at !== "") config.at = at;

  const seed = number(held.get("seed"));
  if (seed !== null) config.seed = seed;

  const length = number(held.get("length"));
  const slots = number(held.get("slots"));
  if (length !== null || slots !== null) {
    config.period = {
      ...(length === null ? {} : { length }),
      ...(slots === null ? {} : { slots }),
    };
  }

  // The control is minutes because that is what the story is told in; the
  // scenario takes milliseconds, like every other duration in the demo.
  const advance = number(held.get("advance"));
  if (advance !== null) config.advance = advance * MINUTE;

  return config;
}

/**
 * The world that ran, written back into the controls. A field left empty comes
 * back filled with the default that applied, so what is on screen is always the
 * run that produced the page below it.
 *
 * @param {any} world
 * @returns {void}
 */
function fill(world) {
  control("at").value = world.at;
  control("seed").value = String(world.seed);
  control("length").value = String(world.period.length);
  control("slots").value = String(world.period.slots);
  control("advance").value = String(world.advanceMinutes);
  control("transportMode").value = world.transportMode;
  control("fallback").checked = world.fallback;
  control("primaryOffline").checked = world.primaryOffline;
}

/** The run the page is showing. A later one supersedes it wherever it finishes. */
let latest = 0;

/**
 * @param {object} config
 * @returns {Promise<void>}
 */
async function show(config) {
  const ticket = ++latest;
  controls.dataset.running = "yes";

  try {
    const trace = await run(config, CLIENT_BOUND);
    if (ticket !== latest) return;

    fill(trace.world);
    main.textContent = "";
    main.appendChild(preamble(trace.world));
    trace.steps.forEach((/** @type {any} */ step, /** @type {number} */ index) => {
      main.appendChild(card(step, index));
    });
    main.appendChild(conclusion(trace));
  } catch (cause) {
    if (ticket !== latest) return;
    main.textContent = "";
    main.appendChild(failure(cause));
  } finally {
    if (ticket === latest) delete controls.dataset.running;
  }
}

controls.addEventListener("change", () => {
  void show(optionsFrom());
});

// A form with no submit button still submits on Enter in a text field, and a
// navigation would take the page away from the run it is showing.
controls.addEventListener("submit", (event) => {
  event.preventDefault();
  void show(optionsFrom());
});

// The first run takes no arguments at all: the controls are empty until it
// comes back and says what the scenario's own defaults are.
await show({});

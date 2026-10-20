// @ts-check

// How the composed issuer carries opened keys on its response. Direct delivery
// leaves the answer alone. Client-bound delivery agrees a key before the issuer
// unseals anything, then wraps each delivered key for that client. The entropy
// belongs here rather than in the reusable engine, which stops at key bytes and
// has no part in the last hop.
//
// This component applies the mode it is given; it does not choose one. The
// issuer application selects the mode (pinned, or per-request policy) and hands
// it to `preflight`. `preflight` returns an opaque request view that carries
// the mode. `prepare` reads the mode from that view instead of taking it a
// second time, so the two calls cannot disagree. This adapter refuses a missing
// client key and never downgrades to raw bytes.

import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { dcaError } from "../core-shared/errors.js";
import {
  isRetirementLeaf,
  mapComposedSections,
  mapDeliveredKeys,
  settleComposedSections,
} from "../core-shared--client-issuer/responseKeys.js";
import { own } from "../core-shared/wire.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";

/**
 * The issuer core defines the response shape, but a client-bound adapter
 * cannot safely pass malformed key material through while it marks the body
 * as wrapped. Validate the two delivered-key sections at their actual depths
 * before a sealer sees any value.
 *
 * @param {any} node
 * @param {number} depth
 * @param {number} expectedBytes
 * @param {'contentKey'|'periodKey'|'chainKey'} keyKind
 */
function requireBase64urlKeyEntries(node, depth, expectedBytes, keyKind) {
  if (depth === 0) {
    if (typeof node !== "string") {
      throw dcaError("bad_config", "client-bound delivery needs string key entries");
    }
    keyEntryBytes(node, expectedBytes, keyKind);
    return;
  }
  if (node === null || typeof node !== "object") {
    throw dcaError("bad_config", "client-bound delivery needs correctly nested key sections");
  }
  for (const name of Object.keys(node)) {
    requireBase64urlKeyEntries(node[name], depth - 1, expectedBytes, keyKind);
  }
}

/**
 * One delivered key entry as bytes. Section 2.2 defines the spelling rule. This
 * adapter applies it both when it validates the shape and when it wraps a
 * value, so it never re-wraps a key entry the response could not have carried
 * while it marks the body as wrapped.
 *
 * @param {string} value
 * @param {number|null} [expectedBytes]
 * @param {string} [keyKind]
 * @returns {Uint8Array}
 */
function keyEntryBytes(value, expectedBytes = null, keyKind = "key") {
  const bytes = binaryStringBytes(value);
  if (bytes === null) {
    throw dcaError("bad_config", "client-bound delivery needs canonical base64url key entries");
  }
  if (expectedBytes !== null && bytes.length !== expectedBytes) {
    throw dcaError(
      "bad_config",
      `client-bound delivery needs ${expectedBytes}-byte ${keyKind} values`,
    );
  }
  return bytes;
}

/**
 * @param {any} keys
 */
function requireClientBoundKeyShape(keys) {
  if (keys === null || typeof keys !== "object") {
    throw dcaError("bad_config", "client-bound delivery needs a keys object");
  }
  const contentKeys = own(keys, "contentKeys");
  if (contentKeys !== undefined) requireBase64urlKeyEntries(contentKeys, 1, 16, "contentKey");

  const periodKeys = own(keys, "periodKeys");
  if (periodKeys !== undefined) {
    requireBase64urlKeyEntries(periodKeys, 2, 16, "periodKey");
  }

  const chainKeys = own(keys, "chainKeys");
  if (chainKeys !== undefined) {
    requireBase64urlKeyEntries(chainKeys, 2, 16, "chainKey");
  }
}

/**
 * The top-level members a base-engine body may carry beside the declared
 * composed sections. Composition fixes the member set, so a client-bound body
 * with any other member holds a section nobody declared for wrapping, and its
 * keys would leave raw under a body marked client-bound.
 */
const BASE_BODY_MEMBERS = Object.freeze(["keys", "errors", "notDelivered", "periodGeometry"]);

/**
 * A declared error map is records down to the section's depth, and every leaf
 * is exactly `{ error: "key_retired" }`. It is never wrapped, so nothing else
 * may sit in it: a free-form leaf would carry key bytes out raw.
 *
 * @param {any} value
 * @param {number} depth
 * @param {string[]} path
 */
function requireRetirementLeaves(value, depth, path) {
  if (depth === 0) {
    if (!isRetirementLeaf(value))
      throw dcaError("bad_config", `${path.join(".")} is not a key_retired error record`);
    return;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw dcaError("bad_config", `the error map ${path.join(".")} is not nested to its depth`);
  for (const name of Object.keys(value))
    requireRetirementLeaves(value[name], depth - 1, [...path, name]);
}

/**
 * Structural nodes above declared sections and error maps are closed:
 * declaring one child does not permit an undeclared sibling to leave raw. At a
 * section terminal, its existing depth and leaf validation owns the payload
 * and metadata; at an error-map terminal, only fixed retirement leaves pass.
 *
 * @param {any} body
 * @param {readonly Readonly<import("../core-shared--client-issuer/responseKeys.js").ComposedSection>[]} sections
 */
function requireDeclaredMembers(body, sections) {
  /** @typedef {{ terminal: boolean, errorDepth: number|null, children: Map<string, SectionNode> }} SectionNode */
  /** @returns {SectionNode} */
  const node = () => ({ terminal: false, errorDepth: null, children: new Map() });
  const root = node();
  /** @param {readonly string[]} path */
  const terminalAt = (path) => {
    let at = root;
    for (const name of path) {
      if (!at.children.has(name)) at.children.set(name, node());
      at = /** @type {SectionNode} */ (at.children.get(name));
    }
    return at;
  };
  for (const section of sections) {
    terminalAt(section.path).terminal = true;
    if (section.errorPath !== undefined) terminalAt(section.errorPath).errorDepth = section.depth;
  }
  /** @param {any} value @param {SectionNode} at @param {string[]} path */
  const walk = (value, at, path) => {
    if (value !== undefined && at.errorDepth !== null) {
      requireRetirementLeaves(value, at.errorDepth, path);
      return;
    }
    if (at.terminal || value === undefined) return;
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw dcaError("bad_config", `response section prefix ${path.join(".")} is not a record`);
    for (const name of Object.keys(value)) {
      if (path.length === 0 && BASE_BODY_MEMBERS.includes(name)) continue;
      const child = at.children.get(name);
      const next = [...path, name];
      if (child === undefined)
        throw dcaError(
          "bad_config",
          `client-bound delivery has no declared section for the response member ${next.join(".")}`,
        );
      walk(value[name], child, next);
    }
  };
  walk(body, root, []);
}

/** The base kinds' widths; a composed kind states its own. */
const BASE_KIND_WIDTHS = Object.freeze({ contentKey: 16, periodKey: 16, chainKey: 16 });

/**
 * Validate every key entry of the composed sections at its declared depth,
 * leaf member and kind width before a sealer sees any value, the way the base
 * sections are validated: a client-bound body never carries a composed key it
 * could not wrap.
 *
 * @param {any} body
 * @param {readonly Readonly<import("../core-shared--client-issuer/responseKeys.js").ComposedSection>[]} sections
 * @param {(keyKind: string) => number} widthOf
 */
function requireComposedKeyShape(body, sections, widthOf) {
  for (const section of sections) {
    let node = body;
    for (const name of section.path) node = own(node, name);
    if (node === undefined) continue;
    const width = widthOf(section.keyKind);
    /** @param {any} value @param {number} depth */
    const walk = (value, depth) => {
      if (depth === 0) {
        const key = section.leafKey === undefined ? value : own(value, section.leafKey);
        if (
          section.leafKey !== undefined &&
          (value === null || typeof value !== "object" || Array.isArray(value))
        ) {
          throw dcaError("bad_config", "client-bound delivery needs record leaves in this section");
        }
        if (typeof key !== "string") {
          throw dcaError("bad_config", "client-bound delivery needs string key entries");
        }
        keyEntryBytes(key, width, /** @type {any} */ (section.keyKind));
        return;
      }
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw dcaError("bad_config", "client-bound delivery needs correctly nested key sections");
      }
      for (const name of Object.keys(value)) walk(value[name], depth - 1);
    };
    walk(node, section.depth);
  }
}

/**
 * Both entries take the request this server was handed, not the document it
 * arrived as. Checked on the direct path too, so asking for the cheaper mode
 * does not skip it.
 *
 * @param {any} request
 * @returns {void}
 */
function requireRequest(request) {
  if (!(request instanceof DcaRequest)) {
    throw dcaError("bad_config", "response transport takes a DcaRequest; construct one first");
  }
}

/**
 * A request seen through one transport mode, as `preflight` resolved it. The
 * view exposes the mode so the caller can decide what depends on it (a shared
 * cache can store only a direct answer). The view does not expose the agreed
 * transport. The `KeyDelivery` that made the view keeps the agreed transport in
 * a table keyed by the view, so nothing that holds a view can reach the
 * wrapping key. `prepare` is the only reader, and it reads its own instance's
 * table.
 */
class RequestView {
  /** @param {'direct'|'client-bound'} mode */
  constructor(mode) {
    /** @type {'direct'|'client-bound'} */
    this.mode = mode;
    Object.freeze(this);
  }

  /** @returns {boolean} */
  isDirect() {
    return this.mode === "direct";
  }
}

export class KeyDelivery {
  /** @type {{ bytes: (n: number) => Uint8Array }|null} */
  #random;

  /**
   * The sealer agreed for each client-bound view this instance handed out. A
   * `WeakMap` so the view is the only key and no entry outlives its view. The
   * map lives here rather than on the view so the wrapping key the sealer
   * closes over never reaches the view's public surface.
   *
   * @type {WeakMap<RequestView, { transport: any, wrap: (keyBytes: Uint8Array, keyKind: string) => Promise<any> }>}
   */
  #sealers = new WeakMap();

  /**
   * The client-bound method this issuer application selected, as a profile
   * module. This component applies the profile it is given. The only method
   * detail it names is the profile's `METHOD`, which it puts on each
   * client-bound body so the client can tell an answer meant for its method
   * from one meant for another.
   *
   * @type {{ METHOD: string, seal: (clientPublicKey: any, options: any) => Promise<any> }|null}
   */
  #profile;

  /** @type {readonly Readonly<import("../core-shared--client-issuer/responseKeys.js").ComposedSection>[]} */
  #composedSections;

  /** @type {Readonly<Record<string, { width: number }>>|undefined} */
  #composedKinds;

  /**
   * @param {object} config
   * @param {{ bytes: (n: number) => Uint8Array }} [config.random] - the
   *   client-bound wrapping nonces, one per delivered key
   * @param {{ METHOD: string, seal: (clientPublicKey: any, options: any) => Promise<any> }} [config.profile] -
   *   the client-bound method selected by the issuer application
   * @param {import("../core-shared--client-issuer/responseKeys.js").ComposedSection[]} [config.composedSections] -
   *   response sections a selected extension adds beside `keys`, each wrapped
   *   under its declared kind in client-bound mode
   * @param {Readonly<Record<string, { width: number }>>} [config.composedKinds] -
   *   the settled kind set the selected profile was composed with; every
   *   composed section names a base kind or one of these, and the profile's
   *   sealer receives the set to bind and check those kinds
   */
  constructor(
    { random, profile, composedSections, composedKinds, ...unsupported } = /** @type {any} */ ({}),
  ) {
    const names = Object.keys(unsupported);
    if (names.length > 0) {
      throw dcaError(
        "unsupported_option",
        `KeyDelivery has no ${names[0]} yet, and will not pretend to`,
      );
    }
    if (random !== undefined && typeof random?.bytes !== "function") {
      throw dcaError("bad_config", "a random is an object with a bytes(n)");
    }
    if (
      profile !== undefined &&
      (typeof profile?.seal !== "function" || typeof profile?.METHOD !== "string")
    ) {
      throw dcaError(
        "bad_config",
        "a profile has a string METHOD and a seal(clientPublicKey, options) function",
      );
    }
    this.#random = random ?? null;
    this.#profile = profile ?? null;
    if (
      composedKinds !== undefined &&
      (composedKinds === null || typeof composedKinds !== "object" || Array.isArray(composedKinds))
    ) {
      throw dcaError("bad_config", "composedKinds is the settled kind set of the profile");
    }
    this.#composedKinds = composedKinds;
    this.#composedSections = settleComposedSections(composedSections ?? []);
    for (const { keyKind } of this.#composedSections) this.#widthOf(keyKind);
  }

  /** @param {string} keyKind @returns {number} */
  #widthOf(keyKind) {
    if (Object.hasOwn(BASE_KIND_WIDTHS, keyKind))
      return BASE_KIND_WIDTHS[/** @type {keyof typeof BASE_KIND_WIDTHS} */ (keyKind)];
    const width =
      this.#composedKinds && Object.hasOwn(this.#composedKinds, keyKind)
        ? this.#composedKinds[keyKind]?.width
        : undefined;
    if (!Number.isSafeInteger(width) || /** @type {number} */ (width) < 1) {
      throw dcaError("bad_config", `composed section kind ${keyKind} is not a composed kind`);
    }
    return /** @type {number} */ (width);
  }

  /**
   * Agree client-bound delivery before the issuer unseals, and hand back an
   * opaque view of the request under the chosen mode. Direct mode agrees
   * nothing. A missing client key is refused here, never silently downgraded.
   *
   * @param {'direct'|'client-bound'} mode
   * @param {DcaRequest} request
   * @returns {Promise<RequestView>}
   */
  async preflight(mode, request) {
    // This check runs before the direct return; otherwise a caller would skip
    // it by asking for direct mode, which agrees nothing.
    requireRequest(request);
    if (mode !== "direct" && mode !== "client-bound") {
      throw dcaError("unsupported_option", `unknown key-delivery mode ${JSON.stringify(mode)}`);
    }
    if (mode === "direct") return new RequestView("direct");

    if (this.#profile === null) {
      throw dcaError("bad_config", "client-bound delivery needs an injected transport profile");
    }

    const clientPublicKey = request.clientPublicKey;
    if (clientPublicKey === undefined) {
      throw dcaError("client_key_required", "client-bound transport needs the client public key");
    }
    // The profile receives the injected random source before a view is agreed.
    // A profile that needs randomness refuses a missing source here rather than
    // downgrading to bytes handed over unwrapped.
    const sealer = await this.#profile.seal(clientPublicKey, {
      random: this.#random,
      ...(this.#composedKinds === undefined ? {} : { composedKinds: this.#composedKinds }),
    });
    const view = new RequestView("client-bound");
    this.#sealers.set(view, sealer);
    return view;
  }

  /**
   * Prepare the response body for the view `preflight` returned. The mode is
   * read from the view, not passed again, so a client-bound view can only be
   * prepared as client-bound. Direct returns the body unchanged; client-bound
   * wraps each delivered key under the view's agreed transport.
   *
   * @param {any} body
   * @param {RequestView} view
   * @returns {Promise<any>}
   */
  async prepare(body, view) {
    if (!(view instanceof RequestView)) {
      throw dcaError("bad_config", "body preparation takes the view preflight returned");
    }
    if (view.mode === "direct") return body;

    const sealer = this.#sealers.get(view);
    if (sealer === undefined) {
      throw dcaError("bad_config", "this client-bound view was not agreed by this KeyDelivery");
    }

    const suppliedKeys = body?.keys ?? {};
    requireDeclaredMembers(body, this.#composedSections);
    requireClientBoundKeyShape(suppliedKeys);
    requireComposedKeyShape(body, this.#composedSections, (kind) => this.#widthOf(kind));
    // The section being written fixes the kind the profile binds into the key entry.
    /** @param {string} value @param {string} keyKind */
    const wrap = async (value, keyKind) => sealer.wrap(keyEntryBytes(value), keyKind);
    const keys = await mapDeliveredKeys(suppliedKeys, wrap);
    const composed = await mapComposedSections(body, this.#composedSections, wrap);
    return {
      ...composed,
      keys,
      transport: {
        ...sealer.transport,
        method: /** @type {any} */ (this.#profile).METHOD,
      },
    };
  }
}

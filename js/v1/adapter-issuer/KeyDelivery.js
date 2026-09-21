// @ts-check

// How the demo issuer carries opened keys on its response. Direct delivery
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
import { mapDeliveredKeys } from "../core-shared--client-issuer/responseKeys.js";
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
 * @param {'contentKey'|'periodKey'} keyKind
 */
function requireBase64urlLeaves(node, depth, expectedBytes, keyKind) {
  if (depth === 0) {
    if (typeof node !== "string") {
      throw dcaError("bad_config", "client-bound delivery needs string key leaves");
    }
    keyLeafBytes(node, expectedBytes, keyKind);
    return;
  }
  if (node === null || typeof node !== "object") {
    throw dcaError("bad_config", "client-bound delivery needs correctly nested key sections");
  }
  for (const name of Object.keys(node)) {
    requireBase64urlLeaves(node[name], depth - 1, expectedBytes, keyKind);
  }
}

/**
 * One delivered leaf as bytes. Section 2.2 defines the spelling rule. This
 * adapter applies it both when it validates the shape and when it wraps a
 * value, so it never re-wraps a leaf the response could not have carried
 * while it marks the body as wrapped.
 *
 * @param {string} value
 * @param {number|null} [expectedBytes]
 * @param {'contentKey'|'periodKey'|'key'} [keyKind]
 * @returns {Uint8Array}
 */
function keyLeafBytes(value, expectedBytes = null, keyKind = "key") {
  const bytes = binaryStringBytes(value);
  if (bytes === null) {
    throw dcaError("bad_config", "client-bound delivery needs canonical base64url key leaves");
  }
  if (expectedBytes !== null && bytes.length !== expectedBytes) {
    throw dcaError(
      "bad_config",
      `client-bound delivery needs ${expectedBytes}-byte ${keyKind} leaves`,
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
  if (own(keys, "periodChainKeys") !== undefined) {
    throw dcaError(
      "unsupported_option",
      "client-bound period-chain delivery needs an explicit byte-free expansion profile",
    );
  }
  const contentKeys = own(keys, "contentKeys");
  if (contentKeys !== undefined) requireBase64urlLeaves(contentKeys, 1, 16, "contentKey");

  const periodKeys = own(keys, "periodKeys");
  if (periodKeys !== undefined) {
    requireBase64urlLeaves(periodKeys, 2, 16, "periodKey");
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
   * @type {WeakMap<RequestView, { transport: any, wrap: (keyBytes: Uint8Array) => Promise<any> }>}
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

  /**
   * @param {object} config
   * @param {{ bytes: (n: number) => Uint8Array }} [config.random] - the
   *   client-bound wrapping nonces, one per delivered key
   * @param {{ METHOD: string, seal: (clientPublicKey: any, options: any) => Promise<any> }} [config.profile] -
   *   the client-bound method selected by the issuer application
   */
  constructor({ random, profile, ...unsupported } = /** @type {any} */ ({})) {
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
    const sealer = await this.#profile.seal(clientPublicKey, { random: this.#random });
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
    requireClientBoundKeyShape(suppliedKeys);
    /** @param {string} value */
    const wrap = async (value) => sealer.wrap(keyLeafBytes(value));
    const keys = await mapDeliveredKeys(suppliedKeys, wrap);
    return {
      ...body,
      keys,
      transport: {
        ...sealer.transport,
        mode: "client-bound",
        method: /** @type {any} */ (this.#profile).METHOD,
      },
    };
  }
}

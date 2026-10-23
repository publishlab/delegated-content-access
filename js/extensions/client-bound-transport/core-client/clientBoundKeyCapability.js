// @ts-check
//
// The client-bound key capability's demo reference implementation, built from
// one logical client's raw keypair. `clientBoundKeyCapability` is the injected seam.
//
// The capability has two duties, and this is where the client's private half
// lives. The public half is the client's request material, handed to
// `DcaRequestBuilder` as the selected profile's public JWK offer. Its input is
// already exported, so projection and request building stay synchronous. The private half opens
// delivered client-bound keys: it agrees the transport with the issuer's
// ephemeral public key and unwraps each delivered value to a non-extractable
// handle. The private key never leaves this closure as bytes; nothing outside
// can read it, only the opener uses it.
//
// A direct-delivery response needs no capability at all: the resolver asks for
// an opener only when a wrapped value actually arrived. Persisting the
// capability is a separate adapter or host seam and not modelled here.

import { dcaError } from "../../../core-shared/errors.js";
import { NO_COMPOSED_KINDS, kindDescriptor } from "../core-shared--client-issuer/keyKind.js";

/**
 * One client's transport pair, in the shape a browser holds it.
 *
 * The private half is a handle whose bytes JavaScript cannot read, which is the
 * whole claim of the mode. The public half is the exported JWK rather than a
 * `CryptoKey`, because it goes on the wire and building a request is
 * synchronous: exporting inside the builder would make the client's one build
 * call return a promise instead of a payload.
 *
 * @typedef {object} ClientKeyPair
 * @property {CryptoKey} privateKey
 * @property {JsonWebKey} publicKey - already exported, once, when the pair was made
 */

/**
 * @param {any} keyPair
 * @returns {ClientKeyPair}
 */
function checkKeyPair(keyPair) {
  const shape = "clientKeys are a private key handle and the public half as an exported JWK";

  if (keyPair === null || typeof keyPair !== "object") throw dcaError("bad_config", shape);
  if (/** @type {any} */ (keyPair).privateKey?.type !== "private") {
    throw dcaError("bad_config", `${shape}; this privateKey is not a private key`);
  }
  const privateKey = /** @type {CryptoKey} */ (/** @type {any} */ (keyPair).privateKey);
  if (privateKey.extractable !== false) {
    throw dcaError("bad_config", `${shape}; this privateKey must be non-extractable`);
  }

  const publicKey = /** @type {any} */ (keyPair).publicKey;
  if (publicKey?.type === "public") {
    throw dcaError(
      "bad_config",
      `${shape}; export it once when the pair is made - buildRequest cannot await one`,
    );
  }
  if (publicKey === null || typeof publicKey !== "object" || typeof publicKey.kty !== "string") {
    throw dcaError("bad_config", `${shape}; this publicKey is not a JWK`);
  }
  for (const member of ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]) {
    if (publicKey[member] !== undefined) {
      throw dcaError(
        "bad_config",
        `${shape}; this publicKey carries private JWK material (${member})`,
      );
    }
  }

  return { privateKey, publicKey };
}

/**
 * Clone one JSON-compatible value without invoking accessors. JWK extensions
 * are profile-owned, so generic client capability code must preserve nested
 * public metadata rather than impose a flat, method-specific schema.
 * @param {any} value
 * @param {Set<object>} ancestors
 * @returns {any}
 */
function snapshotJsonValue(value, ancestors) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object") {
    throw dcaError("bad_config", "a client public offer contains only JSON-compatible values");
  }
  if (ancestors.has(value)) {
    throw dcaError("bad_config", "a client public offer contains no cyclic values");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const copy = [];
      const keys = Reflect.ownKeys(value);
      for (const key of keys) {
        if (key === "length") continue;
        if (
          typeof key !== "string" ||
          !/^(0|[1-9][0-9]*)$/.test(key) ||
          Number(key) >= value.length
        ) {
          throw dcaError("bad_config", "a client public offer array has only indexed own members");
        }
      }
      for (let index = 0; index < value.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor?.enumerable || !("value" in descriptor)) {
          throw dcaError("bad_config", "a client public offer array is dense own data");
        }
        copy.push(snapshotJsonValue(descriptor.value, ancestors));
      }
      return copy;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw dcaError("bad_config", "a client public offer contains only plain JSON records");
    }
    const copy = {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        throw dcaError("bad_config", "a client public offer record has string own members");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) {
        throw dcaError(
          "bad_config",
          "a client public offer record has enumerable own data members",
        );
      }
      Object.defineProperty(copy, key, {
        value: snapshotJsonValue(descriptor.value, ancestors),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return copy;
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Build the client-bound key capability from one client's keypair. The returned
 * object exposes the public request material and opens delivered client-bound
 * keys; the private key is captured in this closure and never handed back.
 *
 * The method is the explicitly selected profile's. The capability holds the
 * client's private half and hands it to the profile's
 * `open`; opening the delivered values is the profile's own work.
 *
 * A selected extension may compose further key kinds, settled by
 * `settleKindDescriptors` and handed here as `options.composedKinds`. The
 * capability hands that set to the profile's opener for every response, and
 * when any composed kind opens to raw bytes it asks the profile's
 * `assertCanOpenRawKeys` at setup: an RSA-OAEP key without decrypt usage is
 * refused here, not on the first answer.
 *
 * @param {ClientKeyPair} keyPair
 * @param {{ METHOD: string, validateClientKeyPair: (keyPair: ClientKeyPair) => void, publicKeyForOffer: (publicKey: JsonWebKey) => JsonWebKey, assertCanOpenChainKeys?: (keyPair: ClientKeyPair) => void, assertCanOpenRawKeys?: (keyPair: ClientKeyPair) => void, open: (transport: unknown, privateKey: CryptoKey, composedKinds?: any) => Promise<{ open: (value: any, usages: KeyUsage[], keyKind: string) => Promise<CryptoKey|Uint8Array|null> }> }} profile
 * @param {{ composedKinds?: Readonly<Record<string, Readonly<import("../core-shared--client-issuer/keyKind.js").KindDescriptor>>> }} [options]
 * @returns {{ publicKey: JsonWebKey, assertCanOpenChainKeys: () => void, openDeliveredKeys: (transport: unknown) => Promise<{ open: (value: any, usages: KeyUsage[], keyKind: string) => Promise<CryptoKey|Uint8Array|null> }> }}
 */
export function clientBoundKeyCapability(keyPair, profile, options = {}) {
  if (
    typeof profile?.METHOD !== "string" ||
    typeof profile?.validateClientKeyPair !== "function" ||
    typeof profile?.publicKeyForOffer !== "function" ||
    typeof profile?.open !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "a client-bound profile has a string METHOD, synchronous validateClientKeyPair({privateKey, publicKey}) and publicKeyForOffer(publicKey), and open(transport, privateKey) function",
    );
  }
  const checkedKeyPair = checkKeyPair(keyPair);
  const { privateKey, publicKey } = checkedKeyPair;
  const validation = profile.validateClientKeyPair(checkedKeyPair);
  if (
    validation !== undefined &&
    validation !== null &&
    typeof (/** @type {any} */ (validation).then) === "function"
  ) {
    throw dcaError(
      "bad_config",
      "a client-bound profile validateClientKeyPair function must validate synchronously",
    );
  }

  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw dcaError("bad_config", "client-bound capability options are an object");
  }
  for (const name of Object.keys(options)) {
    if (name !== "composedKinds") {
      throw dcaError("unsupported_option", `clientBoundKeyCapability has no ${name} option`);
    }
  }
  const composedKinds = options.composedKinds ?? NO_COMPOSED_KINDS;
  // Refuses a set trusted composition did not settle.
  kindDescriptor("contentKey", composedKinds);
  if (Object.values(composedKinds).some(({ open }) => open === "raw")) {
    if (typeof profile.assertCanOpenRawKeys !== "function") {
      throw dcaError(
        "bad_config",
        "this client-bound profile cannot assert raw derivation-key opening support",
      );
    }
    const result = profile.assertCanOpenRawKeys(checkedKeyPair);
    if (
      result !== undefined &&
      result !== null &&
      typeof (/** @type {any} */ (result).then) === "function"
    ) {
      throw dcaError(
        "bad_config",
        "a client-bound profile raw-key validator must validate synchronously",
      );
    }
  }

  const offered = profile.publicKeyForOffer(publicKey);
  if (
    offered === null ||
    typeof offered !== "object" ||
    Array.isArray(offered) ||
    (Object.getPrototypeOf(offered) !== Object.prototype && Object.getPrototypeOf(offered) !== null)
  ) {
    throw dcaError("bad_config", "publicKeyForOffer must return a public JWK record synchronously");
  }
  const offer = /** @type {Record<string, any>} */ (snapshotJsonValue(offered, new Set()));
  for (const member of Reflect.ownKeys(offer)) {
    if (typeof member !== "string") {
      throw dcaError("bad_config", "a client public offer has string own JWK members");
    }
    if (["d", "k", "p", "q", "dp", "dq", "qi", "oth"].includes(member)) {
      throw dcaError(
        "bad_config",
        `a client public offer carries private JWK material (${member})`,
      );
    }
  }
  if (typeof offer.kty !== "string") {
    throw dcaError("bad_config", "publicKeyForOffer must return a public JWK with string kty");
  }

  return {
    // Duty (a): the client's public request material, for DcaRequestBuilder.
    get publicKey() {
      return offer;
    },

    /**
     * Assert synchronously that this keypair can open delivered chain keys.
     * Period-key-only use does not call this duty. The selected transport method
     * owns the extra requirement, which may differ from its period-key usage.
     * @returns {void}
     */
    assertCanOpenChainKeys() {
      if (typeof profile.assertCanOpenChainKeys !== "function") {
        throw dcaError(
          "bad_config",
          "this client-bound profile cannot assert chain-key opening support",
        );
      }
      const result = profile.assertCanOpenChainKeys(checkedKeyPair);
      if (
        result !== undefined &&
        result !== null &&
        typeof (/** @type {any} */ (result).then) === "function"
      ) {
        throw dcaError(
          "bad_config",
          "a client-bound profile chain-key validator must validate synchronously",
        );
      }
    },

    /**
     * Duty (b): open the client-bound keys one response delivered. The
     * response names its method, and this client opens one: an answer tagged
     * another method throws `bad_response` before the private half is reached
     * for, which refuses a body wrapped by a method this client does not
     * hold. Past that, the whole transport goes to the profile, which
     * agrees the key against the private half. The agreement happens inside the
     * profile, and the private key stays in this closure.
     *
     * @param {unknown} transport - the transport member the response carried
     */
    openDeliveredKeys(transport) {
      const method =
        transport === null || typeof transport !== "object"
          ? undefined
          : /** @type {any} */ (transport).method;
      if (method !== profile.METHOD) {
        throw dcaError(
          "bad_response",
          `this client opens client-bound ${profile.METHOD} answers; this one names ${JSON.stringify(method)} method`,
        );
      }
      return composedKinds === NO_COMPOSED_KINDS
        ? profile.open(transport, privateKey)
        : profile.open(transport, privateKey, composedKinds);
    },
  };
}

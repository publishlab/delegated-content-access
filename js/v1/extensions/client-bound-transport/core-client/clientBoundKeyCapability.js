// @ts-check
//
// The client-bound key capability's demo reference implementation, built from
// one logical client's raw keypair. `clientBoundKeyCapability` is the
// provisional descriptive name for this injected seam.
//
// The capability has two duties, and this is where the client's private half
// lives. The public half is the client's request material, handed to
// `DcaRequestBuilder` as the exported JWK. It is exported already, because
// building a request stays synchronous. The private half opens
// delivered client-bound keys: it agrees the transport with the issuer's
// ephemeral public key and unwraps each delivered value to a non-extractable
// handle. The private key never leaves this closure as bytes; nothing outside
// can read it, only the opener uses it.
//
// A direct-delivery response needs no capability at all: the resolver asks for
// an opener only when a wrapped value actually arrived. Persisting the
// capability is a separate adapter or host seam and not modelled here.

import { dcaError } from "../../../core-shared/errors.js";

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
 * Build the client-bound key capability from one client's keypair. The returned
 * object exposes the public request material and opens delivered client-bound
 * keys; the private key is captured in this closure and never handed back.
 *
 * The method is the explicitly selected profile's. The capability holds the
 * client's private half and hands it to the profile's
 * `open`; opening the delivered values is the profile's own work.
 *
 * @param {ClientKeyPair} keyPair
 * @param {{ METHOD: string, validateClientKeyPair: (keyPair: ClientKeyPair) => void, open: (transport: unknown, privateKey: CryptoKey) => Promise<{ open: (value: any, usages: KeyUsage[]) => Promise<CryptoKey|null> }> }} profile
 * @returns {{ publicKey: JsonWebKey, openDeliveredKeys: (transport: unknown) => Promise<{ open: (value: any, usages: KeyUsage[]) => Promise<CryptoKey|null> }> }}
 */
export function clientBoundKeyCapability(keyPair, profile) {
  if (
    typeof profile?.METHOD !== "string" ||
    typeof profile?.validateClientKeyPair !== "function" ||
    typeof profile?.open !== "function"
  ) {
    throw dcaError(
      "bad_config",
      "a client-bound profile has a string METHOD, synchronous validateClientKeyPair({privateKey, publicKey}), and open(transport, privateKey) function",
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

  return {
    // Duty (a): the client's public request material, for DcaRequestBuilder.
    get publicKey() {
      return publicKey;
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
      const mode =
        transport === null || typeof transport !== "object"
          ? undefined
          : /** @type {any} */ (transport).mode;
      const method =
        transport === null || typeof transport !== "object"
          ? undefined
          : /** @type {any} */ (transport).method;
      if (mode !== "client-bound" || method !== profile.METHOD) {
        throw dcaError(
          "bad_response",
          `this client opens client-bound ${profile.METHOD} answers; this one names ${JSON.stringify(mode)} mode and ${JSON.stringify(method)} method`,
        );
      }
      return profile.open(transport, privateKey);
    },
  };
}

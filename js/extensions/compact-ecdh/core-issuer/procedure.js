// @ts-check
//
// The issuer side of the compact-ECDH extension: the envelope procedure the
// base engine runs when a request selects `envelope: "compact-ecdh"` and the
// key entry lists it in `envelopes`. The engine has already chosen the key,
// answered a retirement and built the BIND octets; this only opens.

import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { dcaError } from "../../../core-shared/errors.js";
import { open as openEnvelope } from "../core-shared--publisher-issuer/envelope.js";
import { COMPACT_ECDH } from "../core-shared--publisher-issuer/selector.js";

/** The engine's sealed coordinates carry 16-byte keys (Section 4.2). */
const SEALED_KEY_BYTES = 16;

/**
 * @param {string} sealed - the canonical binary string the request carried
 * @param {{ privateKey: CryptoKey, publicKey?: CryptoKey }} key
 * @param {Uint8Array} aad - the BIND octets
 * @returns {Promise<Uint8Array>}
 */
export async function openCompactEcdh(sealed, key, aad) {
  // The HPKE KEM context includes the issuer's public key, and WebCrypto
  // cannot derive it from a non-extractable private key. An entry without it
  // is this issuer's configuration fault, not the request's.
  if (!(key?.publicKey instanceof CryptoKey)) {
    throw dcaError("bad_config", "a key entry permitting compact-ecdh carries its publicKey");
  }
  const bytes = binaryStringBytes(sealed);
  if (bytes === null) throw dcaError("unseal_failed", "the sealed value does not open");
  return openEnvelope(
    bytes,
    { privateKey: key.privateKey, publicKey: key.publicKey },
    aad,
    SEALED_KEY_BYTES,
  );
}

/**
 * The issuer contribution for `createIssuerCore`. A key entry opts in with
 * its `publicKey` and `compact-ecdh` in its `envelopes` allowlist, beside
 * `ecdh-p256` when it still opens ordinary deliveries. The procedure declares
 * ECDH P-256 keys, so the engine refuses an entry of another algorithm that
 * permits it where it reads the entry.
 */
export function compactEcdhIssuerContribution() {
  return Object.freeze({
    name: "compact-ecdh",
    envelopeProcedures: Object.freeze({
      [COMPACT_ECDH]: Object.freeze({ open: openCompactEcdh, keyAlgorithms: ["ecdh-p256"] }),
    }),
  });
}

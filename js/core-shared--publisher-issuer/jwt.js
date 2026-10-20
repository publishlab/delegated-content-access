// @ts-check
//
// This module supports ES256 only. DCA uses a JWT as a signed JSON envelope
// rather than as a credential: no standard claims are required and none are
// read. A token that arrives carrying `iat` or `exp` is not treated as expired,
// because the format says to ignore them.
//
// The algorithm is pinned in both directions. `sign` refuses to emit anything
// but ES256, and `verify` refuses a header that names anything else before it
// reaches for a key, which stops the alg-substitution family. `typ` is pinned
// the same way: the format fixes one value and both sides hold that value.
// `alg` and `typ` are checked together in a fixed order, so one refusal covers
// the pair.
//
// WebCrypto's ECDSA signature is already the JWS one: r and s concatenated,
// 32 bytes each for P-256, no DER wrapper. There is nothing to re-encode.
//
// `proofHash` deliberately departs from the usual approach: it hashes the
// base64url string as it appears in JSON and does not decode it to bytes.
// Decoding first would produce a digest that is stable and plausible but does
// not match any other implementation, so the input here is a string and never
// bytes.

import { base64urlEncode, base64urlDecode, utf8Encode } from "../core-shared/codec.js";
import { dcaError } from "../core-shared/errors.js";
import { decodeCompactJwt } from "../core-shared/compactJwt.js";
import { own } from "../core-shared/wire.js";
import { es256Sign, es256Verify, sha256Digest } from "../core-shared/cryptoProvider.js";

/** The one algorithm identifier admitted in the JWT header. */
const ALG = "ES256";

/** The one type the format admits. */
const TYP = "JWT";

/**
 * The header a publisher emits. `kid` names which signing key verifies it, so
 * a publisher can rotate without invalidating the markup an edge cache still
 * holds.
 *
 * @typedef {{ alg?: string, typ?: string, kid?: string }} JwtHeader
 */

/**
 * @param {object} value
 * @returns {string}
 */
function encodeSegment(value) {
  return base64urlEncode(utf8Encode(JSON.stringify(value)));
}

/**
 * Reads the header without verifying anything. Code that selects a key by
 * `kid` has to read it this way, because verification needs the selected key.
 *
 * @param {unknown} token
 * @returns {JwtHeader}
 */
export function decodeHeader(token) {
  return decodeCompactJwt(token).header;
}

/**
 * Reads the payload without verification. Use it to locate the key needed to
 * verify the token and for client-side coordinates that fail closed when the
 * issuer later refuses the token. Never base an access decision on it.
 *
 * @param {unknown} token
 * @returns {any}
 */
export function decodePayload(token) {
  return decodeCompactJwt(token).payload;
}

/**
 * @param {object} payload
 * @param {CryptoKey} privateKey - ECDSA P-256
 * @param {JwtHeader} [header] - `kid` belongs here; `alg` and `typ` are fixed
 * @returns {Promise<string>}
 */
export async function sign(payload, privateKey, header = {}) {
  if (header.alg !== undefined && header.alg !== ALG) {
    throw dcaError("unsupported_algorithm", `jwt signs ${ALG} only, not "${header.alg}"`);
  }
  if (header.typ !== undefined && header.typ !== TYP) {
    throw dcaError("unsupported_option", `jwt has no typ "${header.typ}"`);
  }
  if (!privateKey) throw dcaError("bad_config", "jwt.sign needs a private key");

  /** @type {JwtHeader} */
  const head = { alg: ALG, typ: TYP };
  if (header.kid !== undefined) head.kid = header.kid;

  const signing = `${encodeSegment(head)}.${encodeSegment(payload)}`;
  const signature = await es256Sign(privateKey, utf8Encode(signing));

  return `${signing}.${base64urlEncode(signature)}`;
}

/**
 * Checks the two header members the format fixes, in the order the protocol
 * fixes them: the algorithm, then the type. Both are string comparisons
 * against a constant and both run before a key is consulted at all, so a
 * header that says `none`, `HS256`, `DCA` or any other value is refused
 * without a verification-key lookup. Both checks throw the same error code,
 * because both belong to one rule.
 *
 * @param {JwtHeader} header
 */
function requireFixedHeader(header) {
  if (header.alg !== ALG) {
    throw dcaError("bad_alg", `DCA pins ${ALG}; this token says "${header.alg}"`);
  }
  if (header.typ !== TYP) {
    throw dcaError("bad_alg", `DCA pins typ ${TYP}; this token says "${header.typ}"`);
  }
}

/**
 * Checks the unverified protected header and returns the `kid` that a caller
 * uses to select a publisher registration. The function checks the fixed
 * header pair first and then a non-empty `kid`, so a caller does not look up a
 * registration for a token this issuer refuses anyway.
 *
 * The returned `kid` is still untrusted. It names the key to verify under, and
 * signature verification decides whether that key signed these claims.
 *
 * @param {unknown} token
 * @returns {string} the admitted `kid`
 */
export function admitHeader(token) {
  const { header } = decodeCompactJwt(token);
  requireFixedHeader(header);

  const kid = own(header, "kid");
  if (typeof kid !== "string" || kid.length === 0) {
    throw dcaError("bad_jwt", "the resourceJWT kid is required");
  }
  return kid;
}

/**
 * The verification key is host configuration, so a key of the wrong kind is the
 * issuer's fault, not a bad signature the request carried. WebCrypto throws for
 * such a key inside `verify`, which the signature catch below would otherwise
 * report as `bad_signature`. This checks the reference's WebCrypto shape;
 * another runtime checks its own key type.
 *
 * @param {unknown} publicKey
 */
function requireVerificationKey(publicKey) {
  const key = /** @type {any} */ (publicKey);
  if (
    key === null ||
    typeof key !== "object" ||
    key.type !== "public" ||
    key.algorithm?.name !== "ECDSA" ||
    key.algorithm?.namedCurve !== "P-256" ||
    !Array.isArray(key.usages) ||
    !key.usages.includes("verify")
  ) {
    throw dcaError(
      "bad_config",
      "jwt.verify needs a public key of kind ES256: ECDSA P-256 with verify usage",
    );
  }
}

/**
 * The verified payload, or a typed error. The fixed header comes first, so a
 * token naming another algorithm or another type is refused before a key is
 * consulted at all.
 *
 * @param {unknown} token
 * @param {CryptoKey} publicKey - ECDSA P-256
 * @returns {Promise<any>} the payload
 */
export async function verify(token, publicKey) {
  const {
    header,
    payload,
    parts: [head, body, signature],
  } = decodeCompactJwt(token);
  requireFixedHeader(header);
  requireVerificationKey(publicKey);

  let ok;
  try {
    ok = await es256Verify(publicKey, base64urlDecode(signature), utf8Encode(`${head}.${body}`));
  } catch {
    // A signature segment of the wrong length counts as a bad signature and
    // gets the same error.
    ok = false;
  }
  if (!ok) throw dcaError("bad_signature", "the token was not signed by this key");

  return payload;
}

/**
 * `base64url(SHA-256(UTF-8 bytes of the string))`, 43 characters, no padding.
 *
 * The argument is the sealed blob exactly as JSON carries it. This function
 * signature is shaped to prevent decoding it and hashing the bytes:
 * `proofHash` takes a string, so there is nothing to decode.
 *
 * @param {string} base64urlString
 * @returns {Promise<string>}
 */
export async function proofHash(base64urlString) {
  if (typeof base64urlString !== "string") {
    throw dcaError("bad_proof", "a proof hash covers the wire string, and this is not one");
  }
  return base64urlEncode(await sha256Digest(utf8Encode(base64urlString)));
}

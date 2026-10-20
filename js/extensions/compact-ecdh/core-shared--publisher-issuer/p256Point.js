// @ts-check
//
// SEC 1 point compression for P-256 (SEC 1 v2.0 Sections 2.3.3 and 2.3.4).
// The compact carrier of docs/spec-profile--compact-ecdh.md Section 4.3 sends
// `prefix || X` and the issuer recovers `04 || X || Y` before HPKE sees it.
//
// WebCrypto has no portable compressed import, so the issuer recovers Y here
// with BigInt field arithmetic. P-256's prime is 3 mod 4, so a square root of
// `a` is `a^((p+1)/4) mod p` whenever one exists; squaring the candidate
// tells whether it does. The arithmetic runs on public values only (the
// sender's ephemeral public key), so it need not be constant-time.
//
// Decompression answers `null` for any encoding it refuses: a wrong length, a
// prefix other than 02 or 03, x outside the field, and an x with no point on
// the curve. The caller turns `null` into its own failure. A recovered point
// still goes through WebCrypto's own import, which is the final validation.

import { dcaError } from "../../../core-shared/errors.js";

/** The P-256 field prime, SEC 2 v2.0 Section 2.4.2. */
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

/** The curve coefficient b; a is -3. */
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/** `(p + 1) / 4`, the square-root exponent for p ≡ 3 mod 4. */
const SQRT_EXPONENT = (P + 1n) >> 2n;

/** One coordinate, unsigned big-endian. */
const COORDINATE_BYTES = 32;

/** `04 || X || Y`. */
export const UNCOMPRESSED_BYTES = 1 + 2 * COORDINATE_BYTES;

/** `02 || X` or `03 || X`. */
export const COMPRESSED_BYTES = 1 + COORDINATE_BYTES;

/**
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function toBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/**
 * Fixed-width big-endian, so a coordinate with leading zero octets keeps them.
 *
 * @param {bigint} value
 * @param {Uint8Array} out
 * @param {number} offset
 */
function writeCoordinate(value, out, offset) {
  let rest = value;
  for (let i = COORDINATE_BYTES - 1; i >= 0; i--) {
    out[offset + i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
}

/**
 * @param {bigint} base
 * @param {bigint} exponent
 * @returns {bigint}
 */
function powMod(base, exponent) {
  let result = 1n;
  let b = base % P;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

/**
 * `04 || X || Y` to `prefix || X`, where the prefix is 02 for even Y and 03 for
 * odd Y.
 *
 * @param {Uint8Array} point - a 65-octet uncompressed P-256 point
 * @returns {Uint8Array} 33 octets
 */
export function compressP256(point) {
  if (!(point instanceof Uint8Array) || point.length !== UNCOMPRESSED_BYTES || point[0] !== 0x04) {
    throw dcaError("bad_key", "compression takes a 65-octet uncompressed P-256 point");
  }
  const out = new Uint8Array(COMPRESSED_BYTES);
  out[0] = 0x02 | (point[UNCOMPRESSED_BYTES - 1] & 1);
  out.set(point.subarray(1, 1 + COORDINATE_BYTES), 1);
  return out;
}

/**
 * `prefix || X` to the unique `04 || X || Y` whose Y has the prefix's parity.
 *
 * @param {Uint8Array} bytes - 33 octets
 * @returns {Uint8Array|null} 65 octets, or `null` for an encoding SEC 1 refuses
 */
export function decompressP256(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== COMPRESSED_BYTES) return null;
  const prefix = bytes[0];
  if (prefix !== 0x02 && prefix !== 0x03) return null;

  const x = toBigInt(bytes.subarray(1));
  if (x >= P) return null;

  // y² = x³ - 3x + b
  const rhs = (((x * x) % P) * x - 3n * x + B + 3n * P) % P;
  let y = powMod(rhs, SQRT_EXPONENT);
  if ((y * y) % P !== rhs) return null;

  if (Number(y & 1n) !== (prefix & 1)) {
    // P-256 has no point with y = 0, so p - y is the other root and is in range.
    if (y === 0n) return null;
    y = P - y;
  }

  const out = new Uint8Array(UNCOMPRESSED_BYTES);
  out[0] = 0x04;
  out.set(bytes.subarray(1), 1);
  writeCoordinate(y, out, 1 + COORDINATE_BYTES);
  return out;
}

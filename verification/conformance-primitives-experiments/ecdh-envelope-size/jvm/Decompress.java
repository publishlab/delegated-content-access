// The compressed-point decoder for the JVM lane. SunEC reads the uncompressed
// P-256 encoding only, so this recovers `04 || X || Y` from the SEC 1 33-octet
// form and hands the result back to the caller, which imports it through the
// same KeyFactory that refused the compressed bytes. The decoder does the field
// arithmetic and nothing else: point validation stays with the library.
//
// It follows the decoding sketch in docs/spec-proposal--compact-ecdh-envelope.md
// section 4 line for line. p is 3 mod 4 on P-256, so the square root is one
// modular exponentiation, and the result is squared again before it is trusted.
// Every refusal below throws an exception, which tells the caller that the
// point never reached the library.

import java.math.BigInteger;

final class Decompress {
    // The P-256 field prime and the curve coefficient b, from SEC 2 section 2.4.2.
    private static final BigInteger P = new BigInteger(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger B = new BigInteger(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    // (p + 1) / 4, the square-root exponent p == 3 mod 4 allows.
    private static final BigInteger SQRT_EXPONENT = P.add(BigInteger.ONE).shiftRight(2);

    private static final int COORDINATE_BYTES = 32;

    private Decompress() {
    }

    /** The unsigned big-endian integer a fixed-width octet string stands for, SEC 1 OS2IP. */
    private static BigInteger os2ip(byte[] octets, int from, int length) {
        byte[] slice = new byte[length];
        System.arraycopy(octets, from, slice, 0, length);
        return new BigInteger(1, slice);
    }

    /** A non-negative integer as a fixed-width unsigned big-endian octet string, SEC 1 I2OSP. */
    private static byte[] i2osp(BigInteger value, int length) {
        byte[] out = new byte[length];
        byte[] raw = value.toByteArray();
        int take = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - take, out, length - take, take);
        return out;
    }

    private static int parity(BigInteger value) {
        return value.testBit(0) ? 1 : 0;
    }

    /**
     * The 65-octet uncompressed encoding of the point a SEC 1 compressed P-256
     * encoding names.
     *
     * @throws IllegalArgumentException when the encoding is not a compressed
     *     P-256 point: a length other than 33, a prefix other than 0x02 or 0x03,
     *     an x-coordinate at or above p, or a curve equation with no square root.
     */
    static byte[] uncompressed(byte[] encoded) {
        if (encoded.length != 33) {
            throw new IllegalArgumentException("compressed P-256 point is 33 octets, got " + encoded.length);
        }
        int prefix = encoded[0] & 0xff;
        if (prefix != 0x02 && prefix != 0x03) {
            throw new IllegalArgumentException(
                "compressed P-256 prefix is 02 or 03, got " + String.format("%02x", prefix));
        }

        BigInteger x = os2ip(encoded, 1, COORDINATE_BYTES);
        if (x.compareTo(P) >= 0) {
            throw new IllegalArgumentException("x-coordinate is not below the P-256 field prime");
        }

        BigInteger rhs = x.modPow(THREE, P).subtract(x.multiply(THREE)).add(B).mod(P);
        BigInteger y = rhs.modPow(SQRT_EXPONENT, P);
        if (!y.multiply(y).mod(P).equals(rhs)) {
            throw new IllegalArgumentException("the curve equation has no square root at this x-coordinate");
        }

        if (parity(y) != (prefix & 1)) {
            y = P.subtract(y);
        }

        if (y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("y-coordinate is not below the P-256 field prime");
        }
        if (parity(y) != (prefix & 1)) {
            throw new IllegalArgumentException("y-coordinate parity does not match the carried prefix");
        }

        byte[] out = new byte[1 + COORDINATE_BYTES * 2];
        out[0] = 0x04;
        System.arraycopy(i2osp(x, COORDINATE_BYTES), 0, out, 1, COORDINATE_BYTES);
        System.arraycopy(i2osp(y, COORDINATE_BYTES), 0, out, 1 + COORDINATE_BYTES, COORDINATE_BYTES);
        return out;
    }
}

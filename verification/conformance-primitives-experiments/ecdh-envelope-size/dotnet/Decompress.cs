// The compressed-point decoder for the .NET lane. `ECDiffieHellman` reads the
// uncompressed form only, through either entry, so the 33-byte SEC 1 encoding
// is recovered here as `04 || X || Y` and handed to the library's own import,
// which still validates the point. This implements SEC 1 v2.0 section 2.3.4, and it
// follows the decoding sketch in ../README.md#decoding-sketch line for line.
//
// Every refusal is thrown as a CryptographicException, the same exception type the
// library throws when it refuses, so a caller sees one kind of failure whether the
// decoder or the library refused.

using System.Numerics;
using System.Security.Cryptography;

internal static class Decompress
{
    private const int CoordinateBytes = 32;

    // P-256: the field prime, and the b coefficient of y^2 = x^3 - 3x + b.
    // BigInteger reads bytes little-endian and signed by default, so every
    // conversion here names unsigned big-endian explicitly.
    private static readonly BigInteger P = Number(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    private static readonly BigInteger B = Number(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    private static BigInteger Number(string hex) =>
        new(Convert.FromHexString(hex), isUnsigned: true, isBigEndian: true);

    private static byte[] Bytes(BigInteger value)
    {
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == CoordinateBytes)
        {
            return raw;
        }
        var padded = new byte[CoordinateBytes];
        raw.CopyTo(padded, CoordinateBytes - raw.Length);
        return padded;
    }

    private static void Require(bool held, string refusal)
    {
        if (!held)
        {
            throw new CryptographicException(refusal);
        }
    }

    /// <summary>
    /// The 65-byte uncompressed encoding of a 33-byte SEC 1 compressed P-256
    /// point. It throws when the encoding is malformed, the x-coordinate is out
    /// of range, or the curve equation has no square root at that x.
    /// </summary>
    internal static byte[] Uncompressed(byte[] encoded)
    {
        Require(encoded.Length == 33, "a compressed P-256 point is 33 bytes");
        Require(encoded[0] == 0x02 || encoded[0] == 0x03, "a compressed P-256 point starts 02 or 03");

        var x = new BigInteger(encoded.AsSpan(1), isUnsigned: true, isBigEndian: true);
        Require(x < P, "the x-coordinate is outside the field");

        // p is 3 mod 4 on P-256, so the square root is one exponentiation and
        // the check below shows whether the value was a square at all.
        var rhs = (BigInteger.ModPow(x, 3, P) - 3 * x + B) % P;
        if (rhs.Sign < 0)
        {
            rhs += P;
        }
        var y = BigInteger.ModPow(rhs, (P + 1) / 4, P);
        Require(BigInteger.ModPow(y, 2, P) == rhs, "the curve equation has no square root at this x-coordinate");

        var wantOdd = (encoded[0] & 1) == 1;
        if (y.IsEven == wantOdd)
        {
            y = P - y;
        }
        Require(y < P, "the y-coordinate is outside the field");
        Require(y.IsEven != wantOdd, "the y-coordinate does not carry the prefix parity");

        var point = new byte[65];
        point[0] = 0x04;
        Bytes(x).CopyTo(point, 1);
        Bytes(y).CopyTo(point, 1 + CoordinateBytes);
        return point;
    }
}

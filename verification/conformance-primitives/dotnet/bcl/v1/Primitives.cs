using System.Buffers.Text;
using System.Numerics;
using System.Security.Cryptography;

// The library calls the operation bridge (bridge/Bridge.cs) answers with, written
// over the base class library and nothing else. This file states what .NET, the
// environment, produces and reads for a handful of stock calls: base64url, HKDF-SHA-256,
// AES-GCM, ECDH over P-256 and RSA-OAEP. A C# shop reads it without loading any
// JavaScript, PHP, Go or Java.
//
// Two calls need a line of code where every other runtime needs none. AesGcm fills a
// ciphertext span and a tag span separately, so GcmSeal joins them as ciphertext then
// tag and GcmOpen splits the last 16 octets back off. ECDiffieHellman also offers
// DeriveKeyMaterial, which hashes the agreed point and hands back 32 plausible octets
// nobody else computes, so EcdhRaw calls DeriveRawSecretAgreement, which agrees with
// WebCrypto, Go, PHP and the JCA.

static class Primitives
{
    // ---- base64url, unpadded -------------------------------------------------

    /// Decodes a base64url field, or answers null when this runtime refuses it.
    ///
    /// Base64Url is the base class library's own decoder, called deliberately: this
    /// lane reports what .NET does rather than what a hand-rolled decoder could be
    /// made to do. It is stricter than the JVM and Go on non-canonical trailing bits
    /// and looser on padding, both of which the lane README records.
    public static byte[]? B64u(string? s)
    {
        if (s is null) return null;
        try
        {
            return Base64Url.DecodeFromChars(s.AsSpan());
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// A fixed-width 32-octet field element, left padded with zero octets.
    ///
    /// Refuses an over-wide input rather than trimming it. A scalar or coordinate
    /// wider than the field is not a value this curve carries, and dropping its
    /// leading octets turns corrupt key material into a key that imports and then
    /// disagrees with every other runtime. A short value is padded, because a
    /// recorded coordinate whose leading octet is zero is a real value.
    public static byte[]? Pad32(byte[]? b)
    {
        if (b is null) return null;
        if (b.Length > 32) return null;
        if (b.Length == 32) return b;
        byte[] outBytes = new byte[32];
        b.CopyTo(outBytes, 32 - b.Length);
        return outBytes;
    }

    // ---- P-256 keys ----------------------------------------------------------

    /// The 65-octet uncompressed point 0x04 || X || Y, or null when either
    /// coordinate is missing or too wide for the field.
    public static byte[]? PointFromJwk(JObj? jwk)
    {
        if (jwk.Str("kty") != "EC" || jwk.Str("crv") != "P-256") return null;
        byte[]? x = Pad32(B64u(jwk.StrOrNull("x")));
        byte[]? y = Pad32(B64u(jwk.StrOrNull("y")));
        if (x is null || y is null) return null;
        byte[] point = new byte[65];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 33);
        return point;
    }

    /// An ECDH private key from a recorded JWK.
    ///
    /// This runtime checks the private scalar against the public point at import, so
    /// a JWK carrying only `d` does not load here at all. Recorded key material meant
    /// for more than one lane therefore carries x and y beside d, and this answers
    /// null rather than inventing a point.
    public static ECDiffieHellman? EcdhPrivateFromJwk(JObj? jwk)
    {
        if (jwk.Str("kty") != "EC" || jwk.Str("crv") != "P-256") return null;
        byte[]? x = Pad32(B64u(jwk.StrOrNull("x")));
        byte[]? y = Pad32(B64u(jwk.StrOrNull("y")));
        byte[]? d = Pad32(B64u(jwk.StrOrNull("d")));
        if (x is null || y is null || d is null) return null;
        try
        {
            return ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
                D = d,
            });
        }
        catch (CryptographicException) { return null; }
    }

    /// A peer public key from the 65-octet uncompressed SEC 1 point.
    public static ECDiffieHellmanPublicKey? EcdhPublicFromPoint(byte[]? point)
    {
        if (point is null || point.Length != 65 || point[0] != 0x04) return null;
        try
        {
            return ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = point[1..33], Y = point[33..65] },
            }).PublicKey;
        }
        catch (CryptographicException) { return null; }
    }

    /// The raw agreed x-coordinate, at the full 32-octet field width.
    ///
    /// DeriveKeyMaterial hashes the agreed point before handing it back, so the
    /// obvious call answers 32 entirely plausible octets that are not the agreement.
    /// DeriveRawSecretAgreement, available on net8.0 and later, answers the raw
    /// x-coordinate, and Pad32 keeps a leading zero octet that a big-integer path
    /// would drop.
    public static byte[]? EcdhRaw(ECDiffieHellman? priv, ECDiffieHellmanPublicKey? peer)
    {
        if (priv is null || peer is null) return null;
        try { return Pad32(priv.DeriveRawSecretAgreement(peer)); }
        catch (CryptographicException) { return null; }
        catch (ArgumentException) { return null; }
    }

    // ---- HKDF-SHA-256 --------------------------------------------------------

    /// One HKDF-SHA-256 derivation (RFC 5869) over the caller's octets under an
    /// explicitly empty salt. The caller hands info over as octets, so a 0x00 or an
    /// octet above 0x7f arrives as the caller spelled it.
    public static byte[] HkdfEmptySalt(byte[] ikm, byte[] info, int length) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, [], info);

    // ---- AES-GCM -------------------------------------------------------------

    /// Ciphertext with the 16-octet tag appended, or null when the call refuses.
    ///
    /// The key's width picks the cipher: 16 octets run AES-128-GCM and 32 run
    /// AES-256-GCM, which is the AesGcm constructor's own rule. Additional data of
    /// zero octets is an empty span.
    public static byte[]? GcmSeal(byte[]? key, byte[]? nonce, byte[]? plaintext, byte[]? aad)
    {
        if (key is null || nonce is null || plaintext is null) return null;
        try
        {
            using var gcm = new AesGcm(key, tagSizeInBytes: 16);
            byte[] joined = new byte[plaintext.Length + 16];
            gcm.Encrypt(nonce, plaintext, joined.AsSpan(0, plaintext.Length), joined.AsSpan(plaintext.Length, 16), aad);
            return joined;
        }
        catch (CryptographicException) { return null; }
        catch (ArgumentException) { return null; }
    }

    /// Takes ciphertext || tag as one buffer and splits at length minus 16, the other
    /// half of the same decision. Null covers a tag that does not verify and a buffer
    /// too short to hold one.
    public static byte[]? GcmOpen(byte[]? key, byte[]? nonce, byte[]? ctAndTag, byte[]? aad)
    {
        if (key is null || nonce is null || ctAndTag is null) return null;
        if (ctAndTag.Length < 16) return null;
        try
        {
            using var gcm = new AesGcm(key, tagSizeInBytes: 16);
            byte[] plaintext = new byte[ctAndTag.Length - 16];
            gcm.Decrypt(nonce, ctAndTag.AsSpan(0, plaintext.Length), ctAndTag.AsSpan(plaintext.Length, 16), plaintext, aad);
            return plaintext;
        }
        catch (CryptographicException) { return null; }
        catch (ArgumentException) { return null; }
    }

    // ---- RSA -----------------------------------------------------------------

    static byte[]? Fixed(byte[]? raw, int width)
    {
        if (raw is null || raw.Length > width) return null;
        if (raw.Length == width) return raw;
        byte[] outBytes = new byte[width];
        raw.CopyTo(outBytes, width - raw.Length);
        return outBytes;
    }

    static byte[]? Fixed(string? b64, int width) => Fixed(B64u(b64), width);

    /// An RSA private key from a recorded JWK. RSAParameters wants every CRT value at
    /// its exact width, so each one is left padded with zero octets against the
    /// modulus rather than handed over as decoded.
    public static RSA? RsaPrivateFromJwk(JObj? jwk)
    {
        if (jwk.Str("kty") != "RSA") return null;
        byte[]? n = B64u(jwk.StrOrNull("n"));
        byte[]? e = B64u(jwk.StrOrNull("e"));
        if (n is null || e is null || n.Length == 0 || (n.Length & 1) != 0) return null;
        int half = n.Length / 2;

        byte[]? d = Fixed(jwk.StrOrNull("d"), n.Length);
        byte[]? p = Fixed(jwk.StrOrNull("p"), half);
        byte[]? q = Fixed(jwk.StrOrNull("q"), half);
        if (d is null || p is null || q is null) return null;

        // A producer may leave dp, dq and qi out. This reads them from the record when
        // it carries them and computes them when it does not, so either JWK loads.
        byte[]? dp = jwk.Has("dp") ? Fixed(jwk.StrOrNull("dp"), half) : Fixed(CrtExponent(d, p), half);
        byte[]? dq = jwk.Has("dq") ? Fixed(jwk.StrOrNull("dq"), half) : Fixed(CrtExponent(d, q), half);
        byte[]? qi = jwk.Has("qi") ? Fixed(jwk.StrOrNull("qi"), half) : Fixed(CrtCoefficient(p, q), half);
        if (dp is null || dq is null || qi is null) return null;

        var parameters = new RSAParameters
        {
            Modulus = n,
            Exponent = e,
            D = d,
            P = p,
            Q = q,
            DP = dp,
            DQ = dq,
            InverseQ = qi,
        };
        try { return RSA.Create(parameters); }
        catch (CryptographicException) { return null; }
    }

    static BigInteger Unsigned(byte[] b) => new(b, isUnsigned: true, isBigEndian: true);

    static byte[] CrtExponent(byte[] d, byte[] prime)
    {
        BigInteger value = Unsigned(d) % (Unsigned(prime) - BigInteger.One);
        return value.ToByteArray(isUnsigned: true, isBigEndian: true);
    }

    static byte[] CrtCoefficient(byte[] p, byte[] q)
    {
        BigInteger pp = Unsigned(p);
        BigInteger value = ModInverse(Unsigned(q), pp);
        return value.ToByteArray(isUnsigned: true, isBigEndian: true);
    }

    static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger t = BigInteger.Zero, newT = BigInteger.One;
        BigInteger r = m, newR = a % m;
        while (newR != BigInteger.Zero)
        {
            BigInteger quotient = r / newR;
            (t, newT) = (newT, t - quotient * newT);
            (r, newR) = (newR, r - quotient * newR);
        }
        if (t < BigInteger.Zero) t += m;
        return t;
    }

    /// One decrypt call with no OAEP label. RSAEncryptionPadding.OaepSHA256 names one
    /// hash for both the digest and the MGF1 mask, so the JDK's split default has no
    /// analogue to fall into here.
    public static byte[]? RsaOaepDecrypt(RSA rsa, byte[]? ciphertext)
    {
        if (ciphertext is null) return null;
        try { return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256); }
        catch (CryptographicException) { return null; }
    }
}

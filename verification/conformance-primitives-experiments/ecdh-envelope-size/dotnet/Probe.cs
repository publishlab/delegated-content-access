// .NET probe. Reads `_shared/fixture.json` inputs, seals and opens the three
// envelope profiles through System.Security.Cryptography, and writes
// observations as JSON on stdout. It reads no expectation and assigns no
// verdict.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class Probe
{
    private const int TagBytes = 16;

    // The SubjectPublicKeyInfo shell for an uncompressed P-256 point:
    // id-ecPublicKey with prime256v1, then a BIT STRING holding the 65 bytes.
    // The .NET key classes have no raw-point entry, so every point import here
    // is container-assisted.
    private const string Spki65 = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    private static JsonElement inputs;
    private static string compressedImport = "unsupported";
    private static string compressedImportRefusal = "";

    private static string Text(JsonElement node, string key) => node.GetProperty(key).GetString()!;

    private static string Text(string key) => Text(inputs, key);

    private static JsonElement At(string key) => inputs.GetProperty(key);

    private static byte[] Unhex(string hex) => Convert.FromHexString(hex);

    private static string Hex(byte[] raw) => Convert.ToHexString(raw).ToLowerInvariant();

    private static string B64Url(byte[] raw) => Convert.ToBase64String(raw)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Join(params byte[][] parts)
    {
        var out_ = new byte[parts.Sum(p => p.Length)];
        var at = 0;
        foreach (var part in parts)
        {
            part.CopyTo(out_, at);
            at += part.Length;
        }
        return out_;
    }

    private static ECDiffieHellman ImportPointSpki(byte[] point)
    {
        var key = ECDiffieHellman.Create();
        key.ImportSubjectPublicKeyInfo(Join(Unhex(Spki65), point), out _);
        return key;
    }

    // The .NET readers refuse a compressed point inside the container, so a
    // 33-byte point goes through `Decompress.Uncompressed` first and the
    // recovered 65 bytes go through the same import as every other point. The
    // library still validates the point, and a decoder refusal leaves the same
    // way a library refusal does.
    private static ECDiffieHellman ImportPoint(byte[] point)
    {
        if (point.Length == 33 && compressedImport == "unsupported")
        {
            throw new CryptographicException("compressed point import is unsupported here");
        }
        return ImportPointSpki(point.Length == 33 ? Decompress.Uncompressed(point) : point);
    }

    private static void DetectCompressedImport()
    {
        try
        {
            using var imported = ImportPointSpki(
                Decompress.Uncompressed(Unhex(Text(At("ephemeral"), "publicCompressedHex"))));
            compressedImport = "decoder, then container-assisted";
        }
        catch (Exception refusal)
        {
            compressedImport = "unsupported";
            compressedImportRefusal = refusal.Message;
        }
    }

    private static ECDiffieHellman ImportPrivate(string pkcs8Hex)
    {
        var key = ECDiffieHellman.Create();
        key.ImportPkcs8PrivateKey(Unhex(pkcs8Hex), out _);
        return key;
    }

    /// <summary>The 32-byte fixed-width x-coordinate, or null when import or agreement fails.</summary>
    private static byte[]? Agree(byte[] point, string pkcs8Hex)
    {
        try
        {
            using var peer = ImportPoint(point);
            using var mine = ImportPrivate(pkcs8Hex);
            return mine.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static byte[] Derive(byte[] secret, string info, int length) => HKDF.DeriveKey(
        HashAlgorithmName.SHA256, secret, length, Array.Empty<byte>(), Encoding.UTF8.GetBytes(info));

    private static byte[] GcmSeal(byte[] key, byte[] nonce, byte[] plaintext, string aad)
    {
        using var gcm = new AesGcm(key, TagBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(aad));
        return Join(ciphertext, tag);
    }

    private static byte[]? GcmOpen(byte[] key, byte[] nonce, byte[] carrier, string aad)
    {
        if (carrier.Length <= TagBytes)
        {
            return null;
        }
        try
        {
            using var gcm = new AesGcm(key, TagBytes);
            var plaintext = new byte[carrier.Length - TagBytes];
            gcm.Decrypt(
                nonce,
                carrier.AsSpan(0, carrier.Length - TagBytes),
                carrier.AsSpan(carrier.Length - TagBytes),
                plaintext,
                Encoding.UTF8.GetBytes(aad));
            return plaintext;
        }
        catch (Exception)
        {
            return null;
        }
    }

    // One profile switch, shared by the three shapes: how wide the carried point
    // is, and whether the key and nonce come from the fixture or from HKDF.
    private sealed record Shape(string Name, string PointKey, bool Derived)
    {
        public int PointBytes => Name == "hkdf-compressed-65" ? 33 : 65;
    }

    private static readonly Shape[] Profiles =
    {
        new("control-109", "publicUncompressedHex", false),
        new("hkdf-97", "publicUncompressedHex", true),
        new("hkdf-compressed-65", "publicCompressedHex", true),
    };

    private static (byte[] Key, byte[] Nonce)? Material(Shape shape, byte[]? shared, string bind)
    {
        if (shared is null)
        {
            return null;
        }
        if (!shape.Derived)
        {
            return (shared, Unhex(Text("controlNonceHex")));
        }
        var hkdf = At("hkdf");
        return (
            Derive(shared, Text(hkdf, "keyInfoPrefix") + bind, hkdf.GetProperty("keyBytes").GetInt32()),
            Derive(shared, Text(hkdf, "nonceInfoPrefix") + bind, hkdf.GetProperty("nonceBytes").GetInt32()));
    }

    // The publisher side agrees with the issuer public point under the fixed
    // ephemeral private key, so every runtime seals the same bytes.
    private static (byte[] Key, byte[] Nonce) SealingMaterial(Shape shape, string bind) => Material(
        shape,
        Agree(Unhex(Text(At("issuer"), "publicUncompressedHex")), Text(At("ephemeral"), "privatePkcs8Hex")),
        bind)!.Value;

    private static byte[]? OpenEnvelope(Shape shape, byte[] envelope, string bind)
    {
        var width = shape.PointBytes;
        if (envelope.Length < width)
        {
            return null;
        }
        var point = envelope[..width];
        var rest = envelope[width..];
        var material = Material(shape, Agree(point, Text(At("issuer"), "privatePkcs8Hex")), bind);
        if (material is null)
        {
            return null;
        }
        var (key, nonce) = material.Value;
        return shape.Derived
            ? GcmOpen(key, nonce, rest, bind)
            : GcmOpen(key, rest[..12], rest[12..], bind);
    }

    // Every negative case answers with one word. The experiment is looking for
    // a released key, so the probe says which of the two happened
    // and nothing about the cause.
    private static string Releases(Shape shape, byte[] envelope, string bind)
    {
        var opened = OpenEnvelope(shape, envelope, bind);
        return opened is { Length: > 0 } ? "key-released" : "no-key";
    }

    private static Dictionary<string, object?> RunProfile(Shape shape)
    {
        var bind = Text(At("bind"), "value");
        var point = Unhex(Text(At("ephemeral"), shape.PointKey));

        if (point.Length == 33 && compressedImport == "unsupported")
        {
            return new Dictionary<string, object?>
            {
                ["status"] = "unsupported",
                ["reason"] = "no point import through the runtime, decoder included: " + compressedImportRefusal,
            };
        }

        var (key, nonce) = SealingMaterial(shape, bind);
        var carrier = GcmSeal(key, nonce, Unhex(Text("dcaKeyHex")), bind);
        var envelope = shape.Derived ? Join(point, carrier) : Join(point, nonce, carrier);

        var flipped = (byte[])envelope.Clone();
        flipped[^(TagBytes + 1)] ^= 0x01;

        var offCurvePoints = At("offCurvePoints");
        var badPoint = Unhex(Text(offCurvePoints, point.Length == 33 ? "compressedHex" : "uncompressedHex"));
        var offCurve = Join(badPoint, envelope[point.Length..]);

        // A compressed x below p whose curve equation has no square root mod p.
        // Only a 33-byte point carries that case, so the wider profiles answer
        // `n/a`. Here the decoder refuses it.
        var nonResiduePoint = "n/a";
        if (point.Length == 33)
        {
            var nonResidue = Join(
                Unhex(Text(offCurvePoints, "compressedNonResidueHex")), envelope[point.Length..]);
            nonResiduePoint = Releases(shape, nonResidue, bind);
        }

        var opened = OpenEnvelope(shape, envelope, bind);

        return new Dictionary<string, object?>
        {
            ["status"] = "answered",
            ["envelopeHex"] = Hex(envelope),
            ["derivedKeyHex"] = Hex(key),
            ["derivedNonceHex"] = Hex(nonce),
            ["envelopeBase64url"] = B64Url(envelope),
            ["decodedBytes"] = envelope.Length,
            ["base64urlChars"] = B64Url(envelope).Length,
            ["pointBytes"] = point.Length,
            ["openedKeyHex"] = opened is null ? "open-failed" : Hex(opened),
            ["wrongBind"] = Releases(shape, envelope, Text(At("otherBind"), "value")),
            ["flippedCiphertext"] = Releases(shape, flipped, bind),
            ["invalidPoint"] = Releases(shape, offCurve, bind),
            ["nonResiduePoint"] = nonResiduePoint,
        };
    }

    private static Dictionary<string, string> DerivedPair(string pkcs8Hex, string bind)
    {
        var shared = Agree(Unhex(Text(At("issuer"), "publicUncompressedHex")), pkcs8Hex)!;
        var hkdf = At("hkdf");
        return new Dictionary<string, string>
        {
            ["keyHex"] = Hex(Derive(shared, Text(hkdf, "keyInfoPrefix") + bind, hkdf.GetProperty("keyBytes").GetInt32())),
            ["nonceHex"] = Hex(Derive(
                shared, Text(hkdf, "nonceInfoPrefix") + bind, hkdf.GetProperty("nonceBytes").GetInt32())),
        };
    }

    public static int Main()
    {
        var source = Environment.GetEnvironmentVariable("DCA_EXPERIMENT_DIR") ?? "..";
        var raw = File.ReadAllText(Path.Combine(source, "_shared", "fixture.json"));
        using var fixture = JsonDocument.Parse(raw);
        inputs = fixture.RootElement.GetProperty("inputs");

        DetectCompressedImport();
        var bind = Text(At("bind"), "value");

        var profiles = new Dictionary<string, object?>();
        foreach (var shape in Profiles)
        {
            profiles[shape.Name] = RunProfile(shape);
        }

        var ephemeral = Text(At("ephemeral"), "privatePkcs8Hex");
        var pairs = new Dictionary<string, object?>
        {
            ["sameEphemeralSameBind"] = DerivedPair(ephemeral, bind),
            ["sameEphemeralSameBindRepeat"] = DerivedPair(ephemeral, bind),
            ["sameEphemeralOtherBind"] = DerivedPair(ephemeral, Text(At("otherBind"), "value")),
            ["freshEphemeralSameBind"] = DerivedPair(Text(At("ephemeralFresh"), "privatePkcs8Hex"), bind),
        };
        var reuse = new Dictionary<string, object?>();
        foreach (var shape in Profiles.Where(s => s.Derived))
        {
            reuse[shape.Name] = pairs;
        }

        var observations = new Dictionary<string, object?>
        {
            ["runtime"] = "dotnet",
            ["runtimeVersion"] = ".NET " + Environment.Version + " (" +
                System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription + ")",
            ["cryptoProvider"] = "System.Security.Cryptography on " +
                System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            ["compressedPointImport"] = compressedImport,
            ["profiles"] = profiles,
            ["ephemeralReuse"] = reuse,
        };

        Console.WriteLine(JsonSerializer.Serialize(observations, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
}

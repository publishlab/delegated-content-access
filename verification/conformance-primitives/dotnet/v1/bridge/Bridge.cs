// What .NET observes when it is asked to perform one of the contract's seven
// operations, and nothing about whether that observation is right.
//
// One batch in, one batch out. The bridge reads a single `dca-operation-bridge-v1`
// JSON document from stdin, computes one observation per request, writes a single
// JSON document to stdout and exits 0. Diagnostics for a person go to stderr; nothing
// reads a result out of stderr, so a bridge may say whatever it likes there.
//
// Each operation is one stock library call: decode a strict base64url field, derive
// octets with HKDF-SHA-256, open and seal an AES-GCM carrier, agree a P-256 ECDH
// secret, encode a P-256 public point, and open an RSA-OAEP ciphertext. The bridge makes
// each of those calls through `../Primitives.cs`, over the base class library, and
// `bridge.csproj` says why this project compiles that file directly. A JWK input arrives
// here as a parsed `JsonElement`; `Json.TryParseObject` over the element's own raw text
// turns it into the `JObj` those helpers take, so this file holds no second JWK reader.
// This file writes no ECDH agreement, no HKDF and no AES-GCM of its own.
//
// The bridge does not know what any observation is supposed to be. There is no
// expected value here, no comparison, no `held`, `disagreed` or `incomplete` word, no
// pass count and no total. It never opens the case corpus, and the request it is handed
// carries no `expected` for it to peek at. It does not read the identifier either: an
// id goes back into the result that answers it and nowhere else.
//
// The bridge reports a defined refusal as an answer. `invalid_base64url`,
// `authentication_failed` and `unseal_failed` are observations inside an exit-0
// result, because refusing correctly is one of the behaviours under test. A request
// the bridge cannot serve at all, an unparseable batch, an unknown operation or an
// input shape outside the contract, is handled another way entirely: the bridge exits nonzero with
// a stderr line and writes no partial results, and the runner reads that as a run that
// could not be completed. The whole answer is built in memory and written once, so a
// fault on the last request cannot leave the first ones on stdout.
//
// The bridge checks every shape it reads, and each one is closed. The envelope carries
// `protocol` and `requests`, a request row carries `id`, `op` and `input`, and an input
// carries exactly the members its operation names. A member nobody named means the harness
// speaks a protocol this bridge has not agreed to.
//
// The bridge reads the batch with the runtime's own JSON parser and nothing else.
// `System.Text.Json` reads it. There is no token scanner here and no duplicate-member
// check: Node writes the bytes on stdin and never repeats a member, so a bridge
// defending against one would be defending against its own harness, once per language.
//
// The bridge checks the base64url rules itself rather than leaving them to the decoder.
// Measured on SDK 10.0.400, `Base64Url.DecodeFromChars` accepts a padded spelling
// ("3q2-7w==" and even "3q2-7w=" decode to deadbeef) and refuses non-zero trailing bits
// ("3q2-7x" throws FormatException). The decoder applies part of the strict field rule,
// and a runtime update could move where that part ends. So the alphabet, the length and
// the re-encode comparison are all checked below, and the answer holds whichever of them
// the decoder would also have caught.
//
// Run (the runner does this; by hand it is the same):
//   printf '%s\n' '<batch json>' | conformance-primitives/dotnet/v1/bridge/start

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;

internal static class Bridge
{
    private const string BatchProtocol = "dca-operation-bridge-v1";

    // Quoting for a stderr line naming a value the bridge refused. The default encoder
    // escapes a `+` into a six-character unicode escape, and a person reading why a value
    // was refused needs the character that caused it printed as itself.
    private static readonly JsonSerializerOptions Readable = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    // The contract's HKDF-SHA-256 section fixes the widths `hkdf-sha256` derives:
    // one octet at the least, 8160 at the most.
    private const int HkdfLeastOctets = 1;
    private const int HkdfMostOctets = 8160;

    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int PointBytes = 65;

    private static int Main()
    {
        string raw;
        try
        {
            using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
            raw = input.ReadToEnd();
        }
        catch (IOException error)
        {
            Console.Error.WriteLine($"bridge: stdin could not be read: {error.Message}");
            return 1;
        }

        byte[] answer;
        try
        {
            answer = AnswerBatch(raw);
        }
        catch (BridgeFault fault)
        {
            Console.Error.WriteLine($"bridge: {fault.Message}");
            return 1;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"bridge: {error.GetType().Name}: {error.Message}");
            return 1;
        }

        // One JSON value and a newline, and the stream is flushed before the exit code
        // goes back: if the process exits with the answer still buffered, the bridge has said
        // nothing.
        using var output = Console.OpenStandardOutput();
        output.Write(answer, 0, answer.Length);
        output.WriteByte((byte)'\n');
        output.Flush();
        Console.Error.Flush();
        return 0;
    }

    /// <summary>
    /// The request envelope, read strictly, and one result per request in request order.
    /// </summary>
    /// <remarks>
    /// Order is irrelevant to the runner, which keys results by the (id, op) pair, so
    /// request order stays only because it makes a hand-read batch easy to follow.
    /// Every observation is computed before a byte is encoded, so a request this bridge
    /// cannot serve stops the whole answer rather than truncating it.
    /// </remarks>
    private static byte[] AnswerBatch(string raw)
    {
        using var document = ReadBatch(raw);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new BridgeFault("the batch on stdin is not a JSON object.");
        }

        ClosedMembers(root, ["protocol", "requests"], "the batch");
        var protocol = root.GetProperty("protocol");
        if (protocol.ValueKind != JsonValueKind.String || protocol.GetString() != BatchProtocol)
        {
            throw new BridgeFault("the batch names a protocol this bridge does not speak.");
        }

        var requests = root.GetProperty("requests");
        if (requests.ValueKind != JsonValueKind.Array)
        {
            throw new BridgeFault("the batch carries no requests array.");
        }

        var answered = new List<Answer>();
        foreach (var entry in requests.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                throw new BridgeFault("a request entry is not a JSON object.");
            }

            ClosedMembers(entry, ["id", "op", "input"], "a request entry");
            var idMember = entry.GetProperty("id");
            if (idMember.ValueKind != JsonValueKind.String || idMember.GetString()!.Length == 0)
            {
                throw new BridgeFault("a request entry carries no id.");
            }

            var id = idMember.GetString()!;
            var opMember = entry.GetProperty("op");
            if (opMember.ValueKind != JsonValueKind.String)
            {
                throw new BridgeFault($"request {id} carries no op.");
            }

            var op = opMember.GetString()!;
            var input = entry.GetProperty("input");
            if (input.ValueKind != JsonValueKind.Object)
            {
                throw new BridgeFault($"request {id} carries no input object.");
            }

            answered.Add(new Answer(id, op, Observe(op, input, id)));
        }

        return Encode(answered);
    }

    private static JsonDocument ReadBatch(string raw)
    {
        try
        {
            return JsonDocument.Parse(raw);
        }
        catch (JsonException error)
        {
            throw new BridgeFault($"the batch on stdin is not readable JSON: {error.Message}");
        }
    }

    /// <summary>The result envelope as UTF-8 bytes, built once and written once.</summary>
    /// <remarks>
    /// The relaxed encoder keeps every observation value readable as itself on stdout.
    /// Escaping is a JSON spelling and both spellings decode to the same string, so
    /// nothing under test turns on it; a person reading a failing batch by eye gains.
    /// </remarks>
    private static byte[] Encode(List<Answer> answered)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartObject();
            writer.WriteString("protocol", BatchProtocol);
            writer.WriteStartArray("results");
            foreach (var one in answered)
            {
                writer.WriteStartObject();
                writer.WriteString("id", one.Id);
                writer.WriteString("op", one.Op);
                writer.WriteStartObject("observation");
                writer.WriteString(one.Observation.Member, one.Observation.Value);
                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>One observation for one request, or a fault when the operation is not one of the seven.</summary>
    private static Observation Observe(string op, JsonElement input, string id) => op switch
    {
        "decode-base64url" => ObserveDecodeBase64Url(input, id),
        "hkdf-sha256" => ObserveHkdfSha256(input, id),
        "open-aes-gcm" => ObserveOpenAesGcm(input, id),
        "seal-aes-gcm" => ObserveSealAesGcm(input, id),
        "ecdh-p256" => ObserveEcdhP256(input, id),
        "p256-point" => ObserveP256Point(input, id),
        "open-rsa-oaep" => ObserveOpenRsaOaep(input, id),
        _ => throw new BridgeFault($"request {id} names operation {op}, which this bridge does not implement."),
    };

    /// <summary>
    /// The strict field spelling: RFC 4648 section 5 alphabet, no padding, a length that
    /// encodes a whole byte count, and zero unused trailing bits.
    /// </summary>
    /// <remarks>
    /// Which of those rules fired goes to stderr. The observation carries the one closed
    /// code, because the contract has one.
    /// </remarks>
    private static Observation ObserveDecodeBase64Url(JsonElement input, string id)
    {
        ClosedMembers(input, ["value"], $"the input of request {id}");
        var value = RequiredString(input, "value", id);
        var bytes = DecodeStrictBase64Url(value, out var why);
        if (bytes is null)
        {
            Console.Error.WriteLine($"bridge: {id} refused {JsonSerializer.Serialize(value, Readable)}: {why}");
            return Observation.Refused("invalid_base64url");
        }

        return new Observation("bytesHex", Convert.ToHexString(bytes).ToLowerInvariant());
    }

    /// <summary>
    /// One HKDF-SHA-256 derivation over the octets the request carries, run by this
    /// runtime's own `HKDF.DeriveKey` under an explicitly empty salt.
    /// </summary>
    /// <remarks>
    /// The info octets stay octets from the decode to the derivation, so a 0x00 or an
    /// octet above 0x7f arrives as the request spells it. A `length` outside 1 through
    /// 8160 is a request this bridge cannot serve.
    /// </remarks>
    private static Observation ObserveHkdfSha256(JsonElement input, string id)
    {
        ClosedMembers(input, ["ikmBase64url", "infoBase64url", "length"], $"the input of request {id}");
        var ikm = CarrierBytes(input, "ikmBase64url", id);
        var info = CarrierBytes(input, "infoBase64url", id);
        if (!input.TryGetProperty("length", out var asked) || asked.ValueKind != JsonValueKind.Number
            || !asked.TryGetInt32(out var length) || length < HkdfLeastOctets || length > HkdfMostOctets)
        {
            throw new BridgeFault($"request {id} carries no length in {HkdfLeastOctets} to {HkdfMostOctets}.");
        }

        return new Observation("okmBase64url", Base64Url.EncodeToString(Primitives.HkdfEmptySalt(ikm, info, length)));
    }

    /// <summary>AES-GCM over one `ciphertext || tag` carrier, which is how the contract carries it.</summary>
    /// <remarks>
    /// .NET takes the tag as its own span, so `Primitives.GcmOpen` splits the last 16 octets
    /// off. The contract carries one buffer because ciphertext-then-tag is what every
    /// other runtime produces natively, and carrying the tag separately would hand this
    /// split to all of them to test nothing new.
    /// <para>
    /// A carrier too short to hold a tag is `authentication_failed`: no tag in it
    /// verifies, and the contract refuses under any cause. A key that is neither 16 nor
    /// 32 octets, or a nonce that is not 12, is an input outside the shapes this
    /// operation is defined over, so it is a request this bridge cannot serve and not `authentication_failed`.
    /// </para>
    /// </remarks>
    private static Observation ObserveOpenAesGcm(JsonElement input, string id)
    {
        ClosedMembers(input, ["keyBase64url", "nonceBase64url", "ciphertextBase64url", "aadBase64url"], $"the input of request {id}");
        var key = RequiredAeadKey(input, id);
        var nonce = RequiredNonce(input, id);
        var carrier = CarrierBytes(input, "ciphertextBase64url", id);
        var aad = CarrierBytes(input, "aadBase64url", id);

        var plaintext = Primitives.GcmOpen(key, nonce, carrier, aad);
        if (plaintext is null)
        {
            Console.Error.WriteLine($"bridge: {id} did not authenticate.");
            return Observation.Refused("authentication_failed");
        }

        return new Observation("plaintextBase64url", Base64Url.EncodeToString(plaintext));
    }

    /// <summary>AES-GCM the other way: the ciphertext with the 16-octet tag appended.</summary>
    /// <remarks>
    /// The nonce arrives as an input, so a seal has one determined answer.
    /// The operation defines no refusal, so a call that does not return octets is a
    /// request this bridge could not serve.
    /// </remarks>
    private static Observation ObserveSealAesGcm(JsonElement input, string id)
    {
        ClosedMembers(input, ["keyBase64url", "nonceBase64url", "plaintextBase64url", "aadBase64url"], $"the input of request {id}");
        var key = RequiredAeadKey(input, id);
        var nonce = RequiredNonce(input, id);
        var plaintext = CarrierBytes(input, "plaintextBase64url", id);
        var aad = CarrierBytes(input, "aadBase64url", id);

        var carrier = Primitives.GcmSeal(key, nonce, plaintext, aad)
            ?? throw new BridgeFault($"request {id} could not be sealed.");
        return new Observation("ciphertextBase64url", Base64Url.EncodeToString(carrier));
    }

    /// <summary>One ECDH agreement over P-256, answered as the raw agreed x-coordinate.</summary>
    /// <remarks>
    /// The peer arrives as the 65-octet uncompressed SEC 1 point, which
    /// `Primitives.EcdhPublicFromPoint` imports with this runtime's own routines. The
    /// operation defines no refusal, so a point this runtime cannot import is a request
    /// this bridge cannot serve. `Primitives.EcdhRaw` calls DeriveRawSecretAgreement and
    /// pads to the 32-octet field width, applying no KDF over the secret.
    /// </remarks>
    private static Observation ObserveEcdhP256(JsonElement input, string id)
    {
        ClosedMembers(input, ["privateKeyJwk", "peerPointBase64url"], $"the input of request {id}");
        var privateKey = RequiredEcdhPrivate(input, "privateKeyJwk", id);
        var point = CarrierBytes(input, "peerPointBase64url", id);
        var peer = Primitives.EcdhPublicFromPoint(point)
            ?? throw new BridgeFault($"request {id} carries a peerPointBase64url this bridge cannot import.");
        var shared = Primitives.EcdhRaw(privateKey, peer)
            ?? throw new BridgeFault($"request {id} could not agree an ECDH secret.");

        return new Observation("sharedSecretBase64url", Base64Url.EncodeToString(shared));
    }

    /// <summary>One P-256 public key as the 65-octet uncompressed SEC 1 point.</summary>
    /// <remarks>
    /// Each coordinate keeps its full 32-octet width, so a coordinate that starts with a
    /// zero octet answers 65 octets like every other one. The operation defines no
    /// refusal, and a key this bridge cannot read is a request it cannot serve.
    /// </remarks>
    private static Observation ObserveP256Point(JsonElement input, string id)
    {
        ClosedMembers(input, ["publicKeyJwk"], $"the input of request {id}");
        var point = Primitives.PointFromJwk(RequiredJwk(input, "publicKeyJwk", id))
            ?? throw new BridgeFault($"request {id} carries a publicKeyJwk this bridge cannot import.");

        if (point.Length != PointBytes)
        {
            throw new BridgeFault($"request {id} produced a {point.Length}-octet point, and this encoding is {PointBytes}.");
        }

        return new Observation("pointBase64url", Base64Url.EncodeToString(point));
    }

    /// <summary>One RSA-OAEP-SHA256 decryption to the whole plaintext, no label.</summary>
    /// <remarks>
    /// A wrong private key, a ciphertext that is not one modulus wide, and a flipped
    /// octet are one `unseal_failed`: `Primitives.RsaOaepDecrypt` catches every
    /// `CryptographicException` OAEP's padding check raises and answers null, and this is
    /// where that null becomes the refusal rather than a fault, because the contract
    /// defines it as an answer for this operation.
    /// </remarks>
    private static Observation ObserveOpenRsaOaep(JsonElement input, string id)
    {
        ClosedMembers(input, ["ciphertextBase64url", "privateKeyJwk"], $"the input of request {id}");

        var rsa = RequiredRsaPrivate(input, "privateKeyJwk", id);
        var ciphertext = CarrierBytes(input, "ciphertextBase64url", id);
        var plaintext = Primitives.RsaOaepDecrypt(rsa, ciphertext);
        if (plaintext is null)
        {
            Console.Error.WriteLine($"bridge: {id} did not open.");
            return Observation.Refused("unseal_failed");
        }

        return new Observation("plaintextBase64url", Base64Url.EncodeToString(plaintext));
    }

    /// <summary>One `...Jwk` input member, read into the ordered object model `Json` defines.</summary>
    /// <remarks>
    /// `Json.TryParseObject` runs over the element's own raw text, itself produced by
    /// `System.Text.Json`. Reparsing an already-parsed value adds no second JSON
    /// reader; it turns a `JsonElement` into the `JObj` the JWK-import methods in
    /// `Primitives` take, since the two object models are otherwise unrelated types.
    /// </remarks>
    private static JObj RequiredJwk(JsonElement input, string member, string id)
    {
        if (!input.TryGetProperty(member, out var value) || value.ValueKind != JsonValueKind.Object)
        {
            throw new BridgeFault($"request {id} carries no {member} object.");
        }

        return Json.TryParseObject(value.GetRawText()) ?? throw new BridgeFault($"request {id} carries a {member} this bridge cannot read.");
    }

    /// <summary>One ECDH P-256 private-key JWK, imported by `Primitives.EcdhPrivateFromJwk`.</summary>
    private static ECDiffieHellman RequiredEcdhPrivate(JsonElement input, string member, string id) =>
        Primitives.EcdhPrivateFromJwk(RequiredJwk(input, member, id))
            ?? throw new BridgeFault($"request {id} carries a {member} this bridge cannot import.");

    /// <summary>One RSA private-key JWK, imported by `Primitives.RsaPrivateFromJwk`.</summary>
    private static RSA RequiredRsaPrivate(JsonElement input, string member, string id) =>
        Primitives.RsaPrivateFromJwk(RequiredJwk(input, member, id))
            ?? throw new BridgeFault($"request {id} carries a {member} this bridge cannot import.");

    /// <summary>One `keyBase64url` member at one of the two widths AES-GCM takes here.</summary>
    /// <remarks>
    /// 16 octets select AES-128-GCM and 32 select AES-256-GCM. Any other width is an
    /// input outside the operation's shape, so it faults rather than refusing.
    /// </remarks>
    private static byte[] RequiredAeadKey(JsonElement input, string id)
    {
        var key = CarrierBytes(input, "keyBase64url", id);
        if (key.Length != 16 && key.Length != 32)
        {
            throw new BridgeFault($"request {id} carries a {key.Length}-octet key, and this operation takes 16 or 32.");
        }

        return key;
    }

    /// <summary>One `nonceBase64url` member, decoded and checked at the 12-octet width AES-GCM takes here.</summary>
    private static byte[] RequiredNonce(JsonElement input, string id)
    {
        var nonce = CarrierBytes(input, "nonceBase64url", id);
        if (nonce.Length != NonceBytes)
        {
            throw new BridgeFault($"request {id} carries a {nonce.Length}-octet nonce, and this operation takes {NonceBytes}.");
        }

        return nonce;
    }

    /// <summary>
    /// One JSON object holding exactly the named members, or a request this bridge cannot
    /// serve.
    /// </summary>
    /// <remarks>
    /// The contract calls the envelope, the request row and every input closed, and this
    /// method checks that they are. A member outside the set means the
    /// sender writes a protocol this bridge has not agreed to, and a missing one means it
    /// left out something the operation is defined by.
    /// </remarks>
    private static void ClosedMembers(JsonElement element, string[] members, string what)
    {
        var present = element.EnumerateObject().Select(member => member.Name).ToList();
        var unknown = present.Where(name => !members.Contains(name)).ToList();
        var absent = members.Where(name => !present.Contains(name)).ToList();

        if (unknown.Count > 0 || absent.Count > 0)
        {
            throw new BridgeFault($"{what} carries {{{string.Join(", ", present)}}}, and it carries {{{string.Join(", ", members)}}} exactly.");
        }
    }

    /// <summary>One input member that must be present and a string, or a request this bridge cannot serve.</summary>
    private static string RequiredString(JsonElement input, string member, string id)
    {
        if (!input.TryGetProperty(member, out var value) || value.ValueKind != JsonValueKind.String)
        {
            throw new BridgeFault($"request {id} carries no string {member}.");
        }

        return value.GetString()!;
    }

    /// <summary>One base64url input member decoded to raw octets. Every carrier literal is canonical.</summary>
    private static byte[] CarrierBytes(JsonElement input, string member, string id)
    {
        var value = RequiredString(input, member, id);
        var bytes = DecodeStrictBase64Url(value, out var why);
        if (bytes is null)
        {
            throw new BridgeFault($"request {id} carries a {member} this bridge cannot decode: {why}.");
        }

        return bytes;
    }

    /// <summary>Canonical unpadded base64url to octets, or null with the reason in <paramref name="why"/>.</summary>
    /// <remarks>
    /// The alphabet scan refuses padding, since this runtime's decoder accepts it.
    /// The decode and re-encode comparison checks the trailing-bits rule, spelled out because no
    /// runtime decoder promises to apply it.
    /// </remarks>
    private static byte[]? DecodeStrictBase64Url(string value, out string? why)
    {
        why = null;
        if (value.Length == 0)
        {
            return [];
        }

        foreach (var character in value)
        {
            var inAlphabet = character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!inAlphabet)
            {
                why = "a character outside the base64url alphabet, which includes padding";
                return null;
            }
        }

        if (value.Length % 4 == 1)
        {
            why = "a length that encodes no whole byte count";
            return null;
        }

        byte[] bytes;
        try
        {
            bytes = Base64Url.DecodeFromChars(value);
        }
        catch (FormatException)
        {
            why = "octets the base64url decoder would not read";
            return null;
        }

        if (Base64Url.EncodeToString(bytes) != value)
        {
            why = "unused trailing bits: the value does not re-encode to itself";
            return null;
        }

        return bytes;
    }

    /// <summary>One answered request, waiting to be encoded.</summary>
    private readonly record struct Answer(string Id, string Op, Observation Observation);

    /// <summary>
    /// One observation, which is one object carrying one string member.
    /// </summary>
    /// <remarks>
    /// Every shape the contract defines, success and refusal alike, is exactly that, so the
    /// closed shape is the type rather than a rule applied to a freer one. There is no way
    /// to spell an empty observation here, and no way to spell one carrying both a value and
    /// a refusal.
    /// </remarks>
    private readonly record struct Observation(string Member, string Value)
    {
        internal static Observation Refused(string code) => new("refused", code);
    }

    /// <summary>A batch or a request this bridge cannot serve, which is never a refusal.</summary>
    private sealed class BridgeFault(string message) : Exception(message);
}

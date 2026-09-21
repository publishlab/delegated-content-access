using System.Text;
using System.Text.Json;

// The ordered JSON reader the bridge uses, built on Utf8JsonReader.
//
// The bridge needs its own reader because of repeated member names.
// fixtures/protocol-v1/reject-duplicate-member-name.json turns on that reading, and the
// other lanes implement one rule, last value at the first position: `{"a":1,"b":2,"a":3}`
// reads as a two-member object whose first member is `a` and whose value is 3. That is what
// JSON.parse does, what Go's encoding/json does, and what PHP's json_decode does.
// System.Text.Json matches none of them, measured on .NET 10.0.11:
//
//   JsonDocument.Parse       accepts the body; GetProperty("a") hands back the
//                            last value, but EnumerateObject yields THREE
//                            members and names `a` twice, so a walk over the
//                            object visits the same coordinate twice
//   JsonNode.Parse           throws ArgumentException, "An item with the same
//                            key has already been added"
//   Deserialize<Dictionary>  last value, and member order is not preserved
//   JsonSerializerOptions    carries AllowDuplicateProperties, default true,
//                            which decides accept-or-throw and not which value
//                            or which position
//
// So the document layer is unusable here in all three spellings and the reader
// underneath it is not: Utf8JsonReader is a tokenizer, it reports all three
// property names in order and does nothing special with duplicates. The object model
// below is built straight on it, and Put() is the one line that carries the
// rule.

abstract class JVal
{
}

sealed class JObj : JVal
{
    readonly List<string> _keys = new();
    readonly Dictionary<string, JVal> _members = new(StringComparer.Ordinal);

    public IReadOnlyList<string> Keys => _keys;

    // Put applies the whole rule: a repeated name keeps its first position in the
    // key order and takes the last value written under it.
    public void Put(string key, JVal value)
    {
        if (!_members.ContainsKey(key)) _keys.Add(key);
        _members[key] = value;
    }

    public JVal? Lookup(string key) => _members.TryGetValue(key, out JVal? v) ? v : null;
    public bool Contains(string key) => _members.ContainsKey(key);
}

sealed class JArr : JVal
{
    public List<JVal> Items { get; } = new();
}

sealed class JStr : JVal
{
    public JStr(string value) { Value = value; }
    public string Value { get; }
}

sealed class JNum : JVal
{
    public JNum(double value) { Value = value; }
    public double Value { get; }
}

sealed class JBool : JVal
{
    public JBool(bool value) { Value = value; }
    public bool Value { get; }
}

sealed class JNull : JVal
{
    public static readonly JNull Instance = new();
}

// The accessors are extension methods on a nullable receiver, so a missing branch
// stays walkable: `v.Obj("expected").Obj("keys")` on a body that has neither
// returns the empty value rather than failing with a null dereference at the
// first missing member.
static class JsonExt
{
    public static IReadOnlyList<string> KeysOf(this JObj? o) =>
        o is null ? Array.Empty<string>() : o.Keys;

    public static bool Has(this JObj? o, string key) => o is not null && o.Contains(key);

    public static JVal? Val(this JObj? o, string key) => o?.Lookup(key);

    public static JObj? Obj(this JObj? o, string key) => o?.Lookup(key) as JObj;

    public static JArr? Arr(this JObj? o, string key) => o?.Lookup(key) as JArr;

    /// A string member, or "" when it is absent or is not a string. The two are
    /// told apart with StrOrNull where a vector turns on the difference.
    public static string Str(this JObj? o, string key) => (o?.Lookup(key) as JStr)?.Value ?? "";

    public static string? StrOrNull(this JObj? o, string key) => (o?.Lookup(key) as JStr)?.Value;

    public static int Int(this JObj? o, string key) =>
        o?.Lookup(key) is JNum n ? (int)n.Value : 0;

    public static bool? BoolOrNull(this JObj? o, string key) =>
        o?.Lookup(key) is JBool b ? b.Value : null;

    /// Present and explicitly null, or absent entirely. A format-2 vector sets
    /// `code: null` to mark the request as answered rather than refused whole.
    public static bool IsNullOrAbsent(this JObj? o, string key)
    {
        JVal? v = o?.Lookup(key);
        return v is null || v is JNull;
    }

    public static List<string> StrList(this JObj? o, string key)
    {
        var outList = new List<string>();
        if (o?.Lookup(key) is JArr a)
        {
            foreach (JVal item in a.Items)
            {
                if (item is JStr s) outList.Add(s.Value);
            }
        }
        return outList;
    }
}

static class Json
{
    /// Parses one JSON document. Returns null when the bytes are not JSON at
    /// all; the runner reports that as a FAIL line, never as an exception that ends
    /// the run.
    public static JVal? TryParse(ReadOnlySpan<byte> utf8)
    {
        try
        {
            var reader = new Utf8JsonReader(utf8, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            if (!reader.Read()) return null;
            JVal value = ReadValue(ref reader);
            // Anything after the top-level value means this was not one document.
            if (reader.Read()) return null;
            return value;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static JVal? TryParse(string text) => TryParse(Encoding.UTF8.GetBytes(text));

    public static JObj? TryParseObject(ReadOnlySpan<byte> utf8) => TryParse(utf8) as JObj;

    public static JObj? TryParseObject(string text) => TryParse(text) as JObj;

    static JVal ReadValue(ref Utf8JsonReader reader)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.StartObject:
            {
                var obj = new JObj();
                while (true)
                {
                    if (!reader.Read()) throw new JsonException("truncated object");
                    if (reader.TokenType == JsonTokenType.EndObject) return obj;
                    if (reader.TokenType != JsonTokenType.PropertyName) throw new JsonException("expected a member name");
                    string key = reader.GetString()!;
                    if (!reader.Read()) throw new JsonException("member with no value");
                    obj.Put(key, ReadValue(ref reader));
                }
            }
            case JsonTokenType.StartArray:
            {
                var arr = new JArr();
                while (true)
                {
                    if (!reader.Read()) throw new JsonException("truncated array");
                    if (reader.TokenType == JsonTokenType.EndArray) return arr;
                    arr.Items.Add(ReadValue(ref reader));
                }
            }
            case JsonTokenType.String:
                return new JStr(reader.GetString()!);
            case JsonTokenType.Number:
                return new JNum(reader.GetDouble());
            case JsonTokenType.True:
                return new JBool(true);
            case JsonTokenType.False:
                return new JBool(false);
            case JsonTokenType.Null:
                return JNull.Instance;
            default:
                throw new JsonException($"unexpected token {reader.TokenType}");
        }
    }
}

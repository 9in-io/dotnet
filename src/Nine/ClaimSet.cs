using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace Nine;

/// <summary>
/// The claims of a verified token, an introspection answer or userinfo, exactly as 9in sent them
/// (snake_case, standard names), with typed shortcuts for the common ones.
/// </summary>
[SuppressMessage("Naming", "CA1710", Justification = "A set of claims, named like the other 9in SDKs.")]
public sealed class ClaimSet : IReadOnlyDictionary<string, JsonElement>
{
    private readonly JsonElement _root;
    private readonly Dictionary<string, JsonElement> _claims;

    private ClaimSet(JsonElement root)
    {
        _root = root;
        _claims = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            _claims[property.Name] = property.Value;
        }
    }

    /// <summary>No claims.</summary>
    public static ClaimSet Empty { get; } = Parse("{}");

    /// <summary>Claims from a JSON object.</summary>
    public static ClaimSet FromJson(JsonElement json)
    {
        if (json.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("claims are a JSON object", nameof(json));
        }
        return new ClaimSet(json.Clone());
    }

    /// <summary>Claims from JSON text (what <see cref="ToJson"/> returns).</summary>
    public static ClaimSet Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        return FromJson(document.RootElement);
    }

    /// <summary>The claims as a JSON object.</summary>
    public JsonElement Json => _root;

    /// <summary>The claims as JSON text.</summary>
    public string ToJson() => _root.GetRawText();

    /// <summary><c>sub</c>: the user (or, for client-credentials tokens, the client).</summary>
    public string? Subject => GetString("sub");

    /// <summary><c>iss</c>.</summary>
    public string? Issuer => GetString("iss");

    /// <summary><c>aud</c> as a list (a single string becomes one item).</summary>
    public IReadOnlyList<string> Audiences => GetStrings("aud");

    /// <summary><c>client_id</c>: the application the token was issued to.</summary>
    public string? ClientId => GetString("client_id");

    /// <summary><c>jti</c>: the token's id.</summary>
    public string? TokenId => GetString("jti");

    /// <summary><c>sid</c>: the sign-in session.</summary>
    public string? SessionId => GetString("sid");

    /// <summary><c>scope</c>, split on spaces.</summary>
    public IReadOnlyList<string> Scopes => (GetString("scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary><c>exp</c>.</summary>
    public DateTimeOffset? ExpiresAt => GetTime("exp");

    /// <summary><c>iat</c>.</summary>
    public DateTimeOffset? IssuedAt => GetTime("iat");

    /// <summary><c>nbf</c>.</summary>
    public DateTimeOffset? NotBefore => GetTime("nbf");

    /// <summary><c>auth_time</c>: when the user signed in.</summary>
    public DateTimeOffset? AuthTime => GetTime("auth_time");

    /// <summary><c>email</c>.</summary>
    public string? Email => GetString("email");

    /// <summary><c>name</c>.</summary>
    public string? Name => GetString("name");

    /// <summary>Whether <c>scope</c> includes <paramref name="scope"/>.</summary>
    public bool HasScope(string scope) => Scopes.Contains(scope, StringComparer.Ordinal);

    /// <summary>A string claim, or null when it is missing or not a string.</summary>
    public string? GetString(string name) =>
        _claims.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>A string or array-of-strings claim as a list.</summary>
    public IReadOnlyList<string> GetStrings(string name)
    {
        if (!_claims.TryGetValue(name, out var value))
        {
            return [];
        }
        return value.ValueKind switch
        {
            JsonValueKind.String => [value.GetString()!],
            JsonValueKind.Array => value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToArray(),
            _ => [],
        };
    }

    /// <summary>A boolean claim, or null.</summary>
    public bool? GetBoolean(string name) =>
        _claims.TryGetValue(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : null;

    /// <summary>A NumericDate claim (seconds since the epoch), or null.</summary>
    public DateTimeOffset? GetTime(string name) =>
        GetSeconds(name) is { } seconds ? DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000)) : null;

    internal double? GetSeconds(string name) =>
        _claims.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var seconds) && double.IsFinite(seconds)
            ? seconds
            : null;

    /// <inheritdoc/>
    public JsonElement this[string key] => _claims[key];

    /// <inheritdoc/>
    public IEnumerable<string> Keys => _claims.Keys;

    /// <inheritdoc/>
    public IEnumerable<JsonElement> Values => _claims.Values;

    /// <inheritdoc/>
    public int Count => _claims.Count;

    /// <inheritdoc/>
    public bool ContainsKey(string key) => _claims.ContainsKey(key);

    /// <inheritdoc/>
    public bool TryGetValue(string key, [MaybeNullWhen(false)] out JsonElement value) => _claims.TryGetValue(key, out value);

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, JsonElement>> GetEnumerator() => _claims.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <inheritdoc/>
    public override string ToString() => $"ClaimSet(sub={Subject ?? "-"}, {Count} claims)";
}

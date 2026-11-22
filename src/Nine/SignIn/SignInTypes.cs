using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Nine;

/// <summary>Options of one sign-in (<see cref="AuthClient.CreateLoginAsync"/>).</summary>
public sealed record LoginOptions
{
    /// <summary>A path in your app to come back to (only same-site relative paths are kept; see <see cref="Nine.ReturnTo"/>).</summary>
    public string? ReturnTo { get; init; }
    /// <summary><c>signup</c> opens the sign-up form (<c>prompt=create</c>); see <see cref="LoginScreen"/>.</summary>
    public string? Screen { get; init; }
    /// <summary><c>login</c> (sign in again), <c>none</c> (no UI), <c>consent</c>, <c>select_account</c> or <c>create</c>.</summary>
    public string? Prompt { get; init; }
    /// <summary>Pre-fills the identifier on the sign-in page.</summary>
    public string? LoginHint { get; init; }
    /// <summary>Language of the hosted pages (<c>ui_locales</c>), e.g. <c>de</c>.</summary>
    public string? Locale { get; init; }
    /// <summary>Another registered callback URL for this sign-in.</summary>
    public string? RedirectUri { get; init; }
    /// <summary>Extra authorization parameters. They never replace state, nonce, PKCE or the client's own.</summary>
    public IReadOnlyDictionary<string, string>? ExtraParameters { get; init; }
}

/// <summary>Values of <see cref="LoginOptions.Screen"/>.</summary>
public static class LoginScreen
{
    /// <summary>The sign-in form (the default).</summary>
    public const string Login = "login";
    /// <summary>The sign-up form.</summary>
    public const string SignUp = "signup";
}

/// <summary>A started sign-in: send the browser to <see cref="Url"/>, keep <see cref="Pending"/> until the callback.</summary>
/// <param name="Url">The authorization URL.</param>
/// <param name="Pending">State, nonce and PKCE verifier. Secret: keep it server-side or encrypted (e.g. in the session).</param>
public sealed record Login(string Url, PendingLogin Pending);

/// <summary>What to keep between the redirect to 9in and the callback. Serialise with <see cref="ToJson"/>.</summary>
public sealed record PendingLogin
{
    /// <summary>The <c>state</c> sent to 9in.</summary>
    public required string State { get; init; }
    /// <summary>The <c>nonce</c> the ID token must carry.</summary>
    public required string Nonce { get; init; }
    /// <summary>The PKCE code verifier.</summary>
    public required string CodeVerifier { get; init; }
    /// <summary>The callback URL used.</summary>
    public required string RedirectUri { get; init; }
    /// <summary>Where to go after sign-in (a same-site path), if any.</summary>
    public string? ReturnTo { get; init; }
    /// <summary>When the sign-in started.</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>JSON (snake_case keys: <c>state</c>, <c>nonce</c>, <c>verifier</c>, <c>redirect_uri</c>, <c>return_to</c>, <c>created_at</c>).</summary>
    public string ToJson() => JsonText.Write(w =>
    {
        w.WriteString("state", State);
        w.WriteString("nonce", Nonce);
        w.WriteString("verifier", CodeVerifier);
        w.WriteString("redirect_uri", RedirectUri);
        if (ReturnTo is not null)
        {
            w.WriteString("return_to", ReturnTo);
        }
        w.WriteNumber("created_at", CreatedAt.ToUnixTimeSeconds());
    });

    /// <summary>Reads what <see cref="ToJson"/> wrote; null when it isn't a pending login.</summary>
    public static PendingLogin? FromJson(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return null;
        }
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            string? Text(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            if (Text("state") is not { } state || Text("nonce") is not { } nonce || Text("verifier") is not { } verifier || Text("redirect_uri") is not { } redirect)
            {
                return null;
            }
            var created = root.TryGetProperty("created_at", out var c) && c.ValueKind == JsonValueKind.Number && c.TryGetInt64(out var seconds)
                ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                : DateTimeOffset.MinValue;
            return new PendingLogin { State = state, Nonce = nonce, CodeVerifier = verifier, RedirectUri = redirect, ReturnTo = Text("return_to"), CreatedAt = created };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Never prints the secrets.</summary>
    public override string ToString() => $"PendingLogin(redirect_uri={RedirectUri}, return_to={ReturnTo ?? "-"})";
}

/// <summary>Tokens from 9in. Keep them server-side (session); serialise with <see cref="ToJson"/>.</summary>
public sealed record TokenSet
{
    /// <summary>The access token, for your API or userinfo.</summary>
    public required string AccessToken { get; init; }
    /// <summary>Usually <c>Bearer</c>.</summary>
    public string TokenType { get; init; } = "Bearer";
    /// <summary>When the access token expires, when known.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }
    /// <summary>The refresh token (with <c>offline_access</c>). It rotates: always keep the newest.</summary>
    public string? RefreshToken { get; init; }
    /// <summary>The ID token (with <c>openid</c>); pass it as <c>id_token_hint</c> at sign-out.</summary>
    public string? IdToken { get; init; }
    /// <summary>The granted scopes, space-separated.</summary>
    public string? Scope { get; init; }
    /// <summary>The verified ID token's claims: the signed-in user. Empty without an ID token.</summary>
    public ClaimSet Claims { get; init; } = ClaimSet.Empty;
    /// <summary>The <see cref="LoginOptions.ReturnTo"/> of the sign-in (a same-site path), if any.</summary>
    public string? ReturnTo { get; init; }

    /// <summary>Whether the access token has expired, or will within <paramref name="leeway"/>.</summary>
    public bool IsExpired(TimeSpan? leeway = null, TimeProvider? timeProvider = null) =>
        ExpiresAt is { } at && at - (leeway ?? TimeSpan.Zero) <= (timeProvider ?? TimeProvider.System).GetUtcNow();

    /// <summary>
    /// JSON for a session (<c>access_token</c>, <c>token_type</c>, <c>expires_at</c> in unix seconds,
    /// <c>refresh_token</c>, <c>id_token</c>, <c>scope</c>, <c>claims</c>, <c>return_to</c>). It contains
    /// the tokens: store it server-side or encrypted.
    /// </summary>
    public string ToJson() => JsonText.Write(w =>
    {
        w.WriteString("access_token", AccessToken);
        w.WriteString("token_type", TokenType);
        if (ExpiresAt is { } at)
        {
            w.WriteNumber("expires_at", at.ToUnixTimeSeconds());
        }
        Optional(w, "refresh_token", RefreshToken);
        Optional(w, "id_token", IdToken);
        Optional(w, "scope", Scope);
        w.WritePropertyName("claims");
        Claims.Json.WriteTo(w);
        Optional(w, "return_to", ReturnTo);
    });

    /// <summary>Reads what <see cref="ToJson"/> wrote (claims are restored as they were verified, not re-verified).</summary>
    public static TokenSet FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        string? Text(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        return new TokenSet
        {
            AccessToken = Text("access_token") ?? throw new FormatException("no access_token"),
            TokenType = Text("token_type") ?? "Bearer",
            ExpiresAt = root.TryGetProperty("expires_at", out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var seconds) ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null,
            RefreshToken = Text("refresh_token"),
            IdToken = Text("id_token"),
            Scope = Text("scope"),
            Claims = root.TryGetProperty("claims", out var claims) && claims.ValueKind == JsonValueKind.Object ? ClaimSet.FromJson(claims) : ClaimSet.Empty,
            ReturnTo = Text("return_to"),
        };
    }

    private static void Optional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
        {
            writer.WriteString(name, value);
        }
    }

    /// <summary>Never prints the tokens.</summary>
    public override string ToString() =>
        $"TokenSet(sub={Claims.Subject ?? "-"}, expires_at={ExpiresAt?.ToString("O", CultureInfo.InvariantCulture) ?? "-"}, refresh_token={(RefreshToken is null ? "no" : "yes")}, scope={Scope})";
}

/// <summary>A started device sign-in (RFC 8628): show <see cref="UserCode"/> and <see cref="VerificationUri"/>, then poll.</summary>
public sealed record DeviceAuthorization
{
    /// <summary>The code your device polls with (secret).</summary>
    public required string DeviceCode { get; init; }
    /// <summary>The code the user types (<c>XXXX-XXXX</c>).</summary>
    public required string UserCode { get; init; }
    /// <summary>Where the user goes (<c>&lt;issuer&gt;/device</c>).</summary>
    public required string VerificationUri { get; init; }
    /// <summary>The same with the code filled in (for a QR code).</summary>
    public string? VerificationUriComplete { get; init; }
    /// <summary>When the codes expire.</summary>
    public DateTimeOffset ExpiresAt { get; init; }
    /// <summary>How long to wait between polls.</summary>
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Never prints the device code.</summary>
    public override string ToString() => $"DeviceAuthorization(user_code={UserCode}, verification_uri={VerificationUri})";
}

internal static class JsonText
{
    public static string Write(Action<Utf8JsonWriter> write)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}

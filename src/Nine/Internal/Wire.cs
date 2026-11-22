using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Nine.Internal;

internal sealed record UserEnvelope
{
    public ManagedUser User { get; init; } = new();
}

internal sealed record SessionsEnvelope
{
    public IReadOnlyList<ManagedSession> Sessions { get; init; } = [];
}

internal sealed record RevokedEnvelope
{
    public int Revoked { get; init; }
}

internal sealed record ImportRequest
{
    public IReadOnlyList<ImportUser> Users { get; init; } = [];
    public string? OnConflict { get; init; }
    public string? Source { get; init; }
}

internal sealed record ImportResponse
{
    public IReadOnlyList<ImportResult> Results { get; init; } = [];
}

/// <summary>A token endpoint answer, read leniently (numbers may arrive as strings).</summary>
internal sealed record TokenResponse(string AccessToken, string TokenType, long? ExpiresIn, string? RefreshToken, string? IdToken, string? Scope)
{
    public static TokenResponse Parse(HttpResult result)
    {
        var json = result.JsonObject() ?? throw new NineException("invalid_response", "the token endpoint did not answer with JSON", result.Status);
        string? Text(string name) => json.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        long? expiresIn = null;
        if (json.TryGetProperty("expires_in", out var e))
        {
            if (e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out var seconds))
            {
                expiresIn = (long)seconds;
            }
            else if (e.ValueKind == JsonValueKind.String && long.TryParse(e.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                expiresIn = parsed;
            }
        }
        var accessToken = Text("access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            throw new NineException("invalid_response", "no access_token in the token response", result.Status);
        }
        return new TokenResponse(accessToken, Text("token_type") ?? "Bearer", expiresIn, Text("refresh_token"), Text("id_token"), Text("scope"));
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    NumberHandling = JsonNumberHandling.AllowReadingFromString)]
[JsonSerializable(typeof(Discovery))]
[JsonSerializable(typeof(ManagedUser))]
[JsonSerializable(typeof(ManagedUserDetail))]
[JsonSerializable(typeof(UserPage))]
[JsonSerializable(typeof(NewUser))]
[JsonSerializable(typeof(ImportUser))]
[JsonSerializable(typeof(LoginLink))]
[JsonSerializable(typeof(UserEnvelope))]
[JsonSerializable(typeof(SessionsEnvelope))]
[JsonSerializable(typeof(RevokedEnvelope))]
[JsonSerializable(typeof(ImportRequest))]
[JsonSerializable(typeof(ImportResponse))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonElement))]
[JsonSerializable(typeof(AdapterUser))]
[JsonSerializable(typeof(UserUpdatedData))]
[JsonSerializable(typeof(UserLoginData))]
[JsonSerializable(typeof(UserLoginFailedData))]
[JsonSerializable(typeof(UserPasswordChangedData))]
[JsonSerializable(typeof(UserMfaDisabledData))]
[JsonSerializable(typeof(UserSessionsRevokedData))]
[JsonSerializable(typeof(SessionRevokedData))]
[JsonSerializable(typeof(TokenRevokedData))]
[JsonSerializable(typeof(WebhookTestData))]
[JsonSerializable(typeof(OtpRequestedData))]
internal sealed partial class NineJsonContext : JsonSerializerContext;

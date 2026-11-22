using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Nine.Internal;

namespace Nine;

/// <summary>
/// A verified webhook event: <c>{ id, event_type, created_at, tenant, environment, data }</c>. The <see cref="Id"/>
/// is the same on every retry and redelivery, so you can ignore duplicates (see <see cref="EventDeduplicator"/>).
/// </summary>
public sealed class WebhookEvent
{
    private readonly Lazy<ManagedUser?> _user;

    private WebhookEvent(JsonElement json)
    {
        Json = json;
        string? Text(string name) => json.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        Id = Text("id") ?? "";
        EventType = Text("event_type") ?? "";
        Tenant = Text("tenant");
        Environment = Text("environment");
        CreatedAt = Text("created_at") is { } created && DateTimeOffset.TryParse(created, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var at) ? at : null;
        Data = json.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object ? data : EmptyObject;
        _user = new Lazy<ManagedUser?>(() =>
            Data.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object
                ? user.Deserialize(NineJsonContext.Default.ManagedUser)
                : null);
    }

    private static readonly JsonSerializerOptions SnakeCase = new(JsonSerializerDefaults.Web) { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    private static readonly JsonElement EmptyObject = JsonDocument.Parse("{}").RootElement.Clone();

    /// <summary>Parses an event from JSON (already verified: use <see cref="Webhook.Verify(string, string, string?, string, string, TimeSpan?, TimeProvider?)"/>).</summary>
    public static WebhookEvent Parse(JsonElement json)
    {
        if (json.ValueKind != JsonValueKind.Object || !json.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String
            || !json.TryGetProperty("event_type", out var type) || type.ValueKind != JsonValueKind.String)
        {
            throw new NineException("invalid_payload", "the webhook body is not a 9in event", 400);
        }
        return new WebhookEvent(json.Clone());
    }

    /// <summary>The event id (<c>evt_…</c>).</summary>
    public string Id { get; }

    /// <summary>The event name, e.g. <c>user.created</c> (see <see cref="WebhookEventTypes"/>).</summary>
    public string EventType { get; }

    /// <summary>When it happened.</summary>
    public DateTimeOffset? CreatedAt { get; }

    /// <summary>The tenant id (<c>tnt_…</c>).</summary>
    public string? Tenant { get; }

    /// <summary><c>production</c> or <c>sandbox</c>.</summary>
    public string? Environment { get; }

    /// <summary>The event's <c>data</c> object, as sent.</summary>
    public JsonElement Data { get; }

    /// <summary>The whole event, as sent.</summary>
    public JsonElement Json { get; }

    /// <summary>
    /// <c>data.user</c>: the user the event is about, or null (<c>user.login_failed</c>, <c>webhook.test</c>, …).
    /// For <c>user.deleted</c>, the user as it was just before the deletion.
    /// </summary>
    public ManagedUser? User => _user.Value;

    /// <summary><c>data.user.id</c>, or null.</summary>
    public string? UserId =>
        Data.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object && user.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String
            ? id.GetString()
            : null;

    /// <summary>
    /// <c>data</c> as one of the event data types (<see cref="TokenRevokedData"/>, <see cref="UserLoginData"/>, …)
    /// or your own type with snake_case JSON names.
    /// </summary>
    [RequiresUnreferencedCode("Use the overload that takes a JsonTypeInfo for trimmed or AOT apps.")]
    [RequiresDynamicCode("Use the overload that takes a JsonTypeInfo for trimmed or AOT apps.")]
    public T? GetData<T>()
    {
        if (NineJsonContext.Default.GetTypeInfo(typeof(T)) is JsonTypeInfo<T> known)
        {
            return Data.Deserialize(known);
        }
        return Data.Deserialize<T>(SnakeCase);
    }

    /// <summary><c>data</c> deserialised with source-generated metadata (trimming and AOT safe).</summary>
    public T? GetData<T>(JsonTypeInfo<T> typeInfo) => Data.Deserialize(typeInfo);

    /// <inheritdoc/>
    public override string ToString() => $"{EventType} {Id}";
}

/// <summary>Event names of 9in webhooks.</summary>
public static class WebhookEventTypes
{
    /// <summary>A user was created.</summary>
    public const string UserCreated = "user.created";
    /// <summary>A user changed (<see cref="UserUpdatedData.Fields"/>).</summary>
    public const string UserUpdated = "user.updated";
    /// <summary>A user was deleted (<c>data.user</c> is the user before the deletion).</summary>
    public const string UserDeleted = "user.deleted";
    /// <summary>A user signed in.</summary>
    public const string UserLogin = "user.login";
    /// <summary>A sign-in failed.</summary>
    public const string UserLoginFailed = "user.login_failed";
    /// <summary>A password was changed or reset.</summary>
    public const string UserPasswordChanged = "user.password_changed";
    /// <summary>Two-factor authentication was turned on.</summary>
    public const string UserMfaEnabled = "user.mfa_enabled";
    /// <summary>Two-factor authentication was turned off.</summary>
    public const string UserMfaDisabled = "user.mfa_disabled";
    /// <summary>All of a user's sessions were ended.</summary>
    public const string UserSessionsRevoked = "user.sessions_revoked";
    /// <summary>A session was ended.</summary>
    public const string SessionRevoked = "session.revoked";
    /// <summary>A token was revoked.</summary>
    public const string TokenRevoked = "token.revoked";
    /// <summary>A test delivery from the console.</summary>
    public const string WebhookTest = "webhook.test";
}

/// <summary><c>user.updated</c> data.</summary>
public sealed record UserUpdatedData(IReadOnlyList<string>? Fields);

/// <summary><c>user.login</c> data.</summary>
public sealed record UserLoginData(string? Method, string? Ip, string? ClientId, string? Device, string? Country, string? Grant);

/// <summary><c>user.login_failed</c> data (<c>identifier</c> is masked).</summary>
public sealed record UserLoginFailedData(string? Reason, string? Method, string? Grant, string? Identifier, string? Ip, string? ClientId);

/// <summary><c>user.password_changed</c> data.</summary>
public sealed record UserPasswordChangedData(string? Reason);

/// <summary><c>user.mfa_disabled</c> data.</summary>
public sealed record UserMfaDisabledData(string? By);

/// <summary><c>user.sessions_revoked</c> data.</summary>
public sealed record UserSessionsRevokedData(int? Count);

/// <summary><c>session.revoked</c> data.</summary>
public sealed record SessionRevokedData(string? Sid);

/// <summary><c>token.revoked</c> data: <c>token_type</c> is <c>access_token</c> or <c>refresh_token</c>.</summary>
public sealed record TokenRevokedData(string? TokenType, string? ClientId, string? Jti, string? Sid);

/// <summary><c>webhook.test</c> data.</summary>
public sealed record WebhookTestData(string? Message, string? EndpointId);

/// <summary>Adapter <c>otp.requested</c> data: deliver <see cref="Code"/> to <see cref="To"/> yourself.</summary>
public sealed record OtpRequestedData(string? UserId, string? Channel, string? To, string? Code, string? Purpose, DateTimeOffset? ExpiresAt);

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Nine;

/// <summary>A user from your database, in the shape 9in expects (standard claim names). Null fields are left out.</summary>
public sealed record AdapterUser
{
    /// <summary>Creates a user with your id for them.</summary>
    public AdapterUser(string id)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        Id = id;
    }

    /// <summary><c>id</c>: your user id (up to 256 characters).</summary>
    public string Id { get; init; }
    /// <summary><c>email</c>.</summary>
    public string? Email { get; init; }
    /// <summary><c>email_verified</c>.</summary>
    public bool? EmailVerified { get; init; }
    /// <summary><c>phone_number</c> (E.164).</summary>
    public string? PhoneNumber { get; init; }
    /// <summary><c>phone_number_verified</c>.</summary>
    public bool? PhoneNumberVerified { get; init; }
    /// <summary><c>username</c>.</summary>
    public string? Username { get; init; }
    /// <summary><c>name</c>.</summary>
    public string? Name { get; init; }
    /// <summary><c>given_name</c>.</summary>
    public string? GivenName { get; init; }
    /// <summary><c>family_name</c>.</summary>
    public string? FamilyName { get; init; }
    /// <summary><c>picture</c> (an https URL).</summary>
    public string? Picture { get; init; }
    /// <summary><c>locale</c>.</summary>
    public string? Locale { get; init; }
    /// <summary><c>zoneinfo</c>.</summary>
    public string? Zoneinfo { get; init; }
    /// <summary><c>birthdate</c> (<c>YYYY-MM-DD</c>).</summary>
    public string? Birthdate { get; init; }
    /// <summary><c>blocked</c>: true refuses sign-in.</summary>
    public bool? Blocked { get; init; }
    /// <summary><c>metadata</c>: stored on the 9in user.</summary>
    public JsonObject? Metadata { get; init; }
}

/// <summary>What 9in asks about: an email, a username or a phone number, as the user typed it.</summary>
/// <param name="Type"><c>email</c>, <c>username</c> or <c>phone</c>.</param>
/// <param name="Value">The value.</param>
public sealed record AdapterIdentifier(string Type, string Value);

/// <summary>A lookup from 9in: by your user <see cref="Id"/>, or by <see cref="Identifier"/>.</summary>
public sealed record AdapterQuery
{
    /// <summary>Your user id, when 9in looks the user up by id.</summary>
    public string? Id { get; init; }
    /// <summary>The identifier, when 9in looks the user up by email, username or phone.</summary>
    public AdapterIdentifier? Identifier { get; init; }
}

/// <summary>
/// A notification to your adapter's <c>/event</c> endpoint: <c>otp.requested</c> (deliver the code yourself,
/// see <see cref="OtpRequestedData"/>), <c>user.updated</c> and <c>user.password_changed</c> (<c>user_id</c>, <c>fields</c>).
/// <c>data.user_id</c> is your own user id.
/// </summary>
public sealed class AdapterEvent
{
    internal AdapterEvent(JsonElement json)
    {
        Json = json;
        string? Text(string name) => json.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        Id = Text("id") ?? "";
        EventType = Text("event_type") ?? "";
        CreatedAt = Text("created_at") is { } created && DateTimeOffset.TryParse(created, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var at) ? at : null;
        Data = json.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object ? data : JsonDocument.Parse("{}").RootElement.Clone();
    }

    /// <summary>The event id.</summary>
    public string Id { get; }
    /// <summary>The event name, e.g. <c>otp.requested</c>.</summary>
    public string EventType { get; }
    /// <summary>When it happened.</summary>
    public DateTimeOffset? CreatedAt { get; }
    /// <summary>The <c>data</c> object, as sent.</summary>
    public JsonElement Data { get; }
    /// <summary>The whole event, as sent.</summary>
    public JsonElement Json { get; }

    /// <summary><c>data.user_id</c>: your user id.</summary>
    public string? UserId => Data.TryGetProperty("user_id", out var id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null;

    /// <summary><c>data</c> of an <c>otp.requested</c> event, or null for other events.</summary>
    public OtpRequestedData? Otp => EventType == "otp.requested" ? Data.Deserialize(Internal.NineJsonContext.Default.OtpRequestedData) : null;

    /// <inheritdoc/>
    public override string ToString() => $"{EventType} {Id}";
}

/// <summary>
/// The answer to a password check: a user (return the <see cref="AdapterUser"/> itself, it converts),
/// <see cref="Invalid"/> or <see cref="Blocked"/>.
/// </summary>
public sealed class AdapterResult
{
    private AdapterResult(AdapterUser? user, string? error)
    {
        User = user;
        Error = error;
    }

    /// <summary>Unknown user or wrong password (9in doesn't tell them apart). Answered 401 <c>invalid_credentials</c>.</summary>
    public static AdapterResult Invalid { get; } = new(null, "invalid_credentials");

    /// <summary>The user may not sign in. Answered 403 <c>blocked</c>.</summary>
    public static AdapterResult Blocked { get; } = new(null, "blocked");

    /// <summary>The password is right: this is the user.</summary>
    public static AdapterResult Success(AdapterUser user) => new(user ?? throw new ArgumentNullException(nameof(user)), null);

    /// <summary>The user, on success.</summary>
    public AdapterUser? User { get; }

    /// <summary><c>invalid_credentials</c> or <c>blocked</c>, on failure.</summary>
    public string? Error { get; }

    /// <summary>A user is a successful result.</summary>
    public static implicit operator AdapterResult(AdapterUser user) => Success(user);
}

/// <summary>
/// Your user database, as 9in sees it (adapter protocol v2). Implement it and serve it with
/// <see cref="AdapterHandler"/> (or <c>MapNineAdapter&lt;T&gt;()</c> in ASP.NET Core).
/// </summary>
public interface IAdapter
{
    /// <summary>Checks a password. Return the user, <see cref="AdapterResult.Invalid"/> or <see cref="AdapterResult.Blocked"/>.</summary>
    Task<AdapterResult> AuthenticateAsync(AdapterIdentifier identifier, string password, CancellationToken cancellationToken);

    /// <summary>Looks a user up by id or identifier; null when there is none.</summary>
    Task<AdapterUser?> FindUserAsync(AdapterQuery query, CancellationToken cancellationToken);

    /// <summary>Notifications. The default does nothing.</summary>
    Task OnEventAsync(AdapterEvent adapterEvent, CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>A request to the adapter, as your web framework received it.</summary>
/// <param name="Method">The HTTP method.</param>
/// <param name="Path">The request path exactly as 9in called it, without the query string (e.g. <c>/nine/authenticate</c>).</param>
/// <param name="Headers">The request headers (names in any case).</param>
/// <param name="Body">The raw body.</param>
public sealed record AdapterRequest(string Method, string Path, IEnumerable<KeyValuePair<string, string>> Headers, ReadOnlyMemory<byte> Body)
{
    internal string? Header(string name) => Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
}

/// <summary>The signed answer to send back.</summary>
/// <param name="StatusCode">The HTTP status.</param>
/// <param name="Headers">Headers to set (<c>9in-signature</c>, <c>Content-Type</c>, …).</param>
/// <param name="Body">The body (empty for 204).</param>
public sealed record AdapterResponse(int StatusCode, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    /// <summary>The body as text.</summary>
    [JsonIgnore]
    public string BodyText => System.Text.Encoding.UTF8.GetString(Body);
}

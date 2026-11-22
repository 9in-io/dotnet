using System.Text.Json.Nodes;

namespace Nine;

/// <summary>
/// The fields to change with <see cref="ManagementClient.UpdateUserAsync(string, UserChanges, CancellationToken)"/>.
/// Only the properties you set are sent, so setting one to null clears it on the server:
/// <code>new UserChanges { PhoneNumber = "+447700900000", PhoneNumberVerified = true, Nickname = null }</code>
/// <c>Metadata</c> replaces the whole object.
/// </summary>
public sealed class UserChanges
{
    private readonly Dictionary<string, JsonNode?> _fields = new(StringComparer.Ordinal);

    /// <summary><c>email</c>.</summary>
    public string? Email { get => Text("email"); set => Set("email", value); }
    /// <summary><c>email_verified</c>.</summary>
    public bool? EmailVerified { get => Flag("email_verified"); set => Set("email_verified", value); }
    /// <summary><c>phone_number</c> (E.164).</summary>
    public string? PhoneNumber { get => Text("phone_number"); set => Set("phone_number", value); }
    /// <summary><c>phone_number_verified</c>.</summary>
    public bool? PhoneNumberVerified { get => Flag("phone_number_verified"); set => Set("phone_number_verified", value); }
    /// <summary><c>username</c>.</summary>
    public string? Username { get => Text("username"); set => Set("username", value); }
    /// <summary><c>name</c>.</summary>
    public string? Name { get => Text("name"); set => Set("name", value); }
    /// <summary><c>given_name</c>.</summary>
    public string? GivenName { get => Text("given_name"); set => Set("given_name", value); }
    /// <summary><c>family_name</c>.</summary>
    public string? FamilyName { get => Text("family_name"); set => Set("family_name", value); }
    /// <summary><c>picture</c>.</summary>
    public string? Picture { get => Text("picture"); set => Set("picture", value); }
    /// <summary><c>locale</c>.</summary>
    public string? Locale { get => Text("locale"); set => Set("locale", value); }
    /// <summary><c>zoneinfo</c>.</summary>
    public string? Zoneinfo { get => Text("zoneinfo"); set => Set("zoneinfo", value); }
    /// <summary><c>birthdate</c> (<c>YYYY-MM-DD</c>).</summary>
    public string? Birthdate { get => Text("birthdate"); set => Set("birthdate", value); }
    /// <summary><c>blocked</c>.</summary>
    public bool? Blocked { get => Flag("blocked"); set => Set("blocked", value); }
    /// <summary><c>password</c>: sets a new password.</summary>
    public string? Password { get => Text("password"); set => Set("password", value); }
    /// <summary><c>password_hash</c>.</summary>
    public string? PasswordHash { get => Text("password_hash"); set => Set("password_hash", value); }

    /// <summary><c>metadata</c>: replaces the whole object.</summary>
    public JsonObject? Metadata
    {
        get => _fields.TryGetValue("metadata", out var node) ? node as JsonObject : null;
        set => _fields["metadata"] = value?.DeepClone();
    }

    /// <summary>Sets any field by its wire name (for fields this SDK doesn't list yet).</summary>
    public UserChanges Set(string field, JsonNode? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(field);
        _fields[field] = value;
        return this;
    }

    /// <summary>The wire names of the fields that will be sent.</summary>
    public IReadOnlyCollection<string> Fields => _fields.Keys;

    private void Set(string field, string? value) => _fields[field] = value is null ? null : JsonValue.Create(value);

    private void Set(string field, bool? value) => _fields[field] = value is null ? null : JsonValue.Create(value.Value);

    private string? Text(string field) => _fields.TryGetValue(field, out var node) && node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private bool? Flag(string field) => _fields.TryGetValue(field, out var node) && node is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null;

    internal JsonObject ToJson()
    {
        var json = new JsonObject();
        foreach (var (name, value) in _fields)
        {
            json[name] = value?.DeepClone();
        }
        return json;
    }
}

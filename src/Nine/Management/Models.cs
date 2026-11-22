using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Nine;

/// <summary>A user as the Management API and webhooks send it (snake_case on the wire, ISO 8601 UTC times).</summary>
public sealed record ManagedUser
{
    /// <summary><c>id</c> (<c>usr_…</c>, or the id kept from an import).</summary>
    public string Id { get; init; } = "";
    /// <summary><c>email</c>.</summary>
    public string? Email { get; init; }
    /// <summary><c>email_verified</c>.</summary>
    public bool EmailVerified { get; init; }
    /// <summary><c>phone_number</c> (E.164).</summary>
    public string? PhoneNumber { get; init; }
    /// <summary><c>phone_number_verified</c>.</summary>
    public bool PhoneNumberVerified { get; init; }
    /// <summary><c>username</c>.</summary>
    public string? Username { get; init; }
    /// <summary><c>preferred_username</c>.</summary>
    public string? PreferredUsername { get; init; }
    /// <summary><c>name</c>.</summary>
    public string? Name { get; init; }
    /// <summary><c>given_name</c>.</summary>
    public string? GivenName { get; init; }
    /// <summary><c>middle_name</c>.</summary>
    public string? MiddleName { get; init; }
    /// <summary><c>family_name</c>.</summary>
    public string? FamilyName { get; init; }
    /// <summary><c>nickname</c>.</summary>
    public string? Nickname { get; init; }
    /// <summary><c>gender</c>.</summary>
    public string? Gender { get; init; }
    /// <summary><c>website</c>.</summary>
    public string? Website { get; init; }
    /// <summary><c>picture</c>.</summary>
    public string? Picture { get; init; }
    /// <summary><c>locale</c>.</summary>
    public string? Locale { get; init; }
    /// <summary><c>zoneinfo</c>.</summary>
    public string? Zoneinfo { get; init; }
    /// <summary><c>birthdate</c> (<c>YYYY-MM-DD</c>).</summary>
    public string? Birthdate { get; init; }
    /// <summary><c>blocked</c>: a blocked user can't sign in.</summary>
    public bool Blocked { get; init; }
    /// <summary><c>metadata</c>: your own data, passed through unchanged.</summary>
    public JsonObject? Metadata { get; init; }
    /// <summary><c>created_at</c>.</summary>
    public DateTimeOffset? CreatedAt { get; init; }
    /// <summary><c>updated_at</c>.</summary>
    public DateTimeOffset? UpdatedAt { get; init; }
    /// <summary><c>last_login_at</c>.</summary>
    public DateTimeOffset? LastLoginAt { get; init; }
    /// <summary><c>login_count</c>.</summary>
    public int LoginCount { get; init; }
    /// <summary>Fields this SDK doesn't know yet, unchanged.</summary>
    [JsonExtensionData] public IDictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>An active sign-in session (<c>sid</c> is the <c>sid</c> claim of its tokens).</summary>
public sealed record ManagedSession
{
    /// <summary><c>sid</c>.</summary>
    public string Sid { get; init; } = "";
    /// <summary><c>user_id</c>.</summary>
    public string? UserId { get; init; }
    /// <summary><c>auth_time</c>: when the user signed in.</summary>
    public DateTimeOffset? AuthTime { get; init; }
    /// <summary><c>amr</c>: how (<c>pwd</c>, <c>otp</c>, <c>social</c>, <c>mfa</c>, …).</summary>
    public IReadOnlyList<string>? Amr { get; init; }
    /// <summary><c>ip</c>.</summary>
    public string? Ip { get; init; }
    /// <summary><c>user_agent</c>.</summary>
    public string? UserAgent { get; init; }
    /// <summary><c>created_at</c>.</summary>
    public DateTimeOffset? CreatedAt { get; init; }
    /// <summary><c>last_seen_at</c>.</summary>
    public DateTimeOffset? LastSeenAt { get; init; }
    /// <summary><c>expires_at</c>.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }
    /// <summary>Fields this SDK doesn't know yet.</summary>
    [JsonExtensionData] public IDictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>A linked sign-in of a user (<c>social:google</c>, <c>enterprise:&lt;id&gt;</c>, <c>adapter</c>, …).</summary>
public sealed record ManagedIdentity
{
    /// <summary><c>connection</c>.</summary>
    public string Connection { get; init; } = "";
    /// <summary><c>subject</c>: the user's id at that connection.</summary>
    public string Subject { get; init; } = "";
    /// <summary><c>profile</c>: what the provider returned, unchanged.</summary>
    public JsonObject? Profile { get; init; }
    /// <summary><c>created_at</c>.</summary>
    public DateTimeOffset? CreatedAt { get; init; }
}

/// <summary>Two-factor state of a user.</summary>
public sealed record MfaStatus
{
    /// <summary><c>enabled</c>.</summary>
    public bool Enabled { get; init; }
    /// <summary><c>enabled_at</c>.</summary>
    public DateTimeOffset? EnabledAt { get; init; }
    /// <summary><c>recovery_codes_left</c>.</summary>
    public int? RecoveryCodesLeft { get; init; }
}

/// <summary>What <see cref="ManagementClient.GetUserAsync"/> returns: the user with identities, sessions and two-factor state.</summary>
public sealed record ManagedUserDetail
{
    /// <summary><c>user</c>.</summary>
    public ManagedUser User { get; init; } = new();
    /// <summary><c>identities</c>.</summary>
    public IReadOnlyList<ManagedIdentity> Identities { get; init; } = [];
    /// <summary><c>sessions</c>: the active ones.</summary>
    public IReadOnlyList<ManagedSession> Sessions { get; init; } = [];
    /// <summary><c>has_password</c>.</summary>
    public bool HasPassword { get; init; }
    /// <summary><c>mfa</c>.</summary>
    public MfaStatus Mfa { get; init; } = new();
}

/// <summary>A page of users.</summary>
public sealed record UserPage
{
    /// <summary><c>users</c>.</summary>
    public IReadOnlyList<ManagedUser> Users { get; init; } = [];
    /// <summary><c>next_cursor</c>: pass it to get the next page; null on the last one.</summary>
    public string? NextCursor { get; init; }
    /// <summary><c>total</c>, when the server includes it.</summary>
    public int? Total { get; init; }
}

/// <summary>A single-use sign-in URL.</summary>
public sealed record LoginLink
{
    /// <summary><c>url</c>.</summary>
    public string Url { get; init; } = "";
    /// <summary><c>expires_at</c>.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}

/// <summary>Fields of a new user (<see cref="ManagementClient.CreateUserAsync"/>). Null properties are not sent.</summary>
public record NewUser
{
    /// <summary><c>email</c>.</summary>
    public string? Email { get; init; }
    /// <summary><c>email_verified</c>.</summary>
    public bool? EmailVerified { get; init; }
    /// <summary><c>phone_number</c> (E.164, e.g. +447700900000).</summary>
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
    /// <summary><c>picture</c>.</summary>
    public string? Picture { get; init; }
    /// <summary><c>locale</c>.</summary>
    public string? Locale { get; init; }
    /// <summary><c>zoneinfo</c>.</summary>
    public string? Zoneinfo { get; init; }
    /// <summary><c>birthdate</c>.</summary>
    public string? Birthdate { get; init; }
    /// <summary><c>metadata</c>.</summary>
    public JsonObject? Metadata { get; init; }
    /// <summary><c>blocked</c>.</summary>
    public bool? Blocked { get; init; }
    /// <summary><c>password</c>: a plain password.</summary>
    public string? Password { get; init; }
    /// <summary><c>password_hash</c>: bcrypt, argon2, PBKDF2 or Firebase scrypt, so users keep their password.</summary>
    public string? PasswordHash { get; init; }
}

/// <summary>One record for <see cref="ManagementClient.ImportUsersAsync"/>: a <see cref="NewUser"/> plus what an import may carry over.</summary>
public sealed record ImportUser : NewUser
{
    /// <summary><c>id</c>: keep the id from your old system (letters, digits and <c>| _ . : @ + -</c>, max 128).</summary>
    public string? Id { get; init; }
    /// <summary><c>identities</c>: linked sign-ins, e.g. <c>social:google</c> and its subject.</summary>
    public IReadOnlyList<ImportIdentity>? Identities { get; init; }
    /// <summary><c>created_at</c>: the original date.</summary>
    public DateTimeOffset? CreatedAt { get; init; }
    /// <summary><c>last_login_at</c>: the original date.</summary>
    public DateTimeOffset? LastLoginAt { get; init; }
}

/// <summary>A linked sign-in to import.</summary>
/// <param name="Connection">e.g. <c>social:google</c>.</param>
/// <param name="Subject">The user's id at that connection.</param>
public sealed record ImportIdentity(string Connection, string Subject);

/// <summary>Options of <see cref="ManagementClient.ImportUsersAsync"/>.</summary>
public sealed record ImportOptions
{
    /// <summary><c>on_conflict</c>: <c>skip</c> (default on the server) or <c>update</c>.</summary>
    public string? OnConflict { get; init; }
    /// <summary><c>source</c>: where the users come from (<c>auth0</c>, <c>firebase</c>, …), for the activity log.</summary>
    public string? Source { get; init; }
}

/// <summary>The result for one imported record, in order.</summary>
public sealed record ImportResult
{
    /// <summary><c>index</c> of the record.</summary>
    public int Index { get; init; }
    /// <summary><c>ok</c>.</summary>
    public bool Ok { get; init; }
    /// <summary><c>status</c>: <c>created</c>, <c>updated</c>, <c>skipped</c> or <c>failed</c>.</summary>
    public string Status { get; init; } = "";
    /// <summary><c>id</c> of the user (not for failures).</summary>
    public string? Id { get; init; }
    /// <summary><c>reason</c> a record was skipped.</summary>
    public string? Reason { get; init; }
    /// <summary><c>error</c> of a failure.</summary>
    public string? Error { get; init; }
    /// <summary><c>details</c> of a failure.</summary>
    public JsonElement? Details { get; init; }
}

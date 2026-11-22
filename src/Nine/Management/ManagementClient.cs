using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Nine.Internal;

namespace Nine;

/// <summary>Settings of a <see cref="ManagementClient"/>.</summary>
public sealed class ManagementClientOptions
{
    /// <summary>Your tenant's issuer (production or sandbox: the API manages that environment's users).</summary>
    public string Issuer { get; set; } = "";
    /// <summary>A confidential application granted <c>management:*</c> scopes in the console.</summary>
    public string ClientId { get; set; } = "";
    /// <summary>Its client secret.</summary>
    public string ClientSecret { get; set; } = "";
    /// <summary>Accept a plain-http issuer other than localhost (development only).</summary>
    public bool AllowInsecureIssuer { get; set; }
    /// <summary>Timeout of each request. Default 10 seconds.</summary>
    public TimeSpan Timeout { get; set; } = NineHttp.DefaultTimeout;
    /// <summary>The clock (tests).</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary><c>NINE_ISSUER</c>, <c>NINE_CLIENT_ID</c>, <c>NINE_CLIENT_SECRET</c> and <c>NINE_ALLOW_INSECURE_ISSUER</c>.</summary>
    public static ManagementClientOptions FromEnvironment() => new()
    {
        Issuer = NineEnvironment.Get("ISSUER") ?? "",
        ClientId = NineEnvironment.Get("CLIENT_ID") ?? "",
        ClientSecret = NineEnvironment.Get("CLIENT_SECRET") ?? "",
        AllowInsecureIssuer = NineEnvironment.GetBool("ALLOW_INSECURE_ISSUER"),
    };
}

/// <summary>
/// The Management API (<c>/api/v1</c>): users, sessions, single-use sign-in links and bulk import, with
/// a client-credentials token per scope (cached until shortly before it expires), so an application
/// granted only some management scopes works. Wire data is 9in's snake_case, unchanged. Errors are
/// <see cref="NineException"/>s with the server's <c>error</c>, <c>error_description</c> and status.
/// Safe to share: create one and keep it.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA1001", Justification = "The semaphore never allocates a wait handle; the client lives as long as the app.")]
public sealed class ManagementClient
{
    private const string Read = "management:users:read";
    private const string Write = "management:users:write";
    private const string Sessions = "management:sessions:write";

    private readonly NineHttp _http;
    private readonly TimeProvider _time;
    private readonly ClientAuth _client;
    private readonly ConcurrentDictionary<string, (string Token, DateTimeOffset ExpiresAt)> _tokens = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    /// <summary>Creates a client. Pass an <see cref="HttpClient"/> from <c>IHttpClientFactory</c>, or none for a shared default.</summary>
    public ManagementClient(ManagementClientOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        Issuer = Nine.Issuer.Normalize(options.Issuer, options.AllowInsecureIssuer);
        if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new NineException("invalid_options", "ClientId and ClientSecret are required (a confidential application with management scopes)");
        }
        _client = new ClientAuth(options.ClientId, options.ClientSecret);
        _http = new NineHttp(httpClient, options.Timeout);
        _time = options.TimeProvider;
    }

    /// <summary>Creates a client from <see cref="ManagementClientOptions.FromEnvironment"/>.</summary>
    public static ManagementClient FromEnvironment(HttpClient? httpClient = null) => new(ManagementClientOptions.FromEnvironment(), httpClient);

    /// <summary>The normalised issuer.</summary>
    public string Issuer { get; }

    /// <summary>A page of users, newest first. <paramref name="query"/> searches email, phone, username and name.</summary>
    public Task<UserPage> ListUsersAsync(string? query = null, string? cursor = null, int? limit = null, CancellationToken cancellationToken = default)
    {
        var parameters = new List<KeyValuePair<string, string>>();
        if (!string.IsNullOrEmpty(query))
        {
            parameters.Add(new("q", query));
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            parameters.Add(new("cursor", cursor));
        }
        if (limit is { } l)
        {
            parameters.Add(new("limit", l.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
        return RequestAsync(HttpMethod.Get, Query.Append("/users", parameters), null, NineJsonContext.Default.UserPage, cancellationToken)!;
    }

    /// <summary>Every user, page after page.</summary>
    public async IAsyncEnumerable<ManagedUser> ListAllUsersAsync(string? query = null, int? pageSize = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string? cursor = null;
        do
        {
            var page = await ListUsersAsync(query, cursor, pageSize, cancellationToken).ConfigureAwait(false);
            foreach (var user in page.Users)
            {
                yield return user;
            }
            cursor = page.NextCursor;
        }
        while (!string.IsNullOrEmpty(cursor));
    }

    /// <summary>The user with their identities, active sessions and two-factor state. Throws <c>not_found</c> (404).</summary>
    public Task<ManagedUserDetail> GetUserAsync(string userId, CancellationToken cancellationToken = default) =>
        RequestAsync(HttpMethod.Get, "/users/" + Id(userId), null, NineJsonContext.Default.ManagedUserDetail, cancellationToken)!;

    /// <summary>Looks a user up by <c>email</c>, <c>phone_number</c> (E.164) or <c>username</c>; null when there is none.</summary>
    public async Task<ManagedUser?> FindUserAsync(string field, string value, CancellationToken cancellationToken = default)
    {
        if (field is not ("email" or "phone_number" or "username"))
        {
            throw new ArgumentException("field is email, phone_number or username", nameof(field));
        }
        ArgumentException.ThrowIfNullOrEmpty(value);
        try
        {
            var found = await RequestAsync(HttpMethod.Get, Query.Append("/users/lookup", [new(field, value)]), null, NineJsonContext.Default.UserEnvelope, cancellationToken).ConfigureAwait(false);
            return found?.User;
        }
        catch (NineException e) when (e.StatusCode == 404)
        {
            return null;
        }
    }

    /// <summary>The user with this email, or null.</summary>
    public Task<ManagedUser?> FindUserByEmailAsync(string email, CancellationToken cancellationToken = default) => FindUserAsync("email", email, cancellationToken);

    /// <summary>The user with this phone number (E.164), or null.</summary>
    public Task<ManagedUser?> FindUserByPhoneNumberAsync(string phoneNumber, CancellationToken cancellationToken = default) => FindUserAsync("phone_number", phoneNumber, cancellationToken);

    /// <summary>The user with this username, or null.</summary>
    public Task<ManagedUser?> FindUserByUsernameAsync(string username, CancellationToken cancellationToken = default) => FindUserAsync("username", username, cancellationToken);

    /// <summary>Creates a user. Unknown or misspelt fields are refused by the server (<c>invalid_user</c>).</summary>
    public async Task<ManagedUser> CreateUserAsync(NewUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        var body = JsonSerializer.SerializeToUtf8Bytes(user, NineJsonContext.Default.NewUser);
        return (await RequestAsync(HttpMethod.Post, "/users", body, NineJsonContext.Default.UserEnvelope, cancellationToken).ConfigureAwait(false))!.User;
    }

    /// <summary>
    /// Bulk import, up to 500 users per call. Records may keep their old id and carry password hashes,
    /// social identities and original dates. Results are per record, in order; one bad record doesn't stop the others.
    /// </summary>
    public async Task<IReadOnlyList<ImportResult>> ImportUsersAsync(IEnumerable<ImportUser> users, ImportOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(users);
        var request = new ImportRequest { Users = users.ToList(), OnConflict = options?.OnConflict, Source = options?.Source };
        var body = JsonSerializer.SerializeToUtf8Bytes(request, NineJsonContext.Default.ImportRequest);
        return (await RequestAsync(HttpMethod.Post, "/users/import", body, NineJsonContext.Default.ImportResponse, cancellationToken).ConfigureAwait(false))!.Results;
    }

    /// <summary>Changes only the fields you set on <paramref name="changes"/>; <c>metadata</c> is replaced as a whole.</summary>
    public async Task<ManagedUser> UpdateUserAsync(string userId, UserChanges changes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(changes);
        var body = JsonSerializer.SerializeToUtf8Bytes(changes.ToJson(), NineJsonContext.Default.JsonObject);
        return (await RequestAsync(HttpMethod.Patch, "/users/" + Id(userId), body, NineJsonContext.Default.UserEnvelope, cancellationToken).ConfigureAwait(false))!.User;
    }

    /// <summary>Changes the fields in <paramref name="changes"/> (wire names), as given.</summary>
    public async Task<ManagedUser> UpdateUserAsync(string userId, JsonObject changes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(changes);
        var body = JsonSerializer.SerializeToUtf8Bytes(changes, NineJsonContext.Default.JsonObject);
        return (await RequestAsync(HttpMethod.Patch, "/users/" + Id(userId), body, NineJsonContext.Default.UserEnvelope, cancellationToken).ConfigureAwait(false))!.User;
    }

    /// <summary>Deletes a user.</summary>
    public Task DeleteUserAsync(string userId, CancellationToken cancellationToken = default) =>
        RequestAsync<JsonElement>(HttpMethod.Delete, "/users/" + Id(userId), null, null, cancellationToken);

    /// <summary>Blocks a user: they can't sign in, and their sessions and tokens stop working.</summary>
    public Task<ManagedUser> BlockUserAsync(string userId, CancellationToken cancellationToken = default) =>
        UpdateUserAsync(userId, new UserChanges { Blocked = true }, cancellationToken);

    /// <summary>Unblocks a user.</summary>
    public Task<ManagedUser> UnblockUserAsync(string userId, CancellationToken cancellationToken = default) =>
        UpdateUserAsync(userId, new UserChanges { Blocked = false }, cancellationToken);

    /// <summary>
    /// A single-use URL that signs the user in (magic links, handing a signed-in user over from your app).
    /// <paramref name="returnTo"/> must be a registered redirect URL of one of your applications or a path
    /// on the login domain. Two-factor authentication still applies.
    /// </summary>
    public async Task<LoginLink> CreateLoginLinkAsync(string userId, string? returnTo = null, TimeSpan? ttl = null, CancellationToken cancellationToken = default)
    {
        var request = new JsonObject();
        if (!string.IsNullOrEmpty(returnTo))
        {
            request["return_to"] = returnTo;
        }
        if (ttl is { } t)
        {
            request["ttl_seconds"] = (long)t.TotalSeconds;
        }
        var body = JsonSerializer.SerializeToUtf8Bytes(request, NineJsonContext.Default.JsonObject);
        return (await RequestAsync(HttpMethod.Post, $"/users/{Id(userId)}/login-link", body, NineJsonContext.Default.LoginLink, cancellationToken).ConfigureAwait(false))!;
    }

    /// <summary>The user's active sessions, most recently used first.</summary>
    public async Task<IReadOnlyList<ManagedSession>> ListUserSessionsAsync(string userId, CancellationToken cancellationToken = default) =>
        (await RequestAsync(HttpMethod.Get, $"/users/{Id(userId)}/sessions", null, NineJsonContext.Default.SessionsEnvelope, cancellationToken).ConfigureAwait(false))!.Sessions;

    /// <summary>Signs the user out everywhere; returns how many sessions ended.</summary>
    public async Task<int> RevokeUserSessionsAsync(string userId, CancellationToken cancellationToken = default) =>
        (await RequestAsync(HttpMethod.Delete, $"/users/{Id(userId)}/sessions", null, NineJsonContext.Default.RevokedEnvelope, cancellationToken).ConfigureAwait(false))?.Revoked ?? 0;

    /// <summary>Ends one session (its <c>sid</c>) and every token issued under it.</summary>
    public Task RevokeSessionAsync(string sessionId, CancellationToken cancellationToken = default) =>
        RequestAsync<JsonElement>(HttpMethod.Delete, "/sessions/" + Id(sessionId), null, null, cancellationToken);

    private static string Id(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        return Uri.EscapeDataString(value);
    }

    private static string ScopeFor(HttpMethod method, string path) =>
        method == HttpMethod.Get ? Read : path.Contains("/sessions", StringComparison.Ordinal) ? Sessions : Write;

    private async Task<T?> RequestAsync<T>(HttpMethod method, string path, byte[]? body, JsonTypeInfo<T>? type, CancellationToken cancellationToken)
    {
        var scope = ScopeFor(method, path);
        var token = await AccessTokenAsync(scope, cancellationToken).ConfigureAwait(false);
        var result = await _http.SendJsonAsync(method, Issuer + "/api/v1" + path, token, body, cancellationToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            if (result.Status == 401)
            {
                _tokens.TryRemove(scope, out _); // revoked or rotated secret: get a new token next time
            }
            throw result.Error("request_failed");
        }
        if (type is null || result.Status == 204 || result.Body.Length == 0)
        {
            return default;
        }
        try
        {
            return JsonSerializer.Deserialize(result.Body, type);
        }
        catch (JsonException e)
        {
            throw new NineException("invalid_response", $"unexpected answer from {path}", result.Status, e);
        }
    }

    private async Task<string> AccessTokenAsync(string scope, CancellationToken cancellationToken)
    {
        if (_tokens.TryGetValue(scope, out var cached) && cached.ExpiresAt - TimeSpan.FromSeconds(30) > _time.GetUtcNow())
        {
            return cached.Token;
        }
        await _tokenLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_tokens.TryGetValue(scope, out cached) && cached.ExpiresAt - TimeSpan.FromSeconds(30) > _time.GetUtcNow())
            {
                return cached.Token;
            }
            var discovery = await DiscoveryCache.GetAsync(Issuer, _http, _time, cancellationToken).ConfigureAwait(false);
            var result = await _http.PostFormAsync(discovery.TokenEndpoint, [new("grant_type", "client_credentials"), new("scope", scope)], _client, cancellationToken).ConfigureAwait(false);
            if (!result.IsSuccess)
            {
                throw result.Error("request_failed");
            }
            var response = TokenResponse.Parse(result);
            var expiresAt = _time.GetUtcNow() + TimeSpan.FromSeconds(response.ExpiresIn ?? 300);
            _tokens[scope] = (response.AccessToken, expiresAt);
            return response.AccessToken;
        }
        finally
        {
            _tokenLock.Release();
        }
    }
}

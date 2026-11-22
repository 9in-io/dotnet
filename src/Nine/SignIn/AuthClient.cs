using System.Globalization;
using System.Text.Json;
using Nine.Internal;

namespace Nine;

/// <summary>Settings of an <see cref="AuthClient"/>.</summary>
public sealed class AuthClientOptions
{
    /// <summary>Your tenant's issuer, e.g. <c>https://acme.9in.io</c> or your custom login domain.</summary>
    public string Issuer { get; set; } = "";
    /// <summary>The application's client ID.</summary>
    public string ClientId { get; set; } = "";
    /// <summary>The client secret of a confidential application (sent with HTTP Basic). Leave empty for a public one (PKCE only).</summary>
    public string? ClientSecret { get; set; }
    /// <summary>Your callback URL, exactly as registered on the application.</summary>
    public string? RedirectUri { get; set; }
    /// <summary>Default <c>openid profile email offline_access</c> (<c>offline_access</c> gives a refresh token).</summary>
    public IList<string> Scopes { get; set; } = ["openid", "profile", "email", "offline_access"];
    /// <summary>An API identifier, to get access tokens for that API (<c>aud</c>).</summary>
    public string? Audience { get; set; }
    /// <summary>Language of the hosted pages (<c>ui_locales</c>), e.g. <c>de</c>.</summary>
    public string? Locale { get; set; }
    /// <summary>How long a started sign-in stays valid. Default 15 minutes.</summary>
    public TimeSpan LoginTimeout { get; set; } = TimeSpan.FromMinutes(15);
    /// <summary>Clock skew allowed on ID token times. Default 30 seconds.</summary>
    public TimeSpan Leeway { get; set; } = TimeSpan.FromSeconds(30);
    /// <summary>
    /// Where used <c>state</c> values are remembered, so a callback can't be replayed. Default: in this
    /// process; pass a shared cache when several servers handle callbacks.
    /// </summary>
    public INineCache? StateCache { get; set; }
    /// <summary>Accept a plain-http issuer other than localhost (development only).</summary>
    public bool AllowInsecureIssuer { get; set; }
    /// <summary>Timeout of each request to 9in. Default 10 seconds.</summary>
    public TimeSpan Timeout { get; set; } = NineHttp.DefaultTimeout;
    /// <summary>The clock (tests).</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// Settings from <c>NINE_ISSUER</c>, <c>NINE_CLIENT_ID</c>, <c>NINE_CLIENT_SECRET</c>, <c>NINE_REDIRECT_URI</c>,
    /// <c>NINE_AUDIENCE</c> and <c>NINE_ALLOW_INSECURE_ISSUER</c>.
    /// </summary>
    public static AuthClientOptions FromEnvironment() => new()
    {
        Issuer = NineEnvironment.Get("ISSUER") ?? "",
        ClientId = NineEnvironment.Get("CLIENT_ID") ?? "",
        ClientSecret = NineEnvironment.Get("CLIENT_SECRET"),
        RedirectUri = NineEnvironment.Get("REDIRECT_URI"),
        Audience = NineEnvironment.Get("AUDIENCE"),
        AllowInsecureIssuer = NineEnvironment.GetBool("ALLOW_INSECURE_ISSUER"),
    };
}

/// <summary>
/// Sign-in with 9in for any client: confidential (a web app with a client secret) or public (PKCE only:
/// desktop apps, CLIs). Authorization code + PKCE S256 with endpoints from discovery, single-use
/// <c>state</c> compared in constant time, <c>nonce</c>, the RFC 9207 <c>iss</c> check, ID tokens verified
/// against the JWKS, refresh-token rotation, revocation, RP-initiated logout, userinfo, client
/// credentials and the device flow (RFC 8628).
/// <code>
/// var login = await auth.CreateLoginAsync(new LoginOptions { ReturnTo = "/dashboard" });
/// // keep login.Pending (e.g. login.Pending.ToJson() in the session), redirect to login.Url
/// var tokens = await auth.HandleCallbackAsync(callbackUrl, pending);
/// </code>
/// Safe to share: create one and keep it.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA1001", Justification = "The semaphore never allocates a wait handle; the client lives as long as the app.")]
public sealed class AuthClient
{
    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method",
    };

    private readonly AuthClientOptions _options;
    private readonly NineHttp _http;
    private readonly TimeProvider _time;
    private readonly ClientAuth _client;
    private readonly TokenVerifier _verifier;
    private readonly INineCache _states;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, TokenSet> _clientTokens = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _clientTokenLock = new(1, 1);

    /// <summary>Creates a client. Pass an <see cref="HttpClient"/> from <c>IHttpClientFactory</c>, or none for a shared default.</summary>
    public AuthClient(AuthClientOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.ClientId))
        {
            throw new NineException("invalid_options", "ClientId is required (NINE_CLIENT_ID)");
        }
        _options = options;
        Issuer = Nine.Issuer.Normalize(options.Issuer, options.AllowInsecureIssuer);
        _http = new NineHttp(httpClient, options.Timeout);
        _time = options.TimeProvider;
        _client = new ClientAuth(options.ClientId, string.IsNullOrEmpty(options.ClientSecret) ? null : options.ClientSecret);
        _states = options.StateCache ?? new NineMemoryCache(timeProvider: _time);
        var verifierOptions = new TokenVerifierOptions
        {
            Issuer = Issuer,
            AllowInsecureIssuer = options.AllowInsecureIssuer,
            Leeway = options.Leeway,
            Timeout = options.Timeout,
            TimeProvider = _time,
        };
        _verifier = new TokenVerifier(verifierOptions, httpClient);
    }

    /// <summary>Creates a client from <see cref="AuthClientOptions.FromEnvironment"/>.</summary>
    public static AuthClient FromEnvironment(HttpClient? httpClient = null) => new(AuthClientOptions.FromEnvironment(), httpClient);

    /// <summary>The normalised issuer.</summary>
    public string Issuer { get; }

    /// <summary>The client ID.</summary>
    public string ClientId => _client.ClientId;

    /// <summary>Whether the client has a secret (a confidential application).</summary>
    public bool IsConfidential => _client.Secret is not null;

    /// <summary>The tenant's discovery document (cached).</summary>
    public Task<Discovery> GetDiscoveryAsync(CancellationToken cancellationToken = default) => DiscoveryCache.GetAsync(Issuer, _http, _time, cancellationToken);

    /// <summary>
    /// Starts a sign-in: the authorization URL to send the browser to, and the <see cref="PendingLogin"/> to
    /// keep (secret: in the server-side session or encrypted) until the callback.
    /// </summary>
    public async Task<Login> CreateLoginAsync(LoginOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new LoginOptions();
        var redirectUri = options.RedirectUri ?? _options.RedirectUri;
        if (string.IsNullOrEmpty(redirectUri))
        {
            throw new NineException("invalid_options", "RedirectUri is required (NINE_REDIRECT_URI)");
        }
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        var pending = new PendingLogin
        {
            State = Base64Url.Random(24),
            Nonce = Base64Url.Random(24),
            CodeVerifier = Pkce.CreateVerifier(),
            RedirectUri = redirectUri,
            ReturnTo = ReturnTo.Sanitize(options.ReturnTo),
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(_time.GetUtcNow().ToUnixTimeSeconds()),
        };
        var parameters = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"),
            new("client_id", ClientId),
            new("redirect_uri", redirectUri),
            new("scope", string.Join(' ', _options.Scopes)),
            new("state", pending.State),
            new("nonce", pending.Nonce),
            new("code_challenge", Pkce.CreateChallenge(pending.CodeVerifier)),
            new("code_challenge_method", "S256"),
        };
        void Add(string name, string? value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                parameters.Add(new(name, value));
            }
        }
        Add("audience", _options.Audience);
        Add("prompt", options.Screen == LoginScreen.SignUp ? "create" : options.Prompt);
        Add("login_hint", options.LoginHint);
        Add("ui_locales", options.Locale ?? _options.Locale);
        foreach (var (name, value) in options.ExtraParameters ?? new Dictionary<string, string>())
        {
            if (!Reserved.Contains(name) && parameters.TrueForAll(p => p.Key != name))
            {
                Add(name, value);
            }
        }
        return new Login(Query.Append(discovery.AuthorizationEndpoint, parameters), pending);
    }

    /// <summary>
    /// Finishes a sign-in on your callback: checks the error parameter, the <c>state</c> (constant time,
    /// single use), the sign-in's age and the issuer (RFC 9207), exchanges the code with the PKCE verifier and
    /// verifies the ID token (signature, issuer, audience, expiry, nonce). Throws <see cref="InvalidStateException"/>,
    /// <see cref="InvalidTokenException"/>, or <see cref="NineException"/> with 9in's error (<c>access_denied</c>, …).
    /// </summary>
    /// <param name="callback">The full callback URL, or its query string.</param>
    /// <param name="pending">The <see cref="Login.Pending"/> kept since <see cref="CreateLoginAsync"/>; null when there is none.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    public Task<TokenSet> HandleCallbackAsync(string callback, PendingLogin? pending, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callback);
        return HandleCallbackAsync(Query.Parse(callback), pending, cancellationToken);
    }

    /// <summary>Like <see cref="HandleCallbackAsync(string, PendingLogin?, CancellationToken)"/>, with the callback's query parameters.</summary>
    public Task<TokenSet> HandleCallbackAsync(IEnumerable<KeyValuePair<string, string?>> parameters, PendingLogin? pending, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var query = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var (name, value) in parameters)
        {
            if (value is null)
            {
                continue;
            }
            if (!query.TryGetValue(name, out var values))
            {
                query[name] = values = [];
            }
            values.Add(value);
        }
        return HandleCallbackAsync(query, pending, cancellationToken);
    }

    private async Task<TokenSet> HandleCallbackAsync(Dictionary<string, List<string>> query, PendingLogin? pending, CancellationToken cancellationToken)
    {
        foreach (var name in new[] { "code", "state", "iss", "error" })
        {
            if (query.TryGetValue(name, out var values) && values.Count > 1)
            {
                throw new NineException("invalid_request", $"repeated {name} parameter in the callback", 400);
            }
        }
        string? Param(string name) => query.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;

        if (Param("error") is { Length: > 0 } error)
        {
            throw new NineException(error, Param("error_description") ?? error, 400);
        }
        if (pending is null)
        {
            throw new InvalidStateException("no sign-in in progress (it expired, or started in another browser)");
        }
        if (_time.GetUtcNow() - pending.CreatedAt > _options.LoginTimeout)
        {
            throw new InvalidStateException("the sign-in took too long; start again");
        }
        var state = Param("state");
        if (!TokenVerifier.FixedTimeEquals(state, pending.State))
        {
            throw new InvalidStateException("state mismatch");
        }
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        // RFC 9207: when the issuer says who it is, it must be ours; when it advertises the parameter, it must be there.
        var iss = Param("iss");
        if (iss is not null ? !Nine.Issuer.Same(iss, Issuer) : discovery.AuthorizationResponseIssParameterSupported)
        {
            throw new NineException("invalid_issuer", iss is null ? "the callback has no iss parameter" : $"unexpected issuer {iss}", 400);
        }
        if (Param("code") is not { Length: > 0 } code)
        {
            throw new NineException("missing_code", "no authorization code in the callback", 400);
        }
        // Single use: a replayed callback (same state) is refused even if the browser kept the pending login.
        if (!await _states.AddAsync("nine:state:" + Base64Url.Sha256Hex(pending.State), "used", _options.LoginTimeout, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidStateException("this sign-in was already completed");
        }

        var response = await TokenRequestAsync(
            [new("grant_type", "authorization_code"), new("code", code), new("redirect_uri", pending.RedirectUri), new("code_verifier", pending.CodeVerifier)],
            cancellationToken).ConfigureAwait(false);
        var claims = ClaimSet.Empty;
        if (response.IdToken is not null)
        {
            claims = await _verifier.VerifyIdTokenAsync(response.IdToken, ClientId, pending.Nonce, cancellationToken).ConfigureAwait(false);
        }
        else if (_options.Scopes.Contains("openid"))
        {
            throw new InvalidTokenException("no ID token in the token response");
        }
        return ToTokenSet(response, claims) with { ReturnTo = ReturnTo.Sanitize(pending.ReturnTo) };
    }

    /// <summary>
    /// Exchanges an authorization code (with its PKCE verifier) and verifies the ID token, with the nonce when given.
    /// For frameworks that keep the state and handle the callback themselves, like ASP.NET Core's OpenID Connect
    /// handler; otherwise use <see cref="HandleCallbackAsync(string, PendingLogin?, CancellationToken)"/>, which also checks state and issuer.
    /// </summary>
    public async Task<TokenSet> ExchangeCodeAsync(string code, string redirectUri, string codeVerifier, string? nonce = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        ArgumentException.ThrowIfNullOrEmpty(redirectUri);
        ArgumentException.ThrowIfNullOrEmpty(codeVerifier);
        var response = await TokenRequestAsync(
            [new("grant_type", "authorization_code"), new("code", code), new("redirect_uri", redirectUri), new("code_verifier", codeVerifier)],
            cancellationToken).ConfigureAwait(false);
        var claims = ClaimSet.Empty;
        if (response.IdToken is not null)
        {
            claims = await _verifier.VerifyIdTokenAsync(response.IdToken, ClientId, nonce, cancellationToken).ConfigureAwait(false);
        }
        else if (_options.Scopes.Contains("openid"))
        {
            throw new InvalidTokenException("no ID token in the token response");
        }
        return ToTokenSet(response, claims);
    }

    /// <summary>
    /// New tokens from the refresh token. 9in rotates refresh tokens, so keep the returned set (it keeps the
    /// old refresh token and ID token when 9in sends none). A new ID token is verified and must be for the same
    /// user. Throws <c>invalid_grant</c> when the refresh token was revoked or expired: sign the user out.
    /// </summary>
    public async Task<TokenSet> RefreshAsync(TokenSet tokens, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        if (string.IsNullOrEmpty(tokens.RefreshToken))
        {
            throw new NineException("login_required", "no refresh token");
        }
        var response = await TokenRequestAsync([new("grant_type", "refresh_token"), new("refresh_token", tokens.RefreshToken)], cancellationToken).ConfigureAwait(false);
        var claims = tokens.Claims;
        if (response.IdToken is not null)
        {
            var fresh = await _verifier.VerifyIdTokenAsync(response.IdToken, ClientId, null, cancellationToken).ConfigureAwait(false);
            if (claims.Subject is not null && fresh.Subject != claims.Subject)
            {
                throw new InvalidTokenException("the refreshed ID token is for another user");
            }
            claims = fresh;
        }
        var set = ToTokenSet(response, claims);
        return set with
        {
            RefreshToken = set.RefreshToken ?? tokens.RefreshToken,
            IdToken = set.IdToken ?? tokens.IdToken,
            Scope = set.Scope ?? tokens.Scope,
            ReturnTo = tokens.ReturnTo,
        };
    }

    /// <summary>New tokens from a refresh token alone (see <see cref="RefreshAsync(TokenSet, CancellationToken)"/>).</summary>
    public Task<TokenSet> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);
        return RefreshAsync(new TokenSet { AccessToken = "-", RefreshToken = refreshToken }, cancellationToken);
    }

    /// <summary>
    /// <paramref name="tokens"/> itself while the access token is valid for longer than <paramref name="leeway"/>
    /// (default 60 seconds), else refreshed tokens.
    /// </summary>
    public Task<TokenSet> EnsureFreshAsync(TokenSet tokens, TimeSpan? leeway = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        return tokens.IsExpired(leeway ?? TimeSpan.FromSeconds(60), _time) ? RefreshAsync(tokens, cancellationToken) : Task.FromResult(tokens);
    }

    /// <summary>The user's current claims from the userinfo endpoint.</summary>
    public async Task<ClaimSet> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(accessToken);
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        var result = await _http.GetAsync(discovery.UserInfoEndpoint ?? Issuer + "/oauth/userinfo", cancellationToken, bearer: accessToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            throw result.Status == 401 ? new InvalidTokenException("the userinfo endpoint refused the access token") : result.Error("userinfo_failed");
        }
        return result.JsonObject() is { } json ? ClaimSet.FromJson(json) : throw new NineException("userinfo_failed", "the userinfo answer is not JSON");
    }

    /// <summary>
    /// Revokes a refresh token (and its rotation family) or an access token (<paramref name="tokenTypeHint"/>
    /// <c>access_token</c>). 9in answers 200 for unknown or already revoked tokens, so a failure is real and throws.
    /// </summary>
    public async Task RevokeAsync(string token, string tokenTypeHint = "refresh_token", CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        if (discovery.RevocationEndpoint is not { Length: > 0 } endpoint)
        {
            return;
        }
        var result = await _http.PostFormAsync(endpoint, [new("token", token), new("token_type_hint", tokenTypeHint)], _client, cancellationToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            throw result.Error("revocation_failed");
        }
    }

    /// <summary>
    /// The URL that ends the session at 9in (RP-initiated logout) and comes back to
    /// <paramref name="postLogoutRedirectUri"/>, which must be an allowed logout URL of the application.
    /// </summary>
    public async Task<string> GetLogoutUrlAsync(string? idTokenHint = null, string? postLogoutRedirectUri = null, string? state = null, CancellationToken cancellationToken = default)
    {
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        var parameters = new List<KeyValuePair<string, string>> { new("client_id", ClientId) };
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            parameters.Add(new("id_token_hint", idTokenHint));
        }
        if (!string.IsNullOrEmpty(postLogoutRedirectUri))
        {
            parameters.Add(new("post_logout_redirect_uri", postLogoutRedirectUri));
        }
        if (!string.IsNullOrEmpty(state))
        {
            parameters.Add(new("state", state));
        }
        return Query.Append(discovery.EndSessionEndpoint ?? Issuer + "/oauth/logout", parameters);
    }

    /// <summary>
    /// A new token for machine-to-machine calls (client credentials grant; confidential applications only).
    /// Not cached: <see cref="GetClientCredentialsTokenAsync"/> is.
    /// </summary>
    public async Task<TokenSet> ClientCredentialsAsync(string? audience = null, string? scope = null, CancellationToken cancellationToken = default)
    {
        if (!IsConfidential)
        {
            throw new NineException("invalid_options", "client credentials need a confidential application (ClientSecret)");
        }
        var form = new List<KeyValuePair<string, string>> { new("grant_type", "client_credentials") };
        if (!string.IsNullOrEmpty(audience))
        {
            form.Add(new("audience", audience));
        }
        if (!string.IsNullOrEmpty(scope))
        {
            form.Add(new("scope", scope));
        }
        return ToTokenSet(await TokenRequestAsync(form, cancellationToken).ConfigureAwait(false), ClaimSet.Empty);
    }

    /// <summary>
    /// A client-credentials token, cached until a minute before it expires (concurrent callers share one
    /// request). Use it for machine-to-machine calls; <see cref="ClientCredentialsHandler"/> adds it to an
    /// <see cref="HttpClient"/>'s requests.
    /// </summary>
    public async Task<TokenSet> GetClientCredentialsTokenAsync(string? audience = null, string? scope = null, CancellationToken cancellationToken = default)
    {
        var key = audience + "|" + scope;
        if (_clientTokens.TryGetValue(key, out var cached) && !cached.IsExpired(TimeSpan.FromSeconds(60), _time))
        {
            return cached;
        }
        await _clientTokenLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_clientTokens.TryGetValue(key, out cached) && !cached.IsExpired(TimeSpan.FromSeconds(60), _time))
            {
                return cached;
            }
            var token = await ClientCredentialsAsync(audience, scope, cancellationToken).ConfigureAwait(false);
            _clientTokens[key] = token;
            return token;
        }
        finally
        {
            _clientTokenLock.Release();
        }
    }

    /// <summary>Drops a cached client-credentials token (after the API refused it).</summary>
    public void ForgetClientCredentialsToken(string? audience = null, string? scope = null, string? accessToken = null)
    {
        var key = audience + "|" + scope;
        if (accessToken is null)
        {
            _clientTokens.TryRemove(key, out _);
        }
        else if (_clientTokens.TryGetValue(key, out var cached) && cached.AccessToken == accessToken)
        {
            _clientTokens.TryRemove(new KeyValuePair<string, TokenSet>(key, cached));
        }
    }

    /// <summary>
    /// Starts a device sign-in (RFC 8628, for TVs, CLIs and devices without a browser): show the user code and
    /// verification URL, then call <see cref="PollDeviceAuthorizationAsync"/>.
    /// </summary>
    public async Task<DeviceAuthorization> StartDeviceAuthorizationAsync(string? scope = null, string? audience = null, CancellationToken cancellationToken = default)
    {
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        if (discovery.DeviceAuthorizationEndpoint is not { Length: > 0 } endpoint)
        {
            throw new NineException("unsupported", "the issuer has no device authorization endpoint");
        }
        var form = new List<KeyValuePair<string, string>> { new("scope", scope ?? string.Join(' ', _options.Scopes)) };
        if ((audience ?? _options.Audience) is { Length: > 0 } aud)
        {
            form.Add(new("audience", aud));
        }
        var result = await _http.PostFormAsync(endpoint, form, _client, cancellationToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            throw result.Error("device_authorization_failed");
        }
        var json = result.JsonObject() ?? throw new NineException("device_authorization_failed", "the answer is not JSON");
        string? Text(string name) => json.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        long Number(string name, long fallback) => json.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : fallback;
        return new DeviceAuthorization
        {
            DeviceCode = Text("device_code") ?? throw new NineException("device_authorization_failed", "no device_code"),
            UserCode = Text("user_code") ?? throw new NineException("device_authorization_failed", "no user_code"),
            VerificationUri = Text("verification_uri") ?? Issuer + "/device",
            VerificationUriComplete = Text("verification_uri_complete"),
            ExpiresAt = _time.GetUtcNow() + TimeSpan.FromSeconds(Number("expires_in", 600)),
            Interval = TimeSpan.FromSeconds(Math.Max(1, Number("interval", 5))),
        };
    }

    /// <summary>
    /// Waits until the user approves the device sign-in and returns the tokens. Honours the interval and
    /// <c>slow_down</c>; throws <c>expired_token</c> when the codes expire and <c>access_denied</c> when the user declines.
    /// </summary>
    public async Task<TokenSet> PollDeviceAuthorizationAsync(DeviceAuthorization authorization, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        var interval = authorization.Interval;
        while (true)
        {
            await Task.Delay(interval, _time, cancellationToken).ConfigureAwait(false);
            if (_time.GetUtcNow() >= authorization.ExpiresAt)
            {
                throw new NineException("expired_token", "the device code expired; start again", 400);
            }
            try
            {
                var response = await TokenRequestAsync(
                    [new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), new("device_code", authorization.DeviceCode)],
                    cancellationToken).ConfigureAwait(false);
                var claims = response.IdToken is null
                    ? ClaimSet.Empty
                    : await _verifier.VerifyIdTokenAsync(response.IdToken, ClientId, null, cancellationToken).ConfigureAwait(false);
                return ToTokenSet(response, claims);
            }
            catch (NineException e) when (e.Error == "authorization_pending")
            {
            }
            catch (NineException e) when (e.Error == "slow_down")
            {
                interval += TimeSpan.FromSeconds(5);
            }
        }
    }

    /// <summary>Verifies an ID token issued to this client (see <see cref="TokenVerifier.VerifyIdTokenAsync"/>).</summary>
    public Task<ClaimSet> VerifyIdTokenAsync(string idToken, string? nonce = null, CancellationToken cancellationToken = default) =>
        _verifier.VerifyIdTokenAsync(idToken, ClientId, nonce, cancellationToken);

    private async Task<TokenResponse> TokenRequestAsync(List<KeyValuePair<string, string>> form, CancellationToken cancellationToken)
    {
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        var result = await _http.PostFormAsync(discovery.TokenEndpoint, form, _client, cancellationToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            throw result.Error("request_failed");
        }
        return TokenResponse.Parse(result);
    }

    private TokenSet ToTokenSet(TokenResponse response, ClaimSet claims) => new()
    {
        AccessToken = response.AccessToken,
        TokenType = response.TokenType,
        ExpiresAt = _time.GetUtcNow() + TimeSpan.FromSeconds(response.ExpiresIn ?? 3600),
        RefreshToken = response.RefreshToken,
        IdToken = response.IdToken,
        Scope = response.Scope,
        Claims = claims,
    };

    /// <inheritdoc/>
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"AuthClient({Issuer}, {ClientId})");
}

using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;
using Nine.Tests.Support;

namespace Nine.Tests;

public class AuthClientTests
{
    private const string Redirect = "https://app.acme.test/nine/callback";
    private readonly FakeOidc _oidc = new();

    private AuthClient Client(Action<AuthClientOptions>? configure = null, FakeOidc? oidc = null)
    {
        oidc ??= _oidc;
        var options = new AuthClientOptions { Issuer = oidc.Issuer, ClientId = oidc.ClientId, ClientSecret = oidc.ClientSecret, RedirectUri = Redirect };
        configure?.Invoke(options);
        return new AuthClient(options, oidc.Server.Client());
    }

    private async Task<(AuthClient Client, Login Login, string Callback)> SignIn(Action<AuthClientOptions>? configure = null, LoginOptions? login = null)
    {
        var client = Client(configure);
        var started = await client.CreateLoginAsync(login);
        return (client, started, _oidc.Authorize(started.Url));
    }

    [Fact]
    public async Task BuildsTheAuthorizationUrl()
    {
        var client = Client(o => { o.Audience = "https://api.acme.test"; o.Locale = "de"; });
        var login = await client.CreateLoginAsync(new LoginOptions
        {
            ReturnTo = "/dashboard?tab=1",
            LoginHint = "jane@acme.test",
            ExtraParameters = new Dictionary<string, string> { ["max_age"] = "300", ["state"] = "evil", ["code_challenge"] = "evil", ["client_id"] = "evil" },
        });
        var q = FakeOidc.Query(new Uri(login.Url).Query);
        Assert.StartsWith(_oidc.Issuer + "/oauth/authorize?", login.Url);
        Assert.Equal("code", q["response_type"]);
        Assert.Equal(_oidc.ClientId, q["client_id"]);
        Assert.Equal(Redirect, q["redirect_uri"]);
        Assert.Equal("openid profile email offline_access", q["scope"]);
        Assert.Equal(login.Pending.State, q["state"]);
        Assert.Equal(login.Pending.Nonce, q["nonce"]);
        Assert.Equal(Pkce.CreateChallenge(login.Pending.CodeVerifier), q["code_challenge"]);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal("https://api.acme.test", q["audience"]);
        Assert.Equal("de", q["ui_locales"]);
        Assert.Equal("jane@acme.test", q["login_hint"]);
        Assert.Equal("300", q["max_age"]);
        Assert.False(q.ContainsKey("prompt"));
        Assert.Equal("/dashboard?tab=1", login.Pending.ReturnTo);
        Assert.Equal(Redirect, login.Pending.RedirectUri);
        Assert.True(login.Pending.State.Length >= 32);
    }

    [Fact]
    public async Task SignUpOpensTheRegistrationForm()
    {
        var signup = await Client().CreateLoginAsync(new LoginOptions { Screen = LoginScreen.SignUp, Prompt = "login" });
        Assert.Equal("create", FakeOidc.Query(new Uri(signup.Url).Query)["prompt"]);
        var prompt = await Client().CreateLoginAsync(new LoginOptions { Prompt = "login" });
        Assert.Equal("login", FakeOidc.Query(new Uri(prompt.Url).Query)["prompt"]);
    }

    [Fact]
    public async Task OnlySameSiteReturnToIsKept()
    {
        foreach (var bad in new[] { "https://evil.test/", "//evil.test", "/\\evil.test", "javascript:alert(1)" })
        {
            Assert.Null((await Client().CreateLoginAsync(new LoginOptions { ReturnTo = bad })).Pending.ReturnTo);
        }
    }

    [Fact]
    public async Task CompletesTheSignIn()
    {
        var (client, login, callback) = await SignIn(login: new LoginOptions { ReturnTo = "/after" });
        var tokens = await client.HandleCallbackAsync(callback, login.Pending);
        Assert.False(string.IsNullOrEmpty(tokens.AccessToken));
        Assert.NotNull(tokens.RefreshToken);
        Assert.NotNull(tokens.IdToken);
        Assert.Equal("usr_jane", tokens.Claims.Subject);
        Assert.Equal("jane@acme.test", tokens.Claims.Email);
        Assert.Equal("/after", tokens.ReturnTo);
        Assert.False(tokens.IsExpired());
        Assert.Equal("Bearer", tokens.TokenType);
        // client_secret_basic, and the PKCE verifier on the code exchange
        var request = _oidc.Server.Last("/oauth/token");
        Assert.StartsWith("Basic ", request.Authorization);
        Assert.False(request.Form.ContainsKey("client_secret"));
        Assert.Equal(login.Pending.CodeVerifier, request.Form["code_verifier"]);
        Assert.Equal(Redirect, request.Form["redirect_uri"]);
        // The query string alone, or the parameters, work too.
        var (client2, login2, callback2) = await SignIn();
        Assert.Equal("usr_jane", (await client2.HandleCallbackAsync(new Uri(callback2).Query, login2.Pending)).Claims.Subject);
        var (client3, login3, callback3) = await SignIn();
        var parameters = FakeOidc.Query(new Uri(callback3).Query).Select(p => new KeyValuePair<string, string?>(p.Key, p.Value));
        Assert.Equal("usr_jane", (await client3.HandleCallbackAsync(parameters, login3.Pending)).Claims.Subject);
    }

    [Fact]
    public async Task PublicClientsSendTheirClientIdAndNoSecret()
    {
        var oidc = new FakeOidc(clientId: "app_public", clientSecret: null);
        var client = Client(oidc: oidc);
        Assert.False(client.IsConfidential);
        var login = await client.CreateLoginAsync();
        var tokens = await client.HandleCallbackAsync(oidc.Authorize(login.Url), login.Pending);
        Assert.Equal("usr_jane", tokens.Claims.Subject);
        var request = oidc.Server.Last("/oauth/token");
        Assert.Null(request.Authorization);
        Assert.Equal("app_public", request.Form["client_id"]);
    }

    [Fact]
    public async Task ThePendingLoginSurvivesASessionRoundTrip()
    {
        var (client, login, callback) = await SignIn(login: new LoginOptions { ReturnTo = "/x" });
        var restored = PendingLogin.FromJson(login.Pending.ToJson());
        Assert.Equal(login.Pending, restored);
        Assert.Null(PendingLogin.FromJson("{}"));
        Assert.Null(PendingLogin.FromJson("not json"));
        Assert.Null(PendingLogin.FromJson(null));
        Assert.DoesNotContain(login.Pending.CodeVerifier, login.Pending.ToString());
        var tokens = await client.HandleCallbackAsync(callback, restored);
        var again = TokenSet.FromJson(tokens.ToJson());
        Assert.Equal(tokens.AccessToken, again.AccessToken);
        Assert.Equal(tokens.RefreshToken, again.RefreshToken);
        Assert.Equal(tokens.IdToken, again.IdToken);
        Assert.Equal(tokens.Claims.Subject, again.Claims.Subject);
        Assert.Equal(tokens.ExpiresAt!.Value.ToUnixTimeSeconds(), again.ExpiresAt!.Value.ToUnixTimeSeconds());
        Assert.Equal("/x", again.ReturnTo);
        Assert.DoesNotContain(tokens.AccessToken, tokens.ToString());
        Assert.DoesNotContain(tokens.RefreshToken!, tokens.ToString());
    }

    [Fact]
    public async Task RefusesWrongMissingAndReplayedState()
    {
        var (client, login, callback) = await SignIn();
        Assert.Equal("invalid_state", (await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(callback.Replace("state=", "state=x"), login.Pending))).Error);
        await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(Remove(callback, "state"), login.Pending));
        await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(callback, null));
        // The refused attempts did not spend the code: the real callback still works, once.
        await client.HandleCallbackAsync(callback, login.Pending);
        var replay = await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(callback, login.Pending));
        Assert.Contains("already", replay.ErrorDescription);
        Assert.Equal(400, replay.StatusCode);
    }

    [Fact]
    public async Task ASharedStateCacheStopsReplaysAcrossServers()
    {
        var shared = new NineMemoryCache();
        var (serverA, login, callback) = await SignIn(o => o.StateCache = shared);
        await serverA.HandleCallbackAsync(callback, login.Pending);
        var serverB = Client(o => o.StateCache = shared);
        await Assert.ThrowsAsync<InvalidStateException>(() => serverB.HandleCallbackAsync(callback, login.Pending));
    }

    [Fact]
    public async Task RefusesASlowSignIn()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var (client, login, callback) = await SignIn(o => o.TimeProvider = clock);
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Contains("too long", (await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(callback, login.Pending))).ErrorDescription);
    }

    [Fact]
    public async Task ChecksTheIssuerParameter()
    {
        var (client, login, callback) = await SignIn();
        var evil = callback.Replace("iss=" + Uri.EscapeDataString(_oidc.Issuer), "iss=" + Uri.EscapeDataString("https://evil.test"));
        Assert.Equal("invalid_issuer", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(evil, login.Pending))).Error);
        // The issuer advertises RFC 9207 support, so a missing iss is refused too.
        Assert.Equal("invalid_issuer", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(Remove(callback, "iss"), login.Pending))).Error);
        await client.HandleCallbackAsync(callback, login.Pending);
    }

    [Fact]
    public async Task AMissingIssIsFineWhenTheIssuerDoesNotAdvertiseIt()
    {
        var oidc = new FakeOidc();
        oidc.Server.Discovery["authorization_response_iss_parameter_supported"] = false;
        var client = Client(oidc: oidc);
        var login = await client.CreateLoginAsync();
        Assert.Equal("usr_jane", (await client.HandleCallbackAsync(Remove(oidc.Authorize(login.Url), "iss"), login.Pending)).Claims.Subject);
    }

    [Fact]
    public async Task ErrorsFromTheIssuerAndMissingOrRepeatedParameters()
    {
        var (client, login, callback) = await SignIn();
        var denied = await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(Redirect + "?error=access_denied&error_description=The+user+said+no&state=" + login.Pending.State, login.Pending));
        Assert.Equal("access_denied", denied.Error);
        Assert.Equal("The user said no", denied.ErrorDescription);
        Assert.Equal(400, denied.StatusCode);
        Assert.Equal("missing_code", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(Remove(callback, "code"), login.Pending))).Error);
        Assert.Equal("invalid_request", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(callback + "&code=other", login.Pending))).Error);
        Assert.Equal("invalid_request", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(callback + "&state=" + login.Pending.State, login.Pending))).Error);
    }

    [Fact]
    public async Task RefusesBadIdTokens()
    {
        async Task<string> Refused(Action<JsonObject> edit)
        {
            _oidc.EditIdToken = edit;
            var (client, login, callback) = await SignIn();
            return (await Assert.ThrowsAsync<InvalidTokenException>(() => client.HandleCallbackAsync(callback, login.Pending))).ErrorDescription!;
        }
        Assert.Contains("nonce", await Refused(c => c["nonce"] = "other"));
        Assert.Contains("nonce", await Refused(c => c.Remove("nonce")));
        Assert.Contains("audience", await Refused(c => c["aud"] = "app_other"));
        Assert.Contains("authorized party", await Refused(c => { c["aud"] = new JsonArray(_oidc.ClientId, "app_other"); c["azp"] = "app_other"; }));
        Assert.Contains("expired", await Refused(c => c["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 120));
        Assert.Contains("issuer", await Refused(c => c["iss"] = "https://evil.test"));
        Assert.Contains("subject", await Refused(c => c.Remove("sub")));
        _oidc.EditIdToken = null;
        // Several audiences are fine when azp is us.
        _oidc.EditIdToken = c => c["aud"] = new JsonArray(_oidc.ClientId, "app_other");
        var (ok, login, callback) = await SignIn();
        Assert.Equal("usr_jane", (await ok.HandleCallbackAsync(callback, login.Pending)).Claims.Subject);
    }

    [Fact]
    public async Task RefusesAnIdTokenSignedByAnotherKey()
    {
        var (client, login, callback) = await SignIn();
        _oidc.Server.Keys.Clear();
        var other = TestKey.Create("RS256", "other-" + Guid.NewGuid().ToString("N"));
        other.Jwk!["kid"] = _oidc.Key.Kid; // same kid, different key
        _oidc.Server.AddKey(other);
        var e = await Assert.ThrowsAsync<InvalidTokenException>(() => client.HandleCallbackAsync(callback, login.Pending));
        Assert.Contains("bad signature", e.ErrorDescription);
    }

    [Fact]
    public async Task RequiresAnIdTokenWithTheOpenidScope()
    {
        _oidc.Server.On("POST", "/oauth/token", _ => FakeIssuer.Json(new JsonObject { ["access_token"] = "at", ["token_type"] = "Bearer", ["expires_in"] = 60 }));
        var (client, login, callback) = await SignIn();
        Assert.Contains("no ID token", (await Assert.ThrowsAsync<InvalidTokenException>(() => client.HandleCallbackAsync(callback, login.Pending))).ErrorDescription);
    }

    [Fact]
    public async Task TokenEndpointErrorsCarryTheServerError()
    {
        var (client, login, callback) = await SignIn();
        var wrongVerifier = login.Pending with { CodeVerifier = Pkce.CreateVerifier() };
        var e = await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(callback, wrongVerifier));
        Assert.Equal("invalid_grant", e.Error);
        Assert.Equal("PKCE verification failed", e.ErrorDescription);
        Assert.Equal(400, e.StatusCode);

        var bad = Client(o => o.ClientSecret = "wrong");
        var login2 = await bad.CreateLoginAsync();
        Assert.Equal("invalid_client", (await Assert.ThrowsAsync<NineException>(() => bad.HandleCallbackAsync(_oidc.Authorize(login2.Url), login2.Pending))).Error);
    }

    [Fact]
    public async Task RefreshRotatesAndKeepsWhatIsNotReturned()
    {
        var (client, login, callback) = await SignIn();
        var first = await client.HandleCallbackAsync(callback, login.Pending);
        var second = await client.RefreshAsync(first);
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.NotEqual(first.AccessToken, second.AccessToken);
        Assert.Equal("usr_jane", second.Claims.Subject);
        Assert.Same(second, await client.EnsureFreshAsync(second));
        // Using the old refresh token again is reuse.
        Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<NineException>(() => client.RefreshAsync(first))).Error);

        // No new refresh token or ID token: keep the old ones.
        _oidc.RotateRefreshTokens = false;
        _oidc.IdTokenOnRefresh = false;
        var (client2, login2, callback2) = await SignIn();
        var a = await client2.HandleCallbackAsync(callback2, login2.Pending);
        var b = await client2.RefreshAsync(a.RefreshToken!);
        Assert.Equal(a.RefreshToken, b.RefreshToken);
        var c = await client2.RefreshAsync(a);
        Assert.Equal(a.RefreshToken, c.RefreshToken);
        Assert.Equal(a.IdToken, c.IdToken);
        Assert.Equal("usr_jane", c.Claims.Subject);
    }

    [Fact]
    public async Task ARefreshedIdTokenMustBeForTheSameUser()
    {
        var (client, login, callback) = await SignIn();
        var tokens = await client.HandleCallbackAsync(callback, login.Pending);
        _oidc.RefreshSubjectOverride = "usr_mallory";
        Assert.Contains("another user", (await Assert.ThrowsAsync<InvalidTokenException>(() => client.RefreshAsync(tokens))).ErrorDescription);
    }

    [Fact]
    public async Task EnsureFreshRefreshesNearExpiry()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _oidc.AccessTokenLifetime = 120;
        var (client, login, callback) = await SignIn(o => o.TimeProvider = clock);
        var tokens = await client.HandleCallbackAsync(callback, login.Pending);
        Assert.Same(tokens, await client.EnsureFreshAsync(tokens));
        clock.Advance(TimeSpan.FromSeconds(61));
        var fresh = await client.EnsureFreshAsync(tokens);
        Assert.NotSame(tokens, fresh);
        Assert.Equal(1, _oidc.RefreshCount);
        Assert.Equal("login_required", (await Assert.ThrowsAsync<NineException>(() => client.RefreshAsync(tokens with { RefreshToken = null }))).Error);
    }

    [Fact]
    public async Task UserInfoRevokeAndLogout()
    {
        var (client, login, callback) = await SignIn();
        var tokens = await client.HandleCallbackAsync(callback, login.Pending);
        var info = await client.GetUserInfoAsync(tokens.AccessToken);
        Assert.Equal("usr_jane", info.Subject);
        Assert.Equal("Bearer " + tokens.AccessToken, _oidc.Server.Last("/oauth/userinfo").Authorization);

        await client.RevokeAsync(tokens.RefreshToken!);
        Assert.Contains(tokens.RefreshToken, _oidc.Revoked);
        var revoke = _oidc.Server.Last("/oauth/revoke");
        Assert.Equal("refresh_token", revoke.Form["token_type_hint"]);
        Assert.StartsWith("Basic ", revoke.Authorization);
        Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<NineException>(() => client.RefreshAsync(tokens))).Error);

        await client.RevokeAsync(tokens.AccessToken, "access_token");
        Assert.Equal("invalid_token", (await Assert.ThrowsAsync<InvalidTokenException>(() => client.GetUserInfoAsync(tokens.AccessToken))).Error);

        var url = await client.GetLogoutUrlAsync(tokens.IdToken, "https://app.acme.test/", "s1");
        Assert.StartsWith(_oidc.Issuer + "/oauth/logout?", url);
        var q = FakeOidc.Query(new Uri(url).Query);
        Assert.Equal(_oidc.ClientId, q["client_id"]);
        Assert.Equal(tokens.IdToken, q["id_token_hint"]);
        Assert.Equal("https://app.acme.test/", q["post_logout_redirect_uri"]);
        Assert.Equal("s1", q["state"]);
    }

    [Fact]
    public async Task RevokeFailuresThrow()
    {
        _oidc.Server.On("POST", "/oauth/revoke", _ => FakeIssuer.Error("invalid_client", HttpStatusCode.Unauthorized));
        Assert.Equal("invalid_client", (await Assert.ThrowsAsync<NineException>(() => Client().RevokeAsync("rt"))).Error);
    }

    [Fact]
    public async Task ClientCredentials()
    {
        var tokens = await Client().ClientCredentialsAsync("https://api.acme.test", "orders:read");
        Assert.False(string.IsNullOrEmpty(tokens.AccessToken));
        Assert.Null(tokens.IdToken);
        Assert.Empty(tokens.Claims);
        var request = _oidc.Server.Last("/oauth/token");
        Assert.Equal("client_credentials", request.Form["grant_type"]);
        Assert.Equal("https://api.acme.test", request.Form["audience"]);
        Assert.Equal("orders:read", request.Form["scope"]);
        Assert.StartsWith("Basic ", request.Authorization);
        var publicClient = new AuthClient(new AuthClientOptions { Issuer = _oidc.Issuer, ClientId = "app_public" }, _oidc.Server.Client());
        Assert.Equal("invalid_options", (await Assert.ThrowsAsync<NineException>(() => publicClient.ClientCredentialsAsync())).Error);
    }

    [Fact]
    public async Task ClientCredentialsHandlerCachesTheToken()
    {
        var client = Client();
        var api = new RecordingHandler();
        using var http = new HttpClient(new ClientCredentialsHandler(client, "https://api.acme.test") { InnerHandler = api });
        await http.GetAsync("https://api.acme.test/orders");
        await http.GetAsync("https://api.acme.test/orders");
        Assert.Equal(1, _oidc.Server.Count("POST", "/oauth/token"));
        Assert.All(api.Authorizations, a => Assert.StartsWith("Bearer ey", a));
        api.Status = HttpStatusCode.Unauthorized;
        await http.GetAsync("https://api.acme.test/orders");
        api.Status = HttpStatusCode.OK;
        await http.GetAsync("https://api.acme.test/orders");
        Assert.Equal(2, _oidc.Server.Count("POST", "/oauth/token"));
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<string> Authorizations { get; } = [];
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Authorizations.Add(request.Headers.Authorization!.ToString());
            return Task.FromResult(new HttpResponseMessage(Status));
        }
    }

    [Fact]
    public async Task DeviceFlowWaitsSlowsDownAndFinishes()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var polls = 0;
        _oidc.Server.On("POST", "/oauth/device/authorize", _ => FakeIssuer.Json(new JsonObject
        {
            ["device_code"] = "dc_1", ["user_code"] = "ABCD-EFGH", ["verification_uri"] = _oidc.Issuer + "/device",
            ["verification_uri_complete"] = _oidc.Issuer + "/device?user_code=ABCD-EFGH", ["expires_in"] = 600, ["interval"] = 5,
        }));
        _oidc.Server.On("POST", "/oauth/token", request =>
        {
            Assert.Equal("urn:ietf:params:oauth:grant-type:device_code", request.Form["grant_type"]);
            Assert.Equal("dc_1", request.Form["device_code"]);
            return ++polls switch
            {
                1 => FakeIssuer.Error("authorization_pending"),
                2 => FakeIssuer.Error("slow_down"),
                3 => FakeIssuer.Error("authorization_pending"),
                _ => FakeIssuer.Json(new JsonObject { ["access_token"] = "at_device", ["token_type"] = "Bearer", ["expires_in"] = 3600, ["id_token"] = _oidc.IdToken("usr_tv", null) }),
            };
        });
        var client = Client(o => { o.ClientSecret = null; o.TimeProvider = clock; o.Audience = "https://api.acme.test"; });
        var device = await client.StartDeviceAuthorizationAsync();
        Assert.Equal("ABCD-EFGH", device.UserCode);
        Assert.Equal(TimeSpan.FromSeconds(5), device.Interval);
        var start = _oidc.Server.Last("/oauth/device/authorize");
        Assert.Equal(_oidc.ClientId, start.Form["client_id"]);
        Assert.Equal("https://api.acme.test", start.Form["audience"]);
        Assert.DoesNotContain("dc_1", device.ToString());

        var poll = client.PollDeviceAuthorizationAsync(device);
        var started = clock.GetUtcNow();
        await Drive(clock, poll);
        // 5 + 5 + 10 (after slow_down) + 10 seconds of waiting.
        Assert.InRange((clock.GetUtcNow() - started).TotalSeconds, 30, 36);
        var tokens = await poll.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("at_device", tokens.AccessToken);
        Assert.Equal("usr_tv", tokens.Claims.Subject);
        Assert.Equal(4, polls);
    }

    [Fact]
    public async Task DeviceFlowFailures()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _oidc.Server.On("POST", "/oauth/token", _ => FakeIssuer.Error("access_denied"));
        var client = Client(o => o.TimeProvider = clock);
        var device = new DeviceAuthorization { DeviceCode = "dc", UserCode = "u", VerificationUri = "v", ExpiresAt = clock.GetUtcNow().AddMinutes(10), Interval = TimeSpan.FromSeconds(1) };
        var denied = client.PollDeviceAuthorizationAsync(device);
        await Drive(clock, denied);
        Assert.Equal("access_denied", (await Assert.ThrowsAsync<NineException>(() => denied.WaitAsync(TimeSpan.FromSeconds(5)))).Error);

        var expired = client.PollDeviceAuthorizationAsync(device with { ExpiresAt = clock.GetUtcNow() });
        await Drive(clock, expired);
        Assert.Equal("expired_token", (await Assert.ThrowsAsync<NineException>(() => expired.WaitAsync(TimeSpan.FromSeconds(5)))).Error);
    }

    /// <summary>Moves the fake clock a second at a time until the task finishes.</summary>
    private static async Task Drive(FakeTimeProvider clock, Task task)
    {
        for (var i = 0; i < 300 && !task.IsCompleted; i++)
        {
            await Task.Delay(10);
            if (!task.IsCompleted)
            {
                clock.Advance(TimeSpan.FromSeconds(1));
            }
        }
    }

    [Fact]
    public async Task OptionsFromTheEnvironment()
    {
        var names = new Dictionary<string, string?>
        {
            ["NINE_ISSUER"] = _oidc.Issuer + "/", ["NINE_CLIENT_ID"] = _oidc.ClientId, ["NINE_CLIENT_SECRET"] = _oidc.ClientSecret,
            ["NINE_REDIRECT_URI"] = Redirect, ["NINE_AUDIENCE"] = "https://api.acme.test",
        };
        var saved = names.Keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var (k, v) in names)
            {
                Environment.SetEnvironmentVariable(k, v);
            }
            var options = AuthClientOptions.FromEnvironment();
            Assert.Equal(Redirect, options.RedirectUri);
            Assert.Equal("https://api.acme.test", options.Audience);
            var client = new AuthClient(options, _oidc.Server.Client());
            Assert.Equal(_oidc.Issuer, client.Issuer);
            Assert.True(client.IsConfidential);
            Assert.Contains("audience=", (await client.CreateLoginAsync()).Url);
            var management = ManagementClientOptions.FromEnvironment();
            Assert.Equal(_oidc.ClientId, management.ClientId);
        }
        finally
        {
            foreach (var (k, v) in saved)
            {
                Environment.SetEnvironmentVariable(k, v);
            }
        }
    }

    [Fact]
    public void RequiresAClientIdAndARedirectUri()
    {
        Assert.Equal("invalid_options", Assert.Throws<NineException>(() => new AuthClient(new AuthClientOptions { Issuer = _oidc.Issuer })).Error);
        var client = new AuthClient(new AuthClientOptions { Issuer = _oidc.Issuer, ClientId = "x" }, _oidc.Server.Client());
        Assert.Equal("invalid_options", Assert.ThrowsAsync<NineException>(() => client.CreateLoginAsync()).GetAwaiter().GetResult().Error);
    }

    private static string Remove(string url, string parameter)
    {
        var uri = new Uri(url);
        var kept = uri.Query.TrimStart('?').Split('&').Where(p => !p.StartsWith(parameter + "=", StringComparison.Ordinal));
        return uri.GetLeftPart(UriPartial.Path) + "?" + string.Join('&', kept);
    }
}

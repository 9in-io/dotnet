using System.Text;
using System.Text.Json;

namespace Nine.E2E;

/// <summary>
/// The 9in package against live 9in (the sdk-e2e tenants): sandbox sign-in through the hosted page, local,
/// hybrid and introspected token verification, refresh rotation, revocation, the Management API, login links,
/// sessions, import, client credentials, opaque tokens, real webhook deliveries and real adapter requests.
/// </summary>
public sealed class LiveTests(LiveFixture live) : IClassFixture<LiveFixture>
{
    private static string Audience => Live.Env("API_AUDIENCE");

    [Fact]
    public async Task Discovery()
    {
        Live.RequireEnabled();
        var discovery = await LiveFixture.Sandbox().GetDiscoveryAsync();
        Assert.Equal(Live.Env("SANDBOX_ISSUER"), discovery.Issuer);
        Assert.Equal(Live.Env("SANDBOX_ISSUER") + "/oauth/token", discovery.TokenEndpoint);
        Assert.True(discovery.AuthorizationResponseIssParameterSupported);
        Assert.NotNull(discovery.DeviceAuthorizationEndpoint);
        Assert.NotNull(discovery.IntrospectionEndpoint);
    }

    [Fact]
    public async Task SignsInWithPkceThroughTheHostedPage()
    {
        Live.RequireEnabled();
        var (client, tokens) = await live.SandboxSession();
        Assert.Equal("/dotnet-after", tokens.ReturnTo);
        Assert.NotNull(tokens.RefreshToken);
        Assert.False(tokens.IsExpired());
        Assert.Equal(live.SandboxEmail, tokens.Claims.Email);
        Assert.Equal([Live.Env("SPA_CLIENT_ID")], tokens.Claims.Audiences);
        Assert.Equal(Live.Env("SANDBOX_ISSUER"), tokens.Claims.Issuer);

        var info = await client.GetUserInfoAsync(tokens.AccessToken);
        Assert.Equal(tokens.Claims.Subject, info.Subject);
        Assert.Equal(live.SandboxEmail, info.Email);

        var restored = TokenSet.FromJson(tokens.ToJson());
        Assert.Equal(tokens.RefreshToken, restored.RefreshToken);
        Assert.Equal(tokens.Claims.Subject, restored.Claims.Subject);
    }

    [Fact]
    public async Task VerifiesTheAccessTokenLocally()
    {
        Live.RequireEnabled();
        var (_, tokens) = await live.SandboxSession();
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("SANDBOX_ISSUER"), Audience = Audience });
        var claims = await verifier.VerifyAsync("Bearer " + tokens.AccessToken, "read:things");
        Assert.Equal(tokens.Claims.Subject, claims.Subject);
        Assert.Equal(Live.Env("SPA_CLIENT_ID"), claims.ClientId);
        var e = await Assert.ThrowsAsync<InsufficientScopeException>(() => verifier.VerifyAsync(tokens.AccessToken, "write:things"));
        Assert.Equal(403, e.StatusCode);
        var otherApi = new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("SANDBOX_ISSUER"), Audience = "https://other.e2e.9in.test" });
        await Assert.ThrowsAsync<InvalidTokenException>(() => otherApi.VerifyAsync(tokens.AccessToken));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(tokens.AccessToken[..^4] + "AAAA"));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(tokens.IdToken));
        // The production issuer doesn't accept sandbox tokens.
        await Assert.ThrowsAsync<InvalidTokenException>(() => new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("ISSUER") }).VerifyAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task RefreshRotatesAndRevocationSticks()
    {
        Live.RequireEnabled();
        var (client, first) = await live.SandboxSession();
        var rotated = await client.RefreshAsync(first);
        Assert.NotEqual(first.RefreshToken, rotated.RefreshToken);
        Assert.NotEqual(first.AccessToken, rotated.AccessToken);
        Assert.Same(rotated, await client.EnsureFreshAsync(rotated));
        // Within 30 seconds a repeat is a race, not reuse: the same new refresh token comes back.
        Assert.Equal(rotated.RefreshToken, (await client.RefreshAsync(first)).RefreshToken);

        var again = LiveFixture.Sandbox();
        var login = await again.CreateLoginAsync();
        using var browser = new Browser();
        var signIn = await browser.SignIn(login.Url, Live.Env("SPA_REDIRECT_URI"), live.SandboxEmail, "x");
        var tokens = await again.HandleCallbackAsync(signIn.Callback!, login.Pending);
        await again.RevokeAsync(tokens.RefreshToken!);
        Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<NineException>(() => again.RefreshAsync(tokens))).Error);

        var logout = await again.GetLogoutUrlAsync(tokens.IdToken, "http://127.0.0.1:8931/");
        Assert.StartsWith(Live.Env("SANDBOX_ISSUER") + "/oauth/logout?", logout);
        Assert.Contains("id_token_hint=" + Uri.EscapeDataString(tokens.IdToken!), logout);
    }

    [Fact]
    public async Task RefusesBadCallbacks()
    {
        Live.RequireEnabled();
        var client = LiveFixture.Sandbox();
        var login = await client.CreateLoginAsync();
        using var browser = new Browser();
        var callback = (await browser.SignIn(login.Url, Live.Env("SPA_REDIRECT_URI"), live.SandboxEmail, "x")).Callback!;
        Assert.Contains("iss=" + Uri.EscapeDataString(Live.Env("SANDBOX_ISSUER")), callback);

        Assert.Equal("invalid_state", (await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(callback.Replace("state=", "state=forged"), login.Pending))).Error);
        var evil = callback.Replace("iss=" + Uri.EscapeDataString(Live.Env("SANDBOX_ISSUER")), "iss=" + Uri.EscapeDataString("https://evil.example"));
        Assert.Equal("invalid_issuer", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(evil, login.Pending))).Error);
        var denied = Live.Env("SPA_REDIRECT_URI") + "?error=access_denied&state=" + Uri.EscapeDataString(login.Pending.State);
        Assert.Equal("access_denied", (await Assert.ThrowsAsync<NineException>(() => client.HandleCallbackAsync(denied, login.Pending))).Error);
        // The refused attempts didn't spend the code: the real callback still works, once.
        Assert.False(string.IsNullOrEmpty((await client.HandleCallbackAsync(callback, login.Pending)).AccessToken));
        await Assert.ThrowsAsync<InvalidStateException>(() => client.HandleCallbackAsync(callback, login.Pending));
    }

    [Fact]
    public async Task VerifiesRealWebhookDeliveries()
    {
        Live.RequireEnabled();
        var (_, tokens) = await live.SandboxSession();
        var sub = tokens.Claims.Subject;
        var secret = Live.Env("WEBHOOK_SECRET");
        var created = await Live.WaitFor("webhooks", r => r.Text("type") == "user.created" && r.Text("userId") == sub);
        var login = await Live.WaitFor("webhooks", r => r.Text("type") == "user.login" && r.Text("userId") == sub);
        var hour = TimeSpan.FromHours(1); // replayed a little later than 9in sent them

        var webhookEvent = Webhook.Verify(secret, created.Text("raw")!, created.Text("signature"), created.Text("path")!, tolerance: hour);
        Assert.Equal("user.created", webhookEvent.EventType);
        Assert.Equal(sub, webhookEvent.UserId);
        Assert.Equal(live.SandboxEmail, webhookEvent.User!.Email);
        Assert.Equal(Live.Env("TENANT_ID"), webhookEvent.Tenant);
        Assert.Equal("sandbox", webhookEvent.Environment);
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", webhookEvent.Json.GetProperty("created_at").GetString());
        Assert.False(webhookEvent.Data.TryGetProperty("userId", out _));
        Assert.Equal(login.Text("id"), Webhook.Verify(["whsec_old", secret], Encoding.UTF8.GetBytes(login.Text("raw")!), login.Text("signature"), login.Text("path")!, tolerance: hour).Id);

        var raw = login.Text("raw")!;
        var signature = login.Text("signature");
        var path = login.Text("path")!;
        Assert.Throws<SignatureException>(() => Webhook.Verify("whsec_wrong", raw, signature, path, tolerance: hour));
        Assert.Throws<SignatureException>(() => Webhook.Verify(secret, raw.Replace("user.login", "user.deleted"), signature, path, tolerance: hour));
        Assert.Throws<SignatureException>(() => Webhook.Verify(secret, raw, signature, "/elsewhere", tolerance: hour));
        Assert.Throws<SignatureException>(() => Webhook.Verify(secret, raw, null, path, tolerance: hour));
        Assert.Throws<SignatureException>(() => Webhook.Verify(secret, raw, signature, path, "PUT", hour));
        var t = Signature.Parse(signature!)!.Value.Timestamp;
        Assert.Equal(SignatureFailure.Expired, Signature.Check([secret], signature, "POST", path, Encoding.UTF8.GetBytes(raw), TimeSpan.FromSeconds(60), new FixedClock(t + 61)).Failure);
        Assert.True(Signature.Check([secret], signature, "POST", path, Encoding.UTF8.GetBytes(raw), TimeSpan.FromSeconds(60), new FixedClock(t + 59)).Ok);

        var dedupe = new EventDeduplicator(new NineMemoryCache());
        var runs = 0;
        Assert.Equal(EventOutcome.Processed, await dedupe.ProcessAsync(webhookEvent.Id, _ => { runs++; return Task.CompletedTask; }));
        Assert.Equal(EventOutcome.Duplicate, await dedupe.ProcessAsync(webhookEvent.Id, _ => { runs++; return Task.CompletedTask; }));
        Assert.Equal(1, runs);
    }

    internal sealed class AliceAdapter : IAdapter
    {
        public Task<AdapterResult> AuthenticateAsync(AdapterIdentifier identifier, string password, CancellationToken cancellationToken) =>
            Task.FromResult(identifier.Value.Equals("alice@adapter.e2e.test", StringComparison.OrdinalIgnoreCase) && password == "Alice-Password-1"
                ? new AdapterUser("ext_alice") { Email = "alice@adapter.e2e.test", Name = "Alice Adapter" }
                : AdapterResult.Invalid);

        public Task<AdapterUser?> FindUserAsync(AdapterQuery query, CancellationToken cancellationToken) => Task.FromResult<AdapterUser?>(null);
    }

    /// <summary>Alice signs in on the adapter tenant; the receiver's recorded requests are replayed through the handler.</summary>
    internal static async Task<(JsonElement Ok, JsonElement Refused)> AdapterRequests()
    {
        var since = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 5000;
        var client = new AuthClient(new AuthClientOptions
        {
            Issuer = Live.Env("ADAPTER_ISSUER"),
            ClientId = Live.Env("ADAPTER_SPA_CLIENT_ID"),
            RedirectUri = Live.Env("ADAPTER_SPA_REDIRECT_URI"),
        });
        var login = await client.CreateLoginAsync();
        using var browser = new Browser();
        var result = await browser.SignIn(login.Url, Live.Env("ADAPTER_SPA_REDIRECT_URI"), "alice@adapter.e2e.test", "Alice-Password-1");
        Assert.True(result.Callback is not null, result.PageText);
        var tokens = await client.HandleCallbackAsync(result.Callback!, login.Pending);
        Assert.Equal("alice@adapter.e2e.test", tokens.Claims.Email);
        Assert.Equal("Alice Adapter", tokens.Claims.Name);

        var marker = "dotnet-wrong-" + Live.Run;
        var wrong = await new Browser().SignIn((await client.CreateLoginAsync()).Url, Live.Env("ADAPTER_SPA_REDIRECT_URI"), "alice@adapter.e2e.test", marker);
        Assert.Null(wrong.Callback);
        Assert.Equal(401, wrong.Status);
        var blocked = await new Browser().SignIn((await client.CreateLoginAsync()).Url, Live.Env("ADAPTER_SPA_REDIRECT_URI"), "bob@adapter.e2e.test", "Bob-Password-1");
        Assert.Null(blocked.Callback);

        Task<JsonElement> Raw(string needle) => Live.WaitFor("adapter-raw", r => r.Number("at") >= since && r.Text("path")!.EndsWith("/authenticate", StringComparison.Ordinal) && r.Text("body")!.Contains(needle, StringComparison.Ordinal));
        return (await Raw("Alice-Password-1"), await Raw(marker));
    }

    internal static AdapterRequest ToRequest(JsonElement record, string? path = null, string? body = null, string method = "POST") => new(
        method,
        path ?? record.Text("path")!,
        new Dictionary<string, string> { ["9in-Signature"] = record.Text("signature")!, ["9in-Request-Id"] = record.Text("requestId")! },
        Encoding.UTF8.GetBytes(body ?? record.Text("body")!));

    [Fact]
    public async Task AdapterSignInAndRealAdapterRequests()
    {
        Live.RequireEnabled();
        var (ok, refused) = await AdapterRequests();
        var secret = Live.Env("ADAPTER_SECRET");
        var handler = new AdapterHandler(secret, new AliceAdapter());
        var response = await handler.HandleAsync(ToRequest(ok));
        Assert.Equal(200, response.StatusCode);
        Assert.Equal("ext_alice", JsonDocument.Parse(response.Body).RootElement.GetProperty("user").GetProperty("id").GetString());
        Assert.True(Signature.Verify([secret], response.Headers["9in-signature"], "POST", ok.Text("path") + "#" + ok.Text("requestId"), response.Body));
        Assert.Equal(401, (await handler.HandleAsync(ToRequest(refused))).StatusCode);
        Assert.Equal(401, (await handler.HandleAsync(ToRequest(ok, body: ok.Text("body")!.Replace("alice@", "bob@")))).StatusCode);
        Assert.Equal(401, (await handler.HandleAsync(ToRequest(ok, path: "/elsewhere/authenticate"))).StatusCode);
        Assert.Equal(405, (await handler.HandleAsync(ToRequest(ok, method: "GET"))).StatusCode);
        Assert.Equal(401, (await new AdapterHandler("not-the-secret", new AliceAdapter()).HandleAsync(ToRequest(ok))).StatusCode);
    }

    [Fact]
    public async Task ManagementRoundTrip()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var client = LiveFixture.Management();
        Assert.Equal(live.ManagedEmail, managed.Email);
        Assert.True(managed.EmailVerified);
        Assert.False(managed.Blocked);
        Assert.Equal(Live.Run, (string?)managed.Metadata!["run"]);
        var detail = await client.GetUserAsync(managed.Id);
        Assert.Equal(live.ManagedEmail, detail.User.Email);
        Assert.True(detail.HasPassword);
        Assert.Equal(managed.Id, (await client.FindUserByEmailAsync(live.ManagedEmail.ToUpperInvariant()))!.Id);
        Assert.Contains(managed.Id, (await client.ListUsersAsync(Live.Run, limit: 5)).Users.Select(u => u.Id));
        Assert.Equal("Renamed Dotnet", (await client.UpdateUserAsync(managed.Id, new UserChanges { Name = "Renamed Dotnet" })).Name);
        Assert.Equal(409, (await Assert.ThrowsAsync<NineException>(() => client.CreateUserAsync(new NewUser { Email = live.ManagedEmail, Password = live.ManagedPassword }))).StatusCode);
        Assert.Equal(404, (await Assert.ThrowsAsync<NineException>(() => client.GetUserAsync("usr_doesnotexist000000"))).StatusCode);
        Assert.Null(await client.FindUserByEmailAsync($"nobody-{Live.Run}@e2e.9in.test"));
        Assert.Null(await client.FindUserByUsernameAsync($"nobody_{Live.Run}"));
        var invalid = await Assert.ThrowsAsync<NineException>(() => client.UpdateUserAsync(managed.Id, new System.Text.Json.Nodes.JsonObject { ["emailVerified"] = true }));
        Assert.Equal("invalid_user", invalid.Error);
        Assert.Equal(400, invalid.StatusCode);
    }

    [Fact]
    public async Task BlocksAndUnblocksSignIn()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var client = LiveFixture.Management();
        Assert.True((await client.BlockUserAsync(managed.Id)).Blocked);
        try
        {
            using var browser = new Browser();
            var refused = await browser.SignIn((await LiveFixture.Server().CreateLoginAsync()).Url, Live.Env("SERVER_REDIRECT_URI"), live.ManagedEmail, live.ManagedPassword);
            Assert.Null(refused.Callback);
            Assert.Contains("blocked", refused.PageText, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Assert.False((await client.UnblockUserAsync(managed.Id)).Blocked);
        }
    }

    [Fact]
    public async Task ServerSignInRefreshAndRevoke()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var auth = LiveFixture.Server(o => { o.Audience = Audience; o.Scopes = ["openid", "profile", "email", "offline_access", "read:things"]; });
        var tokens = await live.ServerSignIn(auth);
        Assert.Equal("/account", tokens.ReturnTo);
        Assert.Equal(managed.Id, tokens.Claims.Subject);
        Assert.Equal(live.ManagedEmail, tokens.Claims.Email);
        Assert.Equal([Live.Env("SERVER_CLIENT_ID")], tokens.Claims.Audiences);
        Assert.Equal(managed.Id, (await auth.VerifyIdTokenAsync(tokens.IdToken!)).Subject);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("ISSUER") });
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyIdTokenAsync(tokens.IdToken, "app_someoneelse"));
        Assert.Equal(live.ManagedEmail, (await auth.GetUserInfoAsync(tokens.AccessToken)).Email);
        var access = new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("ISSUER"), Audience = Audience });
        Assert.Equal(managed.Id, (await access.VerifyAsync(tokens.AccessToken, "read:things")).Subject);

        Assert.Same(tokens, await auth.EnsureFreshAsync(tokens));
        var refreshed = await auth.EnsureFreshAsync(tokens with { ExpiresAt = DateTimeOffset.UtcNow });
        Assert.NotEqual(tokens.RefreshToken, refreshed.RefreshToken);
        Assert.Equal(refreshed.RefreshToken, (await auth.RefreshAsync(tokens)).RefreshToken); // the 30 s grace
        await auth.RevokeAsync(refreshed.RefreshToken!);
        foreach (var spent in new[] { refreshed, tokens }) // revoking the family ends the grace too
        {
            Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<NineException>(() => auth.RefreshAsync(spent))).Error);
        }
        Assert.StartsWith(Live.Env("ISSUER") + "/oauth/logout?", await auth.GetLogoutUrlAsync(refreshed.IdToken));
    }

    [Fact]
    public async Task ClientCredentials()
    {
        Live.RequireServerSecret();
        var auth = LiveFixture.Server();
        var tokens = await auth.ClientCredentialsAsync(Audience, "read:things");
        Assert.Null(tokens.RefreshToken);
        Assert.True(tokens.ExpiresAt > DateTimeOffset.UtcNow);
        var claims = await new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("ISSUER"), Audience = Audience }).VerifyAsync(tokens.AccessToken, "read:things");
        Assert.Equal(Live.Env("SERVER_CLIENT_ID"), claims.ClientId);
        Assert.Equal(Live.Env("SERVER_CLIENT_ID"), claims.Subject);
        // Cached for the HttpClient handler.
        Assert.Same(await auth.GetClientCredentialsTokenAsync(Audience), await auth.GetClientCredentialsTokenAsync(Audience));
    }

    [Fact]
    public async Task LoginLinksAndSilentSignIn()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var client = LiveFixture.Management();
        var redirect = Live.Env("SERVER_REDIRECT_URI");
        var link = await client.CreateLoginLinkAsync(managed.Id, redirect, TimeSpan.FromMinutes(5));
        Assert.StartsWith(Live.Env("ISSUER") + "/", link.Url);
        Assert.True(link.ExpiresAt > DateTimeOffset.UtcNow);
        using (var peek = new Browser())
        {
            Assert.Equal(200, (await peek.Request(HttpMethod.Get, link.Url)).Status); // a GET alone doesn't use it up
        }
        using var browser = new Browser();
        var landed = await browser.OpenLoginLink(link.Url, redirect);
        Assert.True(landed.Callback?.StartsWith(redirect, StringComparison.Ordinal) == true, landed.PageText);
        using (var other = new Browser())
        {
            var reused = await other.OpenLoginLink(link.Url, redirect);
            Assert.Null(reused.Callback);
            Assert.Equal(400, reused.Status);
        }

        var auth = LiveFixture.Server();
        var started = await auth.CreateLoginAsync(new LoginOptions { Prompt = "none" });
        var (url, _, _) = await browser.Follow(started.Url, redirect);
        Assert.Contains("code=", url);
        Assert.Equal(managed.Id, (await auth.HandleCallbackAsync(url, started.Pending)).Claims.Subject);

        Assert.True(await client.RevokeUserSessionsAsync(managed.Id) >= 1);
        var after = await auth.CreateLoginAsync(new LoginOptions { Prompt = "none" });
        var (denied, _, _) = await browser.Follow(after.Url, redirect);
        Assert.Contains("error=login_required", denied);
        Assert.Equal("login_required", (await Assert.ThrowsAsync<NineException>(() => auth.HandleCallbackAsync(denied, after.Pending))).Error);
    }

    [Fact]
    public async Task SessionsAndIntrospection()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var client = LiveFixture.Management();
        var auth = LiveFixture.Server(o => { o.Audience = Audience; o.Scopes = ["openid", "email", "offline_access", "read:things"]; });
        var tokens = await live.ServerSignIn(auth);
        var sid = tokens.Claims.SessionId!;
        var mine = (await client.ListUserSessionsAsync(managed.Id)).Single(s => s.Sid == sid);
        Assert.Equal(managed.Id, mine.UserId);
        Assert.Equal(["pwd"], mine.Amr);
        Assert.NotNull(mine.AuthTime);
        var introspect = new HybridTokenVerifier(new HybridTokenVerifierOptions
        {
            Issuer = Live.Env("ISSUER"), Audience = Audience, ClientId = Live.Env("SERVER_CLIENT_ID"), ClientSecret = Live.Env("SERVER_CLIENT_SECRET"), Mode = VerificationMode.Introspect,
        });
        Assert.Equal(sid, (await introspect.VerifyAsync(tokens.AccessToken)).SessionId);
        await client.RevokeSessionAsync(sid);
        Assert.DoesNotContain(sid, (await client.ListUserSessionsAsync(managed.Id)).Select(s => s.Sid));
        await Assert.ThrowsAsync<InvalidTokenException>(() => introspect.VerifyAsync(tokens.AccessToken));
        Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<NineException>(() => auth.RefreshAsync(tokens))).Error);
        Assert.Equal(404, (await Assert.ThrowsAsync<NineException>(() => client.RevokeSessionAsync(sid))).StatusCode);
    }

    [Fact]
    public async Task ImportUsers()
    {
        Live.RequireServerSecret();
        var client = LiveFixture.Management();
        var userId = $"e2e|dn{Live.Run}";
        var email = $"imported-dotnet-{Live.Run}@e2e.9in.test";
        var password = $"Imp-{Live.Run}-Password!";
        try
        {
            var first = await client.ImportUsersAsync(
                [
                    new ImportUser { Id = userId, Email = email, EmailVerified = true, Name = "Imported Dotnet", Password = password, CreatedAt = DateTimeOffset.Parse("2020-01-02T04:04:05+01:00", System.Globalization.CultureInfo.InvariantCulture) },
                    new ImportUser { Email = $"broken-dotnet-{Live.Run}@e2e.9in.test", PasswordHash = "md5:not-supported" },
                ],
                new ImportOptions { Source = "e2e-dotnet" });
            Assert.Equal(new ImportResult { Index = 0, Ok = true, Status = "created", Id = userId }, first[0] with { Details = null });
            Assert.False(first[1].Ok);
            Assert.Equal("unsupported_password_hash", first[1].Error);
            Assert.Equal("skipped", (await client.ImportUsersAsync([new ImportUser { Id = userId, Email = email, Name = "Changed" }]))[0].Status);
            Assert.Equal("updated", (await client.ImportUsersAsync([new ImportUser { Id = userId, Email = email, Name = "Changed" }], new ImportOptions { OnConflict = "update" }))[0].Status);
            var found = (await client.GetUserAsync(userId)).User;
            Assert.Equal("Changed", found.Name);
            Assert.Equal(new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero), found.CreatedAt);
            var auth = LiveFixture.Server();
            var started = await auth.CreateLoginAsync();
            using var browser = new Browser();
            var result = await browser.SignIn(started.Url, Live.Env("SERVER_REDIRECT_URI"), email, password);
            Assert.True(result.Callback is not null, result.PageText);
            Assert.Equal(userId, (await auth.HandleCallbackAsync(result.Callback!, started.Pending)).Claims.Subject);
        }
        finally
        {
            try
            {
                await client.DeleteUserAsync(userId);
            }
            catch (NineException)
            {
            }
        }
    }

    [Fact]
    public async Task HybridDropsARevokedTokenWhenTheWebhookArrives()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var auth = LiveFixture.Server(o => { o.Audience = Audience; o.Scopes = ["openid", "email", "offline_access", "read:things"]; });
        var tokens = await live.ServerSignIn(auth);
        var shared = new NineMemoryCache();
        HybridTokenVerifier Verifier(VerificationMode? mode, bool credentials = true) => new(new HybridTokenVerifierOptions
        {
            Issuer = Live.Env("ISSUER"), Audience = Audience, Mode = mode, Cache = shared,
            ClientId = credentials ? Live.Env("SERVER_CLIENT_ID") : null, ClientSecret = credentials ? Live.Env("SERVER_CLIENT_SECRET") : null,
        });
        var hybrid = Verifier(null);
        var introspect = Verifier(VerificationMode.Introspect);
        var local = Verifier(null, credentials: false);
        Assert.Equal(VerificationMode.Hybrid, hybrid.Mode);
        Assert.Equal(VerificationMode.Local, local.Mode);
        var claims = await hybrid.VerifyAsync(tokens.AccessToken, "read:things");
        Assert.Equal(managed.Id, claims.Subject);
        await Assert.ThrowsAsync<InsufficientScopeException>(() => hybrid.VerifyAsync(tokens.AccessToken, "write:things"));

        await auth.RevokeAsync(tokens.AccessToken, "access_token");
        await Assert.ThrowsAsync<InvalidTokenException>(() => introspect.VerifyAsync(tokens.AccessToken));
        Assert.Equal(managed.Id, (await local.VerifyAsync(tokens.AccessToken)).Subject); // local: valid until it expires
        Assert.Equal(managed.Id, (await hybrid.VerifyAsync(tokens.AccessToken)).Subject); // cached until 9in tells us

        var revoked = await Live.WaitFor("webhooks", r => r.Text("type") == "token.revoked" && r.Text("environment") == "production"
            && JsonDocument.Parse(r.Text("raw")!).RootElement.GetProperty("data").Text("jti") == claims.TokenId);
        var webhookEvent = Webhook.Verify(Live.Env("WEBHOOK_SECRET"), revoked.Text("raw")!, revoked.Text("signature"), revoked.Text("path")!, tolerance: TimeSpan.FromHours(1));
        Assert.True(await hybrid.HandleEventAsync(webhookEvent));
        await Assert.ThrowsAsync<InvalidTokenException>(() => hybrid.VerifyAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task OpaqueAccessTokens()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        var opaque = Live.Env("OPAQUE_API_AUDIENCE");
        var auth = LiveFixture.Server(o => { o.Audience = opaque; o.Scopes = ["openid", "offline_access"]; });
        var tokens = await live.ServerSignIn(auth);
        Assert.StartsWith(HybridTokenVerifier.OpaquePrefix, tokens.AccessToken);
        HybridTokenVerifierOptions Options(string audience, bool credentials = true) => new()
        {
            Issuer = Live.Env("ISSUER"), Audience = audience,
            ClientId = credentials ? Live.Env("SERVER_CLIENT_ID") : null, ClientSecret = credentials ? Live.Env("SERVER_CLIENT_SECRET") : null,
        };
        var hybrid = new HybridTokenVerifier(Options(opaque));
        Assert.Equal(managed.Id, (await hybrid.VerifyAsync(tokens.AccessToken)).Subject);
        Assert.Equal(managed.Id, (await hybrid.VerifyAsync(tokens.AccessToken)).Subject); // cached
        await Assert.ThrowsAsync<InvalidTokenException>(() => new HybridTokenVerifier(Options(opaque, credentials: false)).VerifyAsync(tokens.AccessToken));
        await Assert.ThrowsAsync<InvalidTokenException>(() => new HybridTokenVerifier(Options(Audience)).VerifyAsync(tokens.AccessToken));
        await Assert.ThrowsAsync<InvalidTokenException>(() => new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("ISSUER") }).VerifyAsync(tokens.AccessToken));
    }

    [Fact]
    public async Task RefusesAWrongClientSecret()
    {
        Live.RequireServerSecret();
        var wrong = new ManagementClient(new ManagementClientOptions { Issuer = Live.Env("ISSUER"), ClientId = Live.Env("SERVER_CLIENT_ID"), ClientSecret = "not-the-secret" });
        var e = await Assert.ThrowsAsync<NineException>(() => wrong.ListUsersAsync());
        Assert.Equal("invalid_client", e.Error);
        Assert.Equal(401, e.StatusCode);
    }

    internal sealed class FixedClock(long unixSeconds) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
    }
}

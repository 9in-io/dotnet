using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;
using Nine.Tests.Support;

namespace Nine.Tests;

public class HybridTokenVerifierTests
{
    private readonly FakeIssuer _fake = new();
    private readonly TestKey _key = TestKey.Create("ES256", "k1");
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);
    /// <summary>Tokens 9in considers active (by token string); everything else introspects as inactive.</summary>
    private readonly Dictionary<string, JsonObject> _active = [];

    public HybridTokenVerifierTests()
    {
        _fake.AddKey(_key);
        _fake.On("POST", "/oauth/introspect", request =>
        {
            if (request.Authorization != "Basic " + Convert.ToBase64String("api_client:api_secret"u8.ToArray()))
            {
                return FakeIssuer.Error("invalid_client", HttpStatusCode.Unauthorized);
            }
            var token = request.Form["token"];
            return _active.TryGetValue(token, out var claims)
                ? FakeIssuer.Json(new JsonObject { ["active"] = true, ["token_type"] = "access_token" }.Merge(claims))
                : FakeIssuer.Json(new JsonObject { ["active"] = false });
        });
    }

    private HybridTokenVerifier Verifier(VerificationMode? mode = null, INineCache? cache = null, TimeSpan? ttl = null) => new(new HybridTokenVerifierOptions
    {
        Issuer = _fake.Issuer,
        Audience = "https://api.acme.test",
        ClientId = "api_client",
        ClientSecret = "api_secret",
        Mode = mode,
        Cache = cache,
        CacheTtl = ttl ?? TimeSpan.FromMinutes(5),
        TimeProvider = _clock,
    }, _fake.Client());

    private (string Token, JsonObject Claims) Jwt(int lifetimeSeconds = 3600, string sub = "usr_1", string sid = "sid_1")
    {
        var now = _clock.GetUtcNow().ToUnixTimeSeconds();
        var claims = new JsonObject
        {
            ["iss"] = _fake.Issuer, ["sub"] = sub, ["aud"] = "https://api.acme.test", ["client_id"] = "app_1",
            ["scope"] = "orders:read", ["jti"] = Guid.NewGuid().ToString("N"), ["sid"] = sid, ["iat"] = now, ["exp"] = now + lifetimeSeconds,
        };
        var token = TestJwt.Sign(_key, claims);
        _active[token] = claims;
        return (token, claims);
    }

    private int Introspections => _fake.Count("POST", "/oauth/introspect");

    private static WebhookEvent Event(string type, object data) =>
        WebhookEvent.Parse(JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["id"] = "evt_" + Guid.NewGuid().ToString("N"), ["event_type"] = type, ["data"] = data }));

    [Fact]
    public void HybridByDefaultWithCredentialsLocalWithout()
    {
        Assert.Equal(VerificationMode.Hybrid, Verifier().Mode);
        Assert.Equal(VerificationMode.Local, new HybridTokenVerifier(new HybridTokenVerifierOptions { Issuer = _fake.Issuer }).Mode);
        var e = Assert.Throws<NineException>(() => new HybridTokenVerifier(new HybridTokenVerifierOptions { Issuer = _fake.Issuer, Mode = VerificationMode.Introspect }));
        Assert.Equal("invalid_options", e.Error);
        Assert.Equal(VerificationMode.Introspect, HybridTokenVerifierOptions.ParseMode(" Introspect "));
        Assert.Throws<NineException>(() => HybridTokenVerifierOptions.ParseMode("remote"));
    }

    [Fact]
    public async Task IntrospectsOncePerTokenAndCaches()
    {
        var verifier = Verifier();
        var (token, _) = Jwt();
        Assert.Equal("usr_1", (await verifier.VerifyAsync(token, "orders:read")).Subject);
        Assert.Equal("usr_1", (await verifier.VerifyAsync("Bearer " + token)).Subject);
        Assert.Equal(1, Introspections);
        // client_secret_basic on the introspection request
        Assert.StartsWith("Basic ", _fake.Last("/oauth/introspect").Authorization);
        // Scope is still checked on cached answers.
        await Assert.ThrowsAsync<InsufficientScopeException>(() => verifier.VerifyAsync(token, "orders:write"));
    }

    [Fact]
    public async Task ConcurrentVerificationsShareOneIntrospection()
    {
        var verifier = Verifier();
        var (token, _) = Jwt();
        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => verifier.VerifyAsync(token)));
        Assert.All(results, c => Assert.Equal("usr_1", c.Subject));
        Assert.InRange(Introspections, 1, 2);
    }

    [Fact]
    public async Task AnswersAreTrustedForCacheTtlButNeverPastExpiry()
    {
        var verifier = Verifier(ttl: TimeSpan.FromSeconds(60));
        var (token, _) = Jwt(lifetimeSeconds: 3600);
        await verifier.VerifyAsync(token);
        _clock.Advance(TimeSpan.FromSeconds(59));
        await verifier.VerifyAsync(token);
        Assert.Equal(1, Introspections);
        _clock.Advance(TimeSpan.FromSeconds(2));
        await verifier.VerifyAsync(token);
        Assert.Equal(2, Introspections);

        // A token expiring in 20 s is cached for 20 s, not 60.
        var (shortLived, _) = Jwt(lifetimeSeconds: 20);
        await verifier.VerifyAsync(shortLived);
        _clock.Advance(TimeSpan.FromSeconds(21));
        await verifier.VerifyAsync(shortLived); // within the 30 s leeway, so asked again
        Assert.Equal(4, Introspections);
    }

    [Fact]
    public async Task ARevokedTokenIsRefusedAndTheRefusalCachedUntilExpiry()
    {
        var verifier = Verifier(ttl: TimeSpan.FromSeconds(30));
        var (token, _) = Jwt(lifetimeSeconds: 600);
        _active.Remove(token);
        var e = await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
        Assert.Equal("token revoked", e.ErrorDescription);
        _clock.Advance(TimeSpan.FromSeconds(300)); // past cacheTtl, before exp
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
        Assert.Equal(1, Introspections);
    }

    [Fact]
    public async Task RefreshTokensAreNotAccessTokens()
    {
        _fake.On("POST", "/oauth/introspect", _ => FakeIssuer.Json(new JsonObject { ["active"] = true, ["token_type"] = "refresh_token" }));
        var (token, _) = Jwt();
        await Assert.ThrowsAsync<InvalidTokenException>(() => Verifier().VerifyAsync(token));
    }

    [Theory]
    [InlineData("token.revoked", "jti")]
    [InlineData("session.revoked", "sid")]
    [InlineData("user.sessions_revoked", "sub")]
    [InlineData("user.deleted", "sub")]
    [InlineData("user.updated", "sub")]
    [InlineData("user.password_changed", "sub")]
    public async Task WebhookEventsEvictCachedAnswers(string type, string claim)
    {
        var verifier = Verifier();
        var (token, claims) = Jwt();
        var (other, _) = Jwt(sub: "usr_2", sid: "sid_2");
        await verifier.VerifyAsync(token);
        await verifier.VerifyAsync(other);
        Assert.Equal(2, Introspections);

        _active.Remove(token); // 9in now says it is revoked
        object data = claim switch
        {
            "jti" => new { token_type = "access_token", jti = (string)claims["jti"]!, client_id = "app_1" },
            "sid" => new { sid = "sid_1" },
            _ => new { user = new { id = "usr_1" } },
        };
        _clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(await verifier.HandleEventAsync(Event(type, data)));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
        Assert.Equal(3, Introspections);
        // Other users' answers stay cached.
        await verifier.VerifyAsync(other);
        Assert.Equal(3, Introspections);
    }

    [Fact]
    public async Task IrrelevantEventsEvictNothing()
    {
        var verifier = Verifier();
        Assert.False(await verifier.HandleEventAsync(Event("user.created", new { user = new { id = "usr_1" } })));
        Assert.False(await verifier.HandleEventAsync(Event("token.revoked", new { token_type = "refresh_token", jti = "x" })));
        Assert.False(await verifier.HandleEventAsync(Event("session.revoked", new { })));
        Assert.False(await verifier.HandleEventAsync(Event("user.deleted", new { user = (object?)null })));
    }

    [Fact]
    public async Task AnswersCachedAfterAnEventStillCount()
    {
        var verifier = Verifier();
        var (token, _) = Jwt();
        Assert.True(await verifier.HandleEventAsync(Event("user.updated", new { user = new { id = "usr_1" }, fields = new[] { "name" } })));
        _clock.Advance(TimeSpan.FromSeconds(10));
        await verifier.VerifyAsync(token);
        await verifier.VerifyAsync(token);
        Assert.Equal(1, Introspections);
    }

    [Fact]
    public async Task ASharedCacheCarriesEvictionsAcrossServers()
    {
        var shared = new NineMemoryCache(timeProvider: _clock);
        var serverA = Verifier(cache: shared);
        var serverB = Verifier(cache: shared);
        var (token, _) = Jwt();
        await serverA.VerifyAsync(token);
        await serverB.VerifyAsync(token);
        Assert.Equal(1, Introspections); // B used A's answer

        _active.Remove(token);
        _clock.Advance(TimeSpan.FromSeconds(10));
        await serverA.HandleEventAsync(Event("session.revoked", new { sid = "sid_1" })); // the webhook reached A only
        await Assert.ThrowsAsync<InvalidTokenException>(() => serverB.VerifyAsync(token));
    }

    [Fact]
    public async Task OpaqueTokensAreAlwaysIntrospected()
    {
        var now = _clock.GetUtcNow().ToUnixTimeSeconds();
        _active["9in_at_live"] = new JsonObject
        {
            ["iss"] = _fake.Issuer, ["sub"] = "usr_9", ["aud"] = "https://api.acme.test", ["scope"] = "orders:read", ["exp"] = now + 600, ["jti"] = "j9", ["sid"] = "s9",
        };
        var hybrid = Verifier();
        Assert.Equal("usr_9", (await hybrid.VerifyAsync("9in_at_live", "orders:read")).Subject);
        await hybrid.VerifyAsync("9in_at_live");
        Assert.Equal(1, Introspections);
        await Assert.ThrowsAsync<InsufficientScopeException>(() => hybrid.VerifyAsync("9in_at_live", "admin"));

        // The introspection answer is checked like a token: audience, issuer, expiry.
        _active["9in_at_other_api"] = new JsonObject { ["iss"] = _fake.Issuer, ["sub"] = "u", ["aud"] = "https://other.test", ["exp"] = now + 600 };
        Assert.Equal("audience mismatch", (await Assert.ThrowsAsync<InvalidTokenException>(() => hybrid.VerifyAsync("9in_at_other_api"))).ErrorDescription);

        // A refusal is cached for a minute.
        await Assert.ThrowsAsync<InvalidTokenException>(() => hybrid.VerifyAsync("9in_at_dead"));
        await Assert.ThrowsAsync<InvalidTokenException>(() => hybrid.VerifyAsync("9in_at_dead"));
        var before = Introspections;
        _clock.Advance(TimeSpan.FromSeconds(61));
        await Assert.ThrowsAsync<InvalidTokenException>(() => hybrid.VerifyAsync("9in_at_dead"));
        Assert.Equal(before + 1, Introspections);

        var local = new HybridTokenVerifier(new HybridTokenVerifierOptions { Issuer = _fake.Issuer }, _fake.Client());
        Assert.Contains("hybrid or introspect", (await Assert.ThrowsAsync<InvalidTokenException>(() => local.VerifyAsync("9in_at_live"))).ErrorDescription);
    }

    [Fact]
    public async Task IntrospectModeAsksEveryTime()
    {
        var verifier = Verifier(VerificationMode.Introspect);
        var (token, _) = Jwt();
        await verifier.VerifyAsync(token);
        await verifier.VerifyAsync(token);
        Assert.Equal(2, Introspections);
        _active.Remove(token);
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
    }

    [Fact]
    public async Task LocalModeNeverCallsIntrospection()
    {
        var verifier = Verifier(VerificationMode.Local);
        var (token, _) = Jwt();
        _active.Remove(token);
        Assert.Equal("usr_1", (await verifier.VerifyAsync(token)).Subject);
        Assert.Equal(0, Introspections);
    }

    [Fact]
    public async Task LocalChecksComeFirst()
    {
        var verifier = Verifier();
        var (token, _) = Jwt();
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token[..^4] + "AAAA"));
        Assert.Equal(0, Introspections);
    }

    [Fact]
    public async Task IntrospectionFailuresAreNotInvalidTokens()
    {
        _fake.On("POST", "/oauth/introspect", _ => FakeIssuer.Error("server_error", HttpStatusCode.InternalServerError));
        var (token, _) = Jwt();
        var e = await Assert.ThrowsAsync<NineException>(() => Verifier().VerifyAsync(token));
        Assert.IsNotType<InvalidTokenException>(e);
        Assert.Equal(500, e.StatusCode);
    }
}

internal static class JsonObjectExtensions
{
    public static JsonObject Merge(this JsonObject target, JsonObject source)
    {
        foreach (var (key, value) in source)
        {
            target[key] = value?.DeepClone();
        }
        return target;
    }
}

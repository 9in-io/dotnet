using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;
using Nine.Tests.Support;

namespace Nine.Tests;

public class TokenVerifierTests
{
    private readonly FakeIssuer _fake = new();
    private readonly TestKey _key = TestKey.Create("RS256", "k1");

    public TokenVerifierTests() => _fake.AddKey(_key);

    private TokenVerifier Verifier(Action<TokenVerifierOptions>? configure = null)
    {
        var options = new TokenVerifierOptions { Issuer = _fake.Issuer, Audience = "https://api.acme.test" };
        configure?.Invoke(options);
        return new TokenVerifier(options, _fake.Client());
    }

    private string Token(Action<JsonObject>? edit = null)
    {
        var claims = AlgorithmsTests.Claims(_fake.Issuer);
        edit?.Invoke(claims);
        return TestJwt.Sign(_key, claims);
    }

    private async Task<string> Refused(string? token, Action<TokenVerifierOptions>? configure = null, string? scope = null)
    {
        var e = await Assert.ThrowsAsync<InvalidTokenException>(() => Verifier(configure).VerifyAsync(token, scope));
        Assert.Equal("invalid_token", e.Error);
        Assert.Equal(401, e.StatusCode);
        return e.ErrorDescription!;
    }

    [Fact]
    public async Task AcceptsAValidTokenWithOrWithoutTheBearerPrefix()
    {
        var token = Token();
        Assert.Equal("usr_2", (await Verifier().VerifyAsync(token)).Subject);
        Assert.Equal("usr_2", (await Verifier().VerifyAsync("Bearer " + token)).Subject);
        Assert.Equal("usr_2", (await Verifier().VerifyAsync("bearer   " + token + " ")).Subject);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Bearer ")]
    public async Task MissingToken(string? token) => Assert.Equal("missing token", await Refused(token));

    [Theory]
    [InlineData("abc")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("!!!.???.###")]
    [InlineData("eyJhbGciOiJSUzI1NiJ9.bm90IGpzb24.c2ln")]
    [InlineData("WzFd.WzFd.c2ln")]
    public async Task MalformedTokens(string token) => Assert.Equal("malformed token", await Refused(token));

    [Fact]
    public async Task IssuerMismatch()
    {
        Assert.Equal("issuer mismatch", await Refused(Token(c => c["iss"] = "https://evil.9in.test")));
        Assert.Equal("issuer mismatch", await Refused(Token(c => c.Remove("iss"))));
        // A trailing slash on either side is the same issuer.
        Assert.Equal("usr_2", (await Verifier().VerifyAsync(Token(c => c["iss"] = _fake.Issuer + "/"))).Subject);
    }

    [Fact]
    public async Task ExpiryAndNotBeforeWithLeeway()
    {
        var now = TestJwt.Now();
        Assert.Equal("token expired", await Refused(Token(c => c["exp"] = now - 31)));
        Assert.Equal("token expired", await Refused(Token(c => c.Remove("exp"))));
        Assert.Equal("token expired", await Refused(Token(c => c["exp"] = "4102444800")));
        Assert.Equal("usr_2", (await Verifier().VerifyAsync(Token(c => c["exp"] = now - 20))).Subject);
        Assert.Equal("token not yet valid", await Refused(Token(c => c["nbf"] = now + 60)));
        Assert.Equal("usr_2", (await Verifier().VerifyAsync(Token(c => c["nbf"] = now + 20))).Subject);
        Assert.Equal("token expired", await Refused(Token(c => c["exp"] = now - 5), o => o.Leeway = TimeSpan.Zero));
    }

    [Fact]
    public async Task UsesTheInjectedClock()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var token = Token();
        Assert.Equal("usr_2", (await Verifier(o => o.TimeProvider = clock).VerifyAsync(token)).Subject);
        clock.Advance(TimeSpan.FromSeconds(331));
        Assert.Equal("token expired", await Refused(token, o => o.TimeProvider = clock));
    }

    [Fact]
    public async Task Audience()
    {
        Assert.Equal("audience mismatch", await Refused(Token(c => c["aud"] = "https://other.test")));
        Assert.Equal("audience mismatch", await Refused(Token(c => c.Remove("aud"))));
        Assert.Equal("usr_2", (await Verifier().VerifyAsync(Token(c => c["aud"] = new JsonArray("x", "https://api.acme.test")))).Subject);
        Assert.Equal("usr_2", (await Verifier(o => { o.Audience = null; o.Audiences.Add("x"); o.Audiences.Add("https://api.acme.test"); }).VerifyAsync(Token())).Subject);
        // No audience configured: no audience check.
        Assert.Equal("usr_2", (await Verifier(o => o.Audience = null).VerifyAsync(Token(c => c["aud"] = "https://other.test"))).Subject);
    }

    [Fact]
    public async Task Scopes()
    {
        var verifier = Verifier();
        Assert.Equal("usr_2", (await verifier.VerifyAsync(Token(), "orders:read")).Subject);
        Assert.Equal("usr_2", (await verifier.VerifyAsync(Token(), " openid  orders:read ")).Subject);
        var e = await Assert.ThrowsAsync<InsufficientScopeException>(() => verifier.VerifyAsync(Token(), "orders:read orders:write"));
        Assert.Equal("insufficient_scope", e.Error);
        Assert.Equal(403, e.StatusCode);
        Assert.Equal(["orders:write"], e.MissingScopes);
        await Assert.ThrowsAsync<InsufficientScopeException>(() => verifier.VerifyAsync(Token(c => c.Remove("scope")), "orders:read"));
        // "orders" is not "orders:read".
        await Assert.ThrowsAsync<InsufficientScopeException>(() => verifier.VerifyAsync(Token(), "orders"));
    }

    [Fact]
    public async Task UnknownKidRefetchesOnceThenIsThrottled()
    {
        var verifier = Verifier();
        Assert.Equal("usr_2", (await verifier.VerifyAsync(Token())).Subject);
        Assert.Equal(1, _fake.Count("GET", "/.well-known/jwks.json"));

        // A key added at rotation: unknown kid → one refetch finds it.
        var rotated = TestKey.Create("ES256", "k2");
        _fake.AddKey(rotated);
        Assert.Equal("usr_2", (await verifier.VerifyAsync(TestJwt.Sign(rotated, AlgorithmsTests.Claims(_fake.Issuer)))).Subject);
        Assert.Equal(2, _fake.Count("GET", "/.well-known/jwks.json"));

        // A junk kid: one refetch, then ignored for a minute.
        var junk = TestJwt.Sign(TestKey.Create("ES256", "junk"), AlgorithmsTests.Claims(_fake.Issuer));
        Assert.Equal("unknown signing key", await Refused(junk));
        Assert.Equal(3, _fake.Count("GET", "/.well-known/jwks.json"));
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal("unknown signing key", await Refused(junk));
        }
        Assert.Equal(3, _fake.Count("GET", "/.well-known/jwks.json"));
    }

    [Fact]
    public async Task TheThrottleEndsAfterAMinuteAndKeysAreCachedTenMinutes()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var verifier = Verifier(o => o.TimeProvider = clock);
        var later = TestKey.Create("ES256", "later");
        JsonObject LongLived()
        {
            var claims = AlgorithmsTests.Claims(_fake.Issuer);
            claims["exp"] = TestJwt.Now() + 7200;
            return claims;
        }
        var token = TestJwt.Sign(later, LongLived());
        Assert.Equal("unknown signing key", await Refused(token, o => o.TimeProvider = clock));
        Assert.Equal(2, _fake.Count("GET", "/.well-known/jwks.json")); // first fetch + one refetch
        _fake.AddKey(later);
        Assert.Equal("unknown signing key", await Refused(token, o => o.TimeProvider = clock)); // throttled
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal("usr_2", (await verifier.VerifyAsync(token)).Subject);
        Assert.Equal(3, _fake.Count("GET", "/.well-known/jwks.json"));

        // Known keys come from the cache until it is ten minutes old.
        clock.Advance(TimeSpan.FromMinutes(9));
        await verifier.VerifyAsync(TestJwt.Sign(_key, LongLived()));
        Assert.Equal(3, _fake.Count("GET", "/.well-known/jwks.json"));
        clock.Advance(TimeSpan.FromMinutes(2));
        await verifier.VerifyAsync(TestJwt.Sign(_key, LongLived()));
        Assert.Equal(4, _fake.Count("GET", "/.well-known/jwks.json"));
    }

    [Fact]
    public async Task JwksAndDiscoveryFailuresAreNotInvalidTokens()
    {
        _fake.On("GET", "/.well-known/jwks.json", _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var e = await Assert.ThrowsAsync<NineException>(() => Verifier().VerifyAsync(Token()));
        Assert.Equal("jwks_unavailable", e.Error);
        Assert.IsNotType<InvalidTokenException>(e);

        var down = new FakeIssuer();
        down.On("GET", "/.well-known/openid-configuration", _ => new HttpResponseMessage(HttpStatusCode.BadGateway));
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = down.Issuer }, down.Client());
        var claims = AlgorithmsTests.Claims(down.Issuer);
        Assert.Equal("discovery_failed", (await Assert.ThrowsAsync<NineException>(() => verifier.VerifyAsync(TestJwt.Sign(_key, claims)))).Error);
    }

    [Fact]
    public async Task RefusesADiscoveryDocumentForAnotherIssuer()
    {
        var fake = new FakeIssuer();
        fake.Discovery["issuer"] = "https://evil.9in.test";
        fake.AddKey(_key);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        var e = await Assert.ThrowsAsync<NineException>(() => verifier.VerifyAsync(TestJwt.Sign(_key, AlgorithmsTests.Claims(fake.Issuer))));
        Assert.Equal("discovery_failed", e.Error);
    }

    [Fact]
    public async Task DoesNotFollowRedirects()
    {
        var fake = new FakeIssuer();
        fake.On("GET", "/.well-known/openid-configuration", _ => new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://evil.test/") } });
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        var e = await Assert.ThrowsAsync<NineException>(() => verifier.VerifyAsync(TestJwt.Sign(_key, AlgorithmsTests.Claims(fake.Issuer))));
        Assert.Equal("discovery_failed", e.Error);
        Assert.DoesNotContain(fake.Requests, r => r.Path == "/" );
    }

    [Fact]
    public async Task TimesOut()
    {
        var slow = new SlowHandler();
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = "https://slow.9in.test", Timeout = TimeSpan.FromMilliseconds(200) }, new HttpClient(slow));
        var e = await Assert.ThrowsAsync<NineException>(() => verifier.VerifyAsync(TestJwt.Sign(_key, AlgorithmsTests.Claims("https://slow.9in.test"))));
        Assert.Equal("network_error", e.Error);
        Assert.Contains("within", e.ErrorDescription);
    }

    private sealed class SlowHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}

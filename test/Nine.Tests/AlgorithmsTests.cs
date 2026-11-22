using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nine.Tests.Support;

namespace Nine.Tests;

/// <summary>
/// Every algorithm 9in signs access tokens with: vectors signed by WebCrypto (as used by @9in-io/sdk and
/// the 9in server; shared with the PHP SDK) and tokens signed here with .NET.
/// </summary>
public class AlgorithmsTests
{
    private static readonly JsonObject Vectors = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "jws-vectors.json")))!.AsObject();
    private static readonly string VectorIssuer = (string)Vectors["issuer"]!;
    private static readonly string HmacSecret = (string)Vectors["hmacSecret"]!;
    private static readonly object VectorLock = new();

    public static TheoryData<string> Algorithms => new(TestKey.AllAlgorithms);

    private static string VectorToken(string alg) => (string)Vectors["tokens"]![alg]!;

    /// <summary>A verifier for the vectors' issuer, with the vectors' JWKS (or a modified copy).</summary>
    private static TokenVerifier VectorVerifier(Action<JsonObject>? editKey = null, string? secret = null)
    {
        var fake = new FakeIssuer(VectorIssuer);
        foreach (var key in Vectors["jwks"]!["keys"]!.AsArray())
        {
            var copy = key!.DeepClone().AsObject();
            editKey?.Invoke(copy);
            fake.Keys.Add(copy);
        }
        // The vectors share one issuer, so each test starts from an empty cache for it.
        lock (VectorLock)
        {
            TokenVerifier.ClearCaches(VectorIssuer);
        }
        return new TokenVerifier(new TokenVerifierOptions { Issuer = VectorIssuer, Secret = secret }, fake.Client());
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task VerifiesWebCryptoVectors(string alg)
    {
        ClaimSet claims;
        lock (VectorLock)
        {
            claims = VectorVerifier(secret: HmacSecret).VerifyAsync(VectorToken(alg), "orders:read").GetAwaiter().GetResult();
        }
        Assert.Equal("usr_1", claims.Subject);
        Assert.Equal("jti_1", claims.TokenId);
        Assert.Equal("sid_1", claims.SessionId);
        Assert.Equal("app_1", claims.ClientId);
        Assert.Equal(["https://api.acme.test"], claims.Audiences);
        await Task.CompletedTask;
    }

    [Fact]
    public void TamperedSignaturesFailForEveryAlgorithm()
    {
        lock (VectorLock)
        {
            var verifier = VectorVerifier(secret: HmacSecret);
            foreach (var alg in TestKey.AllAlgorithms)
            {
                var parts = VectorToken(alg).Split('.');
                var payload = JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(Pad(parts[1]))))!.AsObject();
                payload["sub"] = "usr_admin";
                parts[1] = TestJwt.B64(payload.ToJsonString());
                var e = Assert.Throws<InvalidTokenException>(() => verifier.VerifyAsync(string.Join('.', parts)).GetAwaiter().GetResult());
                Assert.Contains("bad signature", e.Message);
            }
        }
    }

    [Fact]
    public void RsaPssRequiresTheJwsSaltLength()
    {
        lock (VectorLock)
        {
            var e = Assert.Throws<InvalidTokenException>(() => VectorVerifier().VerifyAsync((string)Vectors["invalid"]!["PS256 salt length 0"]!).GetAwaiter().GetResult());
            Assert.Contains("bad signature", e.Message);
        }
    }

    [Fact]
    public void RefusesIdTokensAsAccessTokens()
    {
        lock (VectorLock)
        {
            var e = Assert.Throws<InvalidTokenException>(() => VectorVerifier().VerifyAsync((string)Vectors["invalid"]!["ES256 ID token (typ JWT)"]!).GetAwaiter().GetResult());
            Assert.Contains("not an access token", e.Message);
        }
    }

    [Fact]
    public void TheJwksKeyDecidesTheAlgorithm()
    {
        lock (VectorLock)
        {
            // The JWKS says RS256 for this key, the token says PS256.
            var verifier = VectorVerifier(key => { if ((string?)key["kid"] == "k-PS256") { key["alg"] = "RS256"; } });
            var e = Assert.Throws<InvalidTokenException>(() => verifier.VerifyAsync(VectorToken("PS256")).GetAwaiter().GetResult());
            Assert.Contains("does not match the key", e.Message);
        }
    }

    [Fact]
    public async Task AKeyWithoutAlgMustStillFitTheAlgorithm()
    {
        // An ES256 header pointing at an RSA key that names no alg.
        var fake = new FakeIssuer();
        var rsa = TestKey.Create("RS256", "rsa", includeAlg: false);
        fake.AddKey(rsa);
        var es = TestKey.Create("ES256", "rsa");
        var token = TestJwt.Sign(es, Claims(fake.Issuer));
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        var e = await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
        Assert.Contains("does not match the key", e.Message);

        // EdDSA header on an EC key, ES384 on a P-256 key.
        fake.AddKey(TestKey.Create("ES256", "p256", includeAlg: false));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(TestJwt.Sign(TestKey.Create("ES384", "p256"), Claims(fake.Issuer))));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(TestJwt.Sign(TestKey.Create("EdDSA", "p256"), Claims(fake.Issuer))));
    }

    [Fact]
    public void HmacTokensNeedTheRightSecret()
    {
        lock (VectorLock)
        {
            var e = Assert.Throws<InvalidTokenException>(() => VectorVerifier().VerifyAsync(VectorToken("HS256")).GetAwaiter().GetResult());
            Assert.Contains("secret", e.Message);
            e = Assert.Throws<InvalidTokenException>(() => VectorVerifier(secret: HmacSecret + "x").VerifyAsync(VectorToken("HS256")).GetAwaiter().GetResult());
            Assert.Contains("bad signature", e.Message);
        }
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task VerifiesDotnetSignedTokens(string alg)
    {
        var fake = new FakeIssuer();
        var key = TestKey.Create(alg);
        fake.AddKey(key);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer, Audience = "https://api.acme.test", Secret = key.Secret }, fake.Client());
        var claims = await verifier.VerifyAsync(TestJwt.Sign(key, Claims(fake.Issuer)), "orders:read");
        Assert.Equal("usr_2", claims.Subject);
    }

    [Fact]
    public async Task AcceptsAnRsaModulusWithALeadingZeroByte()
    {
        var fake = new FakeIssuer();
        var key = TestKey.Create("RS256", "zero");
        var n = Convert.FromBase64String(Pad((string)key.Jwk!["n"]!));
        key.Jwk["n"] = TestJwt.B64([0, .. n]);
        fake.AddKey(key);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        Assert.Equal("usr_2", (await verifier.VerifyAsync(TestJwt.Sign(key, Claims(fake.Issuer)))).Subject);
    }

    [Fact]
    public async Task AcceptsTheMediaTypeFormOfTyp()
    {
        var fake = new FakeIssuer();
        var key = TestKey.Create("ES256");
        fake.AddKey(key);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        Assert.Equal("usr_2", (await verifier.VerifyAsync(TestJwt.Sign(key, Claims(fake.Issuer), typ: "Application/AT+JWT"))).Subject);
        foreach (var typ in new[] { "JWT", "jwt", "at+jwt+x", "" })
        {
            var e = await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(TestJwt.Sign(key, Claims(fake.Issuer), typ: typ)));
            Assert.Contains("not an access token", e.Message);
        }
        var noTyp = TestJwt.Sign(key, Claims(fake.Issuer), header: h => h.Remove("typ"));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(noTyp));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("None")]
    [InlineData("HS1")]
    [InlineData("RS1")]
    [InlineData("ES512")]
    [InlineData("")]
    public async Task RefusesUnknownAlgorithms(string alg)
    {
        var fake = new FakeIssuer();
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer, Secret = "s" }, fake.Client());
        var token = TestJwt.Raw(new JsonObject { ["alg"] = alg, ["typ"] = "at+jwt" }, Claims(fake.Issuer), []);
        var e = await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
        Assert.Contains("unsupported algorithm", e.Message);
    }

    [Fact]
    public async Task RefusesCriticalHeaders()
    {
        var fake = new FakeIssuer();
        var key = TestKey.Create("ES256");
        fake.AddKey(key);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        var token = TestJwt.Sign(key, Claims(fake.Issuer), header: h => h["crit"] = new JsonArray("exp"));
        await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(token));
    }

    [Theory]
    [MemberData(nameof(AsymmetricAlgorithms))]
    public async Task IdTokensVerifyWithEveryAsymmetricAlgorithm(string alg)
    {
        var fake = new FakeIssuer();
        var key = TestKey.Create(alg);
        fake.AddKey(key);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        var token = TestJwt.Sign(key, new JsonObject { ["iss"] = fake.Issuer, ["sub"] = "u", ["aud"] = "app_1", ["nonce"] = "n1", ["exp"] = TestJwt.Now() + 60 }, typ: "JWT");
        Assert.Equal("u", (await verifier.VerifyIdTokenAsync(token, "app_1", "n1")).Subject);
    }

    public static TheoryData<string> AsymmetricAlgorithms => new(TestKey.AsymmetricAlgorithms);

    [Fact]
    public async Task IdTokensAreNeverHmacOrAccessTokens()
    {
        var fake = new FakeIssuer();
        var hs = TestKey.Create("HS256");
        var es = TestKey.Create("ES256");
        fake.AddKey(es);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer, Secret = hs.Secret }, fake.Client());
        var claims = new JsonObject { ["iss"] = fake.Issuer, ["sub"] = "u", ["aud"] = "app_1", ["exp"] = TestJwt.Now() + 60 };
        var e = await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyIdTokenAsync(TestJwt.Sign(hs, claims, typ: "JWT"), "app_1"));
        Assert.Contains("unsupported algorithm", e.Message);
        e = await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyIdTokenAsync(TestJwt.Sign(es, claims, typ: "at+jwt"), "app_1"));
        Assert.Contains("not an ID token", e.Message);
    }

    [Fact]
    public async Task RefusesSignaturesOfTheWrongLength()
    {
        var fake = new FakeIssuer();
        var es = TestKey.Create("ES256");
        var rs = TestKey.Create("RS256");
        fake.AddKey(es).AddKey(rs);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = fake.Issuer }, fake.Client());
        foreach (var key in new[] { es, rs })
        {
            var parts = TestJwt.Sign(key, Claims(fake.Issuer)).Split('.');
            var sig = Convert.FromBase64String(Pad(parts[2]));
            await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(parts[0] + "." + parts[1] + "." + TestJwt.B64([.. sig, 0])));
            await Assert.ThrowsAsync<InvalidTokenException>(() => verifier.VerifyAsync(parts[0] + "." + parts[1] + "." + TestJwt.B64(sig[..^1])));
        }
    }

    internal static JsonObject Claims(string issuer) => new()
    {
        ["iss"] = issuer,
        ["sub"] = "usr_2",
        ["aud"] = "https://api.acme.test",
        ["client_id"] = "app_2",
        ["scope"] = "openid orders:read",
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["iat"] = TestJwt.Now(),
        ["exp"] = TestJwt.Now() + 300,
    };

    private static string Pad(string b64url)
    {
        var s = b64url.Replace('-', '+').Replace('_', '/');
        return s + new string('=', (4 - s.Length % 4) % 4);
    }
}

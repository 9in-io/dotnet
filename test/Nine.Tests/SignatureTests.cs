using System.Text;
using Microsoft.Extensions.Time.Testing;

namespace Nine.Tests;

public class SignatureTests
{
    private const string Secret = "adapter_secret_test";
    private const string Body = """{"identifier":{"type":"email","value":"jane@acme.com"},"password":"hunter2"}""";

    [Fact]
    public void MatchesThePhpReferenceVectors()
    {
        // From sso-sdk/php/tests/SignatureTest.php: HMAC-SHA256("t.METHOD.path.body") as the 9in server computes it.
        Assert.Equal(
            "t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c",
            Signature.Sign(Secret, "post", "/nine/authenticate", Body, 1762682400));
        Assert.Equal(
            "t=1762682400,v1=1b9fb41e87bb256836ea5d5d6600270b77578ffd166d84a2cf35ab9841b3585a",
            Signature.Sign(Secret, "POST", "/nine/authenticate#req_123", """{"user":{"id":"42"}}""", 1762682400));
    }

    [Fact]
    public void BytesAndStringsSignTheSame()
    {
        Assert.Equal(Signature.Sign(Secret, "POST", "/p", "héllo", 1), Signature.Sign(Secret, "POST", "/p", Encoding.UTF8.GetBytes("héllo"), 1));
    }

    [Fact]
    public void RoundTrip()
    {
        var header = Signature.Sign(Secret, "POST", "/nine/user", """{"id":"1"}""");
        Assert.True(Signature.Verify(Secret, header, "POST", "/nine/user", """{"id":"1"}"""));
        Assert.True(Signature.Verify(Secret, header, "post", "/nine/user", """{"id":"1"}"""));
    }

    [Fact]
    public void RefusesTamperedBodyPathMethodAndSecret()
    {
        var header = Signature.Sign(Secret, "POST", "/nine/user", """{"id":"1"}""");
        SignatureFailure? Check(string secret, string method, string path, string body) =>
            Signature.Check([secret], header, method, path, Encoding.UTF8.GetBytes(body)).Failure;
        Assert.Equal(SignatureFailure.Mismatch, Check(Secret, "POST", "/nine/user", """{"id":"2"}"""));
        Assert.Equal(SignatureFailure.Mismatch, Check(Secret, "POST", "/nine/authenticate", """{"id":"1"}"""));
        Assert.Equal(SignatureFailure.Mismatch, Check(Secret, "GET", "/nine/user", """{"id":"1"}"""));
        Assert.Equal(SignatureFailure.Mismatch, Check("other", "POST", "/nine/user", """{"id":"1"}"""));
    }

    [Fact]
    public void RefusesReplaysOutsideTheTolerance()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var old = Signature.Sign(Secret, "POST", "/p", "b", now - 301);
        Assert.Equal(SignatureFailure.Expired, Signature.Check([Secret], old, "POST", "/p", "b"u8).Failure);
        Assert.True(Signature.Verify(Secret, old, "POST", "/p", "b", TimeSpan.FromSeconds(600)));
        var future = Signature.Sign(Secret, "POST", "/p", "b", now + 301);
        Assert.False(Signature.Verify(Secret, future, "POST", "/p", "b"));

        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_000_000));
        var header = Signature.Sign(Secret, "POST", "/p", "b", 1_000_000);
        clock.Advance(TimeSpan.FromSeconds(300));
        Assert.True(Signature.Verify([Secret], header, "POST", "/p", "b"u8, timeProvider: clock));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(SignatureFailure.Expired, Signature.Check([Secret], header, "POST", "/p", "b"u8, timeProvider: clock).Failure);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("t=abc,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("t=1")]
    [InlineData("v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("t=1,v1=ABC")]
    [InlineData("t=1,v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("=x")]
    [InlineData("t=1234567890123,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("t=-1,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void MalformedHeaders(string header)
    {
        Assert.Equal(SignatureFailure.Malformed, Signature.Check([Secret], header, "POST", "/p", "b"u8).Failure);
    }

    [Fact]
    public void MissingHeader()
    {
        Assert.Equal(SignatureFailure.Missing, Signature.Check([Secret], null, "POST", "/p", "b"u8).Failure);
        Assert.Equal(SignatureFailure.Missing, Signature.Check([Secret], "", "POST", "/p", "b"u8).Failure);
    }

    [Fact]
    public void SecretRotationAndSeveralSignatures()
    {
        var header = Signature.Sign("new-secret", "POST", "/p", "b");
        Assert.True(Signature.Verify(["old-secret", "new-secret"], header, "POST", "/p", "b"u8));

        var t = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var old = Signature.Sign("old-secret", "POST", "/p", "b", t);
        var combined = old + "," + Signature.Sign("new-secret", "POST", "/p", "b", t).Split(',')[1];
        Assert.True(Signature.Verify("new-secret", combined, "POST", "/p", "b"));
        Assert.True(Signature.Verify("old-secret", combined, "POST", "/p", "b"));
        // Unknown parts are ignored; empty secrets never match.
        Assert.True(Signature.Verify("new-secret", combined + ",v0=whatever", "POST", "/p", "b"));
        Assert.False(Signature.Verify(["", "nope"], header, "POST", "/p", "b"u8));
    }
}

public class PkceTests
{
    [Fact]
    public void MatchesTheRfc7636Example()
    {
        // RFC 7636 Appendix B.
        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.CreateChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    [Fact]
    public void VerifiersAreLongRandomAndUrlSafe()
    {
        var a = Pkce.CreateVerifier();
        var b = Pkce.CreateVerifier();
        Assert.NotEqual(a, b);
        Assert.InRange(a.Length, 43, 128);
        Assert.Matches("^[A-Za-z0-9_-]+$", a);
    }
}

public class IssuerTests
{
    [Theory]
    [InlineData("https://acme.9in.io", "https://acme.9in.io")]
    [InlineData("https://acme.9in.io/", "https://acme.9in.io")]
    [InlineData("https://login.acme.com:8443/", "https://login.acme.com:8443")]
    [InlineData("http://localhost:8787", "http://localhost:8787")]
    [InlineData("http://auth.localhost", "http://auth.localhost")]
    [InlineData("http://127.0.0.1:9000/", "http://127.0.0.1:9000")]
    [InlineData("http://[::1]:9000", "http://[::1]:9000")]
    public void AcceptsAndNormalises(string issuer, string expected) => Assert.Equal(expected, Issuer.Normalize(issuer));

    [Theory]
    [InlineData("http://acme.9in.io")]
    [InlineData("http://auth:8897")]
    [InlineData("http://localhost.evil.com")]
    [InlineData("http://128.0.0.1")]
    public void RefusesPlainHttp(string issuer) => Assert.Equal("insecure_issuer", Assert.Throws<NineException>(() => Issuer.Normalize(issuer)).Error);

    [Fact]
    public void TheOptOutAllowsPlainHttp() => Assert.Equal("http://auth:8897", Issuer.Normalize("http://auth:8897", allowInsecure: true));

    [Theory]
    [InlineData("https://acme.9in.io/?x=1")]
    [InlineData("https://acme.9in.io/#frag")]
    [InlineData("https://user:pass@acme.9in.io")]
    [InlineData("acme.9in.io")]
    [InlineData("ftp://acme.9in.io")]
    [InlineData("")]
    [InlineData(null)]
    public void RefusesNonIssuers(string? issuer) => Assert.Equal("invalid_issuer", Assert.Throws<NineException>(() => Issuer.Normalize(issuer)).Error);

    [Fact]
    public void EveryClientRefusesAnInsecureIssuer()
    {
        Assert.Equal("insecure_issuer", Assert.Throws<NineException>(() => new TokenVerifier(new TokenVerifierOptions { Issuer = "http://acme.9in.io" })).Error);
        Assert.Equal("insecure_issuer", Assert.Throws<NineException>(() => new AuthClient(new AuthClientOptions { Issuer = "http://acme.9in.io", ClientId = "app" })).Error);
        Assert.Equal("insecure_issuer", Assert.Throws<NineException>(() => new ManagementClient(new ManagementClientOptions { Issuer = "http://acme.9in.io", ClientId = "a", ClientSecret = "b" })).Error);
        Assert.Equal("insecure_issuer", Assert.Throws<NineException>(() => new HybridTokenVerifier(new HybridTokenVerifierOptions { Issuer = "http://acme.9in.io" })).Error);
    }
}

public class ReturnToTests
{
    [Theory]
    [InlineData("/dashboard", "/dashboard")]
    [InlineData("/a/b?c=1#d", "/a/b?c=1#d")]
    [InlineData("/", "/")]
    [InlineData("//evil.com", null)]
    [InlineData("/\\evil.com", null)]
    [InlineData("https://evil.com", null)]
    [InlineData("evil.com", null)]
    [InlineData("javascript:alert(1)", null)]
    [InlineData("/a\nb", null)]
    [InlineData("/a\\b", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void OnlySameSitePaths(string? value, string? expected) => Assert.Equal(expected, ReturnTo.Sanitize(value));
}

public class EnvironmentTests
{
    [Fact]
    public void ReadsNineVariables()
    {
        var name = "NINE_TEST_" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        Environment.SetEnvironmentVariable(name, " value ");
        try
        {
            Assert.Equal("value", NineEnvironment.Get(name));
            Assert.Equal("value", NineEnvironment.Get(name["NINE_".Length..]));
            Environment.SetEnvironmentVariable(name, "a, b,,c");
            Assert.Equal(["a", "b", "c"], NineEnvironment.GetList(name));
            foreach (var truthy in new[] { "1", "true", "TRUE", "yes", "on" })
            {
                Environment.SetEnvironmentVariable(name, truthy);
                Assert.True(NineEnvironment.GetBool(name));
            }
            Environment.SetEnvironmentVariable(name, "0");
            Assert.False(NineEnvironment.GetBool(name));
            Environment.SetEnvironmentVariable(name, "");
            Assert.Null(NineEnvironment.Get(name));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }
}

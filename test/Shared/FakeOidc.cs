using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Nine.Tests.Support;

/// <summary>
/// A small 9in authorization server on top of <see cref="FakeIssuer"/>: authorization codes bound to the
/// PKCE challenge, nonce and redirect URI; ID and access tokens signed with <see cref="Key"/>; refresh-token
/// rotation (a reused refresh token revokes the family); revocation; userinfo; client authentication.
/// <see cref="Authorize"/> plays the user signing in on the hosted page.
/// </summary>
public sealed class FakeOidc
{
    private readonly ConcurrentDictionary<string, CodeGrant> _codes = new();
    private readonly ConcurrentDictionary<string, RefreshGrant> _refresh = new();
    private int _counter;

    public sealed record CodeGrant(string ClientId, string RedirectUri, string Challenge, string? Nonce, string Scope, string Sub, string? Audience);

    private sealed record RefreshGrant(string ClientId, string Sub, string Scope, string Family, string? Audience)
    {
        public bool Used { get; set; }
    }

    public FakeOidc(string clientId = "app_web", string? clientSecret = "web_secret", string alg = "RS256", FakeIssuer? issuer = null)
    {
        Server = issuer ?? new FakeIssuer();
        ClientId = clientId;
        ClientSecret = clientSecret;
        Key = TestKey.Create(alg, "k-" + Guid.NewGuid().ToString("N")[..6]);
        Server.AddKey(Key);
        Server.On("POST", "/oauth/token", Token);
        Server.On("POST", "/oauth/revoke", Revoke);
        Server.On("GET", "/oauth/userinfo", UserInfo);
        Server.On("POST", "/oauth/introspect", Introspect);
    }

    public FakeIssuer Server { get; }
    public string Issuer => Server.Issuer;
    public string ClientId { get; }
    public string? ClientSecret { get; }
    public TestKey Key { get; }

    /// <summary>Lifetime of issued access tokens (expires_in).</summary>
    public int AccessTokenLifetime { get; set; } = 3600;
    /// <summary>Whether refresh responses carry a new refresh token (9in always rotates).</summary>
    public bool RotateRefreshTokens { get; set; } = true;
    /// <summary>Whether refresh responses carry a new ID token.</summary>
    public bool IdTokenOnRefresh { get; set; } = true;
    /// <summary>Override the subject of ID tokens issued on refresh (tests of the same-user check).</summary>
    public string? RefreshSubjectOverride { get; set; }
    /// <summary>Claims added to every ID token.</summary>
    public JsonObject Profile { get; } = new() { ["email"] = "jane@acme.test", ["name"] = "Jane Doe", ["email_verified"] = true };
    /// <summary>Changes to every ID token's claims (to test bad tokens).</summary>
    public Action<JsonObject>? EditIdToken { get; set; }
    public ConcurrentBag<string> Revoked { get; } = [];
    public int RefreshCount;

    /// <summary>Plays the user signing in: validates the authorization URL and returns the callback URL.</summary>
    public string Authorize(string authorizationUrl, string sub = "usr_jane")
    {
        var uri = new Uri(authorizationUrl);
        Assert.Equal(Issuer + "/oauth/authorize", uri.GetLeftPart(UriPartial.Path));
        var q = Query(uri.Query);
        Assert.Equal("code", q["response_type"]);
        Assert.Equal(ClientId, q["client_id"]);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.False(string.IsNullOrEmpty(q["state"]));
        var code = "code_" + Interlocked.Increment(ref _counter) + "_" + Guid.NewGuid().ToString("N")[..8];
        _codes[code] = new CodeGrant(ClientId, q["redirect_uri"], q["code_challenge"], q.GetValueOrDefault("nonce"), q["scope"], sub, q.GetValueOrDefault("audience"));
        return q["redirect_uri"] + "?code=" + code + "&state=" + Uri.EscapeDataString(q["state"]) + "&iss=" + Uri.EscapeDataString(Issuer);
    }

    public static Dictionary<string, string> Query(string query) =>
        query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => p.Length > 1 ? Uri.UnescapeDataString(p[1].Replace('+', ' ')) : "");

    private bool Authenticated(RecordedRequest request, out string clientId)
    {
        clientId = "";
        if (request.Authorization is { } auth && auth.StartsWith("Basic ", StringComparison.Ordinal))
        {
            var pair = Encoding.UTF8.GetString(Convert.FromBase64String(auth[6..])).Split(':', 2);
            clientId = Uri.UnescapeDataString(pair[0]);
            return clientId == ClientId && ClientSecret is not null && Uri.UnescapeDataString(pair[1]) == ClientSecret;
        }
        if (request.Form.TryGetValue("client_secret", out var secret))
        {
            clientId = request.Form.GetValueOrDefault("client_id", "");
            return clientId == ClientId && secret == ClientSecret;
        }
        clientId = request.Form.GetValueOrDefault("client_id", "");
        return clientId == ClientId && ClientSecret is null; // public client
    }

    private HttpResponseMessage Token(RecordedRequest request)
    {
        if (!Authenticated(request, out var clientId))
        {
            return FakeIssuer.Error("invalid_client", HttpStatusCode.Unauthorized);
        }
        var form = request.Form;
        switch (form.GetValueOrDefault("grant_type"))
        {
            case "authorization_code":
            {
                if (!_codes.TryRemove(form.GetValueOrDefault("code", ""), out var grant) || grant.ClientId != clientId)
                {
                    return FakeIssuer.Error("invalid_grant", description: "unknown or used code");
                }
                if (form.GetValueOrDefault("redirect_uri") != grant.RedirectUri)
                {
                    return FakeIssuer.Error("invalid_grant", description: "redirect_uri mismatch");
                }
                var challenge = TestJwt.B64(SHA256.HashData(Encoding.ASCII.GetBytes(form.GetValueOrDefault("code_verifier", ""))));
                if (challenge != grant.Challenge)
                {
                    return FakeIssuer.Error("invalid_grant", description: "PKCE verification failed");
                }
                return Tokens(grant.Sub, grant.Scope, grant.Nonce, grant.Audience, Guid.NewGuid().ToString("N"), withRefresh: grant.Scope.Contains("offline_access"), withIdToken: grant.Scope.Contains("openid"));
            }
            case "refresh_token":
            {
                Interlocked.Increment(ref RefreshCount);
                var token = form.GetValueOrDefault("refresh_token", "");
                if (!_refresh.TryGetValue(token, out var grant) || grant.ClientId != clientId)
                {
                    return FakeIssuer.Error("invalid_grant", description: "unknown refresh token");
                }
                if (grant.Used && RotateRefreshTokens)
                {
                    // Reuse: revoke the family.
                    foreach (var (key, value) in _refresh)
                    {
                        if (value.Family == grant.Family)
                        {
                            _refresh.TryRemove(key, out _);
                        }
                    }
                    return FakeIssuer.Error("invalid_grant", description: "refresh token reuse");
                }
                grant.Used = true;
                return Tokens(RefreshSubjectOverride ?? grant.Sub, grant.Scope, null, grant.Audience, grant.Family, withRefresh: RotateRefreshTokens, withIdToken: IdTokenOnRefresh, refreshFrom: RotateRefreshTokens ? null : token);
            }
            case "client_credentials":
                return FakeIssuer.Json(new JsonObject
                {
                    ["access_token"] = AccessToken(clientId, form.GetValueOrDefault("scope", ""), form.GetValueOrDefault("audience")),
                    ["token_type"] = "Bearer",
                    ["expires_in"] = AccessTokenLifetime,
                    ["scope"] = form.GetValueOrDefault("scope", ""),
                });
            default:
                return FakeIssuer.Error("unsupported_grant_type");
        }
    }

    private HttpResponseMessage Tokens(string sub, string scope, string? nonce, string? audience, string family, bool withRefresh, bool withIdToken, string? refreshFrom = null)
    {
        var body = new JsonObject
        {
            ["access_token"] = AccessToken(sub, scope, audience),
            ["token_type"] = "Bearer",
            ["expires_in"] = AccessTokenLifetime,
            ["scope"] = scope,
        };
        if (withIdToken)
        {
            body["id_token"] = IdToken(sub, nonce, (string)body["access_token"]!);
        }
        if (withRefresh)
        {
            var refresh = "rt_" + Guid.NewGuid().ToString("N");
            _refresh[refresh] = new RefreshGrant(ClientId, sub, scope, family, audience);
            body["refresh_token"] = refresh;
        }
        _ = refreshFrom;
        return FakeIssuer.Json(body);
    }

    public string IdToken(string sub, string? nonce, string? accessToken = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new JsonObject
        {
            ["iss"] = Issuer, ["sub"] = sub, ["aud"] = ClientId, ["azp"] = ClientId, ["iat"] = now, ["exp"] = now + 3600,
            ["auth_time"] = now, ["sid"] = "sid_" + sub, ["amr"] = new JsonArray("pwd"),
        };
        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }
        if (accessToken is not null)
        {
            // OIDC at_hash: the left half of the access token's hash (SHA-512 for EdDSA, as 9in does).
            var input = Encoding.ASCII.GetBytes(accessToken);
            byte[] hash = Key.Alg switch
            {
                "RS384" or "PS384" or "ES384" or "HS384" => SHA384.HashData(input),
                "RS512" or "PS512" or "HS512" or "EdDSA" => SHA512.HashData(input),
                _ => SHA256.HashData(input),
            };
            claims["at_hash"] = TestJwt.B64(hash[..(hash.Length / 2)]);
        }
        foreach (var (k, v) in Profile)
        {
            claims[k] = v?.DeepClone();
        }
        EditIdToken?.Invoke(claims);
        return TestJwt.Sign(Key, claims, typ: "JWT");
    }

    public string AccessToken(string sub, string scope, string? audience)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return TestJwt.Sign(Key, new JsonObject
        {
            ["iss"] = Issuer, ["sub"] = sub, ["aud"] = audience ?? ClientId, ["client_id"] = ClientId, ["scope"] = scope,
            ["jti"] = Guid.NewGuid().ToString("N"), ["sid"] = "sid_" + sub, ["iat"] = now, ["exp"] = now + AccessTokenLifetime,
        });
    }

    private HttpResponseMessage Revoke(RecordedRequest request)
    {
        if (!Authenticated(request, out _))
        {
            return FakeIssuer.Error("invalid_client", HttpStatusCode.Unauthorized);
        }
        var token = request.Form.GetValueOrDefault("token", "");
        Revoked.Add(token);
        _refresh.TryRemove(token, out _);
        return new HttpResponseMessage(HttpStatusCode.OK);
    }

    private HttpResponseMessage UserInfo(RecordedRequest request)
    {
        var auth = request.Authorization;
        if (auth is null || !auth.StartsWith("Bearer ", StringComparison.Ordinal) || Revoked.Contains(auth[7..]))
        {
            return FakeIssuer.Error("invalid_token", HttpStatusCode.Unauthorized);
        }
        var body = new JsonObject { ["sub"] = "usr_jane" };
        foreach (var (k, v) in Profile)
        {
            body[k] = v?.DeepClone();
        }
        return FakeIssuer.Json(body);
    }

    private HttpResponseMessage Introspect(RecordedRequest request)
    {
        if (!Authenticated(request, out _) || ClientSecret is null)
        {
            return FakeIssuer.Error("invalid_client", HttpStatusCode.Unauthorized);
        }
        var token = request.Form.GetValueOrDefault("token", "");
        return FakeIssuer.Json(new JsonObject { ["active"] = !Revoked.Contains(token), ["token_type"] = "access_token" });
    }
}

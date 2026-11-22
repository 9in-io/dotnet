using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nine.Tests.Support;

namespace Nine.AspNetCore.Tests;

public class WebAppTests
{
    private static async Task<JsonElement> Json(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"{(int)response.StatusCode}: {body}");
        return JsonDocument.Parse(body).RootElement;
    }

    private static Dictionary<string, string> Query(Uri uri) => FakeOidc.Query(uri.Query);

    [Fact]
    public async Task LoginRedirectsToNineWithPkceStateNonceAndTheAppSettings()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var response = await app.Browser().GetAsync("/nine/login?return_to=/me&login_hint=jane@acme.test&locale=de&prompt=login");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(app.Oidc.Issuer + "/oauth/authorize", location.GetLeftPart(UriPartial.Path));
        var q = Query(location);
        Assert.Equal("code", q["response_type"]);
        Assert.Equal("query", q.GetValueOrDefault("response_mode", "query")); // query: the default for code
        Assert.Equal(app.Oidc.ClientId, q["client_id"]);
        Assert.Equal("https://localhost/nine/callback", q["redirect_uri"]);
        Assert.Equal("openid profile email offline_access", q["scope"]);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal(43, q["code_challenge"].Length);
        Assert.False(string.IsNullOrEmpty(q["state"]));
        Assert.False(string.IsNullOrEmpty(q["nonce"]));
        Assert.Equal(NineAppFactory.ApiAudience, q["audience"]);
        Assert.Equal("jane@acme.test", q["login_hint"]);
        Assert.Equal("de", q["ui_locales"]);
        Assert.Equal("login", q["prompt"]);
        Assert.False(q.ContainsKey("client_secret"));
        Assert.False(q.ContainsKey("x-client-SKU")); // no telemetry parameters
        // Correlation and nonce cookies: HttpOnly, SameSite=Lax.
        var cookies = response.Headers.GetValues("Set-Cookie").ToArray();
        Assert.Contains(cookies, c => c.StartsWith(".Nine.Correlation.", StringComparison.Ordinal) && c.Contains("samesite=lax", StringComparison.OrdinalIgnoreCase) && c.Contains("httponly", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(cookies, c => c.StartsWith(".Nine.Nonce.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SignUpOpensTheRegistrationForm()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var response = await app.Browser().GetAsync("/nine/signup");
        Assert.Equal("create", Query(response.Headers.Location!)["prompt"]);
        var bogus = await app.Browser().GetAsync("/nine/login?prompt=evil");
        Assert.False(Query(bogus.Headers.Location!).ContainsKey("prompt"));
    }

    [Fact]
    public async Task SignsInAndKeepsTheSession()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        var callback = await app.SignInAsync(browser);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/me", callback.Headers.Location!.OriginalString);
        var session = callback.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("nine_session", StringComparison.Ordinal));
        Assert.Contains("httponly", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", session, StringComparison.OrdinalIgnoreCase);

        var me = await Json(await browser.GetAsync("/me"));
        Assert.Equal("usr_jane", me.GetProperty("sub").GetString());
        Assert.Equal("jane@acme.test", me.GetProperty("email").GetString());
        Assert.Equal("Jane Doe", me.GetProperty("name").GetString());
        var claims = me.GetProperty("claims").EnumerateArray().Select(c => c.GetString()).ToArray();
        Assert.Contains("sid", claims);
        Assert.Contains("amr", claims);
        Assert.DoesNotContain("nonce", claims);
        Assert.DoesNotContain("at_hash", claims);
        Assert.Equal("Hello Jane Doe", await browser.GetStringAsync("/"));

        // The code was exchanged with client_secret_basic and the PKCE verifier.
        var exchange = app.Oidc.Server.Last("/oauth/token");
        Assert.StartsWith("Basic ", exchange.Authorization);
        Assert.False(exchange.Form.ContainsKey("client_secret"));
        Assert.True(exchange.Form.ContainsKey("code_verifier"));
        // The access token for the API was saved.
        var tokenResponse = await browser.GetAsync("/token");
        var token = await tokenResponse.Content.ReadAsStringAsync();
        Assert.True(token.StartsWith("ey", StringComparison.Ordinal), $"{(int)tokenResponse.StatusCode} {tokenResponse.Headers.Location} [{token}] {string.Join(" | ", tokenResponse.Headers.TryGetValues("Set-Cookie", out var sc) ? sc : [])}");
    }

    [Fact]
    public async Task OnlySameSiteReturnTo()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        foreach (var bad in new[] { "https://evil.test/", "//evil.test", "/\\evil.test" })
        {
            var callback = await app.SignInAsync(app.Browser(), "/nine/login?return_to=" + Uri.EscapeDataString(bad));
            Assert.Equal("/", callback.Headers.Location!.OriginalString);
        }
    }

    [Fact]
    public async Task ProtectedPagesSendBrowsersToSignInAndApiCallsGet401()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        var page = new HttpRequestMessage(HttpMethod.Get, "/me");
        page.Headers.Accept.ParseAdd("text/html");
        var redirect = await browser.SendAsync(page);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        Assert.StartsWith(app.Oidc.Issuer + "/oauth/authorize", redirect.Headers.Location!.ToString());
        // And it comes back to the page.
        var callback = await browser.GetAsync(new Uri(app.Oidc.Authorize(redirect.Headers.Location!.ToString())).PathAndQuery);
        Assert.Equal("/me", callback.Headers.Location!.OriginalString);

        var api = new HttpRequestMessage(HttpMethod.Get, "/me");
        api.Headers.Accept.ParseAdd("application/json");
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.Browser().SendAsync(api)).StatusCode);
    }

    [Fact]
    public async Task RefreshesBeforeExpiryAndSavesTheRotatedToken()
    {
        var oidc = new FakeOidc { AccessTokenLifetime = 30 }; // inside the 60 s refresh window
        await using var app = new NineAppFactory(oidc);
        var browser = app.Browser();
        await app.SignInAsync(browser);
        var first = app.Oidc.Server.Requests.Count(r => r.Path == "/oauth/token");
        oidc.AccessTokenLifetime = 3600;
        var refreshed = await browser.GetAsync("/token");
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.Equal(1, oidc.RefreshCount);
        Assert.Contains(refreshed.Headers.GetValues("Set-Cookie"), c => c.StartsWith("nine_session", StringComparison.Ordinal));
        var token = await refreshed.Content.ReadAsStringAsync();
        // Fresh now: no more refreshes, the same token, and the rotated refresh token was kept (the old one is spent).
        Assert.Equal(token, await browser.GetStringAsync("/token"));
        Assert.Equal(1, oidc.RefreshCount);
        Assert.Equal("usr_jane", (await Json(await browser.GetAsync("/me"))).GetProperty("sub").GetString());
        Assert.Equal(first + 1, app.Oidc.Server.Requests.Count(r => r.Path == "/oauth/token"));
    }

    [Fact]
    public async Task ConcurrentRequestsShareOneRefresh()
    {
        var oidc = new FakeOidc { AccessTokenLifetime = 30 };
        await using var app = new NineAppFactory(oidc);
        var browser = app.Browser();
        await app.SignInAsync(browser);
        oidc.AccessTokenLifetime = 3600;
        var tokens = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => browser.GetStringAsync("/token")));
        Assert.Equal(1, oidc.RefreshCount);
        Assert.Single(tokens.Distinct());
    }

    [Fact]
    public async Task ARevokedRefreshTokenSignsTheUserOut()
    {
        var oidc = new FakeOidc { AccessTokenLifetime = 30 };
        await using var app = new NineAppFactory(oidc);
        var browser = app.Browser();
        await app.SignInAsync(browser);
        // 9in ended the session (sign-out everywhere): the refresh token is refused.
        oidc.Server.On("POST", "/oauth/token", _ => FakeIssuer.Error("invalid_grant", HttpStatusCode.BadRequest, "refresh token revoked"));
        var api = new HttpRequestMessage(HttpMethod.Get, "/me");
        api.Headers.Accept.ParseAdd("application/json");
        var response = await browser.SendAsync(api);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("nine_session=;", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ARefreshFailureThatIsNotARevocationKeepsTheSession()
    {
        var oidc = new FakeOidc { AccessTokenLifetime = 30 };
        await using var app = new NineAppFactory(oidc);
        var browser = app.Browser();
        await app.SignInAsync(browser);
        oidc.Server.On("POST", "/oauth/token", _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        Assert.Equal("usr_jane", (await Json(await browser.GetAsync("/me"))).GetProperty("sub").GetString());
    }

    [Fact]
    public async Task LogoutRevokesAndEndsTheSessionAtNine()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        await app.SignInAsync(browser);
        var response = await browser.GetAsync("/nine/logout?return_to=/bye");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(app.Oidc.Issuer + "/oauth/logout", location.GetLeftPart(UriPartial.Path));
        var q = Query(location);
        Assert.Equal(app.Oidc.ClientId, q["client_id"]);
        Assert.Equal("https://localhost/bye", q["post_logout_redirect_uri"]);
        Assert.StartsWith("ey", q["id_token_hint"]);
        Assert.False(q.ContainsKey("state"));
        Assert.Single(app.Oidc.Revoked);
        Assert.StartsWith("rt_", app.Oidc.Revoked.Single());
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("nine_session=;", StringComparison.Ordinal));
        var api = new HttpRequestMessage(HttpMethod.Get, "/me");
        api.Headers.Accept.ParseAdd("application/json");
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.SendAsync(api)).StatusCode);
    }

    [Fact]
    public async Task ACrossSiteLogoutIsRefused()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        await app.SignInAsync(browser);
        var forged = new HttpRequestMessage(HttpMethod.Get, "/nine/logout");
        forged.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(forged)).StatusCode);
        Assert.Empty(app.Oidc.Revoked);
        Assert.Equal("usr_jane", (await Json(await browser.GetAsync("/me"))).GetProperty("sub").GetString());
        var own = new HttpRequestMessage(HttpMethod.Get, "/nine/logout");
        own.Headers.Add("Sec-Fetch-Site", "same-origin");
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SendAsync(own)).StatusCode);
    }

    [Fact]
    public async Task LocalLogoutStaysInTheApp()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        await app.SignInAsync(browser);
        var response = await browser.PostAsync("/nine/logout?local=1&return_to=https://evil.test/", null);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location!.OriginalString);
        Assert.Single(app.Oidc.Revoked);
    }

    [Fact]
    public async Task RefusesAnotherIssuerInTheCallback()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        var start = await browser.GetAsync("/nine/login");
        var callback = app.Oidc.Authorize(start.Headers.Location!.ToString()).Replace("iss=" + Uri.EscapeDataString(app.Oidc.Issuer), "iss=" + Uri.EscapeDataString("https://evil.test"));
        var response = await browser.GetAsync(new Uri(callback).PathAndQuery);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_issuer", await response.Content.ReadAsStringAsync());
        Assert.Equal(0, app.Oidc.Server.Count("POST", "/oauth/token"));
    }

    [Fact]
    public async Task RefusesACallbackWithoutIss()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        var start = await browser.GetAsync("/nine/login");
        var callback = app.Oidc.Authorize(start.Headers.Location!.ToString());
        callback = callback[..callback.IndexOf("&iss=", StringComparison.Ordinal)];
        var response = await browser.GetAsync(new Uri(callback).PathAndQuery);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_issuer", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RefusesTokensInjectedIntoTheCallback()
    {
        var oidc = new FakeOidc();
        await using var app = new NineAppFactory(oidc);
        var browser = app.Browser();
        var start = await browser.GetAsync("/nine/login");
        var callback = oidc.Authorize(start.Headers.Location!.ToString());
        var forged = TestJwt.Sign(TestKey.Create("RS256", "forged"), new JsonObject { ["iss"] = oidc.Issuer, ["sub"] = "usr_jane", ["aud"] = oidc.ClientId, ["email"] = "admin@acme.test", ["exp"] = TestJwt.Now() + 60 }, typ: "JWT");
        var response = await browser.GetAsync(new Uri(callback).PathAndQuery + "&id_token=" + forged);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, oidc.Server.Count("POST", "/oauth/token"));
    }

    [Fact]
    public async Task ACallbackCanBeUsedOnlyOnce()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        var start = await browser.GetAsync("/nine/login");
        var callback = new Uri(app.Oidc.Authorize(start.Headers.Location!.ToString())).PathAndQuery;
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(callback)).StatusCode);
        var replay = await browser.GetAsync(callback);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Contains("invalid_state", await replay.Content.ReadAsStringAsync());
        // A callback from another browser (no correlation cookie) is refused too.
        var other = await app.Browser().GetAsync(callback);
        Assert.Equal(HttpStatusCode.BadRequest, other.StatusCode);
    }

    [Fact]
    public async Task AccessDeniedGoesToTheErrorPage()
    {
        await using var plain = new NineAppFactory(new FakeOidc());
        var browser = plain.Browser();
        var state = Query((await browser.GetAsync("/nine/login")).Headers.Location!)["state"];
        var denied = await browser.GetAsync("/nine/callback?error=access_denied&error_description=no&state=" + Uri.EscapeDataString(state) + "&iss=" + Uri.EscapeDataString(plain.Oidc.Issuer));
        Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        Assert.Contains("access_denied", await denied.Content.ReadAsStringAsync());

        await using var withPage = new NineAppFactory(new FakeOidc(), new() { ["Test:ErrorPath"] = "/sign-in-failed" });
        var browser2 = withPage.Browser();
        var state2 = Query((await browser2.GetAsync("/nine/login")).Headers.Location!)["state"];
        var redirected = await browser2.GetAsync("/nine/callback?error=access_denied&state=" + Uri.EscapeDataString(state2) + "&iss=" + Uri.EscapeDataString(withPage.Oidc.Issuer));
        Assert.Equal(HttpStatusCode.Redirect, redirected.StatusCode);
        Assert.Equal("/sign-in-failed?error=access_denied", redirected.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("aud")]
    [InlineData("signature")]
    [InlineData("expired")]
    [InlineData("at_hash")]
    public async Task RefusesBadIdTokens(string problem)
    {
        var oidc = new FakeOidc();
        var other = TestKey.Create("RS256", "other");
        oidc.EditIdToken = claims =>
        {
            switch (problem)
            {
                case "nonce": claims["nonce"] = "other"; break;
                case "aud": claims["aud"] = "app_other"; break;
                case "expired": claims["exp"] = TestJwt.Now() - 600; break;
                case "at_hash": claims["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA"; break;
            }
        };
        if (problem == "signature")
        {
            oidc.Server.Keys.Clear();
            other.Jwk!["kid"] = oidc.Key.Kid;
            oidc.Server.AddKey(other);
        }
        await using var app = new NineAppFactory(oidc);
        var response = await app.SignInAsync(app.Browser());
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(response.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [], c => c.StartsWith("nine_session", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("EdDSA")]
    [InlineData("ES384")]
    [InlineData("PS512")]
    public async Task SignsInWithEveryAlgorithmIncludingEdDsa(string alg)
    {
        // ID tokens carry at_hash (SHA-512 for EdDSA), which 9in's protocol validator checks.
        await using var app = new NineAppFactory(new FakeOidc(alg: alg));
        var browser = app.Browser();
        var callback = await app.SignInAsync(browser);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("usr_jane", (await Json(await browser.GetAsync("/me"))).GetProperty("sub").GetString());
    }

    [Fact]
    public async Task PublicClientsWork()
    {
        await using var app = new NineAppFactory(new FakeOidc(clientId: "app_public", clientSecret: null), new() { ["Nine:ClientSecret"] = null });
        var browser = app.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await app.SignInAsync(browser)).StatusCode);
        var exchange = app.Oidc.Server.Last("/oauth/token");
        Assert.Null(exchange.Authorization);
        Assert.Equal("app_public", exchange.Form["client_id"]);
    }

    [Fact]
    public async Task TheCallbackPathFollowsTheConfiguredRedirectUri()
    {
        await using var app = new NineAppFactory(new FakeOidc(), new() { ["Nine:RedirectUri"] = "https://localhost/callback" });
        var browser = app.Browser();
        var start = await browser.GetAsync("/nine/login?return_to=/me");
        var callback = new Uri(app.Oidc.Authorize(start.Headers.Location!.ToString()));
        Assert.Equal("/callback", callback.AbsolutePath);
        var response = await browser.GetAsync(callback.PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/me", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task AConfiguredRedirectUriIsUsedForTheCallbackAndLogout()
    {
        await using var app = new NineAppFactory(new FakeOidc(), new() { ["Nine:RedirectUri"] = "https://app.acme.test/nine/callback" });
        var browser = app.Browser();
        var start = await browser.GetAsync("/nine/login");
        Assert.Equal("https://app.acme.test/nine/callback", Query(start.Headers.Location!)["redirect_uri"]);
        var callback = await browser.GetAsync(new Uri(app.Oidc.Authorize(start.Headers.Location!.ToString())).PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("https://app.acme.test/nine/callback", app.Oidc.Server.Last("/oauth/token").Form["redirect_uri"]);
        var logout = await browser.GetAsync("/nine/logout");
        Assert.Equal("https://app.acme.test/", Query(logout.Headers.Location!)["post_logout_redirect_uri"]);
    }
}

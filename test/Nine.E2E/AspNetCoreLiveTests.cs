using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Nine.E2E;

/// <summary>
/// The 9in.AspNetCore package against live 9in: ASP.NET Core's OpenID Connect handler, preconfigured by
/// AddNineWebApp, signs the managed user in through the real hosted pages with the confidential client;
/// refresh with rotation, logout, the bearer API in hybrid mode, and real webhook and adapter requests
/// replayed through MapNineWebhooks and MapNineAdapter.
/// </summary>
public sealed class AspNetCoreLiveTests(LiveFixture live) : IClassFixture<LiveFixture>
{
    private sealed class LiveApp(Dictionary<string, string?> settings) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            foreach (var (key, value) in settings)
            {
                builder.UseSetting(key, value);
            }
        }

        public HttpClient Browser() => CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true,
            BaseAddress = new Uri(Live.Env("SERVER_REDIRECT_URI")).GetLeftPart(UriPartial.Authority) is var origin ? new Uri(origin) : null,
        });
    }

    private static Dictionary<string, string?> Production(Dictionary<string, string?>? more = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Nine:Issuer"] = Live.Env("ISSUER"),
            ["Nine:ClientId"] = Live.Env("SERVER_CLIENT_ID"),
            ["Nine:ClientSecret"] = Live.Env("SERVER_CLIENT_SECRET"),
            ["Nine:RedirectUri"] = Live.Env("SERVER_REDIRECT_URI"),
            ["Nine:Audience"] = Live.Env("API_AUDIENCE"),
            ["Nine:WebhookSecret"] = Live.Env("WEBHOOK_SECRET"),
            ["Nine:AdapterSecret"] = Live.Env("ADAPTER_SECRET"),
        };
        foreach (var (key, value) in more ?? [])
        {
            settings[key] = value;
        }
        return settings;
    }

    [Fact]
    public async Task SignsInRefreshesAndSignsOutWithTheOpenIdConnectHandler()
    {
        Live.RequireServerSecret();
        var managed = await live.ManagedUser();
        // A refresh window longer than the token's life: every request refreshes, with rotation.
        await using var app = new LiveApp(Production(new() { ["Test:RefreshLeewaySeconds"] = "7200" }));
        var client = app.Browser();
        var start = await client.GetAsync("/nine/login?return_to=/me");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var authorize = start.Headers.Location!.ToString();
        Assert.StartsWith(Live.Env("ISSUER") + "/oauth/authorize?", authorize);
        Assert.Contains("code_challenge_method=S256", authorize);

        using var hosted = new Browser();
        var result = await hosted.SignIn(authorize, Live.Env("SERVER_REDIRECT_URI"), live.ManagedEmail, live.ManagedPassword);
        Assert.True(result.Callback is not null, result.PageText);
        var callback = await client.GetAsync(new Uri(result.Callback!).PathAndQuery);
        Assert.True(callback.StatusCode == HttpStatusCode.Redirect, await callback.Content.ReadAsStringAsync());
        Assert.Equal("/me", callback.Headers.Location!.OriginalString);

        var me = JsonDocument.Parse(await client.GetStringAsync("/me")).RootElement;
        Assert.Equal(managed.Id, me.GetProperty("sub").GetString());
        Assert.Equal(live.ManagedEmail, me.GetProperty("email").GetString());

        // The saved access token is for the API, and refreshing rotates it.
        var first = await client.GetStringAsync("/token");
        var second = await client.GetStringAsync("/token");
        Assert.NotEqual(first, second);
        var verifier = new TokenVerifier(new TokenVerifierOptions { Issuer = Live.Env("ISSUER"), Audience = Live.Env("API_AUDIENCE") });
        Assert.Equal(managed.Id, (await verifier.VerifyAsync(second)).Subject);

        var logout = await client.GetAsync("/nine/logout");
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        var end = logout.Headers.Location!.ToString();
        Assert.StartsWith(Live.Env("ISSUER") + "/oauth/logout?", end);
        Assert.Contains("id_token_hint=", end);
        Assert.Contains("client_id=" + Uri.EscapeDataString(Live.Env("SERVER_CLIENT_ID")), end);
        var api = new HttpRequestMessage(HttpMethod.Get, "/me");
        api.Headers.Accept.ParseAdd("application/json");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(api)).StatusCode);
    }

    [Fact]
    public async Task TheBearerApiVerifiesRealTokensInHybridMode()
    {
        Live.RequireServerSecret();
        await using var app = new LiveApp(Production());
        var http = app.CreateClient();
        var auth = LiveFixture.Server();
        var token = (await auth.ClientCredentialsAsync(Live.Env("API_AUDIENCE"), "read:things")).AccessToken;
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/any");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Live.Env("SERVER_CLIENT_ID"), await response.Content.ReadAsStringAsync());

        await auth.RevokeAsync(token, "access_token");
        // In hybrid mode the cached answer stands until the webhook evicts it; a fresh app asks 9in.
        await using var fresh = new LiveApp(Production());
        var again = new HttpRequestMessage(HttpMethod.Get, "/api/any");
        again.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var refused = await fresh.CreateClient().SendAsync(again);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Contains("invalid_token", refused.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task ReplaysARealWebhookThroughMapNineWebhooks()
    {
        Live.RequireEnabled();
        var (_, tokens) = await live.SandboxSession();
        var login = await Live.WaitFor("webhooks", r => r.Text("type") == "user.login" && r.Text("userId") == tokens.Claims.Subject);
        var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - Signature.Parse(login.Text("signature")!)!.Value.Timestamp;
        Assert.SkipWhen(age > 280, "the delivery is older than the 5-minute window");
        await using var app = new LiveApp(new()
        {
            ["Nine:Issuer"] = Live.Env("SANDBOX_ISSUER"),
            ["Nine:ClientId"] = Live.Env("SPA_CLIENT_ID"),
            ["Nine:WebhookSecret"] = Live.Env("WEBHOOK_SECRET"),
            ["Test:WebhookPath"] = login.Text("path"),
        });
        HttpRequestMessage Delivery(string body)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/nine/webhook") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            request.Headers.Add("9in-signature", login.Text("signature"));
            return request;
        }
        var http = app.CreateClient();
        Assert.Equal(HttpStatusCode.NoContent, (await http.SendAsync(Delivery(login.Text("raw")!))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await http.SendAsync(Delivery(login.Text("raw")!))).StatusCode); // duplicate: processed once
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(Delivery(login.Text("raw")!.Replace("user.login", "user.deleted")))).StatusCode);
    }

    [Fact]
    public async Task ReplaysARealAdapterRequestThroughMapNineAdapter()
    {
        Live.RequireEnabled();
        var (ok, _) = await LiveTests.AdapterRequests();
        var path = ok.Text("path")!;
        await using var app = new LiveApp(new()
        {
            ["Nine:Issuer"] = Live.Env("ADAPTER_ISSUER"),
            ["Nine:ClientId"] = Live.Env("ADAPTER_SPA_CLIENT_ID"),
            ["Nine:AdapterSecret"] = Live.Env("ADAPTER_SECRET"),
            ["Test:AdapterPathPrefix"] = path[..path.LastIndexOf('/')],
        });
        var request = new HttpRequestMessage(HttpMethod.Post, "/nine/authenticate") { Content = new StringContent(ok.Text("body")!, Encoding.UTF8, "application/json") };
        request.Headers.Add("9in-signature", ok.Text("signature"));
        request.Headers.Add("9in-request-id", ok.Text("requestId"));
        var response = await app.CreateClient().SendAsync(request);
        // The signature was accepted; the test app's adapter doesn't know Alice, so 9in would be told "invalid".
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("""{"error":"invalid_credentials"}""", Encoding.UTF8.GetString(body));
        Assert.True(Signature.Verify([Live.Env("ADAPTER_SECRET")], response.Headers.GetValues("9in-signature").Single(), "POST", path + "#" + ok.Text("requestId"), body));
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nine.Tests.Support;

namespace Nine.AspNetCore.Tests;

public class ApiTests
{
    private static HttpRequestMessage Get(string path, string? token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        return request;
    }

    private static string Token(FakeOidc oidc, string scope = "orders:read", string audience = NineAppFactory.ApiAudience) =>
        oidc.AccessToken("usr_api", scope, audience);

    [Fact]
    public async Task AcceptsAValidTokenWithTheScope()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var response = await app.CreateClient().SendAsync(Get("/api/orders", Token(app.Oidc, "openid orders:read")));
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("usr_api", body.GetProperty("sub").GetString());
        Assert.Equal(new[] { "openid", "orders:read" }, body.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()!).ToArray());
        Assert.False(string.IsNullOrEmpty(body.GetProperty("jti").GetString()));
    }

    [Fact]
    public async Task MissingAndInvalidTokensGet401WithAChallenge()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        var missing = await client.SendAsync(Get("/api/orders", null));
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal("Bearer", missing.Headers.WwwAuthenticate.ToString());

        foreach (var bad in new[] { "garbage", Token(app.Oidc)[..^4] + "AAAA", Token(app.Oidc, audience: "https://other.test") })
        {
            var response = await client.SendAsync(Get("/api/orders", bad));
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.StartsWith("Bearer error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString());
        }
        // An ID token is not an access token.
        var idToken = app.Oidc.IdToken("usr_api", null);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/api/orders", idToken))).StatusCode);
    }

    [Fact]
    public async Task AMissingScopeIs403WithTheRequiredScope()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var response = await app.CreateClient().SendAsync(Get("/api/orders", Token(app.Oidc, "orders:write")));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("Bearer error=\"insufficient_scope\", scope=\"orders:read\"", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task MvcControllersWithRequireScopeAndAuthorize()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get("/api/admin/orders", Token(app.Oidc, "orders:read orders:write")))).StatusCode);
        var partial = await client.SendAsync(Get("/api/admin/orders", Token(app.Oidc, "orders:read")));
        Assert.Equal(HttpStatusCode.Forbidden, partial.StatusCode);
        Assert.Contains("orders:read orders:write", partial.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/api/admin/orders", null))).StatusCode);
        Assert.Equal("usr_api", await (await client.SendAsync(Get("/api/admin/whoami", Token(app.Oidc, "")))).Content.ReadAsStringAsync());
        Assert.Equal("usr_api", await (await client.SendAsync(Get("/api/any", Token(app.Oidc, "")))).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ASignedInBrowserIsNotAnApiCaller()
    {
        // The session cookie doesn't satisfy endpoints that require a 9in access token.
        await using var app = new NineAppFactory(new FakeOidc());
        var browser = app.Browser();
        await app.SignInAsync(browser);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/orders")).StatusCode);
    }

    [Fact]
    public async Task HybridModeCatchesARevocationWhenTheWebhookArrives()
    {
        var oidc = new FakeOidc();
        await using var app = new NineAppFactory(oidc);
        var client = app.CreateClient();
        var token = Token(oidc);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get("/api/orders", token))).StatusCode);
        Assert.Equal(1, oidc.Server.Count("POST", "/oauth/introspect"));
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get("/api/orders", token))).StatusCode);
        Assert.Equal(1, oidc.Server.Count("POST", "/oauth/introspect")); // cached

        oidc.Revoked.Add(token);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get("/api/orders", token))).StatusCode); // still cached
        var jti = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(Pad(token.Split('.')[1])))).RootElement.GetProperty("jti").GetString();
        var webhook = await WebhookTests.Deliver(client, "token.revoked", new JsonObject { ["token_type"] = "access_token", ["jti"] = jti, ["client_id"] = oidc.ClientId });
        Assert.Equal(HttpStatusCode.NoContent, webhook.StatusCode);
        var refused = await client.SendAsync(Get("/api/orders", token));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Contains("revoked", refused.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task OpaqueTokensAreIntrospected()
    {
        var oidc = new FakeOidc();
        oidc.Server.On("POST", "/oauth/introspect", request => FakeIssuer.Json(request.Form["token"] == "9in_at_good"
            ? new JsonObject { ["active"] = true, ["token_type"] = "access_token", ["iss"] = oidc.Issuer, ["sub"] = "usr_opaque", ["aud"] = NineAppFactory.ApiAudience, ["scope"] = "orders:read", ["exp"] = TestJwt.Now() + 600 }
            : new JsonObject { ["active"] = false }));
        await using var app = new NineAppFactory(oidc);
        var client = app.CreateClient();
        var ok = await client.SendAsync(Get("/api/orders", "9in_at_good"));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains("usr_opaque", await ok.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get("/api/orders", "9in_at_bad"))).StatusCode);
    }

    [Fact]
    public async Task AnUnreachableIssuerIs503NotA401()
    {
        var oidc = new FakeOidc();
        oidc.Server.On("POST", "/oauth/introspect", _ => new HttpResponseMessage(HttpStatusCode.BadGateway));
        await using var app = new NineAppFactory(oidc);
        var response = await app.CreateClient().SendAsync(Get("/api/orders", Token(oidc)));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.NotNull(response.Headers.RetryAfter);
    }

    [Fact]
    public async Task LocalModeNeverIntrospects()
    {
        var oidc = new FakeOidc();
        await using var app = new NineAppFactory(oidc, new() { ["Nine:TokenMode"] = "local" });
        Assert.Equal(HttpStatusCode.OK, (await app.CreateClient().SendAsync(Get("/api/orders", Token(oidc)))).StatusCode);
        Assert.Equal(0, oidc.Server.Count("POST", "/oauth/introspect"));
    }

    [Fact]
    public async Task HmacTokensWithTheApiSecret()
    {
        var oidc = new FakeOidc();
        var hs = TestKey.Create("HS256");
        await using var app = new NineAppFactory(oidc, new() { ["Nine:ApiSecret"] = hs.Secret, ["Nine:TokenMode"] = "local" });
        var token = TestJwt.Sign(hs, new JsonObject { ["iss"] = oidc.Issuer, ["sub"] = "usr_hs", ["aud"] = NineAppFactory.ApiAudience, ["scope"] = "orders:read", ["exp"] = TestJwt.Now() + 60 });
        Assert.Equal(HttpStatusCode.OK, (await app.CreateClient().SendAsync(Get("/api/orders", token))).StatusCode);
    }

    private static string Pad(string b64url)
    {
        var s = b64url.Replace('-', '+').Replace('_', '/');
        return s + new string('=', (4 - s.Length % 4) % 4);
    }
}

public class WebhookTests
{
    internal static Task<HttpResponseMessage> Deliver(HttpClient client, string type, JsonObject data, string? id = null, string secret = NineAppFactory.WebhookSecret, string path = "/nine/webhook")
    {
        var body = new JsonObject
        {
            ["id"] = id ?? "evt_" + Guid.NewGuid().ToString("N"),
            ["event_type"] = type,
            ["created_at"] = "2026-11-22T10:00:00.000Z",
            ["tenant"] = "tnt_1",
            ["environment"] = "sandbox",
            ["data"] = data,
        }.ToJsonString();
        var request = new HttpRequestMessage(HttpMethod.Post, "/nine/webhook") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Add("9in-signature", Signature.Sign(secret, "POST", path, body));
        return client.SendAsync(request);
    }

    private static WebhookLog Log(NineAppFactory app) => (WebhookLog)app.Services.GetService(typeof(WebhookLog))!;

    [Fact]
    public async Task VerifiesAndRunsTheHandlersOnce()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        var user = new JsonObject { ["user"] = new JsonObject { ["id"] = "usr_1", ["email"] = "jane@acme.test" } };
        Assert.Equal(HttpStatusCode.NoContent, (await Deliver(client, "user.created", user, "evt_1")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Deliver(client, "user.created", (JsonObject)user.DeepClone(), "evt_1")).StatusCode);
        Assert.Equal(["evt_1"], Log(app).Handled);
        Assert.Equal(["evt_1"], Log(app).Typed);
        Assert.Equal(HttpStatusCode.NoContent, (await Deliver(client, "user.updated", (JsonObject)user.DeepClone(), "evt_2")).StatusCode);
        Assert.Equal(["evt_1", "evt_2"], Log(app).Handled);
        Assert.Equal(["evt_1"], Log(app).Typed); // On("user.created") only
    }

    [Fact]
    public async Task RefusesBadSignaturesAndPayloads()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        var wrong = await Deliver(client, "user.created", [], secret: "whsec_wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("""{"error":"invalid_signature"}""", await wrong.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Deliver(client, "user.created", [], path: "/elsewhere")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Deliver(client, "user.created", [], secret: "whsec_old")).StatusCode); // rotation

        var unsigned = await client.PostAsync("/nine/webhook", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
        var notAnEvent = new HttpRequestMessage(HttpMethod.Post, "/nine/webhook") { Content = new StringContent("[]") };
        notAnEvent.Headers.Add("9in-signature", Signature.Sign(NineAppFactory.WebhookSecret, "POST", "/nine/webhook", "[]"));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(notAnEvent)).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await client.GetAsync("/nine/webhook")).StatusCode);
    }

    [Fact]
    public async Task AFailedHandlerIsRetried()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        Log(app).FailNext = 1;
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            var response = await Deliver(client, "user.deleted", [], "evt_retry");
            response.EnsureSuccessStatusCode();
        });
        Assert.Equal(HttpStatusCode.NoContent, (await Deliver(client, "user.deleted", [], "evt_retry")).StatusCode);
        Assert.Equal(["evt_retry"], Log(app).Handled);
    }

    [Fact]
    public async Task AConcurrentDuplicateGets409()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Log(app).Gate = gate;
        var first = Deliver(client, "user.login", [], "evt_slow");
        HttpResponseMessage? second = null;
        for (var i = 0; i < 100 && second?.StatusCode != HttpStatusCode.Conflict; i++)
        {
            await Task.Delay(10);
            second = await Deliver(client, "user.login", [], "evt_slow");
        }
        Assert.Equal(HttpStatusCode.Conflict, second!.StatusCode);
        Log(app).Gate = null;
        gate.SetResult();
        Assert.Equal(HttpStatusCode.NoContent, (await first).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Deliver(client, "user.login", [], "evt_slow")).StatusCode);
        Assert.Equal(["evt_slow"], Log(app).Handled);
    }
}

public class AdapterTests
{
    private static HttpRequestMessage Signed(string path, string body, string secret = NineAppFactory.AdapterSecret)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Add("9in-signature", Signature.Sign(secret, "POST", path, body));
        request.Headers.Add("9in-request-id", "req_7");
        return request;
    }

    [Fact]
    public async Task ServesTheThreeRoutesWithSignedResponses()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        var ok = await client.SendAsync(Signed("/nine/authenticate", """{"identifier":{"type":"email","value":"jane@acme.test"},"password":"hunter2"}"""));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var body = await ok.Content.ReadAsByteArrayAsync();
        Assert.Equal("42", JsonNode.Parse(body)!["user"]!["id"]!.GetValue<string>());
        Assert.True(Signature.Verify([NineAppFactory.AdapterSecret], ok.Headers.GetValues("9in-signature").Single(), "POST", "/nine/authenticate#req_7", body));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Signed("/nine/authenticate", """{"identifier":{"type":"email","value":"jane@acme.test"},"password":"nope"}"""))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Signed("/nine/user", """{"id":"42"}"""))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.SendAsync(Signed("/nine/user", """{"id":"7"}"""))).StatusCode);
        var evt = await client.SendAsync(Signed("/nine/event", """{"id":"e1","event_type":"otp.requested","data":{"user_id":"42","code":"123456"}}"""));
        Assert.Equal(HttpStatusCode.NoContent, evt.StatusCode);
        Assert.Contains("adapter:otp.requested", ((WebhookLog)app.Services.GetService(typeof(WebhookLog))!).Handled);
    }

    [Fact]
    public async Task RefusesUnsignedRequests()
    {
        await using var app = new NineAppFactory(new FakeOidc());
        var client = app.CreateClient();
        var wrong = await client.SendAsync(Signed("/nine/user", """{"id":"42"}""", secret: "wrong"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/nine/user", new StringContent("""{"id":"42"}"""))).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await client.GetAsync("/nine/user")).StatusCode);
    }
}

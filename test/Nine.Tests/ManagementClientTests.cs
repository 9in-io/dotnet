using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;
using Nine.Tests.Support;

namespace Nine.Tests;

public class ManagementClientTests
{
    private readonly FakeIssuer _fake = new();
    private readonly List<string> _tokenScopes = [];
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);
    private static readonly JsonObject User = new()
    {
        ["id"] = "usr_1", ["email"] = "jane@acme.test", ["email_verified"] = true, ["phone_number"] = null, ["phone_number_verified"] = false,
        ["username"] = null, ["name"] = "Jane", ["blocked"] = false, ["metadata"] = new JsonObject { ["plan"] = "pro", ["camelKey"] = 1 },
        ["created_at"] = "2026-11-10T09:30:00.000Z", ["updated_at"] = "2026-11-10T09:30:00.000Z", ["last_login_at"] = null, ["login_count"] = 3,
        ["future_field"] = "kept",
    };

    public ManagementClientTests()
    {
        _fake.On("POST", "/oauth/token", request =>
        {
            Assert.Equal("Basic " + Convert.ToBase64String("mgmt_app:mgmt%2Fsecret"u8.ToArray()), request.Authorization);
            Assert.Equal("client_credentials", request.Form["grant_type"]);
            var scope = request.Form["scope"];
            _tokenScopes.Add(scope);
            return FakeIssuer.Json(new JsonObject { ["access_token"] = "tok:" + scope + ":" + _tokenScopes.Count, ["token_type"] = "Bearer", ["expires_in"] = 300 });
        });
    }

    private ManagementClient Client() => new(new ManagementClientOptions { Issuer = _fake.Issuer, ClientId = "mgmt_app", ClientSecret = "mgmt/secret", TimeProvider = _clock }, _fake.Client());

    private static void AssertBearer(RecordedRequest request, string scope) => Assert.StartsWith("Bearer tok:" + scope + ":", request.Authorization);

    [Fact]
    public async Task ListsUsersWithAQueryAndACursor()
    {
        _fake.On("GET", "/api/v1/users", request => FakeIssuer.Json(new JsonObject { ["users"] = new JsonArray(User.DeepClone()), ["next_cursor"] = "c2", ["total"] = 7 }));
        var page = await Client().ListUsersAsync("jane doe", "c1", 50);
        var request = _fake.Last("/api/v1/users");
        Assert.Equal("?q=jane%20doe&cursor=c1&limit=50", request.Query);
        AssertBearer(request, "management:users:read");
        Assert.Equal("c2", page.NextCursor);
        Assert.Equal(7, page.Total);
        var user = Assert.Single(page.Users);
        Assert.Equal("usr_1", user.Id);
        Assert.True(user.EmailVerified);
        Assert.Equal(3, user.LoginCount);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 9, 30, 0, TimeSpan.Zero), user.CreatedAt);
        Assert.Null(user.LastLoginAt);
        Assert.Equal("pro", (string)user.Metadata!["plan"]!);
        Assert.Equal(1, (int)user.Metadata!["camelKey"]!); // metadata keys pass through unchanged
        Assert.Equal("kept", user.Extra!["future_field"].GetString());
    }

    [Fact]
    public async Task ListAllUsersFollowsCursors()
    {
        _fake.On("GET", "/api/v1/users", request => request.Query.Contains("cursor=c2", StringComparison.Ordinal)
            ? FakeIssuer.Json(new JsonObject { ["users"] = new JsonArray(User.DeepClone()), ["next_cursor"] = null })
            : FakeIssuer.Json(new JsonObject { ["users"] = new JsonArray(User.DeepClone(), User.DeepClone()), ["next_cursor"] = "c2" }));
        var all = new List<ManagedUser>();
        await foreach (var user in Client().ListAllUsersAsync())
        {
            all.Add(user);
        }
        Assert.Equal(3, all.Count);
    }

    [Fact]
    public async Task GetsTheUserDetail()
    {
        _fake.On("GET", "/api/v1/users/usr%201", _ => FakeIssuer.Json(new JsonObject
        {
            ["user"] = User.DeepClone(),
            ["identities"] = new JsonArray(new JsonObject { ["connection"] = "social:google", ["subject"] = "106", ["profile"] = new JsonObject { ["hd"] = "acme.test" }, ["created_at"] = "2026-11-10T09:30:00.000Z" }),
            ["sessions"] = new JsonArray(new JsonObject { ["sid"] = "sid_1", ["user_id"] = "usr_1", ["auth_time"] = "2026-11-10T09:30:00.000Z", ["amr"] = new JsonArray("pwd", "mfa"), ["ip"] = "1.2.3.4", ["user_agent"] = "UA", ["created_at"] = "2026-11-10T09:30:00.000Z", ["last_seen_at"] = "2026-11-10T09:31:00.000Z", ["expires_at"] = "2026-12-10T09:30:00.000Z" }),
            ["has_password"] = true,
            ["mfa"] = new JsonObject { ["enabled"] = true, ["enabled_at"] = "2026-11-10T09:30:00.000Z", ["recovery_codes_left"] = 8 },
        }));
        var detail = await Client().GetUserAsync("usr 1");
        Assert.Equal("usr_1", detail.User.Id);
        Assert.Equal("social:google", detail.Identities[0].Connection);
        Assert.Equal("acme.test", (string)detail.Identities[0].Profile!["hd"]!);
        Assert.Equal(["pwd", "mfa"], detail.Sessions[0].Amr);
        Assert.Equal("UA", detail.Sessions[0].UserAgent);
        Assert.True(detail.HasPassword);
        Assert.Equal(8, detail.Mfa.RecoveryCodesLeft);
    }

    [Fact]
    public async Task FindsUsersAndReturnsNullWhenUnknown()
    {
        _fake.On("GET", "/api/v1/users/lookup", request => request.Query switch
        {
            "?email=jane%40acme.test" or "?phone_number=%2B447700900000" or "?username=jane" => FakeIssuer.Json(new JsonObject { ["user"] = User.DeepClone() }),
            _ => FakeIssuer.Error("not_found", HttpStatusCode.NotFound),
        });
        var client = Client();
        Assert.Equal("usr_1", (await client.FindUserByEmailAsync("jane@acme.test"))!.Id);
        Assert.Equal("usr_1", (await client.FindUserByPhoneNumberAsync("+447700900000"))!.Id);
        Assert.Equal("usr_1", (await client.FindUserByUsernameAsync("jane"))!.Id);
        Assert.Null(await client.FindUserAsync("email", "nobody@acme.test"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.FindUserAsync("phone", "+44"));
    }

    [Fact]
    public async Task CreatesUsersWithSnakeCaseFieldsAndNoNulls()
    {
        _fake.On("POST", "/api/v1/users", _ => FakeIssuer.Json(new JsonObject { ["user"] = User.DeepClone() }, HttpStatusCode.Created));
        var user = await Client().CreateUserAsync(new NewUser
        {
            Email = "jane@acme.test", EmailVerified = true, PhoneNumber = "+447700900000", Password = "pw", PasswordHash = null,
            Metadata = new JsonObject { ["plan"] = "pro", ["nestedObject"] = new JsonObject { ["a"] = 1 } },
        });
        Assert.Equal("usr_1", user.Id);
        var request = _fake.Last("/api/v1/users");
        AssertBearer(request, "management:users:write");
        Assert.Equal("application/json; charset=utf-8", request.Headers["Content-Type"]);
        var body = request.Json!.AsObject();
        Assert.Equal(new[] { "email", "email_verified", "metadata", "password", "phone_number" }, body.Select(p => p.Key).Order().ToArray());
        Assert.Equal(1, (int)body["metadata"]!["nestedObject"]!["a"]!);
        Assert.False(body.ContainsKey("password_hash"));
    }

    [Fact]
    public async Task UpdatesOnlyTheFieldsThatWereSet()
    {
        _fake.On("PATCH", "/api/v1/users/usr_1", _ => FakeIssuer.Json(new JsonObject { ["user"] = User.DeepClone() }));
        var client = Client();
        var changes = new UserChanges { PhoneNumber = "+447700900000", PhoneNumberVerified = true, Username = null };
        changes.Set("nickname", null);
        await client.UpdateUserAsync("usr_1", changes);
        var body = _fake.Last("/api/v1/users/usr_1").Json!.AsObject();
        Assert.Equal(4, body.Count);
        Assert.Equal("+447700900000", (string)body["phone_number"]!);
        Assert.True((bool)body["phone_number_verified"]!);
        Assert.True(body.ContainsKey("username") && body["username"] is null);
        Assert.True(body.ContainsKey("nickname") && body["nickname"] is null);
        Assert.Equal("+447700900000", changes.PhoneNumber);
        Assert.Null(changes.Username);

        await client.BlockUserAsync("usr_1");
        Assert.Equal("""{"blocked":true}""", _fake.Last("/api/v1/users/usr_1").Body);
        await client.UnblockUserAsync("usr_1");
        Assert.Equal("""{"blocked":false}""", _fake.Last("/api/v1/users/usr_1").Body);
        await client.UpdateUserAsync("usr_1", new JsonObject { ["metadata"] = new JsonObject { ["x"] = 1 } });
        Assert.Equal("""{"metadata":{"x":1}}""", _fake.Last("/api/v1/users/usr_1").Body);
    }

    [Fact]
    public async Task ImportsUsers()
    {
        _fake.On("POST", "/api/v1/users/import", _ => FakeIssuer.Json(new JsonObject
        {
            ["results"] = new JsonArray(
                new JsonObject { ["index"] = 0, ["ok"] = true, ["status"] = "created", ["id"] = "auth0|42" },
                new JsonObject { ["index"] = 1, ["ok"] = false, ["status"] = "failed", ["error"] = "invalid_user", ["details"] = new JsonArray(new JsonObject { ["path"] = "email", ["message"] = "bad" }) }),
        }));
        var results = await Client().ImportUsersAsync(
            [new ImportUser { Id = "auth0|42", Email = "jane@acme.test", PasswordHash = "$2b$10$abc", CreatedAt = new DateTimeOffset(2021, 3, 4, 5, 6, 7, TimeSpan.Zero), Identities = [new ImportIdentity("social:google", "1069")] }, new ImportUser { Email = "bad" }],
            new ImportOptions { OnConflict = "skip", Source = "auth0" });
        Assert.Equal("created", results[0].Status);
        Assert.Equal("invalid_user", results[1].Error);
        Assert.Equal("email", results[1].Details!.Value[0].GetProperty("path").GetString());
        var body = _fake.Last("/api/v1/users/import").Json!.AsObject();
        Assert.Equal("skip", (string)body["on_conflict"]!);
        Assert.Equal("auth0", (string)body["source"]!);
        var first = body["users"]![0]!.AsObject();
        Assert.Equal("auth0|42", (string)first["id"]!);
        Assert.Equal("$2b$10$abc", (string)first["password_hash"]!);
        Assert.StartsWith("2021-03-04T05:06:07", (string)first["created_at"]!);
        Assert.Equal("social:google", (string)first["identities"]![0]!["connection"]!);
    }

    [Fact]
    public async Task LoginLinksAndSessions()
    {
        _fake.On("POST", "/api/v1/users/usr_1/login-link", _ => FakeIssuer.Json(new JsonObject { ["url"] = _fake.Issuer + "/login/link?t=x", ["expires_at"] = "2026-11-22T10:00:00.000Z" }));
        _fake.On("GET", "/api/v1/users/usr_1/sessions", _ => FakeIssuer.Json(new JsonObject { ["sessions"] = new JsonArray(new JsonObject { ["sid"] = "sid_1" }) }));
        _fake.On("DELETE", "/api/v1/users/usr_1/sessions", _ => FakeIssuer.Json(new JsonObject { ["revoked"] = 2 }));
        _fake.On("DELETE", "/api/v1/sessions/sid_1", _ => FakeIssuer.NoContent());
        _fake.On("DELETE", "/api/v1/users/usr_1", _ => FakeIssuer.NoContent());
        var client = Client();
        var link = await client.CreateLoginLinkAsync("usr_1", "https://app.acme.test/nine/callback", TimeSpan.FromMinutes(10));
        Assert.EndsWith("/login/link?t=x", link.Url);
        Assert.Equal("""{"return_to":"https://app.acme.test/nine/callback","ttl_seconds":600}""", _fake.Last("/api/v1/users/usr_1/login-link").Body);
        await client.CreateLoginLinkAsync("usr_1");
        Assert.Equal("{}", _fake.Last("/api/v1/users/usr_1/login-link").Body);
        Assert.Equal("sid_1", (await client.ListUserSessionsAsync("usr_1"))[0].Sid);
        AssertBearer(_fake.Last("/api/v1/users/usr_1/sessions"), "management:users:read");
        Assert.Equal(2, await client.RevokeUserSessionsAsync("usr_1"));
        AssertBearer(_fake.Last("/api/v1/users/usr_1/sessions"), "management:sessions:write");
        await client.RevokeSessionAsync("sid_1");
        AssertBearer(_fake.Last("/api/v1/sessions/sid_1"), "management:sessions:write");
        await client.DeleteUserAsync("usr_1");
        AssertBearer(_fake.Last("/api/v1/users/usr_1"), "management:users:write");
    }

    [Fact]
    public async Task CachesOneTokenPerScopeUntilShortlyBeforeExpiry()
    {
        _fake.On("GET", "/api/v1/users", _ => FakeIssuer.Json(new JsonObject { ["users"] = new JsonArray() }));
        var client = Client();
        await client.ListUsersAsync();
        await client.ListUsersAsync();
        Assert.Equal(["management:users:read"], _tokenScopes);
        _clock.Advance(TimeSpan.FromSeconds(269));
        await client.ListUsersAsync();
        Assert.Single(_tokenScopes);
        _clock.Advance(TimeSpan.FromSeconds(2)); // within 30 s of expiry
        await client.ListUsersAsync();
        Assert.Equal(2, _tokenScopes.Count);
    }

    [Fact]
    public async Task A401DropsTheCachedToken()
    {
        var calls = 0;
        _fake.On("GET", "/api/v1/users", _ => ++calls == 1 ? FakeIssuer.Error("invalid_token", HttpStatusCode.Unauthorized) : FakeIssuer.Json(new JsonObject { ["users"] = new JsonArray() }));
        var client = Client();
        var e = await Assert.ThrowsAsync<NineException>(() => client.ListUsersAsync());
        Assert.Equal(401, e.StatusCode);
        await client.ListUsersAsync();
        Assert.Equal(2, _tokenScopes.Count);
    }

    [Fact]
    public async Task ErrorsCarryTheServerErrorDescriptionAndStatus()
    {
        _fake.On("POST", "/api/v1/users", _ => FakeIssuer.Error("invalid_user", HttpStatusCode.BadRequest, "unknown field: phone"));
        var e = await Assert.ThrowsAsync<NineException>(() => Client().CreateUserAsync(new NewUser { Email = "x" }));
        Assert.Equal("invalid_user", e.Error);
        Assert.Equal("unknown field: phone", e.ErrorDescription);
        Assert.Equal(400, e.StatusCode);
        _fake.On("GET", "/api/v1/users", _ => new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new StringContent("<html>") });
        var gateway = await Assert.ThrowsAsync<NineException>(() => Client().ListUsersAsync());
        Assert.Equal("request_failed", gateway.Error);
        Assert.Equal(502, gateway.StatusCode);
        _fake.On("POST", "/oauth/token", _ => FakeIssuer.Error("unauthorized_client", HttpStatusCode.BadRequest, "management scopes not granted"));
        Assert.Equal("unauthorized_client", (await Assert.ThrowsAsync<NineException>(() => Client().ListUsersAsync())).Error);
    }

    [Fact]
    public void RequiresCredentials()
    {
        Assert.Equal("invalid_options", Assert.Throws<NineException>(() => new ManagementClient(new ManagementClientOptions { Issuer = _fake.Issuer, ClientId = "x" })).Error);
    }
}

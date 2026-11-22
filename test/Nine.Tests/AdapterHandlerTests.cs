using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;

namespace Nine.Tests;

public class AdapterHandlerTests
{
    private const string Secret = "adapter-secret";
    private readonly TestAdapter _adapter = new();

    private sealed class TestAdapter : IAdapter
    {
        public List<AdapterEvent> Events { get; } = [];
        public List<AdapterQuery> Queries { get; } = [];

        public Task<AdapterResult> AuthenticateAsync(AdapterIdentifier identifier, string password, CancellationToken cancellationToken)
        {
            if (!identifier.Value.Equals("jane@acme.test", StringComparison.OrdinalIgnoreCase) && identifier.Value != "bob" && identifier.Value != "flagged")
            {
                return Task.FromResult(AdapterResult.Invalid);
            }
            if (identifier.Value == "bob")
            {
                return Task.FromResult(AdapterResult.Blocked);
            }
            if (identifier.Value == "flagged")
            {
                return Task.FromResult<AdapterResult>(new AdapterUser("9") { Blocked = true });
            }
            return Task.FromResult(password == "hunter2"
                ? new AdapterUser("42") { Email = "jane@acme.test", EmailVerified = true, Name = "Jane", Metadata = new JsonObject { ["plan"] = "pro" } }
                : AdapterResult.Invalid);
        }

        public Task<AdapterUser?> FindUserAsync(AdapterQuery query, CancellationToken cancellationToken)
        {
            Queries.Add(query);
            return Task.FromResult(query.Id == "42" || query.Identifier?.Value == "+447700900123" ? new AdapterUser("42") { PhoneNumber = "+447700900123" } : null);
        }

        public Task OnEventAsync(AdapterEvent adapterEvent, CancellationToken cancellationToken)
        {
            Events.Add(adapterEvent);
            return Task.CompletedTask;
        }
    }

    private AdapterHandler Handler(params string[] secrets) => new(secrets.Length == 0 ? [Secret] : secrets, _adapter);

    private static AdapterRequest Signed(string path, string body, string secret = Secret, string method = "POST", string requestId = "req_1", long? timestamp = null) =>
        new(method, path, new Dictionary<string, string>
        {
            ["9IN-Signature"] = Signature.Sign(secret, "POST", path, body, timestamp),
            ["9in-request-id"] = requestId,
        }, Encoding.UTF8.GetBytes(body));

    private static void AssertSignedResponse(AdapterResponse response, string path, string requestId = "req_1")
    {
        var header = response.Headers["9in-signature"];
        Assert.True(Signature.Verify([Secret], header, "POST", path + "#" + requestId, response.Body), "the response is signed over path#request-id");
        Assert.False(Signature.Verify([Secret], header, "POST", path + "#req_other", response.Body));
    }

    [Fact]
    public async Task AuthenticateReturnsTheUser()
    {
        var response = await Handler().HandleAsync(Signed("/nine/authenticate", """{"identifier":{"type":"email","value":"Jane@Acme.test"},"password":"hunter2"}"""));
        Assert.Equal(200, response.StatusCode);
        Assert.Equal("application/json", response.Headers["Content-Type"]);
        var user = JsonNode.Parse(response.BodyText)!["user"]!.AsObject();
        Assert.Equal("42", (string)user["id"]!);
        Assert.True((bool)user["email_verified"]!);
        Assert.Equal("pro", (string)user["metadata"]!["plan"]!);
        Assert.False(user.ContainsKey("phone_number")); // nulls are left out
        AssertSignedResponse(response, "/nine/authenticate");
    }

    [Theory]
    [InlineData("""{"identifier":{"type":"email","value":"jane@acme.test"},"password":"wrong"}""", 401, "invalid_credentials")]
    [InlineData("""{"identifier":{"type":"email","value":"nobody@acme.test"},"password":"hunter2"}""", 401, "invalid_credentials")]
    [InlineData("""{"identifier":{"type":"username","value":"bob"},"password":"x"}""", 403, "blocked")]
    [InlineData("""{"identifier":{"type":"username","value":"flagged"},"password":"x"}""", 403, "blocked")]
    [InlineData("""{"identifier":{"type":"email","value":"jane@acme.test"}}""", 400, "invalid_request")]
    [InlineData("""{"identifier":{"type":"email","value":"jane@acme.test"},"password":1}""", 400, "invalid_request")]
    [InlineData("""{"identifier":{"type":"fax","value":"1"},"password":"x"}""", 400, "invalid_request")]
    [InlineData("""{"identifier":{"type":"email","value":""},"password":"x"}""", 400, "invalid_request")]
    [InlineData("""{"password":"x"}""", 400, "invalid_request")]
    [InlineData("""not json""", 400, "invalid_json")]
    [InlineData("""[1,2]""", 400, "invalid_json")]
    public async Task AuthenticateStatusCodes(string body, int status, string error)
    {
        var response = await Handler().HandleAsync(Signed("/nine/authenticate", body));
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(error, JsonNode.Parse(response.BodyText)!["error"]!.GetValue<string>());
        AssertSignedResponse(response, "/nine/authenticate");
    }

    [Fact]
    public async Task UserLooksUpByIdOrIdentifier()
    {
        var byId = await Handler().HandleAsync(Signed("/nine/user", """{"id":"42"}"""));
        Assert.Equal(200, byId.StatusCode);
        Assert.Equal("42", _adapter.Queries[^1].Id);
        var numericId = await Handler().HandleAsync(Signed("/nine/user", """{"id":42}"""));
        Assert.Equal(200, numericId.StatusCode);
        var byPhone = await Handler().HandleAsync(Signed("/nine/user", """{"identifier":{"type":"phone","value":"+447700900123"}}"""));
        Assert.Equal(200, byPhone.StatusCode);
        Assert.Equal("phone", _adapter.Queries[^1].Identifier!.Type);
        var unknown = await Handler().HandleAsync(Signed("/nine/user", """{"id":"7"}"""));
        Assert.Equal(404, unknown.StatusCode);
        Assert.Equal("""{"error":"not_found"}""", unknown.BodyText);
        AssertSignedResponse(unknown, "/nine/user");
        Assert.Equal(400, (await Handler().HandleAsync(Signed("/nine/user", """{}"""))).StatusCode);
        Assert.Equal(400, (await Handler().HandleAsync(Signed("/nine/user", """{"id":""}"""))).StatusCode);
    }

    [Fact]
    public async Task EventsAreDelivered()
    {
        var body = """{"id":"evt_1","event_type":"otp.requested","created_at":"2026-11-10T09:30:00.000Z","data":{"user_id":"42","channel":"email","to":"jane@acme.test","code":"123456","purpose":"login","expires_at":"2026-11-10T09:40:00.000Z"}}""";
        var response = await Handler().HandleAsync(Signed("/nine/event", body, requestId: "req_9"));
        Assert.Equal(204, response.StatusCode);
        Assert.Empty(response.Body);
        Assert.False(response.Headers.ContainsKey("Content-Type"));
        AssertSignedResponse(response, "/nine/event", "req_9");
        var evt = Assert.Single(_adapter.Events);
        Assert.Equal("otp.requested", evt.EventType);
        Assert.Equal("42", evt.UserId);
        Assert.Equal("123456", evt.Otp!.Code);
        Assert.Equal("email", evt.Otp.Channel);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 9, 40, 0, TimeSpan.Zero), evt.Otp.ExpiresAt);
        Assert.Equal(400, (await Handler().HandleAsync(Signed("/nine/event", """{"id":"evt_2"}"""))).StatusCode);
        Assert.Null((await ParseEvent("""{"id":"e","event_type":"user.updated","data":{"user_id":"42","fields":["name"]}}""")).Otp);
    }

    private async Task<AdapterEvent> ParseEvent(string body)
    {
        await Handler().HandleAsync(Signed("/nine/event", body));
        return _adapter.Events[^1];
    }

    [Fact]
    public async Task UnknownRoutesAre404()
    {
        var response = await Handler().HandleAsync(Signed("/nine/other", "{}"));
        Assert.Equal(404, response.StatusCode);
        AssertSignedResponse(response, "/nine/other");
    }

    [Fact]
    public async Task OnlyPost()
    {
        var response = await Handler().HandleAsync(Signed("/nine/user", """{"id":"42"}""", method: "GET"));
        Assert.Equal(405, response.StatusCode);
        Assert.Equal("POST", response.Headers["Allow"]);
    }

    [Fact]
    public async Task RefusesBadSignatures()
    {
        const string body = """{"id":"42"}""";
        var handler = Handler();
        Assert.Equal(401, (await handler.HandleAsync(Signed("/nine/user", body, secret: "wrong"))).StatusCode);
        var tampered = Signed("/nine/user", body) with { Body = Encoding.UTF8.GetBytes("""{"id":"43"}""") };
        Assert.Equal(401, (await handler.HandleAsync(tampered)).StatusCode);
        Assert.Equal(401, (await handler.HandleAsync(Signed("/nine/user", body) with { Path = "/elsewhere/user" })).StatusCode);
        var old = Signed("/nine/user", body, timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 301);
        var refused = await handler.HandleAsync(old);
        Assert.Equal(401, refused.StatusCode);
        Assert.Equal("""{"error":"invalid_signature"}""", refused.BodyText);
        var unsigned = new AdapterRequest("POST", "/nine/user", [], Encoding.UTF8.GetBytes(body));
        Assert.Equal(401, (await handler.HandleAsync(unsigned)).StatusCode);
        Assert.Empty(_adapter.Queries);
    }

    [Fact]
    public async Task AcceptsRotatedSecretsAndSignsWithTheFirst()
    {
        var handler = Handler("new-secret", Secret);
        var response = await handler.HandleAsync(Signed("/nine/user", """{"id":"42"}""", secret: Secret));
        Assert.Equal(200, response.StatusCode);
        Assert.True(Signature.Verify(["new-secret"], response.Headers["9in-signature"], "POST", "/nine/user#req_1", response.Body));
    }

    [Fact]
    public async Task UsesTheInjectedClock()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow.AddHours(1));
        var handler = new AdapterHandler(Secret, _adapter, timeProvider: clock);
        Assert.Equal(401, (await handler.HandleAsync(Signed("/nine/user", """{"id":"42"}"""))).StatusCode);
        Assert.Equal(200, (await handler.HandleAsync(Signed("/nine/user", """{"id":"42"}""", timestamp: clock.GetUtcNow().ToUnixTimeSeconds()))).StatusCode);
    }

    [Fact]
    public void NeedsASecret()
    {
        Assert.Throws<NineException>(() => new AdapterHandler(Array.Empty<string>(), _adapter));
        Assert.Throws<NineException>(() => new AdapterHandler([""], _adapter));
        Assert.Throws<ArgumentException>(() => new AdapterUser(""));
    }
}

public class WebhookTests
{
    private const string Secret = "whsec_test";
    private const string Path = "/nine/webhook";
    private static readonly string Body = """{"id":"evt_1","event_type":"token.revoked","created_at":"2026-11-10T09:30:00.000Z","tenant":"tnt_1","environment":"sandbox","data":{"user":{"id":"usr_1","email":"jane@acme.test","email_verified":true,"blocked":false,"metadata":{},"login_count":2,"created_at":"2026-11-10T09:30:00.000Z"},"token_type":"access_token","client_id":"app_1","jti":"jti_1","sid":"sid_1"}}""";

    [Fact]
    public void VerifiesAndParsesTheEvent()
    {
        var evt = Webhook.Verify(Secret, Body, Signature.Sign(Secret, "POST", Path, Body), Path);
        Assert.Equal("evt_1", evt.Id);
        Assert.Equal(WebhookEventTypes.TokenRevoked, evt.EventType);
        Assert.Equal("tnt_1", evt.Tenant);
        Assert.Equal("sandbox", evt.Environment);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 9, 30, 0, TimeSpan.Zero), evt.CreatedAt);
        Assert.Equal("usr_1", evt.UserId);
        Assert.Equal("jane@acme.test", evt.User!.Email);
        Assert.Equal(2, evt.User.LoginCount);
        var data = evt.GetData(TokenRevokedJsonContext.Default.TokenRevokedData)!;
        Assert.Equal("access_token", data.TokenType);
        Assert.Equal("jti_1", evt.GetData<TokenRevokedData>()!.Jti);
        Assert.Equal("sid_1", evt.GetData<SessionRevokedData>()!.Sid);
        Assert.Equal("app_1", evt.Data.GetProperty("client_id").GetString());
    }

    [Fact]
    public void AcceptsBytesAndRotatedSecrets()
    {
        var header = Signature.Sign(Secret, "POST", Path, Body);
        Assert.Equal("evt_1", Webhook.Verify(["whsec_old", Secret], Encoding.UTF8.GetBytes(Body), header, Path).Id);
    }

    [Fact]
    public void Refusals()
    {
        var header = Signature.Sign(Secret, "POST", Path, Body);
        void Refused(Action verify, SignatureFailure reason)
        {
            var e = Assert.Throws<SignatureException>(verify);
            Assert.Equal(401, e.StatusCode);
            Assert.Equal("invalid_signature", e.Error);
            Assert.Equal(reason, e.Reason);
        }
        Refused(() => Webhook.Verify("whsec_wrong", Body, header, Path), SignatureFailure.Mismatch);
        Refused(() => Webhook.Verify(Secret, Body.Replace("token.revoked", "user.deleted"), header, Path), SignatureFailure.Mismatch);
        Refused(() => Webhook.Verify(Secret, Body, header, "/elsewhere"), SignatureFailure.Mismatch);
        Refused(() => Webhook.Verify(Secret, Body, null, Path), SignatureFailure.Missing);
        Refused(() => Webhook.Verify(Secret, Body, "nope", Path), SignatureFailure.Malformed);
        Refused(() => Webhook.Verify(Secret, Body, header, Path, method: "PUT"), SignatureFailure.Mismatch);
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow.AddSeconds(301));
        Refused(() => Webhook.Verify(Secret, Body, header, Path, timeProvider: clock), SignatureFailure.Expired);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("""{"event_type":"user.created"}""")]
    [InlineData("""{"id":"evt_1"}""")]
    public void RefusesBodiesThatAreNotEvents(string body)
    {
        var e = Assert.Throws<NineException>(() => Webhook.Verify(Secret, body, Signature.Sign(Secret, "POST", Path, body), Path));
        Assert.Equal("invalid_payload", e.Error);
        Assert.Equal(400, e.StatusCode);
    }

    [Fact]
    public void EventsWithoutAUser()
    {
        const string body = """{"id":"evt_2","event_type":"webhook.test","created_at":"2026-11-10T09:30:00.000Z","tenant":"tnt_1","environment":"production","data":{"message":"hello","endpoint_id":"whe_1"}}""";
        var evt = Webhook.Verify(Secret, body, Signature.Sign(Secret, "POST", Path, body), Path);
        Assert.Null(evt.User);
        Assert.Null(evt.UserId);
        Assert.Equal("whe_1", evt.GetData<WebhookTestData>()!.EndpointId);
    }
}

[System.Text.Json.Serialization.JsonSourceGenerationOptions(PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.SnakeCaseLower)]
[System.Text.Json.Serialization.JsonSerializable(typeof(TokenRevokedData))]
internal sealed partial class TokenRevokedJsonContext : System.Text.Json.Serialization.JsonSerializerContext;

public class EventDeduplicatorTests
{
    [Fact]
    public async Task ProcessesOnce()
    {
        var dedupe = new EventDeduplicator(new NineMemoryCache());
        var runs = 0;
        Assert.Equal(EventOutcome.Processed, await dedupe.ProcessAsync("evt_1", _ => { runs++; return Task.CompletedTask; }));
        Assert.Equal(EventOutcome.Duplicate, await dedupe.ProcessAsync("evt_1", _ => { runs++; return Task.CompletedTask; }));
        Assert.Equal(1, runs);
        Assert.Equal(EventOutcome.Processed, await dedupe.ProcessAsync("evt_2", _ => { runs++; return Task.CompletedTask; }));
    }

    [Fact]
    public async Task AConcurrentDuplicateIsInProgress()
    {
        var dedupe = new EventDeduplicator(new NineMemoryCache());
        var release = new TaskCompletionSource();
        var first = dedupe.ProcessAsync("evt_1", _ => release.Task);
        Assert.Equal(EventOutcome.InProgress, await dedupe.ProcessAsync("evt_1", _ => Task.CompletedTask));
        release.SetResult();
        Assert.Equal(EventOutcome.Processed, await first);
        Assert.Equal(EventOutcome.Duplicate, await dedupe.ProcessAsync("evt_1", _ => Task.CompletedTask));
    }

    [Fact]
    public async Task AFailedHandlerReleasesTheIdSoTheRetryRuns()
    {
        var dedupe = new EventDeduplicator(new NineMemoryCache());
        await Assert.ThrowsAsync<InvalidOperationException>(() => dedupe.ProcessAsync("evt_1", _ => throw new InvalidOperationException("db down")));
        var runs = 0;
        Assert.Equal(EventOutcome.Processed, await dedupe.ProcessAsync("evt_1", _ => { runs++; return Task.CompletedTask; }));
        Assert.Equal(1, runs);
    }

    [Fact]
    public async Task AStuckClaimExpiresAndProcessedIdsAreForgottenAfterTheirTtl()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var cache = new NineMemoryCache(timeProvider: clock);
        var dedupe = new EventDeduplicator(cache, ttl: TimeSpan.FromHours(1), lockTime: TimeSpan.FromSeconds(30));
        await cache.SetAsync("nine:event:evt_stuck", "processing", TimeSpan.FromSeconds(30));
        Assert.Equal(EventOutcome.InProgress, await dedupe.ProcessAsync("evt_stuck", _ => Task.CompletedTask));
        clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(EventOutcome.Processed, await dedupe.ProcessAsync("evt_stuck", _ => Task.CompletedTask));
        clock.Advance(TimeSpan.FromMinutes(59));
        Assert.Equal(EventOutcome.Duplicate, await dedupe.ProcessAsync("evt_stuck", _ => Task.CompletedTask));
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(EventOutcome.Processed, await dedupe.ProcessAsync("evt_stuck", _ => Task.CompletedTask));
    }
}

public class NineMemoryCacheTests
{
    [Fact]
    public async Task AddIsAtomic()
    {
        var cache = new NineMemoryCache();
        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(async () => await cache.AddAsync("k", i.ToString(), TimeSpan.FromMinutes(1)))));
        Assert.Single(results, r => r);
    }

    [Fact]
    public async Task ExpiresAndTrims()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var cache = new NineMemoryCache(maxEntries: 10, timeProvider: clock);
        await cache.SetAsync("a", "1", TimeSpan.FromSeconds(10));
        Assert.Equal("1", await cache.GetAsync("a"));
        Assert.False(await cache.AddAsync("a", "2", TimeSpan.FromSeconds(10)));
        clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Null(await cache.GetAsync("a"));
        Assert.True(await cache.AddAsync("a", "2", TimeSpan.FromSeconds(10)));
        await cache.RemoveAsync("a");
        Assert.Null(await cache.GetAsync("a"));
        for (var i = 0; i < 50; i++)
        {
            await cache.SetAsync("k" + i, "v", TimeSpan.FromMinutes(i + 1));
        }
        Assert.InRange(cache.Count, 1, 10);
        Assert.Equal("v", await cache.GetAsync("k49")); // the latest to expire are kept
    }
}

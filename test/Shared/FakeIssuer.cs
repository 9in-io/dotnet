using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace Nine.Tests.Support;

public sealed record RecordedRequest(string Method, string Path, string Query, IReadOnlyDictionary<string, string> Headers, string Body)
{
    public Dictionary<string, string> Form =>
        Body.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace('+', ' ')), p => p.Length > 1 ? Uri.UnescapeDataString(p[1].Replace('+', ' ')) : "");

    public string? Authorization => Headers.TryGetValue("Authorization", out var v) ? v : null;

    public JsonNode? Json => Body.Length == 0 ? null : JsonNode.Parse(Body);
}

/// <summary>
/// An in-memory 9in issuer for unit tests: discovery and JWKS served from <see cref="Keys"/>, every
/// other route answered by a handler registered with <see cref="On"/>. Each instance has its own
/// issuer URL, so the SDK's process-wide caches never mix tests.
/// </summary>
public sealed class FakeIssuer : HttpMessageHandler
{
    private readonly ConcurrentDictionary<string, Func<RecordedRequest, HttpResponseMessage>> _routes = new();

    public FakeIssuer(string? issuer = null)
    {
        Issuer = issuer ?? $"https://t-{Guid.NewGuid():N}.9in.test";
        Discovery = new JsonObject
        {
            ["issuer"] = Issuer,
            ["authorization_endpoint"] = Issuer + "/oauth/authorize",
            ["token_endpoint"] = Issuer + "/oauth/token",
            ["userinfo_endpoint"] = Issuer + "/oauth/userinfo",
            ["jwks_uri"] = Issuer + "/.well-known/jwks.json",
            ["revocation_endpoint"] = Issuer + "/oauth/revoke",
            ["introspection_endpoint"] = Issuer + "/oauth/introspect",
            ["end_session_endpoint"] = Issuer + "/oauth/logout",
            ["device_authorization_endpoint"] = Issuer + "/oauth/device/authorize",
            ["authorization_response_iss_parameter_supported"] = true,
        };
        On("GET", "/.well-known/openid-configuration", _ => Json(Discovery));
        On("GET", "/.well-known/jwks.json", _ =>
        {
            var keys = new JsonArray();
            foreach (var key in Keys)
            {
                keys.Add(key.DeepClone());
            }
            return Json(new JsonObject { ["keys"] = keys });
        });
    }

    public string Issuer { get; }
    public JsonObject Discovery { get; }
    public List<JsonObject> Keys { get; } = [];
    public ConcurrentQueue<RecordedRequest> Requests { get; } = new();

    public int Count(string method, string path) => Requests.Count(r => r.Method == method && r.Path == path);

    public RecordedRequest Last(string path) => Requests.Last(r => r.Path == path);

    public HttpClient Client() => new(this, disposeHandler: false);

    public FakeIssuer AddKey(TestKey key)
    {
        if (key.Jwk is not null)
        {
            Keys.Add(key.Jwk);
        }
        return this;
    }

    public FakeIssuer On(string method, string path, Func<RecordedRequest, HttpResponseMessage> handler)
    {
        _routes[method + " " + path] = handler;
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        if (request.Content is not null)
        {
            foreach (var h in request.Content.Headers)
            {
                headers[h.Key] = string.Join(",", h.Value);
            }
        }
        var recorded = new RecordedRequest(request.Method.Method, uri.AbsolutePath, uri.Query, headers, body);
        Requests.Enqueue(recorded);
        if (!uri.GetLeftPart(UriPartial.Authority).Equals(new Uri(Issuer).GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
        {
            return new HttpResponseMessage(HttpStatusCode.BadGateway);
        }
        if (_routes.TryGetValue(recorded.Method + " " + recorded.Path, out var handler))
        {
            return handler(recorded);
        }
        return Json(new JsonObject { ["error"] = "not_found" }, HttpStatusCode.NotFound);
    }

    public static HttpResponseMessage Json(JsonNode body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Error(string error, HttpStatusCode status = HttpStatusCode.BadRequest, string? description = null)
    {
        var body = new JsonObject { ["error"] = error };
        if (description is not null)
        {
            body["error_description"] = description;
        }
        return Json(body, status);
    }

    public static HttpResponseMessage NoContent() => new(HttpStatusCode.NoContent);
}

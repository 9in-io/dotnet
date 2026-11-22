using System.Text;
using System.Text.Json;
using Nine.Internal;

namespace Nine;

/// <summary>
/// Framework-independent handler for adapter protocol v2: mount it at your adapter base URL and it serves
/// <c>…/authenticate</c>, <c>…/user</c> and <c>…/event</c>. Requests must carry a valid <c>9in-signature</c>
/// (HMAC-SHA256 over timestamp, method, path and raw body, 5-minute window, constant-time compare). Every
/// response is signed over <c>&lt;path&gt;#&lt;9in-request-id&gt;</c>, so 9in rejects a response replayed
/// from another request.
/// </summary>
public sealed class AdapterHandler
{
    private static readonly string[] IdentifierTypes = ["email", "username", "phone"];

    private readonly string[] _secrets;
    private readonly IAdapter _adapter;
    private readonly TimeSpan _tolerance;
    private readonly TimeProvider _time;

    /// <summary>Creates a handler.</summary>
    /// <param name="secrets">The adapter secret from the console (Connections → User database), or several during rotation; responses are signed with the first.</param>
    /// <param name="adapter">Your user database.</param>
    /// <param name="tolerance">How far a request's timestamp may be off. Default 5 minutes.</param>
    /// <param name="timeProvider">The clock (tests).</param>
    public AdapterHandler(IEnumerable<string> secrets, IAdapter adapter, TimeSpan? tolerance = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        _secrets = secrets.Where(s => !string.IsNullOrEmpty(s)).ToArray();
        if (_secrets.Length == 0)
        {
            throw new NineException("invalid_options", "an adapter secret is required (NINE_ADAPTER_SECRET)");
        }
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        _tolerance = tolerance ?? Signature.DefaultTolerance;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc cref="AdapterHandler(IEnumerable{string}, IAdapter, TimeSpan?, TimeProvider?)"/>
    public AdapterHandler(string secret, IAdapter adapter, TimeSpan? tolerance = null, TimeProvider? timeProvider = null)
        : this([secret], adapter, tolerance, timeProvider)
    {
    }

    /// <summary>Handles one request and returns the signed response. Exceptions from your adapter propagate (answer 500).</summary>
    public async Task<AdapterResponse> HandleAsync(AdapterRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var path = request.Path;
        var requestId = request.Header(Signature.RequestIdHeader) ?? "";

        if (!request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
        {
            return new AdapterResponse(405, new Dictionary<string, string> { ["Allow"] = "POST", ["Content-Type"] = "text/plain" }, "Method not allowed"u8.ToArray());
        }
        if (!Signature.Verify(_secrets, request.Header(Signature.Header), "POST", path, request.Body.Span, _tolerance, _time))
        {
            return new AdapterResponse(401, new Dictionary<string, string> { ["Content-Type"] = "application/json" }, """{"error":"invalid_signature"}"""u8.ToArray());
        }

        JsonElement input;
        try
        {
            using var document = request.Body.Length == 0 ? JsonDocument.Parse("{}") : JsonDocument.Parse(request.Body);
            input = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return Respond(path, requestId, 400, Error("invalid_json"));
        }
        if (input.ValueKind != JsonValueKind.Object)
        {
            return Respond(path, requestId, 400, Error("invalid_json"));
        }

        var route = path[(path.LastIndexOf('/') + 1)..];
        switch (route)
        {
            case "authenticate":
            {
                var identifier = ReadIdentifier(input);
                if (identifier is null || !input.TryGetProperty("password", out var password) || password.ValueKind != JsonValueKind.String)
                {
                    return Respond(path, requestId, 400, Error("invalid_request"));
                }
                var result = await _adapter.AuthenticateAsync(identifier, password.GetString()!, cancellationToken).ConfigureAwait(false)
                    ?? AdapterResult.Invalid;
                if (result.Error == "blocked" || result.User?.Blocked == true)
                {
                    return Respond(path, requestId, 403, Error("blocked"));
                }
                if (result.User is not { } user)
                {
                    return Respond(path, requestId, 401, Error("invalid_credentials"));
                }
                return Respond(path, requestId, 200, UserBody(user));
            }
            case "user":
            {
                AdapterQuery query;
                if (input.TryGetProperty("id", out var id) && ScalarText(id) is { Length: > 0 } idText)
                {
                    query = new AdapterQuery { Id = idText };
                }
                else if (ReadIdentifier(input) is { } identifier)
                {
                    query = new AdapterQuery { Identifier = identifier };
                }
                else
                {
                    return Respond(path, requestId, 400, Error("invalid_request"));
                }
                var user = await _adapter.FindUserAsync(query, cancellationToken).ConfigureAwait(false);
                return user is null ? Respond(path, requestId, 404, Error("not_found")) : Respond(path, requestId, 200, UserBody(user));
            }
            case "event":
            {
                if (!input.TryGetProperty("event_type", out var type) || type.ValueKind != JsonValueKind.String)
                {
                    return Respond(path, requestId, 400, Error("invalid_request"));
                }
                await _adapter.OnEventAsync(new AdapterEvent(input), cancellationToken).ConfigureAwait(false);
                return Respond(path, requestId, 204, null);
            }
            default:
                return Respond(path, requestId, 404, Error("not_found"));
        }
    }

    private AdapterResponse Respond(string path, string requestId, int status, byte[]? body)
    {
        var payload = body ?? [];
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [Signature.Header] = Signature.Sign(_secrets[0], "POST", path + "#" + requestId, payload, _time.GetUtcNow().ToUnixTimeSeconds()),
        };
        if (payload.Length > 0)
        {
            headers["Content-Type"] = "application/json";
        }
        return new AdapterResponse(status, headers, payload);
    }

    private static byte[] Error(string code) => Encoding.UTF8.GetBytes($$"""{"error":"{{code}}"}""");

    private static byte[] UserBody(AdapterUser user)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("user");
            JsonSerializer.Serialize(writer, user, NineJsonContext.Default.AdapterUser);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    private static AdapterIdentifier? ReadIdentifier(JsonElement input)
    {
        if (!input.TryGetProperty("identifier", out var identifier) || identifier.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        if (!identifier.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.String || !IdentifierTypes.Contains(type.GetString()))
        {
            return null;
        }
        if (!identifier.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
        {
            return null;
        }
        return new AdapterIdentifier(type.GetString()!, value.GetString()!);
    }

    private static string? ScalarText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.GetRawText(),
        _ => null,
    };
}

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Nine.Internal;

/// <summary>
/// The one place the SDK talks HTTP: a timeout on every call (10 seconds by default), redirects
/// never followed (a 3xx is an error), bounded response bodies, and no tokens or secrets in error
/// messages.
/// </summary>
internal sealed class NineHttp
{
    /// <summary>Default client when none is injected: no automatic redirects, pooled connections recycled.</summary>
    private static readonly Lazy<HttpClient> SharedClient = new(() => new HttpClient(CreateHandler(), disposeHandler: true)
    {
        Timeout = Timeout.InfiniteTimeSpan,
    });

    private const int MaxBody = 8 * 1024 * 1024;

    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    private readonly HttpClient _client;
    private readonly TimeSpan _timeout;

    public NineHttp(HttpClient? client, TimeSpan? timeout)
    {
        _client = client ?? SharedClient.Value;
        _timeout = timeout is { } t && t > TimeSpan.Zero ? t : DefaultTimeout;
    }

    /// <summary>The handler the SDK uses by default; also what the ASP.NET Core package registers.</summary>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectTimeout = TimeSpan.FromSeconds(10),
        AutomaticDecompression = DecompressionMethods.All,
    };

    public async Task<HttpResult> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (request.Headers.UserAgent.Count == 0)
        {
            request.Headers.UserAgent.ParseAdd(UserAgent);
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        var host = request.RequestUri?.Host ?? "?";
        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            var body = await ReadBodyAsync(response, timeout.Token).ConfigureAwait(false);
            return new HttpResult((int)response.StatusCode, body, response.Headers.Location?.ToString());
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new NineException("network_error", $"no answer from {host} within {_timeout.TotalSeconds:0.#} s");
        }
        catch (HttpRequestException e)
        {
            throw new NineException("network_error", $"request to {host} failed: {e.Message}", null, e);
        }
    }

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > MaxBody)
        {
            throw new NineException("network_error", "response too large");
        }
        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxBody)
            {
                throw new NineException("network_error", "response too large");
            }
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    public Task<HttpResult> GetAsync(string url, CancellationToken cancellationToken, string? bearer = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }
        return SendDisposingAsync(request, cancellationToken);
    }

    /// <summary>A form POST, with HTTP Basic client authentication when a secret is given.</summary>
    public Task<HttpResult> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> form, ClientAuth? auth, CancellationToken cancellationToken)
    {
        var fields = form.ToList();
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        if (auth is { Secret: not null } basic)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic.BasicCredentials());
        }
        else if (auth is not null)
        {
            fields.Add(new("client_id", auth.ClientId));
        }
        request.Content = new FormUrlEncodedContent(fields);
        return SendDisposingAsync(request, cancellationToken);
    }

    public Task<HttpResult> SendJsonAsync(HttpMethod method, string url, string bearer, byte[]? json, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (json is not null)
        {
            request.Content = new ByteArrayContent(json);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        }
        return SendDisposingAsync(request, cancellationToken);
    }

    private async Task<HttpResult> SendDisposingAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request)
        {
            return await SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    internal static readonly string UserAgent = "9in-dotnet/" + (typeof(NineHttp).Assembly.GetName().Version?.ToString(3) ?? "0");
}

/// <summary>Client authentication for token, revocation and introspection requests.</summary>
internal sealed record ClientAuth(string ClientId, string? Secret)
{
    /// <summary><c>client_secret_basic</c>: both parts form-URL-encoded, then base64 (RFC 6749 §2.3.1).</summary>
    public string BasicCredentials() =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(Uri.EscapeDataString(ClientId) + ":" + Uri.EscapeDataString(Secret ?? "")));
}

internal readonly record struct HttpResult(int Status, byte[] Body, string? Location)
{
    public bool IsSuccess => Status is >= 200 and < 300;

    /// <summary>The body as a JSON object, or null when it isn't one.</summary>
    public JsonElement? JsonObject()
    {
        if (Body.Length == 0)
        {
            return null;
        }
        try
        {
            using var document = JsonDocument.Parse(Body);
            return document.RootElement.ValueKind == JsonValueKind.Object ? document.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>A <see cref="NineException"/> from an error body (<c>{ error, error_description }</c>), or <paramref name="fallback"/>.</summary>
    public NineException Error(string fallback)
    {
        var json = JsonObject();
        string? error = null, description = null;
        if (json is { } body)
        {
            if (body.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String)
            {
                error = e.GetString();
            }
            if (body.TryGetProperty("error_description", out var d) && d.ValueKind == JsonValueKind.String)
            {
                description = d.GetString();
            }
        }
        if (Status is >= 300 and < 400)
        {
            return new NineException(fallback, $"HTTP {Status}: redirects are not followed", Status);
        }
        return new NineException(string.IsNullOrEmpty(error) ? fallback : error, description ?? $"HTTP {Status}", Status);
    }
}

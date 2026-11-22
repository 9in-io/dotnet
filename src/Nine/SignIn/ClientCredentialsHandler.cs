using System.Net;
using System.Net.Http.Headers;

namespace Nine;

/// <summary>
/// An <see cref="HttpClient"/> handler that adds a client-credentials access token to every request
/// (machine-to-machine calls to your APIs). The token is cached until a minute before it expires, and
/// concurrent requests share one token request. A 401 answer drops the cached token.
/// <code>
/// var http = new HttpClient(new ClientCredentialsHandler(auth, audience: "https://api.acme.com") { InnerHandler = new HttpClientHandler() });
/// </code>
/// </summary>
public sealed class ClientCredentialsHandler : DelegatingHandler
{
    private readonly AuthClient _client;
    private readonly string? _audience;
    private readonly string? _scope;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private TokenSet? _token;

    /// <summary>Creates the handler for a confidential <see cref="AuthClient"/>.</summary>
    public ClientCredentialsHandler(AuthClient client, string? audience = null, string? scope = null, TimeProvider? timeProvider = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        if (!client.IsConfidential)
        {
            throw new NineException("invalid_options", "client credentials need a confidential application (ClientSecret)");
        }
        _audience = audience;
        _scope = scope;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            Interlocked.CompareExchange(ref _token, null, token);
        }
        return response;
    }

    private async Task<TokenSet> TokenAsync(CancellationToken cancellationToken)
    {
        var current = _token;
        if (current is not null && !current.IsExpired(TimeSpan.FromSeconds(60), _time))
        {
            return current;
        }
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            current = _token;
            if (current is not null && !current.IsExpired(TimeSpan.FromSeconds(60), _time))
            {
                return current;
            }
            return _token = await _client.ClientCredentialsAsync(_audience, _scope, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _lock.Dispose();
        }
        base.Dispose(disposing);
    }
}

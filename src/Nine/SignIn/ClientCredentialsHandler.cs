using System.Net;
using System.Net.Http.Headers;

namespace Nine;

/// <summary>
/// An <see cref="HttpClient"/> handler that adds a client-credentials access token to every request
/// (machine-to-machine calls to your APIs). The token comes from
/// <see cref="AuthClient.GetClientCredentialsTokenAsync"/>, cached until a minute before it expires;
/// a 401 answer drops it so the next request gets a new one.
/// <code>
/// var http = new HttpClient(new ClientCredentialsHandler(auth, audience: "https://api.acme.com") { InnerHandler = new HttpClientHandler() });
/// </code>
/// </summary>
public sealed class ClientCredentialsHandler : DelegatingHandler
{
    private readonly AuthClient _client;
    private readonly string? _audience;
    private readonly string? _scope;

    /// <summary>Creates the handler for a confidential <see cref="AuthClient"/>.</summary>
    public ClientCredentialsHandler(AuthClient client, string? audience = null, string? scope = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        if (!client.IsConfidential)
        {
            throw new NineException("invalid_options", "client credentials need a confidential application (ClientSecret)");
        }
        _audience = audience;
        _scope = scope;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var token = await _client.GetClientCredentialsTokenAsync(_audience, _scope, cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            _client.ForgetClientCredentialsToken(_audience, _scope, token.AccessToken);
        }
        return response;
    }
}

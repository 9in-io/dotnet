using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Nine.AspNetCore;

/// <summary>
/// Settings shared by everything 9in in the app, read from the <c>Nine</c> configuration section
/// (<c>appsettings.json</c>, user secrets, <c>Nine__Issuer</c> environment variables…) and, for anything it
/// doesn't set, from the <c>NINE_*</c> environment variables the other 9in SDKs use.
/// </summary>
public sealed class NineOptions
{
    /// <summary><c>Nine:Issuer</c> / <c>NINE_ISSUER</c>: your tenant's issuer, e.g. <c>https://acme.9in.io</c>.</summary>
    public string? Issuer { get; set; }
    /// <summary><c>Nine:ClientId</c> / <c>NINE_CLIENT_ID</c>.</summary>
    public string? ClientId { get; set; }
    /// <summary><c>Nine:ClientSecret</c> / <c>NINE_CLIENT_SECRET</c>: for confidential applications.</summary>
    public string? ClientSecret { get; set; }
    /// <summary><c>Nine:RedirectUri</c> / <c>NINE_REDIRECT_URI</c>: the full callback URL, when it can't be derived from the request (proxies).</summary>
    public string? RedirectUri { get; set; }
    /// <summary><c>Nine:Audience</c> / <c>NINE_AUDIENCE</c>: the API a web app asks access tokens for.</summary>
    public string? Audience { get; set; }
    /// <summary><c>Nine:ApiAudience</c> / <c>NINE_API_AUDIENCE</c>: the identifier of the API this app serves (defaults to <see cref="Audience"/>).</summary>
    public string? ApiAudience { get; set; }
    /// <summary><c>Nine:ApiSecret</c> / <c>NINE_API_SECRET</c>: the API's HMAC secret, for HS256/384/512 tokens.</summary>
    public string? ApiSecret { get; set; }
    /// <summary><c>Nine:TokenMode</c> / <c>NINE_TOKEN_MODE</c>: <c>local</c>, <c>hybrid</c> or <c>introspect</c>.</summary>
    public string? TokenMode { get; set; }
    /// <summary><c>Nine:WebhookSecret</c> / <c>NINE_WEBHOOK_SECRET</c>: comma-separated during rotation.</summary>
    public string? WebhookSecret { get; set; }
    /// <summary><c>Nine:AdapterSecret</c> / <c>NINE_ADAPTER_SECRET</c>: comma-separated during rotation.</summary>
    public string? AdapterSecret { get; set; }
    /// <summary><c>Nine:AllowInsecureIssuer</c> / <c>NINE_ALLOW_INSECURE_ISSUER</c>: accept a plain-http issuer other than localhost (development only).</summary>
    public bool AllowInsecureIssuer { get; set; }

    internal string RequireIssuer() => Issuer is { Length: > 0 } issuer
        ? issuer
        : throw new NineException("invalid_options", "the 9in issuer is missing: set Nine:Issuer in configuration or NINE_ISSUER");

    internal string RequireClientId() => ClientId is { Length: > 0 } id
        ? id
        : throw new NineException("invalid_options", "the 9in client ID is missing: set Nine:ClientId in configuration or NINE_CLIENT_ID");
}

internal sealed class NineOptionsSetup(IConfiguration? configuration = null) : IConfigureOptions<NineOptions>
{
    public void Configure(NineOptions options)
    {
        var section = configuration?.GetSection(NineDefaults.ConfigurationSection);
        string? Read(string key, string env)
        {
            var value = section?[key];
            return string.IsNullOrWhiteSpace(value) ? NineEnvironment.Get(env) : value.Trim();
        }
        options.Issuer ??= Read("Issuer", "ISSUER");
        options.ClientId ??= Read("ClientId", "CLIENT_ID");
        options.ClientSecret ??= Read("ClientSecret", "CLIENT_SECRET");
        options.RedirectUri ??= Read("RedirectUri", "REDIRECT_URI");
        options.Audience ??= Read("Audience", "AUDIENCE");
        options.ApiAudience ??= Read("ApiAudience", "API_AUDIENCE") ?? options.Audience;
        options.ApiSecret ??= Read("ApiSecret", "API_SECRET");
        options.TokenMode ??= Read("TokenMode", "TOKEN_MODE");
        options.WebhookSecret ??= Read("WebhookSecret", "WEBHOOK_SECRET");
        options.AdapterSecret ??= Read("AdapterSecret", "ADAPTER_SECRET");
        options.AllowInsecureIssuer = options.AllowInsecureIssuer || IsTrue(Read("AllowInsecureIssuer", "ALLOW_INSECURE_ISSUER"));
    }

    private static bool IsTrue(string? value) =>
        value is not null && (value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase) || value.Equals("on", StringComparison.OrdinalIgnoreCase));
}

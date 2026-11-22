using Microsoft.AspNetCore.Authentication;

namespace Nine.AspNetCore;

/// <summary>
/// Settings of the 9in bearer scheme (<see cref="NineAuthenticationBuilderExtensions.AddNineApi(AuthenticationBuilder, Action{NineBearerOptions}?)"/>).
/// Unset values come from <see cref="NineOptions"/> (the <c>Nine</c> configuration section and <c>NINE_*</c> variables).
/// </summary>
public sealed class NineBearerOptions : AuthenticationSchemeOptions
{
    /// <summary>Your tenant's issuer.</summary>
    public string? Issuer { get; set; }
    /// <summary>Your API's identifier: tokens must be issued for it (<c>Nine:ApiAudience</c>, else <c>Nine:Audience</c>).</summary>
    public string? Audience { get; set; }
    /// <summary>A confidential application of the tenant, for introspection (hybrid and introspect modes).</summary>
    public string? ClientId { get; set; }
    /// <summary>Its client secret.</summary>
    public string? ClientSecret { get; set; }
    /// <summary>The API's HMAC secret, for HS256/384/512 tokens.</summary>
    public string? Secret { get; set; }
    /// <summary>Hybrid when <see cref="ClientId"/> and <see cref="ClientSecret"/> are set, else local.</summary>
    public VerificationMode? Mode { get; set; }
    /// <summary>Longest time a hybrid answer is trusted without news from 9in. Default 5 minutes.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>Clock skew allowed on <c>exp</c> and <c>nbf</c>. Default 30 seconds.</summary>
    public TimeSpan Leeway { get; set; } = TimeSpan.FromSeconds(30);
    /// <summary>Accept a plain-http issuer other than localhost (development only).</summary>
    public bool AllowInsecureIssuer { get; set; }
    /// <summary>Your own verifier instead of one built from these settings.</summary>
    public IAccessTokenVerifier? Verifier { get; set; }
}

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Nine.AspNetCore;

/// <summary>
/// Settings of 9in sign-in for a web app (<see cref="NineAuthenticationBuilderExtensions.AddNineWebApp(Microsoft.AspNetCore.Authentication.AuthenticationBuilder, Action{NineWebAppOptions}?)"/>).
/// Issuer, client ID, secret, audience and redirect URI default to <see cref="NineOptions"/>.
/// </summary>
public sealed class NineWebAppOptions
{
    /// <summary>Your tenant's issuer (default <c>Nine:Issuer</c> / <c>NINE_ISSUER</c>).</summary>
    public string? Issuer { get; set; }
    /// <summary>The application's client ID (default <c>Nine:ClientId</c>).</summary>
    public string? ClientId { get; set; }
    /// <summary>The client secret of a confidential application (default <c>Nine:ClientSecret</c>).</summary>
    public string? ClientSecret { get; set; }
    /// <summary>An API to get access tokens for (default <c>Nine:Audience</c>).</summary>
    public string? Audience { get; set; }
    /// <summary>The full callback URL, when it can't be derived from the request (default <c>Nine:RedirectUri</c>).</summary>
    public string? RedirectUri { get; set; }
    /// <summary>Accept a plain-http issuer other than localhost (development only).</summary>
    public bool? AllowInsecureIssuer { get; set; }
    /// <summary>Default <c>openid profile email offline_access</c> (<c>offline_access</c> gives a refresh token, so sessions outlive the access token).</summary>
    public IList<string> Scopes { get; } = ["openid", "profile", "email", "offline_access"];
    /// <summary>Where the routes live. Default <c>/nine</c>: <c>/nine/login</c>, <c>/nine/signup</c>, <c>/nine/callback</c>, <c>/nine/logout</c>.</summary>
    public string BasePath { get; set; } = "/nine";
    /// <summary>The callback path. Default <c>{BasePath}/callback</c>; register <c>https://your-app/nine/callback</c> on the application.</summary>
    public string? CallbackPath { get; set; }
    /// <summary>Where users land after sign-in when no <c>return_to</c> was given. Default <c>/</c>.</summary>
    public string AfterSignInPath { get; set; } = "/";
    /// <summary>Where users land after sign-out (an allowed logout URL of the application). Default <c>/</c>.</summary>
    public string AfterSignOutPath { get; set; } = "/";
    /// <summary>How long before expiry the access token is refreshed. Default 60 seconds.</summary>
    public TimeSpan RefreshLeeway { get; set; } = TimeSpan.FromSeconds(60);
    /// <summary>A page for failed sign-ins (gets <c>?error=access_denied</c> and the like). Default: a plain-text 400 answer.</summary>
    public string? ErrorPath { get; set; }
    /// <summary>Language of the hosted pages (<c>ui_locales</c>), e.g. <c>de</c>.</summary>
    public string? Locale { get; set; }
    /// <summary>Revoke the refresh token at 9in when the user signs out. Default true.</summary>
    public bool RevokeOnSignOut { get; set; } = true;
    /// <summary>How long a session lasts without being used. Default 30 days (each request with a refresh starts it again).</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromDays(30);
    /// <summary>More cookie settings (name, domain, a server-side <c>SessionStore</c> for large sessions…).</summary>
    public Action<CookieAuthenticationOptions>? ConfigureCookie { get; set; }
    /// <summary>More OpenID Connect settings. Events you set are kept; 9in's run first.</summary>
    public Action<OpenIdConnectOptions>? ConfigureOpenIdConnect { get; set; }

    /// <summary>The OpenID Connect scheme name (set by <c>AddNineWebApp</c>).</summary>
    public string Scheme { get; internal set; } = NineDefaults.AuthenticationScheme;

    /// <summary>The cookie scheme name (set by <c>AddNineWebApp</c>).</summary>
    public string CookieScheme { get; internal set; } = NineDefaults.CookieScheme;

    internal string NormalizedBasePath => "/" + BasePath.Trim('/');

    internal string EffectiveCallbackPath => CallbackPath ?? NormalizedBasePath + "/callback";
}

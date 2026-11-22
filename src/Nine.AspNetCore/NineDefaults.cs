namespace Nine.AspNetCore;

/// <summary>Names used by the 9in ASP.NET Core integration.</summary>
public static class NineDefaults
{
    /// <summary>The OpenID Connect scheme that signs users in with 9in (the challenge scheme of a web app).</summary>
    public const string AuthenticationScheme = "Nine";

    /// <summary>The cookie scheme that keeps the signed-in session of a web app.</summary>
    public const string CookieScheme = "Nine.Cookies";

    /// <summary>The bearer scheme that verifies access tokens for an API.</summary>
    public const string BearerScheme = "Nine.Bearer";

    /// <summary>The <see cref="IHttpClientFactory"/> client used for calls to 9in (no redirects followed).</summary>
    public const string HttpClientName = "Nine";

    /// <summary>The configuration section read for settings (environment variables <c>NINE_*</c> fill what it lacks).</summary>
    public const string ConfigurationSection = "Nine";
}

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Nine.AspNetCore;

/// <summary>Adds 9in to ASP.NET Core authentication.</summary>
public static class NineAuthenticationBuilderExtensions
{
    /// <summary>
    /// Signs users in with 9in: a cookie scheme (<see cref="NineDefaults.CookieScheme"/>) for the session and
    /// ASP.NET Core's OpenID Connect handler (<see cref="NineDefaults.AuthenticationScheme"/>) preconfigured for
    /// 9in: authorization code + PKCE, the callback at <c>/nine/callback</c>, the RFC 9207 issuer check, ID tokens
    /// verified by 9in's verifier (every algorithm), <c>client_secret_basic</c>, saved tokens, and refresh with
    /// rotation before the access token expires. Map <c>/nine/login</c>, <c>/nine/signup</c> and
    /// <c>/nine/logout</c> with <see cref="NineEndpointRouteBuilderExtensions.MapNineWebApp"/>. Settings come from
    /// the <c>Nine</c> configuration section or <c>NINE_*</c> environment variables.
    /// </summary>
    public static AuthenticationBuilder AddNineWebApp(this AuthenticationBuilder builder, Action<NineWebAppOptions>? configure = null) =>
        builder.AddNineWebApp(NineDefaults.CookieScheme, NineDefaults.AuthenticationScheme, configure);

    /// <summary>Like <see cref="AddNineWebApp(AuthenticationBuilder, Action{NineWebAppOptions}?)"/>, with your own scheme names.</summary>
    public static AuthenticationBuilder AddNineWebApp(this AuthenticationBuilder builder, string cookieScheme, string scheme, Action<NineWebAppOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(cookieScheme);
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        var services = builder.Services;
        services.AddNineCore();
        services.AddOptions<NineWebAppOptions>().Configure(options =>
        {
            options.Scheme = scheme;
            options.CookieScheme = cookieScheme;
        });
        if (configure is not null)
        {
            services.Configure(configure);
        }
        services.TryAddSingleton<NineWebApp>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<CookieAuthenticationOptions>, NineCookieSetup>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, NineCookieSetup>());
        builder.AddCookie(cookieScheme);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<OpenIdConnectOptions>, NineOpenIdConnectSetup>());
        builder.AddOpenIdConnect(scheme, "9in", _ => { });
        // After AddOpenIdConnect, so 9in's events wrap the app's and the framework has set up first.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, NineOpenIdConnectSetup>());
        services.PostConfigure<AuthenticationOptions>(options =>
        {
            if (options.DefaultScheme is null || options.DefaultScheme == NineDefaults.BearerScheme)
            {
                options.DefaultScheme = cookieScheme;
            }
            options.DefaultChallengeScheme ??= scheme;
        });
        return builder;
    }

    /// <summary>
    /// Protects an API with 9in access tokens: a bearer scheme (<see cref="NineDefaults.BearerScheme"/>) that
    /// verifies every algorithm of the key library, requires <c>typ: at+jwt</c>, checks issuer, audience and expiry
    /// and, with client credentials, catches revocations at once (hybrid mode; answers cached in your
    /// <c>IDistributedCache</c> and evicted by <see cref="NineEndpointRouteBuilderExtensions.MapNineWebhooks"/>).
    /// Check scopes with <c>.RequireScope("orders:read")</c> or <c>[RequireScope("orders:read")]</c>.
    /// </summary>
    public static AuthenticationBuilder AddNineApi(this AuthenticationBuilder builder, Action<NineBearerOptions>? configure = null) =>
        builder.AddNineApi(NineDefaults.BearerScheme, configure);

    /// <summary>Like <see cref="AddNineApi(AuthenticationBuilder, Action{NineBearerOptions}?)"/>, with your own scheme name.</summary>
    public static AuthenticationBuilder AddNineApi(this AuthenticationBuilder builder, string scheme, Action<NineBearerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        var services = builder.Services;
        services.AddNineCore();
        // Defaults from NineOptions first; the app's settings (configure) override them.
        services.AddOptions<NineBearerOptions>(scheme).Configure<IOptions<NineOptions>>((options, nine) =>
        {
            var shared = nine.Value;
            options.Issuer ??= shared.Issuer;
            options.Audience ??= shared.ApiAudience;
            options.ClientId ??= shared.ClientId;
            options.ClientSecret ??= shared.ClientSecret;
            options.Secret ??= shared.ApiSecret;
            options.AllowInsecureIssuer = options.AllowInsecureIssuer || shared.AllowInsecureIssuer;
            if (options.Mode is null && shared.TokenMode is { Length: > 0 } mode)
            {
                options.Mode = HybridTokenVerifierOptions.ParseMode(mode);
            }
        });
        builder.AddScheme<NineBearerOptions, NineBearerHandler>(scheme, "9in API", configure);
        services.AddAuthorization();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, ScopeAuthorizationHandler>());
        services.PostConfigure<AuthenticationOptions>(options =>
        {
            // A web app's cookie stays the default when both are registered.
            if (options.DefaultScheme is null && !options.SchemeMap.Values.Any(s => s.HandlerType == typeof(CookieAuthenticationHandler)))
            {
                options.DefaultScheme = scheme;
            }
        });
        return builder;
    }

    /// <summary>
    /// The signed-in user's access token (for calling your API), kept fresh by the session cookie: it is
    /// refreshed, with rotation, shortly before it expires. Null when nobody is signed in.
    /// </summary>
    public static Task<string?> GetNineAccessTokenAsync(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var web = context.RequestServices.GetService<IOptions<NineWebAppOptions>>()?.Value;
        return context.GetTokenAsync(web?.CookieScheme ?? NineDefaults.CookieScheme, "access_token");
    }
}

using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Nine.AspNetCore;

/// <summary>Preconfigures ASP.NET Core's OpenID Connect handler for 9in.</summary>
internal sealed class NineOpenIdConnectSetup(IServiceProvider services) :
    IConfigureNamedOptions<OpenIdConnectOptions>, IPostConfigureOptions<OpenIdConnectOptions>
{
    internal const string ExplicitItem = "nine:explicit";
    internal const string LoginHintItem = "nine:login_hint";
    internal const string LocaleItem = "nine:locale";
    internal const string ClaimsItem = "nine:id_token_claims";
    internal const string RevokedItem = "nine:revoked";
    internal const string IdTokenItem = "nine:id_token";

    private NineWebApp App => services.GetRequiredService<NineWebApp>();

    public void Configure(OpenIdConnectOptions options) { }

    public void Configure(string? name, OpenIdConnectOptions options)
    {
        var web = services.GetRequiredService<IOptions<NineWebAppOptions>>().Value;
        if (name != web.Scheme)
        {
            return;
        }
        var app = App;
        options.Authority = app.Issuer;
        options.MetadataAddress = app.Issuer + "/.well-known/openid-configuration";
        options.RequireHttpsMetadata = app.Issuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        options.ClientId = app.ClientId;
        options.ClientSecret = app.ClientSecret;
        options.ResponseType = OpenIdConnectResponseType.Code;
        // A plain redirect back (GET), so the correlation and nonce cookies can be SameSite=Lax.
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.UsePkce = true;
        options.SaveTokens = true;
        options.UseTokenLifetime = false;
        options.GetClaimsFromUserInfoEndpoint = false;
        options.MapInboundClaims = false;
        options.DisableTelemetry = true;
#if NET9_0_OR_GREATER
        options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
#endif
        options.Scope.Clear();
        foreach (var scope in web.Scopes)
        {
            options.Scope.Add(scope);
        }
        options.CallbackPath = app.CallbackPath;
        options.SignedOutCallbackPath = web.NormalizedBasePath + "/signed-out";
        options.SignInScheme = web.CookieScheme;
        options.SignOutScheme = web.CookieScheme;
        options.Backchannel = services.NineHttpClient();
        options.CorrelationCookie.Name = ".Nine.Correlation.";
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.NonceCookie.Name = ".Nine.Nonce.";
        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name",
            RoleClaimType = "roles",
            ValidIssuer = app.Issuer,
            ValidAudience = app.ClientId,
            // The ID token was verified by 9in's own verifier (every algorithm, EdDSA included) when the code
            // was exchanged; the handler's check only accepts that token.
            SignatureValidator = (token, _) => app.WasVerified(token)
                ? new JsonWebToken(token)
                : throw new SecurityTokenInvalidSignatureException("the ID token was not verified by 9in's verifier"),
        };
        web.ConfigureOpenIdConnect?.Invoke(options);
    }

    /// <summary>9in's events run first; events the app set itself still run after them.</summary>
    public void PostConfigure(string? name, OpenIdConnectOptions options)
    {
        var web = services.GetRequiredService<IOptions<NineWebAppOptions>>().Value;
        if (name != web.Scheme)
        {
            return;
        }
        var events = options.Events ??= new OpenIdConnectEvents();
        var redirect = events.OnRedirectToIdentityProvider;
        events.OnRedirectToIdentityProvider = async context =>
        {
            await RedirectToIdentityProvider(context).ConfigureAwait(false);
            if (!context.Handled)
            {
                await redirect(context).ConfigureAwait(false);
            }
        };
        var received = events.OnMessageReceived;
        events.OnMessageReceived = async context =>
        {
            await MessageReceived(context).ConfigureAwait(false);
            if (context.Result is null)
            {
                await received(context).ConfigureAwait(false);
            }
        };
        var code = events.OnAuthorizationCodeReceived;
        events.OnAuthorizationCodeReceived = async context =>
        {
            await AuthorizationCodeReceived(context).ConfigureAwait(false);
            if (context.Result is null)
            {
                await code(context).ConfigureAwait(false);
            }
        };
        var validated = events.OnTokenValidated;
        events.OnTokenValidated = async context =>
        {
            TokenValidated(context);
            await validated(context).ConfigureAwait(false);
        };
        var failure = events.OnRemoteFailure;
        events.OnRemoteFailure = async context =>
        {
            await failure(context).ConfigureAwait(false);
            if (context.Result is null)
            {
                await RemoteFailure(context).ConfigureAwait(false);
            }
        };
        var signOut = events.OnRedirectToIdentityProviderForSignOut;
        events.OnRedirectToIdentityProviderForSignOut = async context =>
        {
            await signOut(context).ConfigureAwait(false);
            if (!context.Handled)
            {
                await RedirectForSignOut(context).ConfigureAwait(false);
            }
        };
    }

    private Task RedirectToIdentityProvider(RedirectContext context)
    {
        var app = App;
        var items = context.Properties.Items;
        // A page the user wanted to see goes to the sign-in page; an API call or fetch gets a 401 instead.
        if (!items.ContainsKey(ExplicitItem) && !WantsPage(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.HandleResponse();
            return Task.CompletedTask;
        }
        var message = context.ProtocolMessage;
        if (!string.IsNullOrEmpty(app.RedirectUri))
        {
            message.RedirectUri = app.RedirectUri;
        }
        if (!string.IsNullOrEmpty(app.Audience))
        {
            message.SetParameter("audience", app.Audience);
        }
        if (items.TryGetValue(LoginHintItem, out var hint) && !string.IsNullOrEmpty(hint))
        {
            message.LoginHint = hint;
        }
        var locale = items.TryGetValue(LocaleItem, out var l) && !string.IsNullOrEmpty(l) ? l : app.Options.Locale;
        if (!string.IsNullOrEmpty(locale))
        {
            message.UiLocales = locale;
        }
        return Task.CompletedTask;
    }

    private async Task MessageReceived(MessageReceivedContext context)
    {
        var message = context.ProtocolMessage;
        // response_type=code: tokens never come in the redirect. Refusing them keeps the handler from
        // validating an ID token that 9in's verifier didn't check.
        if (!string.IsNullOrEmpty(message.IdToken) || !string.IsNullOrEmpty(message.AccessToken))
        {
            context.Fail(new OpenIdConnectProtocolException("invalid_request: tokens in the authorization response"));
            return;
        }
        if (!string.IsNullOrEmpty(message.Error))
        {
            return;
        }
        // RFC 9207: when the issuer says who it is, it must be ours; when it advertises the parameter, it must be there.
        var app = App;
        var iss = message.Iss;
        bool refused;
        if (iss is not null)
        {
            refused = !string.Equals(iss.TrimEnd('/'), app.Issuer, StringComparison.Ordinal);
        }
        else
        {
            var discovery = await app.Client.GetDiscoveryAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
            refused = discovery.AuthorizationResponseIssParameterSupported;
        }
        if (refused)
        {
            context.Fail(new OpenIdConnectProtocolException(iss is null ? "invalid_issuer: the callback has no iss parameter" : "invalid_issuer: unexpected issuer " + iss));
        }
    }

    private async Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
    {
        var app = App;
        var request = context.TokenEndpointRequest;
        if (request?.Code is not { Length: > 0 } code || request.RedirectUri is not { Length: > 0 } redirectUri
            || !request.Parameters.TryGetValue("code_verifier", out var verifier) || string.IsNullOrEmpty(verifier))
        {
            context.Fail(new OpenIdConnectProtocolException("invalid_request: incomplete code exchange"));
            return;
        }
        try
        {
            // The code exchange with client_secret_basic and the ID token check (signature with every
            // algorithm, issuer, audience, azp, expiry) by 9in's client. The handler skips its own token
            // response validation when the code is redeemed here, so the nonce and at_hash are checked here too.
            var tokens = await app.Client.ExchangeCodeAsync(code, redirectUri, verifier, null, context.HttpContext.RequestAborted).ConfigureAwait(false);
            if (tokens.IdToken is not null)
            {
                if (!ConsumeNonceCookie(context, tokens.Claims.GetString("nonce")))
                {
                    context.Fail(new OpenIdConnectProtocolException("invalid_nonce: the ID token's nonce is not this sign-in's"));
                    return;
                }
                if (!AtHash.Matches(tokens.IdToken, tokens.AccessToken, tokens.Claims.GetString("at_hash")))
                {
                    context.Fail(new OpenIdConnectProtocolException("invalid_token: at_hash does not match the access token"));
                    return;
                }
                app.MarkVerified(tokens.IdToken);
                context.HttpContext.Items[ClaimsItem] = tokens.Claims;
            }
            var response = new OpenIdConnectMessage
            {
                AccessToken = tokens.AccessToken,
                IdToken = tokens.IdToken,
                RefreshToken = tokens.RefreshToken,
                TokenType = tokens.TokenType,
                Scope = tokens.Scope,
            };
            if (tokens.ExpiresAt is { } expires)
            {
                response.ExpiresIn = Math.Max(0, (long)(expires - app.Time.GetUtcNow()).TotalSeconds).ToString(CultureInfo.InvariantCulture);
            }
            context.HandleCodeRedemption(response);
        }
        catch (NineException e)
        {
            context.Fail(new OpenIdConnectProtocolException($"{e.Error}: {e.ErrorDescription}", e));
        }
    }

    /// <summary>
    /// The handler's nonce check: the nonce must be one this browser was given at the start of a sign-in
    /// (a data-protected cookie name); that cookie is then deleted, so the nonce is single-use.
    /// </summary>
    private static bool ConsumeNonceCookie(AuthorizationCodeReceivedContext context, string? nonce)
    {
        var options = context.Options;
        if (string.IsNullOrEmpty(nonce) || options.NonceCookie.Name is not { Length: > 0 } prefix)
        {
            return false;
        }
        foreach (var name in context.Request.Cookies.Keys)
        {
            if (!name.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }
            string? protectedNonce;
            try
            {
                protectedNonce = options.StringDataFormat.Unprotect(name[prefix.Length..]);
            }
            catch (CryptographicException)
            {
                continue;
            }
            if (protectedNonce is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(protectedNonce), Encoding.UTF8.GetBytes(nonce)))
            {
                context.Response.Cookies.Delete(name, options.NonceCookie.Build(context.HttpContext, AppOf(context).Time.GetUtcNow()));
                return true;
            }
        }
        return false;
    }

    private static NineWebApp AppOf(AuthorizationCodeReceivedContext context) => context.HttpContext.RequestServices.GetRequiredService<NineWebApp>();

    private void TokenValidated(TokenValidatedContext context)
    {
        if (context.HttpContext.Items[ClaimsItem] is ClaimSet claims && claims.Count > 0)
        {
            context.Principal = App.Principal(claims);
        }
    }

    private async Task RemoteFailure(RemoteFailureContext context)
    {
        var app = App;
        var error = ErrorCode(context.Failure);
        services.GetRequiredService<ILoggerFactory>().CreateLogger("Nine.AspNetCore").LogInformation("9in sign-in failed: {Error}", error);
        context.HandleResponse();
        if (!string.IsNullOrEmpty(app.Options.ErrorPath))
        {
            context.Response.Redirect(app.Options.ErrorPath + (app.Options.ErrorPath.Contains('?', StringComparison.Ordinal) ? "&" : "?") + "error=" + Uri.EscapeDataString(error));
            return;
        }
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync($"Sign-in failed ({error}). Try again: {app.Options.NormalizedBasePath}/login\n", context.HttpContext.RequestAborted).ConfigureAwait(false);
    }

    private async Task RedirectForSignOut(RedirectContext context)
    {
        var app = App;
        var http = context.HttpContext;
        if (app.Options.RevokeOnSignOut && !http.Items.ContainsKey(RevokedItem))
        {
            var refresh = await http.GetTokenAsync(app.Options.CookieScheme, "refresh_token").ConfigureAwait(false);
            await RevokeQuietly(app, http, refresh).ConfigureAwait(false);
        }
        var message = context.ProtocolMessage;
        message.ClientId = app.ClientId;
        if (string.IsNullOrEmpty(message.IdTokenHint) && http.Items[IdTokenItem] is string idToken)
        {
            message.IdTokenHint = idToken;
        }
        var returnTo = ReturnTo.Sanitize(context.Properties.RedirectUri) ?? app.Options.AfterSignOutPath;
        message.PostLogoutRedirectUri = Absolute(app, context.Request, returnTo);
        message.State = null;
        if (string.IsNullOrEmpty(message.IssuerAddress))
        {
            message.IssuerAddress = (await app.Client.GetDiscoveryAsync(http.RequestAborted).ConfigureAwait(false)).EndSessionEndpoint ?? app.Issuer + "/oauth/logout";
        }
        context.Response.Redirect(message.CreateLogoutRequestUrl());
        context.HandleResponse();
    }

    internal static async Task RevokeQuietly(NineWebApp app, HttpContext http, string? refreshToken)
    {
        http.Items[RevokedItem] = true;
        if (string.IsNullOrEmpty(refreshToken))
        {
            return;
        }
        try
        {
            await app.Client.RevokeAsync(refreshToken, "refresh_token", http.RequestAborted).ConfigureAwait(false);
        }
        catch (NineException e)
        {
            http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Nine.AspNetCore")
                .LogWarning("Revoking the refresh token at sign-out failed: {Error}", e.Error);
        }
    }

    /// <summary>An absolute URL on this app: from the configured redirect URI's origin, else from the request.</summary>
    internal static string Absolute(NineWebApp app, HttpRequest request, string path)
    {
        if (!string.IsNullOrEmpty(app.RedirectUri) && Uri.TryCreate(app.RedirectUri, UriKind.Absolute, out var configured))
        {
            return configured.GetLeftPart(UriPartial.Authority) + path;
        }
        return request.Scheme + "://" + request.Host.ToUriComponent() + request.PathBase.ToUriComponent() + path;
    }

    private static bool WantsPage(HttpRequest request)
    {
        var headers = request.Headers;
        if (string.Equals(headers["Sec-Fetch-Mode"], "navigate", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (string.Equals(headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var accept = headers.Accept.ToString();
        return accept.Length == 0 || accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);
    }

    private static string ErrorCode(Exception? failure)
    {
        if (failure is OpenIdConnectProtocolException protocol)
        {
            if (protocol.Data["error"] is string error && error.Length > 0)
            {
                return error;
            }
            var message = protocol.Message;
            var colon = message.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0 && !message[..colon].Contains(' ', StringComparison.Ordinal))
            {
                return message[..colon];
            }
            if (message.Contains("'access_denied'", StringComparison.Ordinal))
            {
                return "access_denied";
            }
        }
        if (failure?.Message.Contains("Correlation failed", StringComparison.OrdinalIgnoreCase) == true || failure?.Message.Contains("state", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "invalid_state";
        }
        return "sign_in_failed";
    }
}

/// <summary>OIDC <c>at_hash</c> for every 9in algorithm (SHA-512 for EdDSA, as 9in computes it).</summary>
internal static class AtHash
{
    /// <summary>True when there is no <c>at_hash</c> (optional in the code flow) or it matches the access token.</summary>
    public static bool Matches(string idToken, string accessToken, string? atHash)
    {
        if (string.IsNullOrEmpty(atHash))
        {
            return true;
        }
        var alg = new JsonWebToken(idToken).Alg;
        var input = Encoding.ASCII.GetBytes(accessToken);
        byte[] hash;
        switch (alg)
        {
            case "RS256" or "PS256" or "ES256" or "HS256":
                hash = SHA256.HashData(input);
                break;
            case "RS384" or "PS384" or "ES384" or "HS384":
                hash = SHA384.HashData(input);
                break;
            case "RS512" or "PS512" or "HS512" or "EdDSA":
                hash = SHA512.HashData(input);
                break;
            default:
                return false;
        }
        var expected = Base64UrlEncoder.Encode(hash, 0, hash.Length / 2);
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(atHash));
    }
}

/// <summary>The session cookie: SameSite=Lax, HttpOnly, and token refresh with rotation before the access token expires.</summary>
internal sealed class NineCookieSetup(IServiceProvider services) :
    IConfigureNamedOptions<CookieAuthenticationOptions>, IPostConfigureOptions<CookieAuthenticationOptions>
{
    public void Configure(CookieAuthenticationOptions options) { }

    public void Configure(string? name, CookieAuthenticationOptions options)
    {
        var web = services.GetRequiredService<IOptions<NineWebAppOptions>>().Value;
        if (name != web.CookieScheme)
        {
            return;
        }
        options.Cookie.Name = "nine_session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = web.SessionLifetime;
        options.LoginPath = web.NormalizedBasePath + "/login";
        options.LogoutPath = web.NormalizedBasePath + "/logout";
        options.ReturnUrlParameter = "return_to";
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
        web.ConfigureCookie?.Invoke(options);
    }

    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        var web = services.GetRequiredService<IOptions<NineWebAppOptions>>().Value;
        if (name != web.CookieScheme)
        {
            return;
        }
        var events = options.Events ??= new CookieAuthenticationEvents();
        var validate = events.OnValidatePrincipal;
        events.OnValidatePrincipal = async context =>
        {
            await RefreshIfNeeded(context).ConfigureAwait(false);
            if (context.Principal is not null)
            {
                await validate(context).ConfigureAwait(false);
            }
        };
    }

    /// <summary>
    /// Refreshes the access token a little before it expires and saves the rotated refresh token in the
    /// session cookie. A revoked refresh token (the user signed out everywhere, an admin ended the session)
    /// signs the user out here too.
    /// </summary>
    private async Task RefreshIfNeeded(CookieValidatePrincipalContext context)
    {
        var app = services.GetRequiredService<NineWebApp>();
        var properties = context.Properties;
        if (!DateTimeOffset.TryParse(properties.GetTokenValue("expires_at"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expiresAt)
            || expiresAt - app.Options.RefreshLeeway > app.Time.GetUtcNow())
        {
            return;
        }
        if (properties.GetTokenValue("refresh_token") is not { Length: > 0 } refreshToken)
        {
            return;
        }
        TokenSet tokens;
        try
        {
            tokens = await app.RefreshOnceAsync(refreshToken).WaitAsync(context.HttpContext.RequestAborted).ConfigureAwait(false);
        }
        catch (NineException e) when (e.Error == "invalid_grant" || e is InvalidTokenException)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(app.Options.CookieScheme).ConfigureAwait(false);
            return;
        }
        catch (NineException e)
        {
            // 9in unreachable: keep the session; the next request tries again.
            services.GetRequiredService<ILoggerFactory>().CreateLogger("Nine.AspNetCore").LogWarning("Token refresh failed: {Error} {Description}", e.Error, e.ErrorDescription);
            return;
        }
        var subject = context.Principal?.FindFirst("sub")?.Value;
        if (tokens.Claims.Subject is { } fresh && subject is not null && fresh != subject)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(app.Options.CookieScheme).ConfigureAwait(false);
            return;
        }
        var saved = properties.GetTokens().ToDictionary(t => t.Name, t => t.Value, StringComparer.Ordinal);
        saved["access_token"] = tokens.AccessToken;
        saved["token_type"] = tokens.TokenType;
        if (tokens.RefreshToken is not null)
        {
            saved["refresh_token"] = tokens.RefreshToken;
        }
        if (tokens.IdToken is not null)
        {
            saved["id_token"] = tokens.IdToken;
        }
        if (tokens.ExpiresAt is { } expires)
        {
            saved["expires_at"] = expires.ToString("o", CultureInfo.InvariantCulture);
        }
        properties.StoreTokens(saved.Select(t => new AuthenticationToken { Name = t.Key, Value = t.Value }));
        if (tokens.IdToken is not null && tokens.Claims.Count > 0)
        {
            // Keep the profile current with the new ID token (same user only).
            context.ReplacePrincipal(app.Principal(tokens.Claims));
        }
        context.ShouldRenew = true;
    }
}

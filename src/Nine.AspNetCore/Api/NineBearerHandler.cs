using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Nine.AspNetCore;

/// <summary>
/// Authenticates <c>Authorization: Bearer</c> requests with 9in's verifier: every algorithm of the key library,
/// <c>typ: at+jwt</c>, issuer, audience and expiry, and in hybrid mode revocations. Answers RFC 6750 challenges:
/// 401 <c>invalid_token</c>, 403 <c>insufficient_scope</c>, and 503 when 9in can't be reached to check a token.
/// </summary>
public sealed class NineBearerHandler : AuthenticationHandler<NineBearerOptions>
{
    internal const string ClaimsItem = "Nine.Claims";
    internal const string RequiredScopeItem = "Nine.RequiredScope";
    private const string FailureItem = "Nine.BearerFailure";

    private readonly NineApiVerifiers _verifiers;

    /// <summary>Created by ASP.NET Core.</summary>
    public NineBearerHandler(IOptionsMonitor<NineBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, IServiceProvider services)
        : base(options, logger, encoder)
    {
        _verifiers = (NineApiVerifiers)(services.GetService(typeof(NineApiVerifiers)) ?? throw new InvalidOperationException("call AddNineApi()"));
    }

    /// <inheritdoc/>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? header = Request.Headers.Authorization;
        if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }
        var token = header[7..].Trim();
        if (token.Length == 0)
        {
            return AuthenticateResult.NoResult();
        }
        ClaimSet claims;
        try
        {
            claims = await _verifiers.Get(Scheme.Name, Options).VerifyAsync(token, null, Context.RequestAborted).ConfigureAwait(false);
        }
        catch (InvalidTokenException e)
        {
            Context.Items[FailureItem] = e;
            return AuthenticateResult.Fail(e);
        }
        catch (NineException e) when (e.Error != "invalid_options")
        {
            // 9in couldn't be asked (JWKS or introspection): not the client's fault.
            Logger.LogWarning("9in token check failed: {Error} {Description}", e.Error, e.ErrorDescription);
            Context.Items[FailureItem] = e;
            return AuthenticateResult.Fail(e);
        }
        Context.Items[ClaimsItem] = claims;
        var identity = new ClaimsIdentity(NineClaims.From(claims, Options.ClaimsIssuer ?? claims.Issuer), Scheme.Name, "sub", "roles");
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    /// <inheritdoc/>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var failure = Context.Items[FailureItem] as NineException;
        if (failure is not null and not InvalidTokenException)
        {
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            Response.Headers.RetryAfter = "5";
            return Task.CompletedTask;
        }
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = failure is null
            ? "Bearer"
            : $"Bearer error=\"invalid_token\", error_description=\"{Quote(failure.ErrorDescription ?? "invalid token")}\"";
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        var scope = Context.Items[RequiredScopeItem] as string;
        Response.Headers.WWWAuthenticate = scope is null
            ? "Bearer error=\"insufficient_scope\""
            : $"Bearer error=\"insufficient_scope\", scope=\"{Quote(scope)}\"";
        return Task.CompletedTask;
    }

    private static string Quote(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "'", StringComparison.Ordinal);
}

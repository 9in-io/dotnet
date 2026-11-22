using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Nine.AspNetCore;

/// <summary>The access token must have every one of <see cref="Scopes"/> (its <c>scope</c> claim).</summary>
public sealed class ScopeRequirement : IAuthorizationRequirement
{
    /// <summary>Creates the requirement.</summary>
    public ScopeRequirement(IEnumerable<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        Scopes = scopes.SelectMany(s => s.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Distinct(StringComparer.Ordinal).ToArray();
        if (Scopes.Count == 0)
        {
            throw new ArgumentException("at least one scope", nameof(scopes));
        }
    }

    /// <summary>The scopes, all required.</summary>
    public IReadOnlyList<string> Scopes { get; }

    /// <inheritdoc/>
    public override string ToString() => "Scope: " + string.Join(' ', Scopes);
}

/// <summary>Checks <see cref="ScopeRequirement"/>s; a failure is answered 403 <c>insufficient_scope</c> with the required scope.</summary>
public sealed class ScopeAuthorizationHandler : AuthorizationHandler<ScopeRequirement>
{
    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);
        var granted = context.User.GetScopes();
        if (requirement.Scopes.All(s => granted.Contains(s, StringComparer.Ordinal)))
        {
            context.Succeed(requirement);
        }
        else if (context.Resource is HttpContext http)
        {
            http.Items[NineBearerHandler.RequiredScopeItem] = string.Join(' ', requirement.Scopes);
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Requires a 9in access token (the <see cref="NineDefaults.BearerScheme"/> scheme) with every listed scope:
/// <c>[RequireScope("orders:read")]</c> on a controller or action, or <c>.RequireScope("orders:read")</c> on a minimal API endpoint.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireScopeAttribute : AuthorizeAttribute, IAuthorizationRequirementData
{
    /// <summary>Requires these scopes (each may also be space-separated).</summary>
    public RequireScopeAttribute(params string[] scopes)
    {
        Requirement = new ScopeRequirement(scopes);
        AuthenticationSchemes = NineDefaults.BearerScheme;
    }

    /// <summary>The requirement this attribute adds.</summary>
    public ScopeRequirement Requirement { get; }

    /// <inheritdoc/>
    public IEnumerable<IAuthorizationRequirement> GetRequirements()
    {
        yield return Requirement;
    }
}

/// <summary>Scope checks for policies and endpoints.</summary>
public static class NineAuthorizationExtensions
{
    /// <summary>Requires every listed scope in the access token: <c>options.AddPolicy("orders", p => p.RequireScope("orders:read"))</c>.</summary>
    public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder builder, params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement(scopes));
    }

    /// <summary>Requires a 9in access token with every listed scope on this endpoint (or group).</summary>
    public static TBuilder RequireScope<TBuilder>(this TBuilder builder, params string[] scopes)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        var attribute = new RequireScopeAttribute(scopes);
        builder.Add(endpoint => endpoint.Metadata.Add(attribute));
        return builder;
    }

    /// <summary>Requires a valid 9in access token (the bearer scheme) on this endpoint, without a scope check.</summary>
    public static TBuilder RequireNineToken<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = NineDefaults.BearerScheme });
    }
}

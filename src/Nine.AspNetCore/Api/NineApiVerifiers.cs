using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;

namespace Nine.AspNetCore;

/// <summary>One verifier per bearer scheme for the life of the app (their caches must outlive requests), so webhooks can evict them all.</summary>
internal sealed class NineApiVerifiers(IServiceProvider services)
{
    private readonly ConcurrentDictionary<string, Lazy<IAccessTokenVerifier>> _verifiers = new(StringComparer.Ordinal);

    public IAccessTokenVerifier Get(string scheme, NineBearerOptions options) =>
        _verifiers.GetOrAdd(scheme, _ => new Lazy<IAccessTokenVerifier>(() => options.Verifier ?? Create(options))).Value;

    public IEnumerable<HybridTokenVerifier> Hybrid =>
        _verifiers.Values.Where(v => v.IsValueCreated).Select(v => v.Value).OfType<HybridTokenVerifier>();

    private HybridTokenVerifier Create(NineBearerOptions options)
    {
        var verifier = new HybridTokenVerifierOptions
        {
            Issuer = options.Issuer ?? throw new NineException("invalid_options", "the 9in issuer is missing: set Nine:Issuer in configuration or NINE_ISSUER"),
            Audience = options.Audience,
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            Secret = options.Secret,
            Mode = options.Mode,
            CacheTtl = options.CacheTtl,
            Leeway = options.Leeway,
            AllowInsecureIssuer = options.AllowInsecureIssuer,
            Cache = services.GetRequiredService<INineCache>(),
            TimeProvider = services.GetRequiredService<TimeProvider>(),
        };
        return new HybridTokenVerifier(verifier, services.NineHttpClient());
    }
}

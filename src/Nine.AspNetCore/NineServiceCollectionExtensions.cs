using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Nine.AspNetCore;

/// <summary>Registers 9in services.</summary>
public static class NineServiceCollectionExtensions
{
    /// <summary>
    /// Registers the 9in clients for injection, configured from <see cref="NineOptions"/>: <see cref="AuthClient"/>,
    /// <see cref="ManagementClient"/>, <see cref="HybridTokenVerifier"/>, <see cref="INineCache"/> (your
    /// <c>IDistributedCache</c> when there is one) and <see cref="EventDeduplicator"/>. Each is created on first
    /// use, so a missing setting fails when that client is needed, not at startup.
    /// </summary>
    public static IServiceCollection AddNine(this IServiceCollection services, Action<NineOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddNineCore();
        if (configure is not null)
        {
            services.Configure(configure);
        }
        services.TryAddSingleton(sp =>
        {
            var nine = sp.GetRequiredService<IOptions<NineOptions>>().Value;
            return new AuthClient(new AuthClientOptions
            {
                Issuer = nine.RequireIssuer(),
                ClientId = nine.RequireClientId(),
                ClientSecret = nine.ClientSecret,
                RedirectUri = nine.RedirectUri,
                Audience = nine.Audience,
                AllowInsecureIssuer = nine.AllowInsecureIssuer,
                StateCache = sp.GetRequiredService<INineCache>(),
                TimeProvider = sp.GetRequiredService<TimeProvider>(),
            }, sp.NineHttpClient());
        });
        services.TryAddSingleton(sp =>
        {
            var nine = sp.GetRequiredService<IOptions<NineOptions>>().Value;
            return new ManagementClient(new ManagementClientOptions
            {
                Issuer = nine.RequireIssuer(),
                ClientId = nine.RequireClientId(),
                ClientSecret = nine.ClientSecret ?? "",
                AllowInsecureIssuer = nine.AllowInsecureIssuer,
                TimeProvider = sp.GetRequiredService<TimeProvider>(),
            }, sp.NineHttpClient());
        });
        services.TryAddSingleton(sp =>
        {
            var nine = sp.GetRequiredService<IOptions<NineOptions>>().Value;
            var options = new HybridTokenVerifierOptions
            {
                Issuer = nine.RequireIssuer(),
                Audience = nine.ApiAudience,
                ClientId = nine.ClientId,
                ClientSecret = nine.ClientSecret,
                Secret = nine.ApiSecret,
                Mode = nine.TokenMode is { Length: > 0 } mode ? HybridTokenVerifierOptions.ParseMode(mode) : null,
                AllowInsecureIssuer = nine.AllowInsecureIssuer,
                Cache = sp.GetRequiredService<INineCache>(),
                TimeProvider = sp.GetRequiredService<TimeProvider>(),
            };
            return new HybridTokenVerifier(options, sp.NineHttpClient());
        });
        services.TryAddSingleton(sp => new EventDeduplicator(sp.GetRequiredService<INineCache>()));
        return services;
    }

    /// <summary>
    /// Adds a client-credentials token to every request of this <see cref="HttpClient"/> (machine-to-machine
    /// calls), from the registered <see cref="AuthClient"/> (see <see cref="AddNine"/>); the token is cached and shared.
    /// </summary>
    public static IHttpClientBuilder AddNineClientCredentials(this IHttpClientBuilder builder, string? audience = null, string? scope = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddNine();
        return builder.AddHttpMessageHandler(sp => new ClientCredentialsHandler(sp.GetRequiredService<AuthClient>(), audience, scope));
    }

    /// <summary>Everything the 9in integrations share: options, the HTTP client, the cache, the clock.</summary>
    internal static IServiceCollection AddNineCore(this IServiceCollection services)
    {
        // Once: a second AddNine*() must not undo what the app configured in between (e.g. the HTTP handler).
        if (services.Any(d => d.ServiceType == typeof(NineCoreMarker)))
        {
            return services;
        }
        services.AddSingleton<NineCoreMarker>();
        services.AddOptions();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<NineOptions>, NineOptionsSetup>());
        services.AddHttpClient(NineDefaults.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                ConnectTimeout = TimeSpan.FromSeconds(10),
                AutomaticDecompression = System.Net.DecompressionMethods.All,
            })
            .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(30));
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<INineCache>(sp => sp.GetService<IDistributedCache>() is { } distributed
            ? new DistributedNineCache(distributed)
            : new NineMemoryCache(timeProvider: sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<NineApiVerifiers>();
        return services;
    }

    private sealed class NineCoreMarker;

    internal static HttpClient NineHttpClient(this IServiceProvider services) =>
        services.GetRequiredService<IHttpClientFactory>().CreateClient(NineDefaults.HttpClientName);
}

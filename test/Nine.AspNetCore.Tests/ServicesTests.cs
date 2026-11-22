using System.Net;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nine.Tests.Support;

namespace Nine.AspNetCore.Tests;

public class ServicesTests
{
    private static ServiceProvider Build(Dictionary<string, string?> settings, Action<IServiceCollection>? more = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        services.AddLogging();
        services.AddNine();
        more?.Invoke(services);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void ReadsTheNineSectionThenTheEnvironment()
    {
        var name = "NINE_WEBHOOK_SECRET";
        var saved = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, "from-env");
        try
        {
            using var provider = Build(new() { ["Nine:Issuer"] = "https://acme.9in.io", ["Nine:Audience"] = "https://api.acme.test", ["Nine:AllowInsecureIssuer"] = "true" });
            var options = provider.GetRequiredService<IOptions<NineOptions>>().Value;
            Assert.Equal("https://acme.9in.io", options.Issuer);
            Assert.Equal("https://api.acme.test", options.ApiAudience); // defaults to Audience
            Assert.Equal("from-env", options.WebhookSecret);
            Assert.True(options.AllowInsecureIssuer);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, saved);
        }
    }

    [Fact]
    public async Task RegistersTheClients()
    {
        var oidc = new FakeOidc();
        using var provider = Build(new() { ["Nine:Issuer"] = oidc.Issuer, ["Nine:ClientId"] = oidc.ClientId, ["Nine:ClientSecret"] = oidc.ClientSecret, ["Nine:TokenMode"] = "introspect" },
            services => services.AddHttpClient(NineDefaults.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => oidc.Server));
        Assert.Same(provider.GetRequiredService<AuthClient>(), provider.GetRequiredService<AuthClient>());
        Assert.Equal(oidc.Issuer, provider.GetRequiredService<ManagementClient>().Issuer);
        Assert.Equal(VerificationMode.Introspect, provider.GetRequiredService<HybridTokenVerifier>().Mode);
        Assert.IsType<NineMemoryCache>(provider.GetRequiredService<INineCache>());
        Assert.NotNull(provider.GetRequiredService<EventDeduplicator>());
        var tokens = await provider.GetRequiredService<AuthClient>().ClientCredentialsAsync("https://api.acme.test");
        Assert.StartsWith("ey", tokens.AccessToken);
    }

    [Fact]
    public void AMissingIssuerFailsWhenTheClientIsNeeded()
    {
        using var provider = Build([]);
        var e = Assert.Throws<NineException>(() => provider.GetRequiredService<AuthClient>());
        Assert.Contains("Nine:Issuer", e.Message);
    }

    [Fact]
    public void UsesTheDistributedCacheWhenThereIsOne()
    {
        using var provider = Build([], services => services.AddDistributedMemoryCache());
        Assert.IsType<DistributedNineCache>(provider.GetRequiredService<INineCache>());
    }

    [Fact]
    public async Task TheDistributedCacheAdapter()
    {
        var cache = new DistributedNineCache(new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));
        Assert.Null(await cache.GetAsync("k"));
        Assert.True(await cache.AddAsync("k", "1", TimeSpan.FromMinutes(1)));
        Assert.False(await cache.AddAsync("k", "2", TimeSpan.FromMinutes(1)));
        Assert.Equal("1", await cache.GetAsync("k"));
        await cache.SetAsync("k", "3", TimeSpan.FromMinutes(1));
        Assert.Equal("3", await cache.GetAsync("k"));
        await cache.RemoveAsync("k");
        Assert.Null(await cache.GetAsync("k"));
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(i => Task.Run(async () => await cache.AddAsync("race", i.ToString(), TimeSpan.FromMinutes(1)))));
        Assert.Single(results, r => r);
        await cache.SetAsync("short", "x", TimeSpan.FromMilliseconds(50));
        await Task.Delay(200);
        Assert.Null(await cache.GetAsync("short"));
    }

    [Fact]
    public async Task ClientCredentialsOnAnHttpClient()
    {
        var oidc = new FakeOidc();
        var api = new FakeIssuer("https://api.acme.test");
        api.On("GET", "/orders", request => FakeIssuer.Json(new System.Text.Json.Nodes.JsonObject { ["auth"] = request.Authorization }));
        using var provider = Build(new() { ["Nine:Issuer"] = oidc.Issuer, ["Nine:ClientId"] = oidc.ClientId, ["Nine:ClientSecret"] = oidc.ClientSecret }, services =>
        {
            services.AddHttpClient(NineDefaults.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => oidc.Server);
            services.AddHttpClient("orders", c => c.BaseAddress = new Uri("https://api.acme.test")).AddNineClientCredentials("https://api.acme.test", "orders:read")
                .ConfigurePrimaryHttpMessageHandler(() => api);
        });
        var http = provider.GetRequiredService<IHttpClientFactory>().CreateClient("orders");
        var first = await http.GetStringAsync("/orders");
        var second = await provider.GetRequiredService<IHttpClientFactory>().CreateClient("orders").GetStringAsync("/orders");
        Assert.Contains("Bearer ey", first);
        Assert.Equal(first, second);
        Assert.Equal(1, oidc.Server.Count("POST", "/oauth/token"));
        Assert.Equal("orders:read", oidc.Server.Last("/oauth/token").Form["scope"]);
    }
}

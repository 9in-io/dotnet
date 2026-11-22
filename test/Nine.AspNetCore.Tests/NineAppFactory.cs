using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Nine.Tests.Support;

namespace Nine.AspNetCore.Tests;

/// <summary>The test app wired to a <see cref="FakeOidc"/> instead of 9in.</summary>
public sealed class NineAppFactory : WebApplicationFactory<Program>
{
    public const string ApiAudience = "https://api.acme.test";
    public const string WebhookSecret = "whsec_test";
    public const string AdapterSecret = "adapter_secret_test";

    private readonly Dictionary<string, string?> _settings;

    public NineAppFactory(FakeOidc oidc, Dictionary<string, string?>? settings = null)
    {
        Oidc = oidc;
        _settings = new Dictionary<string, string?>
        {
            ["Nine:Issuer"] = oidc.Issuer,
            ["Nine:ClientId"] = oidc.ClientId,
            ["Nine:ClientSecret"] = oidc.ClientSecret,
            ["Nine:Audience"] = ApiAudience,
            ["Nine:WebhookSecret"] = "whsec_old," + WebhookSecret,
            ["Nine:AdapterSecret"] = AdapterSecret,
        };
        foreach (var (key, value) in settings ?? [])
        {
            _settings[key] = value;
        }
    }

    public FakeOidc Oidc { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        foreach (var (key, value) in _settings)
        {
            builder.UseSetting(key, value);
        }
        builder.ConfigureServices(services =>
            services.AddHttpClient(NineDefaults.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => new NonDisposing(Oidc.Server)));
    }

    public HttpClient Browser() => CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = true,
        BaseAddress = new Uri("https://localhost"),
    });

    /// <summary>Signs in through /nine/login like a browser, with the fake issuer playing the hosted page.</summary>
    public async Task<HttpResponseMessage> SignInAsync(HttpClient browser, string login = "/nine/login?return_to=/me", string sub = "usr_jane")
    {
        var start = await browser.GetAsync(login);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var callback = new Uri(Oidc.Authorize(start.Headers.Location!.ToString(), sub));
        return await browser.GetAsync(callback.PathAndQuery);
    }

    /// <summary>The app's IHttpClientFactory disposes handlers; the fake lives as long as the test.</summary>
    private sealed class NonDisposing(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override void Dispose(bool disposing)
        {
            // keep the shared fake alive
        }
    }
}

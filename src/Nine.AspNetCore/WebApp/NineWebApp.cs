using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Nine.AspNetCore;

/// <summary>The effective settings of the web app sign-in and the core client behind it (one per app).</summary>
internal sealed class NineWebApp
{
    private readonly Lazy<AuthClient> _client;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _verifiedIdTokens = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Refresh> _refreshes = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    private sealed class Refresh(Func<Task<TokenSet>> start)
    {
        // Lazy: GetOrAdd may build several entries under contention, but only the stored one ever starts.
        private readonly Lazy<Task<TokenSet>> _task = new(start, LazyThreadSafetyMode.ExecutionAndPublication);

        public Task<TokenSet> Task => _task.Value;
        public DateTimeOffset? DoneAt { get; set; }
    }

    public NineWebApp(IOptions<NineWebAppOptions> web, IOptions<NineOptions> nine, IServiceProvider services)
    {
        Options = web.Value;
        var shared = nine.Value;
        AllowInsecureIssuer = Options.AllowInsecureIssuer ?? shared.AllowInsecureIssuer;
        Issuer = Nine.Issuer.Normalize(Options.Issuer ?? shared.RequireIssuer(), AllowInsecureIssuer);
        ClientId = Options.ClientId ?? shared.RequireClientId();
        ClientSecret = string.IsNullOrEmpty(Options.ClientSecret ?? shared.ClientSecret) ? null : Options.ClientSecret ?? shared.ClientSecret;
        Audience = Options.Audience ?? shared.Audience;
        RedirectUri = Options.RedirectUri ?? shared.RedirectUri;
        _time = services.GetRequiredService<TimeProvider>();
        _client = new Lazy<AuthClient>(() => new AuthClient(new AuthClientOptions
        {
            Issuer = Issuer,
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            RedirectUri = RedirectUri,
            Audience = Audience,
            AllowInsecureIssuer = AllowInsecureIssuer,
            StateCache = services.GetRequiredService<INineCache>(),
            TimeProvider = _time,
        }, services.NineHttpClient()));
    }

    public NineWebAppOptions Options { get; }
    public string Issuer { get; }
    public string ClientId { get; }
    public string? ClientSecret { get; }
    public string? Audience { get; }
    public string? RedirectUri { get; }
    public bool AllowInsecureIssuer { get; }
    public AuthClient Client => _client.Value;
    public TimeProvider Time => _time;

    /// <summary>Remembers an ID token verified by 9in's verifier, for the handler's signature check that follows.</summary>
    public void MarkVerified(string idToken)
    {
        var now = _time.GetUtcNow();
        foreach (var (key, until) in _verifiedIdTokens)
        {
            if (until < now)
            {
                _verifiedIdTokens.TryRemove(key, out _);
            }
        }
        _verifiedIdTokens[Hash(idToken)] = now.AddMinutes(2);
    }

    /// <summary>Whether 9in's verifier checked this ID token in this sign-in (single use).</summary>
    public bool WasVerified(string idToken) =>
        _verifiedIdTokens.TryRemove(Hash(idToken), out var until) && until >= _time.GetUtcNow();

    /// <summary>
    /// Refreshes once per refresh token: concurrent requests share the call, and requests that still carry the
    /// old refresh token within 30 seconds get the same answer (9in rotates refresh tokens and treats a
    /// second use after its grace window as theft).
    /// </summary>
    public Task<TokenSet> RefreshOnceAsync(string refreshToken)
    {
        var now = _time.GetUtcNow();
        foreach (var (stale, entry) in _refreshes)
        {
            if (entry.DoneAt is { } done && now - done > TimeSpan.FromSeconds(30))
            {
                _refreshes.TryRemove(stale, out _);
            }
        }
        var key = Hash(refreshToken);
        var refresh = _refreshes.GetOrAdd(key, _ => new Refresh(() => Client.RefreshAsync(refreshToken, CancellationToken.None)));
        _ = refresh.Task.ContinueWith(
            t =>
            {
                if (t.IsCompletedSuccessfully)
                {
                    refresh.DoneAt ??= _time.GetUtcNow();
                }
                else
                {
                    _refreshes.TryRemove(new KeyValuePair<string, Refresh>(key, refresh));
                }
            },
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return refresh.Task;
    }

    /// <summary>The signed-in user from verified ID token claims.</summary>
    public ClaimsPrincipal Principal(ClaimSet claims) =>
        new(new ClaimsIdentity(NineClaims.User(claims, Issuer), Options.Scheme, "name", "roles"));

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

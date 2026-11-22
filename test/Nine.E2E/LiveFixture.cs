[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Nine.E2E;

/// <summary>
/// Shared state of a live run: one sandbox sign-in through the hosted page, one managed user on production,
/// and the clean-up at the end (this run's sandbox users and the managed user are deleted through the
/// Management API).
/// </summary>
public sealed class LiveFixture : IAsyncLifetime
{
    private Task<(AuthClient Client, TokenSet Tokens)>? _sandbox;
    private Task<ManagedUser>? _managed;

    public string SandboxEmail { get; } = $"dotnet-{Live.Run}@sandbox.e2e.test";
    public string ManagedEmail { get; } = $"managed-dotnet-{Live.Run}@e2e.9in.test";
    public string ManagedPassword { get; } = $"Dn-{Live.Run}-Password!";

    public static AuthClient Sandbox(Action<AuthClientOptions>? configure = null)
    {
        var options = new AuthClientOptions
        {
            Issuer = Live.Env("SANDBOX_ISSUER"),
            ClientId = Live.Env("SPA_CLIENT_ID"),
            RedirectUri = Live.Env("SPA_REDIRECT_URI"),
            Audience = Live.Env("API_AUDIENCE"),
            Scopes = ["openid", "profile", "email", "offline_access", "read:things"],
        };
        configure?.Invoke(options);
        return new AuthClient(options);
    }

    public static AuthClient Server(Action<AuthClientOptions>? configure = null)
    {
        var options = new AuthClientOptions
        {
            Issuer = Live.Env("ISSUER"),
            ClientId = Live.Env("SERVER_CLIENT_ID"),
            ClientSecret = Live.Env("SERVER_CLIENT_SECRET"),
            RedirectUri = Live.Env("SERVER_REDIRECT_URI"),
        };
        configure?.Invoke(options);
        return new AuthClient(options);
    }

    public static ManagementClient Management(string issuerSetting = "ISSUER") => new(new ManagementClientOptions
    {
        Issuer = Live.Env(issuerSetting),
        ClientId = Live.Env("SERVER_CLIENT_ID"),
        ClientSecret = Live.Env("SERVER_CLIENT_SECRET"),
    });

    /// <summary>The sandbox user signs in (any password works there; sign-in creates the user).</summary>
    public Task<(AuthClient Client, TokenSet Tokens)> SandboxSession() => _sandbox ??= SignInToSandbox();

    private async Task<(AuthClient, TokenSet)> SignInToSandbox()
    {
        var client = Sandbox();
        var login = await client.CreateLoginAsync(new LoginOptions { ReturnTo = "/dotnet-after" });
        using var browser = new Browser();
        var result = await browser.SignIn(login.Url, Live.Env("SPA_REDIRECT_URI"), SandboxEmail, "any-password");
        Assert.True(result.Callback is not null, result.PageText[..Math.Min(300, result.PageText.Length)]);
        return (client, await client.HandleCallbackAsync(result.Callback!, login.Pending));
    }

    /// <summary>A user with a password on production, created through the Management API.</summary>
    public Task<ManagedUser> ManagedUser() => _managed ??= Management().CreateUserAsync(new NewUser
    {
        Email = ManagedEmail,
        Password = ManagedPassword,
        Name = "Managed Dotnet",
        EmailVerified = true,
        Metadata = new System.Text.Json.Nodes.JsonObject { ["run"] = Live.Run },
    });

    /// <summary>Signs the managed user in on production with the confidential "E2E Server" client.</summary>
    public async Task<TokenSet> ServerSignIn(AuthClient client, LoginOptions? login = null, Browser? browser = null)
    {
        await ManagedUser();
        var started = await client.CreateLoginAsync(login ?? new LoginOptions { ReturnTo = "/account" });
        var own = browser is null;
        browser ??= new Browser();
        try
        {
            var result = await browser.SignIn(started.Url, Live.Env("SERVER_REDIRECT_URI"), ManagedEmail, ManagedPassword);
            Assert.True(result.Callback is not null, result.PageText[..Math.Min(300, result.PageText.Length)]);
            return await client.HandleCallbackAsync(result.Callback!, started.Pending);
        }
        finally
        {
            if (own)
            {
                browser.Dispose();
            }
        }
    }

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public async ValueTask DisposeAsync()
    {
        if (!Live.Enabled || !Live.Has("SERVER_CLIENT_SECRET"))
        {
            return;
        }
        if (_managed is { IsCompletedSuccessfully: true })
        {
            try
            {
                await Management().DeleteUserAsync(_managed.Result.Id);
            }
            catch (NineException)
            {
            }
        }
        // This run's sandbox users (the sign-in created them).
        var sandbox = Management("SANDBOX_ISSUER");
        await foreach (var user in sandbox.ListAllUsersAsync(Live.Run))
        {
            if (user.Email is { } email && email.EndsWith("@sandbox.e2e.test", StringComparison.Ordinal) && email.Contains(Live.Run, StringComparison.Ordinal))
            {
                try
                {
                    await sandbox.DeleteUserAsync(user.Id);
                }
                catch (NineException)
                {
                }
            }
        }
    }
}

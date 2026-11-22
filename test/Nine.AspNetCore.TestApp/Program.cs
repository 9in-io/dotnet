using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nine;
using Nine.AspNetCore;

// The app the ASP.NET Core integration tests run (WebApplicationFactory): a web app that signs users in,
// an API with scopes (minimal APIs and a controller), webhooks and the adapter, all in one.
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
builder.Services.AddAuthentication()
    .AddNineWebApp(options =>
    {
        options.ErrorPath = config["Test:ErrorPath"];
        if (config["Test:RefreshLeewaySeconds"] is { } leeway)
        {
            options.RefreshLeeway = TimeSpan.FromSeconds(int.Parse(leeway, System.Globalization.CultureInfo.InvariantCulture));
        }
    })
    .AddNineApi();
builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddSingleton<WebhookLog>();
builder.Services.AddScoped<INineWebhookHandler, LoggingWebhookHandler>();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapNineWebApp();
app.MapGet("/", (ClaimsPrincipal user) => user.Identity?.IsAuthenticated == true ? $"Hello {user.FindFirstValue("name")}" : "Hello stranger");
app.MapGet("/me", (ClaimsPrincipal user) => Results.Json(new
{
    sub = user.FindFirstValue("sub"),
    email = user.FindFirstValue("email"),
    name = user.Identity!.Name,
    claims = user.Claims.Select(c => c.Type).Distinct().Order().ToArray(),
})).RequireAuthorization();
// An explicit return type: an expression-bodied (HttpContext) => … lambda would bind to RequestDelegate and drop the result.
app.MapGet("/token", async Task<string?> (HttpContext context) => await context.GetNineAccessTokenAsync()).RequireAuthorization();
app.MapGet("/api/orders", (ClaimsPrincipal user, HttpContext context) => Results.Json(new
{
    sub = user.FindFirstValue("sub"),
    scopes = user.GetScopes(),
    jti = context.GetNineClaims()?.TokenId,
})).RequireScope("orders:read");
app.MapGet("/api/any", (ClaimsPrincipal user) => user.FindFirstValue("sub")).RequireNineToken();
app.MapControllers();
app.MapNineWebhooks(configure: options => options.Path = config["Test:WebhookPath"]).On(WebhookEventTypes.UserCreated, (e, http) =>
{
    http.RequestServices.GetRequiredService<WebhookLog>().Typed.Add(e.Id);
    return Task.CompletedTask;
});
app.MapNineAdapter<TestAdapter>(configure: options => options.PathPrefix = config["Test:AdapterPathPrefix"]);
app.Run();

public partial class Program;

[ApiController]
[Route("api/admin")]
public sealed class AdminController : ControllerBase
{
    [HttpGet("orders")]
    [RequireScope("orders:read", "orders:write")]
    public IActionResult Orders() => Ok(new { sub = User.FindFirstValue("sub") });

    [HttpGet("whoami")]
    [Authorize(AuthenticationSchemes = NineDefaults.BearerScheme)]
    public string WhoAmI() => User.FindFirstValue("sub") ?? "";
}

/// <summary>What the webhook handlers saw, and knobs to make them fail or wait.</summary>
public sealed class WebhookLog
{
    public List<string> Handled { get; } = [];
    public List<string> Typed { get; } = [];
    public int FailNext;
    public TaskCompletionSource? Gate;
    public TaskCompletionSource? Entered;
}

public sealed class LoggingWebhookHandler(WebhookLog log) : INineWebhookHandler
{
    public async Task HandleAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken)
    {
        if (log.Gate is { } gate)
        {
            log.Entered?.TrySetResult();
            await gate.Task;
        }
        if (Interlocked.Exchange(ref log.FailNext, 0) == 1)
        {
            throw new InvalidOperationException("handler failed");
        }
        lock (log.Handled)
        {
            log.Handled.Add(webhookEvent.Id);
        }
    }
}

public sealed class TestAdapter(WebhookLog log) : IAdapter
{
    public Task<AdapterResult> AuthenticateAsync(AdapterIdentifier identifier, string password, CancellationToken cancellationToken) =>
        Task.FromResult(identifier.Value == "jane@acme.test" && password == "hunter2"
            ? new AdapterUser("42") { Email = "jane@acme.test", Name = "Jane" }
            : AdapterResult.Invalid);

    public Task<AdapterUser?> FindUserAsync(AdapterQuery query, CancellationToken cancellationToken) =>
        Task.FromResult(query.Id == "42" ? new AdapterUser("42") : null);

    public Task OnEventAsync(AdapterEvent adapterEvent, CancellationToken cancellationToken)
    {
        lock (log.Handled)
        {
            log.Handled.Add("adapter:" + adapterEvent.EventType);
        }
        return Task.CompletedTask;
    }
}

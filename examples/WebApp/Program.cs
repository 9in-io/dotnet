using System.Net;
using System.Security.Claims;
using Nine;
using Nine.AspNetCore;

// A web app that signs users in with 9in, and an API in the same app protected by 9in access tokens.
// Settings come from the "Nine" section (appsettings.json, user secrets) or NINE_* environment variables:
// NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_AUDIENCE, NINE_WEBHOOK_SECRET.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddNineWebApp()   // cookie session + OpenID Connect, preconfigured for 9in
    .AddNineApi();     // Authorization: Bearer <9in access token>
builder.Services.AddAuthorization();
builder.Services.AddNine(); // AuthClient and ManagementClient for injection

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapNineWebApp(); // /nine/login, /nine/signup, /nine/logout (the callback is /nine/callback)

app.MapGet("/", (ClaimsPrincipal user) =>
{
    var body = user.Identity?.IsAuthenticated == true
        ? $"""<p>Signed in as <b>{Html(user.FindFirstValue("email"))}</b>.</p><p><a href="/profile">Profile</a> · <a href="/nine/logout">Sign out</a></p>"""
        : """<p><a href="/nine/login?return_to=/profile">Sign in</a> · <a href="/nine/signup">Sign up</a></p>""";
    return Results.Content(Page("9in example", body), "text/html");
});

app.MapGet("/profile", async (HttpContext http, ClaimsPrincipal user, AuthClient nine) =>
{
    // The session keeps the access token fresh: it is refreshed, with rotation, before it expires.
    var accessToken = await http.GetNineAccessTokenAsync();
    var current = await nine.GetUserInfoAsync(accessToken!);
    var rows = string.Concat(user.Claims.Select(c => $"<tr><td>{Html(c.Type)}</td><td>{Html(c.Value)}</td></tr>"));
    var body = $"""
        <p>Hello {Html(user.Identity!.Name ?? current.Email)}. <a href="/">Home</a> · <a href="/nine/logout">Sign out</a></p>
        <h2>ID token claims</h2><table>{rows}</table>
        <h2>From the userinfo endpoint</h2><pre>{Html(current.ToJson())}</pre>
        """;
    return Results.Content(Page("Profile", body), "text/html");
}).RequireAuthorization();

// The API: a 9in access token with the read:things scope (set Nine:Audience to the API's identifier).
app.MapGet("/api/things", (ClaimsPrincipal user) => Results.Json(new { user = user.FindFirstValue("sub"), scopes = user.GetScopes() }))
    .RequireScope("read:things");

// Webhooks (set Nine:WebhookSecret): verified, processed once per event, and revocations evict cached tokens.
app.MapNineWebhooks().OnAny((webhookEvent, http) =>
{
    http.RequestServices.GetRequiredService<ILogger<Program>>().LogInformation("9in webhook {Type} {Id}", webhookEvent.EventType, webhookEvent.Id);
    return Task.CompletedTask;
});

app.Run();

static string Html(string? value) => WebUtility.HtmlEncode(value ?? "");

static string Page(string title, string body) => $$"""
    <!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{Html(title)}}</title>
    <style>body { font: 16px system-ui; margin: 2rem auto; max-width: 48rem } td { padding: 2px 8px; border-bottom: 1px solid #ddd }</style>
    </head><body><h1>{{Html(title)}}</h1>{{body}}</body></html>
    """;

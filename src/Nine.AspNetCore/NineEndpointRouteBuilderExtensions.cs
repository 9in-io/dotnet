using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Nine.AspNetCore;

/// <summary>The 9in endpoints: sign-in routes, webhooks and the adapter.</summary>
public static class NineEndpointRouteBuilderExtensions
{
    private static readonly HashSet<string> Prompts = new(StringComparer.Ordinal) { "login", "consent", "none", "select_account", "create" };
    private const int MaxBody = 1024 * 1024;

    /// <summary>
    /// Maps the sign-in routes of <c>AddNineWebApp</c> (the callback, <c>/nine/callback</c>, is served by the handler itself):
    /// <list type="bullet">
    /// <item><description><c>GET /nine/login?return_to=/dashboard</c>: goes to the 9in sign-in page (also takes <c>prompt</c>, <c>login_hint</c>, <c>locale</c>).</description></item>
    /// <item><description><c>GET /nine/signup</c>: goes to the sign-up form.</description></item>
    /// <item><description><c>GET|POST /nine/logout?return_to=/</c>: revokes the refresh token, ends the session here and at 9in (<c>local=1</c>: here only).</description></item>
    /// </list>
    /// </summary>
    public static RouteGroupBuilder MapNineWebApp(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var web = endpoints.ServiceProvider.GetService<IOptions<NineWebAppOptions>>()?.Value
            ?? throw new InvalidOperationException("Call builder.Services.AddAuthentication().AddNineWebApp() before MapNineWebApp().");
        var group = endpoints.MapGroup(web.NormalizedBasePath);
        group.AllowAnonymous();
        group.MapGet("/login", context => Challenge(context, signUp: false)).WithDisplayName("9in login");
        group.MapGet("/signup", context => Challenge(context, signUp: true)).WithDisplayName("9in sign-up");
        group.MapMethods("/logout", ["GET", "POST"], Logout).WithDisplayName("9in logout");
        return group;
    }

    private static Task Challenge(HttpContext context, bool signUp)
    {
        var web = context.RequestServices.GetRequiredService<IOptions<NineWebAppOptions>>().Value;
        var query = context.Request.Query;
        var properties = new OpenIdConnectChallengeProperties
        {
            RedirectUri = ReturnTo.Sanitize(query["return_to"]) ?? ReturnTo.Sanitize(query["returnTo"]) ?? web.AfterSignInPath,
        };
        properties.Items[NineOpenIdConnectSetup.ExplicitItem] = "1";
        string? prompt = query["prompt"];
        if (signUp)
        {
            properties.Prompt = "create";
        }
        else if (prompt is not null && Prompts.Contains(prompt))
        {
            properties.Prompt = prompt;
        }
        if (query["login_hint"] is { Count: 1 } hint && hint[0]!.Length <= 256)
        {
            properties.Items[NineOpenIdConnectSetup.LoginHintItem] = hint[0];
        }
        if (query["locale"] is { Count: 1 } locale && locale[0]!.Length <= 64)
        {
            properties.Items[NineOpenIdConnectSetup.LocaleItem] = locale[0];
        }
        return context.ChallengeAsync(web.Scheme, properties);
    }

    private static async Task Logout(HttpContext context)
    {
        var app = context.RequestServices.GetRequiredService<NineWebApp>();
        var web = app.Options;
        var session = await context.AuthenticateAsync(web.CookieScheme).ConfigureAwait(false);
        if (web.RevokeOnSignOut)
        {
            await NineOpenIdConnectSetup.RevokeQuietly(app, context, session.Properties?.GetTokenValue("refresh_token")).ConfigureAwait(false);
        }
        if (session.Properties?.GetTokenValue("id_token") is { } idToken)
        {
            context.Items[NineOpenIdConnectSetup.IdTokenItem] = idToken;
        }
        var returnTo = ReturnTo.Sanitize(context.Request.Query["return_to"]) ?? web.AfterSignOutPath;
        await context.SignOutAsync(web.CookieScheme).ConfigureAwait(false);
        if (context.Request.Query["local"] == "1")
        {
            context.Response.Redirect(returnTo);
            return;
        }
        await context.SignOutAsync(web.Scheme, new AuthenticationProperties { RedirectUri = returnTo }).ConfigureAwait(false);
    }

    /// <summary>
    /// Receives 9in webhooks at <paramref name="pattern"/> (default <c>/nine/webhook</c>): verifies the
    /// <c>9in-signature</c> (secret from <c>Nine:WebhookSecret</c> / <c>NINE_WEBHOOK_SECRET</c>), drops the hybrid
    /// verification answers the event makes stale, then runs your handlers once per event id (with
    /// <see cref="INineCache"/>: your <c>IDistributedCache</c> when there is one). Answers 204, 409 while another
    /// delivery of the same event is running, 401 for a bad signature, and 500 when a handler throws (9in retries).
    /// Register handlers with <see cref="NineWebhookEndpointBuilder.On(string, Func{WebhookEvent, HttpContext, Task})"/> or as <see cref="INineWebhookHandler"/> services.
    /// </summary>
    public static NineWebhookEndpointBuilder MapNineWebhooks(this IEndpointRouteBuilder endpoints, string pattern = "/nine/webhook", Action<NineWebhookOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        RequireServices(endpoints, nameof(MapNineWebhooks));
        var options = new NineWebhookOptions();
        configure?.Invoke(options);
        var handlers = new NineWebhookHandlers();
        var endpoint = endpoints.MapPost(pattern, context => HandleWebhook(context, options, handlers)).WithDisplayName("9in webhooks");
        endpoint.AllowAnonymous();
        return new NineWebhookEndpointBuilder(endpoint, handlers);
    }

    private static async Task HandleWebhook(HttpContext context, NineWebhookOptions options, NineWebhookHandlers handlers)
    {
        var services = context.RequestServices;
        var nine = services.GetRequiredService<IOptions<NineOptions>>().Value;
        IReadOnlyList<string> secrets = options.Secrets.Count > 0 ? options.Secrets.ToArray() : NineEnvironment.SplitList(nine.WebhookSecret);
        if (secrets.Count == 0)
        {
            throw new NineException("invalid_options", "the webhook secret is missing: set Nine:WebhookSecret in configuration or NINE_WEBHOOK_SECRET");
        }
        var body = await ReadBodyAsync(context).ConfigureAwait(false);
        if (body is null)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        WebhookEvent webhookEvent;
        try
        {
            var path = options.Path ?? (context.Request.PathBase + context.Request.Path).ToString();
            webhookEvent = Webhook.Verify(secrets, body, context.Request.Headers[Signature.Header], path, timeProvider: services.GetRequiredService<TimeProvider>());
        }
        catch (NineException e)
        {
            await WriteError(context, e.StatusCode ?? 400, e.Error).ConfigureAwait(false);
            return;
        }

        // Revocations take effect before anything else, on every hybrid verifier of the app.
        foreach (var verifier in services.GetRequiredService<NineApiVerifiers>().Hybrid)
        {
            await verifier.HandleEventAsync(webhookEvent, context.RequestAborted).ConfigureAwait(false);
        }
        if (services.GetService<HybridTokenVerifier>() is { } registered)
        {
            await registered.HandleEventAsync(webhookEvent, context.RequestAborted).ConfigureAwait(false);
        }

        async Task Dispatch(CancellationToken cancellationToken)
        {
            foreach (var handler in handlers.For(webhookEvent.EventType))
            {
                await handler(webhookEvent, context).ConfigureAwait(false);
            }
            foreach (var handler in services.GetServices<INineWebhookHandler>())
            {
                await handler.HandleAsync(webhookEvent, cancellationToken).ConfigureAwait(false);
            }
        }

        var outcome = EventOutcome.Processed;
        if (options.ProcessOnce)
        {
            var dedupe = new EventDeduplicator(services.GetRequiredService<INineCache>(), options.ProcessedTtl);
            outcome = await dedupe.ProcessAsync(webhookEvent.Id, Dispatch, context.RequestAborted).ConfigureAwait(false);
        }
        else
        {
            await Dispatch(context.RequestAborted).ConfigureAwait(false);
        }
        if (outcome == EventOutcome.InProgress)
        {
            services.GetRequiredService<ILoggerFactory>().CreateLogger("Nine.AspNetCore").LogInformation("Webhook {EventId} is being processed by another delivery", webhookEvent.Id);
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    /// <summary>
    /// Serves the adapter protocol for your own user database at <c>{prefix}/authenticate</c>, <c>{prefix}/user</c>
    /// and <c>{prefix}/event</c> (default prefix <c>/nine</c>), with <typeparamref name="TAdapter"/> created per request
    /// from dependency injection (registered or not). Requests are verified and responses signed with
    /// <c>Nine:AdapterSecret</c> / <c>NINE_ADAPTER_SECRET</c>.
    /// </summary>
    public static RouteGroupBuilder MapNineAdapter<TAdapter>(this IEndpointRouteBuilder endpoints, string prefix = "/nine", Action<NineAdapterOptions>? configure = null)
        where TAdapter : class, IAdapter
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        RequireServices(endpoints, nameof(MapNineAdapter));
        var options = new NineAdapterOptions();
        configure?.Invoke(options);
        var group = endpoints.MapGroup(prefix);
        group.AllowAnonymous();
        foreach (var route in new[] { "/authenticate", "/user", "/event" })
        {
            group.MapPost(route, context => HandleAdapter<TAdapter>(context, options)).WithDisplayName("9in adapter " + route);
        }
        return group;
    }

    private static async Task HandleAdapter<TAdapter>(HttpContext context, NineAdapterOptions options)
        where TAdapter : class, IAdapter
    {
        var services = context.RequestServices;
        var nine = services.GetRequiredService<IOptions<NineOptions>>().Value;
        IReadOnlyList<string> secrets = options.Secrets.Count > 0 ? options.Secrets.ToArray() : NineEnvironment.SplitList(nine.AdapterSecret);
        if (secrets.Count == 0)
        {
            throw new NineException("invalid_options", "the adapter secret is missing: set Nine:AdapterSecret in configuration or NINE_ADAPTER_SECRET");
        }
        var body = await ReadBodyAsync(context).ConfigureAwait(false);
        if (body is null)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        var adapter = ActivatorUtilities.GetServiceOrCreateInstance<TAdapter>(services);
        var handler = new AdapterHandler(secrets, adapter, options.Tolerance, services.GetRequiredService<TimeProvider>());
        var path = options.PathPrefix is { } prefix
            ? prefix.TrimEnd('/') + context.Request.Path.Value![context.Request.Path.Value!.LastIndexOf('/')..]
            : (context.Request.PathBase + context.Request.Path).ToString();
        var headers = context.Request.Headers.Select(h => new KeyValuePair<string, string>(h.Key, h.Value.ToString()));
        var response = await handler.HandleAsync(new AdapterRequest(context.Request.Method, path, headers, body), context.RequestAborted).ConfigureAwait(false);
        context.Response.StatusCode = response.StatusCode;
        foreach (var (name, value) in response.Headers)
        {
            context.Response.Headers[name] = value;
        }
        if (response.Body.Length > 0)
        {
            await context.Response.Body.WriteAsync(response.Body, context.RequestAborted).ConfigureAwait(false);
        }
    }

    private static void RequireServices(IEndpointRouteBuilder endpoints, string method)
    {
        if (endpoints.ServiceProvider.GetService<NineApiVerifiers>() is null)
        {
            throw new InvalidOperationException($"Call builder.Services.AddNine() (or AddNineWebApp / AddNineApi) before {method}().");
        }
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpContext context)
    {
        if (context.Request.ContentLength > MaxBody)
        {
            return null;
        }
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxBody)
            {
                return null;
            }
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    private static Task WriteError(HttpContext context, int status, string error)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        return context.Response.WriteAsync($$"""{"error":"{{error}}"}""", context.RequestAborted);
    }
}

/// <summary>Settings of <see cref="NineEndpointRouteBuilderExtensions.MapNineWebhooks"/>.</summary>
public sealed class NineWebhookOptions
{
    /// <summary>The endpoint's signing secrets (default <c>Nine:WebhookSecret</c>, comma-separated during rotation).</summary>
    public IList<string> Secrets { get; } = [];
    /// <summary>The path 9in posts to, when a proxy rewrites it (default: the request's path base and path).</summary>
    public string? Path { get; set; }
    /// <summary>Run handlers once per event id. Default true.</summary>
    public bool ProcessOnce { get; set; } = true;
    /// <summary>How long a processed id is remembered. Default 3 days.</summary>
    public TimeSpan? ProcessedTtl { get; set; }
}

/// <summary>Settings of <see cref="NineEndpointRouteBuilderExtensions.MapNineAdapter{TAdapter}"/>.</summary>
public sealed class NineAdapterOptions
{
    /// <summary>The adapter secrets (default <c>Nine:AdapterSecret</c>, comma-separated during rotation); responses are signed with the first.</summary>
    public IList<string> Secrets { get; } = [];
    /// <summary>The path prefix 9in calls, when a proxy rewrites it (default: the request's path base and path).</summary>
    public string? PathPrefix { get; set; }
    /// <summary>How far a request's timestamp may be off. Default 5 minutes.</summary>
    public TimeSpan? Tolerance { get; set; }
}

/// <summary>Handles verified 9in webhook events; register with <c>services.AddScoped&lt;INineWebhookHandler, MyHandler&gt;()</c>.</summary>
public interface INineWebhookHandler
{
    /// <summary>Called once per event (unless <see cref="NineWebhookOptions.ProcessOnce"/> is off). Throw to have 9in retry.</summary>
    Task HandleAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken);
}

internal sealed class NineWebhookHandlers
{
    private readonly List<(string? Type, Func<WebhookEvent, HttpContext, Task> Handler)> _handlers = [];

    public void Add(string? type, Func<WebhookEvent, HttpContext, Task> handler)
    {
        lock (_handlers)
        {
            _handlers.Add((type, handler));
        }
    }

    public IEnumerable<Func<WebhookEvent, HttpContext, Task>> For(string type)
    {
        lock (_handlers)
        {
            return _handlers.Where(h => h.Type is null || h.Type == type).Select(h => h.Handler).ToArray();
        }
    }
}

/// <summary>The webhook endpoint: add handlers per event type, and endpoint conventions as usual.</summary>
public sealed class NineWebhookEndpointBuilder : IEndpointConventionBuilder
{
    private readonly IEndpointConventionBuilder _endpoint;
    private readonly NineWebhookHandlers _handlers;

    internal NineWebhookEndpointBuilder(IEndpointConventionBuilder endpoint, NineWebhookHandlers handlers)
    {
        _endpoint = endpoint;
        _handlers = handlers;
    }

    /// <summary>Runs <paramref name="handler"/> for events of <paramref name="eventType"/> (see <see cref="WebhookEventTypes"/>).</summary>
    public NineWebhookEndpointBuilder On(string eventType, Func<WebhookEvent, HttpContext, Task> handler)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventType);
        ArgumentNullException.ThrowIfNull(handler);
        _handlers.Add(eventType, handler);
        return this;
    }

    /// <summary>Runs <paramref name="handler"/> for events of <paramref name="eventType"/>, with <c>data</c> as <typeparamref name="TData"/> (e.g. <see cref="TokenRevokedData"/>).</summary>
    public NineWebhookEndpointBuilder On<TData>(string eventType, Func<WebhookEvent, TData, HttpContext, Task> handler, System.Text.Json.Serialization.Metadata.JsonTypeInfo<TData> dataType)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(dataType);
        return On(eventType, (e, http) => handler(e, e.GetData(dataType)!, http));
    }

    /// <summary>Runs <paramref name="handler"/> for every event.</summary>
    public NineWebhookEndpointBuilder OnAny(Func<WebhookEvent, HttpContext, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handlers.Add(null, handler);
        return this;
    }

    /// <inheritdoc/>
    public void Add(Action<EndpointBuilder> convention) => _endpoint.Add(convention);

    /// <inheritdoc/>
    public void Finally(Action<EndpointBuilder> finallyConvention) => _endpoint.Finally(finallyConvention);
}

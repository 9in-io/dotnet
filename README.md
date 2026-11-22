9in .NET SDK
============

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official .NET SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO.

Two NuGet packages, like `@9in-io/sdk` and `@9in-io/nextjs` in JavaScript:

- **`9in`** (namespace `Nine`) does the protocol and runs in any .NET app: web apps, workers, desktop
  apps and CLIs. It has no dependencies.
- **`9in.AspNetCore`** (namespace `Nine.AspNetCore`) is built on it and plugs 9in into ASP.NET Core's own
  authentication stack.

What they do:

- **Sign users in**: authorization code flow with PKCE, the issuer check of RFC 9207, ID tokens verified
  against your tenant's keys, refresh with rotation, revocation and logout. In ASP.NET Core, the cookie and
  OpenID Connect handlers preconfigured for 9in, with `/nine/login`, `/nine/signup` and `/nine/logout`.
- **Protect your API**: verify access tokens locally with every algorithm of the key library (EdDSA
  included), and catch revocations at once in hybrid mode, with the answers in your `IDistributedCache`.
  In ASP.NET Core, a bearer scheme and scope checks for minimal APIs and MVC.
- **Manage users** through the Management API: users, sessions, single-use sign-in links and bulk import.
- **Keep users in your own database** with the adapter protocol v2 (`/authenticate`, `/user`, `/event`)
  and signed requests and responses.
- **Receive webhooks**, verify their signature and process each event once.
- **Call your APIs from your back end** with client-credentials tokens, and **sign in devices and CLIs**
  with the device flow (RFC 8628).

Requires .NET 8 or .NET 10.

```bash
dotnet add package 9in.AspNetCore   # ASP.NET Core apps (brings in 9in)
dotnet add package 9in              # anything else
```

Guides are at [9in.io/docs](https://9in.io/docs/); start with
[Server-rendered apps](https://9in.io/docs/server-apps/) and [Protecting APIs](https://9in.io/docs/protecting-apis/).
The [examples](examples/) folder has a minimal-API app and an MVC app.

| Building with | Use |
|---|---|
| JavaScript, React or Next.js | [`@9in-io/sdk`](https://github.com/9in-io/sdk), [`@9in-io/react`](https://github.com/9in-io/react), [`@9in-io/nextjs`](https://github.com/9in-io/nextjs) |
| PHP or Laravel | [`9in/php-sdk`](https://github.com/9in-io/php-sdk), [`9in/laravel`](https://github.com/9in-io/laravel) |

## Sign users in (ASP.NET Core)

Create a **Regular Web App** application in the 9in console and add:

- Allowed callback URL: `https://your-app.com/nine/callback` (and `https://localhost:5001/nine/callback`)
- Allowed logout URL: `https://your-app.com/` (and `https://localhost:5001/`)

Put the settings in `appsettings.json`, in user secrets, or in `NINE_*` environment variables:

```json
{
  "Nine": {
    "Issuer": "https://acme.9in.io",
    "ClientId": "app_...",
    "Audience": "https://api.acme.com"
  }
}
```

```bash
dotnet user-secrets set "Nine:ClientSecret" "..."   # or NINE_CLIENT_SECRET
```

Then, in `Program.cs`:

```csharp
using System.Security.Claims;
using Nine.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication().AddNineWebApp();
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapNineWebApp(); // /nine/login, /nine/signup, /nine/logout

app.MapGet("/", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name ?? "stranger"}");
app.MapGet("/dashboard", (ClaimsPrincipal user) => $"Signed in as {user.FindFirstValue("email")}")
    .RequireAuthorization();

app.Run();
```

| Route | What it does |
| --- | --- |
| `/nine/login?return_to=/dashboard` | Goes to the 9in sign-in page and comes back. Also takes `prompt`, `login_hint` and `locale`. |
| `/nine/signup` | Goes to the sign-up form. |
| `/nine/callback` | Finishes the sign-in (served by ASP.NET Core's OpenID Connect handler) and sets the session cookie. |
| `/nine/logout?return_to=/` | Revokes the refresh token and signs out here and at 9in. Add `local=1` to sign out only here. |

A signed-out visit to a page that needs a user goes to the sign-in page and comes back; an API call (a
`fetch` without `Accept: text/html`) gets a 401 instead. `User` holds the ID token's claims with 9in's own
names (`sub`, `email`, `name`, `amr`, your custom claims…), and `User.Identity.Name` is the `name` claim.

In MVC, use `[Authorize]` as usual:

```csharp
public sealed class HomeController : Controller
{
    [Authorize]
    public IActionResult Profile() => View();
}
```

### Calling your API with the user's token

```csharp
app.MapGet("/orders", async (HttpContext http, IHttpClientFactory factory) =>
{
    var token = await http.GetNineAccessTokenAsync(); // refreshed, with rotation, before it expires
    var api = factory.CreateClient();
    api.DefaultRequestHeaders.Authorization = new("Bearer", token);
    return await api.GetStringAsync("https://api.acme.com/orders");
}).RequireAuthorization();
```

Set `Nine:Audience` to your API's identifier to get access tokens for it. 9in rotates refresh tokens: each
one works once. The session refreshes the access token a minute before it expires and saves the new
refresh token in the cookie; requests that arrive together share one refresh. When 9in refuses the refresh
token (the user signed out everywhere, an admin ended the session), the user is signed out here too.

### What `AddNineWebApp` sets up

It adds a cookie scheme (`NineDefaults.CookieScheme`) and ASP.NET Core's OpenID Connect handler
(`NineDefaults.AuthenticationScheme`) configured for 9in:

- Authorization code flow with PKCE (S256), `state`, `nonce`, and the `iss` parameter checked (RFC 9207).
- The code is exchanged with `client_secret_basic`, and the ID token is verified by 9in's verifier, which
  knows every algorithm of the key library (the stock handler can't verify EdDSA).
- Tokens are saved in the session cookie (`HttpOnly`, `SameSite=Lax`, `Secure` over https), encrypted by
  ASP.NET Core Data Protection. For large sessions, set a server-side `SessionStore` with `ConfigureCookie`.
- `return_to` only takes paths on your own site.

```csharp
builder.Services.AddAuthentication().AddNineWebApp(options =>
{
    options.AfterSignOutPath = "/goodbye";            // must be an allowed logout URL
    options.ErrorPath = "/sign-in-failed";            // gets ?error=access_denied and the like
    options.Scopes.Add("orders:read");                // the default is openid profile email offline_access
    options.ConfigureCookie = cookie => cookie.ExpireTimeSpan = TimeSpan.FromDays(7);
});
```

Behind a proxy that changes the host or scheme, use `UseForwardedHeaders`, or set `Nine:RedirectUri` to
the full callback URL. On several servers, share ASP.NET Core's Data Protection keys (the session cookie is
encrypted with them) and register an `IDistributedCache`.

## Sign users in (any .NET app)

`AuthClient` runs the protocol and leaves the session to you:

```csharp
using Nine;

var auth = new AuthClient(new AuthClientOptions
{
    Issuer = "https://acme.9in.io",
    ClientId = "app_...",
    ClientSecret = Environment.GetEnvironmentVariable("NINE_CLIENT_SECRET"), // confidential apps; leave out for public ones
    RedirectUri = "https://app.acme.com/nine/callback",
});

// /nine/login: keep login.Pending (secret) until the callback, e.g. login.Pending.ToJson() in the session
var login = await auth.CreateLoginAsync(new LoginOptions { ReturnTo = "/dashboard" }); // Screen = LoginScreen.SignUp for the sign-up form
// redirect the browser to login.Url

// /nine/callback: checks state (single use), iss and PKCE, verifies the ID token
TokenSet tokens = await auth.HandleCallbackAsync(callbackUrl, PendingLogin.FromJson(savedPending));
// tokens.Claims: the user (sub, email, name, amr…); tokens.ReturnTo; tokens.ToJson() for the session

tokens = await auth.EnsureFreshAsync(tokens);          // refreshes (and rotates) when the access token is about to expire
var profile = await auth.GetUserInfoAsync(tokens.AccessToken);

// /nine/logout
await auth.RevokeAsync(tokens.RefreshToken!);
var logoutUrl = await auth.GetLogoutUrlAsync(tokens.IdToken, "https://app.acme.com/");
```

`AuthClientOptions.FromEnvironment()` reads `NINE_ISSUER`, `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET`,
`NINE_REDIRECT_URI` and `NINE_AUDIENCE`. Every client takes an `HttpClient` (from `IHttpClientFactory`, say)
and has a 10-second timeout per request; redirects are never followed.

## Protect your API

### ASP.NET Core

```csharp
using System.Security.Claims;
using Nine.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication().AddNineApi(); // Nine:Issuer, Nine:ApiAudience (or Nine:Audience)
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/orders", (ClaimsPrincipal user) => new { user = user.FindFirstValue("sub") })
    .RequireScope("orders:read");

app.Run();
```

In MVC, put `[RequireScope("orders:read")]` on a controller or action; several attributes all apply. Or add
policies: `options.AddPolicy("orders", p => p.RequireScope("orders:read"))`.

```csharp
[ApiController]
[Route("api/orders")]
[RequireScope("orders:read")]
public sealed class OrdersController : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok(new { user = User.FindFirstValue("sub") });

    [HttpPost]
    [RequireScope("orders:write")] // orders:read and orders:write
    public IActionResult Create() => Created("/api/orders/1", null);
}
```

A request without a token gets 401 with `WWW-Authenticate: Bearer`; a bad token 401 with
`error="invalid_token"`; a token without the scope 403 with `error="insufficient_scope", scope="orders:read"`;
and if 9in can't be reached to check a token, 503. `HttpContext.GetNineClaims()` returns the token's claims
exactly as 9in sent them. In an app that also signs users in, endpoints with `RequireScope` (or
`RequireNineToken()`) use the bearer scheme; the session cookie doesn't satisfy them.

### Any .NET app

```csharp
var verifier = new TokenVerifier(new TokenVerifierOptions
{
    Issuer = "https://acme.9in.io",
    Audience = "https://api.acme.com",
});

ClaimSet claims = await verifier.VerifyAsync(authorizationHeader, "orders:read"); // "Bearer …" or the token
// claims.Subject, claims.ClientId, claims.Scopes, claims["custom"]…
// InvalidTokenException → 401, InsufficientScopeException → 403
```

Tokens are verified locally against your tenant's JWKS (cached ten minutes, fetched again once when a new
key appears after rotation; unknown key ids are then ignored for a minute). Every algorithm of the 9in key
library is accepted: RS256/384/512, PS256/384/512, ES256, ES384 and EdDSA from the JWKS, and HS256/384/512
when your API uses a shared secret (`Secret`, or `Nine:ApiSecret` / `NINE_API_SECRET`). The key's own
algorithm is enforced, `alg: none` is refused, and only access tokens (`typ: at+jwt`) are accepted.

**EdDSA without a dependency.** .NET has no Ed25519, so the SDK carries a small verifier (RFC 8032) instead
of depending on a crypto library for one algorithm. It only verifies: nothing secret goes through it, so it
doesn't have to run in constant time, and it uses `BigInteger` arithmetic for clarity. It is strict
(non-canonical keys and signatures are refused) and tested against the RFC 8032 vectors and tokens signed
by WebCrypto. Everything else uses .NET's own cryptography.

### Revocation: hybrid verification

A local check can't see revocations: a token revoked through `/oauth/revoke`, a sign-out or a blocked user
keeps passing until it expires. Hybrid verification closes that gap. With a confidential application's
client ID and secret, `AddNineApi` uses it by default:

| Mode | What it does |
|---|---|
| `Local` | Signature and claims only. No calls to 9in. |
| `Hybrid` | Local check, then one introspection per token. The answer is cached until a webhook says otherwise or `CacheTtl` (5 minutes) passes; a refusal is cached until the token expires. |
| `Introspect` | Introspection on every call. |

Opaque access tokens (`9in_at_…`) are always introspected, and cached in hybrid mode. Answers are kept in
your `IDistributedCache` when one is registered (Redis, SQL Server…), so every server sees them, and
`MapNineWebhooks` drops the stale ones when `token.revoked`, `session.revoked`, `user.sessions_revoked`,
`user.updated`, `user.deleted` or `user.password_changed` arrives. Without ASP.NET Core:

```csharp
var verifier = new HybridTokenVerifier(new HybridTokenVerifierOptions
{
    Issuer = "https://acme.9in.io",
    Audience = "https://api.acme.com",
    ClientId = "app_...",           // a confidential application, for introspection
    ClientSecret = "...",
    Cache = myRedisCache,           // INineCache; default: in this process
});

var claims = await verifier.VerifyAsync(bearer, "orders:read");

// webhook endpoint subscribed to token.revoked, session.revoked and user.* events
await verifier.HandleEventAsync(Webhook.Verify(webhookSecret, body, signatureHeader, "/nine/webhook"));
```

## Manage users

```csharp
var nine = new ManagementClient(new ManagementClientOptions
{
    Issuer = "https://acme.9in.io",
    ClientId = "app_...",           // an application with management scopes
    ClientSecret = "...",
});

var user = await nine.CreateUserAsync(new NewUser { Email = "jane@acme.com", Password = "…", EmailVerified = true });
await nine.UpdateUserAsync(user.Id, new UserChanges { PhoneNumber = "+447700900000", PhoneNumberVerified = true });
await nine.BlockUserAsync(user.Id);
var found = await nine.FindUserByPhoneNumberAsync("+447700900000"); // or FindUserByEmailAsync, FindUserByUsernameAsync; null when unknown

// Sessions: list them, end one (its sid), or sign the user out everywhere
var sessions = await nine.ListUserSessionsAsync(user.Id);
await nine.RevokeSessionAsync(sessions[0].Sid);
await nine.RevokeUserSessionsAsync(user.Id);

// Single-use sign-in link (magic links, moving a signed-in user from your app to 9in)
var link = await nine.CreateLoginLinkAsync(user.Id, "https://app.acme.com/nine/callback", TimeSpan.FromMinutes(10));

// Bulk import (500 per call): old ids, password hashes (bcrypt, argon2, PBKDF2, Firebase scrypt), social identities
var results = await nine.ImportUsersAsync(
    [new ImportUser { Id = "auth0|42", Email = "jane@acme.com", PasswordHash = "$2b$10$…", CreatedAt = DateTimeOffset.Parse("2021-03-04T05:06:07Z") }],
    new ImportOptions { OnConflict = "skip", Source = "auth0" });

await foreach (var u in nine.ListAllUsersAsync("acme.com")) { /* every page */ }
```

Users and sessions keep 9in's field names on the wire (`email_verified`, `phone_number`, `password_hash`,
ISO 8601 UTC times) and are typed records here (`ManagedUser.EmailVerified`, `CreatedAt`). `metadata` passes
through unchanged as a `JsonObject`. `UserChanges` sends only the properties you set, so setting one to
null clears it. In ASP.NET Core, `builder.Services.AddNine()` registers `ManagementClient`, `AuthClient` and
`HybridTokenVerifier` from the `Nine` settings, for injection.

## Keep users in your own database

Implement `IAdapter` and map the three endpoints (secret: `Nine:AdapterSecret` / `NINE_ADAPTER_SECRET`):

```csharp
public sealed class MyUsers(AppDb db, IPasswordHasher hasher) : IAdapter
{
    public async Task<AdapterResult> AuthenticateAsync(AdapterIdentifier identifier, string password, CancellationToken cancellationToken)
    {
        var user = await db.FindByLoginAsync(identifier.Type, identifier.Value, cancellationToken);
        if (user is null || !hasher.Verify(user.PasswordHash, password)) return AdapterResult.Invalid;
        if (user.Disabled) return AdapterResult.Blocked;
        return new AdapterUser(user.Id.ToString()) { Email = user.Email, EmailVerified = true, Name = user.Name };
    }

    public async Task<AdapterUser?> FindUserAsync(AdapterQuery query, CancellationToken cancellationToken)
    {
        var user = query.Id is { } id ? await db.FindByIdAsync(id, cancellationToken) : await db.FindByLoginAsync(query.Identifier!.Type, query.Identifier.Value, cancellationToken);
        return user is null ? null : new AdapterUser(user.Id.ToString()) { Email = user.Email, Name = user.Name };
    }

    public async Task OnEventAsync(AdapterEvent adapterEvent, CancellationToken cancellationToken)
    {
        if (adapterEvent.Otp is { } otp) await SendCodeAsync(otp.Channel, otp.To, otp.Code); // when you deliver codes yourself
    }
}

app.MapNineAdapter<MyUsers>(); // POST /nine/authenticate, /nine/user, /nine/event
```

`MyUsers` is created per request from dependency injection. Requests are verified (HMAC-SHA256, 5-minute
window, constant-time compare, several secrets during rotation) and every response is signed over its
request id. Outside ASP.NET Core, `new AdapterHandler(secret, adapter).HandleAsync(request)` does the same.

## Webhooks

Add an endpoint under **Advanced → Webhooks** in the console and keep the signing secret it shows once
(`Nine:WebhookSecret` / `NINE_WEBHOOK_SECRET`; comma-separated while you rotate).

```csharp
app.MapNineWebhooks() // POST /nine/webhook
    .On(WebhookEventTypes.UserCreated, async (webhookEvent, http) =>
    {
        var crm = http.RequestServices.GetRequiredService<Crm>();
        await crm.AddAsync(webhookEvent.User!); // data.user: the user the event is about
    });
```

The endpoint verifies the signature, drops cached hybrid answers the event makes stale, and runs your
handlers once per event id: 9in retries a delivery until it gets a 2xx, and a retry can arrive while a slow
first attempt is still running. It answers 204, 409 while another delivery of the same event is running (9in
tries again later), 401 for a bad signature, and 500 when a handler throws, so 9in retries. Handlers can
also be services: `builder.Services.AddScoped<INineWebhookHandler, MyHandler>()`. Processed ids live in
your `IDistributedCache`; its add-if-absent isn't atomic across servers, so if two servers may get the same
delivery in the same instant, register an `INineCache` whose `AddAsync` is (Redis `SET NX`, a SQL unique key).

Without ASP.NET Core:

```csharp
var webhookEvent = Webhook.Verify(secret, rawBody, request.Headers["9in-signature"], "/nine/webhook");
var outcome = await new EventDeduplicator(cache).ProcessAsync(webhookEvent.Id, ct => HandleAsync(webhookEvent, ct));
// Processed or Duplicate → 204; InProgress → 409; the handler threw → id released, rethrown (5xx)
```

`webhookEvent.GetData<TokenRevokedData>()` and friends give each event's data as a typed record.

## Machine to machine

```csharp
builder.Services.AddNine();
builder.Services.AddHttpClient("orders", c => c.BaseAddress = new Uri("https://api.acme.com"))
    .AddNineClientCredentials(audience: "https://api.acme.com", scope: "orders:read");
```

Every request of that client carries a client-credentials token, cached until a minute before it expires.
Without ASP.NET Core: `await auth.ClientCredentialsAsync(audience, scope)`, or a `ClientCredentialsHandler`.

## Devices and CLIs

```csharp
var auth = new AuthClient(new AuthClientOptions { Issuer = "https://acme.9in.io", ClientId = "app_..." });
var device = await auth.StartDeviceAuthorizationAsync();
Console.WriteLine($"Go to {device.VerificationUri} and enter {device.UserCode}");
var tokens = await auth.PollDeviceAuthorizationAsync(device); // waits, honouring the interval and slow_down
```

## Issuers must use https

Every client refuses an issuer that isn't `https://` (`insecure_issuer`), so a typo can't send tokens or
credentials in clear text. Plain http is accepted for `localhost`, `*.localhost` and loopback addresses; for
other development hosts (e.g. `http://auth:8897` in Docker) set `AllowInsecureIssuer` (or
`NINE_ALLOW_INSECURE_ISSUER=true`). Issuers with a query, fragment or credentials are refused too.

## Configuration

ASP.NET Core reads the `Nine` configuration section; what it doesn't set comes from the environment
variables the other 9in SDKs use. The core clients have `*Options.FromEnvironment()`.

| Setting | Environment variable | |
|---|---|---|
| `Nine:Issuer` | `NINE_ISSUER` | Your tenant's issuer, e.g. `https://acme.9in.io` or your login domain |
| `Nine:ClientId` | `NINE_CLIENT_ID` | |
| `Nine:ClientSecret` | `NINE_CLIENT_SECRET` | Confidential applications |
| `Nine:RedirectUri` | `NINE_REDIRECT_URI` | The full callback URL, when the request can't tell (proxies) |
| `Nine:Audience` | `NINE_AUDIENCE` | The API a web app gets access tokens for |
| `Nine:ApiAudience` | `NINE_API_AUDIENCE` | The API this app serves (default: `Nine:Audience`) |
| `Nine:ApiSecret` | `NINE_API_SECRET` | The API's HMAC secret, for HS256/384/512 tokens |
| `Nine:TokenMode` | `NINE_TOKEN_MODE` | `local`, `hybrid` or `introspect` |
| `Nine:WebhookSecret` | `NINE_WEBHOOK_SECRET` | Comma-separated while you rotate |
| `Nine:AdapterSecret` | `NINE_ADAPTER_SECRET` | Comma-separated while you rotate |
| `Nine:AllowInsecureIssuer` | `NINE_ALLOW_INSECURE_ISSUER` | Development only |

## Errors

Every failure is a `NineException` with an `Error` code (`invalid_token`, `invalid_grant`,
`invalid_state`, `access_denied`, `insecure_issuer`, …), an `ErrorDescription` and, for HTTP failures, a
`StatusCode`. `InvalidTokenException` (401), `InsufficientScopeException` (403), `SignatureException`
(401) and `InvalidStateException` (400) are the ones to answer differently. Errors from 9in carry its
`error` and `error_description`. Messages never contain tokens or secrets.

## Development

```bash
dotnet test                       # unit and ASP.NET Core integration tests, on .NET 8 and .NET 10
NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e dotnet test test/Nine.E2E   # live tests against 9in's test tenants
dotnet pack -c Release            # artifacts/package/release
```

The live tests sign in through the real hosted pages, call every API, and replay real webhook deliveries
and adapter requests; they delete the users they create. Report bugs in
[issues](https://github.com/9in-io/dotnet/issues).

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in is by [Cubelet Ltd](https://cubelet.co.uk).

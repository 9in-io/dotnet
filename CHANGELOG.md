# Changelog

## 0.1.0

First release: two NuGet packages for .NET 8 and .NET 10.

`9in` (namespace `Nine`), no dependencies:

- `AuthClient`: sign-in for confidential and public clients. Authorization code + PKCE (S256) with
  endpoints from discovery, single-use `state` compared in constant time, `nonce`, the RFC 9207 `iss`
  check, ID tokens verified against the JWKS, refresh with rotation (`RefreshAsync`, `EnsureFreshAsync`),
  `client_secret_basic`, revocation, RP-initiated logout, userinfo, client credentials (cached with
  `GetClientCredentialsTokenAsync` and `ClientCredentialsHandler`) and the device flow (RFC 8628).
- `TokenVerifier`: access tokens verified locally with every algorithm of the key library (RS256/384/512,
  PS256/384/512, ES256, ES384, EdDSA, HS256/384/512), `typ: at+jwt`, the key's own algorithm, issuer,
  audience, expiry and scopes. JWKS cached ten minutes, refetched once for an unknown `kid`, unknown kids
  throttled for a minute. EdDSA through a small managed Ed25519 verifier (RFC 8032).
- `HybridTokenVerifier`: `Local`, `Hybrid` and `Introspect` modes, opaque `9in_at_` tokens, answers in a
  pluggable `INineCache`, and revocation webhooks that take effect on every server sharing the cache.
- `ManagementClient`: users (list, get, lookup, create, import, update, delete, block, unblock), login
  links and sessions, with a client-credentials token per scope.
- `AdapterHandler` and `IAdapter`: the adapter protocol v2 with signed requests and responses.
- `Webhook.Verify`, `EventDeduplicator` (process each event once) and `Signature`.
- Issuers must use https (`insecure_issuer`), with exceptions for localhost and an opt-out.

`9in.AspNetCore` (namespace `Nine.AspNetCore`), on ASP.NET Core's authentication stack:

- `AddNineWebApp()` and `MapNineWebApp()`: the cookie and OpenID Connect handlers preconfigured for 9in,
  `/nine/login`, `/nine/signup`, `/nine/callback` and `/nine/logout` (revoke + end session; cross-site
  requests refused), refresh with
  rotation before the access token expires, and sign-out when 9in refuses the refresh token.
- `AddNineApi()`: a bearer scheme with 9in's verifier and hybrid revocation over `IDistributedCache`;
  `RequireScope` for minimal APIs, `[RequireScope]` for MVC, and RFC 6750 challenges.
- `MapNineWebhooks()` (verify, evict, process once, typed events) and `MapNineAdapter<T>()`.
- `AddNine()` registers the clients for injection; `AddNineClientCredentials()` for `HttpClient`s.

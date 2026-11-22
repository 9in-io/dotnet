using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Nine.E2E;

/// <summary>
/// Settings of the live test tenants: the file named by <c>NINE_E2E_ENV</c> (KEY=value lines), overridden
/// by <c>E2E_*</c> environment variables. Values are never printed.
/// </summary>
public static partial class Live
{
    private static readonly Lazy<Dictionary<string, string>> Values = new(Load);

    /// <summary>A unique marker for this run, in the emails and names of the users it creates.</summary>
    public static readonly string Run = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString("x") + Guid.NewGuid().ToString("N")[..4];

    public static bool Enabled => Environment.GetEnvironmentVariable("NINE_E2E") == "1";

    public static void RequireEnabled() => Assert.SkipUnless(Enabled, "live tests run with NINE_E2E=1 (and NINE_E2E_ENV)");

    public static void RequireServerSecret()
    {
        RequireEnabled();
        Assert.SkipUnless(Has("SERVER_CLIENT_SECRET"), "SERVER_CLIENT_SECRET is not set");
    }

    private static Dictionary<string, string> Load()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var file = Environment.GetEnvironmentVariable("NINE_E2E_ENV");
        if (!string.IsNullOrEmpty(file) && File.Exists(file))
        {
            foreach (var line in File.ReadAllLines(file))
            {
                var match = SettingLine().Match(line.Trim());
                if (match.Success)
                {
                    values[match.Groups[1].Value] = match.Groups[2].Value;
                }
            }
        }
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && key.StartsWith("E2E_", StringComparison.Ordinal) && entry.Value is string value)
            {
                values[key[4..]] = value;
            }
        }
        return values;
    }

    public static bool Has(string name) => Values.Value.TryGetValue(name, out var value) && value.Length > 0;

    public static string Env(string name) =>
        Has(name) ? Values.Value[name] : throw new InvalidOperationException($"E2E setting {name} is missing (NINE_E2E_ENV)");

    [GeneratedRegex("^([A-Z0-9_]+)=(.*)$")]
    private static partial Regex SettingLine();

    /// <summary>The receiver Worker's records (webhook deliveries and raw adapter requests it got).</summary>
    public static async Task<List<JsonElement>> Records(string kind)
    {
        using var http = new HttpClient();
        var response = await http.GetAsync($"{Env("RECEIVER_URL")}/records?kind={kind}&t={Uri.EscapeDataString(Env("RECEIVER_TOKEN"))}");
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"receiver answered {(int)response.StatusCode}"); // never the URL: it has the token
        }
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.EnumerateArray().Select(e => e.Clone()).ToList();
    }

    /// <summary>Polls the receiver until a record matches (webhooks arrive asynchronously).</summary>
    public static async Task<JsonElement> WaitFor(string kind, Func<JsonElement, bool> match, int seconds = 60)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            var found = (await Records(kind)).FirstOrDefault(match);
            if (found.ValueKind != JsonValueKind.Undefined)
            {
                return found;
            }
            await Task.Delay(1500);
        }
        throw new TimeoutException($"timed out waiting for the receiver ({kind})");
    }

    public static string? Text(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static long Number(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetInt64() : 0;
}

/// <summary>The outcome of a sign-in on the hosted pages.</summary>
/// <param name="Callback">The callback URL 9in redirected to (with code, state, iss), or null.</param>
/// <param name="Status">The status of the last page when the callback wasn't reached.</param>
/// <param name="Page">That page's HTML.</param>
public sealed record HostedSignIn(string? Callback, int Status, string? Page)
{
    public string PageText => Browser.PageText(Page ?? "");
}

/// <summary>
/// A minimal browser for 9in's hosted pages: a cookie jar per host, manual redirects, form posts (a port of
/// the e2e suite's lib/browser.ts).
/// </summary>
public sealed partial class Browser : IDisposable
{
    private readonly HttpClient _http = new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly Dictionary<string, Dictionary<string, string>> _cookies = new(StringComparer.OrdinalIgnoreCase);

    public void Dispose() => _http.Dispose();

    public async Task<(int Status, string? Location, string Body)> Request(HttpMethod method, string url, Dictionary<string, string>? form = null, string? referer = null)
    {
        var target = new Uri(url);
        using var request = new HttpRequestMessage(method, target);
        request.Headers.UserAgent.ParseAdd("9in-e2e-dotnet/1.0");
        if (_cookies.TryGetValue(target.Host, out var jar) && jar.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", jar.Select(c => $"{c.Key}={c.Value}")));
        }
        if (form is not null)
        {
            request.Content = new FormUrlEncodedContent(form);
            request.Headers.Add("Origin", target.GetLeftPart(UriPartial.Authority));
            request.Headers.Referrer = new Uri(referer ?? url);
        }
        using var response = await _http.SendAsync(request);
        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            jar = _cookies.TryGetValue(target.Host, out var existing) ? existing : _cookies[target.Host] = new(StringComparer.Ordinal);
            foreach (var header in setCookies)
            {
                var parts = header.Split(';');
                var eq = parts[0].IndexOf('=', StringComparison.Ordinal);
                var name = parts[0][..eq].Trim();
                var value = parts[0][(eq + 1)..].Trim();
                var expired = parts.Skip(1).Any(a => a.Trim().Equals("max-age=0", StringComparison.OrdinalIgnoreCase)
                    || (a.Trim().StartsWith("expires=", StringComparison.OrdinalIgnoreCase) && DateTimeOffset.TryParse(a.Trim()[8..], out var at) && at < DateTimeOffset.UtcNow));
                if (expired || value.Length == 0)
                {
                    jar.Remove(name);
                }
                else
                {
                    jar[name] = value;
                }
            }
        }
        var location = response.Headers.Location is { } l ? new Uri(target, l).ToString() : null;
        return ((int)response.StatusCode, location, await response.Content.ReadAsStringAsync());
    }

    /// <summary>Follows redirects until one points at <paramref name="stopAt"/> (returned, not requested) or a page is reached.</summary>
    public async Task<(string Url, int Status, string? Page)> Follow(string url, string? stopAt = null)
    {
        var current = url;
        for (var hops = 0; hops < 20; hops++)
        {
            if (stopAt is not null && current.StartsWith(stopAt, StringComparison.Ordinal))
            {
                return (current, 302, null);
            }
            var (status, location, body) = await Request(HttpMethod.Get, current);
            if (status is >= 300 and < 400 && location is not null)
            {
                current = location;
                continue;
            }
            return (current, status, body);
        }
        throw new InvalidOperationException("too many redirects");
    }

    /// <summary>Signs in on the hosted login page with an identifier and password, stopping at the app's redirect URI.</summary>
    public async Task<HostedSignIn> SignIn(string authorizeUrl, string redirectUri, string identifier, string password)
    {
        var (url, status, page) = await Follow(authorizeUrl, redirectUri);
        if (page is null)
        {
            return new HostedSignIn(url, 302, null);
        }
        if (!page.Contains("name=\"identifier\"", StringComparison.Ordinal))
        {
            return new HostedSignIn(null, status, page);
        }
        var (action, fields) = Form(page, url);
        fields["identifier"] = identifier;
        fields["password"] = password;
        fields["action"] = "password";
        var posted = await Request(HttpMethod.Post, action, fields, url);
        if (posted.Location is null)
        {
            return new HostedSignIn(null, posted.Status, posted.Body);
        }
        var done = await Follow(posted.Location, redirectUri);
        return done.Page is null ? new HostedSignIn(done.Url, 302, null) : new HostedSignIn(null, done.Status, done.Page);
    }

    /// <summary>Opens a login link like a browser: the GET shows a page whose script posts the token back.</summary>
    public async Task<HostedSignIn> OpenLoginLink(string link, string redirectUri)
    {
        var (status, _, page) = await Request(HttpMethod.Get, link);
        if (status != 200 || !page.Contains("data-autosubmit", StringComparison.Ordinal))
        {
            return new HostedSignIn(null, status, page);
        }
        var (action, fields) = Form(page, link);
        var posted = await Request(HttpMethod.Post, action, fields, link);
        if (posted.Location is null)
        {
            return new HostedSignIn(null, posted.Status, posted.Body);
        }
        var done = await Follow(posted.Location, redirectUri);
        return done.Page is null ? new HostedSignIn(done.Url, 302, null) : new HostedSignIn(null, done.Status, done.Page);
    }

    /// <summary>The first form's action (resolved) and hidden inputs.</summary>
    public static (string Action, Dictionary<string, string> Fields) Form(string html, string pageUrl)
    {
        var start = html.IndexOf("<form", StringComparison.Ordinal);
        var form = start < 0 ? "" : html[start..(html.IndexOf("</form>", start, StringComparison.Ordinal) is var end and > 0 ? end : html.Length)];
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match input in InputTag().Matches(form))
        {
            var tag = input.Value;
            if (!tag.Contains("type=\"hidden\"", StringComparison.Ordinal))
            {
                continue;
            }
            var name = NameAttribute().Match(tag);
            if (name.Success)
            {
                fields[name.Groups[1].Value] = WebUtility.HtmlDecode(ValueAttribute().Match(tag) is { Success: true } v ? v.Groups[1].Value : "");
            }
        }
        var action = ActionAttribute().Match(form) is { Success: true } a ? WebUtility.HtmlDecode(a.Groups[1].Value) : "";
        return (new Uri(new Uri(pageUrl), action.Length > 0 ? action : pageUrl).ToString(), fields);
    }

    public static string PageText(string html) =>
        WhiteSpace().Replace(WebUtility.HtmlDecode(Tags().Replace(Scripts().Replace(html, " "), " ")), " ").Trim();

    [GeneratedRegex("<input\\b[^>]*>")] private static partial Regex InputTag();
    [GeneratedRegex("name=\"([^\"]+)\"")] private static partial Regex NameAttribute();
    [GeneratedRegex("value=\"([^\"]*)\"")] private static partial Regex ValueAttribute();
    [GeneratedRegex("action=\"([^\"]*)\"")] private static partial Regex ActionAttribute();
    [GeneratedRegex("<(script|style)[\\s\\S]*?</\\1>")] private static partial Regex Scripts();
    [GeneratedRegex("<[^>]+>")] private static partial Regex Tags();
    [GeneratedRegex("\\s+")] private static partial Regex WhiteSpace();
}

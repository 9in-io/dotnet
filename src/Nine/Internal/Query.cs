using System.Text;

namespace Nine.Internal;

internal static class Query
{
    /// <summary>
    /// The query parameters of a URL or query string. Each name keeps every value, so callers can
    /// refuse a repeated <c>code</c>, <c>state</c>, <c>iss</c> or <c>error</c>.
    /// </summary>
    public static Dictionary<string, List<string>> Parse(string urlOrQuery)
    {
        var query = urlOrQuery;
        var q = query.IndexOf('?', StringComparison.Ordinal);
        if (q >= 0)
        {
            query = query[(q + 1)..];
        }
        else if (query.Contains("://", StringComparison.Ordinal))
        {
            query = "";
        }
        var hash = query.IndexOf('#', StringComparison.Ordinal);
        if (hash >= 0)
        {
            query = query[..hash];
        }
        var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=', StringComparison.Ordinal);
            var name = Decode(eq < 0 ? pair : pair[..eq]);
            var value = eq < 0 ? "" : Decode(pair[(eq + 1)..]);
            if (!result.TryGetValue(name, out var values))
            {
                result[name] = values = [];
            }
            values.Add(value);
        }
        return result;
    }

    private static string Decode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));

    /// <summary><c>url</c> with the parameters appended (to an existing query when it has one).</summary>
    public static string Append(string url, IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var builder = new StringBuilder(url);
        var separator = url.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        foreach (var (name, value) in parameters)
        {
            builder.Append(separator).Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
            separator = '&';
        }
        return builder.ToString();
    }
}

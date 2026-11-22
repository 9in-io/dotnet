namespace Nine;

/// <summary>
/// Reads 9in settings from environment variables: <c>NINE_ISSUER</c>, <c>NINE_CLIENT_ID</c>,
/// <c>NINE_CLIENT_SECRET</c>, <c>NINE_REDIRECT_URI</c>, <c>NINE_AUDIENCE</c>, <c>NINE_API_AUDIENCE</c>,
/// <c>NINE_API_SECRET</c>, <c>NINE_TOKEN_MODE</c>, <c>NINE_ADAPTER_SECRET</c>, <c>NINE_WEBHOOK_SECRET</c>
/// and <c>NINE_ALLOW_INSECURE_ISSUER</c>. An empty variable counts as unset.
/// </summary>
public static class NineEnvironment
{
    /// <summary>The value of <c>NINE_&lt;name&gt;</c> (pass <c>"ISSUER"</c> or <c>"NINE_ISSUER"</c>), or null.</summary>
    public static string? Get(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var key = name.StartsWith("NINE_", StringComparison.Ordinal) ? name : "NINE_" + name;
        var value = Environment.GetEnvironmentVariable(key);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>True when <c>NINE_&lt;name&gt;</c> is <c>1</c>, <c>true</c>, <c>yes</c> or <c>on</c>.</summary>
    public static bool GetBool(string name) => IsTrue(Get(name));

    /// <summary>A comma-separated variable as a list (several webhook or adapter secrets during rotation).</summary>
    public static IReadOnlyList<string> GetList(string name) => SplitList(Get(name));

    internal static bool IsTrue(string? value) =>
        value is not null && (value.Equals("1", StringComparison.Ordinal) || value.Equals("true", StringComparison.OrdinalIgnoreCase)
            || value.Equals("yes", StringComparison.OrdinalIgnoreCase) || value.Equals("on", StringComparison.OrdinalIgnoreCase));

    /// <summary>A comma-separated value as a list (empty entries dropped, entries trimmed).</summary>
    public static IReadOnlyList<string> SplitList(string? value) =>
        value is null ? [] : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

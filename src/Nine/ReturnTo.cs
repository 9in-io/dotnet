namespace Nine;

/// <summary>
/// Where to send a user after sign-in: only paths on your own site are accepted, so a crafted
/// <c>return_to</c> can't turn your login route into an open redirect.
/// </summary>
public static class ReturnTo
{
    /// <summary>
    /// <paramref name="value"/> when it is a same-site relative path (<c>/dashboard?tab=1</c>), else null.
    /// Refuses absolute URLs, protocol-relative <c>//host</c>, <c>/\host</c>, control characters and
    /// anything that doesn't start with <c>/</c>.
    /// </summary>
    public static string? Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 2048 || value[0] != '/')
        {
            return null;
        }
        if (value.Length > 1 && (value[1] == '/' || value[1] == '\\'))
        {
            return null;
        }
        foreach (var c in value)
        {
            if (char.IsControl(c) || c == '\\')
            {
                return null;
            }
        }
        // Resolve against a fixed origin: the result must stay on it.
        var origin = new Uri("https://return-to.invalid");
        if (!Uri.TryCreate(origin, value, out var resolved) || resolved.Host != origin.Host || resolved.Scheme != origin.Scheme || !resolved.IsDefaultPort)
        {
            return null;
        }
        return value;
    }
}

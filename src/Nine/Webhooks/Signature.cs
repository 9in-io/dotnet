using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Nine;

/// <summary>The outcome of <see cref="Signature.Check(IEnumerable{string}, string?, string, string, ReadOnlySpan{byte}, TimeSpan?, TimeProvider?)"/>.</summary>
/// <param name="Ok">Whether the signature is valid.</param>
/// <param name="Failure">Why not, when it isn't.</param>
/// <param name="Timestamp">The header's timestamp, when it could be read.</param>
public readonly record struct SignatureCheck(bool Ok, SignatureFailure? Failure, long? Timestamp);

/// <summary>
/// 9in request signatures, for webhooks and the adapter protocol:
/// <c>9in-signature: t=&lt;unix seconds&gt;,v1=&lt;hex HMAC-SHA256(secret, "&lt;t&gt;.&lt;METHOD&gt;.&lt;path&gt;.&lt;raw body&gt;")&gt;</c>.
/// The timestamp is signed and checked against a tolerance (5 minutes), so a captured request can't be
/// replayed later. Several <c>v1</c> values and several secrets are accepted, for rotation. Adapter
/// responses are signed the same way over <c>&lt;path&gt;#&lt;9in-request-id&gt;</c>.
/// </summary>
public static class Signature
{
    /// <summary>The signature header.</summary>
    public const string Header = "9in-signature";

    /// <summary>The request id header (adapter requests).</summary>
    public const string RequestIdHeader = "9in-request-id";

    /// <summary>The default tolerance: 5 minutes.</summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromSeconds(300);

    /// <summary>A <c>9in-signature</c> header value for a request or response.</summary>
    public static string Sign(string secret, string method, string path, ReadOnlySpan<byte> body, long? timestamp = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        var t = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return "t=" + t.ToString(CultureInfo.InvariantCulture) + ",v1=" + Mac(secret, t, method, path, body);
    }

    /// <inheritdoc cref="Sign(string, string, string, ReadOnlySpan{byte}, long?)"/>
    public static string Sign(string secret, string method, string path, string body, long? timestamp = null) =>
        Sign(secret, method, path, Encoding.UTF8.GetBytes(body ?? ""), timestamp);

    /// <summary>Whether <paramref name="header"/> is a valid signature of the request by any of <paramref name="secrets"/>.</summary>
    public static bool Verify(IEnumerable<string> secrets, string? header, string method, string path, ReadOnlySpan<byte> body, TimeSpan? tolerance = null, TimeProvider? timeProvider = null) =>
        Check(secrets, header, method, path, body, tolerance, timeProvider).Ok;

    /// <inheritdoc cref="Verify(IEnumerable{string}, string?, string, string, ReadOnlySpan{byte}, TimeSpan?, TimeProvider?)"/>
    public static bool Verify(string secret, string? header, string method, string path, string body, TimeSpan? tolerance = null, TimeProvider? timeProvider = null) =>
        Check([secret], header, method, path, Encoding.UTF8.GetBytes(body ?? ""), tolerance, timeProvider).Ok;

    /// <summary>Like <see cref="Verify(IEnumerable{string}, string?, string, string, ReadOnlySpan{byte}, TimeSpan?, TimeProvider?)"/>, with the reason for a refusal.</summary>
    public static SignatureCheck Check(IEnumerable<string> secrets, string? header, string method, string path, ReadOnlySpan<byte> body, TimeSpan? tolerance = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        if (string.IsNullOrEmpty(header))
        {
            return new SignatureCheck(false, SignatureFailure.Missing, null);
        }
        if (Parse(header) is not { } parsed)
        {
            return new SignatureCheck(false, SignatureFailure.Malformed, null);
        }
        var now = (timeProvider ?? TimeProvider.System).GetUtcNow().ToUnixTimeSeconds();
        if (Math.Abs(now - parsed.Timestamp) > (tolerance ?? DefaultTolerance).TotalSeconds)
        {
            return new SignatureCheck(false, SignatureFailure.Expired, parsed.Timestamp);
        }
        foreach (var secret in secrets)
        {
            if (string.IsNullOrEmpty(secret))
            {
                continue;
            }
            var expected = Encoding.ASCII.GetBytes(Mac(secret, parsed.Timestamp, method, path, body));
            foreach (var candidate in parsed.Signatures)
            {
                if (CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(candidate)))
                {
                    return new SignatureCheck(true, null, parsed.Timestamp);
                }
            }
        }
        return new SignatureCheck(false, SignatureFailure.Mismatch, parsed.Timestamp);
    }

    /// <summary>
    /// Parses <c>t=…,v1=…[,v1=…]</c> strictly: <c>t</c> is 1–12 digits, every <c>v1</c> is 64 lower-case
    /// hex digits, unknown names are ignored, anything else is malformed (null).
    /// </summary>
    public static (long Timestamp, IReadOnlyList<string> Signatures)? Parse(string header)
    {
        ArgumentNullException.ThrowIfNull(header);
        long? timestamp = null;
        var signatures = new List<string>();
        foreach (var part in header.Split(','))
        {
            var eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq < 1)
            {
                return null;
            }
            var name = part[..eq].Trim();
            var value = part[(eq + 1)..].Trim();
            if (name == "t")
            {
                if (value.Length is < 1 or > 12 || !value.All(char.IsAsciiDigit))
                {
                    return null;
                }
                timestamp = long.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
            }
            else if (name == "v1")
            {
                if (value.Length != 64 || !value.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f'))
                {
                    return null;
                }
                signatures.Add(value);
            }
        }
        return timestamp is { } t && signatures.Count > 0 ? (t, signatures) : null;
    }

    private static string Mac(string secret, long timestamp, string method, string path, ReadOnlySpan<byte> body)
    {
        var prefix = Encoding.UTF8.GetBytes(timestamp.ToString(CultureInfo.InvariantCulture) + "." + method.ToUpperInvariant() + "." + path + ".");
        var payload = new byte[prefix.Length + body.Length];
        prefix.CopyTo(payload, 0);
        body.CopyTo(payload.AsSpan(prefix.Length));
        return Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), payload)).ToLowerInvariant();
    }
}

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Nine.Internal;

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Encode(string text) => Encode(Encoding.UTF8.GetBytes(text));

    /// <summary>Strict base64url (RFC 4648 §5, no padding): returns false for anything else.</summary>
    public static bool TryDecode(string value, out byte[] bytes)
    {
        bytes = [];
        if (value.Length % 4 == 1)
        {
            return false;
        }
        foreach (var c in value)
        {
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
            {
                return false;
            }
        }
        var padded = value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4);
        try
        {
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static byte[] Decode(string value) =>
        TryDecode(value, out var bytes) ? bytes : throw new FormatException("not base64url");

    /// <summary>A random URL-safe string with <paramref name="bytes"/> bytes of entropy.</summary>
    public static string Random(int bytes) => Encode(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>Lower-case hex SHA-256 of a UTF-8 string (cache keys: never the raw token).</summary>
    public static string Sha256Hex(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}

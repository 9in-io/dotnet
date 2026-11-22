using System.Text;
using System.Text.Json;
using Nine.Internal;

namespace Nine.Tokens;

/// <summary>A compact JWS split into its parts. Nothing is verified here.</summary>
internal sealed class Jwt
{
    private const int MaxLength = 16 * 1024;

    private Jwt(JsonElement header, JsonElement payload, byte[] signingInput, byte[] signature)
    {
        Header = header;
        Payload = payload;
        SigningInput = signingInput;
        Signature = signature;
    }

    public JsonElement Header { get; }
    public JsonElement Payload { get; }
    public byte[] SigningInput { get; }
    public byte[] Signature { get; }

    public string? Alg => HeaderString("alg");
    public string? Kid => HeaderString("kid");
    public string? Typ => HeaderString("typ");

    private string? HeaderString(string name) =>
        Header.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>Splits a compact JWS; returns null for anything that isn't three base64url parts with JSON-object header and payload.</summary>
    public static Jwt? TryDecode(string token)
    {
        if (token.Length > MaxLength)
        {
            return null;
        }
        var parts = token.Split('.');
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0)
        {
            return null;
        }
        if (!Base64Url.TryDecode(parts[0], out var headerBytes) || !Base64Url.TryDecode(parts[1], out var payloadBytes) || !Base64Url.TryDecode(parts[2], out var signature))
        {
            return null;
        }
        var header = ParseObject(headerBytes);
        var payload = ParseObject(payloadBytes);
        if (header is null || payload is null)
        {
            return null;
        }
        return new Jwt(header.Value, payload.Value, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature);
    }

    private static JsonElement? ParseObject(byte[] json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
            return document.RootElement.ValueKind == JsonValueKind.Object ? document.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

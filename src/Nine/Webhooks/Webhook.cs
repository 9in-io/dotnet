using System.Text;
using System.Text.Json;

namespace Nine;

/// <summary>
/// Verifies webhooks from 9in: the <c>9in-signature</c> header over the raw body and the path 9in
/// posted to (as in your endpoint URL, without the query string), within 5 minutes.
/// </summary>
public static class Webhook
{
    /// <summary>The event id header (also the body's <c>id</c>).</summary>
    public const string EventIdHeader = "9in-event-id";
    /// <summary>The event name header (also the body's <c>event_type</c>).</summary>
    public const string EventTypeHeader = "9in-event-type";
    /// <summary>The delivery id header (differs on each retry).</summary>
    public const string DeliveryIdHeader = "9in-delivery-id";

    /// <summary>
    /// Verifies a delivery and returns the event. Throws <see cref="SignatureException"/> (401) for a missing,
    /// malformed, expired or wrong signature, or <see cref="NineException"/> <c>invalid_payload</c> (400) for a body
    /// that isn't an event.
    /// </summary>
    /// <param name="secrets">The endpoint's signing secret, or several during rotation.</param>
    /// <param name="body">The raw request body, exactly as received.</param>
    /// <param name="signature">The <c>9in-signature</c> header.</param>
    /// <param name="path">The path 9in posted to, e.g. <c>/nine/webhook</c>.</param>
    /// <param name="method">The request method (webhooks are POST).</param>
    /// <param name="tolerance">How far the timestamp may be off. Default 5 minutes.</param>
    /// <param name="timeProvider">The clock (tests).</param>
    public static WebhookEvent Verify(IEnumerable<string> secrets, ReadOnlySpan<byte> body, string? signature, string path, string method = "POST", TimeSpan? tolerance = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(method);
        if (!method.Equals("POST", StringComparison.OrdinalIgnoreCase))
        {
            throw new SignatureException(SignatureFailure.Mismatch, "webhooks are POST requests");
        }
        var check = Signature.Check(secrets, signature, "POST", path, body, tolerance, timeProvider);
        if (!check.Ok)
        {
            throw new SignatureException(check.Failure!.Value);
        }
        try
        {
            using var document = JsonDocument.Parse(body.ToArray());
            return WebhookEvent.Parse(document.RootElement);
        }
        catch (JsonException e)
        {
            throw new NineException("invalid_payload", "the webhook body is not JSON", 400, e);
        }
    }

    /// <inheritdoc cref="Verify(IEnumerable{string}, ReadOnlySpan{byte}, string?, string, string, TimeSpan?, TimeProvider?)"/>
    public static WebhookEvent Verify(string secret, ReadOnlySpan<byte> body, string? signature, string path, string method = "POST", TimeSpan? tolerance = null, TimeProvider? timeProvider = null) =>
        Verify([secret], body, signature, path, method, tolerance, timeProvider);

    /// <inheritdoc cref="Verify(IEnumerable{string}, ReadOnlySpan{byte}, string?, string, string, TimeSpan?, TimeProvider?)"/>
    public static WebhookEvent Verify(string secret, string body, string? signature, string path, string method = "POST", TimeSpan? tolerance = null, TimeProvider? timeProvider = null) =>
        Verify([secret], Encoding.UTF8.GetBytes(body ?? ""), signature, path, method, tolerance, timeProvider);

    /// <inheritdoc cref="Verify(IEnumerable{string}, ReadOnlySpan{byte}, string?, string, string, TimeSpan?, TimeProvider?)"/>
    public static WebhookEvent Verify(IEnumerable<string> secrets, string body, string? signature, string path, string method = "POST", TimeSpan? tolerance = null, TimeProvider? timeProvider = null) =>
        Verify(secrets, Encoding.UTF8.GetBytes(body ?? ""), signature, path, method, tolerance, timeProvider);
}

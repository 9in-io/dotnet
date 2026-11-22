namespace Nine;

/// <summary>
/// Every failure of the SDK: an OAuth-style <see cref="Error"/> code (<c>invalid_token</c>,
/// <c>invalid_grant</c>, <c>insecure_issuer</c>, …), an optional <see cref="ErrorDescription"/> and,
/// for HTTP failures, the <see cref="StatusCode"/>.
/// </summary>
public class NineException : Exception
{
    /// <summary>Creates an error with a code, an optional description and an optional HTTP status.</summary>
    public NineException(string error, string? description = null, int? statusCode = null, Exception? innerException = null)
        : base(description is null ? error : $"{error}: {description}", innerException)
    {
        Error = error;
        ErrorDescription = description;
        StatusCode = statusCode;
    }

    /// <summary>The error code, e.g. <c>invalid_token</c> or <c>access_denied</c>.</summary>
    public string Error { get; }

    /// <summary>A human-readable explanation, when there is one.</summary>
    public string? ErrorDescription { get; }

    /// <summary>The HTTP status that goes with the error (401, 403, 404, …), when there is one.</summary>
    public int? StatusCode { get; }
}

/// <summary>A missing, malformed, expired, wrongly signed or revoked token (HTTP 401, <c>invalid_token</c>).</summary>
public sealed class InvalidTokenException : NineException
{
    /// <summary>Creates an <c>invalid_token</c> error.</summary>
    public InvalidTokenException(string description, Exception? innerException = null)
        : base("invalid_token", description, 401, innerException)
    {
    }
}

/// <summary>A valid token without a scope the call needs (HTTP 403, <c>insufficient_scope</c>).</summary>
public sealed class InsufficientScopeException : NineException
{
    /// <summary>Creates an <c>insufficient_scope</c> error for the scopes that are missing.</summary>
    public InsufficientScopeException(IReadOnlyList<string> missingScopes)
        : base("insufficient_scope", "missing " + string.Join(", ", missingScopes), 403)
    {
        MissingScopes = missingScopes;
    }

    /// <summary>The scopes the token lacks.</summary>
    public IReadOnlyList<string> MissingScopes { get; }
}

/// <summary>Why a <c>9in-signature</c> header was refused.</summary>
public enum SignatureFailure
{
    /// <summary>No header.</summary>
    Missing,
    /// <summary>The header is not <c>t=&lt;unix&gt;,v1=&lt;64 hex&gt;</c>.</summary>
    Malformed,
    /// <summary>The timestamp is outside the tolerance (a replay, or a wrong clock).</summary>
    Expired,
    /// <summary>No signature matches any secret (wrong secret, altered body, path or method).</summary>
    Mismatch,
}

/// <summary>A webhook or adapter request whose signature is missing or wrong (HTTP 401, <c>invalid_signature</c>).</summary>
public sealed class SignatureException : NineException
{
    /// <summary>Creates an <c>invalid_signature</c> error.</summary>
    public SignatureException(SignatureFailure reason, string? description = null)
        : base("invalid_signature", description ?? DescribeFailure(reason), 401)
    {
        Reason = reason;
    }

    /// <summary>Why the signature was refused.</summary>
    public SignatureFailure Reason { get; }

    private static string DescribeFailure(SignatureFailure reason) => reason switch
    {
        SignatureFailure.Missing => "no 9in-signature header",
        SignatureFailure.Malformed => "malformed 9in-signature header",
        SignatureFailure.Expired => "the signature timestamp is outside the tolerance",
        _ => "the signature does not match",
    };
}

/// <summary>A sign-in callback whose <c>state</c> is missing, wrong, already used or expired (HTTP 400, <c>invalid_state</c>).</summary>
public sealed class InvalidStateException : NineException
{
    /// <summary>Creates an <c>invalid_state</c> error.</summary>
    public InvalidStateException(string description)
        : base("invalid_state", description, 400)
    {
    }
}

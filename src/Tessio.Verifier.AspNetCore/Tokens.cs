using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Tessio.Verifier.AspNetCore;

/// <summary>Cryptographically random, URL-safe identifiers for nonces, state, and session ids.</summary>
internal static class Tokens
{
    /// <summary>A 256-bit random, base64url-encoded value suitable for a nonce or state.</summary>
    public static string NewNonce() => Random(32);

    /// <summary>A 128-bit random, base64url-encoded opaque session identifier.</summary>
    public static string NewSessionId() => Random(16);

    private static string Random(int bytes) =>
        WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(bytes));
}

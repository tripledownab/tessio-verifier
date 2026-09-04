// What belongs in this file: how this library turns an untrusted compact-serialization JWT string into a
// token, and what it does when the string is not one. Nothing about what any particular JWT means.

using System.Diagnostics.CodeAnalysis;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// Parses a compact JWT that arrived from outside, reporting a malformed one as a return value rather
/// than as an exception.
/// </summary>
/// <remarks>
/// <para>
/// One place, because every caller in this library has the same job. <see cref="JsonWebToken"/>'s
/// constructor reports a malformed token as two unrelated exception types, and a guard written inline
/// tends to name one of them. Parsing input that arrived from outside is this library's whole job, so
/// every way that input can be malformed has to arrive at the caller as a verification error rather
/// than as a throw.
/// </para>
/// <para>
/// Measured against Microsoft.IdentityModel.JsonWebTokens 8.19.2, which is the version this library
/// pins. <c>"eyJhbGciOiJFQ0RILUVTIn0.not.a.real.jwe"</c> raises <see cref="FormatException"/>.
/// <c>"!!!.???.***"</c> raises <see cref="ArgumentException"/>. <c>"one-segment-only"</c> raises
/// <c>SecurityTokenMalformedException</c>, which derives from <see cref="ArgumentException"/> and so is
/// already covered. Catching both named types is therefore the whole set, and catching them is not a
/// fallback: it converts a throw into an explicit failure that every caller has to answer for.
/// </para>
/// </remarks>
internal static class CompactJwt
{
    /// <summary>
    /// True when <paramref name="value"/> parsed, false when it is not a well-formed JWT. The caller
    /// says what a malformed one means in its own context; this only says that it is one.
    /// </summary>
    public static bool TryParse(string value, [NotNullWhen(true)] out JsonWebToken? token)
    {
        try
        {
            token = new JsonWebToken(value);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            token = null;
            return false;
        }
    }
}

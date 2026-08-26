using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// The ISO/IEC 18013-7 Annex C request example published in the EU age verification profile's
/// technical specification (its Annex A, "W3C Digital Credentials API"): the verbatim base64url
/// <c>encryptionInfo</c> and <c>deviceRequest</c>, the session transcript digest the
/// specification prints for them, and the origin that digest was computed for, which is the
/// specification's hosted reference verifier. Externally produced bytes: NEVER regenerate.
/// </summary>
internal static class Iso18013AnnexCVectors
{
    public const string EncryptionInfoBase64Url =
        "gmVkY2FwaaJlbm9uY2VQtJvGiCZ0egQII8fQgu960HJyZWNpcGllbnRQdWJsaWNLZXmkAQIgAS"
        + "FYIMmliVBWgs8KKpAychO3py0Eqagows-CrraFX1rVOniXIlggIMvYr_x55AY4LKiWZLHBlQJm"
        + "X1R9Y5BkUfnuSddAmyE";

    public const string DeviceRequestBase64Url =
        "omd2ZXJzaW9uYzEuMGtkb2NSZXF1ZXN0c4GhbGl0ZW1zUmVxdWVzdNgYWEeiZ2RvY1R5cGVxZXUu"
        + "ZXVyb3BhLmVjLmF2LjFqbmFtZVNwYWNlc6FxZXUuZXVyb3BhLmVjLmF2LjGha2FnZV9vdmVyXzE49A";

    /// <summary>The 32-byte digest inside the transcript the specification prints for the example.</summary>
    public const string TranscriptDigestHex = "4a292708fcf38ad55a7969f1c97ead9decf7756b7e9d8cfee942fe9f31b8db0a";

    /// <summary>The origin the example's digest commits to.</summary>
    public const string Origin = "https://verifier.ageverification.dev";

    public static byte[] EncryptionInfo => Base64UrlEncoder.DecodeBytes(EncryptionInfoBase64Url);

    public static byte[] DeviceRequest => Base64UrlEncoder.DecodeBytes(DeviceRequestBase64Url);

    public static byte[] TranscriptDigest => Convert.FromHexString(TranscriptDigestHex);
}

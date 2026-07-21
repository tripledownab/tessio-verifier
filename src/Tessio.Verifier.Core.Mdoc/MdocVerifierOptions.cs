namespace Tessio.Verifier.Core.Mdoc;

/// <summary>Policy knobs for <see cref="MdocVerifier"/>.</summary>
public sealed class MdocVerifierOptions
{
    /// <summary>
    /// Tolerated clock skew for the MSO validity window. Defaults to 5 minutes, matching
    /// <see cref="SdJwtVcVerifierOptions.ClockSkew"/>.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether device authentication (the holder's signature over the session transcript) is
    /// required. Defaults to true, matching <see cref="SdJwtVcVerifierOptions.RequireKeyBinding"/>.
    /// When false, a present deviceSignature is still verified.
    /// </summary>
    public bool RequireDeviceAuth { get; set; } = true;
}

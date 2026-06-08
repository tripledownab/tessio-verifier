namespace Tessio.Verifier.Core;

/// <summary>
/// Verifies a presented credential (SD-JWT VC) against its issuer, disclosures, and key binding.
/// </summary>
/// <remarks>FROZEN contract (contracts-v0). Do not modify.</remarks>
public interface ICredentialVerifier
{
    Task<VerificationResult> VerifyAsync(
        PresentedCredential credential,
        VerificationContext context,
        CancellationToken ct = default);
}

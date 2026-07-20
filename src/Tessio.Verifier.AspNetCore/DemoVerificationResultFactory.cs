using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Synthesizes a valid <see cref="VerificationResult"/> for DEMO mode from the configured requested claims,
/// so a session can complete without a real wallet or credential.
/// </summary>
internal static class DemoVerificationResultFactory
{
    public static VerificationResult Create(VerifierOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var requested = options.RequestedClaims is { Count: > 0 }
            ? options.RequestedClaims
            : new[] { "age_over_18" };

        var disclosed = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var claim in requested)
        {
            disclosed[claim] = SampleClaimValues.For(claim);
        }

        return new VerificationResult
        {
            IsValid = true,
            DisclosedClaims = disclosed,
            Issuer = new IssuerInfo
            {
                Identifier = "https://demo-issuer.tessio.dev",
                Trusted = true,
                KeyResolutionMethod = "jwt-vc-issuer-metadata",
            },
            Errors = Array.Empty<VerificationError>(),
        };
    }
}

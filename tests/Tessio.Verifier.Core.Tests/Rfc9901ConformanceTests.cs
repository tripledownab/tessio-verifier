namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Verifies the RFC 9901 Appendix A.3 vectors — the spec's own SD-JWT VC example (a German PID) —
/// through the full pipeline, using only the key material the RFC publishes. If these fail, the
/// verifier disagrees with the specification itself.
/// </summary>
public class Rfc9901ConformanceTests
{
    private sealed class FixedClock : TimeProvider
    {
        // Shortly after the example KB-JWT's iat (2025-05-29); inside the credential's validity.
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(1748537300);
    }

    private static SdJwtVcVerifier Verifier(SdJwtVcVerifierOptions? options = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://pid-issuer.bund.de.example/.well-known/jwt-vc-issuer",
            "{\"issuer\":\"" + Rfc9901Vectors.Issuer + "\",\"jwks\":{\"keys\":[" + Rfc9901Vectors.IssuerJwk + "]}}");
        return new SdJwtVcVerifier(new FakeTrustListResolver(), options, new HttpClient(http), new FixedClock());
    }

    [Fact]
    public async Task SpecPresentation_Verifies_WithRecursiveDisclosures()
    {
        var result = await Verifier().VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = Rfc9901Vectors.Presentation },
            new VerificationContext
            {
                Nonce = Rfc9901Vectors.ExpectedNonce,
                Audience = Rfc9901Vectors.ExpectedAudience,
                ExpectedVct = "urn:eudi:pid:de:1",
            });

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.Equal(Rfc9901Vectors.Issuer, result.Issuer.Identifier);
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);

        // The presentation discloses nationalities and the recursive age_equal_or_over."18".
        var nationalities = Assert.IsType<List<object?>>(result.DisclosedClaims["nationalities"]);
        Assert.Equal("DE", Assert.Single(nationalities));

        var ageOver = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims["age_equal_or_over"]);
        Assert.Equal(true, Assert.Single(ageOver, kv => kv.Key == "18").Value);

        // Withheld claims must not appear.
        Assert.False(result.DisclosedClaims.ContainsKey("given_name"));
        Assert.False(result.DisclosedClaims.ContainsKey("birthdate"));
    }

    [Fact]
    public async Task SpecIssuance_AllDisclosures_VerifiesWithoutKeyBinding()
    {
        var result = await Verifier(new SdJwtVcVerifierOptions { RequireKeyBinding = false }).VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = Rfc9901Vectors.Issuance },
            new VerificationContext
            {
                Nonce = Rfc9901Vectors.ExpectedNonce,
                Audience = Rfc9901Vectors.ExpectedAudience,
            });

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.Equal("Erika", result.DisclosedClaims["given_name"]);
        Assert.Equal("Mustermann", result.DisclosedClaims["family_name"]);
        Assert.Equal("1963-08-12", result.DisclosedClaims["birthdate"]);

        var address = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims["address"]);
        Assert.Equal("DE", address["country"]);
    }

    [Fact]
    public async Task SpecPresentation_WrongNonce_FailsKeyBinding()
    {
        var result = await Verifier().VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = Rfc9901Vectors.Presentation },
            new VerificationContext
            {
                Nonce = "some-other-nonce",
                Audience = Rfc9901Vectors.ExpectedAudience,
            });

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "nonce_mismatch");
    }

    [Fact]
    public async Task SpecPresentation_TamperedSignature_IsRejected()
    {
        var raw = Rfc9901Vectors.Presentation;
        var tildeAt = raw.IndexOf('~');
        var sigStart = raw.LastIndexOf('.', tildeAt) + 1;
        var mid = (sigStart + tildeAt) / 2;
        var tampered = raw[..mid] + (raw[mid] == 'A' ? 'B' : 'A') + raw[(mid + 1)..];

        var result = await Verifier().VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = tampered },
            new VerificationContext
            {
                Nonce = Rfc9901Vectors.ExpectedNonce,
                Audience = Rfc9901Vectors.ExpectedAudience,
            });

        Assert.False(result.IsValid);
        Assert.Equal("signature_invalid", result.Errors.Single().Code);
    }
}
